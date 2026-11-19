"""Authenticated, encrypted detector -> enforcer channel in three modes.

  classical : X25519            + Ed25519
  hybrid    : X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65   (secure if either family holds)
  pq        : ML-KEM-768        + ML-DSA-65

Handshake (once per session): the detector encapsulates to the enforcer's static KEM keys and
signs the handshake. Both sides derive one AES-256 key with HKDF.
Alert (every decision): header {v, mode, session, counter} is authenticated as AES-GCM AAD;
plaintext = canonical JSON alert; the signature(s) cover header + plaintext and travel inside
the ciphertext. The receiver fails closed on any problem.
"""
import json
import os
import time
import uuid
from dataclasses import asdict, is_dataclass

from cryptography.exceptions import InvalidTag

from .backend import Ed25519Sig, X25519KEM, load_pq
from .primitives import aes_decrypt, aes_encrypt, canonical, derive_key, pack, unpack
from .replay import ReplayGuard

VERSION = 1
MODES = ("classical", "hybrid", "pq")


def algorithms(mode: str, backend: str = "auto", allow_pure: bool = False):
    if mode not in MODES:
        raise ValueError(mode)
    if mode == "classical":
        return [X25519KEM()], [Ed25519Sig()]
    kem, sig = load_pq(backend, allow_pure)            # raises PQCUnavailable: fail closed
    if mode == "pq":
        return [kem], [sig]
    return [X25519KEM(), kem], [Ed25519Sig(), sig]


class Keys:
    """Long-term keys. In a deployment each side keeps its secrets and pins the other's public keys."""

    def __init__(self, kems, sigs):
        self.enforcer_kem = [k.keygen() for k in kems]       # (public, secret) per KEM
        self.detector_sig = [s.keygen() for s in sigs]       # (public, secret) per signature


class Sender:
    """Runs on the detector."""

    def __init__(self, mode, kems, sigs, enforcer_kem_pubs, detector_sig_secrets):
        self.mode, self.kems, self.sigs = mode, kems, sigs
        self.kem_pubs, self.sig_secrets = enforcer_kem_pubs, detector_sig_secrets
        self.key, self.session, self.counter = None, None, 0

    def handshake(self) -> bytes:
        self.session = os.urandom(16)
        cts, secrets = zip(*[k.encaps(pk) for k, pk in zip(self.kems, self.kem_pubs)])
        body = pack([canonical({"v": VERSION, "mode": self.mode}), self.session, *cts])
        sigs = [s.sign(sk, body) for s, sk in zip(self.sigs, self.sig_secrets)]
        self.key = derive_key(list(secrets), self.session, body)
        self.counter = 0
        return pack([body, *sigs])

    def seal(self, decision, sign: bool = True) -> bytes:
        if self.key is None:
            raise RuntimeError("call handshake() first")
        self.counter += 1
        alert = {"version": VERSION, "alert_id": str(uuid.uuid4()), "counter": self.counter,
                 "timestamp": time.time(),
                 "decision": asdict(decision) if is_dataclass(decision) else decision}
        header = canonical({"v": VERSION, "mode": self.mode, "session": self.session.hex(),
                            "counter": self.counter})
        plaintext = canonical(alert)
        sigs = [s.sign(sk, header + plaintext) for s, sk in zip(self.sigs, self.sig_secrets)] if sign else []
        return pack([header, aes_encrypt(self.key, pack([plaintext, *sigs]), header)])


class Receiver:
    """Runs on the firewall enforcer. receive() returns (accepted, reason, alert_or_None)."""

    def __init__(self, mode, kems, sigs, enforcer_kem_secrets, detector_sig_pubs, window_s=30.0):
        self.mode, self.kems, self.sigs = mode, kems, sigs
        self.kem_secrets, self.sig_pubs = enforcer_kem_secrets, detector_sig_pubs
        self.sessions = {}                                 # session hex -> AES key
        self.guard = ReplayGuard(window_s)

    def accept_handshake(self, blob: bytes):
        try:
            parts = unpack(blob)
            body, sigs = parts[0], parts[1:]
            meta, session, *cts = unpack(body)
        except Exception:
            return False, "malformed_handshake"
        if meta != canonical({"v": VERSION, "mode": self.mode}):
            return False, "mode_mismatch"                  # blocks downgrade attempts
        if len(sigs) != len(self.sigs) or len(cts) != len(self.kems):
            return False, "unsigned_or_incomplete"
        if not all(s.verify(pk, body, sg) for s, pk, sg in zip(self.sigs, self.sig_pubs, sigs)):
            return False, "bad_signature"
        try:
            secrets = [k.decaps(sk, ct) for k, sk, ct in zip(self.kems, self.kem_secrets, cts)]
        except Exception:
            return False, "decapsulation_failed"
        self.sessions[session.hex()] = derive_key(secrets, session, body)
        return True, "ok"

    def receive(self, blob: bytes, now: float = None):
        try:
            header, ct = unpack(blob)
            h = json.loads(header)
        except Exception:
            return False, "malformed", None
        if h.get("v") != VERSION or h.get("mode") != self.mode:
            return False, "mode_mismatch", None
        key = self.sessions.get(h.get("session"))
        if key is None:
            return False, "unknown_session", None
        try:
            plaintext, *sigs = unpack(aes_decrypt(key, ct, header))
        except (InvalidTag, ValueError):
            return False, "decrypt_failed", None
        if len(sigs) != len(self.sigs):
            return False, "unsigned", None
        if not all(s.verify(pk, header + plaintext, sg) for s, pk, sg in zip(self.sigs, self.sig_pubs, sigs)):
            return False, "bad_signature", None
        alert = json.loads(plaintext)
        if alert.get("counter") != h["counter"]:
            return False, "counter_mismatch", None
        problem = self.guard.check(h["session"], alert["counter"], alert["timestamp"], now)
        if problem:
            return False, problem, None
        return True, "ok", alert


def make_pair(mode: str, backend: str = "auto", allow_pure: bool = False, window_s: float = 30.0):
    """Convenience for tests, benchmarks and the demo: fresh keys, connected Sender + Receiver."""
    kems, sigs = algorithms(mode, backend, allow_pure)
    keys = Keys(kems, sigs)
    sender = Sender(mode, kems, sigs, [pk for pk, _ in keys.enforcer_kem], [sk for _, sk in keys.detector_sig])
    receiver = Receiver(mode, kems, sigs, [sk for _, sk in keys.enforcer_kem],
                        [pk for pk, _ in keys.detector_sig], window_s)
    return sender, receiver
