"""Canonical JSON, HKDF key derivation, AES-256-GCM, length-prefixed framing."""
import hashlib
import json
import os
import struct
from typing import List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def canonical(obj) -> bytes:
    """Same object -> same bytes every time (sorted keys, no spaces). Needed for signatures."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def derive_key(shared_secrets: List[bytes], salt: bytes, transcript: bytes) -> bytes:
    """HKDF-SHA256 over the concatenated secrets: secure if ANY of the KEMs is secure."""
    info = b"attack-detective/v1/" + hashlib.sha256(transcript).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(b"".join(shared_secrets))


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)                       # 96-bit random nonce, new for every message
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)    # raises InvalidTag if modified


def pack(parts: List[bytes]) -> bytes:
    return struct.pack(">H", len(parts)) + b"".join(struct.pack(">I", len(p)) + p for p in parts)


def unpack(blob: bytes) -> List[bytes]:
    (n,), off, out = struct.unpack_from(">H", blob, 0), 2, []
    for _ in range(n):
        (ln,) = struct.unpack_from(">I", blob, off)
        off += 4
        if off + ln > len(blob):
            raise ValueError("truncated message")
        out.append(blob[off:off + ln])
        off += ln
    if off != len(blob):
        raise ValueError("trailing bytes")
    return out
