"""One interface for ML-KEM-768 / ML-DSA-65 (three possible libraries) and X25519 / Ed25519.

Backend order for 'auto': cryptography (>=48, native, fast) -> liboqs-python -> pure Python
(kyber-py / dilithium-py: slow, NOT constant-time, prototype only, must be allowed in pqc.yaml).
Every KEM:  keygen() -> (public_bytes, secret);  encaps(public_bytes) -> (ciphertext, shared_secret);
            decaps(secret, ciphertext) -> shared_secret
Every SIG:  keygen() -> (public_bytes, secret);  sign(secret, msg) -> sig;  verify(pub, msg, sig) -> bool
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


class PQCUnavailable(RuntimeError):
    pass


# ----------------------------------------------------------------- classical
class X25519KEM:
    """X25519 used as a KEM: the 'ciphertext' is the sender's ephemeral public key."""
    name, backend = "X25519", "cryptography"

    def keygen(self):
        sk = x25519.X25519PrivateKey.generate()
        return sk.public_key().public_bytes(**_RAW), sk

    def encaps(self, pk: bytes):
        eph = x25519.X25519PrivateKey.generate()
        ss = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk))
        return eph.public_key().public_bytes(**_RAW), ss

    def decaps(self, sk, ct: bytes):
        return sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct))


class Ed25519Sig:
    name, backend = "Ed25519", "cryptography"

    def keygen(self):
        sk = ed25519.Ed25519PrivateKey.generate()
        return sk.public_key().public_bytes(**_RAW), sk

    def sign(self, sk, msg: bytes) -> bytes:
        return sk.sign(msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False


# ----------------------------------------------------------------- post-quantum
class _CryptographyMLKEM:
    name, backend = "ML-KEM-768", "cryptography"

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import mlkem
        self.m = mlkem
        self.m.MLKEM768PrivateKey.generate()        # raises if this build has no ML-KEM

    def keygen(self):
        sk = self.m.MLKEM768PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk

    def encaps(self, pk):
        ss, ct = self.m.MLKEM768PublicKey.from_public_bytes(pk).encapsulate()
        return ct, ss

    def decaps(self, sk, ct):
        return sk.decapsulate(ct)


class _CryptographyMLDSA:
    name, backend = "ML-DSA-65", "cryptography"

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        self.m = mldsa
        self.m.MLDSA65PrivateKey.generate()

    def keygen(self):
        sk = self.m.MLDSA65PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk

    def sign(self, sk, msg):
        return sk.sign(msg)

    def verify(self, pk, msg, sig):
        try:
            self.m.MLDSA65PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False


class _OqsKEM:
    backend = "liboqs"

    def __init__(self):
        import oqs
        self.oqs = oqs
        enabled = oqs.get_enabled_kem_mechanisms()
        self.name = "ML-KEM-768" if "ML-KEM-768" in enabled else "Kyber768"
        if self.name not in enabled:
            raise PQCUnavailable("liboqs has no ML-KEM-768")

    def keygen(self):
        k = self.oqs.KeyEncapsulation(self.name)
        return k.generate_keypair(), k

    def encaps(self, pk):
        with self.oqs.KeyEncapsulation(self.name) as k:
            return k.encap_secret(pk)

    def decaps(self, sk, ct):
        return sk.decap_secret(ct)


class _OqsSig:
    backend = "liboqs"

    def __init__(self):
        import oqs
        self.oqs = oqs
        enabled = oqs.get_enabled_sig_mechanisms()
        self.name = "ML-DSA-65" if "ML-DSA-65" in enabled else "Dilithium3"
        if self.name not in enabled:
            raise PQCUnavailable("liboqs has no ML-DSA-65")

    def keygen(self):
        s = self.oqs.Signature(self.name)
        return s.generate_keypair(), s

    def sign(self, sk, msg):
        return sk.sign(msg)

    def verify(self, pk, msg, sig):
        with self.oqs.Signature(self.name) as s:
            return bool(s.verify(msg, sig, pk))


class _PureKEM:
    name, backend = "ML-KEM-768", "kyber-py (pure Python)"

    def __init__(self):
        from kyber_py.ml_kem import ML_KEM_768
        self.k = ML_KEM_768

    def keygen(self):
        return self.k.keygen()

    def encaps(self, pk):
        ss, ct = self.k.encaps(pk)
        return ct, ss

    def decaps(self, sk, ct):
        return self.k.decaps(sk, ct)


class _PureSig:
    name, backend = "ML-DSA-65", "dilithium-py (pure Python)"

    def __init__(self):
        from dilithium_py.ml_dsa import ML_DSA_65
        self.s = ML_DSA_65

    def keygen(self):
        return self.s.keygen()

    def sign(self, sk, msg):
        return self.s.sign(sk, msg)

    def verify(self, pk, msg, sig):
        try:
            return bool(self.s.verify(pk, msg, sig))
        except Exception:
            return False


_ORDER = {"cryptography": (_CryptographyMLKEM, _CryptographyMLDSA),
          "liboqs": (_OqsKEM, _OqsSig), "pure": (_PureKEM, _PureSig)}


def load_pq(preferred: str = "auto", allow_pure: bool = False):
    """Return (kem, sig). Fails closed: raises PQCUnavailable, never falls back to classical."""
    if preferred == "auto":
        names = ["cryptography", "liboqs"] + (["pure"] if allow_pure else [])
    else:
        names = [preferred]
    errors = []
    for n in names:
        try:
            kem_cls, sig_cls = _ORDER[n]
            return kem_cls(), sig_cls()
        except Exception as e:
            errors.append(f"{n}: {type(e).__name__}: {e}")
    raise PQCUnavailable("No post-quantum backend available -> " + " | ".join(errors))
