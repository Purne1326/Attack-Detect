"""Step 09: attack the secure channel. Every attack must be REJECTED (fail closed); the control must pass."""
import time

import pandas as pd

from common import Dirs, banner, load_cfg, sample_decisions
from attack_detective.pqc.channel import Sender, algorithms, make_pair
from attack_detective.pqc.primitives import pack, unpack


def flip(blob: bytes, pos: int) -> bytes:
    b = bytearray(blob)
    b[pos] ^= 0x01
    return bytes(b)


def run_mode(mode, cfg, decision):
    rows = []
    rec = lambda name, ok, reason, expect: rows.append(
        {"mode": mode, "test": name, "expected": expect, "result": "accepted" if ok else "rejected",
         "reason": reason, "pass": (ok and expect == "accepted") or (not ok and expect == "rejected")})
    new = lambda: make_pair(mode, cfg["backend"], cfg["allow_pure_python"], cfg["replay_window_seconds"])

    s, r = new()
    ok, why = r.accept_handshake(s.handshake())
    rec("valid handshake (control)", ok, why, "accepted")
    good = s.seal(decision)
    ok, why, _ = r.receive(good)
    rec("valid alert (control)", ok, why, "accepted")
    ok, why, _ = r.receive(good)
    rec("replayed alert", ok, why, "rejected")

    header, ct = unpack(s.seal(decision))
    ok, why, _ = r.receive(pack([header, flip(ct, len(ct) // 2)]))
    rec("modified ciphertext", ok, why, "rejected")
    hdr = header.replace(b'"counter":', b'"counter":9')
    ok, why, _ = r.receive(pack([hdr, ct]))
    rec("modified header (counter)", ok, why, "rejected")

    ok, why, _ = r.receive(s.seal(decision, sign=False))
    rec("unsigned alert", ok, why, "rejected")

    ok, why, _ = r.receive(s.seal(decision), now=time.time() + 10 * cfg["replay_window_seconds"])
    rec("stale timestamp (delayed alert)", ok, why, "rejected")

    kems, sigs = algorithms(mode, cfg["backend"], cfg["allow_pure_python"])
    attacker = Sender(mode, kems, sigs, s.kem_pubs, [sig.keygen()[1] for sig in sigs])
    attacker.key, attacker.session, attacker.counter = s.key, s.session, s.counter + 100
    ok, why, _ = r.receive(attacker.seal(decision))
    rec("alert signed with wrong key", ok, why, "rejected")
    ok, why = r.accept_handshake(attacker.handshake())
    rec("handshake signed with wrong key", ok, why, "rejected")

    ok, why, _ = r.receive(s.seal(decision)[:-7])
    rec("truncated message", ok, why, "rejected")

    other, _ = new()
    other.handshake()
    ok, why, _ = r.receive(other.seal(decision))
    rec("unknown session", ok, why, "rejected")

    if mode != "classical":
        cs, _ = make_pair("classical")
        ok, why = r.accept_handshake(cs.handshake())
        rec("downgrade to classical", ok, why, "rejected")
    return rows


def main():
    banner("Step 09 - security tests (every attack must be rejected)")
    full = load_cfg()
    cfg, res = full["pqc"], Dirs(full).res_pqc
    decision = sample_decisions(full)[0]
    rows = []
    for mode in ("classical", "hybrid", "pq"):
        rows += run_mode(mode, cfg, decision)
    df = pd.DataFrame(rows)
    df.to_csv(res / "security_tests.csv", index=False)
    print(df.to_string(index=False))
    print(f"\n{df['pass'].sum()}/{len(df)} tests behaved as expected")
    if not df["pass"].all():
        raise SystemExit("SECURITY TEST FAILURE - fix before continuing")


if __name__ == "__main__":
    main()
