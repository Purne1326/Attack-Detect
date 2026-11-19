"""Step 10: cost of each mode (classical / hybrid / pq): time per operation, bytes, alerts per second."""
import platform
import statistics as st
import time

import pandas as pd

from common import Dirs, banner, load_cfg, sample_decisions
from attack_detective.pqc.backend import Ed25519Sig, X25519KEM, load_pq
from attack_detective.pqc.channel import Keys, algorithms, make_pair
from attack_detective.pqc.primitives import canonical


def timed(fn, n):
    out = []
    for _ in range(n):
        t = time.perf_counter_ns()
        fn()
        out.append((time.perf_counter_ns() - t) / 1e6)
    return st.mean(out), st.stdev(out)


def primitives(cfg, n, decisions):
    rows = []
    kem_pq, sig_pq = load_pq(cfg["backend"], cfg["allow_pure_python"])
    msg = canonical(decisions[0])
    for kem in (X25519KEM(), kem_pq):
        pk, sk = kem.keygen()
        ct, _ = kem.encaps(pk)
        for op, fn in (("keygen", kem.keygen), ("encapsulate", lambda: kem.encaps(pk)),
                       ("decapsulate", lambda: kem.decaps(sk, ct))):
            m, s = timed(fn, n)
            rows.append({"algorithm": kem.name, "backend": kem.backend, "operation": op,
                         "mean_ms": m, "sd_ms": s, "public_key_B": len(pk), "ct_or_sig_B": len(ct)})
    for sig in (Ed25519Sig(), sig_pq):
        pk, sk = sig.keygen()
        sg = sig.sign(sk, msg)
        for op, fn in (("keygen", sig.keygen), ("sign", lambda: sig.sign(sk, msg)),
                       ("verify", lambda: sig.verify(pk, msg, sg))):
            m, s = timed(fn, n)
            rows.append({"algorithm": sig.name, "backend": sig.backend, "operation": op,
                         "mean_ms": m, "sd_ms": s, "public_key_B": len(pk), "ct_or_sig_B": len(sg)})
    return pd.DataFrame(rows)


def channel(cfg, n, decisions):
    rows = []
    d0 = decisions[0]
    plain = len(canonical({"version": 1, "alert_id": "x" * 36, "counter": 1, "timestamp": 0.0,
                           "decision": d0}))
    for mode in ("classical", "hybrid", "pq"):
        kems, sigs = algorithms(mode, cfg["backend"], cfg["allow_pure_python"])
        keygen = timed(lambda: Keys(kems, sigs), max(10, n // 10))
        s, r = make_pair(mode, cfg["backend"], cfg["allow_pure_python"], 1e9)
        hs_send = timed(s.handshake, n)
        hs = s.handshake()
        hs_recv = timed(lambda: r.accept_handshake(hs), n)
        blobs = []
        seal = timed(lambda: blobs.append(s.seal(d0)), n)
        it = iter(blobs)
        open_ = timed(lambda: r.receive(next(it)), n)
        # throughput over many different decisions (seal + verify + apply)
        s2, r2 = make_pair(mode, cfg["backend"], cfg["allow_pure_python"], 1e9)
        r2.accept_handshake(s2.handshake())
        batch = (decisions * (cfg["bench_alerts"] // len(decisions) + 1))[:cfg["bench_alerts"]]
        t = time.perf_counter()
        ok = sum(r2.receive(s2.seal(d))[0] for d in batch)
        secs = time.perf_counter() - t
        rows.append({"mode": mode, "keygen_ms": keygen[0], "handshake_send_ms": hs_send[0],
                     "handshake_send_sd": hs_send[1], "handshake_recv_ms": hs_recv[0],
                     "handshake_recv_sd": hs_recv[1], "seal_ms": seal[0], "seal_sd": seal[1],
                     "open_ms": open_[0], "open_sd": open_[1], "added_latency_ms": seal[0] + open_[0],
                     "handshake_bytes": len(hs), "alert_bytes": len(blobs[0]), "plaintext_bytes": plain,
                     "overhead_bytes": len(blobs[0]) - plain, "alerts_per_s": ok / secs})
    return pd.DataFrame(rows)


def main():
    banner("Step 10 - post-quantum cost benchmark")
    full = load_cfg()
    cfg, res = full["pqc"], Dirs(full).res_pqc
    n = cfg["bench_runs"]
    decisions = sample_decisions(full)
    hw = (f"{platform.system()} {platform.release()} | {platform.processor() or platform.machine()}"
          f" | Python {platform.python_version()}")
    print("Hardware:", hw)
    (res / "hardware.txt").write_text(hw + "\nAdd: CPU model, RAM, power mode\n", encoding="utf-8")
    p = primitives(cfg, n, decisions).round(4)
    p.to_csv(res / "pqc_primitives.csv", index=False)
    print(p.to_string(index=False))
    c = channel(cfg, n, decisions).round(4)
    c.to_csv(res / "pqc_benchmark.csv", index=False)
    print(c.T.to_string(header=False))


if __name__ == "__main__":
    main()
