"""End-to-end run: decisions (from B) -> sign + encrypt -> enforcer verifies -> firewall stub."""
import time
from typing import List

from attack_detective.enforcer.enforcer import Enforcer
from attack_detective.pqc.channel import make_pair


def run(decisions: List[dict], mode: str = "hybrid", backend: str = "auto",
        allow_pure: bool = False, log_path=None) -> dict:
    sender, receiver = make_pair(mode, backend, allow_pure)
    enforcer = Enforcer(receiver, log_path=log_path)
    hs = sender.handshake()
    if not enforcer.on_handshake(hs):
        raise RuntimeError("handshake rejected")
    t0 = time.perf_counter()
    sizes, accepted = [], 0
    for d in decisions:
        blob = sender.seal(d)                 # in a deployment this travels over the network
        sizes.append(len(blob))
        ok, _ = enforcer.on_alert(blob)
        accepted += ok
    elapsed = time.perf_counter() - t0
    enforcer.save_log()
    return {"mode": mode, "alerts": len(decisions), "accepted": accepted,
            "handshake_bytes": len(hs), "mean_alert_bytes": sum(sizes) / max(len(sizes), 1),
            "seconds": elapsed, "alerts_per_second": len(decisions) / elapsed if elapsed else 0.0,
            "firewall": enforcer.firewall.summary()}
