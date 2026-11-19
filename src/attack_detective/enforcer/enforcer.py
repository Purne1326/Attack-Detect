"""Firewall enforcer: verify first, then apply. Anything that fails verification is dropped."""
import json
import time
from pathlib import Path

from .firewall_stub import FirewallStub


class Enforcer:
    def __init__(self, receiver, firewall: FirewallStub = None, log_path=None):
        self.receiver = receiver
        self.firewall = firewall or FirewallStub()
        self.log_path = Path(log_path) if log_path else None
        self.log = []

    def on_handshake(self, blob: bytes) -> bool:
        ok, reason = self.receiver.accept_handshake(blob)
        self._log({"event": "handshake", "accepted": ok, "reason": reason})
        return ok

    def on_alert(self, blob: bytes, now: float = None):
        ok, reason, alert = self.receiver.receive(blob, now)
        entry = {"event": "alert", "accepted": ok, "reason": reason, "bytes": len(blob)}
        if ok:
            d = alert["decision"]
            entry.update(flow_id=d["flow_id"], action=d["action"], score=d["score"],
                         techniques=[t["technique_id"] for t in d["techniques"]],
                         counter=alert["counter"],
                         firewall=self.firewall.apply(d["flow_id"], d["action"]))
        self._log(entry)
        return ok, reason

    def _log(self, entry):
        entry["time"] = time.time()
        self.log.append(entry)

    def save_log(self):
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("w", encoding="utf-8") as f:
                for e in self.log:
                    f.write(json.dumps(e) + "\n")
