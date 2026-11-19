"""In-memory firewall. Prints the Windows command it WOULD run; never changes the real firewall."""


class FirewallStub:
    def __init__(self):
        self.rules = {}                       # flow_id -> action

    def apply(self, flow_id: int, action: str) -> str:
        self.rules[flow_id] = action
        if action == "BLOCK":
            return (f'netsh advfirewall firewall add rule name="AD-block-{flow_id}" '
                    f'dir=in action=block remoteip=<source-ip-of-flow-{flow_id}>   (dry run)')
        if action == "MONITOR":
            return f"log and watch flow {flow_id}"
        return "no rule"

    def summary(self) -> dict:
        out = {"ALLOW": 0, "MONITOR": 0, "BLOCK": 0}
        for a in self.rules.values():
            out[a] += 1
        return out
