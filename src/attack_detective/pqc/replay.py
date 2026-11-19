"""Replay protection: counters must strictly increase per session; timestamps must be fresh."""
import time


class ReplayGuard:
    def __init__(self, window_s: float = 30.0):
        self.window_s = window_s
        self.last = {}                      # session -> highest counter accepted

    def check(self, session: str, counter: int, timestamp: float, now: float = None):
        """Return None if OK, otherwise the rejection reason."""
        now = time.time() if now is None else now
        if counter <= self.last.get(session, 0):
            return "replay"
        if abs(now - timestamp) > self.window_s:
            return "stale_timestamp"
        self.last[session] = counter
        return None
