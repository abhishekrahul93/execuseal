"""Small fixed-window limiter for a single gateway process."""

import threading
from dataclasses import dataclass
from time import monotonic


@dataclass(slots=True)
class Window:
    started: float
    requests: int


class RateLimiter:
    def __init__(self, requests: int, window_seconds: int) -> None:
        if requests < 1 or window_seconds < 1:
            raise ValueError("rate limit and window must be positive")
        self.requests = requests
        self.window_seconds = window_seconds
        self._windows: dict[str, Window] = {}
        self._lock = threading.Lock()

    def allow(self, identity: str, now: float | None = None) -> tuple[bool, int]:
        current = monotonic() if now is None else now
        with self._lock:
            window = self._windows.get(identity)
            if window is None or current - window.started >= self.window_seconds:
                self._windows[identity] = Window(current, 1)
                return True, self.requests - 1
            if window.requests >= self.requests:
                return False, 0
            window.requests += 1
            return True, self.requests - window.requests
