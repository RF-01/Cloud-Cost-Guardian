"""Per-visitor rate limits for the dashboard (task #43, design §6.3, CONTRACT §4.11).

Behind CloudFront every connection comes from a CloudFront server, so the visitor is identified by the IP in
`CloudFront-Viewer-Address` ("<ip>:<port>", IPv6 too: "2001:db8::1:443"), which CloudFront sets itself and the
origin request policy forwards. The header is trustworthy only because nothing but our distribution reaches the
server (security group + secret origin header). Missing header -> one shared key "unknown".

`SlidingWindowLimiter` keeps, per visitor, the times of the hits inside the window (in memory: one server).
Memory is bounded: expired visitors are pruned, and the table holds at most `max_visitors` (when full, the
visitor idle the longest is dropped). Thread-safe (one lock; waitress runs several worker threads).
"""

import math
import threading
import time
from collections import OrderedDict, deque

VIEWER_ADDRESS_HEADER = "CloudFront-Viewer-Address"
UNKNOWN_VISITOR = "unknown"
MAX_VISITORS = 10_000
MAX_KEY_CHARS = 64        # longest IPv6 text form is 45 characters
PRUNE_EVERY = 256         # full sweep of expired visitors every N hits (and whenever the table is full)


def visitor_key(headers):
    """The visitor's IP from CloudFront-Viewer-Address, or "unknown"."""
    raw = (headers.get(VIEWER_ADDRESS_HEADER) or "").strip()
    if not raw:
        return UNKNOWN_VISITOR
    ip = raw.rsplit(":", 1)[0] if ":" in raw else raw
    ip = ip.strip("[]").strip()
    return ip[:MAX_KEY_CHARS] or UNKNOWN_VISITOR


class SlidingWindowLimiter:
    """At most `limit` hits per `window` seconds per key (sliding window).

    hit(key) -> (allowed, retry_after_seconds). A refused hit is not recorded, so a visitor who waits
    `retry_after` seconds is allowed again.
    """

    def __init__(self, limit, window, max_visitors=MAX_VISITORS, clock=time.monotonic):
        if limit < 1 or window <= 0 or max_visitors < 1:
            raise ValueError("limit, window and max_visitors must be positive")
        self.limit = int(limit)
        self.window = float(window)
        self.max_visitors = int(max_visitors)
        self._clock = clock
        self._lock = threading.Lock()
        self._hits = OrderedDict()      # key -> deque of hit times; order = least recently active first
        self._since_prune = 0

    def __len__(self):
        with self._lock:
            return len(self._hits)

    def _prune(self, now):
        cutoff = now - self.window
        for key in [k for k, q in self._hits.items() if not q or q[-1] <= cutoff]:
            del self._hits[key]
        self._since_prune = 0

    def hit(self, key):
        now = self._clock()
        cutoff = now - self.window
        with self._lock:
            self._since_prune += 1
            if self._since_prune >= PRUNE_EVERY:
                self._prune(now)
            q = self._hits.get(key)
            if q is None:
                if len(self._hits) >= self.max_visitors:
                    self._prune(now)
                    while len(self._hits) >= self.max_visitors:
                        self._hits.popitem(last=False)          # drop the visitor idle the longest
                q = self._hits[key] = deque()
            else:
                self._hits.move_to_end(key)
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.limit:
                return False, max(1, math.ceil(q[0] + self.window - now))
            q.append(now)
            return True, 0
