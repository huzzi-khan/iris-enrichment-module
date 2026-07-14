import time
import threading


class EnrichmentCache:
    """
    Simple in-memory cache with TTL for enrichment results.
    TTL and enabled flag passed at init — no config file needed.
    Thread-safe for use in IRIS worker environment.
    """

    def __init__(self, ttl_seconds=86400, enabled=True):
        self._store = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds
        self._enabled = enabled

    def get(self, ioc_value):
        if not self._enabled:
            return None
        with self._lock:
            entry = self._store.get(ioc_value)
            if entry is None:
                return None
            if time.time() - entry.get("_cached_at", 0) > self._ttl:
                del self._store[ioc_value]
                return None
            return entry.get("verdict")

    def set(self, ioc_value, verdict):
        if not self._enabled:
            return
        with self._lock:
            self._store[ioc_value] = {
                "verdict": verdict,
                "_cached_at": time.time()
            }

    def invalidate(self, ioc_value):
        with self._lock:
            self._store.pop(ioc_value, None)

    def clear(self):
        with self._lock:
            self._store.clear()

    def size(self):
        with self._lock:
            return len(self._store)