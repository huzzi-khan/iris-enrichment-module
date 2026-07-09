import time
import threading
from iris_enrichment_module.config_loader import config


class EnrichmentCache:
    """
    Simple in-memory cache with TTL for enrichment results.

    Stores verdict dicts keyed by IOC value.
    Automatically expires entries after configured TTL.
    Thread-safe for use in IRIS worker environment.
    """

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()
        self._ttl = config.cache_ttl
        self._enabled = config.cache_enabled

    def get(self, ioc_value):
        """
        Return cached verdict for ioc_value if it exists
        and has not expired. Returns None if not cached.
        """
        if not self._enabled:
            return None

        with self._lock:
            entry = self._store.get(ioc_value)
            if entry is None:
                return None

            stored_at = entry.get("_cached_at", 0)
            age = time.time() - stored_at

            if age > self._ttl:
                # Expired — remove it
                del self._store[ioc_value]
                return None

            return entry.get("verdict")

    def set(self, ioc_value, verdict):
        """
        Store a verdict for ioc_value with current timestamp.
        """
        if not self._enabled:
            return

        with self._lock:
            self._store[ioc_value] = {
                "verdict": verdict,
                "_cached_at": time.time()
            }

    def invalidate(self, ioc_value):
        """
        Remove a specific entry from the cache.
        Useful if an IOC needs to be re-enriched immediately.
        """
        with self._lock:
            self._store.pop(ioc_value, None)

    def clear(self):
        """Clear all cached entries."""
        with self._lock:
            self._store.clear()

    def size(self):
        """Return number of cached entries."""
        with self._lock:
            return len(self._store)

    def cleanup_expired(self):
        """
        Remove all expired entries.
        Call this periodically to prevent memory growth.
        """
        now = time.time()
        with self._lock:
            expired = [
                k for k, v in self._store.items()
                if now - v.get("_cached_at", 0) > self._ttl
            ]
            for k in expired:
                del self._store[k]
        return len(expired)


# Single shared cache instance used across the whole module
cache = EnrichmentCache()