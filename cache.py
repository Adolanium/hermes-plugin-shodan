"""A small TTL + LRU cache for idempotent, free Shodan lookups.

Agents repeat themselves. They look up the same IP three times while reasoning
about it, re-fetch the filter list before every query, and re-check the account
credits after each call. None of that data changes minute to minute, so caching
it turns a chatty session into a quiet one.

Only free, idempotent endpoints are cached (host lookups, InternetDB, CVEDB,
the metadata endpoints). Search and count are not, because a stale total is
worse than a slow one, and scans and alerts obviously are not.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any


class TTLCache:
    """Thread-safe. Subagents share one process, so this matters."""

    def __init__(self, max_entries: int = 512, ttl_seconds: int = 900) -> None:
        self._max_entries = max(1, max_entries)
        self._ttl = max(0, ttl_seconds)
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
        if self._ttl == 0:
            return None
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if item is None:
                self.misses += 1
                return None
            expires_at, value = item
            if expires_at < now:
                del self._data[key]
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        if self._ttl == 0:
            return
        with self._lock:
            self._data[key] = (time.monotonic() + self._ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max_entries:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> dict:
        with self._lock:
            total = self.hits + self.misses
            return {
                "entries": len(self._data),
                "max_entries": self._max_entries,
                "ttl_seconds": self._ttl,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / total, 3) if total else 0.0,
            }

    def reconfigure(self, max_entries: int, ttl_seconds: int) -> None:
        """Apply new limits without losing what is still valid."""
        with self._lock:
            self._max_entries = max(1, max_entries)
            self._ttl = max(0, ttl_seconds)
            while len(self._data) > self._max_entries:
                self._data.popitem(last=False)
