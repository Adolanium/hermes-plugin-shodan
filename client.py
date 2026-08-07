"""The HTTP layer: one client, one rate limiter, one place that knows about keys.

Deliberately built on httpx rather than the official ``shodan`` package. That
library has been dormant since December 2023, is synchronous requests-based,
and collapses every failure into a single ``APIError(str)`` with the status
code thrown away -- which means an agent cannot tell "out of credits" from "bad
key" from "transient 502", and those three want three different reactions.
The API itself is about forty-five flat GETs with a query-string key. There is
very little to wrap and a lot to get right, so we do it ourselves.

httpx is already a pinned core dependency of Hermes, so this plugin adds no
install step of its own.
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from collections.abc import Mapping
from typing import Any

from . import config as config_mod
from .cache import TTLCache
from .errors import (
    MissingKeyError,
    ShodanError,
    TransportError,
    UpstreamError,
    classify_http,
    redact,
)

logger = logging.getLogger(__name__)

# --- API families ----------------------------------------------------------

REST = "https://api.shodan.io"
EXPLOITS = "https://exploits.shodan.io/api"
TRENDS = "https://trends.shodan.io"
INTERNETDB = "https://internetdb.shodan.io"
CVEDB = "https://cvedb.shodan.io"

# The keyless ones. InternetDB and CVEDB take no auth at all, which is what
# makes a no-key install still useful.
KEYLESS_BASES = {INTERNETDB, CVEDB}

_RETRY_STATUSES = {429, 500, 502, 503, 504}


class RateLimiter:
    """One request per second, enforced across threads.

    Shodan documents a 1 rps limit and returns no rate-limit headers, no
    Retry-After and no documented 429 shape, so there is nothing to react to
    after the fact. Pacing ahead of time is the only option.

    Threads matter here: Hermes runs subagents in the same process, and two of
    them reaching for Shodan at once would otherwise sail straight past the
    limit and get the shared key throttled.
    """

    def __init__(self, per_second: float = 1.0) -> None:
        self._interval = 1.0 / per_second if per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0
        self.total_waited = 0.0

    def acquire(self) -> float:
        """Block until the next request may go out. Returns seconds waited."""
        if self._interval <= 0:
            return 0.0
        with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait <= 0:
                self._next_allowed = now + self._interval
                return 0.0
            self._next_allowed += self._interval
        time.sleep(wait)
        self.total_waited += wait
        return wait

    def reconfigure(self, per_second: float) -> None:
        with self._lock:
            self._interval = 1.0 / per_second if per_second > 0 else 0.0


class ShodanClient:
    """Thin, careful wrapper around the Shodan HTTP surface."""

    def __init__(self, cfg: config_mod.ShodanConfig) -> None:
        self.cfg = cfg
        self.limiter = RateLimiter(cfg.rate_limit_per_second)
        self.cache = TTLCache(
            max_entries=cfg.cache.max_entries,
            ttl_seconds=cfg.cache.ttl_seconds if cfg.cache.enabled else 0,
        )
        self._client: Any = None
        self._client_lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------

    def _http(self) -> Any:
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    import httpx

                    self._client = httpx.Client(
                        timeout=self.cfg.timeout_seconds,
                        follow_redirects=True,
                        headers={
                            # Some Shodan paths sit behind Cloudflare and will
                            # serve a "Just a moment..." interstitial to a
                            # default client UA. A real one avoids that.
                            "User-Agent": self.cfg.user_agent,
                            "Accept": "application/json",
                        },
                    )
        return self._client

    def close(self) -> None:
        with self._client_lock:
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None

    # -- requests -----------------------------------------------------------

    def _cache_key(self, method: str, base: str, path: str, params: Mapping[str, Any]) -> str:
        safe = {k: v for k, v in sorted(params.items()) if k != "key"}
        return f"{method}:{base}{path}?{json.dumps(safe, sort_keys=True, default=str)}"

    def request(
        self,
        method: str,
        path: str,
        *,
        base: str = REST,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: Any | None = None,
        cacheable: bool = False,
    ) -> Any:
        """Perform a request and return decoded JSON.

        Raises a ShodanError subclass on anything that is not a clean success.
        Handlers catch those and turn them into payloads -- nothing raises out
        of a tool.
        """
        params = dict(params or {})
        needs_key = base not in KEYLESS_BASES

        if needs_key:
            if not self.cfg.api_key:
                raise MissingKeyError(
                    f"No Shodan API key configured (looked in ${self.cfg.api_key_env})."
                )
            params["key"] = self.cfg.api_key

        cache_key = ""
        if cacheable and method == "GET" and self.cfg.cache.enabled:
            cache_key = self._cache_key(method, base, path, params)
            hit = self.cache.get(cache_key)
            if hit is not None:
                return hit

        url = f"{base}{path}"
        result = self._send_with_retries(method, url, params, data, json_body)

        if cache_key:
            self.cache.set(cache_key, result)
        return result

    def _send_with_retries(
        self,
        method: str,
        url: str,
        params: dict[str, Any],
        data: dict[str, Any] | None,
        json_body: Any | None,
    ) -> Any:
        import httpx

        attempts = self.cfg.retries + 1
        last_error: ShodanError | None = None

        for attempt in range(attempts):
            self.limiter.acquire()
            try:
                response = self._http().request(
                    method, url, params=params, data=data, json=json_body
                )
            except httpx.TimeoutException as exc:
                last_error = TransportError(
                    f"Request timed out after {self.cfg.timeout_seconds:.0f}s: "
                    f"{redact(str(exc), self.cfg.api_key)}"
                )
            except httpx.HTTPError as exc:
                last_error = TransportError(
                    f"Network error reaching Shodan: {redact(str(exc), self.cfg.api_key)}"
                )
            else:
                parsed, body_text = _decode(response)

                if response.status_code < 300:
                    # A 200 can still carry {"error": ...}. Treat it as the
                    # failure it is rather than handing the model a body it
                    # will misread as data.
                    if isinstance(parsed, dict) and parsed.get("error"):
                        raise classify_http(response.status_code, body_text, parsed)
                    if parsed is None:
                        raise UpstreamError(
                            "Shodan returned a non-JSON success body "
                            f"({len(body_text)} bytes). This usually means a "
                            "Cloudflare interstitial rather than real data.",
                            status=response.status_code,
                        )
                    return parsed

                error = classify_http(response.status_code, body_text, parsed)
                if response.status_code not in _RETRY_STATUSES:
                    raise error
                last_error = error

            if attempt < attempts - 1:
                # Exponential with jitter. The jitter matters because
                # subagents that started together would otherwise retry in
                # lockstep and hit the same wall again.
                delay = (2**attempt) + random.uniform(0, 0.4)
                logger.debug(
                    "shodan: retrying %s after %s (attempt %d/%d, sleeping %.1fs)",
                    redact(url, self.cfg.api_key),
                    last_error.kind if last_error else "unknown error",
                    attempt + 1,
                    attempts,
                    delay,
                )
                time.sleep(delay)

        raise last_error or UpstreamError("Request failed for an unknown reason.")

    # -- convenience --------------------------------------------------------

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self.request("DELETE", path, **kwargs)


def _decode(response: Any) -> tuple[Any, str]:
    """Return ``(parsed_json_or_None, raw_text)``.

    Shodan answers 401 with an nginx HTML page, so "the body is JSON" is not a
    safe assumption anywhere, including on success.
    """
    text = ""
    try:
        text = response.text or ""
    except Exception:
        text = ""
    try:
        return response.json(), text
    except Exception:
        return None, text


# --- process-wide client ---------------------------------------------------

_client: ShodanClient | None = None
_client_fingerprint: tuple | None = None
_singleton_lock = threading.Lock()


def _fingerprint(cfg: config_mod.ShodanConfig) -> tuple:
    """What has to change before the live client is rebuilt."""
    return (
        cfg.api_key,
        cfg.timeout_seconds,
        cfg.user_agent,
        cfg.rate_limit_per_second,
        cfg.retries,
        cfg.cache.enabled,
        cfg.cache.ttl_seconds,
        cfg.cache.max_entries,
    )


def get_client(cfg: config_mod.ShodanConfig | None = None) -> ShodanClient:
    """Return the shared client, rebuilding it when config changed.

    Rebuilding on a fingerprint change is what makes 'hermes shodan setup' take
    effect without restarting the gateway.
    """
    global _client, _client_fingerprint
    cfg = cfg or config_mod.load()
    fp = _fingerprint(cfg)
    with _singleton_lock:
        if _client is None or _client_fingerprint != fp:
            if _client is not None:
                _client.close()
            _client = ShodanClient(cfg)
            _client_fingerprint = fp
        else:
            # Same connection pool, refreshed view of the non-transport
            # settings (verbosity, budgets, scan policy).
            _client.cfg = cfg
        return _client


def reset_client() -> None:
    global _client, _client_fingerprint
    with _singleton_lock:
        if _client is not None:
            _client.close()
        _client = None
        _client_fingerprint = None
