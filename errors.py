"""Typed errors that turn into something a model can act on.

Shodan's own error reporting is thin: the docs say "non-200 means error, the
body carries {"error": "..."}" and leave it there. In practice a 401 returns an
nginx HTML page, a 200 can carry an error body, and there is no documented
429 shape at all. So we classify here, once, and hand every tool handler a
payload that says what went wrong *and* what to do about it.

The ``next_step`` field is the point of this module. A model that reads
"insufficient credits" and stops is worse than one that reads "use shodan_count
instead, it is free and answers the same aggregate question".
"""

from __future__ import annotations

from typing import Any

# Shodan takes the API key as a query parameter, so it ends up in every URL we
# build. Anything that might reach a log, a traceback or a tool result goes
# through redact() first.
_REDACTED = "***"


def redact(text: str, api_key: str | None = None) -> str:
    """Strip the API key out of a URL or message."""
    if not text:
        return text
    out = text
    if api_key:
        out = out.replace(api_key, _REDACTED)
    # Catch the generic ``key=...`` form too, in case the key we hold is not
    # the one that produced this string (profile switches, stale clients).
    import re

    return re.sub(r"(?i)([?&]key=)[^&\s]+", r"\1" + _REDACTED, out)


class ShodanError(Exception):
    """Base for everything this plugin raises internally.

    Handlers catch these and call ``to_payload()``. Nothing else should
    escape a handler -- the registry contract is "return JSON, never raise".
    """

    kind = "error"
    next_step = ""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        next_step: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        if next_step:
            self.next_step = next_step
        self.details = details or {}

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "error": self.message,
            "error_kind": self.kind,
        }
        if self.status is not None:
            payload["http_status"] = self.status
        if self.next_step:
            payload["next_step"] = self.next_step
        if self.details:
            payload["details"] = self.details
        return payload


class ConfigError(ShodanError):
    """The plugin is misconfigured. Not the API's fault."""

    kind = "config"


class MissingKeyError(ConfigError):
    kind = "missing_api_key"
    next_step = (
        "Ask the user to run 'hermes shodan setup', or set SHODAN_API_KEY in "
        "~/.hermes/.env. Meanwhile shodan_host still works through the keyless "
        "InternetDB fallback, and shodan_cve needs no key at all."
    )


class AuthError(ShodanError):
    kind = "auth"
    next_step = (
        "The key was rejected. Run 'hermes shodan doctor' to confirm it, or "
        "generate a fresh one at https://account.shodan.io. Do not retry with "
        "the same key."
    )


class PlanError(ShodanError):
    """403, or a filter/endpoint the current plan cannot reach."""

    kind = "plan"
    next_step = (
        "This needs a higher Shodan plan. Drop the restricted part of the "
        "query and retry: 'vuln:' needs Small Business or above, 'tag:' needs "
        "Corporate or above, and bulk data, org management, trends and "
        "internet-wide scans need Enterprise."
    )


class CreditError(ShodanError):
    kind = "credits"
    next_step = (
        "Out of Shodan query credits. Switch to shodan_count, which answers "
        "totals and facet aggregates for free, or use shodan_host which is "
        "free on this account. Credits reset at the start of each month."
    )


class BudgetError(ShodanError):
    """Our own guard tripped, not Shodan's."""

    kind = "budget"
    next_step = (
        "The per-session credit budget set in config.yaml is spent. Use "
        "shodan_count (free) for aggregates, or tell the user to raise "
        "plugins.entries.shodan.budget.query_credits_per_session."
    )


class RateLimitError(ShodanError):
    kind = "rate_limit"
    next_step = (
        "Shodan allows one request per second and the plugin already paces "
        "itself. Wait a moment and retry once. If it keeps happening, the key "
        "is being used by something else at the same time."
    )


class NotFoundError(ShodanError):
    kind = "not_found"
    next_step = (
        "Shodan has no record for this. That is a real answer, not a failure: "
        "the host may simply have no exposed services in the last scan window. "
        "Do not retry the same lookup."
    )


class BadRequestError(ShodanError):
    kind = "bad_request"
    next_step = (
        "The request was malformed. Validate the search syntax with "
        "shodan_meta(action='validate_query') before retrying, and check the "
        "filter names against the shodan:query-syntax skill."
    )


class UpstreamError(ShodanError):
    """5xx, Cloudflare interstitials, anything transient on their side."""

    kind = "upstream"
    next_step = (
        "Shodan returned a server-side error. The plugin already retried with "
        "backoff. Wait and try once more, or continue without this data."
    )


class TransportError(ShodanError):
    """DNS failure, TLS failure, timeout. Never reached the API."""

    kind = "transport"
    next_step = (
        "Could not reach Shodan at all. Check network access and proxy "
        "settings, then run 'hermes shodan doctor'."
    )


class ScanBlockedError(ShodanError):
    """Local policy refused a scan. Deliberate, and not retryable."""

    kind = "scan_blocked"
    next_step = (
        "On-demand scanning is disabled by local policy. It is opt-in because "
        "it sends real probes to real hosts and spends scan credits. The user "
        "must set plugins.entries.shodan.scan.enabled: true (and profile: "
        "full) to allow it. Do not attempt to work around this."
    )


def classify_http(status: int, body_text: str, parsed: Any) -> ShodanError:
    """Map a non-2xx response onto the right error class.

    ``parsed`` is the decoded JSON body when the body was JSON, otherwise None.
    We look at the message text as well as the status because Shodan returns
    401 for a bad key, a missing key and an out-of-credits key on different
    endpoints, and the prose is the only thing that distinguishes them.
    """
    message = ""
    if isinstance(parsed, dict):
        message = str(parsed.get("error") or parsed.get("detail") or "").strip()
    if not message:
        stripped = (body_text or "").strip()
        # A 401 comes back as an nginx HTML page. The official python client
        # special-cases exactly this, and so do we.
        if stripped.startswith("<"):
            message = "Invalid API key" if status == 401 else f"HTTP {status}"
        else:
            message = stripped[:300] or f"HTTP {status}"

    lowered = message.lower()

    if "credit" in lowered:
        return CreditError(message, status=status)
    if "rate limit" in lowered or status == 429:
        return RateLimitError(message, status=status)
    if status == 401:
        return AuthError(message, status=status)
    if status == 403:
        return PlanError(message or "Access denied (403 Forbidden)", status=status)
    if status == 404:
        return NotFoundError(message, status=status)
    if status in (400, 422):
        return BadRequestError(message, status=status)
    if status >= 500:
        return UpstreamError(message, status=status)
    # Membership-gated filters answer 200-with-error more often than 403, so
    # the text is what gives them away.
    if "upgrade" in lowered or "membership" in lowered or "not available" in lowered:
        return PlanError(message, status=status)
    if status < 300:
        # A 2xx carrying an error body, having survived every check above, is
        # Shodan's way of saying the request itself was wrong.
        return BadRequestError(message, status=status)
    return ShodanError(message, status=status)
