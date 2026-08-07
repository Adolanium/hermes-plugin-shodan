"""Configuration, resolved once and cached briefly.

Everything lives under ``plugins.entries.shodan`` in config.yaml. That is the
namespace Hermes sanctions for per-plugin settings (hermes_cli/plugins.py:492).
A top-level ``shodan:`` key would work today but trips the unknown-root warning
in hermes_cli/config.py, so we stay where we belong.

Every setting has a default that works. An install where the only thing the
user did was paste an API key is a fully functional install.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

PLUGIN_ID = "shodan"

# --- tool profiles ---------------------------------------------------------
#
# Registering all 12 tools by default would cost every session a few thousand
# tokens of schema for capability most sessions never touch. The core seven
# are read-only, cheap and cover the overwhelming majority of real use. The
# rest -- scanning, alerts, the community dork directory, exploits, trends --
# are opt-in through ``profile: full``.

CORE_TOOLS: set[str] = {
    "shodan_host",
    "shodan_search",
    "shodan_count",
    "shodan_dns",
    "shodan_cve",
    "shodan_account",
    "shodan_meta",
}

FULL_ONLY_TOOLS: set[str] = {
    "shodan_scan",
    "shodan_alert",
    "shodan_exploits",
    "shodan_query",
    "shodan_trends",
}

ALL_TOOLS: set[str] = CORE_TOOLS | FULL_ONLY_TOOLS

# Tools that work with no API key at all, through InternetDB and CVEDB.
KEYLESS_TOOLS: set[str] = {"shodan_cve"}

VALID_PROFILES = ("core", "full")
VALID_VERBOSITY = ("summary", "detail", "raw")

DEFAULT_USER_AGENT = (
    "hermes-plugin-shodan/0.1.0 (+https://github.com/Adolanium/hermes-plugin-shodan)"
)


@dataclass(frozen=True)
class CacheConfig:
    enabled: bool = True
    ttl_seconds: int = 900
    max_entries: int = 512


@dataclass(frozen=True)
class BudgetConfig:
    query_credits_per_session: int = 50
    scan_credits_per_session: int = 0


@dataclass(frozen=True)
class ScanConfig:
    enabled: bool = False
    allowlist: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ShodanConfig:
    api_key: str | None = None
    api_key_env: str = "SHODAN_API_KEY"
    profile: str = "core"
    verbosity: str = "summary"
    max_result_chars: int = 24_000
    rate_limit_per_second: float = 1.0
    timeout_seconds: float = 30.0
    retries: int = 2
    internetdb_fallback: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    cache: CacheConfig = field(default_factory=CacheConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    tools_enabled: list[str] = field(default_factory=list)
    tools_disabled: list[str] = field(default_factory=list)

    @property
    def has_key(self) -> bool:
        return bool(self.api_key)

    def visible_tools(self) -> set[str]:
        """Which tool names should be exposed to the model right now.

        Profile picks the baseline, then explicit enable/disable lists win.
        A tool named in ``tools.enabled`` shows up even under the core
        profile, which is how you get exactly one extra tool without taking
        all five.
        """
        base = set(CORE_TOOLS) if self.profile == "core" else set(ALL_TOOLS)
        for name in self.tools_enabled:
            if name in ALL_TOOLS:
                base.add(name)
        for name in self.tools_disabled:
            base.discard(name)
        return base


# --- loading ---------------------------------------------------------------

_lock = threading.Lock()
_cached: ShodanConfig | None = None
_cached_at: float = 0.0
# Short enough that editing config.yaml feels live, long enough that a burst of
# tool calls does not re-read and re-parse YAML a dozen times.
_TTL_SECONDS = 10.0


def _raw_plugin_config() -> dict[str, Any]:
    """Read ``plugins.entries.shodan`` out of config.yaml.

    Returns an empty dict when Hermes config is unavailable, which is the case
    in the test suite and in any standalone use of these modules.
    """
    try:
        from hermes_cli.config import load_config
    except Exception:
        return {}
    try:
        cfg = load_config() or {}
    except Exception:
        return {}
    entries = (cfg.get("plugins") or {}).get("entries") or {}
    entry = entries.get(PLUGIN_ID)
    return entry if isinstance(entry, dict) else {}


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _as_int(value: Any, default: int, *, minimum: int = 0) -> int:
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float, *, minimum: float = 0.0) -> float:
    try:
        return max(minimum, float(value))
    except (TypeError, ValueError):
        return default


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _choice(value: Any, allowed: tuple, default: str) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in allowed else default


def resolve_api_key(raw: dict[str, Any]) -> tuple[str | None, str]:
    """Find the API key. Returns ``(key, env_var_name)``.

    Order: the env var named by ``api_key_env`` (default SHODAN_API_KEY), then
    a literal ``api_key`` in config.yaml. The env var wins because that is
    where ``hermes plugins install`` puts it and where secret sources inject
    it. Putting a key straight in config.yaml works but is the worse habit, so
    it is the fallback rather than the primary.
    """
    env_name = str(raw.get("api_key_env") or "SHODAN_API_KEY").strip() or "SHODAN_API_KEY"
    from_env = os.environ.get(env_name, "").strip()
    if from_env:
        return from_env, env_name
    literal = str(raw.get("api_key") or "").strip()
    if literal:
        return literal, env_name
    return None, env_name


def load(refresh: bool = False) -> ShodanConfig:
    """Return the effective config, cached for a few seconds."""
    global _cached, _cached_at
    with _lock:
        now = time.monotonic()
        if not refresh and _cached is not None and (now - _cached_at) < _TTL_SECONDS:
            return _cached

        raw = _raw_plugin_config()
        api_key, env_name = resolve_api_key(raw)

        cache_raw = raw.get("cache") if isinstance(raw.get("cache"), dict) else {}
        budget_raw = raw.get("budget") if isinstance(raw.get("budget"), dict) else {}
        scan_raw = raw.get("scan") if isinstance(raw.get("scan"), dict) else {}
        tools_raw = raw.get("tools") if isinstance(raw.get("tools"), dict) else {}

        cfg = ShodanConfig(
            api_key=api_key,
            api_key_env=env_name,
            profile=_choice(
                os.environ.get("HERMES_SHODAN_PROFILE") or raw.get("profile"),
                VALID_PROFILES,
                "core",
            ),
            verbosity=_choice(
                os.environ.get("HERMES_SHODAN_VERBOSITY") or raw.get("verbosity"),
                VALID_VERBOSITY,
                "summary",
            ),
            max_result_chars=_as_int(raw.get("max_result_chars"), 24_000, minimum=2_000),
            rate_limit_per_second=_as_float(raw.get("rate_limit_per_second"), 1.0, minimum=0.0),
            timeout_seconds=_as_float(raw.get("timeout_seconds"), 30.0, minimum=1.0),
            retries=_as_int(raw.get("retries"), 2, minimum=0),
            internetdb_fallback=_as_bool(raw.get("internetdb_fallback"), True),
            user_agent=str(raw.get("user_agent") or DEFAULT_USER_AGENT),
            cache=CacheConfig(
                enabled=_as_bool(cache_raw.get("enabled"), True),
                ttl_seconds=_as_int(cache_raw.get("ttl_seconds"), 900, minimum=0),
                max_entries=_as_int(cache_raw.get("max_entries"), 512, minimum=1),
            ),
            budget=BudgetConfig(
                query_credits_per_session=_as_int(
                    budget_raw.get("query_credits_per_session"), 50, minimum=0
                ),
                scan_credits_per_session=_as_int(
                    budget_raw.get("scan_credits_per_session"), 0, minimum=0
                ),
            ),
            scan=ScanConfig(
                enabled=_as_bool(scan_raw.get("enabled"), False),
                allowlist=_as_str_list(scan_raw.get("allowlist")),
            ),
            tools_enabled=_as_str_list(tools_raw.get("enabled")),
            tools_disabled=_as_str_list(tools_raw.get("disabled")),
        )

        _cached = cfg
        _cached_at = now
        return cfg


def reset() -> None:
    """Drop the cache. Used by the CLI after writing config, and by tests."""
    global _cached, _cached_at
    with _lock:
        _cached = None
        _cached_at = 0.0
