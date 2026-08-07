"""Shared plumbing every tool handler sits on.

The registry contract is strict and worth restating: a handler takes
``(args: dict, **kwargs)``, returns a JSON string, and never raises. A handler
that raises takes the turn down with it. So every one of them is wrapped here
once, rather than trusting twelve separate try/except blocks to stay correct.
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable
from typing import Any

from . import config as config_mod
from .budget import tracker
from .client import get_client
from .errors import ShodanError, redact
from .shaping import envelope, fit

logger = logging.getLogger(__name__)


def session_id(kwargs: dict[str, Any]) -> str | None:
    """Which budget bucket this call belongs to.

    Hermes passes ``task_id`` through to handlers when it has one, so gateway
    conversations and subagents get their own ledgers instead of sharing a
    single global counter and starving each other.
    """
    for key in ("task_id", "session_id", "session_key"):
        value = kwargs.get(key)
        if value:
            return str(value)
    return None


def tool(fn: Callable[..., dict[str, Any]]) -> Callable[..., str]:
    """Wrap a handler so it always returns JSON and never raises."""

    @functools.wraps(fn)
    def wrapper(args: dict[str, Any], **kwargs: Any) -> str:
        args = args if isinstance(args, dict) else {}
        try:
            result = fn(args, **kwargs)
        except ShodanError as exc:
            result = exc.to_payload()
        except Exception as exc:  # pragma: no cover - the safety net
            logger.exception("shodan tool %s failed unexpectedly", fn.__name__)
            key = None
            try:
                key = config_mod.load().api_key
            except Exception:
                pass
            result = {
                "ok": False,
                "error": redact(f"{type(exc).__name__}: {exc}", key),
                "error_kind": "internal",
                "next_step": (
                    "This is a bug in the Shodan plugin rather than a problem "
                    "with the request. Report it at "
                    "https://github.com/Adolanium/hermes-plugin-shodan/issues "
                    "and continue without this data."
                ),
            }
        try:
            return json.dumps(result, default=str)
        except Exception:
            return json.dumps({"ok": False, "error": "Result was not serializable."})

    return wrapper


def verbosity_for(args: dict[str, Any], cfg: config_mod.ShodanConfig) -> str:
    """Per-call verbosity, falling back to the configured default."""
    requested = str(args.get("verbosity") or "").strip().lower()
    if requested in config_mod.VALID_VERBOSITY:
        return requested
    return cfg.verbosity


def credit_block(
    cfg: config_mod.ShodanConfig,
    sess: str | None,
    *,
    spent_now: int = 0,
    account: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The credit footer attached to every credit-costing result.

    Showing the balance falling is what makes an agent ration itself. A model
    that only finds out when the budget refuses it has already wasted the
    turn planning around data it will not get.
    """
    led = tracker.ledger(sess)
    block: dict[str, Any] = {
        "spent_by_this_call": spent_now,
        **led.snapshot(
            cfg.budget.query_credits_per_session,
            cfg.budget.scan_credits_per_session,
        ),
    }
    if account:
        block["account_query_credits"] = account.get("query_credits")
        block["account_scan_credits"] = account.get("scan_credits")
    return block


def spend(
    cost: int,
    cfg: config_mod.ShodanConfig,
    sess: str | None,
    kind: str = "query",
) -> None:
    """Check the budget, then record the spend. Raises BudgetError if refused."""
    limit = (
        cfg.budget.scan_credits_per_session
        if kind == "scan"
        else cfg.budget.query_credits_per_session
    )
    tracker.check(cost, limit=limit, session_id=sess, kind=kind)
    tracker.spend(cost, session_id=sess, kind=kind)


def ok(
    data: dict[str, Any],
    cfg: config_mod.ShodanConfig,
    *,
    credits: dict[str, Any] | None = None,
    source: str = "shodan",
) -> dict[str, Any]:
    return envelope(data, max_chars=cfg.max_result_chars, credits=credits, source=source)


def small(data: dict[str, Any], cfg: config_mod.ShodanConfig) -> dict[str, Any]:
    """For results that are already compact. Still fitted, never shaped."""
    return fit({"ok": True, **data}, cfg.max_result_chars)


# --- input helpers ---------------------------------------------------------


def split_list(value: Any, limit: int = 64) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value]
    else:
        items = [part.strip() for part in str(value).split(",")]
    return [item for item in items if item][:limit]


def looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def resolve_hostnames(names: list[str], cfg: config_mod.ShodanConfig) -> dict[str, str]:
    """Turn hostnames into IPs via Shodan's free resolver.

    Free, so there is no reason to make the model do this itself. Returns a
    partial map on partial failure rather than nothing at all.
    """
    if not names or not cfg.has_key:
        return {}
    try:
        client = get_client(cfg)
        result = client.get("/dns/resolve", params={"hostnames": ",".join(names)}, cacheable=True)
        return {k: v for k, v in (result or {}).items() if v}
    except ShodanError:
        return {}


def in_allowlist(target: str, allowlist: list[str]) -> bool:
    """Is this scan target inside one of the operator's permitted ranges?

    An empty allowlist means no range restriction. That is deliberate: the
    scan.enabled switch is the real gate, and demanding a CIDR list on top of
    it would push people toward '0.0.0.0/0' which teaches the wrong habit.
    """
    if not allowlist:
        return True
    import ipaddress

    try:
        candidate = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return False
    for entry in allowlist:
        try:
            if candidate.subnet_of(ipaddress.ip_network(entry.strip(), strict=False)):
                return True
        except (ValueError, TypeError):
            continue
    return False
