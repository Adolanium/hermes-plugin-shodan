"""``/shodan``, the in-conversation command.

Available in the CLI, the TUI, the desktop app and every gateway channel,
because plugin slash commands are registered once and consumed by all of them.

The dispatch is deliberately forgiving. Someone typing ``/shodan 1.1.1.1`` and
someone typing ``/shodan apache country:DE`` both mean something obvious, and
making them remember a subcommand for each would be pointless ceremony. An
argument that parses as an address gets a host lookup, and anything else gets a
free count with facets, never a credit-spending search, because a slash
command should not quietly cost money.
"""

from __future__ import annotations

import json
from typing import Any

from . import config as config_mod
from .runtime import looks_like_ip
from .shaping import format_asn

_USAGE = (
    "**/shodan**: internet exposure lookup\n"
    "```\n"
    "/shodan 1.1.1.1              host intel for an IP or hostname\n"
    "/shodan apache country:DE    free match count, with breakdowns\n"
    "/shodan info                 plan and remaining credits\n"
    "/shodan budget               this session's credit ledger\n"
    "```\n"
    "Searches that return individual hosts cost credits, so ask the agent for "
    "those directly rather than through this command."
)


def _fmt_host(result: dict[str, Any]) -> str:
    host = result.get("host") or (result.get("hosts") or [{}])[0]
    if not host:
        return "No data for that host. Shodan saw no exposed services in the last scan window."

    location = host.get("location") or {}
    lines: list[str] = []
    header = " · ".join(
        part
        for part in [
            f"**{host.get('ip')}**",
            host.get("org"),
            format_asn(host.get("asn")),
            ", ".join(filter(None, [location.get("city"), location.get("country")])) or None,
        ]
        if part
    )
    lines.append(header)

    if host.get("hostnames"):
        lines.append(f"hostnames: {', '.join(host['hostnames'][:6])}")
    if host.get("tags"):
        lines.append(f"tags: {', '.join(host['tags'])}")

    services = host.get("services") or []
    if services:
        lines.append(f"\n**{len(services)} exposed services**")
        for svc in services[:12]:
            http = svc.get("http") or {}
            descriptor = " ".join(filter(None, [svc.get("product"), svc.get("version")]))
            title = http.get("title")
            detail = " - ".join(filter(None, [descriptor or svc.get("module"), title]))
            lines.append(f"  {svc.get('port')}/{svc.get('transport', 'tcp')}  {detail}")
        if len(services) > 12:
            lines.append(f"  ... and {len(services) - 12} more")
    elif host.get("open_ports"):
        lines.append(f"open ports: {', '.join(str(p) for p in host['open_ports'])}")

    vulns = host.get("vulns") or []
    if vulns:
        lines.append(f"\n**{len(vulns)} known CVEs**, worst first")
        for row in vulns[:8]:
            if row.get("note"):
                lines.append(f"  {row['note']}")
                continue
            score = f" (CVSS {row['cvss']})" if row.get("cvss") else ""
            lines.append(f"  {row.get('cve')}{score}")

    if result.get("degraded"):
        lines.append(f"\n_{result['degraded']}_")
    return "\n".join(lines)


def _fmt_count(result: dict[str, Any]) -> str:
    lines = [f"**{result.get('total'):,} matches** for `{result.get('query')}`  (free lookup)"]
    for name, rows in (result.get("facets") or {}).items():
        lines.append(f"\n**{name}**")
        for row in rows[:8]:
            count = row.get("count")
            pretty = f"{count:,}" if isinstance(count, int) else str(count)
            lines.append(f"  {row.get('value')}: {pretty}")
    if not result.get("facets"):
        lines.append(
            "\nAdd facets for a breakdown, or ask the agent to search if you "
            "need the individual hosts."
        )
    return "\n".join(lines)


def _fmt_account(result: dict[str, Any]) -> str:
    account = result.get("account") or {}
    if not account:
        return result.get("note") or "No API key configured. Run `hermes shodan setup`."
    budget = result.get("session_budget") or {}
    return "\n".join(
        [
            f"**Shodan** plan: {account.get('plan') or 'unknown'}",
            f"query credits: {account.get('query_credits')} left",
            f"scan credits: {account.get('scan_credits')} left",
            f"monitored IPs: {account.get('monitored_ips')} of {account.get('monitored_ip_allowance')}",
            f"session budget: {budget.get('query_credits_remaining')} of "
            f"{budget.get('query_credits_budget')} query credits remaining",
        ]
    )


def handle_slash(raw_args: str) -> str:
    """Entry point. Returns markdown for the chat surface."""
    argument = (raw_args or "").strip()
    if not argument or argument.lower() in {"help", "-h", "--help", "?"}:
        return _USAGE

    lowered = argument.lower()

    try:
        if lowered in {"info", "account", "credits"}:
            from .handlers_core import shodan_account

            return _fmt_account(json.loads(shodan_account({"include_myip": False})))

        if lowered == "budget":
            from .budget import tracker

            cfg = config_mod.load()
            snapshot = tracker.ledger(None).snapshot(
                cfg.budget.query_credits_per_session,
                cfg.budget.scan_credits_per_session,
            )
            body = "\n".join(f"  {k}: {v}" for k, v in snapshot.items())
            return f"**Shodan session budget**\n```\n{body}\n```"

        # A single bare token with no filter syntax is a host, not a query.
        is_target = (
            " " not in argument
            and ":" not in argument
            and (looks_like_ip(argument) or "." in argument)
        )

        if is_target:
            from .handlers_core import shodan_host

            result = json.loads(shodan_host({"ip": argument}))
            if not result.get("ok"):
                return _error_text(result)
            return _fmt_host(result)

        from .handlers_core import shodan_count

        result = json.loads(shodan_count({"query": argument, "facets": "country:8,org:8,port:8"}))
        if not result.get("ok"):
            return _error_text(result)
        return _fmt_count(result)

    except Exception as exc:  # pragma: no cover - a slash command must not throw
        return f"Shodan command failed: {type(exc).__name__}: {exc}"


def _error_text(result: dict[str, Any]) -> str:
    parts = [f"**Shodan error:** {result.get('error')}"]
    if result.get("next_step"):
        parts.append(f"\n{result['next_step']}")
    return "\n".join(parts)
