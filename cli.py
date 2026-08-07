"""``hermes shodan ...``, the terminal surface.

Nothing here is required to use the plugin from a conversation. It exists
because setting up an API key, understanding why a call failed, and checking
what credits are left are all things a person does at a prompt, and making
someone ask an agent to introspect its own configuration is a bad trade.

``doctor`` is the one that earns its keep. It answers "why is this not
working" in a single command instead of a debugging conversation.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from . import config as config_mod
from .budget import tracker
from .client import INTERNETDB, get_client, reset_client
from .errors import ShodanError
from .shaping import format_asn

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    _console: Console | None = Console()
except Exception:  # pragma: no cover - rich is a Hermes core dependency
    _console = None
    Console = Panel = Table = None  # type: ignore


def _say(*parts: Any) -> None:
    if _console is not None:
        _console.print(*parts)
    else:
        print(*parts)


def _mask(secret: str | None) -> str:
    if not secret:
        return "(not set)"
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"


def _num(value: Any) -> str:
    """Thousands separators. Shodan totals run to seven figures."""
    return f"{value:,}" if isinstance(value, int) else str(value)


def _status(ok: bool, warn: bool = False) -> str:
    if warn:
        return "[yellow]warn[/yellow]" if _console else "warn"
    return "[green]ok[/green]" if ok else "[red]fail[/red]"


# --- argparse --------------------------------------------------------------


def build_parser(parser: argparse.ArgumentParser) -> None:
    """Build the ``hermes shodan`` tree. Called at plugin load."""
    subs = parser.add_subparsers(dest="shodan_command")

    setup_p = subs.add_parser("setup", help="Store and validate a Shodan API key")
    setup_p.add_argument(
        "--key", default=None, help="Provide the key directly instead of being prompted"
    )

    subs.add_parser("info", help="Plan, credits and limits for the configured key")
    subs.add_parser("doctor", help="Diagnose configuration, connectivity and plan capability")
    subs.add_parser("budget", help="Show this process's credit ledger")

    host_p = subs.add_parser("host", help="Look up one IP or hostname")
    host_p.add_argument("target")
    host_p.add_argument("--verbosity", choices=list(config_mod.VALID_VERBOSITY), default=None)
    host_p.add_argument("--json", action="store_true", help="Print raw JSON instead of a table")

    search_p = subs.add_parser("search", help="Run a search (spends a query credit)")
    search_p.add_argument("query")
    search_p.add_argument("--facets", default=None)
    search_p.add_argument("--limit", type=int, default=10)
    search_p.add_argument("--page", type=int, default=1)
    search_p.add_argument("--json", action="store_true")

    count_p = subs.add_parser("count", help="Count matches and facets (free)")
    count_p.add_argument("query")
    count_p.add_argument("--facets", default=None)
    count_p.add_argument("--json", action="store_true")

    profile_p = subs.add_parser("profile", help="Show or set the tool profile")
    profile_p.add_argument(
        "value", nargs="?", choices=list(config_mod.VALID_PROFILES), default=None
    )

    cache_p = subs.add_parser("cache", help="Inspect or clear the lookup cache")
    cache_p.add_argument("action", nargs="?", choices=["stats", "clear"], default="stats")


# --- dispatch --------------------------------------------------------------


def run_command(args: argparse.Namespace) -> int:
    sub = getattr(args, "shodan_command", None)
    if not sub:
        _say("usage: hermes shodan {setup,info,doctor,budget,host,search,count,profile,cache}")
        return 2

    handlers = {
        "setup": cmd_setup,
        "info": cmd_info,
        "doctor": cmd_doctor,
        "budget": cmd_budget,
        "host": cmd_host,
        "search": cmd_search,
        "count": cmd_count,
        "profile": cmd_profile,
        "cache": cmd_cache,
    }
    handler = handlers.get(sub)
    if handler is None:
        _say(f"Unknown subcommand: {sub}")
        return 2
    try:
        return handler(args)
    except ShodanError as exc:
        _say(f"[red]{exc.message}[/red]" if _console else f"error: {exc.message}")
        if exc.next_step:
            _say(f"  {exc.next_step}")
        return 1
    except KeyboardInterrupt:
        return 130


# --- setup -----------------------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> int:
    key = args.key
    if not key:
        import getpass

        _say("Shodan API key. Find it at https://account.shodan.io")
        try:
            key = getpass.getpass("  key: ").strip()
        except (EOFError, KeyboardInterrupt):
            _say("\nCancelled.")
            return 130
    if not key:
        _say("No key given, nothing changed.")
        return 1

    # Validate before storing. Writing a bad key and finding out later during
    # a conversation is the worst version of this.
    _say("Checking the key...")
    probe_cfg = config_mod.ShodanConfig(api_key=key)
    from .client import ShodanClient

    probe = ShodanClient(probe_cfg)
    try:
        info = probe.get("/api-info")
    except ShodanError as exc:
        _say(f"[red]Rejected:[/red] {exc.message}" if _console else f"Rejected: {exc.message}")
        _say("  Nothing was saved.")
        return 1
    finally:
        probe.close()

    try:
        from hermes_cli.config import save_env_value

        save_env_value("SHODAN_API_KEY", key)
    except Exception as exc:
        _say(f"[red]Could not write ~/.hermes/.env: {exc}[/red]")
        return 1

    import os

    os.environ["SHODAN_API_KEY"] = key
    config_mod.reset()
    reset_client()

    plan = info.get("plan") or "unknown"
    _say(
        f"[green]Saved.[/green] Plan: {plan}, "
        f"{info.get('query_credits')} query credits, "
        f"{info.get('scan_credits')} scan credits."
        if _console
        else f"Saved. Plan: {plan}"
    )

    if not _plugin_enabled():
        _say("\nThe plugin is not enabled yet. Run:\n  hermes plugins enable shodan")
    return 0


def _plugin_enabled() -> bool:
    try:
        from hermes_cli.config import load_config

        cfg = load_config() or {}
    except Exception:
        return False
    enabled = (cfg.get("plugins") or {}).get("enabled") or []
    return "shodan" in enabled


# --- info / budget ---------------------------------------------------------


def cmd_info(args: argparse.Namespace) -> int:
    cfg = config_mod.load(refresh=True)
    if not cfg.has_key:
        _say("No API key configured. Run 'hermes shodan setup'.")
        return 1

    info = get_client(cfg).get("/api-info")
    limits = info.get("usage_limits") or {}

    if _console is None or Table is None:
        print(json.dumps(info, indent=2))
        return 0

    table = Table(title="Shodan account", show_header=False, box=None, padding=(0, 2))
    table.add_row("Plan", str(info.get("plan") or "unknown"))
    table.add_row(
        "Query credits",
        f"{info.get('query_credits')} left of {_unlimited(limits.get('query_credits'))} per month",
    )
    table.add_row(
        "Scan credits",
        f"{info.get('scan_credits')} left of {_unlimited(limits.get('scan_credits'))} per month",
    )
    table.add_row(
        "Monitored IPs",
        f"{info.get('monitored_ips')} of {_unlimited(limits.get('monitored_ips'))}",
    )
    table.add_row("Restricted filters", _filter_availability(str(info.get("plan") or "")))
    _console.print(table)
    return 0


def _unlimited(value: Any) -> str:
    return "unlimited" if value == -1 else str(value)


def _filter_availability(plan: str) -> str:
    """Which plan-gated filters this tier can use.

    Shodan gates 'vuln:' at Small Business and 'tag:' at Corporate. Knowing
    that up front saves a wasted credit and a confusing error.
    """
    plan = plan.lower()
    if any(word in plan for word in ("corp", "enterprise", "unlimited")):
        return "vuln: yes, tag: yes"
    if "small" in plan or "business" in plan:
        return "vuln: yes, tag: no (needs Corporate)"
    return "vuln: no (needs Small Business), tag: no (needs Corporate)"


def cmd_budget(args: argparse.Namespace) -> int:
    cfg = config_mod.load(refresh=True)
    snapshot = tracker.ledger(None).snapshot(
        cfg.budget.query_credits_per_session, cfg.budget.scan_credits_per_session
    )
    _say(json.dumps(snapshot, indent=2))
    _say(
        "\nThis ledger is per process. A conversation running in the gateway "
        "keeps its own, reset at the start of each session."
    )
    return 0


# --- lookups ---------------------------------------------------------------


def _call(handler: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return json.loads(handler(payload))


def cmd_host(args: argparse.Namespace) -> int:
    from .handlers_core import shodan_host

    result = _call(
        shodan_host,
        {"ip": args.target, "verbosity": args.verbosity},
    )
    if args.json or _console is None or Table is None:
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1

    if not result.get("ok"):
        _say(f"[red]{result.get('error')}[/red]")
        return 1

    host = result.get("host") or (result.get("hosts") or [{}])[0]
    if not host:
        _say("No data.")
        return 1

    location = host.get("location") or {}
    header = " · ".join(
        part
        for part in [
            host.get("ip"),
            host.get("org"),
            format_asn(host.get("asn")),
            ", ".join(filter(None, [location.get("city"), location.get("country")])) or None,
        ]
        if part
    )
    _say(Panel(header, title="host", expand=False) if Panel else header)

    if host.get("hostnames"):
        _say(f"  hostnames  {', '.join(host['hostnames'][:8])}")
    if host.get("tags"):
        _say(f"  tags       {', '.join(host['tags'])}")

    services = host.get("services") or []
    if services:
        table = Table(title=f"{len(services)} exposed services", box=None, padding=(0, 2))
        for column in ("port", "service", "product", "title"):
            table.add_column(column)
        for svc in services:
            http = svc.get("http") or {}
            table.add_row(
                f"{svc.get('port')}/{svc.get('transport', 'tcp')}",
                str(svc.get("module") or ""),
                " ".join(filter(None, [svc.get("product"), svc.get("version")])),
                str(http.get("title") or "")[:48],
            )
        _console.print(table)
    elif host.get("open_ports"):
        _say(f"  open ports {', '.join(str(p) for p in host['open_ports'])}")

    vulns = host.get("vulns") or []
    if vulns:
        table = Table(title=f"{len(vulns)} known vulnerabilities", box=None, padding=(0, 2))
        table.add_column("cve")
        table.add_column("cvss")
        for row in vulns[:15]:
            table.add_row(str(row.get("cve") or row.get("note", "")), str(row.get("cvss") or ""))
        _console.print(table)

    if result.get("degraded"):
        _say(f"\n[yellow]{result['degraded']}[/yellow]")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    from .handlers_core import shodan_search

    result = _call(
        shodan_search,
        {
            "query": args.query,
            "facets": args.facets,
            "limit": args.limit,
            "page": args.page,
        },
    )
    if args.json or _console is None or Table is None:
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1

    if not result.get("ok"):
        _say(f"[red]{result.get('error')}[/red]")
        if result.get("next_step"):
            _say(f"  {result['next_step']}")
        return 1

    _say(f"[bold]{_num(result.get('total'))}[/bold] total matches for [cyan]{args.query}[/cyan]")
    _print_facets(result.get("facets") or {})

    matches = result.get("matches") or []
    if matches:
        table = Table(box=None, padding=(0, 2))
        for column in ("ip", "port", "product", "org", "country"):
            table.add_column(column)
        for match in matches:
            table.add_row(
                str(match.get("ip") or ""),
                str(match.get("port") or ""),
                " ".join(filter(None, [match.get("product"), match.get("version")])),
                str(match.get("org") or "")[:28],
                str((match.get("location") or {}).get("country_code") or ""),
            )
        _console.print(table)

    credits = result.get("credits") or {}
    if credits:
        _say(
            f"\nspent {credits.get('spent_by_this_call')} credit(s); "
            f"{credits.get('query_credits_remaining')} left in this session's budget"
        )
    return 0


def cmd_count(args: argparse.Namespace) -> int:
    from .handlers_core import shodan_count

    result = _call(shodan_count, {"query": args.query, "facets": args.facets})
    if args.json or _console is None:
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1

    if not result.get("ok"):
        _say(f"[red]{result.get('error')}[/red]")
        return 1
    _say(f"[bold]{_num(result.get('total'))}[/bold] matches for [cyan]{args.query}[/cyan]  (free)")
    _print_facets(result.get("facets") or {})
    return 0


def _print_facets(facets: dict[str, list[dict[str, Any]]]) -> None:
    if not facets or _console is None or Table is None:
        return
    for name, rows in facets.items():
        table = Table(title=name, box=None, padding=(0, 2), title_justify="left")
        table.add_column("value")
        table.add_column("count", justify="right")
        for row in rows[:15]:
            table.add_row(
                str(row.get("value")),
                f"{row.get('count'):,}"
                if isinstance(row.get("count"), int)
                else str(row.get("count")),
            )
        _console.print(table)


# --- profile / cache -------------------------------------------------------


def cmd_profile(args: argparse.Namespace) -> int:
    cfg = config_mod.load(refresh=True)
    if not args.value:
        visible = sorted(cfg.visible_tools())
        _say(f"profile: {cfg.profile}")
        _say(f"tools ({len(visible)}): {', '.join(visible)}")
        _say("\nSet with: hermes shodan profile full")
        return 0

    try:
        from hermes_cli.config import set_config_value

        set_config_value("plugins.entries.shodan.profile", args.value, force=True)
    except Exception as exc:
        _say(f"[red]Could not write config: {exc}[/red]")
        return 1

    config_mod.reset()
    updated = config_mod.load(refresh=True)
    _say(f"profile: {updated.profile} ({len(updated.visible_tools())} tools)")
    if args.value == "full" and not updated.scan.enabled:
        _say(
            "\nshodan_scan is visible now but still refuses to run. Active "
            "scanning needs a second opt-in:\n"
            "  hermes config set plugins.entries.shodan.scan.enabled true"
        )
    _say("\nRestart the gateway if one is running: hermes gateway restart")
    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    cfg = config_mod.load(refresh=True)
    client = get_client(cfg)
    if args.action == "clear":
        client.cache.clear()
        _say("Cache cleared.")
        return 0
    _say(json.dumps(client.cache.stats(), indent=2))
    return 0


# --- doctor ----------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    """One command that answers 'why is this not working'."""
    config_mod.reset()
    reset_client()
    cfg = config_mod.load(refresh=True)
    rows: list[tuple] = []
    problems: list[str] = []

    rows.append(("plugin enabled", _status(_plugin_enabled()), "plugins.enabled in config.yaml"))
    if not _plugin_enabled():
        problems.append("Run: hermes plugins enable shodan")

    rows.append(
        (
            "api key",
            _status(cfg.has_key),
            f"${cfg.api_key_env} = {_mask(cfg.api_key)}",
        )
    )
    if not cfg.has_key:
        problems.append("Run: hermes shodan setup")

    # Connectivity, checked against the keyless endpoint so a bad key and a
    # broken network stay distinguishable.
    client = get_client(cfg)
    try:
        client.get("/1.1.1.1", base=INTERNETDB)
        rows.append(("connectivity", _status(True), "reached internetdb.shodan.io"))
    except ShodanError as exc:
        rows.append(("connectivity", _status(False), exc.message))
        problems.append("Check network access and proxy settings.")

    plan = ""
    if cfg.has_key:
        try:
            info = client.get("/api-info")
            plan = str(info.get("plan") or "unknown")
            limits = info.get("usage_limits") or {}
            rows.append(("key valid", _status(True), f"plan: {plan}"))
            credits = info.get("query_credits")
            rows.append(
                (
                    "query credits",
                    _status(bool(credits), warn=credits == 0),
                    f"{credits} left of {_unlimited(limits.get('query_credits'))}/month",
                )
            )
            rows.append(("scan credits", _status(True), str(info.get("scan_credits"))))
            rows.append(("restricted filters", "", _filter_availability(plan)))
            if credits == 0:
                problems.append("Out of query credits. shodan_count and shodan_host still work.")
        except ShodanError as exc:
            rows.append(("key valid", _status(False), exc.message))
            problems.append("Run: hermes shodan setup (the stored key was rejected)")

    visible = sorted(cfg.visible_tools())
    rows.append(("profile", "", f"{cfg.profile} ({len(visible)} tools)"))
    rows.append(("verbosity", "", cfg.verbosity))
    rows.append(
        ("rate limit", "", f"{cfg.rate_limit_per_second}/s, timeout {cfg.timeout_seconds}s")
    )
    rows.append(
        (
            "cache",
            "",
            f"{'on' if cfg.cache.enabled else 'off'}, ttl {cfg.cache.ttl_seconds}s, "
            f"{client.cache.stats()['entries']} entries",
        )
    )
    rows.append(
        (
            "budget",
            "",
            f"{cfg.budget.query_credits_per_session} query / "
            f"{cfg.budget.scan_credits_per_session} scan credits per session",
        )
    )
    rows.append(
        (
            "active scanning",
            _status(True, warn=not cfg.scan.enabled),
            "enabled" if cfg.scan.enabled else "disabled (opt-in)",
        )
    )
    if cfg.scan.allowlist:
        rows.append(("scan allowlist", "", ", ".join(cfg.scan.allowlist)))

    if _console is not None and Table is not None:
        table = Table(title="hermes shodan doctor", box=None, padding=(0, 2))
        table.add_column("check")
        table.add_column("")
        table.add_column("detail")
        for row in rows:
            table.add_row(*row)
        _console.print(table)
        _console.print(f"\ntools: {', '.join(visible)}")
    else:
        for name, state, detail in rows:
            print(f"{name:20} {state:6} {detail}")
        print("tools:", ", ".join(visible))

    if problems:
        _say("\n[bold]Next steps[/bold]" if _console else "\nNext steps")
        for item in problems:
            _say(f"  - {item}")
        return 1

    _say("\n[green]Everything checks out.[/green]" if _console else "\nEverything checks out.")
    return 0
