"""Shodan.io for Hermes Agent.

Registration only. Everything real lives in the sibling modules, so a mistake
here cannot take a tool down with it and this file stays readable.

Hermes loads this as ``hermes_plugins.shodan`` with ``__path__`` pointed at the
plugin directory (hermes_cli/plugins.py:1854), which is why the relative
imports below work from ~/.hermes/plugins/shodan/ without any sys.path
surgery.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import config as config_mod
from . import handlers_core, handlers_full, schemas
from .budget import tracker

logger = logging.getLogger(__name__)

__version__ = "0.1.0"

TOOLSET = "shodan"

_HANDLERS: dict[str, Callable[..., str]] = {
    "shodan_host": handlers_core.shodan_host,
    "shodan_search": handlers_core.shodan_search,
    "shodan_count": handlers_core.shodan_count,
    "shodan_dns": handlers_core.shodan_dns,
    "shodan_cve": handlers_core.shodan_cve,
    "shodan_account": handlers_core.shodan_account,
    "shodan_meta": handlers_core.shodan_meta,
    "shodan_scan": handlers_full.shodan_scan,
    "shodan_alert": handlers_full.shodan_alert,
    "shodan_exploits": handlers_full.shodan_exploits,
    "shodan_query": handlers_full.shodan_query,
    "shodan_trends": handlers_full.shodan_trends,
}

# Tools that still do something useful with no API key at all: CVEDB needs
# none, and host lookups fall back to InternetDB.
_KEYLESS_CAPABLE = {"shodan_cve", "shodan_account", "shodan_host"}


def _visible(name: str) -> bool:
    """Should this tool be offered to the model right now?

    Two questions, in order: does the profile include it, and can it actually
    work. Hiding tools that would only ever answer "no API key" keeps the
    schema honest, but shodan_account stays visible precisely so the model can
    find out why the rest are missing.

    The registry caches this for about 30 seconds, so it is cheap to be
    thorough here.
    """
    try:
        cfg = config_mod.load()
    except Exception:
        return True  # fail open rather than silently losing the toolset
    if name not in cfg.visible_tools():
        return False
    if cfg.has_key:
        return True
    if name == "shodan_host":
        return cfg.internetdb_fallback
    return name in _KEYLESS_CAPABLE


def _make_check(name: str) -> Callable[[], bool]:
    def check() -> bool:
        return _visible(name)

    return check


def _on_session_boundary(**kwargs: Any) -> None:
    """Give each session a fresh credit budget.

    Without this a long-lived gateway process would carry one session's
    spending into the next and start refusing calls for reasons that have
    nothing to do with the current conversation.
    """
    task_id = kwargs.get("task_id") or kwargs.get("session_id")
    try:
        tracker.reset(str(task_id) if task_id else None)
    except Exception:  # pragma: no cover - a hook must never break the session
        logger.debug("shodan: budget reset failed", exc_info=True)


def _register_skills(ctx: Any) -> None:
    """Expose the bundled skills as ``shodan:<name>``.

    Plugin skills are explicit loads: they do not enter the system prompt's
    skill index, so they cost nothing until the model asks for one by name.
    That is the right trade for reference material like a 94-entry filter
    table.
    """
    skills_dir = Path(__file__).parent / "skills"
    if not skills_dir.is_dir():
        return
    descriptions = {
        "query-syntax": "Shodan search filters, facets and plan gating",
        "recon": "Credit-efficient attack surface mapping with Shodan",
        "monitoring": "Shodan network alerts, triggers and notifiers",
    }
    for child in sorted(skills_dir.iterdir()):
        skill_file = child / "SKILL.md"
        if not skill_file.exists():
            continue
        try:
            ctx.register_skill(child.name, skill_file, description=descriptions.get(child.name, ""))
        except Exception as exc:
            logger.warning("shodan: could not register skill %s: %s", child.name, exc)


def register(ctx: Any) -> None:
    """Entry point. Hermes calls this once, at startup, on every frontend."""
    for name, handler in _HANDLERS.items():
        ctx.register_tool(
            name=name,
            toolset=TOOLSET,
            schema=schemas.ALL_SCHEMAS[name],
            handler=handler,
            check_fn=_make_check(name),
            emoji=schemas.EMOJI.get(name, "🛰️"),
        )

    ctx.register_hook("on_session_start", _on_session_boundary)
    ctx.register_hook("on_session_reset", _on_session_boundary)

    _register_skills(ctx)

    # Imported here rather than at module scope so a problem in the human-
    # facing surface cannot stop the tools from registering.
    try:
        from .cli import build_parser, run_command

        ctx.register_cli_command(
            name="shodan",
            help="Shodan.io: keys, credits, lookups, diagnostics",
            setup_fn=build_parser,
            handler_fn=run_command,
            description=(
                "Configure and drive the Shodan plugin from the terminal. "
                "Start with 'hermes shodan setup', then 'hermes shodan doctor'."
            ),
        )
    except Exception as exc:
        logger.warning("shodan: CLI command not registered: %s", exc)

    try:
        from .slash import handle_slash

        ctx.register_command(
            "shodan",
            handle_slash,
            description="Shodan lookup, search, credits and budget",
            args_hint="<ip | query | info | budget>",
        )
    except Exception as exc:
        logger.warning("shodan: slash command not registered: %s", exc)

    cfg = config_mod.load()
    logger.info(
        "shodan plugin ready: profile=%s, %d tools visible, key=%s",
        cfg.profile,
        sum(1 for name in _HANDLERS if _visible(name)),
        "configured" if cfg.has_key else "missing",
    )
