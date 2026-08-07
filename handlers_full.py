"""The five tools behind ``profile: full``.

These are here rather than in the core set because they either change state
that outlives the conversation (alerts), send real traffic to real hosts and
spend scan credits (scanning), or serve a narrow enough need that the schema
is not worth its context cost in an average session (exploits, the query
directory, trends).
"""

from __future__ import annotations

from typing import Any

from . import config as config_mod
from . import shaping
from .budget import tracker
from .client import EXPLOITS, TRENDS, get_client
from .errors import ScanBlockedError
from .runtime import credit_block, in_allowlist, ok, session_id, small, spend, split_list, tool

# --- shodan_scan -----------------------------------------------------------


@tool
def shodan_scan(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)
    client = get_client(cfg)
    action = str(args.get("action") or "status").strip().lower()

    if action == "list":
        raw = client.get("/shodan/scans")
        tracker.record_call(sess)
        rows = [
            {
                "id": row.get("id"),
                "status": row.get("status"),
                "created": row.get("created"),
                "size": row.get("size"),
                "credits_left": row.get("credits_left"),
            }
            for row in (raw.get("matches") or [])
            if isinstance(row, dict)
        ]
        return ok({"action": "list", "total": raw.get("total"), "scans": rows}, cfg)

    if action == "status":
        scan_id = str(args.get("scan_id") or "").strip()
        if not scan_id:
            return {
                "ok": False,
                "error": "action='status' needs a scan_id.",
                "error_kind": "bad_request",
            }
        raw = client.get(f"/shodan/scan/{scan_id}")
        tracker.record_call(sess)
        status = raw.get("status")
        return small(
            {
                "action": "status",
                "scan_id": scan_id,
                "status": status,
                "created": raw.get("created"),
                "next_step": (
                    "Scan finished. Read the results with shodan_host on the targets you submitted."
                    if str(status).upper() == "DONE"
                    else "Still running. Scans take minutes. Check again later "
                    "rather than resubmitting."
                ),
            },
            cfg,
        )

    if action != "submit":
        return {
            "ok": False,
            "error": f"Unknown action {action!r}. Use 'submit', 'status' or 'list'.",
            "error_kind": "bad_request",
        }

    # --- submit: three gates before a single packet goes anywhere ----------

    if not cfg.scan.enabled:
        raise ScanBlockedError(
            "On-demand scanning is turned off. Set "
            "plugins.entries.shodan.scan.enabled: true in config.yaml to "
            "allow it."
        )

    targets = split_list(args.get("targets"), limit=64)
    if not targets:
        return {
            "ok": False,
            "error": "action='submit' needs targets.",
            "error_kind": "bad_request",
        }

    blocked: list[str] = [t for t in targets if not in_allowlist(t, cfg.scan.allowlist)]
    if blocked:
        raise ScanBlockedError(
            f"These targets are outside the configured scan allowlist: {', '.join(blocked)}.",
            details={"allowlist": cfg.scan.allowlist, "blocked": blocked},
        )

    # One scan credit per IP. A /24 is 256 of them, so the estimate has to
    # expand CIDRs rather than counting the strings the model typed.
    estimated = _estimate_scan_credits(targets)
    spend(estimated, cfg, sess, kind="scan")

    raw = client.post("/shodan/scan", data={"ips": ",".join(targets)})
    tracker.record_call(sess)

    return ok(
        {
            "action": "submit",
            "scan_id": raw.get("id"),
            "hosts_queued": raw.get("count"),
            "credits_left": raw.get("credits_left"),
            "targets": targets,
            "next_step": (
                "Scanning is asynchronous. Poll with "
                "shodan_scan(action='status', scan_id=...) and read results "
                "with shodan_host once it reports DONE."
            ),
        },
        cfg,
        credits=credit_block(cfg, sess, spent_now=0),
    )


def _estimate_scan_credits(targets: list[str]) -> int:
    """One credit per IP, counting CIDR ranges properly."""
    import ipaddress

    total = 0
    for target in targets:
        try:
            network = ipaddress.ip_network(target.strip(), strict=False)
            total += network.num_addresses
        except ValueError:
            total += 1
    return total


# --- shodan_alert ----------------------------------------------------------


@tool
def shodan_alert(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)
    client = get_client(cfg)
    action = str(args.get("action") or "list").strip().lower()
    alert_id = str(args.get("alert_id") or "").strip()

    def _shape(alert: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": alert.get("id"),
            "name": alert.get("name"),
            "created": alert.get("created"),
            "expires": alert.get("expiration") or alert.get("expires"),
            "size": alert.get("size"),
            "watching": (alert.get("filters") or {}).get("ip"),
            "triggers": sorted((alert.get("triggers") or {}).keys())
            if isinstance(alert.get("triggers"), dict)
            else alert.get("triggers"),
        }

    if action == "list":
        raw = client.get("/shodan/alert/info")
        tracker.record_call(sess)
        alerts = [_shape(a) for a in (raw or []) if isinstance(a, dict)]
        return ok({"action": "list", "count": len(alerts), "alerts": alerts}, cfg)

    if action == "triggers":
        raw = client.get("/shodan/alert/triggers", cacheable=True)
        rows = [
            {"name": t.get("name"), "description": t.get("description")}
            for t in (raw or [])
            if isinstance(t, dict)
        ]
        return ok({"action": "triggers", "triggers": rows}, cfg)

    if action == "info":
        if not alert_id:
            return {
                "ok": False,
                "error": "action='info' needs an alert_id.",
                "error_kind": "bad_request",
            }
        raw = client.get(f"/shodan/alert/{alert_id}/info")
        tracker.record_call(sess)
        return small({"action": "info", "alert": _shape(raw)}, cfg)

    if action == "create":
        name = str(args.get("name") or "").strip()
        ips = split_list(args.get("ips"), limit=64)
        if not name or not ips:
            return {
                "ok": False,
                "error": "action='create' needs both name and ips.",
                "error_kind": "bad_request",
            }
        body: dict[str, Any] = {"name": name, "filters": {"ip": ips}}
        if args.get("expires"):
            body["expires"] = int(args["expires"])
        raw = client.post("/shodan/alert", json_body=body)
        tracker.record_call(sess)
        return small(
            {
                "action": "create",
                "alert": _shape(raw),
                "next_step": (
                    "The monitor exists but has no triggers yet, so it will "
                    "not fire. Attach one with "
                    "shodan_alert(action='enable_trigger', alert_id=..., "
                    "trigger='new_service')."
                ),
            },
            cfg,
        )

    if action == "delete":
        if not alert_id:
            return {
                "ok": False,
                "error": "action='delete' needs an alert_id.",
                "error_kind": "bad_request",
            }
        client.delete(f"/shodan/alert/{alert_id}")
        tracker.record_call(sess)
        return small({"action": "delete", "alert_id": alert_id, "deleted": True}, cfg)

    if action in {"enable_trigger", "disable_trigger"}:
        trigger = str(args.get("trigger") or "").strip()
        if not alert_id or not trigger:
            return {
                "ok": False,
                "error": f"action='{action}' needs both alert_id and trigger.",
                "error_kind": "bad_request",
            }
        path = f"/shodan/alert/{alert_id}/trigger/{trigger}"
        if action == "enable_trigger":
            client.put(path)
        else:
            client.delete(path)
        tracker.record_call(sess)
        return small(
            {"action": action, "alert_id": alert_id, "trigger": trigger, "applied": True},
            cfg,
        )

    return {
        "ok": False,
        "error": f"Unknown action {action!r}.",
        "error_kind": "bad_request",
    }


# --- shodan_exploits -------------------------------------------------------


@tool
def shodan_exploits(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)
    client = get_client(cfg)

    query = str(args.get("query") or "").strip()
    if not query:
        return {"ok": False, "error": "No query given.", "error_kind": "bad_request"}

    params: dict[str, Any] = {"query": query}
    if args.get("facets"):
        params["facets"] = str(args["facets"]).strip()

    if args.get("count_only"):
        raw = client.get("/count", base=EXPLOITS, params=params, cacheable=True)
        tracker.record_call(sess)
        return ok(
            {
                "query": query,
                "total": raw.get("total"),
                "facets": shaping.shape_facets(raw.get("facets")),
            },
            cfg,
            source="exploits",
        )

    params["page"] = max(1, int(args.get("page") or 1))
    limit = max(1, min(50, int(args.get("limit") or 15)))
    raw = client.get("/search", base=EXPLOITS, params=params, cacheable=True)
    tracker.record_call(sess)

    rows = []
    for match in (raw.get("matches") or [])[:limit]:
        if not isinstance(match, dict):
            continue
        description = match.get("description") or ""
        rows.append(
            {
                k: v
                for k, v in {
                    "id": match.get("_id"),
                    "source": match.get("source"),
                    "type": match.get("type"),
                    "platform": match.get("platform"),
                    "title": match.get("title") or description[:120],
                    "description": (description[:300] + "...")
                    if len(description) > 300
                    else description or None,
                    "cve": match.get("cve"),
                    "author": match.get("author"),
                    "date": match.get("date"),
                    "port": match.get("port"),
                }.items()
                if v not in (None, "", [], {})
            }
        )

    return ok(
        {
            "query": query,
            "total": raw.get("total"),
            "returned": len(rows),
            "facets": shaping.shape_facets(raw.get("facets")),
            "exploits": rows,
        },
        cfg,
        source="exploits",
    )


# --- shodan_query ----------------------------------------------------------


@tool
def shodan_query(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)
    client = get_client(cfg)
    action = str(args.get("action") or "search").strip().lower()
    page = max(1, int(args.get("page") or 1))

    if action == "tags":
        raw = client.get("/shodan/query/tags", params={"size": 40}, cacheable=True)
        tracker.record_call(sess)
        tags = [
            {"tag": t.get("value"), "count": t.get("count")}
            for t in (raw.get("matches") or [])
            if isinstance(t, dict)
        ]
        return ok({"action": "tags", "tags": tags}, cfg, source="query-directory")

    if action == "search":
        query = str(args.get("query") or "").strip()
        if not query:
            return {
                "ok": False,
                "error": "action='search' needs a query.",
                "error_kind": "bad_request",
            }
        raw = client.get(
            "/shodan/query/search", params={"query": query, "page": page}, cacheable=True
        )
    elif action == "list":
        sort = str(args.get("sort") or "votes").strip().lower()
        raw = client.get(
            "/shodan/query",
            params={
                "page": page,
                "sort": sort if sort in {"votes", "timestamp"} else "votes",
                "order": "desc",
            },
            cacheable=True,
        )
    else:
        return {
            "ok": False,
            "error": f"Unknown action {action!r}. Use 'search', 'list' or 'tags'.",
            "error_kind": "bad_request",
        }

    tracker.record_call(sess)
    rows = [
        {
            k: v
            for k, v in {
                "title": row.get("title"),
                "query": row.get("query"),
                "description": (row.get("description") or "")[:200] or None,
                "votes": row.get("votes"),
                "tags": row.get("tags"),
            }.items()
            if v not in (None, "", [], {})
        }
        for row in (raw.get("matches") or [])
        if isinstance(row, dict)
    ]
    return ok(
        {
            "action": action,
            "total": raw.get("total"),
            "page": page,
            "page_size": 10,
            "saved_queries": rows,
            "next_step": (
                "These are query strings other people wrote. Validate one with "
                "shodan_meta(action='validate_query') and count it with "
                "shodan_count before spending a credit on a search."
            ),
        },
        cfg,
        source="query-directory",
    )


# --- shodan_trends ---------------------------------------------------------


@tool
def shodan_trends(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)
    client = get_client(cfg)

    query = str(args.get("query") or "").strip()
    if not query:
        return {"ok": False, "error": "No query given.", "error_kind": "bad_request"}

    params: dict[str, Any] = {"query": query}
    if args.get("facets"):
        params["facets"] = str(args["facets"]).strip()

    raw = client.get("/api/v1/search", base=TRENDS, params=params, cacheable=True)
    tracker.record_call(sess)

    months = [
        {"month": row.get("month"), "count": row.get("count")}
        for row in (raw.get("matches") or [])
        if isinstance(row, dict)
    ]
    return ok(
        {
            "query": query,
            "total": raw.get("total"),
            "months": months,
            "facets": shaping.shape_facets(raw.get("facets")),
        },
        cfg,
        source="trends",
    )
