"""The seven core tools. Read-only, cheap, and enough for most work."""

from __future__ import annotations

from typing import Any

from . import config as config_mod
from . import shaping
from .budget import estimate_search_cost, tracker
from .client import CVEDB, INTERNETDB, get_client
from .errors import (
    AuthError,
    CreditError,
    MissingKeyError,
    NotFoundError,
    PlanError,
    ShodanError,
)
from .runtime import (
    credit_block,
    looks_like_ip,
    ok,
    resolve_hostnames,
    session_id,
    small,
    spend,
    split_list,
    tool,
    verbosity_for,
)

# Shodan wants Python-style capitalized booleans in the query string. That is
# what the official client has always sent, so it is what the server parses
# reliably. httpx would render a real bool as lowercase "true", which is a
# different string and not worth gambling on.
_TRUE = "True"
_FALSE = "False"


# --- shodan_host -----------------------------------------------------------


def _lookup_internetdb(ip: str, cfg: config_mod.ShodanConfig) -> dict[str, Any] | None:
    client = get_client(cfg)
    try:
        raw = client.get(f"/{ip}", base=INTERNETDB, cacheable=True)
    except NotFoundError:
        return None
    return shaping.shape_internetdb(raw)


def _lookup_host(
    ip: str,
    cfg: config_mod.ShodanConfig,
    verbosity: str,
    history: bool,
) -> tuple[dict[str, Any] | None, str]:
    """Return ``(shaped_host_or_None, source)``.

    Falls back to InternetDB when the key is missing or the account cannot
    serve the request. A degraded answer beats no answer, and the shaped
    output labels its own source so nobody mistakes one for the other.
    """
    client = get_client(cfg)

    if cfg.has_key:
        params: dict[str, Any] = {}
        if history:
            params["history"] = _TRUE
        # Never send minify here. On /shodan/host/{ip} it means "ports and
        # general host info only, no banners", which throws away the products,
        # versions, titles and certificates that the summary exists to show.
        # We shape the full response ourselves instead. Note this is the
        # opposite of /shodan/host/search, where minify only trims oversized
        # fields and is worth sending.
        try:
            raw = client.get(f"/shodan/host/{ip}", params=params, cacheable=not history)
            return shaping.shape_host(raw, verbosity), "shodan"
        except NotFoundError:
            return None, "shodan"
        except (AuthError, CreditError, PlanError, MissingKeyError):
            if not cfg.internetdb_fallback:
                raise
        # fall through to the free dataset

    if not cfg.internetdb_fallback:
        raise MissingKeyError("No Shodan API key, and the InternetDB fallback is disabled.")

    return _lookup_internetdb(ip, cfg), "internetdb"


@tool
def shodan_host(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    verbosity = verbosity_for(args, cfg)
    history = bool(args.get("history"))

    targets = split_list(args.get("ip"), limit=16)
    if not targets:
        return {
            "ok": False,
            "error": "No IP or hostname given.",
            "error_kind": "bad_request",
        }

    hostnames = [t for t in targets if not looks_like_ip(t)]
    resolved = resolve_hostnames(hostnames, cfg) if hostnames else {}

    queue: list[tuple[str, str | None]] = []
    unresolved: list[str] = []
    for target in targets:
        if looks_like_ip(target):
            queue.append((target, None))
        elif target in resolved:
            queue.append((resolved[target], target))
        else:
            unresolved.append(target)

    hosts: list[dict[str, Any]] = []
    not_found: list[str] = []
    sources = set()

    for ip, original_name in queue:
        shaped, source = _lookup_host(ip, cfg, verbosity, history)
        sources.add(source)
        if shaped is None:
            not_found.append(original_name or ip)
            continue
        if original_name:
            shaped["queried_as"] = original_name
        hosts.append(shaped)

    tracker.record_call(session_id(kwargs))

    payload: dict[str, Any] = {}
    if len(hosts) == 1 and not not_found and not unresolved:
        payload["host"] = hosts[0]
    else:
        payload["hosts"] = hosts
        payload["found"] = len(hosts)
    if not_found:
        payload["no_data_for"] = not_found
        payload["note"] = (
            "Shodan has no record for these. That usually means no exposed "
            "services were seen in the last scan window, not that the host is "
            "offline."
        )
    if unresolved:
        payload["unresolved_hostnames"] = unresolved

    source = "internetdb" if sources == {"internetdb"} else "shodan"
    if source == "internetdb":
        payload["degraded"] = (
            "Answered from the free keyless InternetDB dataset. Ports, CPEs, "
            "tags and CVE ids only. Configure SHODAN_API_KEY for banners, "
            "products, versions and certificates."
        )
    return ok(payload, cfg, source=source)


# --- shodan_search ---------------------------------------------------------


@tool
def shodan_search(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)
    verbosity = verbosity_for(args, cfg)

    query = str(args.get("query") or "").strip()
    if not query:
        return {"ok": False, "error": "No query given.", "error_kind": "bad_request"}

    page = max(1, int(args.get("page") or 1))
    limit = max(1, min(100, int(args.get("limit") or 25)))

    cost = estimate_search_cost(query, page)
    spend(cost, cfg, sess)

    params: dict[str, Any] = {"query": query, "page": page}
    if args.get("facets"):
        params["facets"] = str(args["facets"]).strip()
    params["minify"] = _TRUE if verbosity == "summary" else _FALSE

    client = get_client(cfg)
    raw = client.get("/shodan/host/search", params=params)
    tracker.record_call(sess)

    if isinstance(raw.get("matches"), list) and len(raw["matches"]) > limit:
        raw = {**raw, "matches": raw["matches"][:limit]}

    shaped = shaping.shape_search(raw, verbosity=verbosity, query=query, page=page)
    if shaped.get("more_available"):
        shaped["pagination_hint"] = (
            "More results exist. Each additional page costs another query "
            "credit. If you only need aggregates, use shodan_count with facets "
            "instead, which is free."
        )
    return ok(shaped, cfg, credits=credit_block(cfg, sess, spent_now=cost))


# --- shodan_count ----------------------------------------------------------


@tool
def shodan_count(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)

    query = str(args.get("query") or "").strip()
    if not query:
        return {"ok": False, "error": "No query given.", "error_kind": "bad_request"}

    params: dict[str, Any] = {"query": query}
    if args.get("facets"):
        params["facets"] = str(args["facets"]).strip()

    client = get_client(cfg)
    raw = client.get("/shodan/host/count", params=params)
    tracker.record_call(sess)
    tracker.record_cache_save(sess)

    payload = {
        "query": query,
        "total": raw.get("total"),
        "facets": shaping.shape_facets(raw.get("facets")),
        "cost": "free. /shodan/host/count does not consume query credits",
    }
    return ok(payload, cfg)


# --- shodan_dns ------------------------------------------------------------


@tool
def shodan_dns(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)
    mode = str(args.get("mode") or "").strip().lower()
    target = str(args.get("target") or "").strip()

    if not target:
        return {"ok": False, "error": "No target given.", "error_kind": "bad_request"}

    client = get_client(cfg)

    if mode == "resolve":
        result = client.get(
            "/dns/resolve",
            params={"hostnames": ",".join(split_list(target))},
            cacheable=True,
        )
        tracker.record_call(sess)
        return small({"mode": "resolve", "resolved": result, "cost": "free"}, cfg)

    if mode == "reverse":
        result = client.get(
            "/dns/reverse",
            params={"ips": ",".join(split_list(target))},
            cacheable=True,
        )
        tracker.record_call(sess)
        return small({"mode": "reverse", "hostnames": result, "cost": "free"}, cfg)

    if mode != "domain":
        return {
            "ok": False,
            "error": f"Unknown mode {mode!r}. Use 'domain', 'resolve' or 'reverse'.",
            "error_kind": "bad_request",
        }

    # /dns/domain is the one that costs a credit, and agents reach for it
    # reflexively, so it goes through the budget guard.
    spend(1, cfg, sess)

    params: dict[str, Any] = {"page": max(1, int(args.get("page") or 1))}
    if args.get("record_type"):
        params["type"] = str(args["record_type"]).strip().upper()

    raw = client.get(f"/dns/domain/{target}", params=params)
    tracker.record_call(sess)

    records = raw.get("data") or []
    payload = {
        "mode": "domain",
        "domain": raw.get("domain") or target,
        "tags": raw.get("tags"),
        "subdomains": raw.get("subdomains"),
        "subdomain_count": len(raw.get("subdomains") or []),
        "records": [
            {
                "subdomain": r.get("subdomain"),
                "type": r.get("type"),
                "value": r.get("value"),
                "last_seen": r.get("last_seen"),
            }
            for r in records
            if isinstance(r, dict)
        ],
        "more_pages": bool(raw.get("more")),
    }
    return ok(payload, cfg, credits=credit_block(cfg, sess, spent_now=1))


# --- shodan_cve ------------------------------------------------------------


def _shape_cve(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v
        for k, v in {
            "cve": raw.get("cve_id"),
            "summary": raw.get("summary"),
            "cvss": raw.get("cvss"),
            "cvss_version": raw.get("cvss_version"),
            "cvss_v3": raw.get("cvss_v3"),
            "cvss_v4": raw.get("cvss_v4"),
            "epss": raw.get("epss"),
            "epss_percentile": raw.get("ranking_epss"),
            "known_exploited": raw.get("kev"),
            "ransomware_campaign": raw.get("ransomware_campaign"),
            "recommended_action": raw.get("propose_action"),
            "published": raw.get("published_time"),
            "affected_cpes": (raw.get("cpes") or [])[:20],
            "references": (raw.get("references") or [])[:8],
        }.items()
        if v not in (None, "", [], {})
    }


@tool
def shodan_cve(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    client = get_client(cfg)
    action = str(args.get("action") or "get").strip().lower()
    limit = max(1, min(100, int(args.get("limit") or 20)))

    if action == "get":
        cve = str(args.get("cve") or "").strip().upper()
        if not cve:
            return {
                "ok": False,
                "error": "action='get' needs a cve id.",
                "error_kind": "bad_request",
            }
        raw = client.get(f"/cve/{cve}", base=CVEDB, cacheable=True)
        return small({"source": "cvedb", "cve": _shape_cve(raw)}, cfg)

    if action == "cpes":
        product = str(args.get("product") or "").strip()
        if not product:
            return {
                "ok": False,
                "error": "action='cpes' needs a product name.",
                "error_kind": "bad_request",
            }
        raw = client.get("/cpes", base=CVEDB, params={"product": product}, cacheable=True)
        return small(
            {"source": "cvedb", "product": product, "cpes": (raw.get("cpes") or [])[:limit]},
            cfg,
        )

    if action != "search":
        return {
            "ok": False,
            "error": f"Unknown action {action!r}. Use 'get', 'search' or 'cpes'.",
            "error_kind": "bad_request",
        }

    params: dict[str, Any] = {"limit": limit}
    if args.get("cpe23"):
        params["cpe23"] = str(args["cpe23"]).strip()
    elif args.get("product"):
        params["product"] = str(args["product"]).strip()
    else:
        return {
            "ok": False,
            "error": "action='search' needs either product or cpe23.",
            "error_kind": "bad_request",
        }
    if args.get("kev_only"):
        params["is_kev"] = _TRUE.lower()
    if args.get("sort_by_epss"):
        params["sort_by_epss"] = _TRUE.lower()

    raw = client.get("/cves", base=CVEDB, params=params, cacheable=True)
    rows = raw.get("cves") if isinstance(raw, dict) else raw
    shaped = [_shape_cve(r) for r in (rows or [])[:limit] if isinstance(r, dict)]
    return ok({"source": "cvedb", "count": len(shaped), "cves": shaped}, cfg, source="cvedb")


# --- shodan_account --------------------------------------------------------


@tool
def shodan_account(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    sess = session_id(kwargs)

    payload: dict[str, Any] = {
        "api_key_configured": cfg.has_key,
        "api_key_env": cfg.api_key_env,
        "profile": cfg.profile,
        "verbosity": cfg.verbosity,
        "scanning_enabled": cfg.scan.enabled,
        "session_budget": tracker.ledger(sess).snapshot(
            cfg.budget.query_credits_per_session,
            cfg.budget.scan_credits_per_session,
        ),
    }

    if not cfg.has_key:
        payload["note"] = (
            "No API key configured, so only the keyless endpoints work: "
            "shodan_cve, and shodan_host through the InternetDB fallback."
        )
        return small(payload, cfg)

    client = get_client(cfg)
    info = client.get("/api-info", cacheable=True)
    limits = info.get("usage_limits") or {}
    payload["account"] = {
        "plan": info.get("plan"),
        "query_credits": info.get("query_credits"),
        "scan_credits": info.get("scan_credits"),
        "monitored_ips": info.get("monitored_ips"),
        "unlocked": info.get("unlocked"),
        "monthly_query_credits": limits.get("query_credits"),
        "monthly_scan_credits": limits.get("scan_credits"),
        "monitored_ip_allowance": limits.get("monitored_ips"),
        "https": info.get("https"),
        "telnet": info.get("telnet"),
    }
    try:
        prof = client.get("/account/profile", cacheable=True)
        payload["account"]["display_name"] = prof.get("display_name")
        payload["account"]["member"] = prof.get("member")
        payload["account"]["created"] = prof.get("created")
    except ShodanError:
        # Not every plan exposes the profile endpoint. The credit numbers are
        # what matter and we already have them.
        pass

    if args.get("include_myip"):
        try:
            payload["my_public_ip"] = client.get("/tools/myip", cacheable=True)
        except ShodanError:
            pass

    tracker.record_call(sess)
    payload["cache"] = client.cache.stats()
    return small(payload, cfg)


# --- shodan_meta -----------------------------------------------------------


@tool
def shodan_meta(args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    cfg = config_mod.load()
    client = get_client(cfg)
    action = str(args.get("action") or "validate_query").strip().lower()

    if action == "validate_query":
        query = str(args.get("query") or "").strip()
        if not query:
            return {
                "ok": False,
                "error": "action='validate_query' needs a query.",
                "error_kind": "bad_request",
            }
        raw = client.get("/shodan/host/search/tokens", params={"query": query})
        errors = raw.get("errors") or []
        return small(
            {
                "query": query,
                "valid": not errors,
                "errors": errors,
                "filters_used": raw.get("filters"),
                "parsed_attributes": raw.get("attributes"),
                "free_text": raw.get("string"),
                "cost": "free. Validating does not run the search",
                "note": (
                    "Valid syntax does not mean the plan can run it. 'vuln:' "
                    "needs Small Business or above and 'tag:' needs Corporate "
                    "or above."
                )
                if not errors
                else None,
            },
            cfg,
        )

    endpoints = {
        "filters": "/shodan/host/search/filters",
        "facets": "/shodan/host/search/facets",
        "ports": "/shodan/ports",
        "protocols": "/shodan/protocols",
    }
    path = endpoints.get(action)
    if path is None:
        return {
            "ok": False,
            "error": f"Unknown action {action!r}. Use one of: validate_query, {', '.join(endpoints)}.",
            "error_kind": "bad_request",
        }

    raw = client.get(path, cacheable=True)

    if action == "protocols":
        # A few hundred entries of name plus prose. Names are what the model
        # needs to pick a scan protocol, and the prose is lookup-able.
        names = sorted(raw.keys()) if isinstance(raw, dict) else raw
        return ok({"action": action, "count": len(names), "protocols": names}, cfg)

    if action == "ports":
        ports = sorted(raw) if isinstance(raw, list) else raw
        return ok(
            {
                "action": action,
                "count": len(ports),
                "note": "Shodan crawls these ports. Anything else will not be in the index.",
                "ports": ports,
            },
            cfg,
        )

    return ok({"action": action, "count": len(raw or []), action: sorted(raw or [])}, cfg)
