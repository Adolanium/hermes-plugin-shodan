"""Turning Shodan's firehose into something a model can actually read.

This is the part that makes the difference. A single ``/shodan/host/{ip}``
response for a busy host runs to hundreds of kilobytes: every HTTP response
body in full, base64 favicons, screenshots, complete PEM certificate chains,
robots.txt, sitemaps. Handing that to a model burns the context window on
markup and learns nothing.

So we project. Three levels:

- ``summary``  the default. Identity, location, tags, vulnerabilities sorted
               by severity, and one tight line per exposed service.
- ``detail``   adds HTTP headers, full certificate fields and a truncated
               banner excerpt. For when the summary raised a question.
- ``raw``      untouched, capped only by the byte budget. For when the model
               genuinely needs a field nobody thought to keep.

Below ``raw`` the heavy fields are dropped unconditionally, and then the whole
payload is fitted to a character budget by degrading in a fixed order rather
than truncating mid-JSON and handing back something unparseable.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

# Fields that are large, near-useless in a summary, and present on almost
# every banner. Dropped for summary and detail alike.
_HEAVY_HTTP = (
    "html",
    "robots",
    "sitemap",
    "securitytxt",
    "favicon",
    "components",
    "redirects",
)
_HEAVY_SSL = (
    "chain",
    "chain_sha256",
    "acceptable_cas",
    "handshake_states",
    "unstable",
    "dhparams",
    "tlsext",
)

_BANNER_EXCERPT_CHARS = 400
_VULN_SUMMARY_CHARS = 220


# --- small helpers ---------------------------------------------------------


def _first(mapping: Any, *keys: str) -> Any:
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _clean(mapping: dict[str, Any]) -> dict[str, Any]:
    """Drop empty values. Nulls are pervasive in Shodan data and carry nothing."""
    return {k: v for k, v in mapping.items() if v not in (None, "", [], {})}


def _truncate(text: Any, limit: int) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def format_asn(value: Any) -> str | None:
    """Render an ASN for display without doubling the prefix.

    Shodan already returns ``"AS13335"``, so a naive f-string prefix produces
    ``ASAS13335``. Only add the prefix when it is genuinely missing.
    """
    text = str(value or "").strip()
    if not text:
        return None
    return text if text.upper().startswith("AS") else f"AS{text}"


def _location(source: dict[str, Any]) -> dict[str, Any]:
    """Pull location out of either shape.

    Host lookups flatten location onto the top level, while search matches nest it
    under ``location``. Same data, two layouts, and getting this wrong is the
    classic Shodan integration bug.
    """
    nested = source.get("location") if isinstance(source.get("location"), dict) else {}
    merged = {**source, **nested}
    return _clean(
        {
            "city": merged.get("city"),
            "region": merged.get("region_code"),
            "country": merged.get("country_name") or merged.get("country_code"),
            "country_code": merged.get("country_code"),
            "latitude": merged.get("latitude"),
            "longitude": merged.get("longitude"),
        }
    )


# --- vulnerabilities -------------------------------------------------------


def shape_vulns(vulns: Any, *, limit: int = 40) -> list[dict[str, Any]]:
    """Normalize the vulns field and sort worst-first.

    Two shapes exist in the wild: the main REST API returns an object keyed by
    CVE with CVSS inside, InternetDB returns a bare list of CVE strings. Both
    land here as a list sorted by CVSS descending, because a model reading
    top-down should hit the critical findings first, and because when the
    budget forces a trim it is the low-severity tail that goes.
    """
    if not vulns:
        return []

    rows: list[dict[str, Any]] = []
    if isinstance(vulns, dict):
        for cve, meta in vulns.items():
            if not isinstance(meta, dict):
                rows.append({"cve": cve})
                continue
            rows.append(
                _clean(
                    {
                        "cve": cve,
                        "cvss": meta.get("cvss"),
                        "verified": meta.get("verified"),
                        "summary": _truncate(meta.get("summary", ""), _VULN_SUMMARY_CHARS) or None,
                    }
                )
            )
    elif isinstance(vulns, (list, tuple)):
        rows = [{"cve": str(item)} for item in vulns]

    def severity(row: dict[str, Any]) -> float:
        try:
            return float(row.get("cvss") or 0)
        except (TypeError, ValueError):
            return 0.0

    rows.sort(key=severity, reverse=True)
    if len(rows) > limit:
        trimmed = rows[:limit]
        trimmed.append({"note": f"{len(rows) - limit} lower-severity CVEs omitted"})
        return trimmed
    return rows


# --- certificates ----------------------------------------------------------


def _shape_cert(ssl: dict[str, Any], verbosity: str) -> dict[str, Any]:
    cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
    subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
    issuer = cert.get("issuer") if isinstance(cert.get("issuer"), dict) else {}

    shaped = _clean(
        {
            "subject_cn": subject.get("CN"),
            "issuer_cn": issuer.get("CN") or issuer.get("O"),
            "expired": cert.get("expired"),
            "expires": cert.get("expires"),
            "issued": cert.get("issued"),
            "tls_versions": [v for v in (ssl.get("versions") or []) if not str(v).startswith("-")],
            "jarm": ssl.get("jarm"),
            "ja3s": ssl.get("ja3s"),
        }
    )
    if verbosity == "detail":
        shaped.update(
            _clean(
                {
                    "serial": cert.get("serial"),
                    "fingerprint_sha256": (cert.get("fingerprint") or {}).get("sha256")
                    if isinstance(cert.get("fingerprint"), dict)
                    else None,
                    "signature_algorithm": (cert.get("sig_alg") or cert.get("algorithm")),
                    "pubkey": cert.get("pubkey"),
                    "subject_alt_names": (cert.get("extensions") or [{}])[0].get("data")
                    if isinstance(cert.get("extensions"), list)
                    else None,
                    "cipher": ssl.get("cipher"),
                    "alpn": ssl.get("alpn"),
                    "chain_length": len(ssl.get("chain") or []) or None,
                }
            )
        )
    return shaped


# --- banners ---------------------------------------------------------------


def shape_banner(banner: dict[str, Any], verbosity: str = "summary") -> dict[str, Any]:
    """One exposed service, compressed to what identifies and endangers it."""
    if not isinstance(banner, dict):
        return {}

    http = banner.get("http") if isinstance(banner.get("http"), dict) else {}
    ssl = banner.get("ssl") if isinstance(banner.get("ssl"), dict) else {}
    meta = banner.get("_shodan") if isinstance(banner.get("_shodan"), dict) else {}

    shaped: dict[str, Any] = _clean(
        {
            "port": banner.get("port"),
            "transport": banner.get("transport"),
            "module": meta.get("module"),
            "product": banner.get("product"),
            "version": banner.get("version"),
            "info": banner.get("info"),
            "os": banner.get("os"),
            "device": banner.get("devicetype") or banner.get("device"),
            "cpe": banner.get("cpe23") or banner.get("cpe"),
            "tags": banner.get("tags"),
            "timestamp": banner.get("timestamp"),
        }
    )

    if http:
        shaped["http"] = _clean(
            {
                "status": http.get("status"),
                "title": _truncate(http.get("title") or "", 160) or None,
                "server": http.get("server"),
                "waf": http.get("waf"),
                "location": http.get("location"),
            }
        )
        if verbosity == "detail":
            headers = http.get("headers")
            if isinstance(headers, dict):
                shaped["http"]["headers"] = headers
            shaped["http"] = _clean(
                {
                    **shaped["http"],
                    "host": http.get("host"),
                    "favicon_hash": (http.get("favicon") or {}).get("hash")
                    if isinstance(http.get("favicon"), dict)
                    else None,
                    "dom_hash": http.get("dom_hash"),
                }
            )

    if ssl:
        cert = _shape_cert(ssl, verbosity)
        if cert:
            shaped["tls"] = cert

    vulns = shape_vulns(banner.get("vulns"))
    if vulns:
        shaped["vulns"] = vulns

    if verbosity == "detail":
        excerpt = _truncate(banner.get("data") or "", _BANNER_EXCERPT_CHARS)
        if excerpt:
            shaped["banner_excerpt"] = excerpt

    return shaped


# --- hosts -----------------------------------------------------------------


def shape_host(raw: dict[str, Any], verbosity: str = "summary") -> dict[str, Any]:
    """A full host record, summarized.

    Ports come out sorted so repeated lookups on the same host produce
    byte-identical output, which keeps prompt caches warm.
    """
    if verbosity == "raw":
        return strip_heavy(raw, keep_all=True)

    services = [shape_banner(b, verbosity) for b in (raw.get("data") or [])]
    services = [s for s in services if s]
    services.sort(key=lambda s: (s.get("port") or 0, str(s.get("transport") or "")))

    # Prefer the ports derived from banners, but fall back to the top-level
    # ``ports`` list. A banner-less response is what Shodan returns for a
    # minified host lookup, and it is still worth reporting which ports are
    # open rather than silently dropping them.
    open_ports = sorted({s["port"] for s in services if s.get("port")})
    if not open_ports:
        open_ports = sorted(p for p in (raw.get("ports") or []) if isinstance(p, int))

    shaped = _clean(
        {
            "ip": raw.get("ip_str") or raw.get("ip"),
            "hostnames": raw.get("hostnames"),
            "domains": raw.get("domains"),
            "org": raw.get("org"),
            "isp": raw.get("isp"),
            "asn": raw.get("asn"),
            "os": raw.get("os"),
            "location": _location(raw),
            "tags": raw.get("tags"),
            "last_update": raw.get("last_update"),
            "open_ports": open_ports,
            "vulns": shape_vulns(raw.get("vulns")),
            "services": services,
        }
    )
    return shaped


def shape_internetdb(raw: dict[str, Any]) -> dict[str, Any]:
    """The free InternetDB shape. Six fields, all required, no key needed."""
    return _clean(
        {
            "ip": raw.get("ip"),
            "hostnames": raw.get("hostnames"),
            "open_ports": sorted(raw.get("ports") or []),
            "cpes": raw.get("cpes"),
            "tags": raw.get("tags"),
            "vulns": shape_vulns(raw.get("vulns")),
            "source": "internetdb",
            "note": (
                "InternetDB is the free keyless dataset: ports, CPEs, tags and "
                "CVE ids only, refreshed weekly. No banners, products, versions "
                "or certificates. Use shodan_host with an API key for those."
            ),
        }
    )


# --- search ----------------------------------------------------------------


def shape_facets(facets: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(facets, dict):
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for name, rows in facets.items():
        if not isinstance(rows, list):
            continue
        out[name] = [
            {"value": row.get("value"), "count": row.get("count")}
            for row in rows
            if isinstance(row, dict)
        ]
    return out


def shape_search(
    raw: dict[str, Any],
    *,
    verbosity: str = "summary",
    query: str = "",
    page: int = 1,
) -> dict[str, Any]:
    """Search results: the total, the facets, then the matches.

    Total and facets come first on purpose. They are the cheap answer to most
    questions, and a model that reads them may decide it does not need the
    matches at all.
    """
    matches_raw = raw.get("matches") or []
    if verbosity == "raw":
        matches = [strip_heavy(m, keep_all=True) for m in matches_raw]
    else:
        matches = []
        for match in matches_raw:
            shaped = shape_banner(match, verbosity)
            shaped_ident = _clean(
                {
                    "ip": match.get("ip_str"),
                    "hostnames": match.get("hostnames"),
                    "org": match.get("org"),
                    "asn": match.get("asn"),
                    "location": _location(match),
                }
            )
            # Identity first so a truncated read still tells you which host
            # you are looking at.
            matches.append({**shaped_ident, **shaped})

    total = raw.get("total")
    result = _clean(
        {
            "query": query,
            "total": total,
            "page": page,
            "returned": len(matches),
            "facets": shape_facets(raw.get("facets")),
            "matches": matches,
        }
    )
    if isinstance(total, int) and total > len(matches):
        result["more_available"] = True
    return result


# --- heavy-field stripping and budget fitting ------------------------------


def strip_heavy(obj: Any, keep_all: bool = False) -> Any:
    """Remove the fields that are big and rarely worth their weight.

    Applies even at ``raw`` verbosity, because "raw" means "the fields Shodan
    returned" and not "a base64 screenshot in your context window". Anything
    genuinely dropped is announced through ``_omitted`` so nobody is left
    wondering whether the host really had no HTML.
    """
    if isinstance(obj, list):
        return [strip_heavy(item, keep_all) for item in obj]
    if not isinstance(obj, dict):
        return obj

    out: dict[str, Any] = {}
    omitted: list[str] = []
    for key, value in obj.items():
        if key == "screenshot" and isinstance(value, dict):
            kept = _clean({"hash": value.get("hash"), "labels": value.get("labels")})
            if kept:
                out[key] = kept
            omitted.append("screenshot.data")
            continue
        if key == "http" and isinstance(value, dict):
            inner = {k: v for k, v in value.items() if k not in _HEAVY_HTTP}
            favicon = value.get("favicon")
            if isinstance(favicon, dict) and favicon.get("hash") is not None:
                inner["favicon_hash"] = favicon["hash"]
            dropped = [f"http.{k}" for k in _HEAVY_HTTP if k in value]
            omitted.extend(dropped)
            out[key] = strip_heavy(inner, keep_all)
            continue
        if key == "ssl" and isinstance(value, dict):
            inner = {k: v for k, v in value.items() if k not in _HEAVY_SSL}
            chain = value.get("chain")
            if isinstance(chain, list) and chain:
                inner["chain_length"] = len(chain)
            omitted.extend(f"ssl.{k}" for k in _HEAVY_SSL if k in value)
            out[key] = strip_heavy(inner, keep_all)
            continue
        if key == "opts" and isinstance(value, dict):
            # Shodan's own docs call opts an experimental staging area. It is
            # where raw protocol dumps go to be enormous.
            omitted.append("opts")
            continue
        if key == "data" and isinstance(value, str) and len(value) > 2000:
            out[key] = _truncate(value, 2000)
            omitted.append("data (truncated)")
            continue
        out[key] = strip_heavy(value, keep_all)

    if omitted:
        out["_omitted"] = sorted(set(omitted))
    return out


def fit(payload: dict[str, Any], max_chars: int) -> dict[str, Any]:
    """Shrink a payload until it fits, degrading in a deliberate order.

    The order matters and it is not arbitrary. We give up prose before facts,
    detail before identity, and the low-severity tail before the critical head.
    Blind truncation of the serialized JSON is never an option: a model handed
    a half-closed object either fails to parse it or, worse, silently misreads
    the fragment.
    """
    if max_chars <= 0:
        return payload

    def size(obj: Any) -> int:
        return len(json.dumps(obj, default=str))

    if size(payload) <= max_chars:
        return payload

    trimmed = json.loads(json.dumps(payload, default=str))
    notes: list[str] = []

    # 1. CVE prose. The identifier and score carry the finding. The sentence
    #    of description is the model's to look up if it cares.
    for vulns in _walk_vuln_lists(trimmed):
        for row in vulns:
            if isinstance(row, dict) and "summary" in row:
                row.pop("summary", None)
    if _step_done(trimmed, max_chars, size, notes, "CVE descriptions dropped"):
        return _finish(trimmed, notes)

    # 2. Detail-level extras on each service.
    for service in _walk_services(trimmed):
        service.pop("banner_excerpt", None)
        if isinstance(service.get("http"), dict):
            service["http"].pop("headers", None)
    if _step_done(trimmed, max_chars, size, notes, "banner excerpts and HTTP headers dropped"):
        return _finish(trimmed, notes)

    # 3. Fewer matches / services, halving until it fits. The containers are
    #    found by walking rather than read off the top level, because a host
    #    result nests its services under "host" and a multi-host result nests
    #    them one level deeper again.
    containers = _find_containers(trimmed)
    while size(trimmed) > max_chars and any(len(items) > 1 for _, _, items in containers):
        progressed = False
        for _parent, key, items in containers:
            if len(items) <= 1:
                continue
            keep = max(1, len(items) // 2)
            dropped = len(items) - keep
            del items[keep:]
            notes.append(f"{dropped} {key} omitted to fit the size budget")
            progressed = True
        if not progressed:
            break
    if size(trimmed) <= max_chars:
        return _finish(trimmed, notes)

    # 4. Facet tails.
    facets = trimmed.get("facets")
    if isinstance(facets, dict):
        for name, rows in facets.items():
            if isinstance(rows, list) and len(rows) > 5:
                facets[name] = rows[:5]
        notes.append("facet lists capped at 5 values each")
        if size(trimmed) <= max_chars:
            return _finish(trimmed, notes)

    # 5. Last resort. Drop the collections entirely rather than returning
    #    something that will not parse, and be loud about it.
    for parent, key, items in _find_containers(trimmed):
        if items:
            dropped = len(items)
            parent[key] = []
            notes.append(f"all {dropped} {key} dropped, the payload could not be fitted")
    if size(trimmed) > max_chars:
        notes.append(
            "result still exceeds the size budget after trimming. Narrow the "
            "query or raise plugins.entries.shodan.max_result_chars"
        )
    return _finish(trimmed, notes)


def _finish(payload: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    if notes:
        payload["_truncation"] = notes
    return payload


def _step_done(payload, max_chars, size, notes, message) -> bool:
    """Record a degradation step and report whether the payload now fits.

    The note is recorded either way: the step already happened, and the reader
    deserves to know a field is missing whether or not it was enough.
    """
    notes.append(message)
    return size(payload) <= max_chars


_CONTAINER_KEYS = ("matches", "services", "hosts", "records", "exploits", "cves")


def _find_containers(payload: Any) -> list[tuple]:
    """Every trimmable list in the payload, as ``(parent, key, list)``.

    Returns parent references so the caller can replace a list outright, not
    just shorten it in place.
    """
    found: list[tuple] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _CONTAINER_KEYS and isinstance(value, list):
                    found.append((node, key, value))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    # Longest first, so halving hits the biggest offender before the tail.
    found.sort(key=lambda entry: len(entry[2]), reverse=True)
    return found


def _walk_vuln_lists(payload: Any) -> Iterable[list[Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("vulns"), list):
            yield payload["vulns"]
        for value in payload.values():
            yield from _walk_vuln_lists(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _walk_vuln_lists(item)


def _walk_services(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("services", "matches"):
            for item in payload.get(key) or []:
                if isinstance(item, dict):
                    yield item
        for value in payload.values():
            if isinstance(value, (dict, list)):
                yield from _walk_services(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _walk_services(item)


def envelope(
    data: dict[str, Any],
    *,
    max_chars: int,
    credits: dict[str, Any] | None = None,
    source: str = "shodan",
) -> dict[str, Any]:
    """Wrap a shaped result in the common success envelope.

    Every tool returns the same outer shape, so a model learns it once. The
    credit block is always present on credit-costing calls: seeing the balance
    fall is what makes an agent ration itself instead of discovering the wall.
    """
    payload: dict[str, Any] = {"ok": True, "source": source, **data}
    if credits:
        payload["credits"] = credits
    return fit(payload, max_chars)
