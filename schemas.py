"""Tool schemas: what the model reads before deciding to call anything.

The descriptions carry more weight than the code. Two things are said over and
over on purpose:

1. Which calls cost query credits and which do not. An agent that knows
   ``shodan_count`` is free will reach for it instead of paging a search.
2. What to do instead when a call is refused. A dead end makes a model retry
   the same thing. A signpost makes it take the cheap path.
"""

from __future__ import annotations

# --- core ------------------------------------------------------------------

SHODAN_HOST = {
    "name": "shodan_host",
    "description": (
        "Look up everything Shodan knows about one or more IP addresses: open "
        "ports, the service and version behind each one, TLS certificates, "
        "hostnames, the owning organization and ASN, geolocation, tags, and "
        "known CVEs.\n\n"
        "This is the workhorse. Use it whenever the question is about a "
        "specific host rather than a population of hosts. It does not spend "
        "query credits.\n\n"
        "With no API key configured it automatically falls back to InternetDB, "
        "the free keyless dataset, which gives ports, CPEs, tags and CVE ids "
        "but no banners, products, versions or certificates.\n\n"
        "Give it a hostname and it will resolve first, so 'example.com' works "
        "as well as an IP. Returns nothing for a host with no exposed services "
        "in the last scan window, which is a real answer rather than an error."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": (
                    "IP address, hostname, or a comma-separated list of up to "
                    "16 of either. Hostnames are resolved before lookup."
                ),
            },
            "history": {
                "type": "boolean",
                "description": (
                    "Include historical banners rather than only the latest. "
                    "Much larger output, so only ask for it when you need to see "
                    "how the host changed over time."
                ),
                "default": False,
            },
            "verbosity": {
                "type": "string",
                "enum": ["summary", "detail", "raw"],
                "description": (
                    "How much of each banner to return. 'summary' is the "
                    "default and is almost always right. Step up to 'detail' "
                    "for HTTP headers and full certificate fields, and only "
                    "use 'raw' when you need a field the shaped output drops."
                ),
            },
        },
        "required": ["ip"],
    },
}

SHODAN_SEARCH = {
    "name": "shodan_search",
    "description": (
        "Search Shodan's index of internet-exposed services and return the "
        "matching hosts.\n\n"
        "COSTS QUERY CREDITS: one per search whose query contains any filter "
        "(anything of the form 'name:value'), plus one more for each page past "
        "the first. A bare keyword search on page one is free.\n\n"
        "Before calling this, ask whether you actually need the individual "
        "hosts. If the question is 'how many', 'which countries', 'what "
        "products', 'which organizations' or anything else answerable by a "
        "total or a breakdown, use shodan_count instead, which takes the same "
        "query and the same facets and costs nothing.\n\n"
        "Query syntax is 'filter:value' with no space, double quotes around "
        "multi-word values, and a leading '-' to negate. Load the "
        "shodan:query-syntax skill for the full filter list rather than "
        "guessing filter names. Validate an unfamiliar query with "
        "shodan_meta(action='validate_query') first, which is free."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Shodan search query, e.g. 'apache country:DE', "
                    "'product:MongoDB -authentication', "
                    "'ssl.cert.subject.cn:\"example.com\"'."
                ),
            },
            "facets": {
                "type": "string",
                "description": (
                    "Comma-separated facets to aggregate alongside the "
                    "results, optionally with a size: 'country:10,org,port:20'. "
                    "Default size is 10, maximum 1000."
                ),
            },
            "page": {
                "type": "integer",
                "description": "1-indexed page. 100 results per page. Each page past the first costs an extra credit.",
                "default": 1,
            },
            "limit": {
                "type": "integer",
                "description": "Cap on how many matches to return from the page. Use it to keep results small.",
                "default": 25,
            },
            "verbosity": {
                "type": "string",
                "enum": ["summary", "detail", "raw"],
                "description": "How much of each match to return. Default 'summary'.",
            },
        },
        "required": ["query"],
    },
}

SHODAN_COUNT = {
    "name": "shodan_count",
    "description": (
        "Count how many hosts match a Shodan query, and optionally break the "
        "result down by any facet, WITHOUT SPENDING A QUERY CREDIT.\n\n"
        "Prefer this over shodan_search whenever you can. It accepts exactly "
        "the same query syntax and the same facets, and it answers most "
        "reconnaissance questions outright: how large an exposure is, which "
        "countries or organizations or ASNs it concentrates in, which products "
        "and versions are running, which ports are open across a population.\n\n"
        "The usual efficient pattern is to count first to understand the shape "
        "and size of the result set, then run one narrow shodan_search only if "
        "you genuinely need individual hosts."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Shodan search query, same syntax as shodan_search.",
            },
            "facets": {
                "type": "string",
                "description": (
                    "Comma-separated facets with optional sizes, e.g. "
                    "'country:20,org:10,port'. This is where the value is: the "
                    "breakdown is free."
                ),
            },
        },
        "required": ["query"],
    },
}

SHODAN_DNS = {
    "name": "shodan_dns",
    "description": (
        "DNS operations backed by Shodan's own passive DNS data.\n\n"
        "mode='domain' returns all known subdomains and DNS records for a "
        "registered domain. This is the fastest way to map an organization's "
        "external footprint, and it COSTS ONE QUERY CREDIT per lookup.\n\n"
        "mode='resolve' turns hostnames into IPs and mode='reverse' turns IPs "
        "into hostnames. Both are free. Use them freely."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["domain", "resolve", "reverse"],
                "description": "Which DNS operation to run. 'domain' costs a credit, the others are free.",
            },
            "target": {
                "type": "string",
                "description": (
                    "For 'domain': one registered domain like 'example.com'. "
                    "For 'resolve': comma-separated hostnames. "
                    "For 'reverse': comma-separated IP addresses."
                ),
            },
            "record_type": {
                "type": "string",
                "enum": ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT"],
                "description": "mode='domain' only. Restrict to one record type.",
            },
            "page": {
                "type": "integer",
                "description": "mode='domain' only. 100 records per page.",
                "default": 1,
            },
        },
        "required": ["mode", "target"],
    },
}

SHODAN_CVE = {
    "name": "shodan_cve",
    "description": (
        "Look up vulnerability data from Shodan's CVEDB. Free, needs no API "
        "key, and updated daily from NVD.\n\n"
        "action='get' fetches one CVE by id and returns its summary, CVSS "
        "(v2, v3 and v4 where available), EPSS exploitation-probability score, "
        "whether CISA lists it as known-exploited, the affected CPEs and the "
        "reference links.\n\n"
        "action='search' lists CVEs for a product or CPE, optionally filtered "
        "to known-exploited only or sorted by EPSS so the ones most likely to "
        "be attacked come first.\n\n"
        "Use this to turn a CVE id from a host lookup into something you can "
        "reason about, and to judge which of a long CVE list actually matters."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["get", "search", "cpes"],
                "description": "'get' one CVE, 'search' many, 'cpes' to find the CPE string for a product.",
                "default": "get",
            },
            "cve": {
                "type": "string",
                "description": "action='get'. CVE id, e.g. 'CVE-2021-44228'.",
            },
            "product": {
                "type": "string",
                "description": "action='search' or 'cpes'. Product name, e.g. 'nginx'.",
            },
            "cpe23": {"type": "string", "description": "action='search'. Exact CPE 2.3 string."},
            "kev_only": {
                "type": "boolean",
                "description": "action='search'. Only CVEs on CISA's Known Exploited Vulnerabilities list.",
                "default": False,
            },
            "sort_by_epss": {
                "type": "boolean",
                "description": "action='search'. Sort by exploitation probability, highest first.",
                "default": False,
            },
            "limit": {"type": "integer", "description": "Maximum rows to return.", "default": 20},
        },
        "required": [],
    },
}

SHODAN_ACCOUNT = {
    "name": "shodan_account",
    "description": (
        "Report the state of the Shodan account: plan tier, query credits "
        "remaining, scan credits remaining, monitored IP allowance, and the "
        "plugin's own per-session budget ledger.\n\n"
        "Free. Call it when you are about to run something expensive, when a "
        "call fails in a way that might be credits or plan related, or when "
        "the user asks what they have left."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "include_myip": {
                "type": "boolean",
                "description": "Also report the public IP this machine appears from.",
                "default": False,
            }
        },
        "required": [],
    },
}

SHODAN_META = {
    "name": "shodan_meta",
    "description": (
        "Introspect the Shodan search language and crawler. All free.\n\n"
        "action='validate_query' is the important one: it parses a query and "
        "reports which filters it understood and which it rejected, WITHOUT "
        "running the search. Use it before spending a credit on any query you "
        "are not certain about.\n\n"
        "action='filters' and action='facets' list every valid filter and "
        "facet name. action='ports' lists the ports Shodan crawls, and "
        "action='protocols' lists the protocols it speaks, which tells you "
        "what an on-demand scan can actually look for."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["validate_query", "filters", "facets", "ports", "protocols"],
                "description": "Which piece of metadata to fetch.",
                "default": "validate_query",
            },
            "query": {
                "type": "string",
                "description": "action='validate_query'. The query to parse.",
            },
        },
        "required": ["action"],
    },
}

# --- full profile only -----------------------------------------------------

SHODAN_SCAN = {
    "name": "shodan_scan",
    "description": (
        "Ask Shodan to actively scan specific IPs or networks now, rather than "
        "reading its existing index.\n\n"
        "THIS SENDS REAL PROBES TO REAL HOSTS AND SPENDS SCAN CREDITS, one per "
        "IP. It is disabled by default and requires the operator to opt in "
        "explicitly in config. If it refuses, that is policy, not a bug: say "
        "so and do not look for a way around it.\n\n"
        "Scans are asynchronous. Submit returns an id, and results appear in "
        "the normal index minutes later. Use action='status' to check, then "
        "shodan_host to read the results.\n\n"
        "Only scan hosts the user owns or is explicitly authorized to test."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["submit", "status", "list"],
                "description": "'submit' a new scan, check 'status' of one, or 'list' recent scans.",
                "default": "status",
            },
            "targets": {
                "type": "string",
                "description": "action='submit'. Comma-separated IPs or CIDR ranges. One scan credit per IP.",
            },
            "scan_id": {
                "type": "string",
                "description": "action='status'. The id returned by submit.",
            },
        },
        "required": ["action"],
    },
}

SHODAN_ALERT = {
    "name": "shodan_alert",
    "description": (
        "Manage Shodan network monitors: standing watches on IP ranges that "
        "fire when something changes, such as a new service appearing, an "
        "expired certificate, an open database, or a host matching a known "
        "vulnerability.\n\n"
        "Free, but bounded by the plan's monitored-IP allowance. Creating and "
        "deleting monitors changes account state that outlives this "
        "conversation, so confirm with the user before creating or deleting "
        "anything."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "list",
                    "info",
                    "create",
                    "delete",
                    "triggers",
                    "enable_trigger",
                    "disable_trigger",
                ],
                "description": "What to do. 'list' and 'triggers' are read-only and safe.",
                "default": "list",
            },
            "name": {"type": "string", "description": "action='create'. A label for the monitor."},
            "ips": {
                "type": "string",
                "description": "action='create'. Comma-separated IPs or CIDR ranges to watch.",
            },
            "alert_id": {
                "type": "string",
                "description": "The monitor id, for info, delete and trigger actions.",
            },
            "trigger": {
                "type": "string",
                "description": (
                    "Trigger name for enable_trigger/disable_trigger. Call "
                    "action='triggers' for the current list, which includes "
                    "'new_service', 'vulnerable', 'ssl_expired', "
                    "'open_database', 'malware' and 'industrial_control_system'."
                ),
            },
            "expires": {
                "type": "integer",
                "description": "action='create'. Seconds until the monitor expires. Omit for permanent.",
            },
        },
        "required": ["action"],
    },
}

SHODAN_EXPLOITS = {
    "name": "shodan_exploits",
    "description": (
        "Search Shodan's aggregated exploit database, which pulls from "
        "Exploit-DB, Metasploit and CVE records.\n\n"
        "Supports its own filter set, distinct from the host search language: "
        "author, bid, code, cve, date, description, msb, osvdb, platform, "
        "port, title and type (dos, exploit, local, remote, shellcode, "
        "webapps).\n\n"
        "Use it to answer whether public exploit code exists for a CVE you "
        "found on a host. Knowing a service is vulnerable and knowing it is "
        "trivially exploitable are different conclusions."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Exploit search query, e.g. 'cve:CVE-2021-44228' or 'apache type:remote'.",
            },
            "facets": {
                "type": "string",
                "description": "Comma-separated facets: author, platform, port, source, type.",
            },
            "count_only": {
                "type": "boolean",
                "description": "Return only the total, no results.",
                "default": False,
            },
            "page": {
                "type": "integer",
                "description": "1-indexed page, 100 per page.",
                "default": 1,
            },
            "limit": {
                "type": "integer",
                "description": "Maximum results to return.",
                "default": 15,
            },
        },
        "required": ["query"],
    },
}

SHODAN_QUERY = {
    "name": "shodan_query",
    "description": (
        "Browse the community query directory: search queries other Shodan "
        "users have saved and shared, with vote counts and tags.\n\n"
        "Free, and genuinely useful when you do not know how to express "
        "something. Searching for 'webcam' or 'industrial control' here "
        "returns queries people have already refined, which beats inventing a "
        "filter combination and paying a credit to find out it was wrong.\n\n"
        "Note the directory pages 10 items at a time, not 100."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["search", "list", "tags"],
                "description": "'search' the directory, 'list' the most popular, or fetch the 'tags' cloud.",
                "default": "search",
            },
            "query": {
                "type": "string",
                "description": "action='search'. What to look for, in plain words.",
            },
            "sort": {
                "type": "string",
                "enum": ["votes", "timestamp"],
                "description": "action='list'. Ordering.",
                "default": "votes",
            },
            "page": {
                "type": "integer",
                "description": "1-indexed page, 10 items per page.",
                "default": 1,
            },
        },
        "required": ["action"],
    },
}

SHODAN_TRENDS = {
    "name": "shodan_trends",
    "description": (
        "Query Shodan Trends, the historical index, to see how a query's match "
        "count changed month by month going back years.\n\n"
        "Requires an Enterprise plan. If the account does not have one this "
        "returns a plan error, which is expected rather than a failure to work "
        "around.\n\n"
        "Use it for questions about direction rather than state: whether an "
        "exposure is growing, when a product started appearing, how quickly a "
        "vulnerable version is being patched across the internet."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Shodan search query to trend over time."},
            "facets": {
                "type": "string",
                "description": "Comma-separated facets to break the trend down by.",
            },
        },
        "required": ["query"],
    },
}


ALL_SCHEMAS = {
    "shodan_host": SHODAN_HOST,
    "shodan_search": SHODAN_SEARCH,
    "shodan_count": SHODAN_COUNT,
    "shodan_dns": SHODAN_DNS,
    "shodan_cve": SHODAN_CVE,
    "shodan_account": SHODAN_ACCOUNT,
    "shodan_meta": SHODAN_META,
    "shodan_scan": SHODAN_SCAN,
    "shodan_alert": SHODAN_ALERT,
    "shodan_exploits": SHODAN_EXPLOITS,
    "shodan_query": SHODAN_QUERY,
    "shodan_trends": SHODAN_TRENDS,
}

EMOJI = {
    "shodan_host": "🛰️",
    "shodan_search": "🔎",
    "shodan_count": "🧮",
    "shodan_dns": "🌐",
    "shodan_cve": "🐛",
    "shodan_account": "💳",
    "shodan_meta": "📖",
    "shodan_scan": "📡",
    "shodan_alert": "🔔",
    "shodan_exploits": "💥",
    "shodan_query": "📚",
    "shodan_trends": "📈",
}
