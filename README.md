# hermes-plugin-shodan

Shodan.io for [Hermes Agent](https://github.com/NousResearch/hermes-agent). Twelve tools, three skills, a CLI and a slash command. One line to install, one to remove. Nothing in Hermes core is touched.

Works with **no API key** via [InternetDB](https://internetdb.shodan.io) for host intel and [CVEDB](https://cvedb.shodan.io) for vulnerabilities. Paste a key when you want search, DNS domain enum, alerts, and the rest.

```bash
hermes plugins install Adolanium/hermes-plugin-shodan --enable
```

```bash
hermes plugins remove shodan
```

Install clones the plugin, optionally prompts for `SHODAN_API_KEY`, writes it to `~/.hermes/.env`, and enables it. Restart the gateway if one is running. Tools show up everywhere at once (desktop, CLI, TUI, gateway, ACP, cron) because every Hermes frontend shares the same tool registry.

---

## Demo

Host intel shaped for the context window, then free internet-scale counts (OpenSSH, open RDP, expired TLS, MongoDB). No pitch, just the CLI.

https://github.com/Adolanium/hermes-plugin-shodan/raw/main/docs/demo.mp4

<video src="docs/demo.mp4" controls width="100%"></video>

If the player does not embed in your viewer, open [docs/demo.mp4](docs/demo.mp4).

---

## Try it

After install (key optional for host lookups; counts need a key on most plans but cost **zero query credits**):

```bash
hermes shodan host 1.1.1.1
hermes shodan count 'port:22 product:OpenSSH' --facets version:5
hermes shodan count 'port:3389' --facets country:5
hermes shodan count 'ssl.cert.expired:true' --facets country:5
hermes shodan count 'product:MongoDB' --facets country:5
hermes shodan doctor
```

Captured live on a free-tier key (numbers move as the index moves):

| Query | Matches | Credits |
|---|---:|---|
| `port:22 product:OpenSSH` | ~14.8M | free |
| `port:3389` | ~2.0M | free |
| `ssl.cert.expired:true` | ~7.2M | free |
| `product:MongoDB` | ~134k | free |
| `host 1.1.1.1` | 12 services | free |

```
$ hermes shodan count 'port:22 product:OpenSSH' --facets version:5
14,773,533 matches for port:22 product:OpenSSH  (free)
version
  value                            count
  9.6p1 Ubuntu 3ubuntu13.18    2,789,193
  8.9p1 Ubuntu 3ubuntu0.16     1,509,106
  7.4                            976,610
  8.0                            643,142
  9.2p1 Debian 2+deb12u10        599,639
```

```
$ hermes shodan host 1.1.1.1
╭─────────────────────────────────────── host ────────────────────────────────────────╮
│ 1.1.1.1 · APNIC and Cloudflare DNS Resolver project · AS13335 · Brisbane, Australia │
╰─────────────────────────────────────────────────────────────────────────────────────╯
  hostnames  one.one.one.one
                                           12 exposed services
  port        service                     product       title
  53/tcp      dns-tcp
  53/udp      dns-udp
  80/tcp      http                                      CloudFlare Error Type 1000
  161/udp     snmp_v3
  443/tcp     https                       CloudFlare    403 Forbidden
  ...
```

Same host as raw Shodan JSON vs shaped for the model:

```
raw JSON      225,130 chars
summary         4,321 chars     52x smaller
detail         13,379 chars     17x smaller
```

---

## Why this exists

Wiring Shodan to an agent is easy. Wiring it so the agent is actually good at using it is not, and the two failure modes are brutal.

**The first is size.** One `/shodan/host/{ip}` response for a busy host is hundreds of kilobytes: every HTTP response body in full, base64 favicons, screenshots, complete PEM certificate chains, robots.txt, sitemaps. Hand that to a model and you have spent the context window on markup. A live lookup of `1.1.1.1`, which carries twelve banners, is the 52x example above.

Nothing important is gone. What survives is identity, location, tags, vulnerabilities sorted worst-first, and one tight line per exposed service with its product, version, HTTP title and certificate. What goes is the HTML.

Reproduce it yourself with `hermes shodan host 1.1.1.1 --json` against each verbosity. The ratio scales with how much of the host is web: a machine serving large pages compresses harder than one running only SSH.

**The second is money.** Shodan credits are real: a Membership account gets 100 query credits a month. An agent that decides to page through a broad search can spend all of them in under a minute, and nobody notices until the wall. So this plugin keeps its own ledger, refuses to cross the line, and shows the balance falling on every credit-costing result. When it refuses, it says what to do instead rather than dead-ending.

Most Shodan questions have a free answer. `/shodan/host/count` takes the same query syntax and the same facets as search and costs nothing, and host lookups are free too. The tool descriptions say so in capital letters, repeatedly, and the bundled recon skill teaches the count-first workflow. A full external map of a domain runs about one credit here. The naive version costs ten and returns less.

---

## The tools

Twelve tools, one `shodan` toolset, split across two profiles. The default `core` profile registers seven. Registering all twelve by default would cost every session a few thousand tokens of schema for capability most sessions never touch.

### core, on by default

| Tool | What it does | Credits |
|---|---|---|
| `shodan_host` | Full host intel: ports, products, versions, TLS certs, hostnames, org, ASN, geo, tags, CVEs. Accepts hostnames and comma lists. | free |
| `shodan_search` | Search the index and return matching hosts | 1 per filtered query, +1 per extra page |
| `shodan_count` | Totals and facet breakdowns for the same queries | **free** |
| `shodan_dns` | Subdomain enumeration, forward and reverse resolution | 1 for domain, free otherwise |
| `shodan_cve` | CVEDB: CVSS, EPSS, CISA KEV status, affected CPEs | free, no key needed |
| `shodan_account` | Plan, credits remaining, session ledger | free |
| `shodan_meta` | Filter and facet lists, crawled ports, protocols, and **query validation** | free |

`shodan_meta(action="validate_query")` is the pre-flight. It parses a query and reports which filters Shodan understood, without running the search. Checking a dork before paying for it is the cheapest habit in the whole workflow.

### full, opt in with `hermes shodan profile full`

| Tool | What it does |
|---|---|
| `shodan_scan` | Submit on-demand scans, poll status. Off by default, see below. |
| `shodan_alert` | Network monitors: create, list, delete, attach triggers |
| `shodan_exploits` | Search Exploit-DB, Metasploit and CVE exploit records |
| `shodan_query` | Browse the community directory of saved queries |
| `shodan_trends` | Historical match counts month by month (Enterprise) |

These are gated because they change state that outlives the conversation, send real traffic to real hosts, or serve a narrow enough need that the schema is not worth its context cost every session.

---

## What is actually built in here

**Response shaping with three levels.** `summary` by default, `detail` when the summary raised a question, `raw` when the model needs a field nobody thought to keep. Even `raw` drops screenshots and PEM chains, and says so through an `_omitted` list so nobody wonders whether the host really had no HTML.

**Budget-fitting that degrades in a deliberate order.** When a result still exceeds the character budget after shaping, it gives up prose before facts, detail before identity, and the low-severity CVE tail before the critical head. Blind truncation of serialized JSON is never an option, because a model handed a half-closed object either fails to parse it or silently misreads the fragment.

**A credit budget that refuses before the request goes out.** Per session, so concurrent gateway conversations and subagents each get their own rather than starving each other. The refusal carries a `next_step` pointing at `shodan_count`.

**Two opt-ins before a single scan packet leaves.** `shodan_scan` needs both `profile: full` and `scan.enabled: true`, plus an optional CIDR allowlist on top. The scan budget counts CIDRs by address, so a `/24` correctly costs 256 scan credits rather than one. If it refuses, the error tells the model that is policy and not to look for a way around it.

**A rate limiter that holds across threads.** Shodan allows one request per second, returns no rate-limit headers, no `Retry-After`, and has no documented 429 shape, so pacing ahead of time is the only option. Hermes runs subagents in the same process, and two of them reaching for Shodan at once would otherwise sail past the limit and get the shared key throttled.

**Error classification that survives contact with reality.** A 401 comes back as an nginx HTML page, not JSON. A 200 can carry an error body. Insufficient credits and a bad key both arrive as 401 on different endpoints, and only the prose distinguishes them. Each one maps to a typed error with its own `next_step`, because "out of credits", "wrong plan" and "transient 502" want three different reactions.

**A TTL and LRU cache on the free idempotent lookups.** Agents repeat themselves. The same IP gets looked up three times while reasoning about it.

**Graceful degradation with no key at all.** Host lookups fall back to InternetDB and CVE lookups go to CVEDB, both keyless. The result is labelled `"source": "internetdb"` and carries a note saying exactly what is missing, so a thin answer never gets presented as a full one. Tools that genuinely cannot work without a key hide themselves, except `shodan_account`, which stays visible precisely so the model can find out why the others are missing.

**The API key never leaks.** Shodan takes it as a query parameter, so it lands in every URL the client builds. Everything that could reach a log, a traceback or a tool result goes through redaction first, and there is a test asserting it.

---

## Examples

Everything below is real captured output from a live account, not illustration.

### Just ask

```
> what's exposed on 1.1.1.1?

  shodan_host(ip="1.1.1.1")

1.1.1.1 is Cloudflare's public resolver (AS13335, APNIC and Cloudflare DNS
Resolver project, Brisbane AU). Twelve services are exposed. DNS on 53 over
both TCP and UDP is the point of the host. The rest is Cloudflare's own edge:
HTTPS on 443 and 8443, the cPanel-adjacent ports 2082, 2083, 2086 and 2087,
and 8080/8880 all redirecting. SNMPv3 on 161/udp is the only one I would
question on a resolver. No CVEs recorded against it.
```

### What the model actually receives

The shaped result, which is the whole point of the plugin. Identity first, then ports, then one compact object per service:

```json
{
  "ok": true,
  "source": "shodan",
  "host": {
    "ip": "1.1.1.1",
    "hostnames": ["one.one.one.one", "victoria.schoolloop.com"],
    "org": "APNIC and Cloudflare DNS Resolver project",
    "isp": "Cloudflare, Inc.",
    "asn": "AS13335",
    "location": { "city": "Brisbane", "country": "Australia", "country_code": "AU" },
    "last_update": "2026-08-07T08:04:44.292653",
    "open_ports": [53, 80, 161, 443, 2082, 2083, 2086, 2087, 8080, 8443, 8880],
    "services": [
      { "port": 53, "transport": "tcp", "module": "dns-tcp" },
      { "port": 53, "transport": "udp", "module": "dns-udp" },
      {
        "port": 80,
        "transport": "tcp",
        "module": "http",
        "cpe": ["cpe:2.3:a:cloudflare:cloudflare"],
        "http": {
          "status": 403,
          "title": "CloudFlare Error Type 1000",
          "server": "cloudflare",
          "waf": "Cloudflare (Cloudflare Inc.)"
        }
      }
    ]
  }
}
```

Shodan's own response for that host is 225,130 characters. This is 4,321.

### Counting is free, and answers most questions

No credit spent on any of this:

```
$ hermes shodan count 'product:MongoDB' --facets country:5,version:4
133,750 matches for product:MongoDB  (free)
country
  value     count
  US       45,369
  CN       11,508
  DE       11,156
  ID        9,722
  FR        6,151
```

That is the exposure of an entire product across the internet, broken down by country, for nothing. The equivalent `shodan_search` would cost a credit and return a hundred rows you would then have to aggregate yourself.

### Diagnosing it

```
$ hermes shodan doctor
                              hermes shodan doctor
  check                         detail
  plugin enabled        ok      plugins.enabled in config.yaml
  api key               ok      $SHODAN_API_KEY = ab12************************cd34
  connectivity          ok      reached internetdb.shodan.io
  key valid             ok      plan: dev
  query credits         ok      99 left of 100/month
  scan credits          ok      100
  restricted filters            vuln: no (needs Small Business), tag: no (needs Corporate)
  profile                       core (7 tools)
  verbosity                     summary
  rate limit                    1.0/s, timeout 30.0s
  cache                         on, ttl 900s, 0 entries
  budget                        50 query / 0 scan credits per session
  active scanning       warn    disabled (opt-in)

tools: shodan_account, shodan_count, shodan_cve, shodan_dns, shodan_host,
shodan_meta, shodan_search

Everything checks out.
```

The restricted-filters row is the one people miss. It tells you before you spend a credit that this tier cannot run `vuln:` or `tag:`.

### In a conversation

```
> /shodan info

Shodan plan: dev
query credits: 99 left
scan credits: 100 left
monitored IPs: 0 of 16
session budget: 50 of 50 query credits remaining
```

### When it refuses

Both of these fail locally without touching the network, so neither costs anything. The `next_step` is the important field: it tells the model what to do instead of retrying.

```json
{
  "ok": false,
  "error": "Session query credit budget exhausted: this call needs 1 but only 0 of 0 remain.",
  "error_kind": "budget",
  "next_step": "The per-session credit budget set in config.yaml is spent. Use shodan_count (free) for aggregates, or tell the user to raise plugins.entries.shodan.budget.query_credits_per_session.",
  "details": { "kind": "query", "requested": 1, "remaining": 0, "budget": 0 }
}
```

```json
{
  "ok": false,
  "error": "On-demand scanning is turned off. Set plugins.entries.shodan.scan.enabled: true in config.yaml to allow it.",
  "error_kind": "scan_blocked",
  "next_step": "On-demand scanning is disabled by local policy. It is opt-in because it sends real probes to real hosts and spends scan credits. The user must set plugins.entries.shodan.scan.enabled: true (and profile: full) to allow it. Do not attempt to work around this."
}
```

### Turning a CVE into a decision

```
$ hermes shodan doctor        # confirms the plan first
> is CVE-2021-44228 still worth worrying about?

  shodan_cve(action="get", cve="CVE-2021-44228")

CVSS 10.0, EPSS 0.99999, on CISA's Known Exploited list, and flagged as used
in ransomware campaigns. EPSS that close to 1.0 means near-certain exploitation
attempts in the wild. This is not a theoretical finding.
```

That EPSS score and the KEV flag are why `shodan_cve` exists rather than leaving the model to reason about a bare CVE id. A CVSS 9.8 with an EPSS of 0.0004 and no KEV listing is a very different problem from this one.

---

## Configuration

Everything lives under `plugins.entries.shodan` in `~/.hermes/config.yaml` (`%LOCALAPPDATA%\Hermes\config.yaml` on Windows). Every key has a working default. An install where the only thing you did was paste an API key is a fully functional install.

```yaml
plugins:
  enabled: [shodan]
  entries:
    shodan:
      profile: core            # core | full
      verbosity: summary       # summary | detail | raw
      max_result_chars: 24000
      rate_limit_per_second: 1.0
      timeout_seconds: 30
      retries: 2
      internetdb_fallback: true

      cache:
        enabled: true
        ttl_seconds: 900
        max_entries: 512

      budget:
        query_credits_per_session: 50
        scan_credits_per_session: 0

      scan:
        enabled: false
        allowlist: []          # CIDRs. Empty means no range restriction.

      tools:
        enabled: []            # add specific full-profile tools to core
        disabled: []           # hide specific tools entirely
```

The `tools.enabled` list is how you get exactly one extra tool without taking all five. Adding `shodan_exploits` there keeps everything else in the core profile.

The API key comes from `SHODAN_API_KEY` in `~/.hermes/.env`. Point `api_key_env` at a different variable if you keep it elsewhere. A literal `api_key` in config.yaml works as a fallback but is the worse habit, so it loses to the environment.

---

## Terminal

```bash
hermes shodan setup            # store and validate a key
hermes shodan doctor           # why is this not working
hermes shodan info             # plan, credits, which restricted filters you can use
hermes shodan host 1.1.1.1
hermes shodan count 'product:MongoDB country:DE' --facets org:10,version:10
hermes shodan search 'org:"Example Corp" port:3389' --limit 20
hermes shodan profile full
hermes shodan budget
hermes shodan cache clear
```

`doctor` is the one that earns its keep. It checks whether the plugin is enabled, whether the key exists and works, whether the network is reachable (against the keyless endpoint, so a bad key and a broken network stay distinguishable), how many credits are left, which plan-gated filters you can actually use, and what the cache, budget and scan policy are set to. Then it prints the specific commands to fix whatever it found.

`setup` validates the key against the live API before writing anything. Storing a bad key and discovering it mid-conversation is the worst version of that experience.

---

## In conversation

```
/shodan 1.1.1.1              host intel for an IP or hostname
/shodan apache country:DE    free match count with country, org and port breakdowns
/shodan info                 plan and remaining credits
/shodan budget               this session's ledger
```

Dispatch is forgiving on purpose. An argument that parses as an address gets a host lookup, anything else gets a free count. The slash command never runs a credit-spending search, because a slash command should not quietly cost money. Ask the agent directly when you want the individual hosts.

---

## Skills

Three reference skills ship with the plugin, registered as plugin skills so they cost nothing until the model asks for one by name.

- `shodan:query-syntax` covers all 94 filters and 90 facets, which of them are plan-gated, and the cases where the facet set and filter set differ. This is what stops the model inventing filter names and paying a credit to find out it was wrong.
- `shodan:recon` is the credit-efficient attack surface workflow, plus a section on reading the data honestly: staleness, unverified CVEs inferred from version banners, approximate geolocation, and why absence is not proof.
- `shodan:monitoring` covers alerts, the fourteen triggers, notifier providers, and the trap where a freshly created alert has no triggers and therefore never fires.

Load one with `skill_view("shodan:query-syntax")`.

---

## Development

```bash
git clone https://github.com/Adolanium/hermes-plugin-shodan
cd hermes-plugin-shodan
pytest tests
```

125 tests. None of them call the Shodan API, so you can run the suite without an account and without spending credits. Responses come from a scripted transport rather than recorded fixtures, which is why the whole suite finishes in well under a second. Run them as `pytest tests` rather than bare `pytest`. Hermes requires an `__init__.py` at the plugin root, which makes pytest treat the root as a package and try to import that file standalone as a module named `__init__`. That cannot work, since it is the entry point of a relative-import package. The ini file in `tests/` pins rootdir so collection never walks up into it.

`tests/conftest.py` loads the plugin exactly the way `hermes_cli/plugins.py` does, as `hermes_plugins.shodan` with a synthetic namespace parent and a hand-set `__path__`. Not for authenticity's sake: relative imports either work under that arrangement or they do not, and importing the modules some more convenient way would mean the suite passes while the real thing fails to load.

Install a local checkout without going through GitHub:

```bash
hermes plugins install "file:///C:/Developer/Hermes/hermes-plugin-shodan" --enable
```

Debug discovery with `HERMES_PLUGINS_DEBUG=1 hermes plugins list`.

### Dependencies

None. `httpx`, `rich` and `pyyaml` are already pinned core dependencies of Hermes, and `pip_dependencies` in a plugin manifest is only auto-installed for memory providers anyway. A plugin that needs an install step is a plugin that breaks on somebody's machine.

### Why not the official `shodan` package

It has been dormant since December 2023. It is synchronous and requests-based, its rate limiter is a blocking busy-wait, and it collapses every failure into a single `APIError(str)` with the status code discarded, so an agent cannot tell "out of credits" from "bad key" from "transient 502". The API is about forty-five flat GETs with a query-string key. There is very little to wrap and a lot to get right.

It is still worth reading `client.py` before touching this code, because it documents things the official docs do not: the undocumented `limit` and `offset` parameters, the exact 401-HTML fallback, and the fact that Shodan wants Python-style capitalized booleans in the query string.

---

## Known limits

The Streaming API (`stream.shodan.io`) is not exposed. It is a long-lived connection, which does not fit a request/response tool. A future version could surface it as a background hook that feeds alerts into the conversation.

Notifier creation is not exposed either. Wiring a webhook is a durable change to someone's alerting path and is better done deliberately at [account.shodan.io](https://account.shodan.io) than through a chat message.

Batch host lookups use one request per IP rather than the comma-separated path form, which is Corporate tier and above only.

---

## A note on use

The core tools query a third-party index. That is passive reconnaissance and it is why they are safe to use freely.

`shodan_scan` is different. It asks Shodan to send real probes to real hosts, which is why it is off by default, needs two separate opt-ins, and refuses loudly rather than quietly. Only scan what you own or are explicitly authorized to test.

## License

MIT. See [LICENSE](LICENSE).
