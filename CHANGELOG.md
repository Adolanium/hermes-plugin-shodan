# Changelog

## 0.1.0

First release.

Twelve tools across a `core` and `full` profile, three bundled skills, a
`hermes shodan` CLI and a `/shodan` slash command.

- Response shaping at three verbosity levels, with budget-fitting that degrades
  in a fixed order instead of truncating JSON mid-structure. A live lookup of
  `1.1.1.1` drops from 225,130 characters to 4,321, a factor of 52.
- Per-session query and scan credit budgets, enforced before the request goes
  out, with the remaining balance reported on every credit-costing result.
- On-demand scanning behind two independent opt-ins plus an optional CIDR
  allowlist. CIDR targets are costed by address count.
- Shared 1 rps rate limiter that holds across threads, so concurrent subagents
  cannot blow through the shared key's limit.
- Typed error classification covering the cases Shodan's docs do not: HTML 401
  bodies, error payloads returned with a 200, and insufficient-credit responses
  that arrive as 401.
- Keyless fallback to InternetDB and CVEDB, with the degraded result labelled
  as such.
- API key redaction across logs, errors, tool results and cache keys.
- TTL and LRU caching on the free idempotent lookups.
- 125 tests, none of which call the Shodan API, so the suite runs without an
  account and spends no credits.
