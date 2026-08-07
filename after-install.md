# Shodan is installed

Three commands to know:

```
hermes shodan doctor      why is this not working
hermes shodan info        plan, credits, which restricted filters you can use
hermes shodan profile     which tools the agent can currently see
```

If you skipped the API key prompt, run `hermes shodan setup`. It validates the
key against the live API before saving it. Without one the plugin still runs,
but only the keyless endpoints work: host lookups fall back to InternetDB and
CVE data comes from CVEDB.

If a gateway is running, restart it so the tools show up there too:

```
hermes gateway restart
```

## Defaults worth knowing

**Seven tools, not twelve.** The `core` profile covers host intel, search,
count, DNS, CVE lookups, account status and query validation. Scanning, alerts,
exploits, the community query directory and trends are behind
`hermes shodan profile full`.

**Active scanning is off.** `shodan_scan` sends real probes to real hosts and
spends scan credits, so it needs a second opt-in beyond the full profile:

```
hermes config set plugins.entries.shodan.scan.enabled true
```

**There is a credit budget.** 50 query credits per session by default. The
agent is told to prefer `shodan_count`, which answers totals and facet
breakdowns for free. Raise the ceiling with
`plugins.entries.shodan.budget.query_credits_per_session` in config.yaml.

## Try it

```
/shodan 1.1.1.1
/shodan product:MongoDB country:DE
```

Or just ask: "what's exposed on example.com".
