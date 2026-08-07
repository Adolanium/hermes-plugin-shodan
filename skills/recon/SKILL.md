---
name: recon
description: Credit-efficient attack surface mapping with Shodan
version: 0.1.0
author: hermes-plugin-shodan
license: MIT
metadata:
  hermes:
    tags: [shodan, osint, recon, attack-surface, asm, security]
---

# Attack surface recon with Shodan

A method for mapping what an organization exposes, ordered so the free calls
do the work and the paid ones only run when they have to.

## The shape of it

Free calls first, always. `shodan_count` and `shodan_host` cost nothing;
`shodan_search` and `shodan_dns(mode="domain")` cost query credits. A
Membership account gets 100 query credits per month, so a careless agent can
burn a month's budget in one conversation.

```
1. Enumerate    what names and addresses belong to the target
2. Aggregate    how big the exposure is and what shape it has   (free)
3. Enumerate    only the specific hosts you actually need to see (costs)
4. Assess       what is vulnerable and what is actually exploitable
```

## 1. Enumerate the footprint

Start with what the user gave you and expand outward.

```
shodan_dns(mode="domain", target="example.com")
```

One credit, and it returns every subdomain Shodan has seen. This is usually
the highest-value single call in the whole workflow, because subdomains are
where forgotten infrastructure lives.

Then find hosts by certificate rather than by DNS. Certificates catch things
DNS does not, including staging environments and internal names that leaked
into a public cert:

```
shodan_count(query='ssl.cert.subject.cn:"example.com"', facets="org:10,asn:10")
```

If the user gave you a network or an ASN, use it directly. `net:` and `asn:`
are the cleanest scoping filters available.

## 2. Aggregate before you enumerate

This step is where the credits get saved. Ask `shodan_count` with facets and
you get the whole shape of the exposure for free:

```
shodan_count(
  query='org:"Example Corp"',
  facets="port:25,product:25,country:10,asn:10,vuln:20"
)
```

That single free call tells you how many hosts, which ports dominate, what
software is running, where it is hosted, and which CVEs appear. Most recon
questions are fully answered right here.

Follow up with targeted counts, still free:

```
shodan_count(query='org:"Example Corp" port:3389')     # exposed RDP
shodan_count(query='org:"Example Corp" has_ssl:false') # plaintext services
shodan_count(query='org:"Example Corp" ssl.cert.expired:true')
```

## 3. Enumerate only what you need

Now you know the shape, so narrow before you search. Do not page through a
broad query.

```
shodan_search(query='org:"Example Corp" port:3389', limit=25)
```

Rules of thumb:

- One credit per filtered query, plus one per page past the first. Stay on
  page one unless you have a reason not to.
- `limit` keeps the output small. It does not reduce the credit cost, but it
  does keep the context window usable.
- Validate an unfamiliar query first with
  `shodan_meta(action="validate_query")`. Free, and catches typos that would
  otherwise cost a credit to discover.

For individual hosts that matter, `shodan_host` is free and much richer than a
search result. If you have fifteen IPs to look at, fifteen host lookups cost
nothing while one search costs a credit.

## 4. Assess

A CVE list on a host is a starting point, not a conclusion. Two free calls
turn it into a judgment:

```
shodan_cve(action="get", cve="CVE-2021-44228")
```

Read `epss` (probability of exploitation in the wild) and `known_exploited`
(whether CISA lists it as actively exploited). A CVSS 9.8 with an EPSS of
0.0004 and no KEV listing is a very different finding from a CVSS 7.5 that is
being exploited today.

Then check whether public exploit code exists, if the `full` profile is on:

```
shodan_exploits(query="cve:CVE-2021-44228")
```

## Reading the data honestly

- **Shodan data is a snapshot, not live.** `last_update` on a host and
  `timestamp` on a banner tell you how stale it is. A service listed here may
  have been shut down last week.
- **InternetDB results are much thinner.** When a host result says
  `"source": "internetdb"` you are seeing ports, CPEs, tags and CVE ids only,
  refreshed weekly, with no banners or versions. Say so rather than presenting
  it as a full picture.
- **Unverified CVEs are inferred from version banners.** Shodan flags many
  vulnerabilities purely from a version string, so a patched-but-not-rebranded
  service shows up as vulnerable when it is not. Treat `verified: true` as
  meaningfully stronger evidence.
- **Geolocation is approximate.** Shodan says so itself. City-level claims are
  weak and coordinates are weaker.
- **Absence is not proof.** No result means Shodan has not seen it, which is
  not the same as it not existing. Shodan only crawls the ports listed by
  `shodan_meta(action="ports")`.

## Scope and authority

This is passive reconnaissance against a third-party index, which is why the
core tools are safe to use freely. Active scanning is not, and that is why
`shodan_scan` is off by default and needs two separate opt-ins.

Before submitting any scan, be sure the user owns the target or is explicitly
authorized to test it. If the plugin refuses a scan, that is deliberate policy
and not a bug to route around. Report it and move on.

## A worked sequence

Mapping `example.com` end to end, and what it costs:

```
shodan_dns(mode="domain", target="example.com")                    1 credit
shodan_count(query='ssl.cert.subject.cn:"example.com"',
             facets="org:10,asn:10,port:20")                       free
shodan_count(query='org:"Example Corp"',
             facets="port:25,product:25,vuln:20")                  free
shodan_host(ip="<the interesting ones, comma separated>")          free
shodan_cve(action="get", cve="<worst CVE found>")                  free
```

One credit for a full external map. The naive version of the same task, paging
through searches, costs ten or more and returns less.
