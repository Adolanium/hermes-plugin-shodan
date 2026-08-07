---
name: query-syntax
description: Shodan search filters, facets and plan gating
version: 0.1.0
author: hermes-plugin-shodan
license: MIT
metadata:
  hermes:
    tags: [shodan, osint, recon, search, filters, facets]
---

# Shodan query syntax

Load this before writing any non-obvious Shodan query. Guessing filter names
wastes credits: a query with a filter Shodan does not recognize still costs a
credit to find out.

## The rules

- The form is `filter:value` with **no space** after the colon.
- Multi-word values need double quotes: `org:"SingTel Mobile"`.
- Negate with a leading `-` or `!`: `product:MongoDB -authentication`.
- Terms are ANDed. There is no OR operator.
- Search is case-insensitive in the REST API. The streaming `custom` endpoint
  is case-sensitive, which is a real difference and not a documentation error.
- With no filter at all, only the raw banner `data` field is searched.

## Before you spend a credit

Two free calls, in this order, save more credits than any other habit:

1. `shodan_meta(action="validate_query", query=...)` parses the query and
   reports which filters it understood and which it rejected, without running
   the search.
2. `shodan_count(query=..., facets=...)` returns the total and the breakdown
   for free. Most questions end here.

Only call `shodan_search` when you genuinely need individual hosts.

## Filters worth knowing by heart

**Network and ownership**
`ip`, `net` (CIDR), `asn` (as `asn:AS15169`), `org`, `isp`, `hostname`,
`domain`, `port`, `country`, `city`, `state`, `region`, `postal`, `geo`

**Software identity**
`product`, `version`, `os`, `device`, `cpe`, `shodan.module`, `tag`

**HTTP**
`http.title`, `http.status`, `http.html`, `http.component`, `http.server_hash`,
`http.favicon.hash`, `http.waf`, `http.securitytxt`, `http.dom_hash`,
`http.title_hash`, `http.headers_hash`, `http.robots_hash`, `http.html_hash`

**TLS**
`ssl`, `ssl.cert.subject.cn`, `ssl.cert.issuer.cn`, `ssl.cert.expired`,
`ssl.cert.fingerprint`, `ssl.cert.serial`, `ssl.cert.pubkey.bits`,
`ssl.version`, `ssl.alpn`, `ssl.jarm`, `ssl.ja3s`, `ssl.cipher.name`,
`ssl.chain_count`, `has_ssl`

**Cloud**
`cloud.provider`, `cloud.region`, `cloud.service`

**Vulnerability**
`vuln` (a CVE id), `has_vuln`

**Presence flags**
`has_screenshot`, `has_ipv6`, `has_ssl`, `has_vuln`

The complete list of all 94 filters is in `references/filters.md`.

## Plan gating

Two filters are restricted and will fail on lower tiers:

| Filter | Needs |
|---|---|
| `vuln:` | Small Business or above |
| `tag:` | Corporate or above |

`shodan_account` reports the current plan. `hermes shodan doctor` prints which
of the two the key can use. When a query fails on a plan error, drop the
restricted term rather than retrying the same thing.

## Facets

A facet is a server-side aggregation. Ask for `facets="country:20,org:10,port"`
and Shodan returns the top values with counts instead of, or alongside, the raw
hits. Default size is 10 and the maximum is 1000.

Facets are where `shodan_count` earns its place. "How many exposed Elasticsearch
instances are there, and in which countries and networks" is one free call:

```
shodan_count(query="product:Elasticsearch", facets="country:15,org:15,version:10")
```

**Facets and filters are not the same set.** Some things you can aggregate on
you cannot filter on, and the reverse:

- Facet only, no filter: `bitcoin.user_agent`, `mongodb.database.name`,
  `redis.key`, `rsync.module`, `ssh.cipher`, `ssh.fingerprint`, `ssh.mac`,
  `uptime`, `vuln.verified`
- Filter only, no facet: `net`, `hostname`, `geo`, `has_ssl`, `has_vuln`,
  `has_ipv6`, `scan`, `shodan.module`, `all`, `asset`, `http.html`,
  `http.securitytxt`

One case difference to watch: the facet is `ssl.cert.issuer.cn` in lowercase,
while the JSON field in a result is `ssl.cert.issuer.CN` in uppercase.

The complete list of all 90 facets is in `references/facets.md`.

## Worked examples

```
# Exposed databases in one organization, free
shodan_count(query='org:"Example Corp" product:MongoDB', facets="country,port")

# Certificates for a domain, including subdomains other tools miss
shodan_search(query='ssl.cert.subject.cn:"example.com"', limit=25)

# What is on this network, aggregated rather than enumerated
shodan_count(query="net:203.0.113.0/24", facets="port:50,product:20")

# Industrial control systems in one country, no credit spent
shodan_count(query="country:DE tag:ics", facets="product:20,city:10")

# Find a specific appliance by its favicon
shodan_search(query="http.favicon.hash:-335242539")

# Anything still serving an expired certificate in a network
shodan_count(query="net:203.0.113.0/24 ssl.cert.expired:true")
```

## When you do not know how to express something

`shodan_query(action="search", query="...")` searches the community directory
of saved queries. Other people have already refined queries for webcams,
industrial controllers, exposed databases and most other common targets.
Reading one of theirs beats inventing a filter combination and paying to
discover it was wrong. It is free, and only available under the `full` tool
profile.
