# Every Shodan search filter

The complete list as returned by `/shodan/host/search/filters`. Verify it is
still current with `shodan_meta(action="filters")`, which is free.

`vuln` requires Small Business or above. `tag` requires Corporate or above.
Everything else works from Membership up.

## Network and ownership

| Filter | Matches |
|---|---|
| `ip` | Exact IP address |
| `net` | CIDR range, e.g. `net:203.0.113.0/24` |
| `asn` | Autonomous system, e.g. `asn:AS15169` |
| `org` | Organization that owns the address space |
| `isp` | Internet service provider |
| `hostname` | Any hostname on the host |
| `domain` | Registered domain |
| `port` | Port number |
| `link` | Physical network link type |
| `has_ipv6` | Host has an IPv6 address |
| `asset` | Asset grouping (organization accounts) |
| `scan` | Results from a specific on-demand scan id |
| `all` | Search across every field rather than just the banner |

## Location

`country`, `city`, `state`, `region`, `postal`, `geo` (latitude, longitude and
optional radius)

## Software identity

| Filter | Matches |
|---|---|
| `product` | Software name, e.g. `product:nginx` |
| `version` | Software version |
| `os` | Operating system |
| `device` | Device type |
| `cpe` | Common Platform Enumeration string |
| `shodan.module` | The crawler module that produced the banner |
| `tag` | Shodan-assigned tag. **Corporate or above** |
| `hash` | Hash of the raw banner data |

## HTTP

`http.title`, `http.title_hash`, `http.status`, `http.html`, `http.html_hash`,
`http.dom_hash`, `http.server_hash`, `http.headers_hash`, `http.robots_hash`,
`http.securitytxt`, `http.favicon.hash`, `http.component`,
`http.component_category`, `http.waf`

`http.favicon.hash` is the useful one for fingerprinting a specific appliance
or vendor product across the internet.

## TLS

`ssl`, `has_ssl`, `ssl.version`, `ssl.alpn`, `ssl.jarm`, `ssl.ja3s`,
`ssl.chain_count`, `ssl.cipher.name`, `ssl.cipher.bits`, `ssl.cipher.version`,
`ssl.cert.alg`, `ssl.cert.expired`, `ssl.cert.extension`,
`ssl.cert.fingerprint`, `ssl.cert.issuer.cn`, `ssl.cert.subject.cn`,
`ssl.cert.serial`, `ssl.cert.pubkey.bits`, `ssl.cert.pubkey.type`

## Cloud

`cloud.provider`, `cloud.region`, `cloud.service`

## Vulnerability

`vuln` (a CVE id, **Small Business or above**), `has_vuln`

## Screenshots

`has_screenshot`, `screenshot.hash`, `screenshot.label`

## Web analytics and tracking pixels

`google_ads`, `google_analytics`, `google_tag_manager`, `meta_pixel`,
`tiktok_pixel`, `x_pixel`

Useful for attributing infrastructure: two hosts sharing an analytics id often
belong to the same operator even when nothing else connects them.

## Protocol specific

**SSH** `ssh.hassh`, `ssh.type`

**SNMP** `snmp.contact`, `snmp.location`, `snmp.name`

**NTP** `ntp.ip`, `ntp.ip_count`, `ntp.more`, `ntp.port`

**Telnet** `telnet.do`, `telnet.dont`, `telnet.option`, `telnet.will`,
`telnet.wont`

**Bitcoin** `bitcoin.ip`, `bitcoin.ip_count`, `bitcoin.port`,
`bitcoin.version`

**Open directories** `open_dir.extension`, `open_dir.hash`
