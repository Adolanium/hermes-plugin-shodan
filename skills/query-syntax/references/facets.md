# Every Shodan facet

The complete list as returned by `/shodan/host/search/facets`. Verify with
`shodan_meta(action="facets")`, which is free.

Request them as `facets="name"` or `facets="name:size"`, comma-separated.
Default size 10, maximum 1000. Combine with `shodan_count` and the whole
breakdown costs nothing.

## The ones you will actually use

`country`, `org`, `port`, `product`, `asn`, `city`, `isp`, `os`, `version`,
`http.status`, `http.title`, `http.component`, `domain`, `tag`, `vuln`,
`ssl.version`, `cloud.provider`, `device`

## Complete list

**Location** `country`, `city`, `state`, `region`, `postal`

**Ownership** `asn`, `org`, `isp`, `ip`, `domain`, `link`

**Identity** `product`, `version`, `device`, `os`, `cpe`, `tag`, `hash`

**Vulnerability** `vuln`, `vuln.verified`

`vuln.verified` is facet-only, with no filter equivalent. It separates CVEs
Shodan actually confirmed from ones inferred from a version banner, which is a
meaningful distinction when you are deciding what to act on.

**Cloud** `cloud.provider`, `cloud.region`, `cloud.service`

**HTTP** `http.status`, `http.title`, `http.title_hash`, `http.html_hash`,
`http.dom_hash`, `http.server_hash`, `http.headers_hash`, `http.robots_hash`,
`http.favicon.hash`, `http.component`, `http.component_category`, `http.waf`

**TLS** `ssl.version`, `ssl.alpn`, `ssl.jarm`, `ssl.ja3s`, `ssl.chain_count`,
`ssl.cipher.name`, `ssl.cipher.bits`, `ssl.cipher.version`, `ssl.cert.alg`,
`ssl.cert.expired`, `ssl.cert.extension`, `ssl.cert.fingerprint`,
`ssl.cert.issuer.cn`, `ssl.cert.subject.cn`, `ssl.cert.serial`,
`ssl.cert.pubkey.bits`, `ssl.cert.pubkey.type`

**Screenshots** `has_screenshot`, `screenshot.hash`, `screenshot.label`

**Analytics** `google_ads`, `google_analytics`, `google_tag_manager`,
`meta_pixel`, `tiktok_pixel`, `x_pixel`

**SSH** `ssh.cipher`, `ssh.fingerprint`, `ssh.hassh`, `ssh.mac`, `ssh.type`

**SNMP** `snmp.contact`, `snmp.location`, `snmp.name`

**NTP** `ntp.ip`, `ntp.ip_count`, `ntp.more`, `ntp.port`

**Telnet** `telnet.do`, `telnet.dont`, `telnet.option`, `telnet.will`,
`telnet.wont`

**Bitcoin** `bitcoin.ip`, `bitcoin.ip_count`, `bitcoin.port`,
`bitcoin.user_agent`, `bitcoin.version`

**Service contents** `mongodb.database.name`, `redis.key`, `rsync.module`,
`open_dir.extension`, `open_dir.hash`

**Other** `uptime`

## Facet-only, no filter equivalent

`bitcoin.user_agent`, `mongodb.database.name`, `redis.key`, `rsync.module`,
`ssh.cipher`, `ssh.fingerprint`, `ssh.mac`, `uptime`, `vuln.verified`

You can aggregate on these but not search for a specific value.

## Retired

Older documentation mentions `geocluster`, `timestamp_day`, `timestamp_month`
and `timestamp_year`. None appear in the live facet list. Do not use them.
