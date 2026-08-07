"""Shaping is the thing that makes this plugin usable, so it gets the most tests.

The size assertions are the point. "It looks smaller" is not a guarantee. A
ratio the suite enforces is.
"""

from __future__ import annotations

import json

from hermes_plugins.shodan import shaping


def _fat_banner(port=443):
    """A banner shaped like a real one, including the parts that are enormous."""
    return {
        "port": port,
        "transport": "tcp",
        "product": "nginx",
        "version": "1.18.0",
        "data": "HTTP/1.1 200 OK\r\n" + ("x" * 5000),
        "timestamp": "2026-01-01T00:00:00.000000",
        "hostnames": ["www.example.com"],
        "_shodan": {"module": "https", "id": "abc", "crawler": "xyz"},
        "http": {
            "status": 200,
            "title": "Example Domain",
            "server": "nginx",
            "html": "<html>" + ("y" * 40000) + "</html>",
            "html_hash": 12345,
            "robots": "User-agent: *\n" + ("z" * 3000),
            "sitemap": "w" * 3000,
            "favicon": {"hash": -12345, "data": "b" * 20000},
            "headers": {"server": "nginx", "content-type": "text/html"},
            "components": {"jQuery": {"categories": ["JavaScript libraries"]}},
        },
        "ssl": {
            "versions": ["TLSv1.3", "-TLSv1.1", "TLSv1.2"],
            "jarm": "29d3fd00029d29d00042d43d00041d",
            "chain": ["-----BEGIN CERTIFICATE-----" + ("c" * 4000)] * 3,
            "chain_sha256": ["deadbeef"] * 3,
            "acceptable_cas": ["ca"] * 200,
            "cert": {
                "expired": False,
                "expires": "20270101000000Z",
                "subject": {"CN": "example.com"},
                "issuer": {"CN": "Example CA", "O": "Example"},
                "serial": 12345,
            },
        },
        "vulns": {
            "CVE-2020-0001": {"cvss": 4.3, "verified": False, "summary": "low " * 200},
            "CVE-2021-0002": {"cvss": 9.8, "verified": True, "summary": "critical " * 200},
            "CVE-2019-0003": {"cvss": 7.5, "verified": False, "summary": "medium " * 200},
        },
        "opts": {"raw": "q" * 30000},
    }


def _fat_host(ports=(80, 443, 22)):
    return {
        "ip_str": "203.0.113.10",
        "ip": 3405803786,
        "ports": list(ports),
        "hostnames": ["www.example.com"],
        "domains": ["example.com"],
        "org": "Example Corp",
        "isp": "Example ISP",
        "asn": "AS64500",
        "os": None,
        "city": "Berlin",
        "region_code": "BE",
        "country_name": "Germany",
        "country_code": "DE",
        "latitude": 52.52,
        "longitude": 13.405,
        "last_update": "2026-01-01T00:00:00.000000",
        "tags": ["cloud"],
        "vulns": ["CVE-2021-0002"],
        "data": [_fat_banner(p) for p in ports],
    }


class TestSizeReduction:
    def test_summary_is_dramatically_smaller_than_raw(self):
        raw = _fat_host()
        raw_size = len(json.dumps(raw))
        shaped_size = len(json.dumps(shaping.shape_host(raw, "summary")))

        # The fixture is ~300KB of mostly markup. Anything less than a 20x
        # reduction means a heavy field slipped through.
        assert raw_size > 200_000
        assert shaped_size < raw_size / 20
        assert shaped_size < 6_000

    def test_detail_is_bigger_than_summary_but_still_bounded(self):
        raw = _fat_host()
        summary = len(json.dumps(shaping.shape_host(raw, "summary")))
        detail = len(json.dumps(shaping.shape_host(raw, "detail")))
        assert summary < detail < len(json.dumps(raw)) / 10

    def test_raw_still_drops_the_unbounded_fields(self):
        shaped = shaping.shape_host(_fat_host(), "raw")
        serialized = json.dumps(shaped)
        # "raw" means every field Shodan returned, not a screenshot in your
        # context window.
        assert "yyyy" not in serialized
        assert "BEGIN CERTIFICATE" not in serialized
        assert "_omitted" in serialized


class TestHeavyFieldStripping:
    def test_html_favicon_and_chain_are_gone(self):
        shaped = shaping.shape_banner(_fat_banner(), "detail")
        serialized = json.dumps(shaped)
        for marker in ("<html>", "BEGIN CERTIFICATE", "User-agent"):
            assert marker not in serialized

    def test_useful_hashes_survive_the_strip(self):
        stripped = shaping.strip_heavy(_fat_banner())
        assert stripped["http"]["favicon_hash"] == -12345
        assert stripped["http"]["html_hash"] == 12345
        assert stripped["ssl"]["chain_length"] == 3

    def test_omissions_are_announced(self):
        stripped = shaping.strip_heavy(_fat_banner())
        assert "http.html" in stripped["_omitted"]
        assert "ssl.chain" in stripped["_omitted"]
        assert "opts" in stripped["_omitted"]


class TestVulns:
    def test_sorted_worst_first(self):
        rows = shaping.shape_vulns(_fat_banner()["vulns"])
        assert [r["cve"] for r in rows] == [
            "CVE-2021-0002",
            "CVE-2019-0003",
            "CVE-2020-0001",
        ]

    def test_internetdb_list_form_normalizes_to_the_same_shape(self):
        rows = shaping.shape_vulns(["CVE-2021-0002", "CVE-2020-0001"])
        assert rows == [{"cve": "CVE-2021-0002"}, {"cve": "CVE-2020-0001"}]

    def test_long_lists_are_capped_with_a_note(self):
        many = {f"CVE-2020-{i:04d}": {"cvss": i / 100} for i in range(120)}
        rows = shaping.shape_vulns(many, limit=10)
        assert len(rows) == 11
        assert "omitted" in rows[-1]["note"]

    def test_empty_is_empty_not_none(self):
        assert shaping.shape_vulns(None) == []
        assert shaping.shape_vulns({}) == []


class TestLocationAsymmetry:
    """Host lookups flatten location, search matches nest it. Both must work."""

    def test_flattened_form(self):
        shaped = shaping.shape_host(_fat_host(), "summary")
        assert shaped["location"]["city"] == "Berlin"
        assert shaped["location"]["country"] == "Germany"

    def test_nested_form(self):
        raw = {
            "matches": [
                {
                    "ip_str": "203.0.113.1",
                    "port": 80,
                    "location": {"city": "Paris", "country_name": "France", "country_code": "FR"},
                }
            ],
            "total": 1,
        }
        shaped = shaping.shape_search(raw, query="test")
        assert shaped["matches"][0]["location"]["city"] == "Paris"
        assert shaped["matches"][0]["location"]["country"] == "France"


class TestFit:
    def test_output_is_always_valid_json(self):
        big = {"ok": True, "host": shaping.shape_host(_fat_host(range(1, 60)), "detail")}
        fitted = shaping.fit(big, 3_000)
        # The whole point: never truncate a serialized string mid-structure.
        json.loads(json.dumps(fitted))

    def test_it_actually_gets_under_the_budget(self):
        big = {"ok": True, "host": shaping.shape_host(_fat_host(range(1, 60)), "detail")}
        fitted = shaping.fit(big, 4_000)
        assert len(json.dumps(fitted, default=str)) <= 4_500  # allow the notes

    def test_small_payloads_pass_through_untouched(self):
        payload = {"ok": True, "total": 5}
        assert shaping.fit(payload, 24_000) == payload
        assert "_truncation" not in shaping.fit(payload, 24_000)

    def test_degradation_is_reported(self):
        big = {"ok": True, "host": shaping.shape_host(_fat_host(range(1, 40)), "detail")}
        fitted = shaping.fit(big, 2_000)
        assert fitted["_truncation"], "a trimmed payload must say it was trimmed"

    def test_prose_goes_before_facts(self):
        """CVE summaries are dropped before CVE ids are."""
        payload = {
            "ok": True,
            "vulns": [
                {"cve": f"CVE-2021-{i:04d}", "cvss": 9.0, "summary": "x" * 200} for i in range(20)
            ],
        }
        fitted = shaping.fit(payload, 1_500)
        assert all("summary" not in row for row in fitted["vulns"])
        assert len(fitted["vulns"]) == 20, "ids should survive when only prose was needed"


class TestSearchShape:
    def test_total_and_facets_come_through(self):
        raw = {
            "total": 4213,
            "matches": [{"ip_str": "1.2.3.4", "port": 443}],
            "facets": {"country": [{"count": 100, "value": "DE"}]},
        }
        shaped = shaping.shape_search(raw, query="nginx")
        assert shaped["total"] == 4213
        assert shaped["facets"]["country"] == [{"value": "DE", "count": 100}]
        assert shaped["more_available"] is True

    def test_no_more_flag_when_everything_returned(self):
        raw = {"total": 1, "matches": [{"ip_str": "1.2.3.4", "port": 443}]}
        assert "more_available" not in shaping.shape_search(raw, query="nginx")


class TestAsnFormatting:
    """Shodan returns "AS13335", so a naive prefix yields "ASAS13335"."""

    def test_already_prefixed_is_left_alone(self):
        assert shaping.format_asn("AS13335") == "AS13335"

    def test_bare_number_gets_a_prefix(self):
        assert shaping.format_asn("13335") == "AS13335"
        assert shaping.format_asn(13335) == "AS13335"

    def test_empty_is_none_so_it_drops_out_of_a_join(self):
        assert shaping.format_asn(None) is None
        assert shaping.format_asn("") is None


class TestInternetDB:
    def test_shape_and_the_honest_caveat(self):
        shaped = shaping.shape_internetdb(
            {
                "ip": "1.1.1.1",
                "ports": [443, 80],
                "hostnames": ["one.one.one.one"],
                "cpes": ["cpe:/a:nginx:nginx"],
                "tags": ["cdn"],
                "vulns": ["CVE-2021-0002"],
            }
        )
        assert shaped["open_ports"] == [80, 443]
        assert shaped["source"] == "internetdb"
        assert "No banners" in shaped["note"]


class TestDeterminism:
    def test_repeated_shaping_is_byte_identical(self):
        """Stable output keeps prompt caches warm across repeated lookups."""
        raw = _fat_host()
        first = json.dumps(shaping.shape_host(raw, "summary"))
        second = json.dumps(shaping.shape_host(raw, "summary"))
        assert first == second
