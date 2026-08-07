from __future__ import annotations

import json

from conftest import FakeResponse
from hermes_plugins.shodan import config as config_mod
from hermes_plugins.shodan import handlers_core, handlers_full


def call(handler, args=None, **kwargs):
    return json.loads(handler(args or {}, **kwargs))


HOST_RESPONSE = {
    "ip_str": "1.1.1.1",
    "org": "Cloudflare",
    "asn": "AS13335",
    "country_name": "Australia",
    "city": "Sydney",
    "hostnames": ["one.one.one.one"],
    "ports": [53, 443],
    "data": [
        {"port": 443, "transport": "tcp", "product": "cloudflare", "_shodan": {"module": "https"}},
        {"port": 53, "transport": "udp", "_shodan": {"module": "dns-udp"}},
    ],
}


class TestHost:
    def test_single_host_returns_a_host_key(self, fake_client, budget_reset):
        fake_client([FakeResponse(200, HOST_RESPONSE)])
        result = call(handlers_core.shodan_host, {"ip": "1.1.1.1"})
        assert result["ok"] is True
        assert result["host"]["ip"] == "1.1.1.1"
        assert result["host"]["open_ports"] == [53, 443]

    def test_never_sends_minify_on_a_host_lookup(self, fake_client, budget_reset):
        """minify on /shodan/host/{ip} means "no banners at all".

        Unlike on /shodan/host/search, where it only trims oversized fields,
        here it strips the products, versions, titles and certificates that
        the summary exists to show. Sending it made summary lookups return a
        bare host envelope with an empty services list.
        """
        _, transport = fake_client([FakeResponse(200, HOST_RESPONSE)])
        result = call(handlers_core.shodan_host, {"ip": "1.1.1.1"})

        assert "minify" not in transport.calls[0]["params"]
        assert len(result["host"]["services"]) == 2

    def test_open_ports_fall_back_to_the_top_level_list(self, fake_client, budget_reset):
        """A banner-less response should still report which ports are open."""
        fake_client([FakeResponse(200, {"ip_str": "1.1.1.1", "ports": [443, 53], "data": []})])
        result = call(handlers_core.shodan_host, {"ip": "1.1.1.1"})
        assert result["host"]["open_ports"] == [53, 443]

    def test_missing_target_is_a_clean_refusal(self, fake_client, budget_reset):
        fake_client([])
        result = call(handlers_core.shodan_host, {})
        assert result["ok"] is False
        assert result["error_kind"] == "bad_request"

    def test_not_found_is_reported_as_an_answer_not_an_error(self, fake_client, budget_reset):
        fake_client([FakeResponse(404, {"error": "No information available"})])
        result = call(handlers_core.shodan_host, {"ip": "203.0.113.99"})
        assert result["ok"] is True
        assert result["no_data_for"] == ["203.0.113.99"]
        assert "scan window" in result["note"]

    def test_falls_back_to_internetdb_without_a_key(
        self, fake_client, isolated_config, budget_reset
    ):
        config_mod.reset()
        _, transport = fake_client(
            [
                FakeResponse(
                    200,
                    {
                        "ip": "1.1.1.1",
                        "ports": [443],
                        "vulns": [],
                        "tags": [],
                        "cpes": [],
                        "hostnames": [],
                    },
                )
            ],
            api_key=None,
        )
        result = call(handlers_core.shodan_host, {"ip": "1.1.1.1"})
        assert result["ok"] is True
        assert result["source"] == "internetdb"
        assert "degraded" in result
        assert "internetdb.shodan.io" in transport.calls[0]["url"]

    def test_falls_back_when_credits_run_out(self, fake_client, budget_reset):
        _, transport = fake_client(
            [
                FakeResponse(401, {"error": "Insufficient query credits"}),
                FakeResponse(
                    200,
                    {
                        "ip": "1.1.1.1",
                        "ports": [80],
                        "vulns": [],
                        "tags": [],
                        "cpes": [],
                        "hostnames": [],
                    },
                ),
            ]
        )
        result = call(handlers_core.shodan_host, {"ip": "1.1.1.1"})
        assert result["ok"] is True
        assert result["source"] == "internetdb"
        assert len(transport.calls) == 2

    def test_fallback_can_be_turned_off(self, fake_client, isolated_config, budget_reset):
        isolated_config["internetdb_fallback"] = False
        config_mod.reset()
        fake_client([], api_key=None)
        result = call(handlers_core.shodan_host, {"ip": "1.1.1.1"})
        assert result["ok"] is False
        assert result["error_kind"] == "missing_api_key"


class TestSearchAndCount:
    def test_search_spends_a_credit_for_a_filtered_query(self, fake_client, budget_reset):
        fake_client(
            [FakeResponse(200, {"total": 12, "matches": [{"ip_str": "1.2.3.4", "port": 80}]})]
        )
        result = call(handlers_core.shodan_search, {"query": "nginx country:DE"})
        assert result["credits"]["spent_by_this_call"] == 1
        assert result["credits"]["query_credits_spent"] == 1

    def test_bare_keyword_search_costs_nothing(self, fake_client, budget_reset):
        fake_client([FakeResponse(200, {"total": 3, "matches": []})])
        result = call(handlers_core.shodan_search, {"query": "nginx"})
        assert result["credits"]["spent_by_this_call"] == 0

    def test_budget_refuses_before_the_request_goes_out(
        self, fake_client, isolated_config, budget_reset
    ):
        isolated_config["budget"] = {"query_credits_per_session": 0}
        config_mod.reset()
        _, transport = fake_client([])
        result = call(handlers_core.shodan_search, {"query": "nginx country:DE"})
        assert result["ok"] is False
        assert result["error_kind"] == "budget"
        assert "shodan_count" in result["next_step"]
        assert transport.calls == [], "a refused call must not reach the network"

    def test_count_is_free_and_says_so(self, fake_client, budget_reset):
        fake_client(
            [
                FakeResponse(
                    200, {"total": 900, "facets": {"country": [{"count": 5, "value": "DE"}]}}
                )
            ]
        )
        result = call(
            handlers_core.shodan_count, {"query": "nginx country:DE", "facets": "country"}
        )
        assert result["total"] == 900
        assert "free" in result["cost"]
        assert "credits" not in result

    def test_limit_trims_matches(self, fake_client, budget_reset):
        matches = [{"ip_str": f"1.2.3.{i}", "port": 80} for i in range(50)]
        fake_client([FakeResponse(200, {"total": 50, "matches": matches})])
        result = call(handlers_core.shodan_search, {"query": "nginx", "limit": 5})
        assert len(result["matches"]) == 5

    def test_minify_is_sent_as_a_capitalized_bool(self, fake_client, budget_reset):
        _, transport = fake_client([FakeResponse(200, {"total": 0, "matches": []})])
        call(handlers_core.shodan_search, {"query": "nginx"})
        assert transport.calls[0]["params"]["minify"] == "True"


class TestDns:
    def test_resolve_is_free(self, fake_client, budget_reset):
        fake_client([FakeResponse(200, {"example.com": "93.184.216.34"})])
        result = call(handlers_core.shodan_dns, {"mode": "resolve", "target": "example.com"})
        assert result["resolved"]["example.com"] == "93.184.216.34"
        assert result["cost"] == "free"

    def test_domain_lookup_charges_a_credit(self, fake_client, budget_reset):
        fake_client(
            [FakeResponse(200, {"domain": "example.com", "subdomains": ["www"], "data": []})]
        )
        result = call(handlers_core.shodan_dns, {"mode": "domain", "target": "example.com"})
        assert result["credits"]["spent_by_this_call"] == 1
        assert result["subdomain_count"] == 1

    def test_unknown_mode_is_rejected(self, fake_client, budget_reset):
        fake_client([])
        result = call(handlers_core.shodan_dns, {"mode": "teleport", "target": "x"})
        assert result["ok"] is False


class TestMeta:
    def test_validate_query_reports_success(self, fake_client):
        fake_client([FakeResponse(200, {"errors": [], "filters": ["country"], "string": "nginx"})])
        result = call(
            handlers_core.shodan_meta, {"action": "validate_query", "query": "nginx country:DE"}
        )
        assert result["valid"] is True
        assert result["filters_used"] == ["country"]

    def test_validate_query_reports_failure(self, fake_client):
        fake_client([FakeResponse(200, {"errors": ["Invalid filter: teleport"], "filters": []})])
        result = call(
            handlers_core.shodan_meta, {"action": "validate_query", "query": "teleport:yes"}
        )
        assert result["valid"] is False
        assert result["errors"]


class TestScanGating:
    def test_scanning_is_refused_by_default(self, fake_client, isolated_config, budget_reset):
        isolated_config["profile"] = "full"
        config_mod.reset()
        _, transport = fake_client([])
        result = call(handlers_full.shodan_scan, {"action": "submit", "targets": "203.0.113.1"})
        assert result["ok"] is False
        assert result["error_kind"] == "scan_blocked"
        assert "Do not attempt to work around this" in result["next_step"]
        assert transport.calls == []

    def test_allowlist_blocks_targets_outside_it(self, fake_client, isolated_config, budget_reset):
        isolated_config.update(
            {
                "profile": "full",
                "scan": {"enabled": True, "allowlist": ["10.0.0.0/8"]},
                "budget": {"scan_credits_per_session": 100},
            }
        )
        config_mod.reset()
        _, transport = fake_client([])
        result = call(handlers_full.shodan_scan, {"action": "submit", "targets": "8.8.8.8"})
        assert result["error_kind"] == "scan_blocked"
        assert result["details"]["blocked"] == ["8.8.8.8"]
        assert transport.calls == []

    def test_scan_budget_counts_a_cidr_by_address_count(
        self, fake_client, isolated_config, budget_reset
    ):
        isolated_config.update(
            {
                "profile": "full",
                "scan": {"enabled": True},
                "budget": {"scan_credits_per_session": 10},
            }
        )
        config_mod.reset()
        _, transport = fake_client([])
        # A /24 is 256 scan credits, well past a budget of 10.
        result = call(handlers_full.shodan_scan, {"action": "submit", "targets": "203.0.113.0/24"})
        assert result["error_kind"] == "budget"
        assert transport.calls == []

    def test_an_allowed_scan_goes_through(self, fake_client, isolated_config, budget_reset):
        isolated_config.update(
            {
                "profile": "full",
                "scan": {"enabled": True, "allowlist": ["10.0.0.0/8"]},
                "budget": {"scan_credits_per_session": 10},
            }
        )
        config_mod.reset()
        _, transport = fake_client(
            [FakeResponse(200, {"id": "SCANID", "count": 1, "credits_left": 99})]
        )
        result = call(handlers_full.shodan_scan, {"action": "submit", "targets": "10.1.2.3"})
        assert result["ok"] is True
        assert result["scan_id"] == "SCANID"
        assert len(transport.calls) == 1

    def test_status_and_list_need_no_opt_in(self, fake_client, budget_reset):
        fake_client([FakeResponse(200, {"id": "X", "status": "DONE"})])
        result = call(handlers_full.shodan_scan, {"action": "status", "scan_id": "X"})
        assert result["ok"] is True
        assert "shodan_host" in result["next_step"]


class TestNeverRaises:
    """The registry contract: a handler returns JSON or takes the turn down."""

    def test_an_exploding_client_still_produces_json(self, monkeypatch, budget_reset):
        def boom(*_a, **_kw):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(handlers_core, "get_client", boom)
        raw = handlers_core.shodan_count({"query": "x"})
        result = json.loads(raw)
        assert result["ok"] is False
        assert result["error_kind"] == "internal"

    def test_garbage_args_do_not_raise(self, fake_client, budget_reset):
        fake_client([])
        for handler in (
            handlers_core.shodan_host,
            handlers_core.shodan_search,
            handlers_core.shodan_count,
            handlers_core.shodan_dns,
            handlers_core.shodan_cve,
            handlers_core.shodan_meta,
            handlers_full.shodan_alert,
            handlers_full.shodan_exploits,
            handlers_full.shodan_query,
            handlers_full.shodan_trends,
        ):
            json.loads(handler("not a dict"))  # type: ignore[arg-type]

    def test_the_api_key_never_leaks_into_an_error(self, fake_client, budget_reset):
        fake_client([FakeResponse(401, None, text="<html>401</html>")], api_key="SUPERSECRETKEY")
        raw = handlers_core.shodan_count({"query": "x"})
        assert "SUPERSECRETKEY" not in raw
