from __future__ import annotations

import pytest
from hermes_plugins.shodan import config as config_mod
from hermes_plugins.shodan.budget import BudgetTracker, estimate_search_cost
from hermes_plugins.shodan.errors import BudgetError


class TestDefaults:
    def test_everything_has_a_working_default(self, isolated_config):
        cfg = config_mod.load(refresh=True)
        assert cfg.profile == "core"
        assert cfg.verbosity == "summary"
        assert cfg.rate_limit_per_second == 1.0
        assert cfg.cache.enabled is True
        assert cfg.internetdb_fallback is True
        assert cfg.scan.enabled is False, "active scanning must be opt-in"
        assert cfg.budget.scan_credits_per_session == 0

    def test_key_comes_from_the_env_first(self, isolated_config, monkeypatch):
        isolated_config["api_key"] = "from-config"
        monkeypatch.setenv("SHODAN_API_KEY", "from-env")
        cfg = config_mod.load(refresh=True)
        assert cfg.api_key == "from-env"

    def test_config_key_is_the_fallback(self, isolated_config):
        isolated_config["api_key"] = "from-config"
        assert config_mod.load(refresh=True).api_key == "from-config"

    def test_custom_env_var_name(self, isolated_config, monkeypatch):
        isolated_config["api_key_env"] = "MY_SHODAN"
        monkeypatch.setenv("MY_SHODAN", "custom")
        cfg = config_mod.load(refresh=True)
        assert cfg.api_key == "custom"
        assert cfg.api_key_env == "MY_SHODAN"


class TestCoercion:
    def test_junk_values_fall_back_rather_than_crashing(self, isolated_config):
        isolated_config.update(
            {
                "profile": "nonsense",
                "verbosity": 12,
                "rate_limit_per_second": "not a number",
                "timeout_seconds": None,
                "cache": {"ttl_seconds": "abc"},
            }
        )
        cfg = config_mod.load(refresh=True)
        assert cfg.profile == "core"
        assert cfg.verbosity == "summary"
        assert cfg.rate_limit_per_second == 1.0
        assert cfg.timeout_seconds == 30.0
        assert cfg.cache.ttl_seconds == 900

    def test_allowlist_accepts_a_comma_string_or_a_list(self, isolated_config):
        isolated_config["scan"] = {"allowlist": "10.0.0.0/8, 192.168.0.0/16"}
        assert config_mod.load(refresh=True).scan.allowlist == [
            "10.0.0.0/8",
            "192.168.0.0/16",
        ]


class TestProfiles:
    def test_core_hides_the_side_effecting_tools(self, isolated_config):
        visible = config_mod.load(refresh=True).visible_tools()
        assert visible == config_mod.CORE_TOOLS
        assert "shodan_scan" not in visible
        assert "shodan_alert" not in visible

    def test_full_shows_everything(self, isolated_config):
        isolated_config["profile"] = "full"
        assert config_mod.load(refresh=True).visible_tools() == config_mod.ALL_TOOLS

    def test_one_extra_tool_without_taking_all_five(self, isolated_config):
        isolated_config["tools"] = {"enabled": ["shodan_exploits"]}
        visible = config_mod.load(refresh=True).visible_tools()
        assert "shodan_exploits" in visible
        assert "shodan_scan" not in visible

    def test_disable_wins_over_profile(self, isolated_config):
        isolated_config.update(
            {"profile": "full", "tools": {"disabled": ["shodan_scan", "shodan_trends"]}}
        )
        visible = config_mod.load(refresh=True).visible_tools()
        assert "shodan_scan" not in visible
        assert "shodan_alert" in visible

    def test_unknown_tool_names_are_ignored(self, isolated_config):
        isolated_config["tools"] = {"enabled": ["shodan_teleport"]}
        assert "shodan_teleport" not in config_mod.load(refresh=True).visible_tools()


class TestSearchCostEstimate:
    """Shodan charges one credit per filtered query plus one per extra page."""

    @pytest.mark.parametrize(
        "query,page,expected",
        [
            ("apache", 1, 0),  # bare keyword, page one: free
            ("apache country:DE", 1, 1),  # any filter: one credit
            ("apache", 2, 1),  # page two of a free query
            ("apache country:DE", 3, 3),  # filter plus two extra pages
            ("", 1, 0),
        ],
    )
    def test_estimates(self, query, page, expected):
        assert estimate_search_cost(query, page) == expected


class TestBudget:
    def test_refuses_past_the_limit(self):
        tracker = BudgetTracker()
        tracker.check(3, limit=5)
        tracker.spend(3)
        with pytest.raises(BudgetError) as exc:
            tracker.check(3, limit=5)
        assert exc.value.details["remaining"] == 2
        assert "shodan_count" in exc.value.next_step

    def test_zero_limit_blocks_everything(self):
        tracker = BudgetTracker()
        with pytest.raises(BudgetError):
            tracker.check(1, limit=0, kind="scan")

    def test_free_calls_never_trip_the_guard(self):
        tracker = BudgetTracker()
        tracker.check(0, limit=0)  # must not raise

    def test_sessions_have_separate_ledgers(self):
        tracker = BudgetTracker()
        tracker.spend(5, session_id="alpha")
        assert tracker.ledger("alpha").query_credits_spent == 5
        assert tracker.ledger("beta").query_credits_spent == 0
        tracker.check(5, limit=5, session_id="beta")  # beta is untouched

    def test_query_and_scan_credits_are_tracked_apart(self):
        tracker = BudgetTracker()
        tracker.spend(10, kind="scan")
        assert tracker.ledger().scan_credits_spent == 10
        assert tracker.ledger().query_credits_spent == 0
        tracker.check(10, limit=10)  # query budget untouched

    def test_reset_clears_one_session(self):
        tracker = BudgetTracker()
        tracker.spend(4, session_id="alpha")
        tracker.reset("alpha")
        assert tracker.ledger("alpha").query_credits_spent == 0

    def test_snapshot_reports_both_sides(self):
        tracker = BudgetTracker()
        tracker.spend(7)
        snap = tracker.ledger().snapshot(50, 0)
        assert snap["query_credits_spent"] == 7
        assert snap["query_credits_remaining"] == 43
        assert snap["scan_credits_remaining"] == 0
