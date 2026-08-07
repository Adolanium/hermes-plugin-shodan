"""Does the plugin actually register, the way Hermes will call it?

These are the tests that catch the mistakes that make a plugin silently absent:
a schema whose name does not match its registry name, a check_fn that hides
everything, a skill path that does not exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from hermes_plugins import shodan as plugin
from hermes_plugins.shodan import config as config_mod
from hermes_plugins.shodan import schemas

PLUGIN_DIR = Path(plugin.__file__).parent


class FakeContext:
    """Stands in for hermes_cli.plugins.PluginContext."""

    def __init__(self):
        self.tools = {}
        self.hooks = {}
        self.skills = {}
        self.cli_commands = {}
        self.commands = {}

    def register_tool(self, name, toolset, schema, handler, check_fn=None, emoji="", **kw):
        assert name not in self.tools, f"{name} registered twice"
        self.tools[name] = {
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
            "check_fn": check_fn,
            "emoji": emoji,
        }

    def register_hook(self, hook_name, callback):
        self.hooks.setdefault(hook_name, []).append(callback)

    def register_skill(self, name, path, description=""):
        assert Path(path).exists(), f"skill file missing: {path}"
        self.skills[name] = {"path": path, "description": description}

    def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
        self.cli_commands[name] = {"setup_fn": setup_fn, "handler_fn": handler_fn}

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = {"handler": handler, "args_hint": args_hint}


@pytest.fixture
def registered(isolated_config):
    ctx = FakeContext()
    plugin.register(ctx)
    return ctx


class TestRegistration:
    def test_all_twelve_tools_register(self, registered):
        assert len(registered.tools) == 12
        assert set(registered.tools) == config_mod.ALL_TOOLS

    def test_every_tool_shares_one_toolset(self, registered):
        assert {t["toolset"] for t in registered.tools.values()} == {"shodan"}

    def test_schema_name_matches_registry_name(self, registered):
        for name, entry in registered.tools.items():
            assert entry["schema"]["name"] == name

    def test_schemas_are_well_formed(self, registered):
        for name, entry in registered.tools.items():
            schema = entry["schema"]
            assert schema["description"].strip(), name
            params = schema["parameters"]
            assert params["type"] == "object"
            assert isinstance(params["properties"], dict)
            for required in params.get("required", []):
                assert required in params["properties"], f"{name}: {required}"

    def test_lifecycle_hooks_are_wired(self, registered):
        assert "on_session_start" in registered.hooks
        assert "on_session_reset" in registered.hooks

    def test_skills_ship_and_register(self, registered):
        assert set(registered.skills) == {"query-syntax", "recon", "monitoring"}

    def test_cli_and_slash_surfaces_exist(self, registered):
        assert "shodan" in registered.cli_commands
        assert "shodan" in registered.commands
        assert registered.commands["shodan"]["args_hint"]


class TestVisibility:
    def test_core_profile_hides_the_advanced_tools(self, registered, isolated_config):
        config_mod.reset()
        assert registered.tools["shodan_count"]["check_fn"]() is False, "no key configured"
        isolated_config["api_key"] = "k"
        config_mod.reset()
        assert registered.tools["shodan_count"]["check_fn"]() is True
        assert registered.tools["shodan_scan"]["check_fn"]() is False

    def test_full_profile_reveals_them(self, registered, isolated_config):
        isolated_config.update({"profile": "full", "api_key": "k"})
        config_mod.reset()
        assert registered.tools["shodan_scan"]["check_fn"]() is True
        assert registered.tools["shodan_trends"]["check_fn"]() is True

    def test_without_a_key_only_the_keyless_tools_show(self, registered, isolated_config):
        config_mod.reset()
        visible = {n for n, e in registered.tools.items() if e["check_fn"]()}
        assert visible == {"shodan_cve", "shodan_account", "shodan_host"}

    def test_host_disappears_when_the_fallback_is_off_too(self, registered, isolated_config):
        isolated_config["internetdb_fallback"] = False
        config_mod.reset()
        visible = {n for n, e in registered.tools.items() if e["check_fn"]()}
        assert visible == {"shodan_cve", "shodan_account"}


class TestManifest:
    def test_manifest_parses_and_matches_the_code(self):
        manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8"))
        assert manifest["name"] == "shodan"
        assert manifest["kind"] == "standalone"
        assert manifest["manifest_version"] == 1
        assert manifest["version"] == plugin.__version__

    def test_declared_tools_are_the_core_profile(self):
        manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8"))
        assert set(manifest["provides_tools"]) == config_mod.CORE_TOOLS

    def test_declared_hooks_are_registered(self, registered):
        manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8"))
        assert set(manifest["provides_hooks"]) <= set(registered.hooks)

    def test_the_api_key_is_declared_so_install_prompts_for_it(self):
        manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8"))
        entry = manifest["requires_env"][0]
        assert entry["name"] == "SHODAN_API_KEY"
        assert entry["secret"] is True


class TestSchemaGuidance:
    """The descriptions are load-bearing. These assert the steering survives edits."""

    def test_search_points_at_the_free_alternative(self):
        text = schemas.SHODAN_SEARCH["description"]
        assert "shodan_count" in text
        assert "CREDIT" in text.upper()

    def test_count_advertises_that_it_is_free(self):
        assert "WITHOUT SPENDING" in schemas.SHODAN_COUNT["description"].upper()

    def test_scan_warns_before_it_is_ever_called(self):
        text = schemas.SHODAN_SCAN["description"]
        assert "REAL PROBES" in text.upper()
        assert "authorized" in text

    def test_dns_flags_the_one_mode_that_costs(self):
        assert "COSTS ONE QUERY CREDIT" in schemas.SHODAN_DNS["description"].upper()


class TestSkillContent:
    @pytest.mark.parametrize("name", ["query-syntax", "recon", "monitoring"])
    def test_frontmatter_is_valid(self, name):
        text = (PLUGIN_DIR / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
        assert text.startswith("---\n")
        front = yaml.safe_load(text.split("---", 2)[1])
        assert front["name"] == name
        assert front["description"]
        assert len(front["description"]) <= 60, "Hermes truncates the index at 60 chars"
