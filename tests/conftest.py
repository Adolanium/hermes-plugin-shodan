"""Load the plugin exactly the way Hermes loads it.

Not for authenticity's sake. The loader in hermes_cli/plugins.py imports the
directory as ``hermes_plugins.shodan`` with a synthetic namespace parent and a
hand-set ``__path__``, and relative imports either work under that arrangement
or they do not. Importing the modules some more convenient way in tests would
mean the suite passes while the real thing fails to load.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
NS_PARENT = "hermes_plugins"
MODULE_NAME = f"{NS_PARENT}.shodan"


def _load_plugin():
    if MODULE_NAME in sys.modules:
        return sys.modules[MODULE_NAME]

    if NS_PARENT not in sys.modules:
        parent = types.ModuleType(NS_PARENT)
        parent.__path__ = []  # type: ignore[attr-defined]
        parent.__package__ = NS_PARENT
        sys.modules[NS_PARENT] = parent

    spec = importlib.util.spec_from_file_location(
        MODULE_NAME,
        PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = MODULE_NAME
    module.__path__ = [str(PLUGIN_DIR)]  # type: ignore[attr-defined]
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


plugin = _load_plugin()


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    """Never read the developer's real config.yaml or real API key.

    Without this the suite would behave differently on a machine that happens
    to have Hermes configured, which is the worst kind of flaky.
    """
    from hermes_plugins.shodan import client as client_mod
    from hermes_plugins.shodan import config as config_mod

    settings: dict = {}
    monkeypatch.setattr(config_mod, "_raw_plugin_config", lambda: settings)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("HERMES_SHODAN_PROFILE", raising=False)
    monkeypatch.delenv("HERMES_SHODAN_VERBOSITY", raising=False)
    config_mod.reset()
    client_mod.reset_client()
    yield settings
    config_mod.reset()
    client_mod.reset_client()


@pytest.fixture
def budget_reset():
    from hermes_plugins.shodan.budget import tracker

    tracker.reset()
    yield tracker
    tracker.reset()


class FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text or payload is None else ""
        if payload is not None and not text:
            import json

            self.text = json.dumps(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeTransport:
    """Stands in for httpx.Client. Records calls, replays queued responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, params=None, data=None, json=None):
        self.calls.append(
            {"method": method, "url": url, "params": dict(params or {}), "data": data, "json": json}
        )
        if not self.responses:
            raise AssertionError(f"unexpected extra request: {method} {url}")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        pass


@pytest.fixture
def fake_client(monkeypatch, isolated_config):
    """Build a ShodanClient whose transport is scripted.

    The api_key is written into the isolated config as well as the client, so
    the handlers -- which read config themselves rather than asking the client
    -- take the same branch the client is scripted for.
    """
    from hermes_plugins.shodan import client as client_mod
    from hermes_plugins.shodan import config as config_mod

    def build(responses, **overrides):
        overrides.setdefault("api_key", "test-key")
        overrides.setdefault("retries", 0)
        overrides.setdefault("rate_limit_per_second", 0.0)  # no sleeping in tests
        if overrides["api_key"]:
            isolated_config["api_key"] = overrides["api_key"]
        else:
            isolated_config.pop("api_key", None)
        config_mod.reset()
        cfg = config_mod.ShodanConfig(**overrides)
        instance = client_mod.ShodanClient(cfg)
        transport = FakeTransport(responses)
        instance._client = transport

        stub = lambda c=None: instance  # noqa: E731
        # The handler modules bind get_client by name at import, so patching
        # the definition alone would leave them talking to the real API.
        monkeypatch.setattr(client_mod, "get_client", stub)
        for module_name in (
            "hermes_plugins.shodan.handlers_core",
            "hermes_plugins.shodan.handlers_full",
            "hermes_plugins.shodan.runtime",
        ):
            module = sys.modules.get(module_name)
            if module is not None and hasattr(module, "get_client"):
                monkeypatch.setattr(module, "get_client", stub)
        return instance, transport

    return build
