from __future__ import annotations

import time

import pytest
from conftest import FakeResponse
from hermes_plugins.shodan import client as client_mod
from hermes_plugins.shodan import config as config_mod
from hermes_plugins.shodan.client import RateLimiter
from hermes_plugins.shodan.errors import (
    AuthError,
    BadRequestError,
    CreditError,
    MissingKeyError,
    NotFoundError,
    PlanError,
    RateLimitError,
    UpstreamError,
    classify_http,
    redact,
)

# nginx serves this on a 401. The body is HTML, not JSON, and assuming
# otherwise is the classic way to turn a clear auth failure into a parse error.
NGINX_401 = "<html>\r\n<head><title>401 Unauthorized</title></head>\r\n</html>"


class TestClassification:
    def test_html_401_is_recognized_as_an_auth_failure(self):
        error = classify_http(401, NGINX_401, None)
        assert isinstance(error, AuthError)
        assert error.message == "Invalid API key"
        assert "account.shodan.io" in error.next_step

    def test_credits_beat_the_status_code(self):
        # Shodan reports insufficient credits with a 401 on some endpoints.
        # The prose is the only thing that distinguishes it from a bad key,
        # and the two want completely different reactions.
        error = classify_http(401, "", {"error": "Insufficient query credits"})
        assert isinstance(error, CreditError)
        assert "shodan_count" in error.next_step

    @pytest.mark.parametrize(
        "status,expected",
        [
            (403, PlanError),
            (404, NotFoundError),
            (400, BadRequestError),
            (422, BadRequestError),
            (429, RateLimitError),
            (500, UpstreamError),
            (502, UpstreamError),
        ],
    )
    def test_status_mapping(self, status, expected):
        assert isinstance(classify_http(status, "", {"error": "x"}), expected)

    def test_membership_gating_reported_with_a_200(self):
        error = classify_http(200, "", {"error": "This filter requires a membership upgrade"})
        assert isinstance(error, PlanError)

    def test_payload_carries_a_next_step(self):
        payload = classify_http(403, "", {"error": "denied"}).to_payload()
        assert payload["ok"] is False
        assert payload["error_kind"] == "plan"
        assert payload["next_step"]
        assert payload["http_status"] == 403


class TestRedaction:
    def test_key_is_stripped_from_a_url(self):
        url = "https://api.shodan.io/shodan/host/1.1.1.1?key=SECRETVALUE123&minify=True"
        assert "SECRETVALUE123" not in redact(url, "SECRETVALUE123")

    def test_generic_key_param_is_stripped_even_without_knowing_the_value(self):
        url = "https://api.shodan.io/api-info?key=someothersecret"
        assert "someothersecret" not in redact(url)

    def test_harmless_text_is_untouched(self):
        assert redact("nothing secret here") == "nothing secret here"


class TestRateLimiter:
    def test_paces_requests(self):
        limiter = RateLimiter(per_second=20.0)  # 50ms apart
        started = time.monotonic()
        for _ in range(4):
            limiter.acquire()
        elapsed = time.monotonic() - started
        assert elapsed >= 0.10, "four calls at 20/s cannot finish instantly"

    def test_zero_disables_pacing(self):
        limiter = RateLimiter(per_second=0.0)
        started = time.monotonic()
        for _ in range(50):
            limiter.acquire()
        assert time.monotonic() - started < 0.1

    def test_first_call_is_immediate(self):
        assert RateLimiter(per_second=1.0).acquire() == 0.0


class TestRequests:
    def test_key_is_injected(self, fake_client):
        instance, transport = fake_client([FakeResponse(200, {"ok": 1})])
        instance.get("/api-info")
        assert transport.calls[0]["params"]["key"] == "test-key"

    def test_keyless_bases_get_no_key(self, fake_client):
        instance, transport = fake_client([FakeResponse(200, {"ip": "1.1.1.1"})])
        instance.get("/1.1.1.1", base=client_mod.INTERNETDB)
        assert "key" not in transport.calls[0]["params"]

    def test_missing_key_fails_before_any_network_call(self, fake_client):
        instance, transport = fake_client([], api_key=None)
        with pytest.raises(MissingKeyError):
            instance.get("/api-info")
        assert transport.calls == []

    def test_error_body_on_a_200_is_still_an_error(self, fake_client):
        instance, _ = fake_client([FakeResponse(200, {"error": "Invalid IP"})])
        with pytest.raises(BadRequestError):
            instance.get("/shodan/host/999.999.999.999")

    def test_non_json_success_is_treated_as_upstream_trouble(self, fake_client):
        instance, _ = fake_client([FakeResponse(200, None, text="<html>Just a moment...</html>")])
        with pytest.raises(UpstreamError) as exc:
            instance.get("/shodan/host/search")
        assert "Cloudflare" in exc.value.message

    def test_a_real_user_agent_is_sent(self):
        cfg = config_mod.ShodanConfig(api_key="k")
        assert "hermes-plugin-shodan" in cfg.user_agent


class TestRetries:
    def test_transient_failures_are_retried(self, fake_client, monkeypatch):
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)
        instance, transport = fake_client(
            [FakeResponse(502, {"error": "bad gateway"}), FakeResponse(200, {"ok": 1})],
            retries=1,
        )
        assert instance.get("/api-info") == {"ok": 1}
        assert len(transport.calls) == 2

    def test_auth_failures_are_not_retried(self, fake_client):
        instance, transport = fake_client([FakeResponse(401, None, text=NGINX_401)], retries=3)
        with pytest.raises(AuthError):
            instance.get("/api-info")
        assert len(transport.calls) == 1, "retrying a rejected key is pointless"

    def test_gives_up_and_surfaces_the_last_error(self, fake_client, monkeypatch):
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)
        instance, transport = fake_client([FakeResponse(503, {"error": "down"})] * 3, retries=2)
        with pytest.raises(UpstreamError):
            instance.get("/api-info")
        assert len(transport.calls) == 3


class TestCache:
    def test_repeated_lookups_hit_the_cache(self, fake_client):
        instance, transport = fake_client([FakeResponse(200, {"ip": "1.1.1.1"})])
        first = instance.get("/shodan/host/1.1.1.1", cacheable=True)
        second = instance.get("/shodan/host/1.1.1.1", cacheable=True)
        assert first == second
        assert len(transport.calls) == 1

    def test_uncacheable_calls_always_go_out(self, fake_client):
        instance, transport = fake_client(
            [FakeResponse(200, {"total": 1}), FakeResponse(200, {"total": 2})]
        )
        instance.get("/shodan/host/count", params={"query": "a"})
        instance.get("/shodan/host/count", params={"query": "a"})
        assert len(transport.calls) == 2

    def test_the_key_never_becomes_part_of_the_cache_key(self, fake_client):
        instance, _ = fake_client([FakeResponse(200, {"ok": 1})])
        key = instance._cache_key("GET", client_mod.REST, "/x", {"key": "secret", "q": "1"})
        assert "secret" not in key
