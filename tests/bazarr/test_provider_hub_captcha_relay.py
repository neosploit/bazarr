# coding=utf-8
"""The Provider Hub captcha relay: plugins solve captchas through the user's vendor
without ever seeing its key."""
import json
import threading
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest


@pytest.fixture
def vendor_env(monkeypatch):
    monkeypatch.setenv("ANTICAPTCHA_CLASS", "TwoCaptchaProxyLess")
    monkeypatch.setenv("ANTICAPTCHA_ACCOUNT_KEY", "vendor-key-0123456789")


@pytest.fixture
def no_vendor_env(monkeypatch):
    monkeypatch.setenv("ANTICAPTCHA_CLASS", "")
    monkeypatch.setenv("ANTICAPTCHA_ACCOUNT_KEY", "")


@pytest.fixture(autouse=True)
def clean_relay(monkeypatch):
    from provider_hub import captcha_relay
    from secret_store.scrub import clear_secret_values

    monkeypatch.setattr(captcha_relay, "_relay", None)
    yield
    relay = captcha_relay._relay
    if relay is not None:
        relay.stop()
    clear_secret_values()


def _relay(solved="solved-token", vendor_ready=True):
    from provider_hub.captcha_relay import CaptchaRelay

    calls = []

    def solve(site_key, site_url, invisible, provider):
        calls.append((site_key, site_url, invisible, provider))
        if isinstance(solved, Exception):
            raise solved
        return solved

    return CaptchaRelay(solve=solve, vendor_ready=lambda: vendor_ready), calls


def _body(**fields):
    payload = {
        "provider": "subs4series",
        "site_key": "6Lf6Yu8SAAAAAG-4tMd_7yKjgCCWlO43_xYDuaPP",
        "site_url": "https://www.subs4series.com/getSub-tkABC.html",
        "invisible": False,
    }
    payload.update(fields)
    return json.dumps({k: v for k, v in payload.items() if v is not None}).encode("utf-8")


def test_relay_solves_with_the_vendor_and_returns_the_token():
    relay, calls = _relay()

    status, payload = relay.handle(f"Bearer {relay.token}", _body())

    assert (status, payload) == (200, {"token": "solved-token"})
    assert calls == [(
        "6Lf6Yu8SAAAAAG-4tMd_7yKjgCCWlO43_xYDuaPP",
        "https://www.subs4series.com/getSub-tkABC.html",
        False,
        "subs4series",
    )]


@pytest.mark.parametrize("authorization", [None, "", "Bearer wrong", "token-without-bearer"])
def test_relay_refuses_a_request_without_its_token(authorization):
    relay, calls = _relay()

    assert relay.handle(authorization, _body())[0] == 401
    assert calls == []


@pytest.mark.parametrize("body", [
    b"not json",
    b"[]",
    _body(site_key=None),
    _body(site_key="has spaces"),
    _body(site_url="file:///etc/passwd"),
    _body(site_url="https://"),
    _body(invisible="yes"),
    _body(provider="Not A Provider"),
])
def test_relay_refuses_a_malformed_request(body):
    relay, calls = _relay()

    status, payload = relay.handle(f"Bearer {relay.token}", body)

    assert status == 400
    assert payload["error"]
    assert calls == []


def test_relay_accepts_the_url_field_subs4series_also_sends():
    relay, calls = _relay()
    body = _body(site_url=None, url="https://www.subs4series.com/getSub-tkABC.html")

    assert relay.handle(f"Bearer {relay.token}", body)[0] == 200
    assert calls[0][1] == "https://www.subs4series.com/getSub-tkABC.html"


def test_relay_answers_503_without_a_configured_vendor():
    relay, calls = _relay(vendor_ready=False)

    status, payload = relay.handle(f"Bearer {relay.token}", _body())

    assert status == 503
    assert "anti-captcha" in payload["error"]
    assert calls == []


@pytest.mark.parametrize("solved", [None, "", RuntimeError("vendor down")])
def test_relay_answers_502_when_the_vendor_does_not_solve_it(solved):
    relay, _calls = _relay(solved=solved)

    assert relay.handle(f"Bearer {relay.token}", _body())[0] == 502


def test_relay_turns_away_requests_beyond_its_concurrent_solves():
    from provider_hub.captcha_relay import MAX_CONCURRENT_SOLVES

    relay, calls = _relay()
    for _ in range(MAX_CONCURRENT_SOLVES):
        assert relay._slots.acquire(blocking=False)
    try:
        assert relay.handle(f"Bearer {relay.token}", _body())[0] == 429
        assert calls == []
    finally:
        for _ in range(MAX_CONCURRENT_SOLVES):
            relay._slots.release()
    assert relay.handle(f"Bearer {relay.token}", _body())[0] == 200


def _post(url, body, token=None):
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_relay_serves_http_on_loopback_and_masks_its_token():
    from secret_store.scrub import refresh_secret_values, scrub_text

    relay, _calls = _relay()
    relay.ensure_started()
    try:
        assert relay.url.startswith("http://127.0.0.1:")
        assert relay.url.endswith("/solve")
        assert _post(relay.url, _body(), relay.token) == (200, {"token": "solved-token"})
        assert _post(relay.url, _body())[0] == 401
        assert _post(relay.url.replace("/solve", "/other"), _body(), relay.token)[0] == 404
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(relay.url, timeout=10)
        assert refused.value.code == 405

        # The token is masked in text, and stays masked after a settings refresh
        # rebuilds the scrub set from the settings and the Hub state.
        assert relay.token not in scrub_text(f"config: {relay.token}")
        from secret_store.scrub import register_secret_values, registered_secret_values

        register_secret_values(registered_secret_values() | {"stale-credential-0123456789"})
        refresh_secret_values(
            settings_obj=SimpleNamespace(), state={"installations": {}},
        )
        # The refresh rebuilt the set (the stale value is gone) and kept the token.
        assert "stale-credential-0123456789" not in registered_secret_values()
        assert relay.token not in scrub_text(f"config: {relay.token}")
    finally:
        relay.stop()


def test_relay_refuses_an_oversized_body():
    relay, calls = _relay()
    relay.ensure_started()
    try:
        status, _payload = _post(relay.url, b"{" + b" " * 5000 + b"}", relay.token)
    finally:
        relay.stop()
    assert status == 413
    assert calls == []


def test_solver_config_points_a_plugin_at_the_relay(vendor_env):
    from provider_hub import captcha_relay

    config = captcha_relay.solver_config({"request_delay_ms": 0})

    relay = captcha_relay.get_relay()
    assert config == {
        "captcha_solver_url": relay.url,
        "captcha_solver_token": relay.token,
        "captcha_solver_timeout_ms": captcha_relay.SOLVE_TIMEOUT_SECONDS * 1000,
    }


def test_solver_config_is_empty_without_a_vendor(no_vendor_env):
    from provider_hub import captcha_relay

    assert captcha_relay.solver_config({}) == {}
    assert captcha_relay._relay is None


@pytest.mark.parametrize("own", [
    {"captcha_solver_url": "http://my-solver.local/solve"},
    {"captcha_response": "pre-solved"},
])
def test_solver_config_leaves_a_users_own_solver_alone(vendor_env, own):
    from provider_hub import captcha_relay

    assert captcha_relay.solver_config(own) == {}


class _FakeWorker:
    def __init__(self):
        self.requests = []

    def request(self, op, payload, timeout):
        self.requests.append((op, payload, timeout))
        return SimpleNamespace(payload={"candidates": []}, events=[])

    def stop(self):
        return None


def _provider(anti_captcha, **config):
    from provider_hub.registry import _make_provider_class

    manifest = SimpleNamespace(
        provider_id="subs4series",
        languages=("ell",),
        supported_media=("episode",),
        raw={"provider_id": "subs4series", "anti_captcha": anti_captcha},
    )
    worker = _FakeWorker()
    return _make_provider_class(manifest, worker_client=worker)(**config), worker


def _episode():
    from subliminal.video import Episode

    return Episode("/tv/show.s01e01.mkv", "Show", 1, 1)


def test_an_anti_captcha_plugin_gets_the_relay_and_the_time_to_use_it(vendor_env):
    from babelfish import Language

    from provider_hub import captcha_relay

    provider, worker = _provider(True, request_delay_ms=0)
    provider.list_subtitles(_episode(), {Language("ell")})

    _op, payload, timeout = worker.requests[0]
    relay = captcha_relay.get_relay()
    assert payload["config"]["captcha_solver_url"] == relay.url
    assert payload["config"]["captcha_solver_token"] == relay.token
    assert payload["config"]["request_delay_ms"] == 0
    # The solve's wait plus the host margin, above the 120 s default.
    assert timeout == captcha_relay.SOLVE_TIMEOUT_SECONDS + 30
    # The user's own config is never written to.
    assert "captcha_solver_url" not in provider.config


@pytest.mark.parametrize("anti_captcha", [False, None, "true"])
def test_other_plugins_never_get_the_relay(vendor_env, anti_captcha):
    from babelfish import Language

    from provider_hub import captcha_relay

    provider, worker = _provider(anti_captcha, request_delay_ms=0)
    provider.list_subtitles(_episode(), {Language("ell")})

    assert "captcha_solver_url" not in worker.requests[0][1]["config"]
    assert captcha_relay._relay is None


def test_an_anti_captcha_plugin_without_a_vendor_gets_its_config_unchanged(no_vendor_env):
    from babelfish import Language

    provider, worker = _provider(True, request_delay_ms=0)
    provider.list_subtitles(_episode(), {Language("ell")})

    assert worker.requests[0][1]["config"] == {"request_delay_ms": 0}


def test_relay_handles_concurrent_requests():
    gate = threading.Event()
    from provider_hub.captcha_relay import CaptchaRelay

    def slow_solve(site_key, site_url, invisible, provider):
        gate.wait(5)
        return "slow-token"

    relay = CaptchaRelay(solve=slow_solve, vendor_ready=lambda: True)
    relay.ensure_started()
    results = []
    try:
        threads = [threading.Thread(target=lambda: results.append(_post(relay.url, _body(), relay.token)))
                   for _ in range(3)]
        for thread in threads:
            thread.start()
        # Two solves run at once; the third is turned away instead of queued.
        deadline = threading.Event()
        for _ in range(50):
            if any(status == 429 for status, _ in results):
                break
            deadline.wait(0.1)
        gate.set()
        for thread in threads:
            thread.join(10)
    finally:
        relay.stop()
    assert sorted(status for status, _ in results) == [200, 200, 429]
