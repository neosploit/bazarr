# coding=utf-8
"""Solve captchas for Provider Hub plugins with the user's anti-captcha vendor.

A plugin runs out of process and never sees the vendor key. When its manifest sets
``anti_captcha`` and the user has a vendor configured, the host hands the plugin the
address of this relay and a token for it (``captcha_solver_url`` and
``captcha_solver_token`` in its config). The plugin posts the captcha it met; the
relay solves it through the same pitchers the built-in providers use and answers
with the response token.

The relay is its own small HTTP server, not a Bazarr API route: it listens on the
loopback interface only, on a port the OS picks, so it does not depend on Bazarr's
bind address, port, base URL or reverse proxy, nobody on the network can reach it,
and a plugin is never given Bazarr's API key. It starts the first time a plugin
needs it.

Request: ``POST /solve`` with ``Authorization: Bearer <token>`` and a JSON body
``{"site_key": str, "site_url": str, "invisible": bool, "provider": str}``. A
reCAPTCHA v3 adds ``"type": "recaptcha_v3"`` and, optionally, its ``action`` and
``min_score``; without a ``type`` the captcha is a reCAPTCHA v2.
Reply: ``200 {"token": str}``, or an error status with ``{"error": str}``.
"""
import hmac
import json
import logging
import os
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# How long one solve may take. The plugin is told to wait this long for the relay,
# and the host stretches its own deadline for the plugin's operation to cover it.
SOLVE_TIMEOUT_SECONDS = 120
# Solves running at once. Each one is a paid vendor job; more requests than this
# are turned away with 429 rather than queued behind each other.
MAX_CONCURRENT_SOLVES = 2
_MAX_BODY_BYTES = 4096
_SITE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,200}$")
_PROVIDER_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# reCAPTCHA allows letters, digits, slashes and underscores in an action name.
_ACTION_RE = re.compile(r"^[A-Za-z0-9_/]{1,100}$")
_MAX_URL_LENGTH = 2048
_TYPES = {"recaptcha_v2": "v2", "recaptcha_v3": "v3"}
DEFAULT_V3_ACTION = "verify"
DEFAULT_V3_MIN_SCORE = 0.3
_MIN_SCORE_RANGE = (0.1, 0.9)


class CaptchaRequest(NamedTuple):
    """One captcha a plugin asked the relay to solve."""
    provider: str
    site_key: str
    site_url: str
    invisible: bool = False
    version: str = "v2"
    action: str | None = None
    min_score: float | None = None


class SolveRejected(Exception):
    """A request the relay will not solve, with the HTTP status to answer."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def vendor_configured():
    """Whether the user has an anti-captcha vendor and key set up."""
    return bool(os.environ.get("ANTICAPTCHA_CLASS") and os.environ.get("ANTICAPTCHA_ACCOUNT_KEY"))


def solve_with_vendor(captcha):
    """The response token from the user's vendor, or None when it did not solve it."""
    from subliminal_patch.pitcher import pitchers

    pitcher_cls = pitchers.get_pitcher()
    pitcher = pitcher_cls(
        captcha.provider, captcha.site_url, captcha.site_key, tries=1, is_invisible=captcha.invisible,
        version=captcha.version, action=captcha.action, min_score=captcha.min_score,
    )
    # A pitcher's own wait can be longer than the plugin is told to allow.
    if isinstance(getattr(pitcher, "timeout", None), (int, float)):
        pitcher.timeout = min(pitcher.timeout, SOLVE_TIMEOUT_SECONDS)
    return pitcher.throw()


def _parse_request(body):
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SolveRejected(400, "the body must be a JSON object") from None
    if not isinstance(payload, dict):
        raise SolveRejected(400, "the body must be a JSON object")
    site_key = payload.get("site_key")
    if not isinstance(site_key, str) or not _SITE_KEY_RE.match(site_key):
        raise SolveRejected(400, "site_key is missing or malformed")
    site_url = payload.get("site_url") or payload.get("url")
    parsed = urlparse(site_url) if isinstance(site_url, str) and len(site_url) <= _MAX_URL_LENGTH else None
    if parsed is None or parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SolveRejected(400, "site_url must be an http(s) URL")
    invisible = payload.get("invisible", False)
    if not isinstance(invisible, bool):
        raise SolveRejected(400, "invisible must be true or false")
    provider = payload.get("provider") or "provider_hub"
    if not isinstance(provider, str) or not _PROVIDER_RE.match(provider):
        raise SolveRejected(400, "provider is malformed")
    version = _TYPES.get(payload.get("type") or "recaptcha_v2")
    if version is None:
        raise SolveRejected(400, "only recaptcha_v2 and recaptcha_v3 captchas are supported")
    if version != "v3":
        return CaptchaRequest(provider, site_key, site_url, invisible)
    action = payload.get("action") or DEFAULT_V3_ACTION
    if not isinstance(action, str) or not _ACTION_RE.match(action):
        raise SolveRejected(400, "action is malformed")
    min_score = payload.get("min_score", DEFAULT_V3_MIN_SCORE)
    if (isinstance(min_score, bool) or not isinstance(min_score, (int, float))
            or not _MIN_SCORE_RANGE[0] <= min_score <= _MIN_SCORE_RANGE[1]):
        raise SolveRejected(400, "min_score must be a number from 0.1 to 0.9")
    return CaptchaRequest(provider, site_key, site_url, False, version, action, float(min_score))


class CaptchaRelay:
    """The relay server. One per process, started on first use."""

    def __init__(self, solve=None, vendor_ready=None):
        self.token = secrets.token_urlsafe(32)
        self._solve = solve or solve_with_vendor
        self._vendor_ready = vendor_ready or vendor_configured
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_SOLVES)
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    @property
    def url(self):
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/solve"

    def ensure_started(self):
        with self._lock:
            if self._server is not None:
                return
            from secret_store.scrub import add_runtime_secret_value

            # Registered before the token can leave the process, so it is masked in
            # any log line or worker output that carries a plugin's config.
            add_runtime_secret_value(self.token)
            self._server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(self))
            self._server.daemon_threads = True
            self._thread = threading.Thread(
                target=self._server.serve_forever, name="provider-hub-captcha-relay", daemon=True
            )
            self._thread.start()
            logger.info("Provider Hub captcha relay listening on %s", self.url)

    def stop(self):
        with self._lock:
            if self._server is None:
                return
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    def handle(self, authorization, body):
        """(status, payload) for one solve request."""
        expected = f"Bearer {self.token}"
        if not isinstance(authorization, str) or not hmac.compare_digest(
            authorization.encode("utf-8"), expected.encode("utf-8")
        ):
            return 401, {"error": "unauthorized"}
        try:
            captcha = _parse_request(body)
        except SolveRejected as rejected:
            return rejected.status, {"error": rejected.message}
        if not self._vendor_ready():
            return 503, {"error": "no anti-captcha service is configured in Bazarr+"}
        if not self._slots.acquire(blocking=False):
            return 429, {"error": "the captcha relay is busy, try again later"}
        try:
            logger.info("Provider Hub captcha relay: solving a reCAPTCHA %s for %s",
                        captcha.version, captcha.provider)
            token = self._solve(captcha)
        except Exception as error:
            logger.warning("Provider Hub captcha relay: the solve for %s failed: %s",
                           captcha.provider, type(error).__name__)
            return 502, {"error": "the anti-captcha service failed"}
        finally:
            self._slots.release()
        if not isinstance(token, str) or not token:
            return 502, {"error": "the anti-captcha service did not solve the captcha"}
        return 200, {"token": token}


def _handler_for(relay):
    class _Handler(BaseHTTPRequestHandler):
        server_version = "BazarrCaptchaRelay"
        sys_version = ""

        def do_POST(self):
            if self.path != "/solve":
                return self._reply(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._reply(400, {"error": "bad Content-Length"})
            if length <= 0 or length > _MAX_BODY_BYTES:
                return self._reply(413 if length > _MAX_BODY_BYTES else 400, {"error": "bad body size"})
            status, payload = relay.handle(self.headers.get("Authorization"), self.rfile.read(length))
            self._reply(status, payload)

        def do_GET(self):
            self._reply(405, {"error": "use POST"})

        def _reply(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            # The access log would carry nothing useful and is kept out of Bazarr's.
            return

    return _Handler


_relay = None
_relay_lock = threading.Lock()


def get_relay():
    """The process's relay, created (but not started) on first use."""
    global _relay
    with _relay_lock:
        if _relay is None:
            _relay = CaptchaRelay()
        return _relay


def solver_config(config):
    """The config entries that point a plugin at the relay, or {} when it should not get them.

    A plugin gets the relay only when the user has a vendor configured and has not
    pointed the plugin at a solver or a pre-solved response of their own.
    """
    if not vendor_configured():
        return {}
    if str(config.get("captcha_solver_url") or "").strip() or str(config.get("captcha_response") or "").strip():
        return {}
    relay = get_relay()
    relay.ensure_started()
    return {
        "captcha_solver_url": relay.url,
        "captcha_solver_token": relay.token,
        "captcha_solver_timeout_ms": SOLVE_TIMEOUT_SECONDS * 1000,
    }
