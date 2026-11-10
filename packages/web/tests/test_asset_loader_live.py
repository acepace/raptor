"""Real HTTP and Chromium coverage for isolated asset loading."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time

import pytest

from core.http import HttpError
from core.sandbox import proxy as proxy_mod
from core.testing.proxy_scope import isolated_proxy_scope
from packages.web.asset_loader import AssetLoader
from packages.web.browser import BrowserEngine, browser_available
from packages.web.tests.http_server import start_http_server


class _Asset(BaseHTTPRequestHandler):
    received: list[tuple[str, dict[str, str]]] = []
    target_port = 0

    def do_GET(self) -> None:  # noqa: N802
        type(self).received.append((self.path, dict(self.headers)))
        if self.path == "/drip":
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                for _ in range(32):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.25)
            except OSError:
                pass
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{type(self).target_port}/asset-return"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"window.assetLoaded = true;"
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Set-Cookie", "session=asset-overwrite; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


class _Target(BaseHTTPRequestHandler):
    received: list[tuple[str, dict[str, str]]] = []
    binary_received: list[tuple[str, bytes]] = []
    asset_port = 0

    def do_GET(self) -> None:  # noqa: N802
        type(self).received.append((self.path, dict(self.headers)))
        if self.path == "/redirect-script":
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{type(self).asset_port}/app.js"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/asset-return":
            body = b"unexpected"
        elif self.path == "/redirect-page":
            body = b'<html><script src="/redirect-script"></script></html>'
        elif self.path == "/redirect-away-page":
            body = f'<html><script src="http://127.0.0.1:{type(self).asset_port}/redirect"></script></html>'.encode()
        elif self.path == "/check":
            body = b"ok"
        else:
            body = f'<html><script src="http://127.0.0.1:{type(self).asset_port}/app.js"></script></html>'.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).binary_received.append((self.path, body))
        if self.path == "/binary-redirect":
            self.send_response(307)
            self.send_header("Location", "/binary-final")
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def sites(request, monkeypatch):
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    target = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    asset = ThreadingHTTPServer(("127.0.0.1", 0), _Asset)
    add_cleanup = lambda callback, *args: request.addfinalizer(lambda: callback(*args))
    start_http_server(target, add_cleanup)
    start_http_server(asset, add_cleanup)
    _Target.asset_port = asset.server_port
    _Asset.target_port = target.server_port
    _Target.received = []
    _Target.binary_received = []
    _Asset.received = []
    return f"http://127.0.0.1:{target.server_port}", asset.server_port


@pytest.fixture
def allow_local_proxy(monkeypatch):
    """Use the real proxy, relaxing only fixture-owned loopback resolution."""
    blocked = proxy_mod._ip_is_blocked
    monkeypatch.setattr(
        proxy_mod,
        "_ip_is_blocked",
        lambda ip: False if ip == "127.0.0.1" else blocked(ip),
    )
    with isolated_proxy_scope():
        yield


def _engine(base, monkeypatch):
    # Permit loopback only in this owned fixture; production admission still
    # requires an exact public DNS name and validates resolved IP addresses.
    monkeypatch.setattr("packages.web.asset_loader.required_host", lambda host: host)
    engine = BrowserEngine(
        base,
        cookies={"session": "target-session"},
        extra_headers={
            "Authorization": "Bearer target-token",
            "X-Origin-Verify": "a" * 64,
        },
        asset_hosts=["127.0.0.1"],
    )
    return engine


@pytest.mark.integration
@pytest.mark.linux_native
def test_direct_assets_do_not_share_target_state(sites, monkeypatch, allow_local_proxy):
    base, _ = sites
    if not browser_available(base_url=base):
        pytest.skip("confined Chromium unavailable")
    with _engine(base, monkeypatch) as engine:
        engine.render(base + "/")
        engine.render(base + "/check")

    asset_hits = [headers for path, headers in _Asset.received if path == "/app.js"]
    assert len(asset_hits) == 1
    for headers in asset_hits:
        names = {name.lower() for name in headers}
        assert not names & {"authorization", "cookie", "x-origin-verify", "referer"}
    target_check = [headers for path, headers in _Target.received if path == "/check"]
    assert len(target_check) == 1
    assert target_check[0].get("Authorization") == "Bearer target-token"
    assert target_check[0].get("X-Origin-Verify") == "a" * 64
    assert "session=target-session" in target_check[0].get("Cookie", "")
    assert "asset-overwrite" not in target_check[0].get("Cookie", "")


@pytest.mark.integration
@pytest.mark.linux_native
def test_target_redirect_to_asset_host_is_blocked(
    sites, monkeypatch, allow_local_proxy
):
    base, _ = sites
    if not browser_available(base_url=base):
        pytest.skip("confined Chromium unavailable")
    with _engine(base, monkeypatch) as engine:
        engine.render(base + "/redirect-page")
        assert engine.blocked_requests >= 1
    assert not _Asset.received


@pytest.mark.integration
@pytest.mark.linux_native
def test_asset_redirect_is_never_followed_into_target(
    sites, monkeypatch, allow_local_proxy
):
    base, _ = sites
    if not browser_available(base_url=base):
        pytest.skip("confined Chromium unavailable")
    with _engine(base, monkeypatch) as engine:
        engine.render(base + "/redirect-away-page")
    assert any(path == "/redirect" for path, _ in _Asset.received)
    assert not any(path == "/asset-return" for path, _ in _Target.received)


@pytest.mark.integration
@pytest.mark.linux_native
def test_binary_post_body_survives_same_origin_redirect(sites):
    base, _ = sites
    if not browser_available(base_url=base):
        pytest.skip("confined Chromium unavailable")
    with BrowserEngine(base) as engine:
        page = engine._context.new_page()
        try:
            page.goto(base + "/check")
            status = page.evaluate("""async () => {
                const body = new Uint8Array([0, 255, 1, 128, 42]);
                return (await fetch('/binary-redirect', {
                    method: 'POST', body, headers: {'Content-Type': 'application/octet-stream'}
                })).status;
            }""")
        finally:
            page.close()
    assert status == 200
    assert _Target.binary_received == [
        ("/binary-redirect", b"\x00\xff\x01\x80*"),
        ("/binary-final", b"\x00\xff\x01\x80*"),
    ]


def test_asset_host_grants_both_schemes_any_port():
    loader = AssetLoader(["Assets.Example.Net"])
    for url in (
        "http://assets.example.net:8080/a.js",
        "https://assets.example.net:8443/a.js",
    ):
        assert loader.allows(url, "GET", "script")
    assert not loader.allows("https://other.example.net/a.js", "GET", "script")
    assert not loader.allows("https://assets.example.net:bad/a.js", "GET", "script")
    assert not loader.allows(
        "https://assets.example.net@other.example.net/a.js", "GET", "script"
    )
    assert not loader.allows("https://assets.example.net/login", "POST", "document")
    assert not loader.allows("https://assets.example.net/api", "GET", "fetch")


def test_asset_host_cli_trims_environment(monkeypatch):
    from packages.web.scanner import build_arg_parser

    monkeypatch.setenv(
        "RAPTOR_WEB_ASSET_HOSTS", " cdn.example.net , static.example.net "
    )
    args = build_arg_parser().parse_args(["--url", "https://target.example"])
    assert args.asset_host == ["cdn.example.net", "static.example.net"]


@pytest.mark.integration
def test_asset_private_address_is_refused_by_real_proxy(sites, monkeypatch):
    _, asset_port = sites
    monkeypatch.setattr("packages.web.asset_loader.required_host", lambda host: host)
    loader = AssetLoader(["127.0.0.1"])
    with isolated_proxy_scope():
        with pytest.raises(HttpError):
            loader.fetch(f"http://127.0.0.1:{asset_port}/app.js", "GET", "script")
    assert not _Asset.received


@pytest.mark.integration
def test_http_asset_uses_connect_proxy_without_browser_state(
    sites,
    monkeypatch,
    allow_local_proxy,
):
    _, asset_port = sites
    monkeypatch.setattr("packages.web.asset_loader.required_host", lambda host: host)
    loader = AssetLoader(["127.0.0.1"])
    result = loader.fetch(f"http://127.0.0.1:{asset_port}/app.js", "GET", "script")
    assert result.status == 200
    assert result.body == b"window.assetLoaded = true;"
    assert "set-cookie" not in {name.lower() for name in result.headers}
    assert proxy_mod.get_proxy([]).snapshot()["counters"]["requests_connect"] >= 1
    headers = _Asset.received[0][1]
    assert not {name.lower() for name in headers} & {
        "authorization",
        "cookie",
        "referer",
    }


@pytest.mark.integration
def test_asset_request_budget_stops_additional_fetches(
    sites, monkeypatch, allow_local_proxy
):
    import packages.web.asset_loader as asset_module

    _, asset_port = sites
    monkeypatch.setattr(asset_module, "required_host", lambda host: host)
    monkeypatch.setattr(asset_module, "_MAX_ASSET_REQUESTS", 1)
    loader = AssetLoader(["127.0.0.1"])
    url = f"http://127.0.0.1:{asset_port}/app.js"
    assert loader.fetch(url, "GET", "script").status == 200
    with pytest.raises(ValueError, match="budget exhausted"):
        loader.fetch(url, "GET", "script")
    assert len(_Asset.received) == 1


@pytest.mark.integration
def test_asset_total_byte_budget_stops_additional_fetches(
    sites, monkeypatch, allow_local_proxy
):
    import packages.web.asset_loader as asset_module

    _, asset_port = sites
    monkeypatch.setattr(asset_module, "required_host", lambda host: host)
    monkeypatch.setattr(
        asset_module, "_MAX_TOTAL_ASSET_BYTES", len(b"window.assetLoaded = true;")
    )
    loader = AssetLoader(["127.0.0.1"])
    url = f"http://127.0.0.1:{asset_port}/app.js"
    assert loader.fetch(url, "GET", "script").status == 200
    with pytest.raises(ValueError, match="budget exhausted"):
        loader.fetch(url, "GET", "script")
    assert len(_Asset.received) == 1


@pytest.mark.integration
def test_http_asset_deadline_cuts_drip_feed(sites, monkeypatch, allow_local_proxy):
    import packages.web.asset_loader as asset_module

    _, asset_port = sites
    monkeypatch.setattr(asset_module, "required_host", lambda host: host)
    monkeypatch.setattr(asset_module, "_MAX_ASSET_READ_SECONDS", 1)
    loader = AssetLoader(["127.0.0.1"])
    start = time.monotonic()
    with pytest.raises(HttpError, match="[Tt]ime|deadline"):
        loader.fetch(f"http://127.0.0.1:{asset_port}/drip", "GET", "script")
    assert time.monotonic() - start < 4
