"""Explicit transport hosts do not expand the web scan's origin."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from packages.web.browser import BrowserEngine
from packages.web.egress_hosts import required_host, target_host
from packages.web.origin_verify import HEADER_NAME, read_value
from packages.web.scanner import WebScanner, build_arg_parser


@pytest.mark.parametrize("host", [
    "https://assets.example.net", "assets.example.net:443", "*.example.net",
    "127.0.0.1", "localhost", "login.localhost", "example.net/path",
    " example.net", "example..net",
])
def test_required_host_rejects_ambiguous_or_unsafe_input(host):
    with pytest.raises(ValueError):
        required_host(host)


def test_cli_accepts_repeatable_required_hosts(monkeypatch):
    monkeypatch.delenv("RAPTOR_WEB_REQUIRED_HOSTS", raising=False)
    args = build_arg_parser().parse_args([
        "--url", "https://target.example", "--required-host", "login.example.net",
        "--required-host", "assets.example.net",
    ])
    assert args.required_host == ["login.example.net", "assets.example.net"]


def test_cli_reads_case_specific_required_hosts(monkeypatch):
    monkeypatch.setenv(
        "RAPTOR_WEB_REQUIRED_HOSTS", "sso.app22.tenzai.io,integrator-6828119.okta.com",
    )
    args = build_arg_parser().parse_args(["--url", "https://target.example"])
    assert args.required_host == [
        "sso.app22.tenzai.io", "integrator-6828119.okta.com",
    ]


def test_target_host_never_adds_proxy_wildcard():
    with pytest.raises(ValueError):
        target_host("https://*.example.net")
    assert target_host("https://127.0.0.1:8443/") == "127.0.0.1"


def test_origin_verify_file_must_be_private_and_never_echoes_value(tmp_path):
    secret = "a" * 64
    path = tmp_path / "origin.secret"
    path.write_text(secret + "\n")
    path.chmod(0o600)
    assert read_value(path) == secret
    path.chmod(0o644)
    with pytest.raises(ValueError) as error:
        read_value(path)
    assert secret not in str(error.value)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        read_value(link)


def test_origin_verify_header_applies_to_target_and_principal_clients(tmp_path):
    from core.llm import egress

    clients = [MagicMock(), MagicMock()]
    for item in clients:
        item.session.headers = {}
    with patch.object(egress, "_enabled", False), patch(
        "packages.web.scanner.WebClient"
    ) as client, patch("packages.web.scanner.WebCrawler"):
        client.side_effect = clients
        scanner = WebScanner(
            "https://target.example", None, Path(tmp_path), origin_verify="b" * 64,
        )
        scanner._make_principal_client()
    assert client.call_count == 2
    assert clients[0].session.headers[HEADER_NAME] == "b" * 64
    assert clients[1].session.headers[HEADER_NAME] == "b" * 64


def test_scanner_registers_target_and_required_hosts_before_client(tmp_path):
    from core.llm import egress

    order = []
    with patch.object(egress, "_enabled", True), patch(
        "core.sandbox.proxy.get_proxy"
    ) as proxy, patch("packages.web.scanner.WebClient") as client, patch(
        "packages.web.scanner.WebCrawler"
    ):
        proxy.side_effect = lambda hosts: order.append("proxy")
        client.side_effect = lambda *args, **kwargs: (order.append("client"), MagicMock())[1]
        WebScanner(
            "https://target.example/path", None, Path(tmp_path),
            required_hosts=["Login.Example.Net", "login.example.net"],
        )
    proxy.assert_called_once_with(["target.example", "login.example.net"])
    assert order[:2] == ["proxy", "client"]


def test_browser_allows_only_named_asset_hosts_without_credentials():
    engine = BrowserEngine("https://target.example", required_hosts=["assets.example.net"])
    response = SimpleNamespace(status=200, headers={})
    route = MagicMock()
    route.request.url = "https://assets.example.net/app.js"
    route.request.method = "GET"
    route.request.resource_type = "script"
    route.request.headers = {
        "Authorization": "Bearer private", "Cookie": "session=private",
        "X-Api-Key": "private", "Accept": "*/*",
    }
    route.fetch.return_value = response
    engine._route_gate(route)
    route.fetch.assert_called_once_with(max_redirects=0, headers={"Accept": "*/*"})
    route.fulfill.assert_called_once_with(response=response)

    for url, resource_type in [
        ("https://other.example.net/app.js", "script"),
        ("https://assets.example.net/login", "document"),
    ]:
        blocked = MagicMock()
        blocked.request.url = url
        blocked.request.method = "GET"
        blocked.request.resource_type = resource_type
        engine._route_gate(blocked)
        blocked.abort.assert_called_once()
        blocked.fetch.assert_not_called()


def test_browser_origin_header_is_target_only():
    engine = BrowserEngine(
        "https://target.example", required_hosts=["assets.example.net"],
        target_headers={HEADER_NAME: "c" * 64},
    )
    target = MagicMock()
    target.request.url = "https://target.example/"
    target.request.method = "GET"
    target.request.resource_type = "document"
    target.request.headers = {"Accept": "text/html"}
    target.fetch.return_value = SimpleNamespace(status=200, headers={})
    engine._route_gate(target)
    target.fetch.assert_called_once_with(
        max_redirects=0, headers={"Accept": "text/html", HEADER_NAME: "c" * 64},
    )

    asset = MagicMock()
    asset.request.url = "https://assets.example.net/app.js"
    asset.request.method = "GET"
    asset.request.resource_type = "script"
    asset.request.headers = {"Accept": "*/*", HEADER_NAME: "c" * 64}
    asset.fetch.return_value = SimpleNamespace(status=200, headers={})
    engine._route_gate(asset)
    asset.fetch.assert_called_once_with(max_redirects=0, headers={"Accept": "*/*"})


def test_asset_redirect_stays_on_explicit_hosts_and_strips_credentials():
    engine = BrowserEngine("https://target.example", required_hosts=["assets.example.net"])
    engine._context = MagicMock()
    route = MagicMock()
    route.request.url = "https://target.example/script.js"
    route.request.method = "GET"
    route.request.resource_type = "script"
    route.request.headers = {"Authorization": "Bearer private", "Accept": "*/*"}
    route.fetch.return_value = SimpleNamespace(
        status=302, headers={"location": "https://assets.example.net/script.js"},
    )
    final = SimpleNamespace(status=200, headers={})
    engine._context.request.get.return_value = final
    engine._route_gate(route)
    engine._context.request.get.assert_called_once_with(
        "https://assets.example.net/script.js",
        headers={"Accept": "*/*"}, max_redirects=0,
    )
    route.fulfill.assert_called_once_with(response=final)
