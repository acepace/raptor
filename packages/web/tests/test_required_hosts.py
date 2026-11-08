"""Explicit transport hosts do not expand the web scan's origin."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from packages.web.browser import BrowserEngine
from packages.web.egress_hosts import required_host, target_host
from packages.web.scanner import WebScanner, build_arg_parser


@pytest.mark.parametrize("host", [
    "https://assets.example.net", "assets.example.net:443", "*.example.net",
    "127.0.0.1", "localhost", "login.localhost", "example.net/path",
    " example.net", "example..net",
])
def test_required_host_rejects_ambiguous_or_unsafe_input(host):
    with pytest.raises(ValueError):
        required_host(host)


def test_cli_accepts_repeatable_required_hosts():
    args = build_arg_parser().parse_args([
        "--url", "https://target.example", "--required-host", "login.example.net",
        "--required-host", "assets.example.net",
    ])
    assert args.required_host == ["login.example.net", "assets.example.net"]


def test_target_host_never_adds_proxy_wildcard():
    with pytest.raises(ValueError):
        target_host("https://*.example.net")
    assert target_host("https://127.0.0.1:8443/") == "127.0.0.1"


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
