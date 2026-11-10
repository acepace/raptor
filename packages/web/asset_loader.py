"""Credential-free loading for explicitly named browser asset hosts."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from urllib.parse import urlsplit

from core.http.anonymous import AnonymousOriginClient
from core.http.headers import anonymous_resource_headers
from packages.web.egress_hosts import required_host


_RESOURCE_TYPES = frozenset({"script", "stylesheet", "image", "font"})
_MAX_ASSET_BYTES = 8 * 1024 * 1024
_MAX_ASSET_READ_SECONDS = 15
_MAX_ASSET_REQUESTS = 256
_MAX_TOTAL_ASSET_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class AssetResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class AssetLoader:
    """Fetch declared page assets without sharing target browser state."""

    def __init__(self, hosts: tuple[str, ...] | list[str]) -> None:
        self.hosts = frozenset(required_host(host) for host in hosts)
        self._budget_lock = Lock()
        self._requests = 0
        self._remaining_bytes = _MAX_TOTAL_ASSET_BYTES

    def allows(self, url: str, method: str, resource_type: str) -> bool:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return False
        return (
            parsed.scheme in ("http", "https")
            and parsed.hostname is not None
            and parsed.hostname.lower().rstrip(".") in self.hosts
            and parsed.username is None
            and parsed.password is None
            and (port is None or 1 <= port <= 65535)
            and method in ("GET", "HEAD")
            and resource_type in _RESOURCE_TYPES
        )

    def fetch(self, url: str, method: str, resource_type: str) -> AssetResponse:
        if not self.allows(url, method, resource_type):
            raise ValueError("browser asset is not allowed")

        # The declared URL is chosen only after the host and resource-type
        # gate. A fresh anonymous client constrains this request to its exact
        # origin, routes HTTP and HTTPS through the real egress proxy, bounds
        # the body and deadline, and never imports browser state.
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        with self._budget_lock:
            if self._requests >= _MAX_ASSET_REQUESTS or self._remaining_bytes == 0:
                raise ValueError("browser asset budget exhausted")
            cap = min(_MAX_ASSET_BYTES, self._remaining_bytes)
            self._requests += 1
            self._remaining_bytes -= cap
        charged = cap
        try:
            with AnonymousOriginClient(
                [origin],
                max_bytes=cap,
                timeout=10,
                total_timeout=_MAX_ASSET_READ_SECONDS,
                max_requests=1,
                max_total_bytes=cap,
            ) as client:
                response = client.request(method, url)
            if 300 <= response.status < 400:
                raise ValueError("browser asset redirect refused")
            headers = anonymous_resource_headers(response.headers)
            charged = len(response.body)
            return AssetResponse(
                status=response.status, headers=headers, body=response.body
            )
        finally:
            # Failed reads retain their full reservation; partial body size is
            # unknown. Successful reads return only their unused allowance.
            with self._budget_lock:
                self._remaining_bytes += cap - charged
