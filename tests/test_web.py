"""web_fetch's guards, offline: a mock transport answers instead of the network, and a fake
name server stands in for DNS. No request goes to a private address."""

from __future__ import annotations

import asyncio
import functools
import socket

import httpx
import pytest

import web_tools as wt

PUBLIC = "93.184.215.14"


@pytest.fixture
def requests(monkeypatch: pytest.MonkeyPatch) -> list[httpx.Request]:
    """The requests web_fetch sends, answered by a mock server."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if path == "/to-private":
            return httpx.Response(302, headers={"location": "http://192.168.1.10:8080/"})
        if path == "/loop":
            return httpx.Response(302, headers={"location": "/loop"})
        if path == "/big":
            body = b"x" * (wt.FETCH_MAX_BYTES + 5000)
            return httpx.Response(200, headers={"content-type": "text/plain"}, content=body)
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"hello")

    real = httpx.AsyncClient
    monkeypatch.setattr(
        wt.httpx, "AsyncClient", functools.partial(real, transport=httpx.MockTransport(handler))
    )
    return seen


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost:8080/",
        "http://192.168.1.10:8080/",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",
        "http://0x7f.1/",
        "http://0.0.0.0/",
        "http://100.64.0.1/",
        f"ftp://{PUBLIC}/x",
        "file:///C:/Windows/win.ini",
    ],
)
def test_local_and_private_addresses_are_not_fetched(url: str, requests: list) -> None:
    with pytest.raises((wt.BlockedUrl, OSError)):
        asyncio.run(wt._fetch_direct(url))
    assert requests == []


def test_a_redirect_into_the_lan_is_stopped_before_its_request(requests: list) -> None:
    with pytest.raises(wt.BlockedUrl):
        asyncio.run(wt._fetch_direct(f"http://{PUBLIC}/to-private"))
    assert [r.url.path for r in requests] == ["/to-private"]


def test_redirect_loop_ends(requests: list) -> None:
    with pytest.raises(wt.FetchError, match="too many"):
        asyncio.run(wt._fetch_direct(f"http://{PUBLIC}/loop"))
    assert len(requests) == wt.MAX_REDIRECTS + 1


def test_public_page_and_size_cap(requests: list) -> None:
    assert asyncio.run(wt._fetch_direct(f"http://{PUBLIC}/ok.txt"))["content"] == "hello"
    page = asyncio.run(wt._fetch_direct(f"http://{PUBLIC}/big"))
    assert len(page["content"]) == wt.FETCH_MAX_BYTES


def test_the_tool_reports_a_blocked_address(requests: list) -> None:
    tools = wt.WebTools(None, None, "none")
    with pytest.raises(wt.FetchError, match="cannot be fetched"):
        asyncio.run(tools.web_fetch("http://192.168.1.10:8080/"))


def test_the_connection_goes_to_the_checked_address(requests: list) -> None:
    """A name server that answers a public address for the check and 127.0.0.1 afterwards
    (DNS rebinding): the request still goes to the address that was checked."""
    lookups: list[str] = []

    async def go() -> None:
        loop = asyncio.get_running_loop()

        async def fake(host, port, *args, **kwargs):
            lookups.append(host)
            ip = PUBLIC if len(lookups) == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0))]

        loop.getaddrinfo = fake
        await wt._fetch_direct("http://rebind.test/page")

    asyncio.run(go())
    assert [(r.url.host, r.headers["host"]) for r in requests] == [(PUBLIC, "rebind.test")]
    assert lookups == ["rebind.test"]


def test_pinned_urls_keep_port_path_and_name() -> None:
    assert wt._pinned("https://example.com:8443/a?b=1", PUBLIC) == (
        f"https://{PUBLIC}:8443/a?b=1",
        "example.com:8443",
    )
    assert wt._pinned("https://example.com/x", "2606:2800::1") == (
        "https://[2606:2800::1]/x",
        "example.com",
    )
