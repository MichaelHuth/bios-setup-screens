"""
web_search and web_fetch as tools for the AI model: through a SearXNG instance, with Ollama's
hosted web API as the fallback.

The same limits, paging and find behaviour as the SearXNG and Ollama MCP search tools, but
called directly by the bot instead of through an MCP server.
- Search goes to SearXNG (SEARXNG_URL; by default port 8888 on the AI's host); when
  it does not answer, to Ollama's web_search if ollama-api-key.txt is there.
- Pages are fetched straight from this PC and turned into text (as searxng-mcp does); when that
  fails and the Ollama key is there, Ollama's web_fetch is tried.
- BOT_WEB=searxng|ollama|none picks one by hand (default: auto, SearXNG first).
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import re
import socket
from html.parser import HTMLParser
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import httpx

# Results are cut down so that they do not fill the model's context; web_fetch returns a page in
# windows of FETCH_MAX_CHARS (start=...) or only the passages around a search term (find=...).
SEARCH_SNIPPET_CHARS = 1500
FETCH_MAX_CHARS = 40000
FETCH_MAX_LINKS = 40
FETCH_MAX_BYTES = 8 * 1024 * 1024
MAX_REDIRECTS = 5
FIND_CONTEXT_CHARS = 1500
FIND_MAX_MATCHES = 8
PAGE_CACHE_SIZE = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) discord-bot/1.0"
MODES = ("auto", "searxng", "ollama", "none")

TOOLS = [
    {
        "name": "web_search",
        "description": "Search the web (through SearXNG: Google, Bing, DuckDuckGo and others). "
        "Returns titles, URLs and a text snippet of each result.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The search query to run."},
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 5, at most 20).",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "web_fetch",
        "description": "Fetch the content of a web page for the provided URL. Long pages come in "
        "windows of 40000 characters: the result gives total_chars and next_start; call again with "
        'start=next_start to read on. To jump to a topic on a long page, pass find="term": the '
        "result then holds only the passages around each match (case-insensitive, up to 8), with "
        "offsets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The absolute URL to fetch."},
                "start": {
                    "type": "integer",
                    "description": "Character offset to read from (default 0).",
                },
                "find": {
                    "type": "string",
                    "description": "Optional search term; returns the passages around its "
                    "matches instead of a window.",
                },
            },
            "required": ["url"],
        },
    },
]


class _TextExtractor(HTMLParser):
    """Plain text of an HTML page: drops scripts, styles and navigation chrome, keeps block
    structure and links."""

    SKIP = {"script", "style", "noscript", "svg", "template", "head"}
    BLOCK = {
        "p",
        "div",
        "br",
        "li",
        "tr",
        "section",
        "article",
        "header",
        "footer",
        "pre",
        "blockquote",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "table",
        "ul",
        "ol",
        "dd",
        "dt",
    }

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.parts: List[str] = []
        self.links: List[str] = []
        self.title = ""
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.SKIP:
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag in self.BLOCK:
            self.parts.append("\n")
        if tag in ("h1", "h2", "h3", "h4"):
            self.parts.append("#" * int(tag[1]) + " ")
        if tag == "a":
            href = dict(attrs).get("href")
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(urljoin(self.base_url, href))

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif not self._skip:
            self.parts.append(data)

    def text(self) -> str:
        t = "".join(self.parts)
        t = re.sub(r"[ \t\r\f\v]+", " ", t)
        t = re.sub(r"\n\s*\n\s*(\n\s*)+", "\n\n", t)
        return t.strip()


def _cut(text: str, limit: int) -> str:
    if text and len(text) > limit:
        return text[:limit] + f"\n[... cut, {len(text) - limit} more characters]"
    return text


def _find_windows(text: str, term: str) -> list[dict]:
    windows: list[dict] = []
    low, needle, pos = text.lower(), term.lower(), 0
    while len(windows) < FIND_MAX_MATCHES:
        i = low.find(needle, pos)
        if i < 0:
            break
        a, b = max(0, i - FIND_CONTEXT_CHARS), min(len(text), i + len(term) + FIND_CONTEXT_CHARS)
        if windows and a <= windows[-1]["end"]:
            windows[-1]["end"] = b
        else:
            windows.append({"start": a, "end": b})
        pos = i + len(term)
    for w in windows:
        w["text"] = text[w["start"] : w["end"]]
    return windows


# Plain-text files are kept as they are; when the server answers one with a web page instead,
# the file is gone or moved
TEXT_FILE_SUFFIXES = (
    ".txt",
    ".nfo",
    ".diz",
    ".doc",
    ".me",
    ".asm",
    ".c",
    ".h",
    ".ini",
    ".cfg",
    ".bat",
    ".md",
    ".log",
)


class FetchError(Exception):
    pass


class BlockedUrl(Exception):
    """A URL that is not on the public internet: any Discord user can have pages fetched
    from this PC, whose network holds the AI host, SearXNG and the router."""


async def _check_public(url: str) -> str:
    """The address to connect to; raises BlockedUrl unless every address the URL's host
    resolves to is public."""
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise BlockedUrl(f"only http and https addresses can be fetched: {url}")
    infos = await asyncio.get_running_loop().getaddrinfo(
        parts.hostname, None, type=socket.SOCK_STREAM
    )
    addrs = []
    for info in infos:
        addr = ipaddress.ip_address(str(info[4][0]).split("%", maxsplit=1)[0])
        addr = getattr(addr, "ipv4_mapped", None) or addr
        if not addr.is_global or addr.is_multicast:
            raise BlockedUrl(f"local and private addresses cannot be fetched: {url}")
        addrs.append(addr)
    if not addrs:
        raise BlockedUrl(f"the address of {parts.hostname} could not be found: {url}")
    return str(addrs[0])


def _pinned(url: str, addr: str) -> tuple[str, str]:
    """The URL with its host replaced by the checked address, and the Host header: the
    connection goes where the check looked, not to a second answer of the name server (a
    name that resolves to a public address first and a local one next)."""
    parts = urlparse(url)
    host = f"[{addr}]" if ":" in addr else addr
    port = f":{parts.port}" if parts.port else ""
    name = parts.hostname or ""
    header = (f"[{name}]" if ":" in name else name) + port
    return parts._replace(netloc=host + port).geturl(), header


async def _fetch_direct(url: str) -> Dict[str, Any] | None:
    """The page fetched from this PC as text (HTML turned into text with its links), or None
    for a plain-text file the server answered with a web page instead."""
    requested, final, ctype, data = url, url, "", bytearray()
    async with httpx.AsyncClient(
        timeout=30, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):  # (each hop checked: a redirect may lead inside)
            target, host = _pinned(final, await _check_public(final))
            async with client.stream(
                "GET",
                target,
                headers={"Host": host},
                extensions={"sni_hostname": urlparse(final).hostname},  # (TLS checks the name)
            ) as r:
                if r.is_redirect and "location" in r.headers:
                    final = urljoin(final, r.headers["location"])
                    continue
                r.raise_for_status()
                ctype = r.headers.get("content-type", "")
                async for chunk in r.aiter_bytes():
                    data += chunk
                    if len(data) >= FETCH_MAX_BYTES:
                        break
            break
        else:
            raise FetchError(f"too many redirects: {requested}")
    data = data[:FETCH_MAX_BYTES]
    m = re.search(r"charset=([\w-]+)", ctype)
    try:
        body = data.decode(m.group(1) if m else "utf-8")
    except (UnicodeDecodeError, LookupError):  # DOS-era text files
        body = data.decode("cp437")
    is_html = "html" in ctype.lower() or body.lstrip()[:15].lower().startswith(
        ("<!doctype html", "<html")
    )
    if is_html and urlparse(requested).path.lower().endswith(TEXT_FILE_SUFFIXES):
        return None
    if is_html:
        p = _TextExtractor(final)
        p.feed(body)
        return {
            "title": html.unescape(p.title.strip()),
            "content": p.text(),
            "links": list(dict.fromkeys(p.links)),
        }
    name = url.rstrip("/").rsplit("/", 1)[-1]
    return {"title": name, "content": body.replace("\r\n", "\n"), "links": []}


class WebTools:
    def __init__(self, searxng_url: str | None, ollama_key: str | None, mode: str = "auto"):
        mode = (mode or "auto").lower()
        if mode not in MODES:
            raise ValueError(f"BOT_WEB must be one of {', '.join(MODES)}")
        self.searxng_url = (searxng_url or "").rstrip("/") if mode in ("auto", "searxng") else ""
        self.ollama = None
        if ollama_key and mode in ("auto", "ollama"):
            # (imported only when needed: the fallback)
            from ollama import AsyncClient  # pylint: disable=import-outside-toplevel

            self.ollama = AsyncClient(headers={"Authorization": f"Bearer {ollama_key}"})
        self._page_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.searxng_url or self.ollama)

    async def status(self) -> str:
        """What the web tools use, for the start-up message."""
        if not self.enabled:
            return "off (no SearXNG and no ollama-api-key.txt, or BOT_WEB=none)"
        parts = []
        if self.searxng_url:
            ok = await self._searxng_alive()
            parts.append(f"SearXNG at {self.searxng_url} ({'answers' if ok else 'not answering'})")
        if self.ollama:
            parts.append("Ollama web API" + (" as fallback" if self.searxng_url else ""))
        return "on: " + ", ".join(parts)

    async def _searxng_alive(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                return (await client.get(f"{self.searxng_url}/healthz")).status_code == 200
        except httpx.HTTPError:
            return False

    async def _searxng_search(self, query: str, max_results: int) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": USER_AGENT}) as client:
            r = await client.get(
                f"{self.searxng_url}/search", params={"q": query, "format": "json"}
            )
            r.raise_for_status()
            data = r.json()
        results = []
        for item in (data.get("results") or [])[: max(1, min(max_results, 20))]:
            results.append(
                {
                    "title": item.get("title"),
                    "url": item.get("url"),
                    "content": _cut(item.get("content") or "", SEARCH_SNIPPET_CHARS),
                    "engines": item.get("engines"),
                }
            )
        out: Dict[str, Any] = {"results": results}
        if data.get("unresponsive_engines"):
            out["unresponsive_engines"] = data["unresponsive_engines"]
        if not results:
            out["note"] = (
                "no results; try other words, or the search engines behind SearXNG "
                "may be blocking for a while"
            )
        return out

    async def web_search(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        error = None
        if self.searxng_url:
            try:
                return await self._searxng_search(query, max_results)
            except (httpx.HTTPError, ValueError) as e:  # not running, or not answering JSON
                error = f"SearXNG: {type(e).__name__}: {e}"
        if self.ollama:
            res = (await self.ollama.web_search(query=query, max_results=max_results)).model_dump()
            for r in res.get("results") or []:
                r["content"] = _cut(r.get("content") or "", SEARCH_SNIPPET_CHARS)
            if error:
                res["note"] = f"searched through Ollama ({error})"
            return res
        raise FetchError(error or "no web search available")

    async def _get_page(self, url: str) -> Dict[str, Any]:
        # paging through one page must not fetch it again; failures are kept too, so retrying
        # the same URL fails fast instead of fetching again
        if url not in self._page_cache:
            if len(self._page_cache) >= PAGE_CACHE_SIZE:
                self._page_cache.pop(next(iter(self._page_cache)))
            try:
                page = await _fetch_direct(url)
                if page is None:  # a text file answered with a web page
                    page = {
                        "title": url.rstrip("/").rsplit("/", 1)[-1],
                        "content": "",
                        "links": [],
                        "note": "the server answered with a web page instead of this file "
                        "(the file is probably gone or moved); try an archived copy "
                        "(https://web.archive.org/web/2024/<url>) or find its new location",
                    }
            except BlockedUrl as e:  # (not retried through the fallback either)
                page = {"error": str(e)}
            except Exception as e:  # 404, timeouts, blocked sites ...
                page = {"error": f"{type(e).__name__}: {e}"}
                if self.ollama:  # Ollama's fetch service may get through where this PC cannot
                    try:
                        page = (await self.ollama.web_fetch(url=url)).model_dump()
                    except Exception:
                        pass
            self._page_cache[url] = page
        page = self._page_cache[url]
        if "error" in page:
            raise FetchError(
                f"{page['error']} - fetching this URL again will fail the same way. Try an "
                "archived copy (https://web.archive.org/web/2024/<url>), another page, or "
                "web_search."
            )
        return page

    async def web_fetch(self, url: str, start: int = 0, find: str = "") -> Dict[str, Any]:
        page = await self._get_page(url)
        text = page.get("content") or ""
        res: Dict[str, Any] = {"title": page.get("title"), "total_chars": len(text)}
        if page.get("note"):
            res["page_note"] = page["note"]
        if find:
            res["find"] = find
            res["matches"] = _find_windows(text, find)
            if not res["matches"]:
                res["note"] = "no match; try another term, or page through with start="
            return res
        start = max(0, min(start, len(text)))
        end = min(len(text), start + FETCH_MAX_CHARS)
        res.update(start=start, end=end, content=text[start:end])
        if end < len(text):
            res["next_start"] = end
            res["note"] = (
                f"{len(text) - end} more characters: call again with start={end}, "
                'or use find="term"'
            )
        if start == 0:
            links = page.get("links") or []
            res["links"] = links[:FETCH_MAX_LINKS] + (
                [f"... {len(links) - FETCH_MAX_LINKS} more links"]
                if len(links) > FETCH_MAX_LINKS
                else []
            )
        return res

    async def run(self, name: str, args: Dict[str, Any]) -> str:
        """Run a tool call and return its result as JSON text for a tool_result block."""
        if name == "web_search":
            result = await self.web_search(args["query"], int(args.get("max_results", 5)))
        elif name == "web_fetch":
            result = await self.web_fetch(
                args["url"], int(args.get("start", 0)), args.get("find", "")
            )
        else:
            raise ValueError(f"unknown tool: {name}")
        return json.dumps(result, ensure_ascii=False, default=str)
