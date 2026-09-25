"""Bounded same-host crawler and passive endpoint extraction."""

from __future__ import annotations

from collections import deque

import httpx
from bs4 import BeautifulSoup

from ..http_client import HttpClient
from ..utils.helpers import normalize_url, same_site
from .javascript import extract_javascript_urls


async def crawl(
    client: HttpClient,
    root: str,
    max_depth: int = 1,
    max_pages: int = 50,
    disallowed: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    queue = deque([(normalize_url(root), 0)])
    seen = set()
    endpoints = []
    external = []
    blocked = disallowed or []
    while queue and len(seen) < max_pages:
        url, depth = queue.popleft()
        if url in seen or any(url.startswith(rule) for rule in blocked):
            continue
        seen.add(url)
        endpoints.append(url)
        try:
            response = await client.request("GET", url, capture_limit=65536)
        except httpx.HTTPError:
            continue
        if "javascript" in response.content_type or url.lower().split("?", 1)[0].endswith(".js"):
            for candidate in extract_javascript_urls(response.body_preview, url):
                (endpoints if same_site(candidate, root) else external).append(candidate)
            continue
        if "html" not in response.content_type:
            continue
        soup = BeautifulSoup(response.body_preview, "html.parser")
        candidates = [
            tag.get(attr)
            for tag, attr in [(x, "href") for x in soup.find_all("a")]
            + [(x, "src") for x in soup.find_all("script")]
        ]
        candidates += extract_javascript_urls(response.body_preview, url)
        for value in candidates:
            if not value:
                continue
            try:
                candidate = normalize_url(value, url)
            except ValueError:
                continue
            if same_site(candidate, root):
                if depth < max_depth and candidate not in seen:
                    queue.append((candidate, depth + 1))
                if "/api/" in candidate or "/graphql" in candidate:
                    endpoints.append(candidate)
            else:
                external.append(candidate)
    return list(dict.fromkeys(endpoints)), list(dict.fromkeys(external))
