"""Asynchronous, pooled HTTP transport with retries and polite rate limiting."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import time
from collections.abc import Mapping
from typing import Self

import httpx

from .config import Config
from .models import ResponseRecord
from .utils.sanitizer import redact_headers

LOG = logging.getLogger("corspectra.http")


class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.interval = 1.0 / requests_per_second if requests_per_second else 0.0
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        async with self._lock:
            delay = self.interval - (time.monotonic() - self._last)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last = time.monotonic()


class HttpClient:
    def __init__(self, config: Config, cookies: str | None = None) -> None:
        self.config = config
        self.limiter = RateLimiter(config.rate_limit)
        headers = {"User-Agent": config.user_agent, **config.headers}
        if cookies:
            headers["Cookie"] = cookies
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout),
            verify=config.verify_ssl,
            follow_redirects=config.follow_redirects,
            proxy=config.proxy,
            headers=headers,
            limits=httpx.Limits(
                max_connections=config.threads, max_keepalive_connections=config.threads
            ),
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self.client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        origin: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        capture_limit: int = 500,
    ) -> ResponseRecord:
        headers = dict(extra_headers or {})
        if origin is not None:
            headers["Origin"] = origin
        last_error: Exception | None = None
        for attempt in range(self.config.retries + 1):
            try:
                await self.limiter.wait()
                if self.config.delay:
                    await asyncio.sleep(self.config.delay)
                LOG.debug("%s %s headers=%s", method, url, redact_headers(headers))
                started = time.perf_counter()
                response = await self.client.request(method, url, headers=headers)
                elapsed = (time.perf_counter() - started) * 1000
                body = response.content
                normalized = {k.lower(): v for k, v in response.headers.items()}
                LOG.debug("Response %s %s (%d bytes)", response.status_code, url, len(body))
                return ResponseRecord(
                    endpoint=url,
                    method=method.upper(),
                    origin=origin,
                    status_code=response.status_code,
                    headers=normalized,
                    content_type=normalized.get("content-type", ""),
                    content_length=len(body),
                    body_hash=hashlib.sha256(body).hexdigest(),
                    body_preview=response.text[:capture_limit]
                    if any(
                        kind in normalized.get("content-type", "")
                        for kind in ("text", "json", "xml", "javascript")
                    )
                    else "",
                    redirect_location=normalized.get("location"),
                    elapsed_ms=round(elapsed, 2),
                    requested_method=headers.get("Access-Control-Request-Method"),
                    requested_headers=[
                        item.strip()
                        for item in headers.get("Access-Control-Request-Headers", "").split(",")
                        if item.strip()
                    ],
                )
            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
                last_error = exc
                if attempt < self.config.retries:
                    backoff = min(2**attempt * 0.25 + random.random() * 0.1, 3)
                    LOG.info(
                        "Retry %d/%d for %s after %s",
                        attempt + 1,
                        self.config.retries,
                        url,
                        type(exc).__name__,
                    )
                    await asyncio.sleep(backoff)
        assert last_error
        raise last_error
