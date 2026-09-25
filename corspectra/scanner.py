"""High-level CORS scan orchestration and importable API."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from urllib.parse import urljoin

import httpx

from .analyzers import analyze
from .analyzers.consistency import analyze_consistency
from .config import Config
from .discovery import crawl, parse_robots, parse_sitemap
from .http_client import HttpClient
from .models import ScanResult
from .plugins import load_plugins
from .utils.helpers import deduplicate, generate_origins, normalize_origin, normalize_url, same_site

LOG = logging.getLogger("corspectra.scanner")
COMMON_PATHS = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/users",
    "/api/profile",
    "/api/account",
    "/api/auth",
    "/api/admin",
    "/graphql",
)


class CorsScanner:
    """CORS policy scanner. ``scan`` is synchronous; ``scan_async`` supports async apps."""

    def __init__(
        self,
        target: str,
        *,
        config: Config | None = None,
        deep: bool = False,
        crawl_enabled: bool | None = None,
        preflight: bool = False,
        origins: list[str] | None = None,
        methods: list[str] | None = None,
        request_headers: list[str] | None = None,
        cookies: str | None = None,
        progress_callback: Callable[[ScanResult], None] | None = None,
    ) -> None:
        self.target = normalize_url(target)
        self.config = (config or Config()).validate()
        self.deep = deep
        self.crawl_enabled = self.config.crawl if crawl_enabled is None else crawl_enabled
        self.preflight = preflight or deep
        self.origins = origins if origins is not None else self.config.origins or None
        if self.origins:
            for origin in self.origins:
                normalize_origin(origin)
        self.methods = methods or ["GET", "POST", "PUT", "DELETE"]
        self.request_headers = request_headers or [
            "Authorization",
            "Content-Type",
            "X-Requested-With",
        ]
        self.cookies = cookies
        self.progress_callback = progress_callback

    def _notify(self, result: ScanResult) -> None:
        if self.progress_callback:
            try:
                self.progress_callback(result)
            except Exception as exc:  # noqa: BLE001 - UI callbacks cannot stop a scan
                LOG.debug("Progress callback failed: %s", exc)

    def scan(self) -> ScanResult:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.scan_async())
        raise RuntimeError("CorsScanner.scan() cannot run inside an event loop; await scan_async()")

    async def _discover(self, client: HttpClient, result: ScanResult) -> list[str]:
        endpoints = [self.target]
        if self.deep:
            endpoints += [normalize_url(urljoin(self.target, p)) for p in COMMON_PATHS]
        disallowed = []
        try:
            robots = await client.request(
                "GET", urljoin(self.target, "/robots.txt"), capture_limit=65536
            )
            if robots.status_code < 400:
                refs, disallowed = parse_robots(robots.body_preview, self.target)
                for sitemap_url in refs[:3]:
                    try:
                        sm = await client.request("GET", sitemap_url, capture_limit=262144)
                        endpoints += [
                            u for u in parse_sitemap(sm.body_preview) if same_site(u, self.target)
                        ][:100]
                    except httpx.HTTPError as exc:
                        LOG.debug("Sitemap failed: %s", exc)
            try:
                sitemap = await client.request(
                    "GET", urljoin(self.target, "/sitemap.xml"), capture_limit=262144
                )
                if sitemap.status_code < 400:
                    endpoints += [
                        u for u in parse_sitemap(sitemap.body_preview) if same_site(u, self.target)
                    ][:100]
            except httpx.HTTPError:
                pass
        except httpx.HTTPError as exc:
            LOG.debug("Discovery request failed: %s", exc)
        if self.crawl_enabled:
            found, external = await crawl(
                client, self.target, self.config.crawl_depth, self.config.max_pages, disallowed
            )
            endpoints += found
            if external:
                LOG.info("Observed %d external URL(s), kept out of scan scope", len(external))
        return deduplicate(endpoints)

    async def scan_async(self) -> ScanResult:
        result = ScanResult(self.target)
        origins = self.origins or generate_origins(self.target)
        if not self.deep and self.origins is None:
            origins = origins[:4]
        semaphore = asyncio.Semaphore(self.config.threads)
        async with HttpClient(self.config, self.cookies) as client:
            result.endpoints = await self._discover(client, result)
            self._notify(result)

            async def probe(
                endpoint: str,
                origin: str | None,
                preflight_method: str | None = None,
            ) -> None:
                method = "OPTIONS" if preflight_method else "GET"
                extra = {}
                if preflight_method:
                    extra = {
                        "Access-Control-Request-Method": preflight_method,
                        "Access-Control-Request-Headers": ", ".join(self.request_headers),
                    }
                async with semaphore:
                    try:
                        result.responses.append(
                            await client.request(method, endpoint, origin, extra)
                        )
                    except (httpx.HTTPError, ValueError) as exc:
                        message = f"{method} {endpoint} ({origin or 'no origin'}): {type(exc).__name__}: {exc}"
                        result.errors.append(message)
                        LOG.warning(message)
                    finally:
                        result.statistics.requests = len(result.responses)
                        result.statistics.errors = len(result.errors)
                        result.statistics.origins_tested = len(
                            {response.origin for response in result.responses if response.origin}
                        )
                        self._notify(result)

            tasks = []
            for endpoint in result.endpoints:
                tasks.append(probe(endpoint, None))
                for origin in origins:
                    tasks.append(probe(endpoint, origin))
                    if self.preflight:
                        tasks.extend(probe(endpoint, origin, method) for method in self.methods)
            await asyncio.gather(*tasks)
        by_endpoint = {}
        for record in result.responses:
            by_endpoint.setdefault(record.endpoint, []).append(record)
        for records in by_endpoint.values():
            result.findings.extend(analyze(records))
        result.findings.extend(analyze_consistency(result.responses))
        for plugin in load_plugins():
            try:
                result.findings.extend(plugin(result.responses))
            except Exception as exc:  # noqa: BLE001 - isolate optional third-party plugins
                LOG.warning("Analyzer plugin %r failed: %s", plugin, exc)
        unique_findings = {}
        for finding in result.findings:
            key = (finding.finding_id, finding.endpoint, finding.origin_tested)
            unique_findings[key] = finding
        result.findings = sorted(
            unique_findings.values(),
            key=lambda finding: (int(finding.severity), finding.score),
            reverse=True,
        )
        result.finish()
        self._notify(result)
        return result
