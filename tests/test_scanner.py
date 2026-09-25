import pytest

from corspectra.config import Config
from corspectra.http_client import HttpClient
from corspectra.models import ResponseRecord
from corspectra.scanner import CorsScanner


@pytest.mark.asyncio
async def test_scanner_with_mocked_transport(monkeypatch):
    async def request(self, method, url, origin=None, extra_headers=None, capture_limit=500):
        headers = {"content-type": "application/json"}
        if origin:
            headers["access-control-allow-origin"] = origin
        return ResponseRecord(
            url, method, origin, 200, headers, "application/json", 2, "hash", "{}"
        )

    monkeypatch.setattr(HttpClient, "request", request)
    scanner = CorsScanner(
        "https://app.test", config=Config(retries=0), origins=["https://evil.example"]
    )
    result = await scanner.scan_async()
    assert result.statistics.requests == 2
    assert any(f.finding_id == "CORS-001" for f in result.findings)
