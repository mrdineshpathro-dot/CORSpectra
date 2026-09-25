import json

from corspectra.models import Finding, ScanResult, Severity
from corspectra.reporting import REPORTERS


def result():
    r = ScanResult("https://x.test", endpoints=["https://x.test/"])
    r.findings = [
        Finding(
            "CORS-001",
            "<reflection>",
            Severity.HIGH,
            "High",
            r.target,
            "GET",
            "https://evil.example",
            {"access-control-allow-origin": "https://evil.example"},
            "trusted only",
            "evidence",
            "reason",
            "impact",
            "fix",
        )
    ]
    r.finish()
    return r


def test_all_reports_render():
    r = result()
    assert json.loads(REPORTERS["json"][0](r))["findings"][0]["severity"] == "HIGH"
    assert "finding_id" in REPORTERS["csv"][0](r)
    assert "CORS-001" in REPORTERS["markdown"][0](r)
    html = REPORTERS["html"][0](r)
    assert "&lt;reflection&gt;" in html and "<!doctype html>" in html
