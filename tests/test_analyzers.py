from corspectra.analyzers import analyze
from corspectra.analyzers.severity import score_policy
from corspectra.models import ResponseRecord, Severity


def record(origin, acao, **headers):
    all_headers = {
        "access-control-allow-origin": acao,
        "content-type": "application/json",
        **headers,
    }
    return ResponseRecord(
        "https://x.test/api/profile", "GET", origin, 200, all_headers, "application/json", 10, "abc"
    )


def test_arbitrary_reflection_with_credentials_is_high():
    findings = analyze(
        [
            record("https://x.test", "https://x.test"),
            record(
                "https://evil.example",
                "https://evil.example",
                **{"access-control-allow-credentials": "true"},
            ),
        ]
    )
    finding = next(f for f in findings if f.finding_id == "CORS-001")
    assert finding.severity >= Severity.HIGH
    assert "arbitrary origin" in finding.reason


def test_wildcard_public_is_not_overstated():
    finding = next(
        f for f in analyze([record("https://evil.example", "*")]) if f.finding_id == "CORS-003"
    )
    assert finding.severity == Severity.LOW
    assert "intentional" in finding.impact


def test_credentialed_wildcard_and_broad_headers():
    findings = analyze(
        [
            record(
                "https://evil.example",
                "*",
                **{
                    "access-control-allow-credentials": "true",
                    "access-control-allow-headers": "*",
                    "access-control-allow-methods": "GET, DELETE",
                },
            )
        ]
    )
    ids = {f.finding_id for f in findings}
    assert {"CORS-004", "CORS-005", "CORS-006"} <= ids


def test_null_and_preflight_difference():
    get = record("null", "null")
    opt = ResponseRecord(get.endpoint, "OPTIONS", "null", 204, {})
    ids = {f.finding_id for f in analyze([get, opt])}
    assert "CORS-002" in ids and "CORS-008" in ids


def test_severity_is_correlated():
    score, severity, reasons = score_policy(arbitrary=True, credentials=True, sensitive=True)
    assert score == 85 and severity == Severity.HIGH and len(reasons) == 3
