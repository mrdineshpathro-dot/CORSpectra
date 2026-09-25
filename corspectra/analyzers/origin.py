"""Evidence-driven origin policy analysis."""

from __future__ import annotations

from urllib.parse import urlsplit

from ..models import Finding, ResponseRecord, Severity
from ..utils.helpers import normalize_origin, origin_for
from .severity import is_sensitive, score_policy

REFS = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    "https://portswigger.net/web-security/cors",
]


def _is_untrusted(origin: str | None, endpoint: str) -> bool:
    if not origin or origin == "null":
        return False
    try:
        return (
            urlsplit(normalize_origin(origin)).hostname != urlsplit(origin_for(endpoint)).hostname
        )
    except ValueError:
        return True


def analyze_origin_policy(records: list[ResponseRecord]) -> list[Finding]:
    findings: list[Finding] = []
    if not records:
        return findings
    endpoint = records[0].endpoint
    wildcard = [
        r for r in records if r.headers.get("access-control-allow-origin", "").strip() == "*"
    ]

    def origin_matches(record: ResponseRecord) -> bool:
        if not record.origin or record.origin == "null":
            return False
        try:
            return normalize_origin(
                record.headers.get("access-control-allow-origin", "").strip()
            ) == normalize_origin(record.origin)
        except ValueError:
            return False

    reflected = [
        record
        for record in records
        if origin_matches(record) and _is_untrusted(record.origin, endpoint)
    ]
    nulls = [
        r
        for r in records
        if r.origin == "null"
        and r.headers.get("access-control-allow-origin", "").strip().lower() == "null"
    ]
    sensitive = any(is_sensitive(r) for r in records)

    def finding(fid: str, title: str, sample: ResponseRecord, **signals: bool) -> Finding:
        creds = sample.headers.get("access-control-allow-credentials", "").lower() == "true"
        score, severity, reasons = score_policy(credentials=creds, sensitive=sensitive, **signals)
        return Finding(
            fid,
            title,
            severity,
            "High" if len([r for r in records if r.origin]) >= 2 else "Medium",
            endpoint,
            sample.method,
            sample.origin,
            sample.cors_headers,
            "Only explicitly trusted origins should receive an Access-Control-Allow-Origin value.",
            f"Origin: {sample.origin}\nAccess-Control-Allow-Origin: {sample.headers.get('access-control-allow-origin')}\nStatus: {sample.status_code}",
            "; ".join(reasons),
            "A permitted browser origin may read this response; impact depends on response sensitivity and credentials.",
            "Use an exact allowlist after canonical origin parsing. Reject null and attacker-controlled origins; add Vary: Origin for dynamic policies.",
            REFS,
            score,
        )

    if reflected:
        sample = reflected[0]
        findings.append(
            finding("CORS-001", "Arbitrary origin reflection detected", sample, arbitrary=True)
        )
        vary = {item.strip().lower() for item in sample.headers.get("vary", "").split(",")}
        if "origin" not in vary:
            findings.append(
                Finding(
                    "CORS-010",
                    "Dynamic origin policy missing Vary: Origin",
                    Severity.LOW,
                    "High",
                    endpoint,
                    sample.method,
                    sample.origin,
                    sample.cors_headers,
                    "Responses with origin-specific ACAO values should include Vary: Origin.",
                    f"Reflected ACAO: {sample.origin}; Vary: {sample.headers.get('vary', '<absent>')}",
                    "A dynamic origin response was observed without an Origin cache key.",
                    "A shared cache could serve an origin-specific policy to another requester; practical impact depends on cache behavior.",
                    "Add Vary: Origin and ensure caches do not mix authenticated responses.",
                    REFS,
                    25,
                )
            )
    if nulls:
        findings.append(finding("CORS-002", "Null origin accepted", nulls[0], null_origin=True))
    if wildcard:
        sample = wildcard[0]
        score, severity, reasons = score_policy(wildcard=True, sensitive=sensitive)
        public = (
            not sensitive
            and sample.headers.get("access-control-allow-credentials", "").lower() != "true"
        )
        findings.append(
            Finding(
                "CORS-003",
                "Wildcard CORS policy",
                severity,
                "High",
                endpoint,
                sample.method,
                sample.origin,
                sample.cors_headers,
                "Wildcard access should be limited to deliberately public, non-sensitive resources.",
                "Access-Control-Allow-Origin: *",
                "; ".join(reasons) + ("; resource appears public/non-sensitive" if public else ""),
                "Any website can read non-credentialed responses. This can be intentional for public resources.",
                "Confirm the resource is public; otherwise use a narrow origin allowlist.",
                REFS,
                score,
            )
        )
    return findings
