from __future__ import annotations

from ..models import Finding, ResponseRecord, Severity


def analyze_preflight(records: list[ResponseRecord]) -> list[Finding]:
    findings = []
    gets = {(r.origin, r.endpoint): r for r in records if r.method == "GET"}
    for opt in (r for r in records if r.method == "OPTIONS"):
        get = gets.get((opt.origin, opt.endpoint))
        if get and bool(get.headers.get("access-control-allow-origin")) != bool(
            opt.headers.get("access-control-allow-origin")
        ):
            findings.append(
                Finding(
                    "CORS-008",
                    "Actual/preflight policy inconsistency",
                    Severity.MEDIUM,
                    "High",
                    opt.endpoint,
                    "OPTIONS",
                    opt.origin,
                    opt.cors_headers,
                    "Actual and preflight responses should consistently enforce the same origin policy.",
                    f"GET ACAO={get.headers.get('access-control-allow-origin', '<absent>')}; OPTIONS ACAO={opt.headers.get('access-control-allow-origin', '<absent>')}",
                    "Cross-origin sharing differs between GET and OPTIONS.",
                    "Inconsistency can break clients or expose unreviewed method-specific behavior.",
                    "Centralize CORS enforcement and test every method consistently.",
                    [],
                    40,
                )
            )
    return findings
