"""Cross-endpoint and requested-method CORS policy comparison."""

from __future__ import annotations

from collections import defaultdict

from ..models import Finding, ResponseRecord, Severity


def analyze_consistency(records: list[ResponseRecord]) -> list[Finding]:
    """Report policy differences as review signals, never as proven bypasses."""
    findings: list[Finding] = []
    actual = [r for r in records if r.method == "GET" and r.origin]
    endpoint_profiles: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for record in actual:
        endpoint_profiles[record.endpoint].add(
            (
                record.origin or "",
                record.headers.get("access-control-allow-origin", "<absent>"),
            )
        )
    unique_profiles = {tuple(sorted(profile)) for profile in endpoint_profiles.values()}
    if len(unique_profiles) > 1:
        evidence = "\n".join(
            f"{endpoint}: " + ", ".join(f"{origin}→{acao}" for origin, acao in sorted(profile))
            for endpoint, profile in sorted(endpoint_profiles.items())
        )
        findings.append(
            Finding(
                "CORS-009",
                "CORS policy differs between endpoints",
                Severity.INFO,
                "High",
                records[0].endpoint if records else "",
                "GET",
                None,
                {},
                "Policy differences should be intentional and documented per endpoint.",
                evidence,
                "Observed Access-Control-Allow-Origin behavior is not uniform across scanned endpoints.",
                "Differences are often legitimate, but can reveal an endpoint omitted from centralized policy controls.",
                "Review outlier endpoints and centralize policy enforcement where appropriate.",
                [],
                5,
            )
        )

    options: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    for record in records:
        if record.method == "OPTIONS" and record.origin and record.requested_method:
            options[(record.endpoint, record.origin)][record.requested_method] = record.headers.get(
                "access-control-allow-origin", "<absent>"
            )
    for (endpoint, origin), policies in options.items():
        if len(set(policies.values())) > 1:
            evidence = "; ".join(f"{method}→{acao}" for method, acao in sorted(policies.items()))
            findings.append(
                Finding(
                    "CORS-011",
                    "Preflight origin policy differs by requested method",
                    Severity.LOW,
                    "High",
                    endpoint,
                    "OPTIONS",
                    origin,
                    {},
                    "Method-specific policy differences should follow the intended API authorization model.",
                    evidence,
                    "The same origin received different CORS decisions for different requested methods.",
                    "This may be intentional, but an outlier method can indicate incomplete CORS middleware coverage.",
                    "Review each advertised method and enforce one documented policy layer.",
                    [],
                    15,
                )
            )
    return findings
