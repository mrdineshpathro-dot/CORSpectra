from .credentials import analyze_credentials
from .headers import analyze_headers
from .origin import analyze_origin_policy
from .preflight import analyze_preflight


def analyze(records):
    findings = []
    for analyzer in (
        analyze_origin_policy,
        analyze_credentials,
        analyze_headers,
        analyze_preflight,
    ):
        findings.extend(analyzer(records))
    return sorted(findings, key=lambda f: (int(f.severity), f.score), reverse=True)


__all__ = ["analyze"]
