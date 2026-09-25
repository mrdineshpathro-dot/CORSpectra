from __future__ import annotations

from ..models import Finding, ResponseRecord, Severity

DANGEROUS_EXPOSED = {"authorization", "set-cookie", "x-api-key", "x-auth-token"}
BROAD_METHODS = {"PUT", "PATCH", "DELETE", "CONNECT", "TRACE"}


def analyze_headers(records: list[ResponseRecord]) -> list[Finding]:
    findings = []
    for r in records:
        methods = {
            x.strip().upper()
            for x in r.headers.get("access-control-allow-methods", "").split(",")
            if x.strip()
        }
        headers = {
            x.strip().lower()
            for x in r.headers.get("access-control-allow-headers", "").split(",")
            if x.strip()
        }
        exposed = {
            x.strip().lower()
            for x in r.headers.get("access-control-expose-headers", "").split(",")
            if x.strip()
        }
        if methods & BROAD_METHODS or "*" in methods:
            findings.append(
                Finding(
                    "CORS-005",
                    "Broad preflight methods",
                    Severity.LOW,
                    "Medium",
                    r.endpoint,
                    r.method,
                    r.origin,
                    r.cors_headers,
                    "Only required cross-origin methods should be enabled.",
                    f"Allowed methods: {', '.join(sorted(methods))}",
                    "Potentially state-changing methods are advertised; this alone does not prove authorization bypass.",
                    "A trusted origin may issue these methods, subject to credentials and server authorization.",
                    "Restrict methods and enforce server-side authorization.",
                    [],
                    20,
                )
            )
        if "*" in headers:
            findings.append(
                Finding(
                    "CORS-006",
                    "Wildcard allowed request headers",
                    Severity.LOW,
                    "High",
                    r.endpoint,
                    r.method,
                    r.origin,
                    r.cors_headers,
                    "Allow only request headers needed by the application.",
                    "Access-Control-Allow-Headers: *",
                    "Any non-credentialed request header is allowed by policy.",
                    "Broadens cross-origin request capability but does not bypass authentication by itself.",
                    "Use a minimal explicit header allowlist.",
                    [],
                    15,
                )
            )
        risky = exposed & DANGEROUS_EXPOSED
        if risky:
            findings.append(
                Finding(
                    "CORS-007",
                    "Sensitive response headers exposed",
                    Severity.MEDIUM,
                    "Medium",
                    r.endpoint,
                    r.method,
                    r.origin,
                    r.cors_headers,
                    "Security tokens should not be exposed to cross-origin scripts.",
                    f"Exposed: {', '.join(sorted(risky))}",
                    "Names associated with security credentials are exposed.",
                    "A permitted origin could read these headers if they contain sensitive values.",
                    "Remove sensitive names from Access-Control-Expose-Headers.",
                    [],
                    40,
                )
            )
    unique = {}
    for f in findings:
        unique[(f.finding_id, f.endpoint)] = f
    return list(unique.values())
