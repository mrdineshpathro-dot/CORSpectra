from __future__ import annotations

from ..models import Finding, ResponseRecord, Severity


def analyze_credentials(records: list[ResponseRecord]) -> list[Finding]:
    output = []
    for r in records:
        acao = r.headers.get("access-control-allow-origin", "").strip()
        cred = r.headers.get("access-control-allow-credentials", "").lower() == "true"
        if cred and acao == "*":
            output.append(
                Finding(
                    "CORS-004",
                    "Credentialed wildcard configuration",
                    Severity.MEDIUM,
                    "High",
                    r.endpoint,
                    r.method,
                    r.origin,
                    r.cors_headers,
                    "Credentialed sharing must name an explicit trusted origin.",
                    "ACAO: *; ACAC: true",
                    "Browsers reject this combination, indicating a malformed and misleading policy.",
                    "Current browsers block credentialed wildcard reads, but configuration drift or non-browser clients may create risk.",
                    "Return an allowlisted origin and Vary: Origin, or disable credentials.",
                    [
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials"
                    ],
                    45,
                )
            )
            break
    return output
