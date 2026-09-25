"""Secret-safe logging utilities."""

import re

SENSITIVE = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "api-key"}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        k: ("<redacted>" if k.lower() in SENSITIVE else redact_text(v)) for k, v in headers.items()
    }


def redact_text(value: str) -> str:
    return re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer <redacted>", value)
