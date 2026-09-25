"""Transparent context-aware finding score calculation."""

from __future__ import annotations

from urllib.parse import urlsplit

from ..models import ResponseRecord, Severity

SENSITIVE_WORDS = {
    "account",
    "admin",
    "auth",
    "billing",
    "me",
    "profile",
    "token",
    "user",
    "graphql",
}


def is_sensitive(response: ResponseRecord) -> bool:
    path = urlsplit(response.endpoint).path.lower()
    semantic = any(word in path.split("/") for word in SENSITIVE_WORDS)
    authenticated = response.status_code not in {401, 403} and (
        "json" in response.content_type
        or "authorization" in response.headers.get("vary", "").lower()
    )
    return semantic and authenticated


def score_policy(
    *,
    arbitrary: bool = False,
    credentials: bool = False,
    wildcard: bool = False,
    null_origin: bool = False,
    sensitive: bool = False,
    actual_sharing: bool = True,
) -> tuple[int, Severity, list[str]]:
    score = 0
    reasons: list[str] = []
    for condition, points, label in [
        (arbitrary, 35, "arbitrary origin accepted"),
        (credentials, 30, "credentials enabled"),
        (wildcard, 15, "wildcard origin"),
        (null_origin, 20, "null origin accepted"),
        (sensitive, 20, "endpoint appears sensitive"),
        (not actual_sharing, -15, "response did not enable sharing"),
    ]:
        if condition:
            score += points
            reasons.append(label)
    score = max(0, min(100, score))
    severity = (
        Severity.CRITICAL
        if score >= 90
        else Severity.HIGH
        if score >= 70
        else Severity.MEDIUM
        if score >= 40
        else Severity.LOW
        if score >= 15
        else Severity.INFO
    )
    return score, severity, reasons
