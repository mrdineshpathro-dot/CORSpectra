"""Static URL extraction from JavaScript source; scripts are never executed."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..utils.helpers import deduplicate

_PATTERNS = [
    re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"),
    re.compile(r"[\"'](/(?:api(?:/v\d+)?|graphql)/?[A-Za-z0-9._~/?#=&%-]*)[\"']"),
]


def extract_javascript_urls(source: str, base_url: str) -> list[str]:
    found = []
    for pattern in _PATTERNS:
        for match in pattern.finditer(source):
            value = match.group(1) if match.lastindex else match.group(0)
            found.append(urljoin(base_url, value.rstrip("'\"),;")))
    return deduplicate(found)
