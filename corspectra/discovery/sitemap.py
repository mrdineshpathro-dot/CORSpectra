"""Sitemap and robots URL parsers."""

from __future__ import annotations

from urllib.parse import urljoin
from xml.etree import ElementTree

from ..utils.helpers import deduplicate


def parse_sitemap(xml: str) -> list[str]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return []
    return deduplicate(
        [
            (node.text or "").strip()
            for node in root.iter()
            if node.tag.rsplit("}", 1)[-1] == "loc" and (node.text or "").strip()
        ]
    )


def parse_robots(text: str, base_url: str) -> tuple[list[str], list[str]]:
    refs = []
    disallowed = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (x.strip() for x in line.split(":", 1))
        if key.lower() == "sitemap":
            refs.append(value)
        elif key.lower() == "disallow" and value:
            disallowed.append(urljoin(base_url, value))
    return deduplicate(refs), deduplicate(disallowed)
