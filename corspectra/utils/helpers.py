"""URL, origin, and collection helpers."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit


def normalize_url(url: str, base: str | None = None) -> str:
    url = urljoin(base, url) if base else url.strip()
    parts = urlsplit(url)
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
    ):
        raise ValueError(f"Invalid HTTP(S) URL: {url}")
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    default = (parts.scheme.lower() == "http" and port == 80) or (
        parts.scheme.lower() == "https" and port == 443
    )
    netloc = host if not port or default else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def normalize_origin(origin: str) -> str:
    if origin == "null":
        return origin
    parts = urlsplit(origin.strip())
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError(f"Invalid origin: {origin}")
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    default = (parts.scheme.lower() == "http" and port == 80) or (
        parts.scheme.lower() == "https" and port == 443
    )
    return f"{parts.scheme.lower()}://{host}" + (f":{port}" if port and not default else "")


def same_site(url: str, root: str) -> bool:
    a, b = urlsplit(url), urlsplit(root)
    return (a.hostname or "").lower() == (b.hostname or "").lower()


def deduplicate(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def origin_for(url: str) -> str:
    p = urlsplit(normalize_url(url))
    return f"{p.scheme}://{p.netloc}"


def generate_origins(target: str) -> list[str]:
    p = urlsplit(normalize_url(target))
    host = p.hostname or "target.invalid"
    scheme = p.scheme
    other = "http" if scheme == "https" else "https"
    candidates = [
        f"{scheme}://{host}",
        "https://evil.example",
        "https://attacker.example",
        "null",
        f"{other}://{host}",
        f"{scheme}://www.{host}",
        f"{scheme}://sub.{host}",
        f"{scheme}://{host}.attacker.example",
        f"{scheme}://attacker-{host}",
        f"{scheme}://{host}.",
        f"{scheme.upper()}://{host.upper()}",
        f"{scheme}://{host}:8443",
    ]
    return deduplicate(candidates)
