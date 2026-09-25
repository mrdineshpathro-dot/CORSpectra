import pytest

from corspectra.utils.helpers import deduplicate, generate_origins, normalize_origin, normalize_url


def test_url_normalization():
    assert normalize_url("HTTPS://Example.COM:443/a#x") == "https://example.com/a"
    assert normalize_url("/api", "https://Example.com/base") == "https://example.com/api"


def test_origin_normalization():
    assert normalize_origin("HTTPS://Example.COM:443") == "https://example.com"
    assert normalize_origin("https://example.com.") == "https://example.com"
    assert normalize_origin("null") == "null"
    with pytest.raises(ValueError):
        normalize_origin("javascript:alert(1)")


def test_origin_generation_and_deduplication():
    origins = generate_origins("https://example.com")
    assert "https://example.com.attacker.example" in origins
    assert "null" in origins
    assert deduplicate(["a", "b", "a"]) == ["a", "b"]
