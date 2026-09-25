from corspectra.discovery.javascript import extract_javascript_urls
from corspectra.discovery.sitemap import parse_robots, parse_sitemap


def test_js_extraction_no_execution():
    src = 'const api="/api/v1/users"; const x="https://external.test/graphql"; alert("no")'
    urls = extract_javascript_urls(src, "https://app.test/main.js")
    assert "https://app.test/api/v1/users" in urls
    assert "https://external.test/graphql" in urls


def test_sitemap_and_robots():
    xml = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://x.test/api</loc></url></urlset>'
    assert parse_sitemap(xml) == ["https://x.test/api"]
    refs, blocked = parse_robots(
        "Sitemap: https://x.test/map.xml\nDisallow: /private", "https://x.test"
    )
    assert refs == ["https://x.test/map.xml"] and blocked == ["https://x.test/private"]
