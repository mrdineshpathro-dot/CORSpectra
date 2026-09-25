<div align="center">

# ◈ CORSpectra

### Advanced CORS Configuration Analyzer

**Accurate · Evidence-driven · Asynchronous · Defensive**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-36d7e8)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-7f5af0)](#)

</div>

CORSpectra is a production-oriented CORS auditing CLI for security researchers, penetration testers, bug bounty hunters, application security engineers, and developers. It correlates actual and preflight behavior across carefully generated origins and explains evidence without equating every permissive header with exploitation.

> [!IMPORTANT]
> Use CORSpectra only against systems you own or have explicit permission to test. Safe defaults, bounded crawling, and rate limiting do not replace authorization.

## Highlights

- Asynchronous pooled HTTP engine with retries, TLS controls, proxies, redirects, concurrency, and rate limiting
- Wildcard, arbitrary reflection, `null`, credentials, methods, headers, exposed-header, and actual/preflight analysis
- Context-aware severity scoring using credentials, endpoint sensitivity, sharing behavior, and response context
- Exact, scheme, port, subdomain, suffix, prefix, and trailing-dot origin probes
- Response fingerprints: status, CORS headers, type, length, SHA-256 body hash, redirect, and timing
- Bounded same-host crawler, sitemap and robots discovery, static JavaScript URL extraction
- Multi-target operation, live Rich dashboard, origin/preflight matrix, and secret-safe logs
- Standalone HTML, JSON, CSV, and Markdown reports
- YAML configuration, typed importable API, and analyzer plugin entry-point namespace

## Installation on Kali Linux

```bash
git clone https://github.com/mrdineshpathro-dot/CORSpectra.git
cd CORSpectra

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .

python3 -m corspectra --help
```

Or install the command in an isolated environment:

```bash
pipx install .
corspectra --version
```

Python 3.11 or newer is required.

## Usage

```bash
corspectra https://example.com
corspectra -u https://api.example.com --deep
corspectra -u https://example.com --headers --preflight
corspectra -u https://example.com --origins origins.txt
corspectra -u https://example.com --crawl --depth 2 --max-pages 40
corspectra -u https://example.com --deep --crawl --preflight
corspectra -l urls.txt --threads 15 --rate-limit 8
corspectra -u https://example.com --header 'Authorization: Bearer TOKEN'
corspectra -u https://example.com -o report.html
corspectra -u https://example.com --json > result.json
```

Run `corspectra --help` for organized target, scan, CORS, discovery, network, output, display, and advanced options. TLS verification is enabled by default; `--no-verify-ssl` exists for authorized testing of known development systems.

### Custom inputs

`urls.txt` and origin files accept one value per line. Blank lines and lines beginning with `#` are ignored.

```text
https://api.example.test
https://portal.example.test/api/profile
```

Custom request headers are repeatable. Authorization and cookie values are redacted in logs; reports may still contain response evidence, so handle them as sensitive artifacts.

## How findings are classified

CORSpectra reports standard severity levels and a plain-language interpretation:

| Severity | Interpretation | Typical meaning |
|---|---|---|
| INFO | Informational / Safe context | Intentional public sharing or observations with little standalone risk |
| LOW | Suspicious | Broad behavior worth review, without strong impact evidence |
| MEDIUM | Potentially misconfigured | Multiple meaningful policy signals or inconsistent enforcement |
| HIGH | High risk | Arbitrary access plus credentials or sensitive endpoint context |
| CRITICAL | High risk | Strong, correlated high-impact signals; manual validation still required |

The score is transparent and additive. For example, arbitrary reflection contributes 35 points, credentials 30, sensitive endpoint context 20, and `null` acceptance 20. Browser-rejected `ACAO: *` plus credentials is reported as malformed configuration—not falsely claimed as an exploitable browser read.

### Example finding

```text
CORS-001 — Arbitrary origin reflection detected
Severity   : HIGH
Confidence : High
Endpoint   : https://target.test/api/profile
Origin     : https://evil.example
Evidence   : Access-Control-Allow-Origin: https://evil.example
Reason     : arbitrary origin accepted; credentials enabled; endpoint appears sensitive
```

A finding proves only the behavior shown in its evidence. Authentication, response sensitivity, browser rules, and application state must be validated before reporting a vulnerability.

## Reports

```bash
corspectra -u https://example.com -o results.json
corspectra -u https://example.com -o results.csv
corspectra -u https://example.com -o report.md
corspectra -u https://example.com -o report.html
corspectra -u https://example.com --format html -o audit.output
```

HTML output is a self-contained dark security report with an executive summary, severity overview, endpoint statistics, evidence, impact, and remediation. JSON preserves complete response fingerprints and structured finding fields for automation.

## Configuration

Default path: `~/.config/corspectra/config.yaml`

```yaml
timeout: 10
threads: 10
retries: 2
rate_limit: 10
user_agent: "CORSpectra/1.0.0 (authorized security audit)"
follow_redirects: false
verify_ssl: true
crawl: false
crawl_depth: 1
max_pages: 50
origins: []
headers: {}
proxy: null
output_directory: reports
```

CLI values override configuration. Unknown keys and unsafe bounds fail with a friendly configuration error.

## Python API

```python
from corspectra import CorsScanner

scanner = CorsScanner("https://example.com", deep=True, preflight=True)
result = scanner.scan()
for finding in result.findings:
    print(finding.severity.name, finding.title, finding.evidence)
```

Inside an existing event loop, use `await scanner.scan_async()`.

## Architecture

```text
corspectra/
├── analyzers/      # origin, credentials, headers, severity, preflight
├── discovery/      # crawler, sitemap/robots, static JS extraction
├── reporting/      # JSON, CSV, Markdown, standalone HTML
├── utils/          # URL normalization, logging, secret redaction
├── plugins/        # corspectra.analyzers entry-point loader
├── http_client.py  # async transport, retry, pacing, pooling
├── scanner.py      # scan orchestration and Python API
├── models.py       # typed records, findings, and scan results
└── cli.py          # Rich terminal experience and multi-target mode
```

Third-party analyzer packages can register callables in the `corspectra.analyzers` Python entry-point group. Core analyzers remain deterministic and independently testable.

## Testing and quality

Tests never contact third-party sites.

```bash
pip install -e '.[dev]'
pytest -q
ruff check corspectra tests
```

Coverage includes URL/origin normalization, deduplication, wildcard/reflection/credential/header/preflight decisions, severity calculation, configuration validation, discovery parsers, report generation, and mocked scanner transport.

## Screenshots

> Terminal dashboard, finding table, preflight matrix, and HTML report screenshots will be published under `docs/screenshots/`.

## Roadmap

- Cookie and security-header analyzer plugins
- CSRF and cache-policy correlation
- OpenAPI endpoint ingestion
- Optional authenticated browser confirmation workflow
- SARIF output and CI policy gates

## Responsible disclosure

Keep concurrency and request rates appropriate for the target. Honor written scope restrictions, avoid collecting unnecessary personal data, and manually validate evidence before disclosure. CORSpectra contains no destructive actions and does not execute discovered JavaScript.

## Author

Created by **Mr Dinesh Pathro**  
Support development: [buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro)

## License

[MIT](LICENSE)
