from __future__ import annotations

from html import escape
from pathlib import Path

from ..models import ScanResult, Severity


def render_html(results: list[ScanResult] | ScanResult) -> str:
    values = results if isinstance(results, list) else [results]
    pairs = [(r, f) for r in values for f in r.findings]
    counts = {s.name: sum(f.severity == s for _, f in pairs) for s in Severity}
    cards = "".join(
        f'<div class="card {k.lower()}"><b>{v}</b><span>{k}</span></div>'
        for k, v in reversed(counts.items())
    )
    rows = (
        "".join(
            f"<tr><td><span class='pill {f.severity.name.lower()}'>{f.severity.name}</span></td><td>{escape(f.finding_id)}</td><td>{escape(f.title)}</td><td><code>{escape(f.endpoint)}</code></td><td>{escape(f.confidence)}</td><td>{f.score}</td></tr>"
            for _, f in pairs
        )
        or "<tr><td colspan='6'>No reportable findings</td></tr>"
    )
    details = "".join(
        f"<article><h3>{escape(f.finding_id)} · {escape(f.title)}</h3><p><b>{f.severity.name}</b> · Confidence {escape(f.confidence)} · {f.score}/100</p><dl><dt>Endpoint</dt><dd><code>{escape(f.endpoint)}</code></dd><dt>Origin tested</dt><dd><code>{escape(f.origin_tested or 'none')}</code></dd><dt>Evidence</dt><dd><pre>{escape(f.evidence)}</pre></dd><dt>Reason</dt><dd>{escape(f.reason)}</dd><dt>Impact</dt><dd>{escape(f.impact)}</dd><dt>Remediation</dt><dd>{escape(f.remediation)}</dd></dl></article>"
        for _, f in pairs
    )
    targets = "".join(
        f"<li><code>{escape(r.target)}</code> — {len(r.endpoints)} endpoint(s), {r.statistics.requests} request(s), {len(r.errors)} error(s)</li>"
        for r in values
    )
    matrix_rows = (
        "".join(
            f"<tr><td><code>{escape(record.endpoint)}</code></td><td>{escape(record.origin or 'none')}</td><td>{escape(record.method)}</td><td>{escape(record.requested_method or '—')}</td><td>{record.status_code}</td><td><code>{escape(record.headers.get('access-control-allow-origin', '—'))}</code></td><td>{escape(record.headers.get('access-control-allow-credentials', '—'))}</td></tr>"
            for result in values
            for record in result.responses
            if record.origin is not None
        )
        or "<tr><td colspan='7'>No origin probes recorded</td></tr>"
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CORSpectra Security Report</title><style>
:root{{--bg:#080d16;--panel:#101827;--line:#26354d;--text:#dce8f8;--muted:#91a3ba;--cyan:#36d7e8}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,sans-serif}}main{{max-width:1180px;margin:auto;padding:40px 24px}}header{{border:1px solid var(--line);background:linear-gradient(135deg,#11233b,#101827);padding:32px;border-radius:16px}}h1{{color:var(--cyan);font-size:38px;margin:0}}h2{{margin-top:42px}}.muted,footer{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:24px 0}}.card{{padding:18px;background:var(--panel);border:1px solid var(--line);border-radius:12px;display:flex;flex-direction:column}}.card b{{font-size:28px}}table{{width:100%;border-collapse:collapse;background:var(--panel)}}th,td{{padding:13px;text-align:left;border-bottom:1px solid var(--line)}}code,pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#b6f4fa}}article{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px;margin:14px 0}}dt{{color:var(--cyan);font-weight:bold;margin-top:12px}}dd{{margin:5px 0}}.pill{{font-weight:bold}}.critical,.high{{color:#ff6685}}.medium{{color:#ffbf69}}.low{{color:#e8df7a}}.info{{color:#65c7ff}}footer{{margin-top:48px}}@media(max-width:700px){{.cards{{grid-template-columns:1fr 1fr}}table{{display:block;overflow:auto}}}}
</style></head><body><main><header><h1>CORSpectra</h1><p>CORS Configuration Analyzer · Security Report v1.0.0</p><p class="muted">Author: Mr Dinesh Pathro · Generated {escape(values[0].completed_at or values[0].started_at)}</p></header><div class="cards">{cards}</div><h2>Executive summary</h2><ul>{targets}</ul><p>Findings are evidence-based configuration observations, not claims of exploitation.</p><h2>Finding overview</h2><table><thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Endpoint</th><th>Confidence</th><th>Score</th></tr></thead><tbody>{rows}</tbody></table><h2>Origin and preflight matrix</h2><table><thead><tr><th>Endpoint</th><th>Origin</th><th>HTTP method</th><th>Requested method</th><th>Status</th><th>ACAO</th><th>Credentials</th></tr></thead><tbody>{matrix_rows}</tbody></table><h2>Evidence & recommendations</h2>{details}<footer>Authorized testing only · <a href="https://buymeacoffee.com/mrdineshpathro">Mr Dinesh Pathro</a></footer></main></body></html>"""


def write_html(results, path: str) -> None:
    Path(path).write_text(render_html(results), encoding="utf-8")
