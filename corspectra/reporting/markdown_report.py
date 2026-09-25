from pathlib import Path

from ..models import ScanResult, Severity


def render_markdown(results: list[ScanResult] | ScanResult) -> str:
    values = results if isinstance(results, list) else [results]
    findings = [(r, f) for r in values for f in r.findings]
    counts = {s.name: sum(f.severity == s for _, f in findings) for s in Severity}
    lines = [
        "# CORSpectra Security Report",
        "",
        "> CORS Configuration Analyzer — v1.0.0",
        "> Author: Mr Dinesh Pathro",
        "",
        "## Executive summary",
        "",
        f"Scanned **{len(values)}** target(s), **{sum(len(r.endpoints) for r in values)}** endpoint(s), and made **{sum(r.statistics.requests for r in values)}** requests.",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        f"| {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} | {counts['INFO']} |",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines += [
            "No reportable CORS findings were observed. This does not prove the target is vulnerability-free.",
            "",
        ]
    for result, f in findings:
        lines += [
            f"### {f.finding_id} — {f.title}",
            "",
            f"**Severity:** {f.severity.name} · **Confidence:** {f.confidence} · **Score:** {f.score}/100",
            f"**Endpoint:** `{f.endpoint}` · **Method:** `{f.method}` · **Origin:** `{f.origin_tested or 'none'}`",
            "",
            "**Evidence**",
            "```text",
            f.evidence,
            "```",
            f"**Reason:** {f.reason}",
            "",
            f"**Impact:** {f.impact}",
            "",
            f"**Remediation:** {f.remediation}",
            "",
        ]
    lines += [
        "## Responsible use",
        "",
        "Use this tool only against systems you own or have explicit permission to test.",
        "",
        "---",
        "[Support Mr Dinesh Pathro](https://buymeacoffee.com/mrdineshpathro)",
    ]
    return "\n".join(lines) + "\n"


def write_markdown(results, path: str) -> None:
    Path(path).write_text(render_markdown(results), encoding="utf-8")
