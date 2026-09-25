import csv
import io
from pathlib import Path

from ..models import ScanResult


def render_csv(results: list[ScanResult] | ScanResult) -> str:
    values = results if isinstance(results, list) else [results]
    stream = io.StringIO()
    fields = [
        "target",
        "finding_id",
        "title",
        "severity",
        "confidence",
        "endpoint",
        "method",
        "origin_tested",
        "score",
        "evidence",
        "reason",
        "impact",
        "remediation",
    ]
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for result in values:
        for f in result.findings:
            writer.writerow(
                {
                    "target": result.target,
                    **{
                        name: (f.severity.name if name == "severity" else getattr(f, name))
                        for name in fields[1:]
                    },
                }
            )
    return stream.getvalue()


def write_csv(results, path: str) -> None:
    Path(path).write_text(render_csv(results), encoding="utf-8", newline="")
