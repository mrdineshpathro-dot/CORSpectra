from rich.table import Table

from .models import ScanResult, Severity


def dashboard(results: list[ScanResult], total_targets: int, active: int = 0) -> Table:
    t = Table(title="CORSpectra Dashboard", border_style="cyan", show_header=False)
    t.add_column(style="bright_cyan")
    t.add_column(justify="right", style="bold white")
    findings = [f for r in results for f in r.findings]
    values = [
        ("Targets", f"{len(results)}/{total_targets}"),
        ("Active", str(active)),
        ("Endpoints", str(sum(len(r.endpoints) for r in results))),
        ("Requests", str(sum(r.statistics.requests for r in results))),
        ("Origins Tested", str(sum(r.statistics.origins_tested for r in results))),
        ("Findings", str(len(findings))),
        ("High / Critical", str(sum(f.severity >= Severity.HIGH for f in findings))),
        ("Medium", str(sum(f.severity == Severity.MEDIUM for f in findings))),
        ("Errors", str(sum(len(r.errors) for r in results))),
    ]
    for row in values:
        t.add_row(*row)
    return t
