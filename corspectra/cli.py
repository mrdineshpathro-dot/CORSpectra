"""Command-line interface for CORSpectra."""

from __future__ import annotations

import argparse
import asyncio
import io
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from . import __version__
from .banner import show_banner
from .config import Config
from .dashboard import dashboard
from .models import ScanResult, Severity
from .reporting import REPORTERS
from .scanner import CorsScanner
from .utils.helpers import deduplicate, normalize_url
from .utils.logger import configure_logging

VERSION_TEXT = f"""CORSpectra v{__version__}
CORS Configuration Analyzer
Author: Mr Dinesh Pathro
https://buymeacoffee.com/mrdineshpathro"""


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        Console(stderr=True).print(
            f"[bold red]✗ Argument error:[/] {message}\nUse [cyan]corspectra --help[/] for usage."
        )
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    p = Parser(
        prog="corspectra",
        description="Evidence-driven CORS configuration analysis for authorized security testing.",
        epilog=(
            "Use only against systems you own or have explicit permission to test.\n"
            "Author: Mr Dinesh Pathro · https://buymeacoffee.com/mrdineshpathro"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = p.add_argument_group("Target Options")
    target.add_argument("target", nargs="?", help="HTTP(S) target URL")
    target.add_argument("-u", "--url", help="HTTP(S) target URL")
    target.add_argument("-l", "--list", metavar="FILE", help="newline-delimited target URLs")
    scan = p.add_argument_group("Scanning Options")
    scan.add_argument(
        "--deep", action="store_true", help="test expanded origins and common API paths"
    )
    scan.add_argument("--preflight", action="store_true", help="send OPTIONS preflight probes")
    scan.add_argument(
        "--headers", action="store_true", help="highlight CORS response-header analysis"
    )
    scan.add_argument(
        "--threads", type=int, metavar="N", help="maximum concurrent requests (1-100)"
    )
    cors = p.add_argument_group("CORS Testing Options")
    cors.add_argument("--origins", metavar="FILE", help="custom origin list")
    cors.add_argument(
        "--methods", default="GET,POST,PUT,DELETE", help="preflight method candidates"
    )
    cors.add_argument(
        "--headers-list",
        default="Authorization,Content-Type,X-Requested-With",
        help="preflight request headers",
    )
    discover = p.add_argument_group("Discovery Options")
    discover.add_argument(
        "--crawl", action="store_true", default=None, help="enable same-host lightweight crawling"
    )
    discover.add_argument("--depth", type=int, metavar="N", help="maximum crawl depth")
    discover.add_argument("--max-pages", type=int, metavar="N", help="maximum pages to crawl")
    network = p.add_argument_group("Network Options")
    network.add_argument("--proxy", help="HTTP/SOCKS proxy URL")
    network.add_argument("--cookie", help="Cookie header (redacted from logs)")
    network.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="custom request header; repeatable",
    )
    network.add_argument("--user-agent", help="custom User-Agent")
    network.add_argument("--timeout", type=float, help="request timeout in seconds")
    network.add_argument("--retries", type=int, help="network retry count")
    network.add_argument(
        "--rate-limit", type=float, metavar="RPS", help="maximum requests per second"
    )
    network.add_argument("--delay", type=float, help="additional delay before each request")
    network.add_argument("--follow-redirects", action=argparse.BooleanOptionalAction, default=None)
    network.add_argument("--verify-ssl", action=argparse.BooleanOptionalAction, default=None)
    output = p.add_argument_group("Output Options")
    output.add_argument("-o", "--output", help="report file path")
    output.add_argument("--format", choices=REPORTERS, help="report format")
    output.add_argument("--json", action="store_true", help="emit JSON")
    output.add_argument("--csv", action="store_true", help="emit CSV")
    output.add_argument("--html", action="store_true", help="emit HTML")
    output.add_argument("--markdown", action="store_true", help="emit Markdown")
    display = p.add_argument_group("Display Options")
    display.add_argument("--no-color", action="store_true")
    display.add_argument("--quiet", action="store_true")
    display.add_argument("--verbose", action="store_true")
    display.add_argument("--debug", action="store_true")
    advanced = p.add_argument_group("Advanced Options")
    advanced.add_argument("--config", metavar="FILE", help="YAML configuration path")
    advanced.add_argument("--version", action="version", version=VERSION_TEXT)
    advanced.add_argument("--about", action="version", version=VERSION_TEXT)
    return p


def _headers(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        if ":" not in value:
            raise ValueError(f"custom header must be NAME: VALUE: {value}")
        key, item = value.split(":", 1)
        if not key.strip():
            raise ValueError("custom header name cannot be empty")
        result[key.strip()] = item.strip()
    return result


def _file_lines(path: str) -> list[str]:
    try:
        return [
            line.strip()
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def _format_from(args: argparse.Namespace) -> str | None:
    selected = [name for name in ("json", "csv", "html", "markdown") if getattr(args, name)]
    if len(selected) > 1:
        raise ValueError("choose only one format shortcut")
    if args.format and selected and args.format != selected[0]:
        raise ValueError("--format conflicts with format shortcut")
    if args.format:
        return args.format
    if selected:
        return selected[0]
    if args.output:
        return {
            ".json": "json",
            ".csv": "csv",
            ".html": "html",
            ".htm": "html",
            ".md": "markdown",
        }.get(Path(args.output).suffix.lower(), "json")
    return None


def _result_table(results: list[ScanResult]) -> Table:
    table = Table(title="Findings", border_style="cyan", header_style="bold cyan", expand=True)
    table.add_column("Assessment", width=24)
    table.add_column("ID", width=9)
    table.add_column("Finding")
    table.add_column("Endpoint")
    table.add_column("Origin")
    colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "bright_yellow",
        Severity.INFO: "blue",
    }
    classifications = {
        Severity.CRITICAL: "High Risk",
        Severity.HIGH: "High Risk",
        Severity.MEDIUM: "Potentially Misconfigured",
        Severity.LOW: "Suspicious",
        Severity.INFO: "Informational",
    }
    for result in results:
        for f in result.findings:
            table.add_row(
                f"[{colors[f.severity]}]{f.severity.name} · {classifications[f.severity]}[/]",
                f.finding_id,
                f.title,
                f.endpoint,
                f.origin_tested or "—",
            )
    if not any(r.findings for r in results):
        table.add_row("[green]SAFE*[/]", "—", "No reportable CORS policy findings", "—", "—")
    return table


def _print_finding_evidence(console: Console, results: list[ScanResult]) -> None:
    for result in results:
        for finding in result.findings:
            summary = Text()
            summary.append("Endpoint: ", style="bold cyan")
            summary.append(finding.endpoint)
            summary.append("\nOrigin: ", style="bold cyan")
            summary.append(finding.origin_tested or "none")
            summary.append("\nReason: ", style="bold cyan")
            summary.append(finding.reason)
            summary.append("\nImpact: ", style="bold cyan")
            summary.append(finding.impact)
            summary.append("\nRemediation: ", style="bold cyan")
            summary.append(finding.remediation)
            evidence = Syntax(finding.evidence, "http", word_wrap=True, background_color="default")
            console.print(
                Panel(
                    Group(summary, Text("\nEvidence", style="bold magenta"), evidence),
                    title=Text(f"{finding.finding_id} · {finding.title}"),
                    border_style="red" if finding.severity >= Severity.HIGH else "yellow",
                )
            )


def _comparison_table(results: list[ScanResult]) -> Table:
    table = Table(title="Origin Response Comparison", border_style="magenta")
    for column in ("Endpoint", "Origin", "Status", "ACAO", "Credentials", "Vary", "Body changed"):
        table.add_column(column)
    for result in results:
        baselines = {
            record.endpoint: record
            for record in result.responses
            if record.method == "GET" and record.origin is None
        }
        for record in result.responses:
            if record.method != "GET" or record.origin is None:
                continue
            baseline = baselines.get(record.endpoint)
            table.add_row(
                record.endpoint,
                record.origin,
                str(record.status_code),
                record.headers.get("access-control-allow-origin", "—"),
                record.headers.get("access-control-allow-credentials", "—"),
                record.headers.get("vary", "—"),
                "YES" if baseline and baseline.body_hash != record.body_hash else "NO",
            )
    return table


def _preflight_table(results: list[ScanResult]) -> Table:
    table = Table(title="Origin / Preflight Matrix", border_style="blue")
    table.add_column("Endpoint")
    table.add_column("Origin")
    table.add_column("GET")
    table.add_column("OPTIONS")
    for result in results:
        actual = {
            (record.endpoint, record.origin): record
            for record in result.responses
            if record.origin and record.method == "GET"
        }
        options: dict[tuple[str, str | None], list] = {}
        for record in result.responses:
            if record.origin and record.method == "OPTIONS":
                options.setdefault((record.endpoint, record.origin), []).append(record)
        state = lambda record: (
            "Allowed"
            if record and record.headers.get("access-control-allow-origin")
            else "Blocked/absent"
        )
        for (endpoint, origin), get in sorted(actual.items(), key=lambda item: item[0]):
            option_records = options.get((endpoint, origin), [])
            option_state = (
                ", ".join(
                    f"{record.requested_method or '?'}={state(record)}" for record in option_records
                )
                or "Not tested"
            )
            table.add_row(endpoint, origin or "—", state(get), option_state)
    return table


async def _run_scans(
    targets: list[str], args: argparse.Namespace, config: Config, console: Console
) -> list[ScanResult]:
    done: list[ScanResult] = []
    lock = asyncio.Lock()
    gate = asyncio.Semaphore(min(4, len(targets)))
    origins = _file_lines(args.origins) if args.origins else None
    methods = [x.strip().upper() for x in args.methods.split(",") if x.strip()]
    request_headers = [x.strip() for x in args.headers_list.split(",") if x.strip()]
    live_console = Console(file=io.StringIO()) if args.quiet else console
    live = Live(
        dashboard(done, len(targets), 0),
        console=live_console,
        refresh_per_second=6,
        transient=False,
    )
    active = 0
    active_results: dict[str, ScanResult] = {}

    def progress(result: ScanResult) -> None:
        active_results[result.target] = result
        live.update(dashboard(done + list(active_results.values()), len(targets), active))

    async def one(target: str) -> None:
        nonlocal active
        async with gate:
            active += 1
            live.update(dashboard(done, len(targets), active))
            try:
                scanner = CorsScanner(
                    target,
                    config=config,
                    deep=args.deep,
                    crawl_enabled=args.crawl,
                    preflight=args.preflight,
                    origins=origins,
                    methods=methods,
                    request_headers=request_headers,
                    cookies=args.cookie,
                    progress_callback=progress,
                )
                result = await scanner.scan_async()
            except Exception as exc:  # noqa: BLE001 - target failures must not abort a batch
                result = ScanResult(target=target, errors=[f"{type(exc).__name__}: {exc}"])
                result.finish()
                if args.debug:
                    console.print_exception()
            async with lock:
                active_results.pop(result.target, None)
                done.append(result)
            active -= 1
            live.update(dashboard(done, len(targets), active))

    with live:
        await asyncio.gather(*(one(t) for t in targets))
    return done


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(
        no_color=args.no_color,
        stderr=bool(args.format or args.json or args.csv or args.html or args.markdown),
    )
    configure_logging(args.verbose, args.debug, args.quiet)
    try:
        config = Config.load(args.config)
        config = config.merge(
            timeout=args.timeout,
            threads=args.threads,
            retries=args.retries,
            rate_limit=args.rate_limit,
            delay=args.delay,
            user_agent=args.user_agent,
            follow_redirects=args.follow_redirects,
            verify_ssl=args.verify_ssl,
            proxy=args.proxy,
            crawl_depth=args.depth,
            max_pages=args.max_pages,
            headers={**config.headers, **_headers(args.header)},
        )
        raw = []
        if args.target:
            raw.append(args.target)
        if args.url:
            raw.append(args.url)
        if args.list:
            raw.extend(_file_lines(args.list))
        if not raw:
            parser.error("provide TARGET, --url, or --list")
        targets = deduplicate([normalize_url(x) for x in raw])
        report_format = _format_from(args)
    except (TypeError, ValueError) as exc:
        console.print(f"[bold red]✗ Configuration error:[/] {exc}")
        raise SystemExit(2)
    if not args.quiet:
        show_banner(console)
        console.print(
            Panel.fit(
                f"[cyan]Targets[/]: {len(targets)}\n[cyan]Mode[/]: {'Deep CORS Analysis' if args.deep else 'Standard Analysis'}\n[cyan]Concurrency[/]: {config.threads}\n[cyan]Rate limit[/]: {config.rate_limit:g} req/s\n[dim]Authorized testing only.[/]",
                title="Scan Configuration",
                border_style="blue",
            )
        )
    try:
        results = asyncio.run(_run_scans(targets, args, config, console))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted safely by user.[/]")
        raise SystemExit(130)
    if report_format:
        render, write = REPORTERS[report_format]
        if args.output:
            try:
                Path(args.output).expanduser().parent.mkdir(parents=True, exist_ok=True)
                write(results, str(Path(args.output).expanduser()))
            except OSError as exc:
                console.print(f"[bold red]✗ Could not write report:[/] {exc}")
                raise SystemExit(1)
            if not args.quiet:
                console.print(f"[green]✓ Report written:[/] {args.output}")
        else:
            print(render(results))
    elif not args.quiet:
        console.print(_result_table(results))
        _print_finding_evidence(console, results)
        if args.headers:
            console.print(_comparison_table(results))
        if args.preflight or args.deep:
            console.print(_preflight_table(results))
        errors = sum(len(r.errors) for r in results)
        failed = sum(not result.responses for result in results)
        console.print(
            f"\n[bold green]✓ Scan complete[/] · {sum(r.statistics.requests for r in results)} probes · {sum(len(r.findings) for r in results)} findings · {errors} errors · {failed} failed targets"
        )
        console.print(
            "[dim]* No finding is not proof of security. Validate findings manually in authorized scope.[/]"
        )
    if results and all(not result.responses for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
