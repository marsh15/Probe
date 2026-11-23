"""The console view of a finished scan, and the exit code it implies.

Every string that came from the server is passed through ``sanitize_console`` so a hostile server
cannot move the cursor, recolor the screen or fake output.
"""

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from probe.engine.outcomes import Family, Severity, Status
from probe.report.json_out import status_counts
from probe.report.models import ScanReport
from probe.util.sanitize_console import sanitize_console

FAIL_ON = ("critical", "high", "medium", "low", "none")
_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE, EXIT_UNAVAILABLE, EXIT_INTERNAL = 0, 1, 2, 3, 4


def exit_code_for(report: ScanReport, fail_on: str) -> int:
    """0 if nothing at or above ``fail_on`` was found, 1 if something was, 3 if no target."""
    if report.scan.status == "target_unavailable":
        return EXIT_UNAVAILABLE
    if fail_on == "none":
        return EXIT_OK
    threshold = _RANK[Severity(fail_on)]
    return (
        EXIT_THRESHOLD if any(_RANK[f.severity] >= threshold for f in report.findings) else EXIT_OK
    )


def _clean(text: object) -> str:
    """Server-controlled text made safe to print: no control codes, and no Rich markup."""
    return escape(sanitize_console(str(text)))


def render_summary(
    report: ScanReport, console: Console, *, verbose: int = 0, quiet: bool = False
) -> None:
    target = report.target
    era = target.era
    console.print(
        f"[bold]{_clean(target.name)}[/bold] over {target.transport.value}; "
        f"era {era.kind or 'unknown'}"
        + (f" ({era.negotiated_version})" if era.negotiated_version else "")
        + f"; mode {report.scan.mode}; {report.scan.duration_ms / 1000:.1f} s",
        highlight=False,
    )
    if report.scan.status == "target_unavailable":
        for note in report.limitations:
            console.print(f"[red]{_clean(note)}[/red]", highlight=False)
        return
    counts = status_counts(report.results)
    table = Table("family", "pass", "fail", "n/a", "skipped", "error", box=None)
    for family in Family:
        c = counts[family]
        if not sum(c.values()):
            continue
        table.add_row(
            family.value,
            str(c[Status.PASS]),
            f"[red]{c[Status.FAIL]}[/red]" if c[Status.FAIL] else "0",
            str(c[Status.NA]),
            str(c[Status.SKIPPED]),
            f"[yellow]{c[Status.ERROR]}[/yellow]" if c[Status.ERROR] else "0",
        )
    console.print(table)
    if verbose:
        for row in report.results:
            console.print(
                f"  {row.status.value:<15} {row.check_id}"
                + (f"  ({_clean(row.reason)})" if row.reason else ""),
                highlight=False,
            )
    if quiet:
        return
    shown = [f for f in report.findings if f.severity is not Severity.INFO or verbose]
    for finding in sorted(shown, key=lambda f: (-_RANK[f.severity], f.check_id, f.finding_id)):
        where = f" ({_clean(finding.tool)})" if finding.tool else ""
        console.print(
            f"[{_STYLE[finding.severity]}]{finding.severity.value:<8}[/] "
            f"{finding.check_id}{where}: {_clean(finding.message)}",
            highlight=False,
        )
    errors = [r for r in report.results if r.status is Status.ERROR]
    for row in errors:
        console.print(
            f"[yellow]error[/yellow]    {row.check_id}: {_clean(row.reason)}", highlight=False
        )
