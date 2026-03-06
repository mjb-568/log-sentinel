"""Rich terminal reporter."""

from typing import List, Optional

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import AnalysisResult, EventType, SecurityEvent, Severity

console = Console(highlight=False)

_SEVERITY_STYLE = {
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}

_EVENT_ICONS = {
    EventType.FAILED_LOGIN: "🔑",
    EventType.BRUTE_FORCE: "🚨",
    EventType.ROOT_LOGIN: "👑",
    EventType.PRIVILEGE_ESCALATION: "⬆️",
    EventType.SUDO_COMMAND: "⚡",
    EventType.SUDO_FAILURE: "🚫",
    EventType.SU_FAILURE: "🚫",
    EventType.ACCOUNT_CREATED: "👤",
    EventType.GROUP_MODIFIED: "👥",
    EventType.SUSPICIOUS_AGENT: "🤖",
    EventType.DIRECTORY_TRAVERSAL: "📂",
    EventType.SQL_INJECTION: "💉",
    EventType.XSS_ATTEMPT: "📜",
    EventType.SCANNER_DETECTED: "🔍",
    EventType.LOG_CLEARED: "🗑️",
    EventType.SCHEDULED_TASK: "📅",
    EventType.SERVICE_INSTALLED: "⚙️",
    EventType.SPECIAL_PRIVILEGES: "🔓",
    EventType.EXPLICIT_CREDENTIALS: "🔐",
}


def _icon(event: SecurityEvent) -> str:
    return _EVENT_ICONS.get(event.event_type, "•")


def print_summary(result: AnalysisResult) -> None:
    by_sev = result.by_severity

    stats = Table.grid(padding=(0, 2))
    stats.add_column()
    stats.add_column()
    stats.add_row("[bold]File:[/bold]", result.log_file)
    stats.add_row("[bold]Format:[/bold]", result.log_type)
    stats.add_row("[bold]Lines parsed:[/bold]", str(result.total_lines))
    stats.add_row("[bold]Events found:[/bold]", str(len(result.events)))

    sev_text = Text()
    for sev in reversed(list(Severity)):
        count = len(by_sev[sev.value])
        if count:
            sev_text.append(f"  {sev.value.upper()}: {count}", style=_SEVERITY_STYLE[sev])
    if sev_text:
        stats.add_row("[bold]By severity:[/bold]", sev_text)

    console.print(Panel(stats, title="[bold blue]Log Sentinel[/bold blue]", border_style="blue"))


def print_events(events: List[SecurityEvent], max_raw: int = 120) -> None:
    if not events:
        console.print("[green]No security events detected.[/green]")
        return

    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        show_lines=True,
        expand=True,
    )
    table.add_column("#", style="dim", width=5, no_wrap=True)
    table.add_column("Timestamp", width=19, no_wrap=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Type", width=22, no_wrap=True)
    table.add_column("User", width=14, no_wrap=True)
    table.add_column("Source IP", width=16, no_wrap=True)
    table.add_column("Description")

    for idx, ev in enumerate(events, 1):
        sev_style = _SEVERITY_STYLE[ev.severity]
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "—"
        icon = _icon(ev)
        table.add_row(
            str(idx),
            ts,
            Text(ev.severity.value.upper(), style=sev_style),
            f"{icon} {ev.event_type.label}",
            ev.user or "—",
            ev.source_ip or "—",
            ev.description,
        )

    console.print(table)


def print_brute_force_summary(result: AnalysisResult) -> None:
    from collections import defaultdict

    bf_events = [e for e in result.events if e.event_type == EventType.BRUTE_FORCE]
    if not bf_events:
        return

    console.print("\n[bold red]Brute-Force Summary[/bold red]")
    ip_map: dict = defaultdict(list)
    for ev in bf_events:
        ip_map[ev.source_ip or "unknown"].append(ev)

    for ip, evs in ip_map.items():
        latest = evs[-1]
        count = latest.details.get("failure_count", "?")
        users = latest.details.get("users_tried", [])
        console.print(
            f"  [bold red]{ip}[/bold red]  —  {count} failures  "
            f"users tried: {', '.join(str(u) for u in users) or '—'}"
        )


def print_report(result: AnalysisResult, verbose: bool = False) -> None:
    print_summary(result)
    if result.events:
        print_events(result.events)
        print_brute_force_summary(result)
    if result.errors:
        console.print(f"\n[yellow]Parse warnings ({len(result.errors)}):[/yellow]")
        for err in result.errors[:10]:
            console.print(f"  [dim]{err}[/dim]")
