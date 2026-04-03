"""Colored CLI output using rich."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

RISK_COLORS = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}

RISK_BARS = {
    "LOW": "[green]###-------[/]",
    "MEDIUM": "[yellow]#####-----[/]",
    "HIGH": "[red]########--[/]",
    "CRITICAL": "[bold red]##########[/]",
}


def print_header():
    console.print(Panel.fit(
        "[bold cyan]ThreatLens[/] — AI-Powered File Threat Analyzer",
        border_style="cyan",
    ))


def print_file_info(analysis):
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()

    table.add_row("File", analysis.file_name)
    table.add_row("Size", f"{analysis.file_size:,} bytes ({analysis.file_size // 1024} KB)")
    table.add_row("Type", analysis.file_type or analysis.detected_type)
    table.add_row("MD5", analysis.md5)
    table.add_row("SHA256", analysis.sha256)
    table.add_row("Entropy", f"{analysis.entropy} ({analysis.entropy_verdict})")

    console.print(table)


def print_risk(score):
    color = RISK_COLORS.get(score.level, "white")
    bar = RISK_BARS.get(score.level, "")

    console.print()
    console.print(Panel(
        f"  RISK: {bar}  [{color}]{score.level}[/]  ({score.score}/100)\n\n"
        f"  {score.summary}",
        title="Threat Assessment",
        border_style=color,
    ))


def print_findings(findings: list):
    if not findings:
        console.print("\n  [green]No suspicious findings.[/]")
        return

    console.print("\n[bold]Findings:[/]")
    for f in findings:
        if any(tag in f.lower() for tag in ["injection", "keylogger", "password", "stealer", "critical"]):
            icon = "[red]!![/]"
        elif any(tag in f.lower() for tag in ["network", "persistence", "obfuscation", "packed"]):
            icon = "[yellow]![/]"
        else:
            icon = "[dim]-[/]"
        console.print(f"  {icon} {f}")


def print_ai_explanation(explanation: str):
    console.print()
    console.print(Panel(
        explanation,
        title="[bold cyan]AI Explanation[/]",
        border_style="cyan",
        padding=(1, 2),
    ))


def print_recommendations(recommendations: list):
    if not recommendations:
        return
    console.print("\n[bold]Recommendations:[/]")
    for r in recommendations:
        console.print(f"  [bold]>[/] {r}")


def print_pe_info(pe):
    if not pe.is_pe:
        return
    table = Table(title="PE Analysis", box=box.ROUNDED)
    table.add_column("Property")
    table.add_column("Value")
    table.add_row("Architecture", pe.machine)
    table.add_row("DLL", str(pe.is_dll))
    table.add_row("Compiled", pe.timestamp)
    table.add_row("Signed", "[green]Yes[/]" if pe.has_signature else "[red]No[/]")
    table.add_row("Packed", f"[red]{pe.detected_packer}[/]" if pe.is_packed else "[green]No[/]")
    table.add_row("Imports", str(pe.total_imports))
    table.add_row("Suspicious imports", str(len(pe.suspicious_imports)))
    console.print(table)
