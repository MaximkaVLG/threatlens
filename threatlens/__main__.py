"""ThreatLens CLI — Analyze files for threats with AI explanations.

Usage:
    python -m threatlens scan <file>              # Basic analysis
    python -m threatlens scan <file> --ai          # With YandexGPT explanation
    python -m threatlens scan <dir> --recursive    # Scan directory
"""

import os
import sys
import argparse
import logging
import json

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("threatlens")


def scan_file(file_path: str, use_ai: bool = False, format: str = "text"):
    """Analyze a single file."""
    from threatlens.output.colors import (
        console, print_header, print_file_info, print_risk,
        print_findings, print_ai_explanation, print_recommendations,
        print_pe_info,
    )

    if not os.path.exists(file_path):
        console.print(f"[red]File not found: {file_path}[/]")
        return

    print_header()
    console.print(f"\n  Scanning: [bold]{file_path}[/]\n")

    # Check if archive first
    from threatlens.analyzers import archive_analyzer
    ext = os.path.splitext(file_path)[1].lower()
    if ext in archive_analyzer.ARCHIVE_EXTENSIONS or file_path.lower().endswith((".zip", ".rar", ".7z")):
        _scan_archive(file_path, use_ai, format, console)
        return

    # Single entry point — no duplication
    from threatlens.core import analyze_file
    result = analyze_file(file_path)

    # Output
    if format == "json":
        output = {
            "file": result.file,
            "size": result.size,
            "type": result.file_type,
            "md5": result.md5,
            "sha256": result.sha256,
            "entropy": result.entropy,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "findings": result.findings,
            "recommendations": result.recommendations,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    # Text output
    print_file_info(result.generic_analysis)

    if result.pe_analysis and result.pe_analysis.is_pe:
        print_pe_info(result.pe_analysis)

    from threatlens.scoring.threat_scorer import ThreatScore
    score = ThreatScore(score=result.risk_score, level=result.risk_level, summary=result.summary)
    print_risk(score)
    print_findings(result.findings)

    # Built-in explanation (computed in core.py from real categories)
    if result.explanation:
        print_ai_explanation(result.explanation)

    # Optional: LLM explanation for deeper analysis
    if use_ai:
        console.print("\n  [dim]Generating advanced AI explanation (YandexGPT)...[/]")
        from threatlens.ai.providers import get_provider
        from threatlens.ai.prompts import THREAT_EXPLANATION_PROMPT

        provider = get_provider()
        prompt = THREAT_EXPLANATION_PROMPT.format(
            findings="\n".join(f"- {f}" for f in result.findings) or "No findings",
            filename=result.file,
            filetype=result.file_type,
            filesize=f"{result.size:,} bytes",
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            categories=", ".join(f for f in result.findings if f.startswith("[")) or "none",
        )
        explanation = provider.explain(prompt)
        from threatlens.output.colors import Panel
        console.print(Panel(
            explanation,
            title="[bold magenta]Advanced AI Analysis (YandexGPT)[/]",
            border_style="magenta", padding=(1, 2),
        ))

    print_recommendations(result.recommendations)
    console.print()


def _scan_archive(file_path: str, use_ai: bool, format: str, console):
    """Scan archive and show per-file results."""
    from threatlens.analyzers.archive_analyzer import analyze as analyze_archive
    from threatlens.output.colors import (
        print_header, print_ai_explanation, Panel, Table, box,
        RISK_COLORS,
    )

    print_header()
    console.print(f"\n  Scanning archive: [bold]{file_path}[/]\n")

    result = analyze_archive(file_path)

    if not result.is_archive:
        console.print("[red]  Not a valid archive file.[/]")
        return

    # Archive info
    console.print(f"  Type: {result.archive_type}")
    console.print(f"  Files: {result.total_files}")
    console.print(f"  Uncompressed: {result.total_size_uncompressed // 1024} KB")
    if result.is_password_protected:
        console.print("[yellow]  Password protected — cannot analyze contents[/]")
        return

    console.print()

    # Summary
    n_dangerous = len(result.dangerous_files)
    n_suspicious = len(result.suspicious_files)
    n_safe = result.total_files - n_dangerous - n_suspicious

    if n_dangerous > 0:
        console.print(Panel(
            f"  [bold red]FOUND {n_dangerous} DANGEROUS FILE(S)[/]\n"
            f"  [yellow]{n_suspicious} suspicious[/] | [green]{n_safe} safe[/]",
            title="Archive Scan Result",
            border_style="red",
        ))
    elif n_suspicious > 0:
        console.print(Panel(
            f"  [yellow]{n_suspicious} suspicious file(s)[/] | [green]{n_safe} safe[/]",
            title="Archive Scan Result",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            f"  [green]All {n_safe} files appear safe[/]",
            title="Archive Scan Result",
            border_style="green",
        ))

    # Per-file results table
    if result.file_scan_results:
        table = Table(title="File Analysis", box=box.ROUNDED)
        table.add_column("File", style="bold", max_width=40)
        table.add_column("Type", max_width=15)
        table.add_column("Risk", justify="center")
        table.add_column("Score", justify="center")
        table.add_column("Key Findings", max_width=50)

        for scan in sorted(result.file_scan_results, key=lambda x: x["risk_score"], reverse=True):
            level = scan["risk_level"]
            color = RISK_COLORS.get(level, "white")
            findings_str = "; ".join(scan["findings"][:2]) if scan["findings"] else "No issues"
            if len(findings_str) > 50:
                findings_str = findings_str[:47] + "..."

            table.add_row(
                scan["file"],
                scan["type"][:15] if scan["type"] else "?",
                f"[{color}]{level}[/]",
                f"[{color}]{scan['risk_score']}[/]",
                findings_str,
            )

        console.print(table)

    # Detailed findings for dangerous files
    for finfo in result.dangerous_files:
        scan = finfo.scan_result
        if not scan:
            continue

        console.print(f"\n[bold red]--- {scan['file']} ---[/]")
        console.print(f"  Risk: [{RISK_COLORS.get(scan['risk_level'], 'white')}]{scan['risk_level']} ({scan['risk_score']}/100)[/]")

        for f in scan["findings"]:
            console.print(f"  [red]![/] {f}")

        if scan.get("explanation"):
            print_ai_explanation(scan["explanation"])

        if scan.get("recommendations"):
            console.print("[bold]  Recommendations:[/]")
            for r in scan["recommendations"]:
                console.print(f"    > {r}")

    console.print()


def scan_directory(dir_path: str, **kwargs):
    """Scan all files in a directory."""
    from threatlens.output.colors import console

    if not os.path.isdir(dir_path):
        console.print(f"[red]Not a directory: {dir_path}[/]")
        return

    files = []
    for root, dirs, filenames in os.walk(dir_path):
        for f in filenames:
            files.append(os.path.join(root, f))

    console.print(f"\n  Found {len(files)} files in {dir_path}\n")

    for f in files:
        try:
            scan_file(f, **kwargs)
        except Exception as e:
            console.print(f"  [red]Error scanning {f}: {e}[/]")


def _scan_repo(url: str):
    """Scan a GitHub repository."""
    from threatlens.analyzers.repo_analyzer import analyze as analyze_repo
    from threatlens.output.colors import (
        console, print_header, print_ai_explanation, Panel, Table, box,
        RISK_COLORS,
    )

    print_header()
    console.print(f"\n  Scanning repository: [bold cyan]{url}[/]\n")
    console.print("  [dim]Cloning repository...[/]")

    result = analyze_repo(url)

    if not result.scanned_files:
        console.print("[red]  Failed to clone or scan repository.[/]")
        for f in result.findings:
            console.print(f"  [red]{f}[/]")
        return

    # Summary
    console.print(f"\n  Repository: [bold]{result.repo_name}[/]")
    console.print(f"  Total files: {result.total_files}")
    console.print(f"  Scanned: {result.scanned_files}")
    console.print(f"  Skipped: {result.skipped_files} (images, binaries, etc.)")
    console.print()

    n_dangerous = len(result.dangerous_files)
    n_suspicious = len(result.suspicious_files)

    if n_dangerous > 0:
        console.print(Panel(
            f"  [bold red]FOUND {n_dangerous} DANGEROUS FILE(S)[/]\n"
            f"  [yellow]{n_suspicious} suspicious[/] | [green]{result.safe_files} safe[/]",
            title="Repository Scan Result",
            border_style="red",
        ))
    elif n_suspicious > 0:
        console.print(Panel(
            f"  [yellow]{n_suspicious} suspicious file(s)[/] | [green]{result.safe_files} safe[/]",
            title="Repository Scan Result",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            f"  [green]All {result.safe_files} files appear safe[/]",
            title="Repository Scan Result",
            border_style="green",
        ))

    # Results table (show dangerous + suspicious)
    show_files = result.dangerous_files + result.suspicious_files
    if show_files:
        table = Table(title="Flagged Files", box=box.ROUNDED)
        table.add_column("File", style="bold", max_width=50)
        table.add_column("Risk", justify="center")
        table.add_column("Score", justify="center")
        table.add_column("Key Findings", max_width=45)

        for fr in sorted(show_files, key=lambda x: x.risk_score, reverse=True):
            color = RISK_COLORS.get(fr.risk_level, "white")
            findings_str = "; ".join(fr.findings[:2]) if fr.findings else ""
            if len(findings_str) > 45:
                findings_str = findings_str[:42] + "..."
            table.add_row(
                fr.path,
                f"[{color}]{fr.risk_level}[/]",
                f"[{color}]{fr.risk_score}[/]",
                findings_str,
            )

        console.print(table)

    # Detailed findings for dangerous files
    for fr in result.dangerous_files[:10]:
        console.print(f"\n[bold red]--- {fr.path} ---[/]")
        color = RISK_COLORS.get(fr.risk_level, "white")
        console.print(f"  Risk: [{color}]{fr.risk_level} ({fr.risk_score}/100)[/]")

        for f in fr.findings[:10]:
            console.print(f"  [red]![/] {f}")

        if fr.explanation:
            print_ai_explanation(fr.explanation)

    console.print()


def _lookup_hash(hash_str: str):
    """Look up a previously scanned file by SHA256."""
    from threatlens.cache import get_cache
    from threatlens.output.colors import console, print_header, RISK_COLORS

    print_header()
    cache = get_cache()

    # Try exact match first
    result = cache.get(hash_str)
    if result:
        color = RISK_COLORS.get(result["risk_level"], "white")
        console.print(f"\n  [green]Found in cache![/] (scanned {result['scan_count']} times)\n")
        console.print(f"  File:    {result['file']}")
        console.print(f"  SHA256:  {result['sha256']}")
        console.print(f"  Size:    {result['size']:,} bytes")
        console.print(f"  Type:    {result['type']}")
        console.print(f"  Risk:    [{color}]{result['risk_level']} ({result['risk_score']}/100)[/]")
        if result.get("heuristic_type"):
            console.print(f"  Threat:  {result['heuristic_type']} ({result['heuristic_confidence']:.0%})")
        console.print(f"\n  Findings ({len(result['findings'])}):")
        for f in result["findings"][:10]:
            console.print(f"    ! {f}")
        if result.get("explanation"):
            console.print(f"\n  {result['explanation'][:200]}")
        return

    # Try prefix search
    results = cache.search(hash_str)
    if results:
        console.print(f"\n  Found {len(results)} matches for prefix '{hash_str}':\n")
        for r in results:
            console.print(f"  {r['sha256'][:16]}...  {r['file_name']:30s}  {r['risk_level']:8s}  score={r['risk_score']}")
    else:
        console.print(f"\n  [yellow]Not found in cache: {hash_str}[/]")
        console.print("  Scan a file first: threatlens scan <file>")
    console.print()


def _show_stats():
    """Show cache statistics."""
    from threatlens.cache import get_cache
    from threatlens.output.colors import console, print_header

    print_header()
    stats = get_cache().get_stats()

    console.print(f"\n  Cache Statistics:")
    console.print(f"  Total unique files: {stats['total_files']}")
    console.print(f"  Total scans:        {stats['total_scans']}")
    console.print(f"  Cache hits:         {stats['cache_hits']}")
    console.print(f"\n  By risk level:")
    for level, count in stats.get("by_risk_level", {}).items():
        console.print(f"    {level}: {count}")
    console.print()


def main():
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens — AI-Powered File Threat Analyzer",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("target", help="File or directory to scan")
    scan_p.add_argument("--ai", action="store_true", help="Enable YandexGPT explanation")
    scan_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    scan_p.add_argument("--recursive", action="store_true", help="Scan directory recursively")

    repo_p = subparsers.add_parser("repo", help="Scan a GitHub repository")
    repo_p.add_argument("url", help="GitHub repository URL")

    lookup_p = subparsers.add_parser("lookup", help="Look up a file by SHA256 hash in cache")
    lookup_p.add_argument("hash", help="SHA256 hash (full or prefix)")

    stats_p = subparsers.add_parser("stats", help="Show cache statistics")

    args = parser.parse_args()

    if args.command == "scan":
        if args.recursive or os.path.isdir(args.target):
            scan_directory(args.target, use_ai=args.ai, format=args.format)
        else:
            scan_file(args.target, use_ai=args.ai, format=args.format)
    elif args.command == "repo":
        _scan_repo(args.url)
    elif args.command == "lookup":
        _lookup_hash(args.hash)
    elif args.command == "stats":
        _show_stats()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
