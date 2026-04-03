"""ThreatLens CLI — Analyze files for threats with AI explanations.

Usage:
    python -m threatlens scan <file>              # Basic analysis
    python -m threatlens scan <file> --ai          # With AI explanation
    python -m threatlens scan <file> --ai --provider openai
    python -m threatlens scan <dir> --recursive    # Scan directory
"""

import os
import sys
import argparse
import logging
import json

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("threatlens")


def scan_file(file_path: str, use_ai: bool = False, ai_provider: str = None, format: str = "text"):
    """Analyze a single file."""
    from threatlens.analyzers import generic_analyzer, pe_analyzer, script_analyzer
    from threatlens.scoring.threat_scorer import calculate_score
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

    # Generic analysis (all files)
    generic = generic_analyzer.analyze(file_path)
    all_findings = list(generic.findings)

    # PE analysis
    pe = None
    if generic.detected_type.startswith("PE") or file_path.lower().endswith((".exe", ".dll", ".sys")):
        pe = pe_analyzer.analyze(file_path)
        all_findings.extend(pe.findings)

    # Script analysis
    script = None
    ext = os.path.splitext(file_path)[1].lower()
    if ext in script_analyzer.SCRIPT_EXTENSIONS or generic.detected_type == "Shell script":
        script = script_analyzer.analyze(file_path)
        all_findings.extend(script.findings)

    # YARA scan
    from threatlens.rules.signatures import scan as yara_scan
    yara_result = yara_scan(file_path)
    all_findings.extend(yara_result.findings)

    # Calculate threat score
    score = calculate_score(all_findings, generic, pe, script)

    # Output
    if format == "json":
        output = {
            "file": generic.file_name,
            "size": generic.file_size,
            "type": generic.file_type,
            "md5": generic.md5,
            "sha256": generic.sha256,
            "entropy": generic.entropy,
            "risk_score": score.score,
            "risk_level": score.level,
            "findings": all_findings,
            "urls": generic.urls,
            "ip_addresses": generic.ip_addresses,
            "recommendations": score.recommendations,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    # Text output
    print_file_info(generic)

    if pe and pe.is_pe:
        print_pe_info(pe)

    print_risk(score)
    print_findings(all_findings)

    # Built-in explanation (always works, no AI needed)
    from threatlens.ai.explanations import generate_explanation
    builtin_explanation = generate_explanation(score.categories, lang="ru")
    if builtin_explanation:
        print_ai_explanation(builtin_explanation)

    # Optional: LLM explanation for deeper analysis
    if use_ai:
        console.print("\n  [dim]Generating advanced AI explanation (YandexGPT)...[/]")
        from threatlens.ai.providers import get_provider
        from threatlens.ai.prompts import THREAT_EXPLANATION_PROMPT

        provider = get_provider(ai_provider or "yandexgpt")
        prompt = THREAT_EXPLANATION_PROMPT.format(
            findings="\n".join(f"- {f}" for f in all_findings) or "No findings",
            filename=generic.file_name,
            filetype=generic.file_type,
            filesize=f"{generic.file_size:,} bytes",
            risk_score=score.score,
            risk_level=score.level,
            categories=", ".join(score.categories.keys()) or "none",
        )
        explanation = provider.explain(prompt)
        from threatlens.output.colors import Panel
        console.print(Panel(
            explanation,
            title="[bold magenta]Advanced AI Analysis (YandexGPT)[/]",
            border_style="magenta", padding=(1, 2),
        ))

    print_recommendations(score.recommendations)
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


def main():
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens — AI-Powered File Threat Analyzer",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("target", help="File or directory to scan")
    scan_p.add_argument("--ai", action="store_true", help="Enable AI-powered explanation")
    scan_p.add_argument("--provider", default=None, help="AI provider (ollama/openai/yandexgpt)")
    scan_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    scan_p.add_argument("--recursive", action="store_true", help="Scan directory recursively")

    args = parser.parse_args()

    if args.command == "scan":
        if args.recursive or os.path.isdir(args.target):
            scan_directory(args.target, use_ai=args.ai, ai_provider=args.provider, format=args.format)
        else:
            scan_file(args.target, use_ai=args.ai, ai_provider=args.provider, format=args.format)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
