"""GitHub repository analyzer — scans all files in a repo for threats.

Usage: threatlens repo https://github.com/user/project

Clones the repo (shallow), scans every file, shows which ones are dangerous.
"""

import os
import re
import shutil
import tempfile
import subprocess
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Files to always skip (not useful to scan)
SKIP_FILES = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".idea", ".vscode", ".DS_Store", "Thumbs.db",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mkv",
    ".ttf", ".woff", ".woff2", ".eot",
    ".lock", ".sum",
}

# Max file size to analyze (5MB)
MAX_FILE_SIZE = 5 * 1024 * 1024


@dataclass
class RepoFileResult:
    """Scan result for a single file in the repo."""
    path: str
    risk_level: str = "LOW"
    risk_score: int = 0
    findings: list = field(default_factory=list)
    explanation: str = ""


@dataclass
class RepoAnalysis:
    """Full repository analysis results."""
    repo_url: str = ""
    repo_name: str = ""
    total_files: int = 0
    scanned_files: int = 0
    skipped_files: int = 0

    dangerous_files: list[RepoFileResult] = field(default_factory=list)
    suspicious_files: list[RepoFileResult] = field(default_factory=list)
    safe_files: int = 0

    findings: list = field(default_factory=list)


ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


def _validate_repo_url(url: str) -> str | None:
    """Validate repository URL. Returns error message or None if valid."""
    try:
        parsed = urlparse(url)
    except Exception:
        return "Invalid URL format"
    if parsed.scheme not in ("https",):
        return f"Only HTTPS URLs are allowed (got {parsed.scheme!r})"
    if not parsed.hostname:
        return "URL has no hostname"
    hostname = parsed.hostname.lower()
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return "Loopback/local addresses are not allowed"
    if hostname not in ALLOWED_HOSTS:
        return f"Host {hostname!r} is not in allowed list: {', '.join(sorted(ALLOWED_HOSTS))}"
    return None


def _clone_repo(url: str, dest: str) -> bool:
    """Shallow clone a git repository."""
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, dest],
            capture_output=True, text=True, timeout=120,
        )
        return os.path.exists(dest) and os.listdir(dest)
    except FileNotFoundError:
        logger.error("git not found. Install git to use repo scanning.")
        return False
    except subprocess.TimeoutExpired:
        logger.error("Clone timed out after 120s")
        return False
    except Exception as e:
        logger.error("Clone error: %s", e)
        return False


def _parse_repo_url(url: str) -> str:
    """Extract repo name from GitHub URL."""
    # Handle various URL formats
    url = url.rstrip("/").rstrip(".git")
    parts = url.split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return url


def _should_skip(file_path: str, root: str) -> bool:
    """Check if file should be skipped."""
    rel = os.path.relpath(file_path, root)
    parts = rel.split(os.sep)

    # Skip directories
    for part in parts:
        if part in SKIP_FILES:
            return True

    # Skip by extension
    ext = os.path.splitext(file_path)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return True

    # Skip large files
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            return True
    except OSError:
        return True

    return False


def _scan_single_file(file_path: str) -> dict:
    """Run ThreatLens analysis on a single file."""
    from threatlens.analyzers import generic_analyzer, pe_analyzer, script_analyzer, office_analyzer
    from threatlens.scoring.threat_scorer import calculate_score
    from threatlens.scoring.heuristic_engine import analyze as heuristic_analyze
    from threatlens.rules.signatures import scan as yara_scan
    from threatlens.ai.explanations import generate_explanation

    generic = generic_analyzer.analyze(file_path)
    all_findings = list(generic.findings)

    ext = os.path.splitext(file_path)[1].lower()

    pe = None
    if generic.detected_type.startswith("PE") or ext in (".exe", ".dll"):
        pe = pe_analyzer.analyze(file_path)
        all_findings.extend(pe.findings)

    script = None
    if ext in script_analyzer.SCRIPT_EXTENSIONS:
        script = script_analyzer.analyze(file_path)
        all_findings.extend(script.findings)

    if ext in office_analyzer.OFFICE_EXTENSIONS:
        office = office_analyzer.analyze(file_path)
        all_findings.extend(office.findings)

    yara_result = yara_scan(file_path)
    all_findings.extend(yara_result.findings)

    heuristic_verdicts = heuristic_analyze(generic, pe, script, all_findings)
    for v in heuristic_verdicts:
        all_findings.append(
            f"[HEURISTIC] {v.threat_type.upper()} ({v.confidence:.0%} confidence)"
        )

    score = calculate_score(all_findings, generic, pe, script)
    explanation = generate_explanation(score.categories, lang="ru")

    return {
        "risk_level": score.level,
        "risk_score": score.score,
        "findings": all_findings,
        "explanation": explanation,
    }


def analyze(repo_url: str) -> RepoAnalysis:
    """Clone and scan a GitHub repository.

    Args:
        repo_url: GitHub repository URL

    Returns:
        RepoAnalysis with per-file results
    """
    result = RepoAnalysis(
        repo_url=repo_url,
        repo_name=_parse_repo_url(repo_url),
    )

    url_error = _validate_repo_url(repo_url)
    if url_error:
        result.findings.append(f"Invalid repository URL: {url_error}")
        return result

    tmp_dir = tempfile.mkdtemp(prefix="threatlens_repo_")

    try:
        logger.info("Cloning %s...", repo_url)
        if not _clone_repo(repo_url, tmp_dir):
            result.findings.append("Failed to clone repository")
            return result

        # Collect files
        all_files = []
        for root, dirs, files in os.walk(tmp_dir):
            # Skip .git directory
            dirs[:] = [d for d in dirs if d not in SKIP_FILES]
            for f in files:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, tmp_dir)

                if _should_skip(full_path, tmp_dir):
                    result.skipped_files += 1
                    continue

                all_files.append((full_path, rel_path))

        result.total_files = len(all_files) + result.skipped_files

        # Scan each file
        for full_path, rel_path in all_files:
            result.scanned_files += 1

            try:
                scan = _scan_single_file(full_path)

                file_result = RepoFileResult(
                    path=rel_path,
                    risk_level=scan["risk_level"],
                    risk_score=scan["risk_score"],
                    findings=scan["findings"],
                    explanation=scan["explanation"],
                )

                if scan["risk_level"] in ("HIGH", "CRITICAL"):
                    result.dangerous_files.append(file_result)
                elif scan["risk_level"] == "MEDIUM":
                    result.suspicious_files.append(file_result)
                else:
                    result.safe_files += 1

            except Exception as e:
                logger.warning("Error scanning %s: %s", rel_path, e)

        # Summary
        if result.dangerous_files:
            result.findings.append(
                f"FOUND {len(result.dangerous_files)} DANGEROUS FILE(S) in repository!"
            )
        if result.suspicious_files:
            result.findings.append(
                f"{len(result.suspicious_files)} suspicious file(s) found"
            )
        if not result.dangerous_files and not result.suspicious_files:
            result.findings.append("No threats detected in repository")

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result
