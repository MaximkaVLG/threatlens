"""Core analysis function — single entry point for all analyzers.

Used by CLI, Web UI, and repo scanner. No duplication.
"""

import os
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Unified analysis result."""
    file: str = ""
    size: int = 0
    file_type: str = ""
    md5: str = ""
    sha256: str = ""
    entropy: float = 0.0
    entropy_verdict: str = ""

    risk_score: int = 0
    risk_level: str = "LOW"
    summary: str = ""

    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    explanation: str = ""

    heuristic_verdicts: list = field(default_factory=list)
    yara_matches: list = field(default_factory=list)

    # Raw analysis objects (for CLI display)
    generic_analysis: object = None
    pe_analysis: object = None
    script_analysis: object = None
    office_analysis: object = None


def analyze_file(file_path: str, use_cache: bool = True) -> AnalysisResult:
    """Run full ThreatLens analysis on a single file.

    This is THE single function that both CLI and Web use.
    Checks cache first — returns instant result if file was scanned before.
    """
    import time as _time
    import hashlib as _hashlib
    from threatlens.analyzers import generic_analyzer, pe_analyzer, script_analyzer, office_analyzer
    from threatlens.scoring.threat_scorer import calculate_score
    from threatlens.scoring.heuristic_engine import analyze as heuristic_analyze
    from threatlens.rules.signatures import scan as yara_scan
    from threatlens.ai.explanations import generate_explanation

    # Validate input
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if os.path.isdir(file_path):
        raise IsADirectoryError(f"Expected a file, got directory: {file_path}")
    if os.path.getsize(file_path) == 0:
        result = AnalysisResult(file=os.path.basename(file_path))
        result.findings = ["Empty file (0 bytes)"]
        result.summary = "Empty file — nothing to analyze."
        return result

    # Read file once, reuse for cache check and analysis
    with open(file_path, "rb") as f:
        file_data = f.read()

    sha256 = _hashlib.sha256(file_data).hexdigest()

    # Check cache by SHA256
    if use_cache:
        try:
            from threatlens.cache import get_cache
            cached = get_cache().get(sha256)
            if cached:
                logger.info("Cache hit for %s", sha256[:16])
                result = AnalysisResult(
                    file=os.path.basename(file_path),
                    sha256=sha256,
                    size=cached["size"],
                    file_type=cached["type"],
                    risk_score=cached["risk_score"],
                    risk_level=cached["risk_level"],
                    findings=cached["findings"],
                    explanation=cached["explanation"],
                    recommendations=cached["recommendations"],
                )
                return result
        except Exception as e:
            logger.debug("Cache check failed: %s", e)

    scan_start = _time.time()
    result = AnalysisResult(file=os.path.basename(file_path))

    # Generic (all files) — pass pre-read data to avoid double read
    generic = generic_analyzer.analyze(file_path, data=file_data)
    all_findings = list(generic.findings)
    result.generic_analysis = generic
    result.size = generic.file_size
    result.file_type = generic.file_type
    result.md5 = generic.md5
    result.sha256 = generic.sha256
    result.entropy = generic.entropy
    result.entropy_verdict = generic.entropy_verdict

    ext = os.path.splitext(file_path)[1].lower()

    # PE
    pe = None
    if generic.detected_type.startswith("PE") or ext in (".exe", ".dll", ".sys"):
        pe = pe_analyzer.analyze(file_path)
        all_findings.extend(pe.findings)
        result.pe_analysis = pe

    # Script
    script = None
    if ext in script_analyzer.SCRIPT_EXTENSIONS or generic.detected_type == "Shell script":
        script = script_analyzer.analyze(file_path)
        all_findings.extend(script.findings)
        result.script_analysis = script

    # Office
    if ext in office_analyzer.OFFICE_EXTENSIONS or generic.detected_type.startswith("Microsoft Office"):
        office = office_analyzer.analyze(file_path)
        all_findings.extend(office.findings)
        result.office_analysis = office

    # Archive (ZIP, RAR, 7z, tar.gz)
    from threatlens.analyzers.archive_analyzer import ARCHIVE_EXTENSIONS, analyze as archive_analyze
    if ext in ARCHIVE_EXTENSIONS or generic.detected_type in ("ZIP archive", "RAR archive"):
        archive_result = archive_analyze(file_path)
        all_findings.extend(archive_result.findings)
        result.file_type = f"Archive ({ext})"

    # YARA
    yara_result = yara_scan(file_path)
    all_findings.extend(yara_result.findings)
    result.yara_matches = yara_result.matches

    # Heuristic
    heuristic_verdicts = heuristic_analyze(generic, pe, script, all_findings)
    for v in heuristic_verdicts:
        all_findings.append(
            f"[HEURISTIC] {v.threat_type.upper()} detected "
            f"({v.confidence:.0%} confidence, "
            f"behaviors: {', '.join(v.matching_behaviors[:5])})"
        )
    result.heuristic_verdicts = heuristic_verdicts

    # Score
    score = calculate_score(all_findings, generic, pe, script)
    result.risk_score = score.score
    result.risk_level = score.level
    result.summary = score.summary
    result.recommendations = score.recommendations
    result.findings = all_findings

    # Explanation
    result.explanation = generate_explanation(score.categories, lang="ru")

    # Save to cache
    if use_cache:
        try:
            scan_time = _time.time() - scan_start
            from threatlens.cache import get_cache
            get_cache().put(result, scan_time=scan_time)
        except Exception as e:
            logger.debug("Cache save failed: %s", e)

    return result
