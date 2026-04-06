"""Core analysis function — single entry point for all analyzers.

Used by CLI, Web UI, and repo scanner. No duplication.
Optimized: PE + YARA + Script/Office run in parallel via ThreadPoolExecutor.
"""

import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def analyze_file(file_path: str, use_cache: bool = True, password: str = None) -> AnalysisResult:
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

    MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB hard limit

    # Validate input
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if os.path.isdir(file_path):
        raise IsADirectoryError(f"Expected a file, got directory: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        result = AnalysisResult(file=os.path.basename(file_path))
        result.findings = ["Empty file (0 bytes)"]
        result.summary = "Empty file — nothing to analyze."
        return result
    if file_size > MAX_FILE_SIZE:
        result = AnalysisResult(file=os.path.basename(file_path))
        result.size = file_size
        result.findings = [f"File too large ({file_size // (1024*1024)} MB, limit {MAX_FILE_SIZE // (1024*1024)} MB). Skipping full analysis."]
        result.summary = "File exceeds size limit."
        result.risk_level = "LOW"
        # Still compute hash without loading entire file
        h = _hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        result.sha256 = h.hexdigest()
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
    archive_result = None  # Set later if archive
    result.generic_analysis = generic
    result.size = generic.file_size
    result.file_type = generic.file_type
    result.md5 = generic.md5
    result.sha256 = generic.sha256
    result.entropy = generic.entropy
    result.entropy_verdict = generic.entropy_verdict

    ext = os.path.splitext(file_path)[1].lower()
    from threatlens.analyzers.archive_analyzer import ARCHIVE_EXTENSIONS, analyze as archive_analyze

    # --- Parallel analysis: PE + YARA + Script + Office run concurrently ---
    pe = None
    script = None
    office = None
    archive_result = None

    need_pe = generic.detected_type.startswith("PE") or ext in (".exe", ".dll", ".sys")
    need_script = ext in script_analyzer.SCRIPT_EXTENSIONS or generic.detected_type == "Shell script"
    need_office = ext in office_analyzer.OFFICE_EXTENSIONS or generic.detected_type.startswith("Microsoft Office")
    need_archive = ext in ARCHIVE_EXTENSIONS or generic.detected_type in ("ZIP archive", "RAR archive")

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {}

        if need_pe:
            futures["pe"] = pool.submit(pe_analyzer.analyze, file_path)
        if need_script:
            futures["script"] = pool.submit(script_analyzer.analyze, file_path)
        if need_office:
            futures["office"] = pool.submit(office_analyzer.analyze, file_path)
        if need_archive:
            futures["archive"] = pool.submit(archive_analyze, file_path, 100 * 1024 * 1024, password)

        # YARA always runs (in parallel with above)
        futures["yara"] = pool.submit(yara_scan, file_path)

        # Collect results
        for key, future in futures.items():
            try:
                res = future.result(timeout=90)
                if key == "pe":
                    pe = res
                    all_findings.extend(pe.findings)
                    result.pe_analysis = pe
                elif key == "script":
                    script = res
                    all_findings.extend(script.findings)
                    result.script_analysis = script
                elif key == "office":
                    office = res
                    all_findings.extend(office.findings)
                    result.office_analysis = office
                elif key == "yara":
                    all_findings.extend(res.findings)
                    result.yara_matches = res.matches
                elif key == "archive":
                    archive_result = res
            except Exception as e:
                logger.error("Parallel analyzer %s failed: %s", key, e)

    # Archive post-processing
    if archive_result:
        all_findings.extend(archive_result.findings)
        result.file_type = f"Archive ({ext})"

        # Propagate worst risk from contents to archive level
        if archive_result.dangerous_files:
            max_inner_score = max(
                (f.scan_result.get("risk_score", 0) for f in archive_result.dangerous_files if f.scan_result),
                default=0,
            )
            if max_inner_score > 0:
                all_findings.insert(0, f"[injection] Archive contains CRITICAL threat (inner score: {max_inner_score}/100)")

        # Detect nested encrypted archives — strong malware indicator
        if archive_result.is_password_protected:
            for finfo in archive_result.files:
                inner_ext = finfo.extension.lower()
                if inner_ext in (".7z", ".rar", ".zip"):
                    all_findings.insert(0,
                        f"[evasion] Nested encrypted archive detected: encrypted {ext} contains {inner_ext} — "
                        f"this double-encryption pattern is commonly used by malware to evade detection"
                    )
                    if not archive_result.dangerous_files:
                        all_findings.insert(0,
                            f"[obfuscation] WARNING: inner {inner_ext} could not be fully analyzed — "
                            f"contents may be malicious but hidden behind encryption"
                        )

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

    # If archive contains dangerous files, inherit the worst score
    if ext in ARCHIVE_EXTENSIONS or generic.detected_type in ("ZIP archive", "RAR archive"):
        if archive_result and archive_result.dangerous_files:
            max_inner = max(
                (f.scan_result.get("risk_score", 0) for f in archive_result.dangerous_files if f.scan_result),
                default=0,
            )
            if max_inner > score.score:
                score.score = max_inner
                score.level = "CRITICAL" if max_inner >= 70 else "HIGH" if max_inner >= 40 else score.level
                score.summary = "Archive contains dangerous file(s)."
                score.recommendations = [
                    "DELETE this archive immediately",
                    "Do NOT extract or execute files inside",
                    "If already extracted: run full antivirus scan",
                ]

    result.risk_score = score.score
    result.risk_level = score.level
    result.summary = score.summary
    result.recommendations = score.recommendations
    result.findings = all_findings

    # Explanation
    result.explanation = generate_explanation(score.categories, lang="ru")
    # Override explanation for dangerous archives
    if result.risk_level in ("HIGH", "CRITICAL") and ext in ARCHIVE_EXTENSIONS:
        inner_explanations = [f.scan_result.get("explanation", "") for f in archive_result.dangerous_files if f.scan_result] if archive_result else []
        if inner_explanations and inner_explanations[0]:
            result.explanation = inner_explanations[0]

    # Save to cache
    if use_cache:
        try:
            scan_time = _time.time() - scan_start
            from threatlens.cache import get_cache
            get_cache().put(result, scan_time=scan_time)
        except Exception as e:
            logger.debug("Cache save failed: %s", e)

    return result
