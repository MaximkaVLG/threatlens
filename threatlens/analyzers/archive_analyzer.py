"""Archive analyzer — recursively scans contents of ZIP/RAR/7z archives.

Shows exactly which file inside the archive is dangerous.
This is the key use case: user downloads a cheat/crack as .zip,
wants to know which file inside is the threat.
"""

import os
import zipfile
import tempfile
import shutil
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tar.gz", ".tgz"}

# Extensions that are suspicious inside archives
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".wsf", ".hta", ".msi", ".pif", ".com", ".lnk",
}

# Double extensions (social engineering)
DOUBLE_EXTENSION_TRICKS = [
    ".pdf.exe", ".jpg.exe", ".png.exe", ".doc.exe", ".mp4.exe",
    ".txt.exe", ".pdf.scr", ".jpg.scr", ".doc.js", ".pdf.bat",
]


@dataclass
class ArchiveFileInfo:
    """Info about a single file inside an archive."""
    name: str
    size: int
    compressed_size: int = 0
    extension: str = ""
    is_dangerous_ext: bool = False
    is_double_ext: bool = False
    is_password_protected: bool = False
    scan_result: dict = field(default_factory=dict)  # Full scan result if analyzed


@dataclass
class ArchiveAnalysis:
    """Results from archive analysis."""
    is_archive: bool = False
    archive_type: str = ""
    total_files: int = 0
    total_size_uncompressed: int = 0

    files: list[ArchiveFileInfo] = field(default_factory=list)
    dangerous_files: list[ArchiveFileInfo] = field(default_factory=list)
    suspicious_files: list[ArchiveFileInfo] = field(default_factory=list)

    is_password_protected: bool = False
    has_nested_archives: bool = False

    # Full scan results for each extracted file
    file_scan_results: list[dict] = field(default_factory=list)

    findings: list = field(default_factory=list)


def _scan_extracted_file(file_path: str, original_name: str) -> dict:
    """Run full ThreatLens analysis on an extracted file (including heuristics)."""
    from threatlens.core import analyze_file

    result = analyze_file(file_path, use_cache=False)

    return {
        "file": original_name,
        "size": result.size,
        "type": result.file_type,
        "md5": result.md5,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "findings": result.findings,
        "explanation": result.explanation,
        "recommendations": result.recommendations,
    }


def analyze(file_path: str, max_extract_size: int = 100 * 1024 * 1024) -> ArchiveAnalysis:
    """Analyze an archive file recursively.

    Args:
        file_path: Path to archive
        max_extract_size: Max total extracted size (default 100MB, safety limit)

    Returns:
        ArchiveAnalysis with per-file scan results
    """
    result = ArchiveAnalysis()
    ext = os.path.splitext(file_path)[1].lower()

    if ext not in ARCHIVE_EXTENSIONS:
        return result

    result.is_archive = True
    result.archive_type = ext

    # Currently supporting ZIP (most common for cheats/cracks)
    if ext == ".zip":
        return _analyze_zip(file_path, result, max_extract_size)
    else:
        result.findings.append(f"Archive type {ext} detected but extraction not yet supported")
        return result


def _analyze_zip(file_path: str, result: ArchiveAnalysis, max_extract_size: int) -> ArchiveAnalysis:
    """Analyze ZIP archive."""
    try:
        zf = zipfile.ZipFile(file_path, "r")
    except zipfile.BadZipFile:
        result.findings.append("Corrupted or invalid ZIP file")
        return result

    with zf:
        return _analyze_zip_inner(zf, file_path, result, max_extract_size)


def _analyze_zip_inner(zf, file_path: str, result: ArchiveAnalysis, max_extract_size: int) -> ArchiveAnalysis:
    """Inner ZIP analysis (zf is guaranteed to be closed by caller)."""
    # Check if password protected
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            result.is_password_protected = True
            result.findings.append("Archive is password-protected (cannot analyze contents)")
            return result

    # List all files
    try:
        file_list = zf.infolist()
    except Exception:
        result.findings.append("Corrupted ZIP — cannot read file list")
        return result

    if not file_list:
        result.findings.append("Empty or corrupted archive — no files inside")
        return result

    total_uncompressed = 0
    for info in file_list:
        if info.is_dir():
            continue

        finfo = ArchiveFileInfo(
            name=info.filename,
            size=info.file_size,
            compressed_size=info.compress_size,
            extension=os.path.splitext(info.filename)[1].lower(),
        )

        # Check dangerous extension
        if finfo.extension in DANGEROUS_EXTENSIONS:
            finfo.is_dangerous_ext = True

        # Check double extension trick
        name_lower = info.filename.lower()
        for trick in DOUBLE_EXTENSION_TRICKS:
            if name_lower.endswith(trick):
                finfo.is_double_ext = True
                result.findings.append(
                    f"[evasion] Double extension trick: {info.filename} (disguised executable)"
                )

        # Check nested archives
        if finfo.extension in ARCHIVE_EXTENSIONS:
            result.has_nested_archives = True

        result.files.append(finfo)
        total_uncompressed += info.file_size

    result.total_files = len(result.files)
    result.total_size_uncompressed = total_uncompressed

    if total_uncompressed > max_extract_size:
        result.findings.append(
            f"Archive too large to extract safely ({total_uncompressed // (1024*1024)} MB)"
        )
        return result

    # Archive bomb detection: check compression ratio
    compressed_size = os.path.getsize(file_path)
    if compressed_size > 0 and total_uncompressed / compressed_size > 100:
        result.findings.append(
            f"[evasion] Possible archive bomb: compression ratio "
            f"{total_uncompressed / compressed_size:.0f}:1 "
            f"({compressed_size} bytes -> {total_uncompressed} bytes)"
        )
        return result

    # Extract and scan each file (with Zip Slip protection)
    tmp_dir = tempfile.mkdtemp(prefix="threatlens_")
    result.file_scan_results = []

    try:
        # Safe extraction — prevent path traversal (Zip Slip)
        for info in zf.infolist():
            target_path = os.path.join(tmp_dir, info.filename)
            target_real = os.path.realpath(target_path)
            tmp_real = os.path.realpath(tmp_dir)
            if not target_real.startswith(tmp_real + os.sep) and target_real != tmp_real:
                result.findings.append(
                    f"[evasion] BLOCKED path traversal attempt: {info.filename}"
                )
                continue
            zf.extract(info, tmp_dir)
        zf.close()

        for finfo in result.files:
            extracted_path = os.path.join(tmp_dir, finfo.name)
            # Double-check path traversal
            if not os.path.realpath(extracted_path).startswith(os.path.realpath(tmp_dir)):
                continue
            if not os.path.exists(extracted_path) or os.path.isdir(extracted_path):
                continue

            try:
                scan_result = _scan_extracted_file(extracted_path, finfo.name)
                finfo.scan_result = scan_result
                result.file_scan_results.append(scan_result)

                if scan_result["risk_level"] in ("HIGH", "CRITICAL"):
                    result.dangerous_files.append(finfo)
                    result.findings.append(
                        f"[DANGEROUS] {finfo.name} — {scan_result['risk_level']} "
                        f"({scan_result['risk_score']}/100): "
                        f"{', '.join(scan_result['findings'][:3])}"
                    )
                elif scan_result["risk_level"] == "MEDIUM":
                    result.suspicious_files.append(finfo)
                    result.findings.append(
                        f"[suspicious] {finfo.name} — MEDIUM ({scan_result['risk_score']}/100)"
                    )
            except Exception as e:
                logger.debug("Error scanning %s: %s", finfo.name, e)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Summary findings
    if result.dangerous_files:
        result.findings.insert(0,
            f"FOUND {len(result.dangerous_files)} DANGEROUS FILE(S) inside archive!"
        )
    elif not result.suspicious_files:
        result.findings.append("No threats detected in archive contents")

    return result
