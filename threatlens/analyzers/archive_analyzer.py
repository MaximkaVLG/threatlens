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
    ".wsf", ".hta", ".msi", ".pif", ".com", ".lnk",
}
# Note: .js NOT included — too many false positives from node_modules

# Directories to skip inside archives (not useful to scan)
SKIP_ARCHIVE_DIRS = {
    "node_modules", "__pycache__", ".git", ".svn", ".hg",
    "vendor", "bower_components", ".tox", ".nox", ".mypy_cache",
    "__MACOSX", ".DS_Store",
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


MAX_ARCHIVE_FILES = 5000  # Max files to extract from archive (prevents inode exhaustion)


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
    elif ext == ".rar":
        return _analyze_rar(file_path, result, max_extract_size)
    elif ext in (".7z",):
        return _analyze_7z(file_path, result, max_extract_size)
    elif ext in (".tar", ".gz", ".tgz", ".tar.gz"):
        return _analyze_tar(file_path, result, max_extract_size)
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
    skipped_dirs = 0
    for info in file_list:
        if info.is_dir():
            continue

        # Skip files inside known safe directories (node_modules, .git, etc.)
        path_parts = info.filename.replace("\\", "/").split("/")
        if any(part in SKIP_ARCHIVE_DIRS for part in path_parts):
            skipped_dirs += 1
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

    # File count limit (prevents inode exhaustion from zip bombs with millions of tiny files)
    if result.total_files > MAX_ARCHIVE_FILES:
        result.findings.append(
            f"Archive contains too many files ({result.total_files}, limit {MAX_ARCHIVE_FILES}). "
            f"Only first {MAX_ARCHIVE_FILES} will be analyzed."
        )
        result.files = result.files[:MAX_ARCHIVE_FILES]

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


def _scan_extracted_dir(tmp_dir: str, result: ArchiveAnalysis):
    """Scan all files in extracted directory. Shared by RAR/7z/tar."""
    for root, dirs, files in os.walk(tmp_dir):
        # Skip known safe directories
        dirs[:] = [d for d in dirs if d not in SKIP_ARCHIVE_DIRS]

        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, tmp_dir)

            # Skip files in safe dirs (double check)
            parts = rel_path.replace("\\", "/").split("/")
            if any(part in SKIP_ARCHIVE_DIRS for part in parts):
                continue

            # Path traversal check
            if not os.path.realpath(full_path).startswith(os.path.realpath(tmp_dir)):
                result.findings.append(f"[evasion] BLOCKED path traversal: {rel_path}")
                continue

            ext = os.path.splitext(fname)[1].lower()
            finfo = ArchiveFileInfo(
                name=rel_path,
                size=os.path.getsize(full_path),
                extension=ext,
                is_dangerous_ext=ext in DANGEROUS_EXTENSIONS,
            )

            # Double extension
            name_lower = fname.lower()
            for trick in DOUBLE_EXTENSION_TRICKS:
                if name_lower.endswith(trick):
                    finfo.is_double_ext = True
                    result.findings.append(f"[evasion] Double extension trick: {fname}")

            result.files.append(finfo)

            try:
                scan_result = _scan_extracted_file(full_path, rel_path)
                finfo.scan_result = scan_result
                result.file_scan_results.append(scan_result)

                if scan_result["risk_level"] in ("HIGH", "CRITICAL"):
                    result.dangerous_files.append(finfo)
                    result.findings.append(
                        f"[DANGEROUS] {rel_path} — {scan_result['risk_level']} "
                        f"({scan_result['risk_score']}/100): "
                        f"{', '.join(scan_result['findings'][:3])}"
                    )
                elif scan_result["risk_level"] == "MEDIUM":
                    result.suspicious_files.append(finfo)
                    result.findings.append(
                        f"[suspicious] {rel_path} — MEDIUM ({scan_result['risk_score']}/100)"
                    )
            except Exception as e:
                logger.debug("Error scanning %s: %s", rel_path, e)

    result.total_files = len(result.files)

    if result.dangerous_files:
        result.findings.insert(0,
            f"FOUND {len(result.dangerous_files)} DANGEROUS FILE(S) inside archive!"
        )
    elif not result.suspicious_files:
        result.findings.append("No threats detected in archive contents")


def _analyze_rar(file_path: str, result: ArchiveAnalysis, max_extract_size: int) -> ArchiveAnalysis:
    """Analyze RAR archive."""
    try:
        import rarfile
    except ImportError:
        result.findings.append("RAR support requires: pip install rarfile")
        return result

    try:
        rf = rarfile.RarFile(file_path)
    except (rarfile.BadRarFile, rarfile.NotRarFile):
        result.findings.append("Corrupted or invalid RAR file")
        return result
    except rarfile.NeedFirstVolume:
        result.findings.append("Multi-volume RAR — only first volume can be analyzed")
        return result

    # Check password
    if rf.needs_password():
        result.is_password_protected = True
        result.findings.append("Archive is password-protected (cannot analyze contents)")
        rf.close()
        return result

    # Check total size
    total_size = sum(info.file_size for info in rf.infolist() if not info.is_dir())
    if total_size > max_extract_size:
        result.findings.append(f"Archive too large ({total_size // (1024*1024)} MB)")
        rf.close()
        return result

    tmp_dir = tempfile.mkdtemp(prefix="threatlens_rar_")
    result.file_scan_results = []

    try:
        # Safe extraction — check each member for path traversal
        tmp_real = os.path.realpath(tmp_dir)
        for member in rf.infolist():
            target = os.path.join(tmp_dir, member.filename)
            target_real = os.path.realpath(target)
            if not target_real.startswith(tmp_real + os.sep) and target_real != tmp_real:
                result.findings.append(f"[evasion] BLOCKED path traversal in RAR: {member.filename}")
                continue
            rf.extract(member, tmp_dir)
        rf.close()
        _scan_extracted_dir(tmp_dir, result)
    except rarfile.BadRarFile:
        result.findings.append("Error extracting RAR — file may be corrupted")
    except Exception as e:
        result.findings.append(f"RAR extraction error: {type(e).__name__}")
        logger.debug("RAR error: %s", e)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


def _analyze_7z(file_path: str, result: ArchiveAnalysis, max_extract_size: int) -> ArchiveAnalysis:
    """Analyze 7z archive."""
    try:
        import py7zr
    except ImportError:
        result.findings.append("7z support requires: pip install py7zr")
        return result

    try:
        with py7zr.SevenZipFile(file_path, mode="r") as szf:
            # Check password
            if szf.needs_password():
                result.is_password_protected = True
                result.findings.append("Archive is password-protected (cannot analyze contents)")
                return result

            # Check total size
            total_size = sum(info.uncompressed for info in szf.list() if not info.is_directory)
            if total_size > max_extract_size:
                result.findings.append(f"Archive too large ({total_size // (1024*1024)} MB)")
                return result

            tmp_dir = tempfile.mkdtemp(prefix="threatlens_7z_")
            result.file_scan_results = []

            try:
                # Safe extraction — extract then verify paths
                szf.extractall(tmp_dir)
                # Post-extraction path traversal check
                tmp_real = os.path.realpath(tmp_dir)
                for root, dirs, files in os.walk(tmp_dir):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        if not os.path.realpath(fpath).startswith(tmp_real + os.sep):
                            result.findings.append(f"[evasion] BLOCKED path traversal in 7z: {fname}")
                            os.unlink(fpath)
                _scan_extracted_dir(tmp_dir, result)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    except py7zr.Bad7zFile:
        result.findings.append("Corrupted or invalid 7z file")
    except Exception as e:
        result.findings.append(f"7z error: {type(e).__name__}")
        logger.debug("7z error: %s", e)

    return result


def _analyze_tar(file_path: str, result: ArchiveAnalysis, max_extract_size: int) -> ArchiveAnalysis:
    """Analyze tar/tar.gz/tgz archive."""
    import tarfile

    try:
        tf = tarfile.open(file_path, "r:*")
    except (tarfile.TarError, EOFError):
        result.findings.append("Corrupted or invalid tar archive")
        return result

    # Check total size and path traversal
    total_size = 0
    for member in tf.getmembers():
        if member.isfile():
            total_size += member.size
            # Block path traversal in tar
            if member.name.startswith("/") or ".." in member.name:
                result.findings.append(f"[evasion] BLOCKED path traversal in tar: {member.name}")
                tf.close()
                return result

    if total_size > max_extract_size:
        result.findings.append(f"Archive too large ({total_size // (1024*1024)} MB)")
        tf.close()
        return result

    tmp_dir = tempfile.mkdtemp(prefix="threatlens_tar_")
    result.file_scan_results = []

    try:
        # Safe extraction — filter dangerous members
        safe_members = [m for m in tf.getmembers()
                        if not m.name.startswith("/") and ".." not in m.name]
        tf.extractall(tmp_dir, members=safe_members)
        tf.close()
        _scan_extracted_dir(tmp_dir, result)
    except Exception as e:
        result.findings.append(f"Tar extraction error: {type(e).__name__}")
        logger.debug("Tar error: %s", e)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result
