"""Archive analyzer — recursively scans contents of ZIP/RAR/7z archives.

Shows exactly which file inside the archive is dangerous.
This is the key use case: user downloads a cheat/crack as .zip,
wants to know which file inside is the threat.
"""

import os
import subprocess
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


def _scan_extracted_file(file_path: str, original_name: str, password: str = None) -> dict:
    """Run full ThreatLens analysis on an extracted file (including nested archives)."""
    from threatlens.core import analyze_file

    # Pass password for nested archives (MalwareBazaar: ZIP -> 7z -> exe, same password)
    result = analyze_file(file_path, use_cache=False, password=password)

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


def analyze(file_path: str, max_extract_size: int = 100 * 1024 * 1024, password: str = None) -> ArchiveAnalysis:
    """Analyze an archive file recursively.

    Args:
        file_path: Path to archive
        max_extract_size: Max total extracted size (default 100MB, safety limit)
        password: Optional password for encrypted archives

    Returns:
        ArchiveAnalysis with per-file scan results
    """
    result = ArchiveAnalysis()
    name_lower = file_path.lower()
    ext = os.path.splitext(file_path)[1].lower()

    # Handle double extensions: .tar.gz, .tar.bz2
    if name_lower.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        ext = ".tar.gz"
    elif ext == ".tgz":
        ext = ".tar.gz"

    if ext not in ARCHIVE_EXTENSIONS:
        return result

    result.is_archive = True
    result.archive_type = ext

    if ext == ".zip":
        return _analyze_zip(file_path, result, max_extract_size, password=password)
    elif ext == ".rar":
        return _analyze_rar(file_path, result, max_extract_size, password=password)
    elif ext in (".7z",):
        return _analyze_7z(file_path, result, max_extract_size, password=password)
    elif ext in (".tar", ".gz", ".tgz", ".tar.gz"):
        return _analyze_tar(file_path, result, max_extract_size, password=password)
    else:
        result.findings.append(f"Archive type {ext} detected but extraction not yet supported")
        return result


def _analyze_zip(file_path: str, result: ArchiveAnalysis, max_extract_size: int, password: str = None) -> ArchiveAnalysis:
    """Analyze ZIP archive, with optional password for encrypted archives.

    Uses pyzipper for AES-256 support (MalwareBazaar, etc.), falls back to zipfile.
    """
    try:
        import pyzipper
        zf = pyzipper.AESZipFile(file_path, "r")
    except ImportError:
        try:
            zf = zipfile.ZipFile(file_path, "r")
        except zipfile.BadZipFile:
            result.findings.append("Corrupted or invalid ZIP file")
            return result
    except Exception:
        try:
            zf = zipfile.ZipFile(file_path, "r")
        except zipfile.BadZipFile:
            result.findings.append("Corrupted or invalid ZIP file")
            return result

    with zf:
        return _analyze_zip_inner(zf, file_path, result, max_extract_size, password=password)


def _analyze_zip_inner(zf, file_path: str, result: ArchiveAnalysis, max_extract_size: int, password: str = None) -> ArchiveAnalysis:
    """Inner ZIP analysis (zf is guaranteed to be closed by caller)."""
    pwd_bytes = password.encode("utf-8") if password else None

    # Check if password protected
    is_encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
    if is_encrypted:
        result.is_password_protected = True
        if not pwd_bytes:
            result.findings.append("Archive is password-protected. Provide a password to analyze contents.")
            return result
        # Verify password works
        try:
            test_info = next(i for i in zf.infolist() if not i.is_dir())
            zf.read(test_info, pwd=pwd_bytes)
            result.findings.append("Password-protected archive — unlocked successfully")
        except RuntimeError:
            result.findings.append("Wrong password — cannot decrypt archive")
            return result
        except Exception:
            result.findings.append("Failed to decrypt archive with provided password")
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
            zf.extract(info, tmp_dir, pwd=pwd_bytes)
        zf.close()

        # Only fully scan files with dangerous or archive extensions (skip .txt, .png, etc.)
        from threatlens.analyzers.script_analyzer import SCRIPT_EXTENSIONS
        from threatlens.analyzers.office_analyzer import OFFICE_EXTENSIONS
        scannable_exts = DANGEROUS_EXTENSIONS | ARCHIVE_EXTENSIONS | SCRIPT_EXTENSIONS | OFFICE_EXTENSIONS
        files_to_scan = [f for f in result.files if f.extension in scannable_exts]
        safe_skipped = len(result.files) - len(files_to_scan)
        if safe_skipped > 0:
            logger.info("Archive: skipping %d safe files, scanning %d dangerous", safe_skipped, len(files_to_scan))

        for finfo in files_to_scan:
            extracted_path = os.path.join(tmp_dir, finfo.name)
            # Double-check path traversal
            if not os.path.realpath(extracted_path).startswith(os.path.realpath(tmp_dir)):
                continue
            if not os.path.exists(extracted_path) or os.path.isdir(extracted_path):
                continue

            try:
                scan_result = _scan_extracted_file(extracted_path, finfo.name, password=pwd_bytes.decode() if pwd_bytes else None)
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


def _scan_extracted_dir(tmp_dir: str, result: ArchiveAnalysis, password: str = None):
    """Scan files in extracted directory. Only fully scans dangerous/archive extensions."""
    from threatlens.analyzers.script_analyzer import SCRIPT_EXTENSIONS
    from threatlens.analyzers.office_analyzer import OFFICE_EXTENSIONS
    scannable_exts = DANGEROUS_EXTENSIONS | ARCHIVE_EXTENSIONS | SCRIPT_EXTENSIONS | OFFICE_EXTENSIONS
    files_collected = []

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
            files_collected.append((finfo, full_path, rel_path))

    # Only fully scan dangerous/archive extensions (skip .txt, .png, .jpg, etc.)
    for finfo, full_path, rel_path in files_collected:
        if finfo.extension not in scannable_exts:
            continue
        try:
            scan_result = _scan_extracted_file(full_path, rel_path, password=password)
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


def _analyze_rar(file_path: str, result: ArchiveAnalysis, max_extract_size: int, password: str = None) -> ArchiveAnalysis:
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
        _scan_extracted_dir(tmp_dir, result, password=password)
    except rarfile.BadRarFile:
        result.findings.append("Error extracting RAR — file may be corrupted")
    except Exception as e:
        result.findings.append(f"RAR extraction error: {type(e).__name__}")
        logger.debug("RAR error: %s", e)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


def _extract_7z_system(file_path: str, tmp_dir: str, password: str = None) -> bool:
    """Try extracting 7z using system 7z binary (supports all encryption methods)."""
    for bin_path in ["7z", "7za", "/usr/bin/7z", "C:\\Program Files\\7-Zip\\7z.exe"]:
        try:
            cmd = [bin_path, "x", f"-o{tmp_dir}", "-y"]
            if password:
                cmd.append(f"-p{password}")
            else:
                cmd.append("-p")  # empty password
            cmd.append(file_path)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def _analyze_7z(file_path: str, result: ArchiveAnalysis, max_extract_size: int, password: str = None) -> ArchiveAnalysis:
    """Analyze 7z archive. Uses system 7z binary as fallback for unsupported encryption."""
    tmp_dir = tempfile.mkdtemp(prefix="threatlens_7z_")
    result.file_scan_results = []
    extracted = False

    # Method 1: Try py7zr (pure Python)
    try:
        import py7zr
        try:
            szf = py7zr.SevenZipFile(file_path, mode="r", password=password)
            file_list = szf.list()
            total_size = sum(info.uncompressed for info in file_list if not info.is_directory)
            if total_size > max_extract_size:
                result.findings.append(f"Archive too large ({total_size // (1024*1024)} MB)")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return result
            with szf:
                szf.extractall(tmp_dir)
            extracted = True
            if password:
                result.findings.append("Password-protected 7z — unlocked successfully")
        except Exception as e:
            err_str = str(e)
            if "Password" in err_str or "password" in err_str or "Decompression" in err_str:
                result.is_password_protected = True
            # py7zr failed — try system 7z
    except ImportError:
        pass

    # Method 2: Fallback to system 7z binary (supports AES-256 and all methods)
    if not extracted:
        if _extract_7z_system(file_path, tmp_dir, password):
            extracted = True
            if password:
                result.findings.append("Password-protected 7z — unlocked with system 7z")
        elif result.is_password_protected and not password:
            result.findings.append("7z archive is password-protected. Provide a password to analyze.")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return result

    if not extracted:
        if result.is_password_protected:
            result.findings.append("Cannot decrypt 7z — unsupported encryption method. Install 7-Zip for full support.")
        else:
            result.findings.append("Corrupted or invalid 7z file")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return result

    try:
        # Post-extraction path traversal check
        tmp_real = os.path.realpath(tmp_dir)
        for root, dirs, files in os.walk(tmp_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if not os.path.realpath(fpath).startswith(tmp_real + os.sep):
                    result.findings.append(f"[evasion] BLOCKED path traversal in 7z: {fname}")
                    os.unlink(fpath)
        _scan_extracted_dir(tmp_dir, result, password=password)
    except Exception as e:
        result.findings.append(f"7z error: {type(e).__name__}")
        logger.debug("7z error: %s", e)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


def _analyze_tar(file_path: str, result: ArchiveAnalysis, max_extract_size: int, password: str = None) -> ArchiveAnalysis:
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
        _scan_extracted_dir(tmp_dir, result, password=password)
    except Exception as e:
        result.findings.append(f"Tar extraction error: {type(e).__name__}")
        logger.debug("Tar error: %s", e)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result
