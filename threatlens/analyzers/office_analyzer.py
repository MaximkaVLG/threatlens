"""Office document analyzer — detects malicious macros, OLE objects, DDE attacks.

Analyzes: .doc, .docx, .xls, .xlsx, .ppt, .pptx, .docm, .xlsm
Uses oletools for OLE2/VBA analysis.
"""

import os
import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    from oletools import oleid
    HAS_OLETOOLS = True
except ImportError:
    HAS_OLETOOLS = False

OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".docm", ".dot", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xlt", ".xltm",
    ".ppt", ".pptx", ".pptm", ".pot", ".potm",
    ".rtf",
}

# Suspicious VBA keywords
SUSPICIOUS_VBA = {
    "auto_execution": [
        "AutoOpen", "AutoClose", "AutoExec", "Auto_Open", "Auto_Close",
        "Document_Open", "Document_Close", "DocumentOpen",
        "Workbook_Open", "Workbook_Activate",
    ],
    "shell_execution": [
        "Shell", "WScript.Shell", "Shell.Application",
        "ShellExecute", "CreateObject", "GetObject",
        "Environ", "PowerShell", "cmd.exe", "cmd /c",
    ],
    "file_operations": [
        "FileCopy", "CopyFile", "DeleteFile", "Kill",
        "MkDir", "Open.*For Output", "Write #",
        "SaveToFile", "CreateTextFile",
    ],
    "network": [
        "XMLHTTP", "ServerXMLHTTP", "MSXML2",
        "InternetExplorer.Application", "URLDownloadToFile",
        "WinHttp", "Net.WebClient", "Invoke-WebRequest",
    ],
    "obfuscation": [
        "Chr\\(", "ChrW\\(", "Asc\\(", "StrReverse",
        "CallByName", "Replace\\(.*,.*,",
        "FromBase64", "Base64",
    ],
    "persistence": [
        "RegWrite", "RegCreate", "CurrentVersion\\\\Run",
        "Startup", "Scheduled",
    ],
    "process_injection": [
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlMoveMemory",
    ],
}

# Suspicious OLE indicators
SUSPICIOUS_OLE = [
    "Package",  # Embedded executable
    "OLE2Link",  # External OLE link (can download malware)
    "Equation.3",  # Equation Editor exploit (CVE-2017-11882)
]


@dataclass
class OfficeAnalysis:
    """Results from Office document analysis."""
    is_office: bool = False
    doc_type: str = ""
    has_macros: bool = False
    has_vba: bool = False

    # VBA analysis
    vba_modules: list = field(default_factory=list)
    vba_code_size: int = 0
    suspicious_vba: list = field(default_factory=list)
    auto_execution: bool = False

    # OLE analysis
    ole_objects: list = field(default_factory=list)
    has_external_links: bool = False
    has_dde: bool = False

    # Embedded files
    embedded_executables: list = field(default_factory=list)

    findings: list = field(default_factory=list)


def analyze(file_path: str) -> OfficeAnalysis:
    """Analyze an Office document for malicious content."""
    result = OfficeAnalysis()

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in OFFICE_EXTENSIONS:
        return result

    result.is_office = True
    result.doc_type = ext

    if not HAS_OLETOOLS:
        result.findings.append("oletools not installed — Office analysis limited")
        _basic_analysis(file_path, result)
        return result

    # VBA/Macro analysis
    _analyze_vba(file_path, result)

    # OLE analysis
    _analyze_ole(file_path, result)

    # DDE detection (in OOXML files)
    if ext in (".docx", ".xlsx", ".pptx"):
        _detect_dde(file_path, result)

    return result


def _analyze_vba(file_path: str, result: OfficeAnalysis):
    """Extract and analyze VBA macros."""
    try:
        vba_parser = VBA_Parser(file_path)
    except Exception as e:
        logger.debug("VBA parser error: %s", e)
        return

    try:
        if not vba_parser.detect_vba_macros():
            result.has_macros = False
            return

        result.has_macros = True
        result.has_vba = True
        result.findings.append("[obfuscation] Document contains VBA macros")

        try:
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                result.vba_modules.append({
                    "filename": vba_filename,
                    "stream": stream_path,
                    "code_length": len(vba_code),
                })
                result.vba_code_size += len(vba_code)

                # Check for suspicious patterns
                for category, patterns in SUSPICIOUS_VBA.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, vba_code, re.IGNORECASE)
                        if matches:
                            result.suspicious_vba.append({
                                "category": category,
                                "pattern": pattern,
                                "match": matches[0][:80] if matches else "",
                                "module": vba_filename,
                            })

                            if category == "auto_execution":
                                result.auto_execution = True
                                result.findings.append(
                                    f"[persistence] Auto-execution macro: {matches[0]} in {vba_filename}"
                                )
                            elif category == "shell_execution":
                                result.findings.append(
                                    f"[injection] Shell/command execution in macro: {matches[0][:60]}"
                                )
                            elif category == "network":
                                result.findings.append(
                                    f"[network] Network access in macro: {matches[0][:60]}"
                                )
                            elif category == "obfuscation":
                                result.findings.append(
                                    f"[obfuscation] Obfuscation technique in macro: {pattern}"
                                )
                            elif category == "process_injection":
                                result.findings.append(
                                    f"[injection] Process injection in macro: {matches[0]}"
                                )
                            elif category == "persistence":
                                result.findings.append(
                                    f"[persistence] Persistence mechanism in macro: {matches[0][:60]}"
                                )
                            elif category == "file_operations":
                                result.findings.append(
                                    f"[file_operations] File operation in macro: {matches[0][:60]}"
                                )
                            break  # One finding per category per module

        except Exception as e:
            logger.debug("VBA extraction error: %s", e)

        if result.auto_execution:
            result.findings.insert(0,
                "[persistence] DANGER: Document has auto-executing macros — "
                "code runs automatically when opened!"
            )
    finally:
        vba_parser.close()


def _analyze_ole(file_path: str, result: OfficeAnalysis):
    """Analyze OLE objects embedded in the document."""
    try:
        oid = oleid.OleID(file_path)
        indicators = oid.check()

        for indicator in indicators:
            if indicator.id == "vba_macros" and indicator.value:
                pass  # Already handled above
            elif indicator.id == "ext_rels" and indicator.value:
                result.has_external_links = True
                result.findings.append(
                    "[network] Document contains external relationships (may download content)"
                )
            elif indicator.id == "ObjectPool" and indicator.value:
                result.findings.append(
                    "[obfuscation] Document contains OLE Object Pool (may have embedded objects)"
                )
    except Exception as e:
        logger.debug("OLE analysis error: %s", e)


def _detect_dde(file_path: str, result: OfficeAnalysis):
    """Detect DDE (Dynamic Data Exchange) attacks in OOXML files."""
    try:
        import zipfile
        if not zipfile.is_zipfile(file_path):
            return

        with zipfile.ZipFile(file_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".xml") or name.endswith(".rels"):
                    try:
                        content = zf.read(name).decode("utf-8", errors="ignore")
                        # DDE patterns
                        dde_patterns = [
                            r"DDEAUTO",
                            r"DDE\s",
                            r'fldCharType="begin".*?instrText.*?DDEAUTO',
                            r"cmd\.exe",
                            r"powershell",
                            r"mshta",
                        ]
                        for pattern in dde_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                result.has_dde = True
                                result.findings.append(
                                    f"[injection] DDE attack detected in {name}: {pattern}"
                                )
                                break
                    except Exception:
                        pass
    except Exception as e:
        logger.debug("DDE detection error: %s", e)


def _basic_analysis(file_path: str, result: OfficeAnalysis):
    """Basic analysis without oletools — check for obvious indicators."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(50000)  # First 50KB

        content = data.decode("utf-8", errors="ignore")

        # Check for macro indicators
        if b"vbaProject.bin" in data or b"VBA" in data:
            result.has_macros = True
            result.findings.append("[obfuscation] File likely contains VBA macros")

        # Check for auto-execution
        for keyword in SUSPICIOUS_VBA["auto_execution"]:
            if keyword.lower() in content.lower():
                result.auto_execution = True
                result.findings.append(f"[persistence] Auto-execution keyword found: {keyword}")

        # Check for suspicious strings
        suspicious = ["cmd.exe", "powershell", "WScript.Shell", "XMLHTTP", "Shell("]
        for sus in suspicious:
            if sus.lower() in content.lower():
                result.findings.append(f"[injection] Suspicious string in document: {sus}")

    except Exception as e:
        logger.debug("Basic analysis error: %s", e)
