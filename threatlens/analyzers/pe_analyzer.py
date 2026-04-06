"""PE file analyzer — analyzes Windows executables (.exe, .dll).

Extracts imports, sections, resources, compiler info, packer detection.
"""

import os
import math
from dataclasses import dataclass, field

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# Suspicious Windows API imports (grouped by threat category)
SUSPICIOUS_IMPORTS = {
    "injection": [
        "CreateRemoteThread", "CreateRemoteThreadEx", "WriteProcessMemory",
        "VirtualAllocEx", "NtCreateThreadEx", "QueueUserAPC",
        "NtWriteVirtualMemory", "RtlCreateUserThread",
    ],
    "hooking": [
        "SetWindowsHookExA", "SetWindowsHookExW", "UnhookWindowsHookEx",
        "CallNextHookEx",
    ],
    "keylogger": [
        "GetAsyncKeyState", "GetKeyState", "MapVirtualKeyA",
        "MapVirtualKeyW", "GetKeyboardState",
    ],
    "process_manipulation": [
        "TerminateProcess", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next", "NtUnmapViewOfSection",
    ],
    "privilege_escalation": [
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
        "ImpersonateLoggedOnUser",
    ],
    "network": [
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
        "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA",
        "URLDownloadToFileW", "WSAStartup", "connect", "send", "recv",
    ],
    "file_operations": [
        "DeleteFileA", "DeleteFileW", "MoveFileA",
        "CopyFileA", "CopyFileW",
    ],
    "registry": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "RegDeleteKeyA", "RegDeleteValueA",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
        "CryptDeriveKey", "CryptAcquireContextA",
    ],
    "anti_debug": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA",
    ],
    "service": [
        "CreateServiceA", "CreateServiceW", "StartServiceA",
        "OpenSCManagerA", "ChangeServiceConfigA",
    ],
}

# Known packers by section names
KNOWN_PACKERS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    "PEtite": "PEtite", ".petite": "PEtite",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    "MEW": "MEW",
    "nsp0": "NsPack", "nsp1": "NsPack",
}


@dataclass
class PEAnalysis:
    """Results from PE file analysis."""
    is_pe: bool = False
    is_dll: bool = False
    is_64bit: bool = False
    machine: str = ""
    timestamp: str = ""

    # Sections
    sections: list = field(default_factory=list)
    high_entropy_sections: list = field(default_factory=list)

    # Imports
    imports: dict = field(default_factory=dict)  # dll -> [functions]
    suspicious_imports: list = field(default_factory=list)
    total_imports: int = 0

    # Packer detection
    detected_packer: str = ""
    is_packed: bool = False

    # Digital signature
    has_signature: bool = False

    # Resources
    resources: list = field(default_factory=list)

    findings: list = field(default_factory=list)


def analyze(file_path: str) -> PEAnalysis:
    """Analyze a PE file (exe/dll)."""
    result = PEAnalysis()

    if not HAS_PEFILE:
        result.findings.append("pefile not installed — PE analysis skipped")
        return result

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        result.findings.append("Not a valid PE file")
        return result

    try:
        return _analyze_pe_inner(pe, result)
    finally:
        pe.close()


def _analyze_pe_inner(pe, result: PEAnalysis) -> PEAnalysis:
    """Inner PE analysis — pe is guaranteed to be closed by caller."""
    result.is_pe = True
    result.is_dll = pe.is_dll()
    result.is_64bit = pe.FILE_HEADER.Machine == 0x8664
    result.machine = "x64" if result.is_64bit else "x86"

    # Timestamp
    import datetime
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        result.timestamp = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        # Suspicious timestamps
        year = datetime.datetime.fromtimestamp(ts).year
        if year < 2000 or year > datetime.datetime.now().year + 5:
            result.findings.append(f"Suspicious compilation timestamp: {result.timestamp}")
    except Exception:
        result.timestamp = "unknown"

    # Sections analysis
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        entropy = section.get_entropy()
        size = section.SizeOfRawData

        section_info = {
            "name": name,
            "entropy": round(entropy, 2),
            "size": size,
            "virtual_size": section.Misc_VirtualSize,
        }
        result.sections.append(section_info)

        # High entropy in .rsrc/.reloc is normal (icons, compressed resources)
        if entropy > 7.0 and name not in (".rsrc", ".reloc", ".rdata"):
            result.high_entropy_sections.append(section_info)
            result.findings.append(f"High entropy section '{name}' ({entropy:.1f}) — likely encrypted/packed")

        # Packer detection
        if name in KNOWN_PACKERS:
            result.detected_packer = KNOWN_PACKERS[name]
            result.is_packed = True

    if result.is_packed:
        result.findings.append(f"Packed with {result.detected_packer}")

    # Imports analysis
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore")
            functions = []
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode("utf-8", errors="ignore")
                    functions.append(func_name)
                    result.total_imports += 1

                    # Check suspicious imports
                    for category, suspicious_funcs in SUSPICIOUS_IMPORTS.items():
                        if func_name in suspicious_funcs:
                            result.suspicious_imports.append({
                                "function": func_name,
                                "dll": dll_name,
                                "category": category,
                            })

            result.imports[dll_name] = functions

    # Generate findings from suspicious imports
    categories_found = set()
    for si in result.suspicious_imports:
        cat = si["category"]
        if cat not in categories_found:
            categories_found.add(cat)
            funcs = [s["function"] for s in result.suspicious_imports if s["category"] == cat]
            result.findings.append(
                f"[{cat}] Suspicious imports: {', '.join(funcs[:5])}"
                + (f" (+{len(funcs)-5} more)" if len(funcs) > 5 else "")
            )

    # Very low import count = likely packed (but .NET/Go have few PE imports normally)
    is_dotnet = "mscoree.dll" in (d.lower() for d in result.imports.keys())
    if result.total_imports < 5 and not result.is_packed and not is_dotnet:
        result.findings.append(f"Very few imports ({result.total_imports}) — possibly packed or obfuscated")
        result.is_packed = True

    # Digital signature (informational — not a finding by itself)
    has_sig = False
    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
        has_sig = True
    result.has_signature = has_sig

    # Resources
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, "directory"):
                for entry in resource_type.directory.entries:
                    if hasattr(entry, "directory"):
                        for res in entry.directory.entries:
                            size = res.data.struct.Size
                            if size > 500000:  # Very large embedded resource (>500KB)
                                result.resources.append({
                                    "type": str(resource_type.name or resource_type.id),
                                    "size": size,
                                })

    return result
