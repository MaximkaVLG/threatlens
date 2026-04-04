"""Generic file analyzer — works on any file type.

Extracts: hashes, file size, entropy, printable strings, magic bytes.
"""

import os
import math
import hashlib
import re
from dataclasses import dataclass, field


@dataclass
class GenericAnalysis:
    """Results from generic file analysis."""
    file_path: str
    file_name: str
    file_size: int
    file_type: str = "unknown"

    # Hashes
    md5: str = ""
    sha1: str = ""
    sha256: str = ""

    # Entropy
    entropy: float = 0.0
    entropy_verdict: str = ""  # "normal", "packed", "encrypted"

    # Strings
    urls: list = field(default_factory=list)
    ip_addresses: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    file_paths: list = field(default_factory=list)
    registry_keys: list = field(default_factory=list)
    suspicious_strings: list = field(default_factory=list)
    all_strings: list = field(default_factory=list)

    # Magic bytes
    magic_bytes: str = ""
    detected_type: str = ""

    findings: list = field(default_factory=list)


# Magic bytes signatures
MAGIC_SIGNATURES = {
    b"MZ": "PE executable (Windows)",
    b"\x7fELF": "ELF executable (Linux)",
    b"PK\x03\x04": "ZIP archive",
    b"Rar!\x1a\x07": "RAR archive",
    b"\xd0\xcf\x11\xe0": "Microsoft Office (OLE2)",
    b"%PDF": "PDF document",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF8": "GIF image",
    b"#!/": "Shell script",
}

# Suspicious string patterns
SUSPICIOUS_PATTERNS = {
    "password_theft": [
        # Require full file path context, not bare words
        r"\\Login\s*Data", r"\\Web\s*Data",
        r"\\Mozilla\\Firefox\\Profiles", r"\\Google\\Chrome\\User Data",
        r"wallet\.dat",
        r"key3\.db", r"key4\.db", r"logins\.json", r"signons\.sqlite",
    ],
    "persistence": [
        r"CurrentVersion\\Run", r"CurrentVersion\\RunOnce",
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        r"schtasks\s*/create",
        r"\\Start Menu\\Programs\\Startup\\",
    ],
    "evasion": [
        r"IsDebuggerPresent", r"CheckRemoteDebuggerPresent",
        r"NtQueryInformationProcess",
        r"wine_get_unix_file_name",
    ],
    "network": [
        r"InternetOpenA", r"InternetOpenW", r"HttpSendRequest",
        r"URLDownloadToFile",
        r"Invoke-WebRequest",
    ],
    "injection": [
        r"CreateRemoteThread", r"WriteProcessMemory", r"VirtualAllocEx",
        r"NtCreateThreadEx", r"QueueUserAPC",
    ],
    "crypto": [
        r"CryptEncrypt", r"CryptDecrypt", r"CryptAcquireContext",
        r"\bAES[-_]?(128|256|CBC|GCM)\b", r"\bRSA[-_]?(2048|4096|OAEP)\b",
        r"\bbitcoin\b", r"\bmonero\b", r"\bethereum\b", r"\bwallet\.dat\b",
    ],
    "keylogger": [
        r"GetAsyncKeyState", r"SetWindowsHookExA.*WH_KEYBOARD",
        r"GetKeyboardState", r"\bkeylog",
    ],
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0-8 scale)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII and Unicode strings."""
    # ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    strings = [s.decode("ascii", errors="ignore") for s in ascii_pattern.findall(data)]

    # Unicode (UTF-16LE) strings
    unicode_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    for match in unicode_pattern.findall(data):
        try:
            strings.append(match.decode("utf-16le").rstrip("\x00"))
        except Exception:
            pass

    return list(set(strings))


def classify_strings(strings: list[str]) -> dict:
    """Classify extracted strings into categories."""
    result = {
        "urls": [],
        "ip_addresses": [],
        "emails": [],
        "file_paths": [],
        "registry_keys": [],
        "suspicious": [],
    }

    url_re = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.I)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    email_re = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
    path_re = re.compile(r"[A-Z]:\\[\w\\. -]+", re.I)
    reg_re = re.compile(r"(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[\w\\]+", re.I)

    seen_suspicious = set()

    for s in strings:
        for url in url_re.findall(s):
            if url not in result["urls"]:
                result["urls"].append(url)
        for ip in ip_re.findall(s):
            if ip not in result["ip_addresses"] and not ip.startswith(("0.", "127.", "255.")):
                result["ip_addresses"].append(ip)
        for email in email_re.findall(s):
            if email not in result["emails"]:
                result["emails"].append(email)
        for path in path_re.findall(s):
            if path not in result["file_paths"]:
                result["file_paths"].append(path)
        for reg in reg_re.findall(s):
            if reg not in result["registry_keys"]:
                result["registry_keys"].append(reg)

        # Check suspicious patterns
        for category, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, s, re.I):
                    key = f"{category}:{s[:80]}"
                    if key not in seen_suspicious:
                        seen_suspicious.add(key)
                        result["suspicious"].append({
                            "category": category,
                            "match": s[:120],
                            "pattern": pattern,
                        })

    return result


def detect_file_type(data: bytes) -> str:
    """Detect file type from magic bytes."""
    for magic, name in MAGIC_SIGNATURES.items():
        if data[:len(magic)] == magic:
            return name
    return "unknown"


def analyze(file_path: str) -> GenericAnalysis:
    """Perform generic analysis on any file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        data = f.read()

    result = GenericAnalysis(
        file_path=file_path,
        file_name=os.path.basename(file_path),
        file_size=len(data),
    )

    # Hashes
    result.md5 = hashlib.md5(data).hexdigest()
    result.sha1 = hashlib.sha1(data).hexdigest()
    result.sha256 = hashlib.sha256(data).hexdigest()

    # File type (detect early — needed for entropy verdict)
    result.magic_bytes = data[:4].hex()
    result.detected_type = detect_file_type(data)
    result.file_type = result.detected_type

    # Known compressed/media formats where high entropy is normal
    _COMPRESSED_TYPES = {"ZIP archive", "RAR archive", "PNG image", "JPEG image", "GIF image"}
    is_compressed_type = result.detected_type in _COMPRESSED_TYPES

    # Entropy
    result.entropy = calculate_entropy(data)
    if result.entropy > 7.5:
        if is_compressed_type:
            result.entropy_verdict = "compressed"
            # High entropy is expected for archives/media — not suspicious
        else:
            result.entropy_verdict = "encrypted/packed"
            result.findings.append(f"Very high entropy ({result.entropy}) — likely encrypted or packed")
    elif result.entropy > 6.5:
        result.entropy_verdict = "compressed"
    else:
        result.entropy_verdict = "normal"

    # Strings — skip extraction for archives (compressed data produces garbage matches)
    if is_compressed_type:
        all_strings = []
        classified = {"urls": [], "ip_addresses": [], "emails": [], "file_paths": [], "registry_keys": [], "suspicious": []}
    else:
        all_strings = extract_strings(data)
        classified = classify_strings(all_strings)

    result.urls = classified["urls"]
    result.ip_addresses = classified["ip_addresses"]
    result.emails = classified["emails"]
    result.file_paths = classified["file_paths"]
    result.registry_keys = classified["registry_keys"]
    result.suspicious_strings = classified["suspicious"]

    # Generate findings
    if result.urls:
        result.findings.append(f"Contains {len(result.urls)} URLs")
    if result.ip_addresses:
        result.findings.append(f"Contains {len(result.ip_addresses)} IP addresses")
    if result.registry_keys:
        result.findings.append(f"References {len(result.registry_keys)} registry keys")
    for sus in result.suspicious_strings:
        result.findings.append(f"[{sus['category']}] {sus['match']}")

    return result
