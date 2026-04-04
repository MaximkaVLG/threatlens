"""Script analyzer — analyzes Python, JavaScript, PowerShell, Batch, VBS files."""

import os
import re
from dataclasses import dataclass, field

SCRIPT_EXTENSIONS = {".py", ".js", ".ps1", ".bat", ".cmd", ".vbs", ".sh", ".rb", ".php"}

# Suspicious patterns by language/category
PATTERNS = {
    "obfuscation": [
        # Only flag eval/exec with encoding — bare eval() is common in legit code
        (r"\-e(nc)?\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command"),
        (r"Invoke-Expression", "PowerShell dynamic execution"),
        (r"iex\s", "PowerShell IEX (Invoke-Expression shorthand)"),
        (r"\[System\.Convert\]::FromBase64String", "PowerShell Base64 decode"),
        (r"fromCharCode\s*\([^)]{50,}", "Long char code construction (JS obfuscation)"),
        (r"(\\x[0-9a-fA-F]{2}){10,}", "Long hex-encoded string (10+ bytes)"),
        (r"(chr\(\d+\)\s*[\+\.&]\s*){5,}", "Character code concatenation chain"),
    ],
    "network": [
        (r"socket\.connect\s*\(", "Raw socket connection"),
        (r"Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient", "PowerShell HTTP requests"),
        (r"paramiko|fabric", "SSH library usage"),
    ],
    "file_access": [
        (r"AppData.*Chrome.*User Data|AppData.*Mozilla.*Profiles", "Browser profile data access"),
        (r"\\Login\s*Data|\\Web\s*Data", "Browser credential files"),
        (r"wallet\.dat|\.electrum|metamask.*keystore", "Cryptocurrency wallet access"),
        (r"\.ssh[/\\]id_rsa|\.ssh[/\\]id_ed25519", "SSH private key access"),
        (r"/etc/shadow", "System password file"),
        (r"\.aws[/\\]credentials", "AWS credentials access"),
    ],
    "system": [
        (r"reg\s+add\s+.*\\Run", "Registry autorun modification"),
        (r"schtasks\s*/create", "Scheduled task creation"),
        (r"net\s+user\s+/add|net\s+localgroup\s+administrators", "User account creation/elevation"),
        (r"sc\s+create|New-Service", "Service creation"),
    ],
    "keylogger": [
        (r"pynput\.keyboard|keyboard\.on_press", "Keyboard monitoring library"),
        (r"GetAsyncKeyState", "Low-level keyboard monitoring"),
        (r"ImageGrab\.grab", "Screen capture"),
    ],
    "persistence": [
        (r"CurrentVersion\\\\Run|CurrentVersion\\\\RunOnce", "Autorun registry key"),
        (r"\\Start Menu\\Programs\\Startup\\", "Startup folder drop"),
        (r"crontab\s+-e|@reboot", "Linux cron persistence"),
        (r"LaunchAgents|LaunchDaemons", "macOS persistence"),
    ],
    "data_exfiltration": [
        (r"smtplib\.SMTP\(|send_mail\(", "Email sending (possible exfiltration)"),
        (r"api\.telegram\.org/bot|discord\.com/api/webhooks", "Messenger bot (exfiltration channel)"),
        (r"transfer\.sh", "Anonymous file sharing service"),
    ],
}


@dataclass
class ScriptAnalysis:
    """Results from script analysis."""
    is_script: bool = False
    language: str = ""
    line_count: int = 0
    char_count: int = 0

    # Detected patterns
    obfuscation: list = field(default_factory=list)
    network_activity: list = field(default_factory=list)
    file_access: list = field(default_factory=list)
    system_commands: list = field(default_factory=list)
    keylogger_patterns: list = field(default_factory=list)
    persistence_patterns: list = field(default_factory=list)
    exfiltration_patterns: list = field(default_factory=list)

    # Obfuscation metrics
    avg_line_length: float = 0.0
    max_line_length: int = 0
    is_obfuscated: bool = False

    findings: list = field(default_factory=list)


LANG_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ps1": "PowerShell",
    ".bat": "Batch", ".cmd": "Batch", ".vbs": "VBScript",
    ".sh": "Bash", ".rb": "Ruby", ".php": "PHP",
}


def analyze(file_path: str) -> ScriptAnalysis:
    """Analyze a script file."""
    result = ScriptAnalysis()

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in SCRIPT_EXTENSIONS:
        return result

    result.is_script = True
    result.language = LANG_MAP.get(ext, "Unknown")

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        result.findings.append("Could not read file as text")
        return result

    lines = content.split("\n")
    result.line_count = len(lines)
    result.char_count = len(content)

    # Obfuscation detection
    line_lengths = [len(line) for line in lines if line.strip()]
    if line_lengths:
        result.avg_line_length = sum(line_lengths) / len(line_lengths)
        result.max_line_length = max(line_lengths)

        # Very long single lines = likely obfuscated
        if result.max_line_length > 1000 and result.line_count < 20:
            result.is_obfuscated = True
            result.findings.append(
                f"Likely obfuscated: {result.line_count} lines, max line {result.max_line_length} chars"
            )

    # Pattern matching
    category_map = {
        "obfuscation": result.obfuscation,
        "network": result.network_activity,
        "file_access": result.file_access,
        "system": result.system_commands,
        "keylogger": result.keylogger_patterns,
        "persistence": result.persistence_patterns,
        "data_exfiltration": result.exfiltration_patterns,
    }

    for category, patterns in PATTERNS.items():
        for pattern, description in patterns:
            matches = re.findall(pattern, content, re.I)
            if matches:
                entry = {
                    "pattern": description,
                    "count": len(matches),
                    "sample": matches[0] if isinstance(matches[0], str) else str(matches[0]),
                }
                category_map[category].append(entry)
                result.findings.append(f"[{category}] {description} ({len(matches)} occurrences)")

    return result
