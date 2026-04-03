"""Script analyzer — analyzes Python, JavaScript, PowerShell, Batch, VBS files."""

import os
import re
from dataclasses import dataclass, field

SCRIPT_EXTENSIONS = {".py", ".js", ".ps1", ".bat", ".cmd", ".vbs", ".sh", ".rb", ".php"}

# Suspicious patterns by language/category
PATTERNS = {
    "obfuscation": [
        (r"eval\s*\(", "eval() — dynamic code execution"),
        (r"exec\s*\(", "exec() — dynamic code execution"),
        (r"base64", "Base64 encoding (possible obfuscation)"),
        (r"\\x[0-9a-fA-F]{2}", "Hex-encoded strings"),
        (r"fromCharCode", "String construction from char codes (JS obfuscation)"),
        (r"atob\s*\(", "Base64 decode (JS)"),
        (r"\-e(nc)?\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command"),
        (r"Invoke-Expression", "PowerShell dynamic execution"),
        (r"iex\s", "PowerShell IEX (Invoke-Expression shorthand)"),
        (r"[System.Convert]::FromBase64String", "PowerShell Base64 decode"),
        (r"chr\(\d+\)", "Character code construction"),
    ],
    "network": [
        (r"urllib\.request|requests\.(get|post)|httpx\.(get|post)", "Python HTTP requests"),
        (r"fetch\s*\(|XMLHttpRequest|axios", "JavaScript HTTP requests"),
        (r"Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient", "PowerShell HTTP requests"),
        (r"curl\s|wget\s", "Command-line download"),
        (r"socket\.(socket|connect)", "Raw socket connection"),
        (r"paramiko|fabric|ssh", "SSH library usage"),
    ],
    "file_access": [
        (r"AppData.*Chrome|AppData.*Firefox|AppData.*Mozilla", "Browser data access"),
        (r"Login\s*Data|Cookies|Web\s*Data", "Browser credential files"),
        (r"wallet\.dat|electrum|metamask", "Cryptocurrency wallet access"),
        (r"\.ssh[/\\]|id_rsa|authorized_keys", "SSH key access"),
        (r"shadow|passwd|/etc/password", "System credential files"),
        (r"\.aws[/\\]credentials|\.env", "Cloud/environment credentials"),
    ],
    "system": [
        (r"subprocess\.(run|call|Popen)|os\.system|os\.popen", "Python system command execution"),
        (r"child_process|spawn|execSync", "Node.js command execution"),
        (r"Start-Process|cmd\s*/c|powershell\s+-", "Windows command execution"),
        (r"reg\s+add|regedit", "Registry modification"),
        (r"schtasks\s*/create|at\s+\d", "Scheduled task creation"),
        (r"net\s+user|net\s+localgroup", "User account manipulation"),
        (r"sc\s+create|New-Service", "Service creation"),
    ],
    "keylogger": [
        (r"pynput|keyboard\.on_press|GetAsyncKeyState", "Keyboard monitoring"),
        (r"pyautogui|screenshot|ImageGrab", "Screen capture"),
        (r"pyperclip|clipboard", "Clipboard access"),
    ],
    "persistence": [
        (r"\\Run\\|\\RunOnce\\", "Autorun registry key"),
        (r"Startup|startup", "Startup folder"),
        (r"crontab|@reboot|systemctl\s+enable", "Linux persistence"),
        (r"launchd|LaunchAgents|LaunchDaemons", "macOS persistence"),
    ],
    "data_exfiltration": [
        (r"smtp|smtplib|send_mail", "Email sending (possible exfiltration)"),
        (r"telegram.*bot|discord.*webhook|api\.telegram", "Messenger bot (exfiltration channel)"),
        (r"pastebin|hastebin|transfer\.sh", "Data sharing service"),
        (r"ftp\.|ftplib|sftp", "FTP transfer"),
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
