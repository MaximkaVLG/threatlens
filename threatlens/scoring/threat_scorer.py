"""Threat scoring engine — calculates risk level from analysis results."""

from dataclasses import dataclass, field

RISK_WEIGHTS = {
    "injection": 30,
    "keylogger": 25,
    "password_theft": 25,
    "data_exfiltration": 20,
    "crypto": 15,
    "persistence": 15,
    "network": 10,
    "obfuscation": 10,
    "anti_debug": 10,
    "evasion": 10,
    "hooking": 15,
    "privilege_escalation": 20,
    "process_manipulation": 15,
    "system": 10,
    "file_access": 10,
    "file_operations": 5,
    "registry": 10,
    "service": 10,
}


@dataclass
class ThreatScore:
    """Overall threat assessment."""
    score: int = 0  # 0-100
    level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    categories: dict = field(default_factory=dict)
    summary: str = ""
    recommendations: list = field(default_factory=list)


def calculate_score(findings: list[str], generic_analysis=None, pe_analysis=None, script_analysis=None) -> ThreatScore:
    """Calculate threat score from all findings."""
    result = ThreatScore()
    category_hits = {}

    # Score from findings (only match explicit [category] tags, not substrings)
    for finding in findings:
        finding_lower = finding.lower()
        for category, weight in RISK_WEIGHTS.items():
            # Only match explicit tags like [injection], [network], [HEURISTIC]
            if f"[{category}]" in finding_lower:
                category_hits[category] = category_hits.get(category, 0) + weight

    # Bonus points from specific indicators
    # Known compressed types where high entropy is expected
    _COMPRESSED_TYPES = {"ZIP archive", "RAR archive", "PNG image", "JPEG image", "GIF image"}

    if generic_analysis:
        if generic_analysis.entropy > 7.5 and generic_analysis.file_type not in _COMPRESSED_TYPES:
            category_hits["packed"] = 15
        if generic_analysis.urls:
            category_hits["network"] = category_hits.get("network", 0) + len(generic_analysis.urls) * 3
        if generic_analysis.ip_addresses:
            category_hits["network"] = category_hits.get("network", 0) + len(generic_analysis.ip_addresses) * 5

    if pe_analysis:
        if pe_analysis.is_packed:
            category_hits["packed"] = category_hits.get("packed", 0) + 10
        if not pe_analysis.has_signature:
            category_hits["unsigned"] = 5
        if pe_analysis.suspicious_imports:
            for imp in pe_analysis.suspicious_imports:
                cat = imp["category"]
                category_hits[cat] = category_hits.get(cat, 0) + RISK_WEIGHTS.get(cat, 5)

    if script_analysis:
        if script_analysis.is_obfuscated:
            category_hits["obfuscation"] = category_hits.get("obfuscation", 0) + 20
        if script_analysis.keylogger_patterns:
            category_hits["keylogger"] = 30
        if script_analysis.exfiltration_patterns:
            category_hits["data_exfiltration"] = 25

    result.categories = category_hits
    result.score = min(100, sum(category_hits.values()))

    # Level
    if result.score >= 70:
        result.level = "CRITICAL"
    elif result.score >= 40:
        result.level = "HIGH"
    elif result.score >= 15:
        result.level = "MEDIUM"
    else:
        result.level = "LOW"

    # Summary
    if result.level == "CRITICAL":
        result.summary = "This file is almost certainly malicious."
        result.recommendations = [
            "DELETE this file immediately",
            "Do NOT execute it under any circumstances",
            "If already executed: change all passwords, run full antivirus scan",
            "Check for unauthorized processes in Task Manager",
        ]
    elif result.level == "HIGH":
        result.summary = "This file shows strong indicators of malicious behavior."
        result.recommendations = [
            "Do not execute this file",
            "Consider deleting it",
            "If you must use it, run in a virtual machine only",
        ]
    elif result.level == "MEDIUM":
        result.summary = "This file contains suspicious elements that warrant caution."
        result.recommendations = [
            "Proceed with caution",
            "Verify the source of this file",
            "Consider running in a sandbox before execution",
        ]
    else:
        result.summary = "This file appears to be low risk, but always exercise caution."
        result.recommendations = [
            "File appears safe based on static analysis",
            "Dynamic behavior may differ — use caution with unknown sources",
        ]

    return result
