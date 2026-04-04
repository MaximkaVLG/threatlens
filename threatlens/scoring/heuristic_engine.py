"""Heuristic Engine — behavioral analysis based on combination of indicators.

Unlike YARA (exact pattern matching), the heuristic engine evaluates
the COMBINATION of behaviors to classify unknown threats.

Think of it like a doctor: not one symptom, but a pattern of symptoms
leads to a diagnosis. A file that is packed, unsigned, accesses Chrome
passwords, and has network calls is 95% a stealer — even without
matching any specific YARA rule.
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class HeuristicVerdict:
    """Result of heuristic analysis."""
    threat_type: str = ""  # stealer, rat, ransomware, miner, dropper, clean
    confidence: float = 0.0  # 0.0 - 1.0
    matching_behaviors: list = field(default_factory=list)
    explanation_key: str = ""  # Key for explanation lookup


# Each heuristic profile defines:
# - required: behaviors that MUST be present (AND)
# - optional: behaviors that increase confidence (OR)
# - weight: how much each optional behavior adds
# - min_score: minimum to trigger this profile

HEURISTIC_PROFILES = {
    "stealer": {
        "description": "Password/data stealer",
        "required_any": [  # At least one MUST match
            "accesses_browser_data",
            "accesses_crypto_wallets",
        ],
        "required_also": [  # At least one of these too (stealer = access + exfil)
            "has_exfiltration_channel",
            "has_network_capability",
        ],
        "optional": [
            ("has_exfiltration_channel", 0.15),
            ("is_packed", 0.05),
            ("has_obfuscation", 0.05),
            ("accesses_browser_data", 0.10),
            ("accesses_crypto_wallets", 0.10),
            ("accesses_discord", 0.10),
            ("accesses_telegram_data", 0.10),
            ("accesses_ssh_keys", 0.10),
            ("accesses_game_platforms", 0.05),
        ],
        "base_confidence": 0.50,
        "explanation_key": "password_theft",
    },
    "rat": {
        "description": "Remote Access Trojan",
        "required_any": [
            "has_injection_capability",
            "has_reverse_shell",
        ],
        "optional": [
            ("has_network_capability", 0.15),
            ("has_persistence", 0.15),
            ("has_keylogger", 0.10),
            ("has_process_manipulation", 0.10),
            ("has_anti_debug", 0.10),
            ("is_packed", 0.05),
            ("has_privilege_escalation", 0.10),
            ("has_reverse_shell", 0.15),
        ],
        "base_confidence": 0.40,
        "explanation_key": "injection",
    },
    "ransomware": {
        "description": "Ransomware / file encryptor",
        "required_any": [
            "has_crypto_operations",
        ],
        "optional": [
            ("has_file_operations", 0.15),
            ("has_persistence", 0.10),
            ("has_network_capability", 0.10),
            ("mentions_ransom", 0.25),
            ("mentions_bitcoin", 0.15),
            ("has_obfuscation", 0.10),
            ("no_signature", 0.05),
        ],
        "base_confidence": 0.30,
        "explanation_key": "crypto",
    },
    "miner": {
        "description": "Cryptocurrency miner",
        "required_any": [
            "mentions_mining",
        ],
        "optional": [
            ("has_network_capability", 0.10),
            ("has_persistence", 0.10),
            ("is_packed", 0.05),
            ("high_entropy", 0.05),
            ("has_anti_debug", 0.05),
            ("has_download_and_execute", 0.05),
        ],
        "base_confidence": 0.70,
        "explanation_key": "crypto",
    },
    "dropper": {
        "description": "Payload dropper/downloader",
        "required_any": [
            "has_download_and_execute",
            "has_obfuscation_exec",
        ],
        "optional": [
            ("has_persistence", 0.15),
            ("is_packed", 0.05),
            ("has_obfuscation", 0.10),
            ("has_obfuscation_exec", 0.10),
            ("has_network_capability", 0.10),
            ("has_download_and_execute", 0.10),
        ],
        "base_confidence": 0.50,
        "explanation_key": "network",
    },
    "keylogger": {
        "description": "Keylogger / spyware",
        "required_any": [
            "has_keylogger",
        ],
        "optional": [
            ("has_network_capability", 0.15),
            ("has_exfiltration_channel", 0.20),
            ("has_persistence", 0.10),
            ("has_screenshot_capability", 0.15),
            ("has_clipboard_access", 0.10),
        ],
        "base_confidence": 0.50,
        "explanation_key": "keylogger",
    },
}


def _extract_behaviors(generic_analysis, pe_analysis, script_analysis, findings: list) -> set:
    """Extract behavioral indicators from all analysis results."""
    behaviors = set()
    findings_lower = " ".join(findings).lower()

    # From generic analysis
    if generic_analysis:
        from threatlens.analyzers.generic_analyzer import COMPRESSED_TYPES
        if generic_analysis.entropy > 7.5 and generic_analysis.file_type not in COMPRESSED_TYPES:
            behaviors.add("high_entropy")
        # URLs/IPs alone are not suspicious — many legit programs have them
        if len(generic_analysis.ip_addresses) >= 3:
            behaviors.add("has_network_capability")

        for sus in generic_analysis.suspicious_strings:
            cat = sus.get("category", "")
            if cat == "password_theft":
                behaviors.add("accesses_browser_data")
                behaviors.add("accesses_credentials")
            elif cat == "persistence":
                behaviors.add("has_persistence")
            elif cat == "evasion":
                behaviors.add("has_anti_debug")
            elif cat == "network":
                behaviors.add("has_network_capability")
            elif cat == "injection":
                behaviors.add("has_injection_capability")
            elif cat == "crypto":
                behaviors.add("has_crypto_operations")
            elif cat == "keylogger":
                behaviors.add("has_keylogger")

    # From PE analysis
    if pe_analysis:
        if pe_analysis.is_packed:
            behaviors.add("is_packed")
        if not pe_analysis.has_signature:
            behaviors.add("no_signature")

        for imp in pe_analysis.suspicious_imports:
            cat = imp.get("category", "")
            if cat == "injection":
                behaviors.add("has_injection_capability")
            elif cat == "keylogger":
                behaviors.add("has_keylogger")
            elif cat == "network":
                behaviors.add("has_network_capability")
            elif cat == "anti_debug":
                behaviors.add("has_anti_debug")
            elif cat == "registry":
                behaviors.add("has_persistence")
            elif cat == "process_manipulation":
                behaviors.add("has_process_manipulation")
            elif cat == "privilege_escalation":
                behaviors.add("has_privilege_escalation")
            elif cat == "crypto":
                behaviors.add("has_crypto_operations")
            elif cat == "file_operations":
                behaviors.add("has_file_operations")
            elif cat == "hooking":
                behaviors.add("has_injection_capability")
            elif cat == "service":
                behaviors.add("has_persistence")

    # From script analysis
    if script_analysis:
        if script_analysis.is_obfuscated:
            behaviors.add("has_obfuscation")
        if script_analysis.obfuscation:
            behaviors.add("has_obfuscation")
            # Check for exec/eval with encoding — strong dropper indicator
            for o in script_analysis.obfuscation:
                pat = o.get("pattern", "").lower()
                if "eval" in pat or "exec" in pat or "invoke-expression" in pat:
                    behaviors.add("has_obfuscation_exec")
        if script_analysis.network_activity:
            behaviors.add("has_network_capability")
        if script_analysis.file_access:
            # Only flag as browser access if pattern actually matches browser paths
            for fa in script_analysis.file_access:
                pat = fa.get("pattern", "").lower()
                if "browser" in pat or "chrome" in pat or "firefox" in pat or "login" in pat:
                    behaviors.add("accesses_browser_data")
                elif "wallet" in pat or "electrum" in pat or "metamask" in pat:
                    behaviors.add("accesses_crypto_wallets")
                elif "ssh" in pat or "id_rsa" in pat:
                    behaviors.add("accesses_ssh_keys")
        if script_analysis.keylogger_patterns:
            behaviors.add("has_keylogger")
        if script_analysis.persistence_patterns:
            behaviors.add("has_persistence")
        if script_analysis.exfiltration_patterns:
            behaviors.add("has_exfiltration_channel")
        # system_commands alone is not "download and execute" — need network + system together
        if script_analysis.system_commands and script_analysis.network_activity:
            behaviors.add("has_download_and_execute")

        # Reverse shell detection: socket + subprocess/cmd + connect
        if script_analysis.network_activity and script_analysis.system_commands:
            # Check for socket.connect pattern
            for n in script_analysis.network_activity:
                if "socket" in n.get("pattern", "").lower():
                    behaviors.add("has_reverse_shell")
                    behaviors.add("has_injection_capability")
                    break

    # From findings text
    if "telegram" in findings_lower or "discord" in findings_lower:
        behaviors.add("has_exfiltration_channel")
    if "clipboard" in findings_lower or "pyperclip" in findings_lower:
        behaviors.add("has_clipboard_access")
    if "discord" in findings_lower and "token" in findings_lower:
        behaviors.add("accesses_discord")
    if "tdata" in findings_lower or "telegram desktop" in findings_lower:
        behaviors.add("accesses_telegram_data")
    if "wallet.dat" in findings_lower or "metamask" in findings_lower or "electrum" in findings_lower:
        behaviors.add("accesses_crypto_wallets")
    if "ssh" in findings_lower and ("id_rsa" in findings_lower or "private key" in findings_lower):
        behaviors.add("accesses_ssh_keys")
    if "steam" in findings_lower or "epic games" in findings_lower or "battle.net" in findings_lower:
        behaviors.add("accesses_game_platforms")
    if "ransom" in findings_lower or "your_files" in findings_lower or "decrypt" in findings_lower:
        behaviors.add("mentions_ransom")
    if "bitcoin" in findings_lower or "monero" in findings_lower or "btc" in findings_lower:
        behaviors.add("mentions_bitcoin")
    if "stratum" in findings_lower or "hashrate" in findings_lower or "xmrig" in findings_lower:
        behaviors.add("mentions_mining")
    if "screenshot" in findings_lower or "imagegrab" in findings_lower:
        behaviors.add("has_screenshot_capability")

    return behaviors


def analyze(generic_analysis=None, pe_analysis=None, script_analysis=None, findings: list = None) -> list[HeuristicVerdict]:
    """Run heuristic analysis based on behavioral indicators.

    Returns:
        List of HeuristicVerdict, sorted by confidence (highest first)
    """
    findings = findings or []
    behaviors = _extract_behaviors(generic_analysis, pe_analysis, script_analysis, findings)

    if not behaviors:
        return []

    verdicts = []

    for profile_name, profile in HEURISTIC_PROFILES.items():
        # Check required behaviors (at least one must match)
        has_required = any(req in behaviors for req in profile["required_any"])
        if not has_required:
            continue

        # Check secondary requirements if present
        if "required_also" in profile:
            has_also = any(req in behaviors for req in profile["required_also"])
            if not has_also:
                continue

        # Calculate confidence
        confidence = profile["base_confidence"]
        matching = []

        for req in profile["required_any"]:
            if req in behaviors:
                matching.append(req)

        for opt_behavior, weight in profile["optional"]:
            if opt_behavior in behaviors:
                confidence += weight
                matching.append(opt_behavior)

        confidence = min(confidence, 0.99)

        verdict = HeuristicVerdict(
            threat_type=profile_name,
            confidence=round(confidence, 2),
            matching_behaviors=matching,
            explanation_key=profile["explanation_key"],
        )
        verdicts.append(verdict)

    # Sort by confidence
    verdicts.sort(key=lambda v: v.confidence, reverse=True)

    if verdicts:
        top = verdicts[0]
        logger.info(
            "Heuristic: %s (%.0f%% confidence, %d behaviors)",
            top.threat_type, top.confidence * 100, len(top.matching_behaviors),
        )

    return verdicts
