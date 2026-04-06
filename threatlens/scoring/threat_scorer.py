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

    # Nested encrypted archive = very high suspicion
    findings_text = " ".join(findings).lower()
    if "nested encrypted archive" in findings_text:
        category_hits["evasion"] = category_hits.get("evasion", 0) + 40
    if "could not be fully analyzed" in findings_text and "malicious" in findings_text:
        category_hits["obfuscation"] = category_hits.get("obfuscation", 0) + 30

    # Bonus points from specific indicators
    from threatlens.analyzers.generic_analyzer import COMPRESSED_TYPES

    if generic_analysis:
        if generic_analysis.entropy > 7.5 and generic_analysis.file_type not in COMPRESSED_TYPES:
            category_hits["packed"] = 15

    if pe_analysis:
        if pe_analysis.is_packed:
            category_hits["packed"] = category_hits.get("packed", 0) + 10
        # Score suspicious imports once per category (not per function)
        if pe_analysis.suspicious_imports:
            seen_cats = set()
            for imp in pe_analysis.suspicious_imports:
                cat = imp["category"]
                if cat not in seen_cats:
                    seen_cats.add(cat)
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
        result.summary = "Этот файл почти наверняка является вредоносным."
        result.recommendations = [
            "НЕМЕДЛЕННО УДАЛИТЕ этот файл",
            "НЕ запускайте его ни при каких обстоятельствах",
            "Если уже запускали: смените все пароли и проведите полное антивирусное сканирование",
            "Проверьте Диспетчер задач на наличие подозрительных процессов",
        ]
    elif result.level == "HIGH":
        result.summary = "Файл содержит явные признаки вредоносного поведения."
        result.recommendations = [
            "Не запускайте этот файл",
            "Рекомендуется удалить его",
            "Если необходимо использовать — запускайте только в виртуальной машине",
        ]
    elif result.level == "MEDIUM":
        result.summary = "Файл содержит подозрительные элементы, требующие осторожности."
        result.recommendations = [
            "Действуйте с осторожностью",
            "Проверьте источник этого файла",
            "Перед запуском рекомендуется проверить в песочнице (sandbox)",
        ]
    else:
        result.summary = "Файл выглядит безопасным, но всегда соблюдайте осторожность."
        result.recommendations = [
            "По результатам статического анализа файл безопасен",
            "Поведение при запуске может отличаться — будьте осторожны с файлами из неизвестных источников",
        ]

    return result
