"""YARA rule scanning integration."""

import os
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

RULES_DIR = os.path.join(os.path.dirname(__file__), "yara_rules")


@dataclass
class YARAResult:
    """YARA scan results."""
    matches: list = field(default_factory=list)
    findings: list = field(default_factory=list)


def scan(file_path: str) -> YARAResult:
    """Scan file against YARA rules."""
    result = YARAResult()

    if not HAS_YARA:
        logger.debug("yara-python not installed, skipping YARA scan")
        return result

    if not os.path.exists(RULES_DIR):
        return result

    rule_files = [f for f in os.listdir(RULES_DIR) if f.endswith(".yar")]
    if not rule_files:
        return result

    for rule_file in rule_files:
        rule_path = os.path.join(RULES_DIR, rule_file)
        try:
            rules = yara.compile(filepath=rule_path)
            matches = rules.match(file_path)
            for match in matches:
                meta = match.meta
                severity = meta.get("severity", "medium")
                category = meta.get("category", "unknown")
                description = meta.get("description", match.rule)

                result.matches.append({
                    "rule": match.rule,
                    "description": description,
                    "severity": severity,
                    "category": category,
                    "tags": list(match.tags) if match.tags else [],
                })
                result.findings.append(
                    f"[{category}] YARA: {description} (rule: {match.rule})"
                )
        except yara.Error as e:
            logger.debug("YARA error in %s: %s", rule_file, e)
        except Exception as e:
            logger.debug("Error scanning with %s: %s", rule_file, e)

    return result
