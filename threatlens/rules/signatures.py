"""YARA rule scanning integration.

Scans files against:
1. Custom ThreatLens rules (yara_rules/)
2. Community rules from YARA-Rules project (yara_community/, 566 files)
"""

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
COMMUNITY_DIR = os.path.join(os.path.dirname(__file__), "yara_community")

# Community rule directories to scan (skip deprecated and broken)
COMMUNITY_CATEGORIES = [
    "malware",
    "crypto",
    "cve_rules",
    "capabilities",
    "antidebug_antivm",
    "packers",
    "webshells",
    "email",
]


@dataclass
class YARAResult:
    """YARA scan results."""
    matches: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    rules_loaded: int = 0


def _collect_rule_files() -> list[str]:
    """Collect all YARA rule files from custom and community directories."""
    rule_files = []

    # Custom rules (always loaded)
    if os.path.exists(RULES_DIR):
        for f in os.listdir(RULES_DIR):
            if f.endswith((".yar", ".yara")):
                rule_files.append(os.path.join(RULES_DIR, f))

    # Community rules
    if os.path.exists(COMMUNITY_DIR):
        for category in COMMUNITY_CATEGORIES:
            cat_dir = os.path.join(COMMUNITY_DIR, category)
            if not os.path.isdir(cat_dir):
                continue
            for f in os.listdir(cat_dir):
                if f.endswith((".yar", ".yara")):
                    rule_files.append(os.path.join(cat_dir, f))

    return rule_files


def scan(file_path: str) -> YARAResult:
    """Scan file against all YARA rules (custom + community)."""
    result = YARAResult()

    if not HAS_YARA:
        logger.debug("yara-python not installed, skipping YARA scan")
        return result

    rule_files = _collect_rule_files()
    if not rule_files:
        return result

    result.rules_loaded = len(rule_files)
    seen_rules = set()

    for rule_path in rule_files:
        try:
            rules = yara.compile(filepath=rule_path)
            matches = rules.match(file_path, timeout=10)
            for match in matches:
                if match.rule in seen_rules:
                    continue
                seen_rules.add(match.rule)

                meta = match.meta
                severity = meta.get("severity", meta.get("threat_level", "medium"))
                category = meta.get("category", "unknown")
                description = meta.get("description", match.rule)
                author = meta.get("author", "")

                result.matches.append({
                    "rule": match.rule,
                    "description": description,
                    "severity": severity,
                    "category": category,
                    "author": author,
                    "source": os.path.basename(os.path.dirname(rule_path)),
                    "tags": list(match.tags) if match.tags else [],
                })
                result.findings.append(
                    f"[{category}] YARA: {description} (rule: {match.rule})"
                )
        except yara.SyntaxError as e:
            # Some community rules have syntax issues — skip silently
            logger.debug("YARA syntax error in %s: %s", os.path.basename(rule_path), e)
        except yara.TimeoutError:
            logger.debug("YARA timeout on %s", os.path.basename(rule_path))
        except Exception as e:
            logger.debug("YARA error in %s: %s", os.path.basename(rule_path), e)

    if result.matches:
        logger.info("YARA: %d matches from %d rule files", len(result.matches), result.rules_loaded)

    return result
