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


_compiled_rules = None
_compiled_sources = {}


def _compile_all_rules():
    """Compile all YARA rules into a single ruleset (cached)."""
    global _compiled_rules, _compiled_sources

    if _compiled_rules is not None:
        return _compiled_rules

    if not HAS_YARA:
        return None

    rule_files = _collect_rule_files()
    if not rule_files:
        return None

    # Build sources dict: namespace -> filepath
    # Each file gets a unique namespace to avoid rule name collisions
    sources = {}
    for rule_path in rule_files:
        ns = os.path.splitext(os.path.basename(rule_path))[0]
        # Deduplicate namespace names
        base_ns = ns
        counter = 1
        while ns in sources:
            ns = f"{base_ns}_{counter}"
            counter += 1
        sources[ns] = rule_path

    # Compile all at once, skipping files with syntax errors
    compiled = None
    failed = set()

    # Try compiling all together first (fast path)
    try:
        compiled = yara.compile(filepaths=sources)
        _compiled_sources = sources
        logger.info("YARA: compiled %d rule files in single batch", len(sources))
    except yara.SyntaxError:
        # Some files have errors — compile individually to find good ones
        logger.debug("YARA batch compile failed, falling back to per-file compile")
        good_sources = {}
        for ns, path in sources.items():
            try:
                yara.compile(filepath=path)
                good_sources[ns] = path
            except Exception:
                failed.add(path)

        if good_sources:
            try:
                compiled = yara.compile(filepaths=good_sources)
                _compiled_sources = good_sources
            except Exception as e:
                logger.error("YARA compile failed: %s", e)

        if failed:
            logger.warning("YARA: skipped %d rule files with errors: %s",
                           len(failed), ", ".join(os.path.basename(f) for f in failed))

    _compiled_rules = compiled
    return compiled


_compiled_custom = None
_compiled_custom_sources = {}
_compiled_community = None
_compiled_community_sources = {}


def _compile_custom_rules():
    """Compile only custom ThreatLens rules (fast tier)."""
    global _compiled_custom, _compiled_custom_sources
    if _compiled_custom is not None:
        return _compiled_custom
    if not HAS_YARA:
        return None

    sources = {}
    if os.path.exists(RULES_DIR):
        for f in os.listdir(RULES_DIR):
            if f.endswith((".yar", ".yara")):
                ns = os.path.splitext(f)[0]
                sources[ns] = os.path.join(RULES_DIR, f)

    if not sources:
        return None
    try:
        _compiled_custom = yara.compile(filepaths=sources)
        _compiled_custom_sources = sources
        logger.info("YARA custom: compiled %d rule files", len(sources))
    except Exception as e:
        logger.error("YARA custom compile error: %s", e)
    return _compiled_custom


def _compile_community_rules():
    """Compile community rules (slow tier)."""
    global _compiled_community, _compiled_community_sources
    if _compiled_community is not None:
        return _compiled_community
    if not HAS_YARA:
        return None

    sources = {}
    if os.path.exists(COMMUNITY_DIR):
        for category in COMMUNITY_CATEGORIES:
            cat_dir = os.path.join(COMMUNITY_DIR, category)
            if not os.path.isdir(cat_dir):
                continue
            for f in os.listdir(cat_dir):
                if f.endswith((".yar", ".yara")):
                    ns = os.path.splitext(f)[0]
                    base_ns = ns
                    counter = 1
                    while ns in sources:
                        ns = f"{base_ns}_{counter}"
                        counter += 1
                    sources[ns] = os.path.join(cat_dir, f)

    if not sources:
        return None

    failed = set()
    try:
        _compiled_community = yara.compile(filepaths=sources)
        _compiled_community_sources = sources
        logger.info("YARA community: compiled %d rule files", len(sources))
    except yara.SyntaxError:
        good_sources = {}
        for ns, path in sources.items():
            try:
                yara.compile(filepath=path)
                good_sources[ns] = path
            except Exception:
                failed.add(path)
        if good_sources:
            try:
                _compiled_community = yara.compile(filepaths=good_sources)
                _compiled_community_sources = good_sources
            except Exception as e:
                logger.error("YARA community compile failed: %s", e)
        if failed:
            logger.warning("YARA: skipped %d community rule files with errors", len(failed))

    return _compiled_community


def _match_rules(rules, file_path: str, result: YARAResult, seen_rules: set):
    """Run YARA match and append findings to result."""
    try:
        matches = rules.match(file_path, timeout=30, fast=True)
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
                "source": match.namespace,
                "tags": list(match.tags) if match.tags else [],
            })
            result.findings.append(
                f"[{category}] YARA: {description} (rule: {match.rule})"
            )
    except yara.TimeoutError:
        logger.warning("YARA scan timed out on %s", os.path.basename(file_path))
    except Exception as e:
        logger.error("YARA scan error: %s", e)


def scan(file_path: str) -> YARAResult:
    """Tiered YARA scan: custom rules first, community only if no matches found."""
    result = YARAResult()

    if not HAS_YARA:
        logger.debug("yara-python not installed, skipping YARA scan")
        return result

    # Also keep _compile_all_rules working for pre-warm
    _compile_all_rules()

    seen_rules = set()

    # Tier 1: Custom rules (fast — ~20 rules)
    custom = _compile_custom_rules()
    if custom:
        result.rules_loaded = len(_compiled_custom_sources)
        _match_rules(custom, file_path, result, seen_rules)

    # Tier 2: Community rules — only if custom found nothing
    if not result.matches:
        community = _compile_community_rules()
        if community:
            result.rules_loaded += len(_compiled_community_sources)
            _match_rules(community, file_path, result, seen_rules)

    if result.matches:
        logger.info("YARA: %d matches from %d rule files", len(result.matches), result.rules_loaded)

    return result
