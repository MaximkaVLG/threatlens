"""Analysis cache — instant results for previously scanned files.

Stores results by SHA256 hash. If the same file (or any file with the
same hash) is scanned again, returns cached result instantly.

Storage: SQLite database (zero dependencies, works everywhere).
"""

import os
import json
import time
import sqlite3
import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def _default_cache_path() -> str:
    """Determine cache DB path: env var > user cache dir > in-tree fallback."""
    env_dir = os.environ.get("THREATLENS_CACHE_DIR")
    if env_dir:
        return os.path.join(env_dir, "cache.db")
    # Platform-appropriate user cache directory
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        return os.path.join(base, "threatlens", "cache.db")
    return os.path.join(os.path.expanduser("~"), ".cache", "threatlens", "cache.db")


DEFAULT_DB_PATH = _default_cache_path()


class AnalysisCache:
    """SQLite-backed analysis result cache."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        except OSError:
            # Fall back to in-tree data/ if user cache dir is not writable
            fallback = os.path.join(os.path.dirname(__file__), "..", "data", "cache.db")
            os.makedirs(os.path.dirname(fallback), exist_ok=True)
            self.db_path = fallback
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_cache (
                    sha256 TEXT PRIMARY KEY,
                    file_name TEXT,
                    file_size INTEGER,
                    file_type TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    findings TEXT,
                    explanation TEXT,
                    recommendations TEXT,
                    heuristic_type TEXT,
                    heuristic_confidence REAL,
                    yara_matches TEXT,
                    scan_time REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_risk ON scan_cache(risk_level)
            """)

    def get(self, sha256: str) -> Optional[dict]:
        """Get cached result by SHA256 hash. Returns None if not found."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM scan_cache WHERE sha256 = ?", (sha256,)
            ).fetchone()

            if not row:
                return None

            # Update scan count
            conn.execute(
                "UPDATE scan_cache SET scan_count = scan_count + 1 WHERE sha256 = ?",
                (sha256,)
            )

            return {
                "sha256": row["sha256"],
                "file": row["file_name"],
                "size": row["file_size"],
                "type": row["file_type"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "findings": json.loads(row["findings"]),
                "explanation": row["explanation"],
                "recommendations": json.loads(row["recommendations"]),
                "heuristic_type": row["heuristic_type"],
                "heuristic_confidence": row["heuristic_confidence"],
                "yara_matches": json.loads(row["yara_matches"]),
                "scan_time": row["scan_time"],
                "scan_count": row["scan_count"],
                "cached": True,
            }

    def put(self, result, scan_time: float = 0.0):
        """Store analysis result in cache."""
        sha256 = result.sha256 if hasattr(result, "sha256") else result.get("sha256", "")
        if not sha256:
            return

        heuristic_type = ""
        heuristic_conf = 0.0
        if hasattr(result, "heuristic_verdicts") and result.heuristic_verdicts:
            heuristic_type = result.heuristic_verdicts[0].threat_type
            heuristic_conf = result.heuristic_verdicts[0].confidence
        elif isinstance(result, dict) and result.get("heuristic_type"):
            heuristic_type = result["heuristic_type"]
            heuristic_conf = result.get("heuristic_confidence", 0)

        findings = result.findings if hasattr(result, "findings") else result.get("findings", [])
        recommendations = result.recommendations if hasattr(result, "recommendations") else result.get("recommendations", [])
        explanation = result.explanation if hasattr(result, "explanation") else result.get("explanation", "")
        yara = [m["rule"] for m in result.yara_matches] if hasattr(result, "yara_matches") else result.get("yara_matches", [])

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO scan_cache
                (sha256, file_name, file_size, file_type, risk_score, risk_level,
                 findings, explanation, recommendations, heuristic_type,
                 heuristic_confidence, yara_matches, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    risk_score=excluded.risk_score, risk_level=excluded.risk_level,
                    findings=excluded.findings, explanation=excluded.explanation,
                    recommendations=excluded.recommendations,
                    heuristic_type=excluded.heuristic_type,
                    heuristic_confidence=excluded.heuristic_confidence,
                    yara_matches=excluded.yara_matches,
                    scan_time=excluded.scan_time,
                    scan_count=scan_count + 1,
                    last_seen=CURRENT_TIMESTAMP
            """, (
                sha256,
                result.file if hasattr(result, "file") else result.get("file", ""),
                result.size if hasattr(result, "size") else result.get("size", 0),
                result.file_type if hasattr(result, "file_type") else result.get("type", ""),
                result.risk_score if hasattr(result, "risk_score") else result.get("risk_score", 0),
                result.risk_level if hasattr(result, "risk_level") else result.get("risk_level", "LOW"),
                json.dumps(findings, ensure_ascii=False),
                explanation,
                json.dumps(recommendations, ensure_ascii=False),
                heuristic_type,
                heuristic_conf,
                json.dumps(yara, ensure_ascii=False),
                scan_time,
            ))

        logger.debug("Cached result for %s", sha256[:16])

    def get_stats(self) -> dict:
        """Get cache statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()[0]
            by_level = {}
            for row in conn.execute("SELECT risk_level, COUNT(*) FROM scan_cache GROUP BY risk_level"):
                by_level[row[0]] = row[1]
            total_scans = conn.execute("SELECT SUM(scan_count) FROM scan_cache").fetchone()[0] or 0

        return {
            "total_files": total,
            "total_scans": total_scans,
            "cache_hits": total_scans - total,
            "by_risk_level": by_level,
        }

    def search(self, sha256_prefix: str) -> list[dict]:
        """Search cache by SHA256 prefix."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT sha256, file_name, risk_level, risk_score, created_at "
                "FROM scan_cache WHERE sha256 LIKE ? LIMIT 20",
                (sha256_prefix + "%",)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_history(self, limit: int = 50) -> list[dict]:
        """Get recent scan history sorted by last activity."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT sha256, file_name, file_size, file_type,
                          risk_score, risk_level, heuristic_type,
                          scan_count, created_at
                   FROM scan_cache
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]


# Global cache instance
_cache = None


def get_cache() -> AnalysisCache:
    global _cache
    if _cache is None:
        _cache = AnalysisCache()
    return _cache
