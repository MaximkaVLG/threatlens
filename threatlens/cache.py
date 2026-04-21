"""Analysis cache — instant results for previously scanned files.

Stores results by SHA256 hash. If the same file (or any file with the
same hash) is scanned again, returns cached result instantly.

Storage: SQLite database (zero dependencies, works everywhere).
"""

import os
import json
import time
import secrets
import sqlite3
import hashlib
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _resolve_stats_salt() -> str:
    """Read STATS_SALT from env; if missing, generate a per-process salt and warn.

    A stable hardcoded default would let anyone reproduce user hashes by
    guessing the salt, so we deliberately refuse that path. The trade-off
    is that unique-user counts reset on app restart — acceptable for a pet
    project and a loud signal to the operator to set STATS_SALT.
    """
    salt = os.environ.get("STATS_SALT", "").strip()
    if salt:
        return salt
    generated = secrets.token_hex(16)
    logger.warning(
        "STATS_SALT is not set — generated ephemeral per-process salt. "
        "Unique-user stats will reset on restart. Set STATS_SALT in the "
        "environment for stable cross-restart aggregation."
    )
    return generated


_STATS_SALT = _resolve_stats_salt()


def hash_client_ip(raw_ip: Optional[str]) -> str:
    """Return sha256(salt + ip) for privacy-preserving unique-user counting.

    Validates that `raw_ip` parses as IPv4/IPv6; if not, hashes the literal
    string anyway (keeps bucketing consistent even for malformed inputs).
    Empty/None -> empty string (skips the user from unique counts).
    """
    if not raw_ip:
        return ""
    try:
        ip = str(ipaddress.ip_address(raw_ip.strip()))
    except (ValueError, AttributeError):
        ip = str(raw_ip).strip()
        if not ip:
            return ""
    return hashlib.sha256((_STATS_SALT + ip).encode("utf-8")).hexdigest()

def _default_cache_path() -> str:
    """Determine cache DB path: env var > user cache dir > /tmp fallback."""
    env_dir = os.environ.get("THREATLENS_CACHE_DIR")
    if env_dir:
        return os.path.join(env_dir, "cache.db")
    # Platform-appropriate user cache directory
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        path = os.path.join(base, "threatlens", "cache.db")
    else:
        path = os.path.join(os.path.expanduser("~"), ".cache", "threatlens", "cache.db")
    # Verify we can write — fallback to /tmp for Docker/Railway
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Quick write test
        with open(path + ".test", "w") as f:
            f.write("ok")
        os.unlink(path + ".test")
        return path
    except (OSError, PermissionError):
        return os.path.join("/tmp", "threatlens_cache.db")


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
                    entropy REAL DEFAULT 0,
                    entropy_verdict TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_risk ON scan_cache(risk_level)
            """)
            # Migration for existing DBs that don't have entropy columns
            for col, ddl in (
                ("entropy", "ALTER TABLE scan_cache ADD COLUMN entropy REAL DEFAULT 0"),
                ("entropy_verdict", "ALTER TABLE scan_cache ADD COLUMN entropy_verdict TEXT DEFAULT ''"),
            ):
                try:
                    conn.execute(ddl)
                except sqlite3.OperationalError:
                    pass  # already exists
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    scan_type TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    file_size_bytes INTEGER,
                    client_ip_hash TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_ts ON scan_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_user ON scan_events(client_ip_hash)")

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

            cols = row.keys()
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
                "entropy": row["entropy"] if "entropy" in cols and row["entropy"] is not None else 0.0,
                "entropy_verdict": row["entropy_verdict"] if "entropy_verdict" in cols and row["entropy_verdict"] is not None else "",
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

        if isinstance(result, dict):
            entropy_val = result.get("entropy", 0.0)
            entropy_v = result.get("entropy_verdict", "")
        else:
            entropy_val = getattr(result, "entropy", 0.0)
            entropy_v = getattr(result, "entropy_verdict", "")

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO scan_cache
                (sha256, file_name, file_size, file_type, risk_score, risk_level,
                 findings, explanation, recommendations, heuristic_type,
                 heuristic_confidence, yara_matches, scan_time, entropy, entropy_verdict)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    risk_score=excluded.risk_score, risk_level=excluded.risk_level,
                    findings=excluded.findings, explanation=excluded.explanation,
                    recommendations=excluded.recommendations,
                    heuristic_type=excluded.heuristic_type,
                    heuristic_confidence=excluded.heuristic_confidence,
                    yara_matches=excluded.yara_matches,
                    scan_time=excluded.scan_time,
                    entropy=excluded.entropy,
                    entropy_verdict=excluded.entropy_verdict,
                    scan_count=scan_count + 1
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
                float(entropy_val or 0.0),
                entropy_v or "",
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

    def record_scan_event(
        self,
        scan_type: str,
        verdict: str,
        duration_ms: int,
        file_size_bytes: Optional[int] = None,
        client_ip_hash: str = "",
    ) -> None:
        """Insert one usage-telemetry row. Safe to call in a try/except wrapper."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO scan_events
                   (timestamp, scan_type, verdict, duration_ms, file_size_bytes, client_ip_hash)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    int(time.time()),
                    scan_type,
                    verdict,
                    int(duration_ms),
                    int(file_size_bytes) if file_size_bytes is not None else None,
                    client_ip_hash or "",
                ),
            )

    def get_usage_stats(self) -> dict:
        """Aggregate public metrics over scan_events. No per-scan rows exposed."""
        now = int(time.time())
        cutoff_24h = now - 24 * 3600
        cutoff_7d = now - 7 * 24 * 3600
        cutoff_30d = now - 30 * 24 * 3600

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            total_scans = conn.execute("SELECT COUNT(*) FROM scan_events").fetchone()[0]
            scans_24h = conn.execute(
                "SELECT COUNT(*) FROM scan_events WHERE timestamp >= ?", (cutoff_24h,)
            ).fetchone()[0]
            scans_7d = conn.execute(
                "SELECT COUNT(*) FROM scan_events WHERE timestamp >= ?", (cutoff_7d,)
            ).fetchone()[0]

            unique_total = conn.execute(
                "SELECT COUNT(DISTINCT client_ip_hash) FROM scan_events "
                "WHERE client_ip_hash != ''"
            ).fetchone()[0]
            unique_7d = conn.execute(
                "SELECT COUNT(DISTINCT client_ip_hash) FROM scan_events "
                "WHERE client_ip_hash != '' AND timestamp >= ?",
                (cutoff_7d,),
            ).fetchone()[0]

            # Threats: file 'suspicious'/'malicious', pcap anything != BENIGN,
            # hash_lookup never counts as a threat.
            threats = conn.execute(
                """SELECT COUNT(*) FROM scan_events
                   WHERE (scan_type = 'file' AND verdict IN ('suspicious','malicious'))
                      OR (scan_type = 'pcap' AND verdict != 'BENIGN')"""
            ).fetchone()[0]

            by_type = {"file": 0, "pcap": 0, "hash_lookup": 0}
            for row in conn.execute(
                "SELECT scan_type, COUNT(*) AS n FROM scan_events GROUP BY scan_type"
            ):
                by_type[row["scan_type"]] = row["n"]

            avg_row = conn.execute(
                "SELECT AVG(duration_ms) FROM scan_events"
            ).fetchone()
            avg_duration = float(avg_row[0]) if avg_row and avg_row[0] is not None else 0.0

            first_row = conn.execute(
                "SELECT MIN(timestamp) FROM scan_events"
            ).fetchone()
            first_scan_at = int(first_row[0]) if first_row and first_row[0] is not None else None

            # Daily buckets for the last 30 days. SQLite's date('now','unixepoch')
            # is UTC by default — matches our timestamp column semantics.
            daily_rows = conn.execute(
                """SELECT date(timestamp, 'unixepoch') AS d, COUNT(*) AS n
                   FROM scan_events
                   WHERE timestamp >= ?
                   GROUP BY d
                   ORDER BY d""",
                (cutoff_30d,),
            ).fetchall()
            daily_scans_last_30d = [{"date": r["d"], "count": r["n"]} for r in daily_rows]

        return {
            "total_scans": int(total_scans),
            "scans_last_7d": int(scans_7d),
            "scans_last_24h": int(scans_24h),
            "unique_users_total": int(unique_total),
            "unique_users_7d": int(unique_7d),
            "threats_detected_total": int(threats),
            "scans_by_type": by_type,
            "avg_scan_duration_ms": round(avg_duration, 1),
            "first_scan_at": first_scan_at,
            "daily_scans_last_30d": daily_scans_last_30d,
        }


# Global cache instance
_cache = None


def get_cache() -> AnalysisCache:
    global _cache
    if _cache is None:
        _cache = AnalysisCache()
    return _cache
