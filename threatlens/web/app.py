"""ThreatLens Web UI — Upload files and get threat analysis.

Security: file size limit, rate limiting, safe temp file handling.
"""

import os
import re
import time
import asyncio
import logging
import tempfile
from collections import defaultdict

logger = logging.getLogger(__name__)

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{1,64}$")

from contextlib import asynccontextmanager

@asynccontextmanager
async def _lifespan(application):
    """Pre-compile YARA rules on startup so first scan is fast."""
    def _compile():
        try:
            from threatlens.rules.signatures import _compile_all_rules
            _compile_all_rules()
            logger.info("YARA rules pre-compiled on startup")
        except Exception as e:
            logger.warning("YARA pre-warm failed: %s", e)
    await asyncio.to_thread(_compile)
    yield

app = FastAPI(title="ThreatLens", description="AI-Powered File Threat Analyzer", lifespan=_lifespan)

# CORS — restrict to same origin by default, allow configured origins
ALLOWED_ORIGINS = os.environ.get("CORS_ORIGINS", "").split(",") if os.environ.get("CORS_ORIGINS") else []
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# Security headers on every response
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Health check for Railway/Docker
@app.get("/health")
async def health():
    import shutil
    has_7z = shutil.which("7z") is not None or shutil.which("7za") is not None
    return {"status": "ok", "7z_available": has_7z}

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Security limits
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 10  # requests per window

# Simple in-memory rate limiter
_rate_limits = defaultdict(list)

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


_rate_limit_last_sweep = 0.0

# Trusted proxy IPs — only accept X-Forwarded-For from these
_TRUSTED_PROXIES = {"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For behind trusted proxies."""
    direct_ip = request.client.host if request.client else "unknown"

    # Only trust X-Forwarded-For if coming from known proxy ranges
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # X-Forwarded-For: client, proxy1, proxy2 — first is the real client
        ips = [ip.strip() for ip in forwarded.split(",")]
        if ips:
            candidate = ips[0]
            # Basic validation: must look like an IP
            if candidate.replace(".", "").replace(":", "").isalnum():
                return candidate

    return direct_ip


def _check_rate_limit(client_ip: str) -> bool:
    """Check if client has exceeded rate limit."""
    global _rate_limit_last_sweep
    now = time.time()

    # Sweep ALL stale IPs every 5 minutes to prevent unbounded growth
    if now - _rate_limit_last_sweep > 300:
        _rate_limit_last_sweep = now
        stale = [ip for ip, ts in _rate_limits.items() if not ts or now - ts[-1] > RATE_LIMIT_WINDOW]
        for ip in stale:
            del _rate_limits[ip]

    # Clean current IP's old entries
    timestamps = [t for t in _rate_limits.get(client_ip, []) if now - t < RATE_LIMIT_WINDOW]
    if len(timestamps) >= RATE_LIMIT_MAX:
        return False
    timestamps.append(now)
    _rate_limits[client_ip] = timestamps
    return True


@app.post("/api/scan")
async def api_scan(request: Request, file: UploadFile = File(...), ai: bool = Form(False), password: str = Form("")):
    """Scan uploaded file via API."""
    # Rate limiting — use X-Forwarded-For behind reverse proxy (Railway, Cloudflare)
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Try again in 60 seconds.")

    # File size check (read in chunks)
    content = b""
    while chunk := await file.read(1024 * 1024):  # 1MB chunks
        content += chunk
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail=f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB")

    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    # Safe temp file
    suffix = os.path.splitext(file.filename or "file")[1]
    # Sanitize suffix
    suffix = suffix[:10] if suffix else ""
    if not all(c.isalnum() or c == "." for c in suffix):
        suffix = ".bin"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="tl_") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        from threatlens.core import analyze_file
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(analyze_file, tmp_path, True, password or None),
                timeout=120.0,  # 2 minute hard limit
            )
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Analysis timed out (2 min limit). Try a smaller file.")
        except (IsADirectoryError, FileNotFoundError, PermissionError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error("Analysis error: %s", e)
            raise HTTPException(status_code=500, detail="Analysis failed. Try a smaller file or different format.")

        # AI explanation (optional, async — non-blocking)
        ai_explanation = ""
        if ai:
            try:
                from threatlens.ai.providers import get_provider
                from threatlens.ai.prompts import THREAT_EXPLANATION_PROMPT
                prov = get_provider()
                prompt = THREAT_EXPLANATION_PROMPT.format(
                    findings="\n".join(f"- {f}" for f in result.findings[:20]) or "No findings",
                    filename=file.filename, filetype=result.file_type,
                    filesize=f"{result.size:,} bytes",
                    risk_score=result.risk_score, risk_level=result.risk_level,
                    categories="",
                )
                ai_explanation = await prov.explain_async(prompt)
            except Exception as e:
                logger.error("AI provider error: %s", e)
                ai_explanation = "AI explanation unavailable. Try again later."

        return JSONResponse({
            "file": file.filename,
            "size": result.size,
            "type": result.file_type,
            "md5": result.md5,
            "sha256": result.sha256,
            "entropy": result.entropy,
            "entropy_verdict": result.entropy_verdict,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "summary": result.summary,
            "findings": result.findings,
            "recommendations": result.recommendations,
            "explanation": result.explanation,
            "ai_explanation": ai_explanation,
            "yara_matches": [m["rule"] for m in result.yara_matches],
        })
    finally:
        os.unlink(tmp_path)


@app.get("/api/lookup/{sha256}")
async def api_lookup(sha256: str):
    """Look up a previously scanned file by SHA256 hash."""
    if not _SHA256_RE.match(sha256):
        raise HTTPException(status_code=400, detail="Invalid SHA256 format (expected 1-64 hex characters)")
    from threatlens.cache import get_cache
    result = get_cache().get(sha256)
    if result:
        return JSONResponse(result)

    # Try prefix search
    results = get_cache().search(sha256)
    if results:
        return JSONResponse({"matches": results})

    raise HTTPException(status_code=404, detail="Hash not found in cache")


@app.get("/api/stats")
async def api_stats():
    """Cache statistics."""
    from threatlens.cache import get_cache
    return JSONResponse(get_cache().get_stats())


@app.get("/api/history")
async def api_history(limit: int = 50):
    """Get recent scan history."""
    from threatlens.cache import get_cache
    return JSONResponse(get_cache().get_history(limit=min(limit, 200)))


@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(TEMPLATES_DIR, "index.html"), "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8888))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
