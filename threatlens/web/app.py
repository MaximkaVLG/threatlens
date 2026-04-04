"""ThreatLens Web UI — Upload files and get threat analysis.

Security: file size limit, rate limiting, safe temp file handling.
"""

import os
import time
import tempfile
from collections import defaultdict

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="ThreatLens", description="AI-Powered File Threat Analyzer")

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


def _check_rate_limit(client_ip: str) -> bool:
    """Check if client has exceeded rate limit."""
    now = time.time()
    # Clean old entries
    _rate_limits[client_ip] = [t for t in _rate_limits[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[client_ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[client_ip].append(now)
    return True


@app.post("/api/scan")
async def api_scan(request: Request, file: UploadFile = File(...), ai: bool = Form(False), provider: str = Form("ollama")):
    """Scan uploaded file via API."""
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
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
        result = analyze_file(tmp_path)

        # AI explanation (optional)
        ai_explanation = ""
        if ai:
            try:
                from threatlens.ai.providers import get_provider
                from threatlens.ai.prompts import THREAT_EXPLANATION_PROMPT
                prov = get_provider(provider)
                prompt = THREAT_EXPLANATION_PROMPT.format(
                    findings="\n".join(f"- {f}" for f in result.findings[:20]) or "No findings",
                    filename=file.filename, filetype=result.file_type,
                    filesize=f"{result.size:,} bytes",
                    risk_score=result.risk_score, risk_level=result.risk_level,
                    categories="",
                )
                ai_explanation = prov.explain(prompt)
            except Exception as e:
                ai_explanation = f"AI error: {e}"

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


@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(TEMPLATES_DIR, "index.html"), "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8888))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
