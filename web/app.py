"""ThreatLens Web UI — Upload files and get threat analysis."""

import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="ThreatLens", description="AI-Powered File Threat Analyzer")

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def analyze_uploaded_file(file_path: str, use_ai: bool = False, ai_provider: str = None) -> dict:
    """Run full analysis on uploaded file."""
    from threatlens.analyzers import generic_analyzer, pe_analyzer, script_analyzer
    from threatlens.scoring.threat_scorer import calculate_score
    from threatlens.rules.signatures import scan as yara_scan

    generic = generic_analyzer.analyze(file_path)
    all_findings = list(generic.findings)

    pe = None
    if generic.detected_type.startswith("PE") or file_path.lower().endswith((".exe", ".dll")):
        pe = pe_analyzer.analyze(file_path)
        all_findings.extend(pe.findings)

    script = None
    ext = os.path.splitext(file_path)[1].lower()
    if ext in script_analyzer.SCRIPT_EXTENSIONS:
        script = script_analyzer.analyze(file_path)
        all_findings.extend(script.findings)

    yara_result = yara_scan(file_path)
    all_findings.extend(yara_result.findings)

    score = calculate_score(all_findings, generic, pe, script)

    ai_explanation = ""
    if use_ai:
        try:
            from threatlens.ai.providers import get_provider
            from threatlens.ai.prompts import THREAT_EXPLANATION_PROMPT
            provider = get_provider(ai_provider)
            prompt = THREAT_EXPLANATION_PROMPT.format(
                findings="\n".join(f"- {f}" for f in all_findings) or "No findings",
                filename=generic.file_name, filetype=generic.file_type,
                filesize=f"{generic.file_size:,} bytes",
                risk_score=score.score, risk_level=score.level,
                categories=", ".join(score.categories.keys()) or "none",
            )
            ai_explanation = provider.explain(prompt)
        except Exception as e:
            ai_explanation = f"AI error: {e}"

    return {
        "file": generic.file_name,
        "size": generic.file_size,
        "type": generic.file_type,
        "md5": generic.md5,
        "sha256": generic.sha256,
        "entropy": generic.entropy,
        "entropy_verdict": generic.entropy_verdict,
        "risk_score": score.score,
        "risk_level": score.level,
        "summary": score.summary,
        "findings": all_findings,
        "urls": generic.urls[:10],
        "ip_addresses": generic.ip_addresses[:10],
        "recommendations": score.recommendations,
        "ai_explanation": ai_explanation,
        "yara_matches": [m["rule"] for m in yara_result.matches],
        "pe": {
            "is_pe": pe.is_pe if pe else False,
            "machine": pe.machine if pe else "",
            "signed": pe.has_signature if pe else False,
            "packed": pe.detected_packer if pe and pe.is_packed else "",
            "suspicious_imports": len(pe.suspicious_imports) if pe else 0,
        } if pe else None,
    }


@app.post("/api/scan")
async def api_scan(file: UploadFile = File(...), ai: bool = Form(False), provider: str = Form("ollama")):
    """Scan uploaded file via API."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = analyze_uploaded_file(tmp_path, use_ai=ai, ai_provider=provider if ai else None)
        result["file"] = file.filename
        return JSONResponse(result)
    finally:
        os.unlink(tmp_path)


@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(TEMPLATES_DIR, "index.html"), "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8888)
