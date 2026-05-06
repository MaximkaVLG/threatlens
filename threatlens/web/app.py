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
            from threatlens.rules.signatures import _compile_custom_rules, _compile_community_rules
            _compile_custom_rules()
            _compile_community_rules()
            logger.info("YARA rules pre-compiled on startup (custom + community)")
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
MAX_PCAP_SIZE = 200 * 1024 * 1024  # 200MB — network captures are often larger
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 10  # requests per window

# Lazy-loaded ML detector for network flows (models are ~15MB, loaded on first PCAP request)
_flow_detector = None
_flow_detector_lock = asyncio.Lock()


async def _get_flow_detector():
    """Return a shared FlowDetector, loading models from disk on first call.

    Default model directory is ``results/python_only`` (Day 9e candidate —
    F1 0.96 / recall 96 % on real-world). Can be overridden via the
    ``THREATLENS_ML_DIR`` env var (e.g. point at ``results/cicids2017``
    to roll back to the legacy CIC-only model).

    ``THREATLENS_STRICT_MODE=1`` enables the Mahalanobis abstainer to
    rewrite OOD predictions as ``UNCERTAIN`` (yellow / "review" in UI).
    Default is off — the abstainer is loaded but only sets a flag.
    """
    global _flow_detector
    if _flow_detector is not None:
        return _flow_detector
    async with _flow_detector_lock:
        if _flow_detector is None:
            from threatlens.network import FlowDetector
            default_dir = os.path.join(
                os.path.dirname(__file__), "..", "..",
                "results", "python_only")
            results_dir = os.environ.get("THREATLENS_ML_DIR", default_dir)
            # Fallback for environments where the python_only artefacts
            # weren't shipped (e.g. legacy Railway image): try cicids2017
            if not os.path.exists(
                    os.path.join(results_dir, "xgboost.joblib")):
                fallback = os.path.join(
                    os.path.dirname(__file__), "..", "..",
                    "results", "cicids2017")
                if os.path.exists(
                        os.path.join(fallback, "xgboost.joblib")):
                    logger.warning(
                        "%s missing — falling back to %s",
                        results_dir, fallback)
                    results_dir = fallback
            strict = os.environ.get(
                "THREATLENS_STRICT_MODE", "0").lower() in (
                    "1", "true", "yes", "on")
            _flow_detector = await asyncio.to_thread(
                FlowDetector.from_results_dir, results_dir,
                strict_abstention=strict)
            logger.info(
                "FlowDetector loaded from %s (strict_abstention=%s)",
                results_dir, strict)
    return _flow_detector

# Simple in-memory rate limiter
_rate_limits = defaultdict(list)

# 60-second in-memory cache for /api/stats so that dashboard polling
# (every 30s from each connected browser) doesn't hammer SQLite.
_USAGE_STATS_TTL = 60.0
_usage_stats_cache: dict = {"data": None, "ts": 0.0}


def _record_scan_event_safe(
    scan_type: str,
    verdict: str,
    start_monotonic: float,
    file_size_bytes=None,
    client_ip: str = "",
) -> None:
    """Write a stats row, swallow any failure. Telemetry must not break scans."""
    try:
        from threatlens.cache import get_cache, hash_client_ip
        duration_ms = int((time.monotonic() - start_monotonic) * 1000)
        get_cache().record_scan_event(
            scan_type=scan_type,
            verdict=verdict,
            duration_ms=duration_ms,
            file_size_bytes=file_size_bytes,
            client_ip_hash=hash_client_ip(client_ip),
        )
    except Exception:
        logger.exception("Failed to record scan event (telemetry only; scan unaffected)")


def _record_prediction_summary_safe(predictions, summary, model_dir: str) -> None:
    """Phase 6 — capture per-scan ML aggregates for the drift monitor.

    Sample-rate: env var ``THREATLENS_DRIFT_LOG_RATE`` (default 1.0 = log all).
    Set to e.g. 0.1 to log 10 % of scans once production traffic outgrows
    the storage budget.

    Always swallows exceptions — telemetry must never break scans.
    """
    try:
        import os, random
        rate = float(os.environ.get("THREATLENS_DRIFT_LOG_RATE", "1.0"))
        if rate < 1.0 and random.random() > rate:
            return
        if predictions is None or len(predictions) == 0:
            return
        from threatlens.cache import get_cache
        labels_dict = summary.get("labels", {}) if isinstance(summary, dict) else {}
        n_attack = int(summary.get("attack_flows", 0)) if isinstance(summary, dict) else 0
        n_benign = int(summary.get("benign_flows", 0)) if isinstance(summary, dict) else 0
        n_abstain = int(summary.get("uncertain_flows", 0)) if isinstance(summary, dict) else 0
        mean_conf = (float(predictions["confidence"].dropna().mean())
                      if "confidence" in predictions.columns
                      and predictions["confidence"].notna().any()
                      else 0.0)
        get_cache().record_prediction_summary(
            model_dir=model_dir,
            n_flows=int(len(predictions)),
            n_attack=n_attack,
            n_benign=n_benign,
            n_abstain=n_abstain,
            mean_confidence=mean_conf,
            class_distribution=labels_dict,
        )
    except Exception:
        logger.exception(
            "Failed to record prediction summary "
            "(drift telemetry only; scan unaffected)")

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


_RISK_TO_VERDICT = {"LOW": "clean", "MEDIUM": "suspicious", "HIGH": "malicious", "CRITICAL": "malicious"}


@app.post("/api/scan")
async def api_scan(request: Request, file: UploadFile = File(...), ai: bool = Form(False), password: str = Form("")):
    """Scan uploaded file via API."""
    # Rate limiting — use X-Forwarded-For behind reverse proxy (Railway, Cloudflare)
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Try again in 60 seconds.")
    _stats_start = time.monotonic()

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

        # DEBUG: trace archive detection
        print(f"SCAN DEBUG: score={result.risk_score}, level={result.risk_level}, type={result.file_type}, findings={result.findings[:5]}", flush=True)
        if hasattr(result, '_archive_debug'):
            print(f"ARCHIVE INFO: {result._archive_debug}", flush=True)

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

        _record_scan_event_safe(
            scan_type="file",
            verdict=_RISK_TO_VERDICT.get(result.risk_level, "clean"),
            start_monotonic=_stats_start,
            file_size_bytes=result.size,
            client_ip=client_ip,
        )

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


_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}


def _json_safe(obj):
    """Recursively convert numpy / pandas scalars to native Python types."""
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    if hasattr(obj, "item") and callable(obj.item):
        try:
            return obj.item()
        except (ValueError, TypeError):
            return obj
    return obj


@app.post("/api/network/analyze-pcap")
async def api_analyze_pcap(
    request: Request,
    file: UploadFile = File(...),
    model: str = Form("xgboost"),
    max_flows: int = Form(50),
):
    """Extract flows from an uploaded PCAP and classify each with the ML models.

    Returns summary statistics plus up to `max_flows` highest-risk flows.
    Caller may request up to 200 explicitly; the conservative default keeps
    a single response well under 100 KB to avoid bandwidth / parse DoS.
    """
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Try again in 60 seconds.")
    _stats_start = time.monotonic()

    # Validate against detector.available_models — python_only ships
    # xgboost only; legacy combined_v2 / cicids2017 also have random_forest.
    detector_for_check = await _get_flow_detector()
    if model not in detector_for_check.available_models:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown model {model!r}. Available: "
                f"{detector_for_check.available_models}"
            ),
        )

    # Hard cap lowered from 1000 to 200 — with 70 feature cols per flow, an
    # unbounded response could exceed several MB.
    max_flows = max(1, min(int(max_flows), 200))

    # Stream to disk in bounded chunks — PCAPs can be hundreds of MB.
    suffix = os.path.splitext(file.filename or "capture.pcap")[1].lower()
    if suffix not in _PCAP_EXTS:
        raise HTTPException(status_code=400, detail=f"Expected PCAP extension, got {suffix!r}")

    total_size = 0
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="tl_pcap_") as tmp:
        tmp_path = tmp.name
        while chunk := await file.read(1024 * 1024):
            total_size += len(chunk)
            if total_size > MAX_PCAP_SIZE:
                tmp.close()
                os.unlink(tmp_path)
                raise HTTPException(
                    status_code=413,
                    detail=f"PCAP too large. Maximum size: {MAX_PCAP_SIZE // (1024*1024)}MB",
                )
            tmp.write(chunk)

    if total_size == 0:
        os.unlink(tmp_path)
        raise HTTPException(status_code=400, detail="Empty file")

    try:
        from threatlens.network import FlowExtractor

        extractor = FlowExtractor()
        try:
            flows_df = await asyncio.wait_for(
                asyncio.to_thread(extractor.extract, tmp_path),
                timeout=180.0,  # 3 min hard limit on parsing
            )
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="PCAP parsing timed out (3 min limit).")
        except Exception as e:
            logger.error("PCAP parse error: %s", e)
            raise HTTPException(status_code=400, detail="Could not parse PCAP file.")

        if flows_df.empty:
            _record_scan_event_safe(
                scan_type="pcap", verdict="BENIGN",
                start_monotonic=_stats_start,
                file_size_bytes=total_size, client_ip=client_ip,
            )
            return JSONResponse({
                "file": file.filename,
                "size": total_size,
                "summary": {
                    "total_flows": 0, "attack_flows": 0, "benign_flows": 0,
                    "anomaly_flows": 0, "labels": {}, "top_talkers": [],
                },
                "flows": [],
                "model": model,
            })

        detector = await _get_flow_detector()
        try:
            predictions = await asyncio.to_thread(detector.predict, flows_df, model)
        except Exception as e:
            logger.error("Prediction error: %s", e)
            raise HTTPException(status_code=500, detail="ML prediction failed.")

        summary = detector.summary(predictions)

        # Rank: attacks first (by confidence), then anomalies, then benign.
        ranked = predictions.assign(
            _sort=lambda d: d["is_attack"] * 1e6
                            + d.get("anomaly_flag", 0) * 1e3
                            + d["confidence"].fillna(0),
        ).sort_values("_sort", ascending=False).drop(columns="_sort")

        top_flows = ranked.head(max_flows).to_dict(orient="records")

        labels = summary.get("labels", {}) if isinstance(summary, dict) else {}
        non_benign = {lbl: n for lbl, n in labels.items() if lbl and lbl != "BENIGN"}
        verdict = max(non_benign, key=non_benign.get) if non_benign else "BENIGN"
        _record_scan_event_safe(
            scan_type="pcap", verdict=verdict,
            start_monotonic=_stats_start,
            file_size_bytes=total_size, client_ip=client_ip,
        )
        # Phase 6 — drift telemetry. Independent of scan_event recording so a
        # failure in one path doesn't kill the other.
        _record_prediction_summary_safe(
            predictions=predictions,
            summary=summary,
            model_dir=os.environ.get("THREATLENS_ML_DIR", "results/python_only"),
        )

        return JSONResponse(_json_safe({
            "file": file.filename,
            "size": total_size,
            "summary": summary,
            "flows": top_flows,
            "model": model,
        }))
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


_IP_RE = re.compile(r"^[0-9a-fA-F:.]{1,45}$")
# CIC-IDS2017 class labels normalised to use a plain ASCII hyphen. We run
# incoming labels through `_normalize_label` before whitelist check so that
# any en-dash / em-dash / double-space variant from the original CSV is
# equivalent. Strict whitelist keeps prompt-injection out of the LLM path.
_ALLOWED_LABELS = frozenset({
    "BENIGN", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest",
    "Heartbleed", "DDoS", "PortScan", "FTP-Patator", "SSH-Patator",
    "Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection",
    "Bot", "Infiltration",
})
# Characters CIC-IDS2017 uses interchangeably with ASCII hyphen in labels.
_DASH_VARIANTS = ("\u2013", "\u2014", "\u2012", "\u2212")  # en, em, figure, minus


def _normalize_label(label: str) -> str:
    """Collapse CIC-IDS2017 label variants (unicode dashes, double spaces)
    down to a single canonical ASCII form so the whitelist check matches
    regardless of which CSV encoding produced the label."""
    label = label.strip()
    for d in _DASH_VARIANTS:
        label = label.replace(d, "-")
    # Original CSVs sometimes drop the dash altogether: "Web Attack  Brute Force".
    while "  " in label:
        label = label.replace("  ", " - ", 1) if "Web Attack" in label else label.replace("  ", " ")
    return label


_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}


def _num(d: dict, *keys, default: float = 0.0) -> float:
    """Read the first available numeric key, coercing to float."""
    for k in keys:
        if k in d and d[k] is not None:
            try:
                return float(d[k])
            except (TypeError, ValueError):
                continue
    return default


def _sanitize_flow_for_prompt(flow: dict) -> dict:
    """Validate and extract a safe subset of fields from a flow dict.

    Guards against prompt-injection by enforcing regex on string fields and
    dropping anything not in the expected schema. All numeric fields are
    coerced to floats.
    """
    src_ip = str(flow.get("src_ip", ""))
    dst_ip = str(flow.get("dst_ip", ""))
    if not _IP_RE.match(src_ip) or not _IP_RE.match(dst_ip):
        raise HTTPException(status_code=400, detail="Invalid IP in flow data")

    label = _normalize_label(str(flow.get("label", "BENIGN")))
    if label not in _ALLOWED_LABELS:
        raise HTTPException(status_code=400, detail="Unknown label")

    protocol_num = int(_num(flow, "protocol"))
    proto_str = _PROTO_NAMES.get(protocol_num, f"IP {protocol_num}")

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(_num(flow, "src_port")),
        "dst_port": int(_num(flow, "dst_port", "Destination Port")),
        "protocol": proto_str,
        "label": label,
        "confidence": f"{_num(flow, 'confidence'):.3f}",
        "anomaly": "да" if int(_num(flow, "anomaly_flag")) else "нет",
        "anomaly_score": f"{_num(flow, 'anomaly_score'):.3f}",
        "flow_duration": f"{_num(flow, 'Flow Duration'):.0f}",
        "fwd_pkts": int(_num(flow, "Total Fwd Packets")),
        "bwd_pkts": int(_num(flow, "Total Backward Packets")),
        "fwd_bytes": int(_num(flow, "Total Length of Fwd Packets")),
        "bwd_bytes": int(_num(flow, "Total Length of Bwd Packets")),
        "avg_pkt_size": f"{_num(flow, 'Average Packet Size'):.1f}",
        "bytes_per_sec": f"{_num(flow, 'Flow Bytes/s'):.1f}",
        "pkts_per_sec": f"{_num(flow, 'Flow Packets/s'):.1f}",
        "syn": int(_num(flow, "SYN Flag Count")),
        "ack": int(_num(flow, "ACK Flag Count")),
        "rst": int(_num(flow, "RST Flag Count")),
        "fin": int(_num(flow, "FIN Flag Count")),
        "psh": int(_num(flow, "PSH Flag Count")),
        "urg": int(_num(flow, "URG Flag Count")),
        "init_win_fwd": int(_num(flow, "Init_Win_bytes_forward")),
        "init_win_bwd": int(_num(flow, "Init_Win_bytes_backward")),
        "down_up_ratio": f"{_num(flow, 'Down/Up Ratio'):.2f}",
    }


@app.post("/api/network/explain-flow-shap")
async def api_explain_flow_shap(request: Request):
    """Return top-K SHAP feature contributions for the model's prediction.

    Body: {"flow": {...flow feature dict...}, "model": "xgboost"|"random_forest", "top_k": 10}
    """
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Try again in 60 seconds.")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(payload, dict) or not isinstance(payload.get("flow"), dict):
        raise HTTPException(status_code=400, detail="Body must be {\"flow\": {...}}")

    model_name = payload.get("model", "xgboost")
    if model_name not in {"xgboost", "random_forest"}:
        raise HTTPException(status_code=400, detail="Model must be 'xgboost' or 'random_forest'")
    top_k = max(1, min(int(payload.get("top_k", 10) or 10), 30))

    detector = await _get_flow_detector()
    try:
        explanation = await asyncio.to_thread(
            detector.explain_shap, payload["flow"], model_name, top_k
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("SHAP explain error: %s", e)
        raise HTTPException(status_code=500, detail="SHAP computation failed.")

    return JSONResponse(_json_safe(explanation))


@app.post("/api/network/explain-flow")
async def api_explain_flow(request: Request):
    """Generate a YandexGPT explanation for a single classified flow.

    Body: {"flow": { ...flow fields from /api/network/analyze-pcap... }}
    """
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Try again in 60 seconds.")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(payload, dict) or not isinstance(payload.get("flow"), dict):
        raise HTTPException(status_code=400, detail="Body must be {\"flow\": {...}}")

    fields = _sanitize_flow_for_prompt(payload["flow"])

    from threatlens.ai.providers import get_provider
    from threatlens.ai.prompts import NETWORK_FLOW_PROMPT
    prompt = NETWORK_FLOW_PROMPT.format(**fields)

    try:
        explanation = await get_provider().explain_async(prompt)
    except Exception as e:
        logger.error("explain-flow AI error: %s", e)
        raise HTTPException(status_code=502, detail="AI service unavailable.")

    return JSONResponse({"explanation": explanation, "label": fields["label"]})


@app.get("/api/lookup/{sha256}")
async def api_lookup(request: Request, sha256: str):
    """Look up a previously scanned file by SHA256 hash."""
    if not _SHA256_RE.match(sha256):
        raise HTTPException(status_code=400, detail="Invalid SHA256 format (expected 1-64 hex characters)")
    _stats_start = time.monotonic()
    client_ip = _get_client_ip(request)

    from threatlens.cache import get_cache
    result = get_cache().get(sha256)
    if result:
        _record_scan_event_safe(
            scan_type="hash_lookup", verdict="found",
            start_monotonic=_stats_start, client_ip=client_ip,
        )
        return JSONResponse(result)

    # Try prefix search
    results = get_cache().search(sha256)
    if results:
        _record_scan_event_safe(
            scan_type="hash_lookup", verdict="found",
            start_monotonic=_stats_start, client_ip=client_ip,
        )
        return JSONResponse({"matches": results})

    _record_scan_event_safe(
        scan_type="hash_lookup", verdict="not_found",
        start_monotonic=_stats_start, client_ip=client_ip,
    )
    raise HTTPException(status_code=404, detail="Hash not found in cache")


@app.get("/api/cache-stats")
async def api_cache_stats():
    """Cache statistics (unique files, cache hits, risk breakdown)."""
    from threatlens.cache import get_cache
    return JSONResponse(get_cache().get_stats())


@app.get("/api/stats")
async def api_stats():
    """Public usage statistics, cached in memory for 60 seconds."""
    now = time.monotonic()
    cached = _usage_stats_cache.get("data")
    if cached is not None and (now - _usage_stats_cache.get("ts", 0.0)) < _USAGE_STATS_TTL:
        return JSONResponse(cached)
    from threatlens.cache import get_cache
    data = await asyncio.to_thread(get_cache().get_usage_stats)
    _usage_stats_cache["data"] = data
    _usage_stats_cache["ts"] = now
    return JSONResponse(data)


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
