# ThreatLens — production Docker image.
#
# Two-stage build (builder + runtime). Pinned to Python 3.12 because
# yara-python 4.5 has no Python 3.14 wheel as of 2026-04 — see
# docs/day4_yara_synergy.md "Local validation limits". Inside this image
# YARA actually runs, so the YARA-on-payload features are not zero-variance.
#
# Build:  docker build -t threatlens .
# Run:    docker run --rm -p 8888:8888 threatlens
# Health: curl http://localhost:8888/health  ->  {"status":"ok"}

# -------------------- Stage 1: builder --------------------
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libc-dev git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so this layer caches across source edits
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir py7zr rarfile

# Copy source and install the package
COPY . .
RUN pip install --no-cache-dir .

# Pre-download community YARA rules so the runtime image is offline-ready.
# Tolerate failure — bundled rules in threatlens/rules/ still cover the
# critical detections.
RUN python scripts/download_yara_rules.py \
    || echo "[warn] YARA community rules download failed — continuing with bundled rules"

# -------------------- Stage 2: runtime --------------------
FROM python:3.12-slim

# 7z + curl. curl is for the HEALTHCHECK below (cheaper than spinning up Python).
RUN apt-get update && apt-get install -y --no-install-recommends \
        p7zip-full curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

# Defence-in-depth: drop root.
RUN useradd -m -s /bin/bash scanner && chown -R scanner:scanner /app
USER scanner

# Default to the Day 9e python_only model bundle (F1 0.96 / recall 96 %).
# Override with `-e THREATLENS_ML_DIR=/app/results/cicids2017` to roll back.
ENV THREATLENS_ML_DIR=/app/results/python_only \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8888

EXPOSE 8888

# Healthcheck — fixed from OLD version which pointed at port 8080 while
# EXPOSE was 8888 (always reported "unhealthy").
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent --max-time 4 http://localhost:8888/health || exit 1

# `python -m threatlens.web.app` triggers the `if __name__ == "__main__":`
# block in app.py (line 686) which calls uvicorn.run(app, host=HOST, port=PORT).
CMD ["python", "-m", "threatlens.web.app"]
