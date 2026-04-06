# Stage 1: Build (install dependencies, compile YARA, download rules)
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc-dev git && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir yara-python oletools fastapi uvicorn python-multipart py7zr rarfile

COPY . .
RUN pip install --no-cache-dir .
RUN python scripts/download_yara_rules.py

# Stage 2: Runtime (no gcc, no git — smaller + more secure)
FROM python:3.12-slim

# Install 7z for encrypted archive support (AES-256 etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    p7zip-full && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

# Security: non-root user
RUN useradd -m -s /bin/bash scanner && chown -R scanner:scanner /app
USER scanner

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import httpx; httpx.get('http://localhost:8080/health').raise_for_status()" || exit 1

CMD ["python", "-m", "threatlens.web.app"]
