FROM python:3.12-slim

# System dependencies for YARA compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    libmagic1 \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir yara-python oletools fastapi uvicorn python-multipart

# Copy project
COPY . .

# Install as package
RUN pip install --no-cache-dir -e .

# Download YARA community rules
RUN python scripts/download_yara_rules.py

# Security: run as non-root user
RUN useradd -m -s /bin/bash scanner
RUN chown -R scanner:scanner /app
USER scanner

# Web UI port (Railway sets $PORT dynamically)
EXPOSE 8888

# Default: run web UI — Python reads $PORT from env, no shell expansion needed
CMD ["python", "-m", "threatlens.web.app"]
