# Project VANGUARD — Multi-stage Docker build
# Stage 1: builder — install dependencies
# Stage 2: runtime — minimal image

# ─── Builder ──────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into a prefix so we can copy them cleanly
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Runtime ──────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="Project VANGUARD"
LABEL description="Immutable Defense for the Post-Botnet Era"
LABEL version="0.1.0"

# Non-root user for security
RUN addgroup --system vanguard && adduser --system --ingroup vanguard vanguard

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source code
COPY vanguard/ ./vanguard/
COPY setup.py .

RUN pip install --no-cache-dir -e . --no-deps

# Ensure correct ownership
RUN chown -R vanguard:vanguard /app

USER vanguard

# Ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" \
    || exit 1

# Environment defaults (override at runtime)
ENV PROXY_HOST=0.0.0.0 \
    PROXY_PORT=8080 \
    ORIGIN_URL=http://localhost:8000 \
    ENTROPY_BENIGN_THRESHOLD=0.45 \
    ENTROPY_BLOCK_CONFIDENCE=0.85 \
    DOJO_PAYLOADS_PER_MINUTE=1000 \
    VANGUARD_DEBUG=false

CMD ["python", "-m", "vanguard.main", "--workers", "4"]
