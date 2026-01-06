# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Production Dockerfile
# Enterprise AI-Powered Penetration Testing Platform
# ═══════════════════════════════════════════════════════════════════════════════

# Stage 1: Builder
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production
FROM python:3.12-slim as production

LABEL maintainer="RAGLOX Team"
LABEL version="3.0.0"
LABEL description="RAGLOX v3.0 - Enterprise AI-Powered Penetration Testing Platform"

# Create non-root user for security
RUN groupadd -r raglox && useradd -r -g raglox raglox

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    openssh-client \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    nmap \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY --chown=raglox:raglox src/ ./src/
COPY --chown=raglox:raglox data/ ./data/
COPY --chown=raglox:raglox tests/ ./tests/

# Create directories
RUN mkdir -p /app/logs /app/tmp /app/uploads && \
    chown -R raglox:raglox /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    APP_ENV=production \
    LOG_LEVEL=INFO \
    HOST=0.0.0.0 \
    PORT=8000

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Switch to non-root user
USER raglox

# Default command
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# ═══════════════════════════════════════════════════════════════════════════════
# Development Stage
# ═══════════════════════════════════════════════════════════════════════════════
FROM production as development

USER root

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    htop \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install dev dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    pytest-cov \
    httpx \
    black \
    isort \
    mypy

USER raglox

ENV APP_ENV=development \
    LOG_LEVEL=DEBUG

CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
