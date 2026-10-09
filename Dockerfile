# ==============================================================================
# WhistleDrop Production Multi-Stage Dockerfile
# Security Hardened: Non-root execution, minimal attack surface, verified runtimes
# ==============================================================================

# Stage 1: Build virtualenv with all compiled dependencies
FROM python:3.13-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Stage 2: Minimal hardened production runtime
FROM python:3.13-slim-bookworm AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Security invariant: Dedicated unprivileged non-root system user and group
RUN groupadd -g 10001 whistledrop && \
    useradd -u 10001 -g whistledrop -s /bin/bash -m whistledrop

WORKDIR /app

# Copy python virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy application source code
COPY --chown=whistledrop:whistledrop app/ /app/app/
COPY --chown=whistledrop:whistledrop alembic.ini /app/alembic.ini
COPY --chown=whistledrop:whistledrop alembic/ /app/alembic/
COPY --chown=whistledrop:whistledrop scripts/ /app/scripts/

# Create evidence storage directories with strict directory permissions
RUN mkdir -p /app/storage/evidence/quarantine /app/storage/evidence/approved && \
    chown -R whistledrop:whistledrop /app/storage && \
    chmod -R 700 /app/storage

USER whistledrop:whistledrop

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1,172.28.0.10}\""]
