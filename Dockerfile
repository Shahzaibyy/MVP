# ── Stage 1: Prowler installer ────────────────────────────────────────────────
FROM python:3.11-slim AS prowler-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/prowler-venv \
    && /opt/prowler-venv/bin/pip install --upgrade pip \
    && /opt/prowler-venv/bin/pip install prowler

# ── Stage 2: Final image ──────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="security-mvp"
LABEL description="Prowler + Trivy → FastAPI → PostgreSQL → Grafana"

# System dependencies + Trivy
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget curl ca-certificates gnupg apt-transport-https \
    && mkdir -p /etc/apt/keyrings \
    && wget -qO /etc/apt/keyrings/trivy.gpg \
         https://aquasecurity.github.io/trivy-repo/deb/public.key \
    && echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] \
         https://aquasecurity.github.io/trivy-repo/deb generic main" \
         > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# Copy Prowler venv from builder stage
COPY --from=prowler-builder /opt/prowler-venv /opt/prowler-venv

# App setup
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Directories for logs and scan output
RUN mkdir -p /app/logs /app/scan-results

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
