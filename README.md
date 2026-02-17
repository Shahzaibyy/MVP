# Security MVP — Prowler + Trivy → Grafana

Production-grade security monitoring stack for Azure. One `docker-compose up` command
deploys the entire infrastructure.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Client browser                                          │
│       │  http://<VM-IP>:3000  (Grafana Dashboard)       │
└───────┼──────────────────────────────────────────────────┘
        │
┌───────▼────────────────── Azure VM ──────────────────────┐
│                                                          │
│  ┌─────────────────┐   POST /trigger-scan               │
│  │   FastAPI :8000 │◄──────────────── Client / Cron     │
│  └────────┬────────┘                                     │
│           │  subprocess                                  │
│     ┌─────┴─────┐                                        │
│   Trivy       Prowler                                    │
│  (Container) (Azure CIS)                                 │
│     └─────┬─────┘                                        │
│           │  JSON parse + INSERT                         │
│  ┌────────▼────────┐                                     │
│  │  PostgreSQL     │◄────── Grafana (SELECT)             │
│  │  :5432          │                                     │
│  └─────────────────┘                                     │
│                                                          │
│  ┌─────────────────┐                                     │
│  │  Grafana :3000  │──────► Dashboard (auto-provisioned)│
│  └─────────────────┘                                     │
└──────────────────────────────────────────────────────────┘
```

---

## Quick Start (5 Steps)

### Step 1 — Clone & Configure

```bash
# On your Azure VM
git clone <your-repo> security-mvp
cd security-mvp

# Create your secrets file
cp .env.example .env
nano .env          # Fill in your Azure Service Principal values
```

### Step 2 — Create Azure Service Principal (for Prowler)

```bash
# Run this in Azure Cloud Shell or your local az cli
az ad sp create-for-rbac \
  --name "security-mvp-prowler" \
  --role "Reader" \
  --scopes /subscriptions/<YOUR_SUBSCRIPTION_ID>

# Copy the output JSON values into your .env file:
# appId        → AZURE_CLIENT_ID
# password     → AZURE_CLIENT_SECRET
# tenant       → AZURE_TENANT_ID
```

### Step 3 — Open Azure VM Ports

In Azure Portal → VM → Networking → Add inbound rules for:

| Port | Service            |
|------|--------------------|
| 8000 | FastAPI Backend    |
| 3000 | Grafana Dashboard  |

### Step 4 — Launch the Stack

```bash
# Install Docker (if not already installed)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Launch everything
docker-compose up -d --build

# Watch logs
docker-compose logs -f api
```

### Step 5 — Trigger Your First Scan

```bash
# Trigger a scan via API
curl -X POST "http://localhost:8000/trigger-scan?image=python:3.7-slim"

# Or with your VM's public IP:
curl -X POST "http://<YOUR-VM-IP>:8000/trigger-scan"
```

Open Grafana: **http://\<YOUR-VM-IP\>:3000** (admin / admin)
→ The "Security MVP Dashboard" loads automatically.

---

## API Reference

| Method | Endpoint         | Description                          |
|--------|-----------------|--------------------------------------|
| GET    | `/health`        | Health check                         |
| POST   | `/trigger-scan`  | Start Prowler + Trivy scan           |
| GET    | `/findings`      | List findings (filter by severity/tool) |
| GET    | `/summary`       | Severity × tool breakdown            |
| DELETE | `/findings`      | Clear all findings (for demo reset)  |

**Interactive API Docs:** http://\<VM-IP\>:8000/docs

### trigger-scan Query Parameters

```
?image=python:3.7-slim     # Docker image for Trivy (default from .env)
?image=node:10-slim        # Use older images for more CVEs in showcase
```

---

## Grafana Dashboard Panels

| Panel | Type | Description |
|-------|------|-------------|
| CRITICAL / HIGH / MEDIUM / LOW | Stat | Live counts with colour thresholds |
| Severity Breakdown | Pie chart | Distribution of all findings |
| Findings by Tool | Donut chart | Prowler vs Trivy split |
| Tool × Severity | Bar chart | Cross-breakdown |
| All Findings | Table | Full searchable list with colour-coded severity |
| Vulnerabilities Over Time | Time series | Trend line for each severity |

---

## Useful Commands

```bash
# Stop everything
docker-compose down

# Wipe DB and start fresh (between client demos)
curl -X DELETE http://localhost:8000/findings

# Check scan logs
docker-compose logs -f api

# Restart only the API (after code changes)
docker-compose restart api

# Shell into API container for debugging
docker exec -it security-api bash

# Shell into Postgres
docker exec -it security-postgres psql -U security_user -d security_mvp
```

---

## For Maximum Vulnerability Showcase (Client Demo)

Use older images with many known CVEs:

```bash
# Many CRITICAL CVEs
curl -X POST "http://localhost:8000/trigger-scan?image=python:3.4-alpine"

# More HIGH/MEDIUM from Node
curl -X POST "http://localhost:8000/trigger-scan?image=node:10-slim"
```

---

## File Structure

```
security-mvp/
├── main.py                              # FastAPI app (scanner + API)
├── requirements.txt                     # Python dependencies
├── Dockerfile                           # Multi-stage (Prowler + Trivy + FastAPI)
├── docker-compose.yml                   # Full stack orchestration
├── init.sql                             # PostgreSQL schema (auto-runs on boot)
├── .env.example                         # Template – copy to .env and fill in
├── .gitignore
└── grafana/
    └── provisioning/
        ├── datasources/
        │   └── postgres.yml             # Auto-connects Grafana → PostgreSQL
        └── dashboards/
            ├── dashboards.yml           # Dashboard loader config
            └── security-mvp.json       # Pre-built dashboard (auto-loaded)
```
