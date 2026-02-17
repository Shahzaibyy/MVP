"""
Security MVP - FastAPI Backend
Integrates Prowler (Azure) + Trivy (Container) → PostgreSQL → Grafana
"""

import subprocess
import json
import glob
import logging
import os
from datetime import datetime
from typing import Optional, List

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/app/logs/scanner.log"),
    ],
)
logger = logging.getLogger(__name__)

# ─── App Init ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Security Monitoring MVP",
    description="Prowler + Trivy → PostgreSQL → Grafana",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── DB Config ─────────────────────────────────────────────────────────────────
# Direct PostgreSQL connection string (Neon)
DB_DSN = (
    "postgresql://neondb_owner:"
    "npg_PhqbB7Ao4XcN"
    "@ep-weathered-breeze-a8fhysep-pooler.eastus2.azure.neon.tech/"
    "neondb?sslmode=require&channel_binding=require"
)

TRIVY_IMAGE   = os.getenv("TRIVY_IMAGE", "python:3.7-slim")
PROWLER_VENV  = os.getenv("PROWLER_VENV", "/opt/prowler-venv/bin/prowler")
OUTPUT_DIR    = "/app/scan-results"

# ─── Pydantic Models ──────────────────────────────────────────────────────────
class ScanStatus(BaseModel):
    status: str
    message: str
    timestamp: str

class Finding(BaseModel):
    id: int
    tool_name: str
    scan_target: Optional[str]
    severity: Optional[str]
    title: Optional[str]
    description: Optional[str]
    resource_id: Optional[str]
    status: Optional[str]
    scan_timestamp: str

# ─── Database Helpers ─────────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DB_DSN)
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


def init_db():
    """Create tables if they don't exist yet."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_scans (
            id              SERIAL PRIMARY KEY,
            tool_name       VARCHAR(50)  NOT NULL,
            scan_target     VARCHAR(255),
            severity        VARCHAR(20),
            title           TEXT,
            description     TEXT,
            resource_id     VARCHAR(512),
            status          VARCHAR(50),
            scan_timestamp  TIMESTAMP    DEFAULT NOW(),
            raw_data        JSONB
        );
        CREATE INDEX IF NOT EXISTS idx_severity  ON security_scans(severity);
        CREATE INDEX IF NOT EXISTS idx_tool      ON security_scans(tool_name);
        CREATE INDEX IF NOT EXISTS idx_timestamp ON security_scans(scan_timestamp);
    """)
    conn.commit()
    cursor.close()
    conn.close()
    logger.info("Database tables verified / created.")


def save_findings(findings: list):
    """Bulk-insert a list of finding dicts into PostgreSQL."""
    if not findings:
        logger.warning("No findings to save.")
        return

    conn = get_db()
    cursor = conn.cursor()
    query = """
        INSERT INTO security_scans
            (tool_name, scan_target, severity, title, description, resource_id, status, raw_data)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    rows = [
        (
            f["tool_name"],
            f.get("scan_target"),
            f.get("severity"),
            f.get("title"),
            f.get("description", "")[:1000],
            f.get("resource_id"),
            f.get("status"),
            json.dumps(f.get("raw_data", {})),
        )
        for f in findings
    ]
    psycopg2.extras.execute_batch(cursor, query, rows, page_size=200)
    conn.commit()
    cursor.close()
    conn.close()
    logger.info(f"Saved {len(findings)} findings to PostgreSQL.")


# ─── Trivy Scanner ────────────────────────────────────────────────────────────
def run_trivy(image: str = TRIVY_IMAGE) -> List[dict]:
    """Run Trivy against a container image and return parsed findings."""
    output_file = f"{OUTPUT_DIR}/trivy_results.json"
    logger.info(f"[Trivy] Scanning image: {image}")

    result = subprocess.run(
        ["trivy", "image", "--format", "json", "--output", output_file,
         "--timeout", "10m", "--quiet", image],
        capture_output=True, text=True,
    )

    if result.returncode not in (0, 1):        # 1 = vulns found (expected)
        logger.error(f"[Trivy] Error: {result.stderr}")
        return []

    try:
        with open(output_file) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"[Trivy] Could not read output: {e}")
        return []

    findings = []
    for result_item in data.get("Results", []):
        for vuln in result_item.get("Vulnerabilities") or []:
            findings.append({
                "tool_name":   "Trivy",
                "scan_target": image,
                "severity":    vuln.get("Severity", "UNKNOWN").upper(),
                "title":       vuln.get("VulnerabilityID", ""),
                "description": vuln.get("Title") or vuln.get("Description", ""),
                "resource_id": result_item.get("Target", ""),
                "status":      "DETECTED",
                "raw_data":    vuln,
            })

    logger.info(f"[Trivy] Found {len(findings)} vulnerabilities.")
    return findings


# ─── Prowler Scanner ──────────────────────────────────────────────────────────
def run_prowler() -> List[dict]:
    """Run Prowler against Azure and return parsed findings."""
    logger.info("[Prowler] Starting Azure scan…")

    for old_file in glob.glob(f"{OUTPUT_DIR}/prowler-output-azure*"):
        try:
            os.remove(old_file)
        except:
            pass

    result = subprocess.run(
        [
            PROWLER_VENV, "azure",
            "--output-formats", "json",
            "--output-directory", OUTPUT_DIR,
            "--output-filename", "prowler-output-azure",
            "--quiet" 
        ],
        capture_output=True, text=True,
        env={
            **os.environ,
            "AZURE_CLIENT_ID":       os.getenv("AZURE_CLIENT_ID", ""),
            "AZURE_CLIENT_SECRET":   os.getenv("AZURE_CLIENT_SECRET", ""),
            "AZURE_TENANT_ID":       os.getenv("AZURE_TENANT_ID", ""),
            "AZURE_SUBSCRIPTION_ID": os.getenv("AZURE_SUBSCRIPTION_ID", ""),
        },
    )

    json_files = glob.glob(f"{OUTPUT_DIR}/prowler-output-azure*.json")
    
    if not json_files:
        logger.error(f"[Prowler] No JSON output file found in {OUTPUT_DIR}")
        logger.info(f"Directory contents: {os.listdir(OUTPUT_DIR)}")
        return []

    latest_file = max(json_files, key=os.path.getctime)
    logger.info(f"[Prowler] Reading latest findings from: {latest_file}")

    try:
        with open(latest_file, "r") as f:
            raw = json.load(f)
    except Exception as e:
        logger.error(f"[Prowler] JSON parse error or file read error: {e}")
        return []

    items = raw if isinstance(raw, list) else raw.get("findings", [])

    findings = []
    for item in items:
        status_val = str(item.get("status", item.get("Status", "FAIL"))).upper()
        
        if status_val in ["FAIL", "WARNING"]:
            findings.append({
                "tool_name":   "Prowler",
                "scan_target": "Azure-Subscription",
                "severity":    str(item.get("severity", item.get("Severity", "MEDIUM"))).upper(),
                "title":       item.get("check_title") or item.get("CheckTitle", item.get("check_id", "")),
                "description": item.get("description", item.get("Description", "")),
                "resource_id": item.get("resource_id") or item.get("resource_name", "Azure-Resource"),
                "status":      status_val,
                "raw_data":    item,
            })

    logger.info(f"[Prowler] Successfully parsed {len(findings)} FAIL/WARNING findings.")
    return findings

# ─── Background Scan Task ─────────────────────────────────────────────────────
def run_full_scan(image: str):
    logger.info("=== Full security scan starting ===")
    all_findings = []

    try:
        all_findings += run_trivy(image)
    except Exception as e:
        logger.error(f"[Trivy] Exception: {e}")

    try:
        all_findings += run_prowler()
    except Exception as e:
        logger.error(f"[Prowler] Exception: {e}")

    save_findings(all_findings)
    logger.info(f"=== Scan complete. {len(all_findings)} total findings stored. ===")


# ─── Startup ──────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs("/app/logs", exist_ok=True)

    # Retry DB connection on startup (postgres container may still be booting)
    for attempt in range(10):
        try:
            init_db()
            break
        except Exception as e:
            logger.warning(f"DB not ready (attempt {attempt + 1}/10): {e}")
            import time; time.sleep(3)


# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.get("/health", tags=["Monitoring"])
def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/trigger-scan", response_model=ScanStatus, tags=["Scanning"])
def trigger_scan(
    background_tasks: BackgroundTasks,
    image: str = Query(default=TRIVY_IMAGE, description="Docker image for Trivy to scan"),
):
    """
    Trigger a full security scan (Prowler + Trivy) in the background.
    Results are written to PostgreSQL and visible in Grafana within minutes.
    """
    background_tasks.add_task(run_full_scan, image)
    return ScanStatus(
        status="started",
        message=f"Scan triggered for image '{image}'. Results will appear in Grafana shortly.",
        timestamp=datetime.now().isoformat(),
    )


@app.get("/findings", tags=["Results"])
def get_findings(
    severity: Optional[str] = None,
    tool:     Optional[str] = None,
    limit:    int           = 200,
):
    """Retrieve stored findings with optional filters."""
    conn   = get_db()
    cursor = conn.cursor()

    query  = "SELECT * FROM security_scans WHERE 1=1"
    params = []

    if severity:
        query += " AND UPPER(severity) = %s"
        params.append(severity.upper())
    if tool:
        query += " AND tool_name = %s"
        params.append(tool)

    query += " ORDER BY scan_timestamp DESC LIMIT %s"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Convert timestamps to ISO strings for JSON serialisation
    for row in rows:
        if row.get("scan_timestamp"):
            row["scan_timestamp"] = row["scan_timestamp"].isoformat()

    return {"total": len(rows), "findings": rows}


@app.get("/summary", tags=["Results"])
def get_summary():
    """Severity × tool breakdown — used by Grafana Stat panels."""
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            tool_name,
            severity,
            COUNT(*) AS count,
            MAX(scan_timestamp) AS last_seen
        FROM security_scans
        GROUP BY tool_name, severity
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                ELSE 5
            END
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    for row in rows:
        if row.get("last_seen"):
            row["last_seen"] = row["last_seen"].isoformat()
    return {"summary": rows}


@app.delete("/findings", tags=["Admin"])
def clear_findings():
    """Wipe all findings — useful between demo sessions."""
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("TRUNCATE TABLE security_scans RESTART IDENTITY;")
    conn.commit()
    conn.close()
    return {"message": "All findings cleared.", "timestamp": datetime.now().isoformat()}
