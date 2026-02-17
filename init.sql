-- ─────────────────────────────────────────────────────────────────────────────
--  Security MVP – PostgreSQL Schema
--  Auto-executed on first container boot by docker-entrypoint-initdb.d
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS security_scans (
    id              SERIAL          PRIMARY KEY,
    tool_name       VARCHAR(50)     NOT NULL,
    scan_target     VARCHAR(255),
    severity        VARCHAR(20),
    title           TEXT,
    description     TEXT,
    resource_id     VARCHAR(512),
    status          VARCHAR(50),
    scan_timestamp  TIMESTAMP       DEFAULT NOW(),
    raw_data        JSONB
);

-- Indexes for Grafana query performance
CREATE INDEX IF NOT EXISTS idx_severity  ON security_scans(severity);
CREATE INDEX IF NOT EXISTS idx_tool      ON security_scans(tool_name);
CREATE INDEX IF NOT EXISTS idx_timestamp ON security_scans(scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_status    ON security_scans(status);

-- ─── Grafana read-only user (best practice) ───────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'grafana_reader') THEN
        CREATE ROLE grafana_reader WITH LOGIN PASSWORD 'GrafanaRead123!';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE security_mvp TO grafana_reader;
GRANT USAGE   ON SCHEMA public         TO grafana_reader;
GRANT SELECT  ON ALL TABLES IN SCHEMA public TO grafana_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO grafana_reader;
