-- Security Web Gateway v3.3.0
-- Operational guardrails + browser/HAR discovery schema.

CREATE TABLE discovery_runs_new(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 application_id INTEGER,
 query TEXT,
 method TEXT NOT NULL CHECK(method IN('catalog','official_api','official_url','observed','seed_probe','browser_auto','har_import')),
 status TEXT NOT NULL CHECK(status IN('running','ready','approved','failed','discarded')),
 source_ref TEXT,
 source_version TEXT,
 client_ip TEXT,
 window_minutes INTEGER,
 started_by TEXT NOT NULL,
 started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 completed_at TEXT,
 error_text TEXT,
 FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE SET NULL
);

INSERT INTO discovery_runs_new(id,application_id,query,method,status,source_ref,source_version,client_ip,window_minutes,started_by,started_at,completed_at,error_text)
SELECT id,application_id,query,method,status,source_ref,source_version,client_ip,window_minutes,started_by,started_at,completed_at,error_text
FROM discovery_runs;

CREATE TABLE discovery_candidates_new(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 run_id INTEGER NOT NULL,
 endpoint_type TEXT NOT NULL CHECK(endpoint_type IN('domain','ip')),
 destination TEXT NOT NULL,
 protocol TEXT NOT NULL DEFAULT 'HTTPS' CHECK(protocol IN('HTTP','HTTPS','BOTH')),
 required INTEGER NOT NULL DEFAULT 1,
 source TEXT NOT NULL,
 confidence TEXT NOT NULL DEFAULT 'medium' CHECK(confidence IN('high','medium','low')),
 selected INTEGER NOT NULL DEFAULT 1,
 already_present INTEGER NOT NULL DEFAULT 0,
 metadata_json TEXT,
 classification TEXT NOT NULL DEFAULT 'unknown',
 recommendation TEXT NOT NULL DEFAULT 'review' CHECK(recommendation IN('allow','review','ignore')),
 request_count INTEGER NOT NULL DEFAULT 0,
 first_seen_context TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(run_id,endpoint_type,destination,protocol),
 FOREIGN KEY(run_id) REFERENCES discovery_runs_new(id) ON DELETE CASCADE
);

INSERT INTO discovery_candidates_new(
 id,run_id,endpoint_type,destination,protocol,required,source,confidence,selected,already_present,metadata_json,
 classification,recommendation,request_count,first_seen_context,created_at
)
SELECT id,run_id,endpoint_type,destination,protocol,required,source,confidence,selected,already_present,metadata_json,
       'unknown','review',0,NULL,created_at
FROM discovery_candidates;

DROP TABLE discovery_candidates;
DROP TABLE discovery_runs;
ALTER TABLE discovery_runs_new RENAME TO discovery_runs;
ALTER TABLE discovery_candidates_new RENAME TO discovery_candidates;

CREATE INDEX IF NOT EXISTS idx_discovery_runs_app ON discovery_runs(application_id,started_at);
CREATE INDEX IF NOT EXISTS idx_discovery_runs_status ON discovery_runs(status,started_at);
CREATE INDEX IF NOT EXISTS idx_discovery_candidates_run ON discovery_candidates(run_id,selected);
CREATE INDEX IF NOT EXISTS idx_discovery_candidates_recommendation ON discovery_candidates(run_id,recommendation);

INSERT INTO settings(key,value,updated_at) VALUES('telemetry_retention_days','30',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('telemetry_max_used_bytes','8589934592',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('telemetry_cleanup_target_bytes','6979321856',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('telemetry_min_free_bytes','10737418240',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('squid_raw_log_retention_days','14',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('squid_raw_log_max_bytes','4294967296',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('schema_version','3.3.0',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP;
