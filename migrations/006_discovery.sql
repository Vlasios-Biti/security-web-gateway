CREATE TABLE IF NOT EXISTS discovery_runs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 application_id INTEGER,
 query TEXT,
 method TEXT NOT NULL CHECK(method IN('catalog','official_api','official_url','observed','seed_probe')),
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
CREATE TABLE IF NOT EXISTS discovery_candidates(
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
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(run_id,endpoint_type,destination,protocol),
 FOREIGN KEY(run_id) REFERENCES discovery_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_discovery_runs_app ON discovery_runs(application_id,started_at);
CREATE INDEX IF NOT EXISTS idx_discovery_candidates_run ON discovery_candidates(run_id,selected);
