-- Security Web Gateway v3.4.0
-- Single-VM performance instrumentation, cached dashboard summaries,
-- application dependency candidates, and operational indexes.

CREATE TABLE IF NOT EXISTS dashboard_cache(
 key TEXT PRIMARY KEY,
 payload_json TEXT NOT NULL,
 generated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS performance_samples(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 epoch REAL NOT NULL,
 sampled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 cpu_percent REAL NOT NULL DEFAULT 0,
 iowait_percent REAL NOT NULL DEFAULT 0,
 load1 REAL NOT NULL DEFAULT 0,
 load5 REAL NOT NULL DEFAULT 0,
 memory_percent REAL NOT NULL DEFAULT 0,
 disk_percent REAL NOT NULL DEFAULT 0,
 disk_free_bytes INTEGER NOT NULL DEFAULT 0,
 db_file_bytes INTEGER NOT NULL DEFAULT 0,
 telemetry_lag_seconds REAL,
 proxy_p50_ms REAL,
 proxy_p95_ms REAL,
 proxy_p99_ms REAL,
 proxy_connections INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_performance_epoch ON performance_samples(epoch DESC);

CREATE TABLE IF NOT EXISTS application_dependency_candidates(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 application_id INTEGER NOT NULL,
 destination TEXT NOT NULL,
 protocol TEXT NOT NULL DEFAULT 'HTTPS' CHECK(protocol IN('HTTP','HTTPS','BOTH')),
 classification TEXT NOT NULL DEFAULT 'unknown',
 confidence_score INTEGER NOT NULL DEFAULT 0,
 confidence TEXT NOT NULL DEFAULT 'low' CHECK(confidence IN('high','medium','low')),
 recommendation TEXT NOT NULL DEFAULT 'review' CHECK(recommendation IN('allow','review','ignore')),
 request_count INTEGER NOT NULL DEFAULT 0,
 client_count INTEGER NOT NULL DEFAULT 0,
 first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 first_client_ip TEXT,
 evidence_json TEXT,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','approved','ignored')),
 reviewed_by TEXT,
 reviewed_at TEXT,
 FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
 UNIQUE(application_id,destination,protocol)
);
CREATE INDEX IF NOT EXISTS idx_appdep_candidates_status ON application_dependency_candidates(status,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_appdep_candidates_app ON application_dependency_candidates(application_id,status,last_seen_at DESC);

CREATE TABLE IF NOT EXISTS application_dependency_candidate_clients(
 candidate_id INTEGER NOT NULL,
 client_ip TEXT NOT NULL,
 first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(candidate_id,client_ip),
 FOREIGN KEY(candidate_id) REFERENCES application_dependency_candidates(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_appdep_candidate_clients_ip ON application_dependency_candidate_clients(client_ip);

CREATE INDEX IF NOT EXISTS idx_sessions_active_token ON sessions(token_hash,revoked_at,expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id,revoked_at,expires_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_elapsed_epoch ON telemetry_events(epoch DESC,elapsed_ms);
CREATE INDEX IF NOT EXISTS idx_telemetry_host_decision_epoch ON telemetry_events(destination_host,decision,epoch DESC);

INSERT INTO settings(key,value,updated_at) VALUES('dashboard_cache_ttl_seconds','20',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('telemetry_batch_max','10000',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('session_touch_interval_seconds','60',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('dependency_candidate_window_seconds','120',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('performance_retention_days','7',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('schema_version','3.4.0',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP;
