CREATE TABLE IF NOT EXISTS telemetry_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 epoch REAL NOT NULL,
 event_time TEXT NOT NULL,
 elapsed_ms INTEGER,
 client_ip TEXT NOT NULL,
 decision TEXT NOT NULL CHECK(decision IN('ALLOW','DENY','INFO')),
 result_code TEXT,
 http_status INTEGER,
 bytes INTEGER NOT NULL DEFAULT 0,
 method TEXT,
 destination TEXT,
 destination_host TEXT,
 destination_ip TEXT,
 destination_port INTEGER,
 hierarchy TEXT,
 hierarchy_code TEXT,
 upstream_ip TEXT,
 mime_type TEXT,
 network_id INTEGER,
 network_name TEXT,
 vlan_id INTEGER,
 application_ids TEXT,
 application_names TEXT,
 matched_rule_id INTEGER,
 matched_rule_destination TEXT,
 access_profile_names TEXT,
 traffic_path TEXT NOT NULL DEFAULT 'PROXY' CHECK(traffic_path IN('PROXY','DIRECT','EMERGENCY-DIRECT')),
 raw_line TEXT,
 event_hash TEXT NOT NULL UNIQUE,
 ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_telemetry_epoch ON telemetry_events(epoch DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_client_epoch ON telemetry_events(client_ip,epoch DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_decision_epoch ON telemetry_events(decision,epoch DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_destination_host ON telemetry_events(destination_host);
CREATE INDEX IF NOT EXISTS idx_telemetry_destination_ip ON telemetry_events(destination_ip);
CREATE INDEX IF NOT EXISTS idx_telemetry_network_epoch ON telemetry_events(network_id,epoch DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_app_epoch ON telemetry_events(application_ids,epoch DESC);

CREATE TABLE IF NOT EXISTS telemetry_state(
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO settings(key,value,updated_at) VALUES('telemetry_retention_days','30',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('telemetry_bootstrap_bytes','52428800',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('traffic_default_page_size','100',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO NOTHING;
INSERT INTO settings(key,value,updated_at) VALUES('schema_version','3.2.0',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP;
