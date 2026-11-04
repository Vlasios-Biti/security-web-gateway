ALTER TABLE discovery_runs ADD COLUMN auto_apply INTEGER NOT NULL DEFAULT 0 CHECK(auto_apply IN (0,1));
ALTER TABLE discovery_runs ADD COLUMN baseline_dirty INTEGER NOT NULL DEFAULT 0 CHECK(baseline_dirty IN (0,1));

INSERT INTO settings(key,value,updated_at) VALUES('schema_version','3.8.0',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP;
