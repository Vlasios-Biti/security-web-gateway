ALTER TABLE discovery_runs ADD COLUMN auto_approve INTEGER NOT NULL DEFAULT 0 CHECK(auto_approve IN (0,1));

INSERT INTO settings(key,value,updated_at) VALUES('schema_version','3.7.0',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP;
