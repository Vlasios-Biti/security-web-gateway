CREATE TABLE IF NOT EXISTS import_batches(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('domain','ip')),
 management_type TEXT NOT NULL CHECK(management_type IN('custom','system')),
 category_slug TEXT,
 defaults_json TEXT NOT NULL,
 rows_json TEXT NOT NULL,
 accepted_count INTEGER NOT NULL DEFAULT 0,
 rejected_count INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'preview' CHECK(status IN('preview','applied','expired','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_import_batches_status ON import_batches(status,expires_at);
INSERT INTO settings(key,value,updated_at) VALUES('schema_version','3.1.0',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP;
