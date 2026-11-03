INSERT INTO settings(key,value,updated_at) VALUES('schema_version','3.1.0',CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP;
