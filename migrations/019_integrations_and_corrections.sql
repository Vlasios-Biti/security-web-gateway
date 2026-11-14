CREATE TABLE api_tokens(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
 token_prefix TEXT NOT NULL, scopes_json TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL,
 revoked_at TEXT, last_used_at TEXT, window_start INTEGER NOT NULL DEFAULT 0, request_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE client_labels(
 ip TEXT PRIMARY KEY, name TEXT NOT NULL, updated_by TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE dependency_corrections(
 source_application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE, destination TEXT NOT NULL, protocol TEXT NOT NULL,
 target_application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE, updated_by TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(source_application_id,destination,protocol)
);
-- Timing alone is weak attribution. Approved rules remain unchanged.
UPDATE application_dependency_candidates SET confidence='low',confidence_score=MIN(confidence_score,40),recommendation='review'
WHERE status='pending';
