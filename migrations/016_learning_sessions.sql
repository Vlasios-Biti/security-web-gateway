CREATE TABLE application_learning_sessions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 -- Historical object IDs deliberately survive policy snapshot replacement.
 application_id INTEGER NOT NULL,
 client_ip TEXT NOT NULL,
 started_by TEXT NOT NULL,
 started_epoch REAL NOT NULL,
 expires_epoch REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN('active','completed','stopped','failed')),
 last_event_id INTEGER NOT NULL DEFAULT 0,
 learned_count INTEGER NOT NULL DEFAULT 0,
 error_text TEXT
);
CREATE UNIQUE INDEX idx_learning_one_client ON application_learning_sessions(client_ip) WHERE status='active';
CREATE TABLE application_learning_destinations(
 session_id INTEGER NOT NULL REFERENCES application_learning_sessions(id) ON DELETE CASCADE,
 destination TEXT NOT NULL,
 protocol TEXT NOT NULL,
 event_id INTEGER NOT NULL,
 rule_id INTEGER NOT NULL,
 PRIMARY KEY(session_id,destination,protocol)
);
