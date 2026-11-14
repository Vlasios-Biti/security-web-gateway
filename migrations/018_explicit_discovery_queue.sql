ALTER TABLE discovery_runs ADD COLUMN queued INTEGER NOT NULL DEFAULT 0 CHECK(queued IN(0,1));
UPDATE discovery_runs SET queued=1 WHERE method='browser_auto' AND status='running';
CREATE INDEX idx_discovery_queued_status ON discovery_runs(queued,status,id);
