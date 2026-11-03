CREATE INDEX IF NOT EXISTS idx_rules_destination ON rules(destination);
CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status);
CREATE INDEX IF NOT EXISTS idx_rules_pending ON rules(pending);
CREATE INDEX IF NOT EXISTS idx_networks_pending ON networks(pending);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
