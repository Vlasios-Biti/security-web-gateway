-- Relationship-level state prevents disabling a shared atomic rule when an
-- administrator only wants to disable it inside one Application Policy.
ALTER TABLE application_rules ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1));
CREATE INDEX IF NOT EXISTS idx_application_rules_effective ON application_rules(application_id,enabled,rule_id);
