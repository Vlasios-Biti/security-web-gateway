-- Application dependencies inherit scope from their Application Policy and Policy Groups.
-- Remove legacy per-dependency scopes only after application_networks was bootstrapped in migration 007.
DELETE FROM rule_networks
WHERE rule_id IN (SELECT rule_id FROM application_rules);
