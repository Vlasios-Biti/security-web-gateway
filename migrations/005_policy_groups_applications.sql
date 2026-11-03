ALTER TABLE rules ADD COLUMN scope_mode TEXT NOT NULL DEFAULT 'selected' CHECK(scope_mode IN('selected','all_proxy'));

CREATE TABLE IF NOT EXISTS applications(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 slug TEXT NOT NULL UNIQUE,
 provider TEXT,
 description TEXT,
 seed_domain TEXT,
 source_kind TEXT NOT NULL DEFAULT 'manual' CHECK(source_kind IN('manual','builtin','official_api','official_url','observed')),
 source_ref TEXT,
 system_managed INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN('active','disabled','deleted')),
 pending INTEGER NOT NULL DEFAULT 0,
 auto_monitor INTEGER NOT NULL DEFAULT 0,
 last_discovery_at TEXT,
 last_source_version TEXT,
 created_by TEXT NOT NULL DEFAULT 'system',
 updated_by TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS application_rules(
 application_id INTEGER NOT NULL,
 rule_id INTEGER NOT NULL,
 required INTEGER NOT NULL DEFAULT 1,
 source TEXT NOT NULL DEFAULT 'manual',
 confidence TEXT NOT NULL DEFAULT 'high' CHECK(confidence IN('high','medium','low')),
 metadata_json TEXT,
 PRIMARY KEY(application_id,rule_id),
 FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
 FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS application_networks(
 application_id INTEGER NOT NULL,
 network_id INTEGER NOT NULL,
 PRIMARY KEY(application_id,network_id),
 FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
 FOREIGN KEY(network_id) REFERENCES networks(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS policy_groups(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 description TEXT,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN('active','disabled','deleted')),
 pending INTEGER NOT NULL DEFAULT 0,
 system_managed INTEGER NOT NULL DEFAULT 0,
 created_by TEXT NOT NULL DEFAULT 'system',
 updated_by TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS policy_group_applications(
 group_id INTEGER NOT NULL,
 application_id INTEGER NOT NULL,
 PRIMARY KEY(group_id,application_id),
 FOREIGN KEY(group_id) REFERENCES policy_groups(id) ON DELETE CASCADE,
 FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS policy_group_rules(
 group_id INTEGER NOT NULL,
 rule_id INTEGER NOT NULL,
 PRIMARY KEY(group_id,rule_id),
 FOREIGN KEY(group_id) REFERENCES policy_groups(id) ON DELETE CASCADE,
 FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS policy_group_networks(
 group_id INTEGER NOT NULL,
 network_id INTEGER NOT NULL,
 PRIMARY KEY(group_id,network_id),
 FOREIGN KEY(group_id) REFERENCES policy_groups(id) ON DELETE CASCADE,
 FOREIGN KEY(network_id) REFERENCES networks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_app_rules_rule ON application_rules(rule_id);
CREATE INDEX IF NOT EXISTS idx_app_networks_network ON application_networks(network_id);
CREATE INDEX IF NOT EXISTS idx_pg_apps_app ON policy_group_applications(application_id);
CREATE INDEX IF NOT EXISTS idx_pg_rules_rule ON policy_group_rules(rule_id);
CREATE INDEX IF NOT EXISTS idx_pg_networks_network ON policy_group_networks(network_id);
