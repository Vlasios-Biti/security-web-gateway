CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN('viewer','operator','admin','auditor')), enabled INTEGER NOT NULL DEFAULT 1,
 failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT, last_login_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,token_hash TEXT NOT NULL UNIQUE,csrf_token TEXT NOT NULL,
 source_ip TEXT,user_agent TEXT,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,last_seen_at TEXT NOT NULL,revoked_at TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS networks(
 id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,vlan_id INTEGER,cidr TEXT NOT NULL UNIQUE,
 proxy_enabled INTEGER NOT NULL DEFAULT 1,enabled INTEGER NOT NULL DEFAULT 1,system_managed INTEGER NOT NULL DEFAULT 0,
 pending INTEGER NOT NULL DEFAULT 0,reason TEXT,change_reference TEXT,description TEXT,
 created_by TEXT NOT NULL DEFAULT 'system',updated_by TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS categories(
 id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,slug TEXT NOT NULL UNIQUE,
 system_managed INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS rules(
 id INTEGER PRIMARY KEY AUTOINCREMENT,rule_type TEXT NOT NULL CHECK(rule_type IN('domain','ip')),
 action TEXT NOT NULL DEFAULT 'ALLOW' CHECK(action='ALLOW'),destination TEXT NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN('HTTP','HTTPS','BOTH')),category_id INTEGER,
 management_type TEXT NOT NULL CHECK(management_type IN('system','custom')),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN('active','disabled','deleted')),
 pending INTEGER NOT NULL DEFAULT 0,reason TEXT,change_reference TEXT,expires_at TEXT,
 source_file TEXT,source_line INTEGER,fingerprint TEXT UNIQUE,created_by TEXT NOT NULL DEFAULT 'system',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_by TEXT,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(category_id) REFERENCES categories(id));
CREATE TABLE IF NOT EXISTS rule_networks(
 rule_id INTEGER NOT NULL,network_id INTEGER NOT NULL,PRIMARY KEY(rule_id,network_id),
 FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE,
 FOREIGN KEY(network_id) REFERENCES networks(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS deployments(
 id INTEGER PRIMARY KEY AUTOINCREMENT,version TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL CHECK(status IN('deployed','failed','rolled_back')),created_by TEXT NOT NULL,
 description TEXT,config_sha256 TEXT,config_content TEXT NOT NULL,diff_text TEXT,state_json TEXT NOT NULL,
 previous_deployment_id INTEGER,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,deployed_at TEXT,
 FOREIGN KEY(previous_deployment_id) REFERENCES deployments(id));
CREATE TABLE IF NOT EXISTS audit_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 actor TEXT NOT NULL,action TEXT NOT NULL,object_type TEXT,object_id TEXT,source_ip TEXT,result TEXT NOT NULL,details_json TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
