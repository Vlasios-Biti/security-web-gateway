INSERT OR IGNORE INTO settings(key,value) VALUES('schema_version','3.1.0');
INSERT OR IGNORE INTO settings(key,value) VALUES('default_policy','DENY');
INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES('Google Search','google-search',1);
INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES('Google Maps','google-maps',1);
INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES('Business','business',0);
INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES('Explicit IP','explicit-ip',0);
