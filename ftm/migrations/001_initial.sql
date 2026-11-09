BEGIN IMMEDIATE;
PRAGMA application_id = 1179934001;
CREATE TABLE IF NOT EXISTS migration_versions(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY, name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 device_limit INTEGER CHECK(device_limit IS NULL OR device_limit > 0),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS devices(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 platform TEXT NOT NULL CHECK(platform IN ('android','windows','ios','other')),
 vpn_type TEXT NOT NULL CHECK(vpn_type = 'wg'),
 wg_public_key TEXT NOT NULL UNIQUE CHECK(length(wg_public_key)=44),
 preshared_key TEXT NOT NULL UNIQUE CHECK(length(preshared_key)=44),
 cid TEXT NOT NULL UNIQUE CHECK(length(cid)=32 AND cid NOT GLOB '*[^0-9a-f]*'),
 ip TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 state TEXT NOT NULL CHECK(state IN ('pending','active','error','revoking','revoked')),
 origin TEXT NOT NULL CHECK(origin IN ('manager','legacy')),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 request_hash TEXT NOT NULL, request_fingerprint TEXT NOT NULL,
 last_handshake_at TEXT, created_at TEXT NOT NULL,
 UNIQUE(user_id,request_hash)
) STRICT;
CREATE INDEX IF NOT EXISTS devices_user_idx ON devices(user_id);
CREATE TABLE IF NOT EXISTS operations(
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id),
 revision INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','applying','done','error','cancelled')),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(device_id,revision)
) STRICT;
CREATE TABLE IF NOT EXISTS subscriptions(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
 token_hash TEXT NOT NULL UNIQUE, version INTEGER NOT NULL DEFAULT 1, revoked_at TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS device_tokens(
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id),
 token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS bootstraps(
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id),
 nonce_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, consumed_at TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS config_revisions(
 id TEXT PRIMARY KEY, revision INTEGER NOT NULL UNIQUE, hash TEXT NOT NULL,
 created_at TEXT NOT NULL, applied_at TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS audit_events(
 id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
 subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, ts TEXT NOT NULL,
 sanitized_details TEXT NOT NULL DEFAULT '{}'
) STRICT;
CREATE TABLE IF NOT EXISTS metrics_samples(
 ts TEXT PRIMARY KEY, cpu_pct REAL, mem_bytes INTEGER,
 rx_bytes INTEGER, tx_bytes INTEGER, vpn_peers_active_estimate INTEGER
) STRICT;
INSERT OR IGNORE INTO settings VALUES('subnet','10.77.43.0/24');
INSERT OR IGNORE INTO settings VALUES('next_ip','10');
INSERT OR IGNORE INTO migration_versions VALUES(1,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
COMMIT;
