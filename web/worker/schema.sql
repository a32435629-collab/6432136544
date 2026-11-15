PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE CHECK(length(key_hash) = 64),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked')),
    expires_at TEXT NOT NULL,
    max_devices INTEGER NOT NULL DEFAULT 1 CHECK(max_devices BETWEEN 1 AND 10),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_licenses_status_expiry
ON licenses(status, expires_at);
