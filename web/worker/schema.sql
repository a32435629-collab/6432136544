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

CREATE TABLE IF NOT EXISTS license_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL CHECK(length(device_hash) = 64),
    activated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(license_id, device_hash)
);

CREATE INDEX IF NOT EXISTS idx_license_devices_license
ON license_devices(license_id);

CREATE TRIGGER IF NOT EXISTS enforce_license_device_limit
BEFORE INSERT ON license_devices
WHEN (SELECT COUNT(*) FROM license_devices WHERE license_id = NEW.license_id) >=
     (SELECT max_devices FROM licenses WHERE id = NEW.license_id)
BEGIN
    SELECT RAISE(ABORT, 'device_limit_reached');
END;
