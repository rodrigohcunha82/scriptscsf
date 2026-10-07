-- CSF Next persistent security state
-- Target: CloudLinux 9.x + cPanel/WHM
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS addresses (
  id INTEGER PRIMARY KEY,
  address TEXT NOT NULL,
  family INTEGER NOT NULL CHECK (family IN (4,6)),
  first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  country_code TEXT,
  asn TEXT,
  UNIQUE(address, family)
);

CREATE TABLE IF NOT EXISTS blocks (
  id INTEGER PRIMARY KEY,
  address_id INTEGER NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
  block_type TEXT NOT NULL CHECK (block_type IN ('temporary','permanent')),
  source TEXT NOT NULL,
  reason TEXT,
  service TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','expired','removed')),
  removed_at TEXT,
  removed_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_blocks_active
  ON blocks(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_blocks_address
  ON blocks(address_id, created_at);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  address_id INTEGER REFERENCES addresses(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  source TEXT NOT NULL,
  service TEXT,
  occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_address_time
  ON events(address_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_type_time
  ON events(event_type, occurred_at);

CREATE TABLE IF NOT EXISTS allowlist (
  id INTEGER PRIMARY KEY,
  address_id INTEGER NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  comment TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(address_id)
);

INSERT OR IGNORE INTO schema_version(version) VALUES (1);
