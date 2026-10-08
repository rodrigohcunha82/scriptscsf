-- CSF Next persistent security state
-- Target: CloudLinux 9.x + cPanel/WHM

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS addresses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    address      TEXT NOT NULL,
    family       INTEGER NOT NULL CHECK (family IN (4,6)),
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    country_code TEXT,
    asn          TEXT,

    UNIQUE(address, family)
);

CREATE INDEX IF NOT EXISTS idx_addresses_address
    ON addresses(address);

CREATE TABLE IF NOT EXISTS blocks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    address_id     INTEGER NOT NULL,
    block_type     TEXT NOT NULL
        CHECK (block_type IN ('temporary','permanent')),
    source         TEXT NOT NULL,
    reason         TEXT,
    service        TEXT,

    created_at     INTEGER NOT NULL,
    expires_at     INTEGER,

    status         TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','expired','removed')),

    kernel_state   TEXT NOT NULL DEFAULT 'pending'
        CHECK (kernel_state IN (
            'pending',
            'applied',
            'missing',
            'error',
            'removed'
        )),

    removed_at     INTEGER,
    removed_reason TEXT,

    FOREIGN KEY(address_id)
        REFERENCES addresses(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_blocks_address
    ON blocks(address_id);

CREATE INDEX IF NOT EXISTS idx_blocks_status
    ON blocks(status);

CREATE INDEX IF NOT EXISTS idx_blocks_expires
    ON blocks(expires_at);

CREATE INDEX IF NOT EXISTS idx_blocks_kernel_state
    ON blocks(kernel_state);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    address_id    INTEGER,
    block_id      INTEGER,

    event_type    TEXT NOT NULL,
    source        TEXT NOT NULL,
    service       TEXT,

    occurred_at   INTEGER NOT NULL,
    metadata_json TEXT,

    FOREIGN KEY(address_id)
        REFERENCES addresses(id)
        ON DELETE SET NULL,

    FOREIGN KEY(block_id)
        REFERENCES blocks(id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_events_address_time
    ON events(address_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_events_block_time
    ON events(block_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_events_type_time
    ON events(event_type, occurred_at);

CREATE TABLE IF NOT EXISTS allowlist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    address_id INTEGER NOT NULL,
    source     TEXT NOT NULL,
    comment    TEXT,
    created_at INTEGER NOT NULL,

    FOREIGN KEY(address_id)
        REFERENCES addresses(id)
        ON DELETE CASCADE,

    UNIQUE(address_id)
);

CREATE TABLE IF NOT EXISTS metadata (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO schema_version(version, applied_at)
VALUES (1, CAST(strftime('%s','now') AS INTEGER));

INSERT OR IGNORE INTO metadata(key, value, updated_at)
VALUES (
    'database_format',
    'csf-next',
    CAST(strftime('%s','now') AS INTEGER)
);

INSERT OR IGNORE INTO metadata(key, value, updated_at)
VALUES (
    'schema_version',
    '1',
    CAST(strftime('%s','now') AS INTEGER)
);
