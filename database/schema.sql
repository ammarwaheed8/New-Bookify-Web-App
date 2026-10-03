-- Bookify schema (SQLite)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS permissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    email             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    username          TEXT UNIQUE COLLATE NOCASE,
    phone             TEXT NOT NULL DEFAULT '',
    password_hash     TEXT NOT NULL,
    type              TEXT NOT NULL DEFAULT 'customer' CHECK (type IN ('customer','admin')),
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','blocked')),
    email_verified_at TEXT,
    country           TEXT NOT NULL DEFAULT '',
    city              TEXT NOT NULL DEFAULT '',
    address           TEXT NOT NULL DEFAULT '',
    date_of_birth     TEXT,
    preferences       TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_type_status ON users(type, status);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

CREATE TABLE IF NOT EXISTS hotels (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    address         TEXT NOT NULL DEFAULT '',
    city            TEXT NOT NULL,
    country         TEXT NOT NULL,
    location_text   TEXT NOT NULL DEFAULT '',
    stars           INTEGER NOT NULL DEFAULT 3 CHECK (stars BETWEEN 1 AND 5),
    rating          REAL    NOT NULL DEFAULT 4.5,
    reviews_count   INTEGER NOT NULL DEFAULT 0,
    price_per_night REAL    NOT NULL DEFAULT 0,
    amenities       TEXT    NOT NULL DEFAULT '[]',
    policies        TEXT    NOT NULL DEFAULT '[]',
    status          TEXT    NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hotels_status ON hotels(status);
CREATE INDEX IF NOT EXISTS idx_hotels_city   ON hotels(city);

CREATE TABLE IF NOT EXISTS hotel_images (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    hotel_id   INTEGER NOT NULL REFERENCES hotels(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    alt        TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hotel_images_hotel ON hotel_images(hotel_id, sort_order);

CREATE TABLE IF NOT EXISTS room_types (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hotel_id        INTEGER NOT NULL REFERENCES hotels(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    capacity        INTEGER NOT NULL DEFAULT 2 CHECK (capacity >= 1),
    total_rooms     INTEGER NOT NULL DEFAULT 10 CHECK (total_rooms >= 0),
    price_per_night REAL    NOT NULL DEFAULT 0,
    amenities       TEXT    NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_room_types_hotel ON room_types(hotel_id);

CREATE TABLE IF NOT EXISTS room_inventory (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    room_type_id INTEGER NOT NULL REFERENCES room_types(id) ON DELETE CASCADE,
    date         TEXT NOT NULL,
    total        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (room_type_id, date)
);
CREATE INDEX IF NOT EXISTS idx_room_inventory_window ON room_inventory(room_type_id, date);

CREATE TABLE IF NOT EXISTS bookings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    reference      TEXT NOT NULL UNIQUE,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    hotel_id       INTEGER NOT NULL REFERENCES hotels(id) ON DELETE RESTRICT,
    room_type_id   INTEGER NOT NULL REFERENCES room_types(id) ON DELETE RESTRICT,
    check_in       TEXT NOT NULL,
    check_out      TEXT NOT NULL,
    nights         INTEGER NOT NULL,
    num_guests     INTEGER NOT NULL DEFAULT 1,
    num_rooms      INTEGER NOT NULL DEFAULT 1,
    guest_name     TEXT NOT NULL,
    guest_email    TEXT NOT NULL,
    guest_phone    TEXT NOT NULL DEFAULT '',
    subtotal       REAL NOT NULL DEFAULT 0,
    taxes          REAL NOT NULL DEFAULT 0,
    service_fee    REAL NOT NULL DEFAULT 0,
    total          REAL NOT NULL DEFAULT 0,
    currency       TEXT NOT NULL DEFAULT 'USD',
    payment_method TEXT NOT NULL CHECK (payment_method IN ('card','paypal','property')),
    status         TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','confirmed','cancelled','completed')),
    notes          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_bookings_user   ON bookings(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_bookings_hotel  ON bookings(hotel_id, check_in);
CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings(status);
CREATE INDEX IF NOT EXISTS idx_bookings_window ON bookings(room_type_id, status, check_in, check_out);

CREATE TABLE IF NOT EXISTS booking_guests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL DEFAULT '',
    phone      TEXT NOT NULL DEFAULT '',
    is_primary INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_booking_guests_booking ON booking_guests(booking_id);

CREATE TABLE IF NOT EXISTS payments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id      INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
    method          TEXT NOT NULL CHECK (method IN ('card','paypal','property')),
    amount          REAL NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'USD',
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid','refunded','failed')),
    transaction_ref TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_payments_booking ON payments(booking_id);
CREATE INDEX IF NOT EXISTS idx_payments_status  ON payments(status);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_evt_user ON email_verification_tokens(user_id);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_prt_user ON password_reset_tokens(user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_label TEXT NOT NULL DEFAULT 'system',
    action      TEXT NOT NULL,
    entity      TEXT NOT NULL,
    entity_id   INTEGER,
    detail      TEXT NOT NULL DEFAULT '{}',
    ip          TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_entity  ON audit_logs(entity, entity_id);
