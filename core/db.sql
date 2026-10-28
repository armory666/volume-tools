CREATE TABLE IF NOT EXISTS users (
  id           TEXT PRIMARY KEY,
  telegram_id  INTEGER UNIQUE,
  email        TEXT UNIQUE,
  tier         TEXT NOT NULL DEFAULT 'free',
  credits      INTEGER NOT NULL DEFAULT 0,
  paid_until   TEXT,
  created_at   TEXT NOT NULL,
  last_seen    TEXT
);

CREATE TABLE IF NOT EXISTS usage (
  user_id      TEXT NOT NULL,
  day          TEXT NOT NULL,
  queries      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);

CREATE TABLE IF NOT EXISTS payments (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  provider     TEXT NOT NULL,
  provider_id  TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  tier_days    INTEGER NOT NULL,
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
  key           TEXT PRIMARY KEY,
  user_id       TEXT,
  duration_days INTEGER NOT NULL,
  created_at    TEXT NOT NULL,
  redeemed_at   TEXT,
  expires_at    TEXT
);
