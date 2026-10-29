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

CREATE TABLE IF NOT EXISTS admin_keys (
  key           TEXT PRIMARY KEY,
  user_id       TEXT,
  created_at    TEXT NOT NULL,
  redeemed_at   TEXT,
  expires_at    TEXT,
  revoked       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS referrals (
  id           TEXT PRIMARY KEY,
  code         TEXT UNIQUE NOT NULL,
  owner_id     TEXT NOT NULL,
  used_by      TEXT,
  used_at      TEXT,
  created_at   TEXT NOT NULL,
  reward_days  INTEGER NOT NULL DEFAULT 30
);

CREATE TABLE IF NOT EXISTS referral_claims (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  code         TEXT NOT NULL,
  days_granted INTEGER NOT NULL,
  claimed_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_referrals_code ON referrals(code);
CREATE INDEX IF NOT EXISTS idx_referrals_owner ON referrals(owner_id);
CREATE INDEX IF NOT EXISTS idx_referral_claims_user ON referral_claims(user_id);
