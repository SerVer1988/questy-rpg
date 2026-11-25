CREATE TABLE IF NOT EXISTS push_subscriptions (
  user_id TEXT NOT NULL,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  timezone TEXT NOT NULL DEFAULT 'UTC',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);
CREATE TABLE IF NOT EXISTS push_deliveries (
  user_id TEXT NOT NULL,
  delivery_key TEXT NOT NULL,
  delivered_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, delivery_key),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
