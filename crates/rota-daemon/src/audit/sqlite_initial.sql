CREATE TABLE IF NOT EXISTS renewal (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  cert_id      TEXT NOT NULL,
  started_at   TEXT NOT NULL,
  completed_at TEXT,
  status       TEXT NOT NULL,
  error        TEXT
);

CREATE INDEX IF NOT EXISTS idx_renewal_cert_id ON renewal(cert_id);
CREATE INDEX IF NOT EXISTS idx_renewal_status  ON renewal(status);

CREATE TABLE IF NOT EXISTS renewal_event (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  renewal_id INTEGER NOT NULL REFERENCES renewal(id) ON DELETE CASCADE,
  ts         TEXT NOT NULL,
  kind       TEXT NOT NULL,
  detail     TEXT
);

CREATE INDEX IF NOT EXISTS idx_renewal_event_renewal_id ON renewal_event(renewal_id);
