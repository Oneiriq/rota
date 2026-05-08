-- Audit log schema for the SurrealDB-backed AuditStore impl.
-- Mirrors the SQLite schema in shape: a renewal table whose rows own
-- a chain of renewal_event children. Idempotent; runs at every
-- daemon startup against the configured SurrealDB.

DEFINE TABLE IF NOT EXISTS renewal SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS cert_id ON TABLE renewal TYPE string;
DEFINE FIELD IF NOT EXISTS started_at ON TABLE renewal TYPE datetime;
DEFINE FIELD IF NOT EXISTS completed_at ON TABLE renewal TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS status ON TABLE renewal TYPE string;
DEFINE FIELD IF NOT EXISTS error ON TABLE renewal TYPE option<string>;
DEFINE INDEX IF NOT EXISTS idx_renewal_cert_id ON TABLE renewal COLUMNS cert_id;
DEFINE INDEX IF NOT EXISTS idx_renewal_status ON TABLE renewal COLUMNS status;

DEFINE TABLE IF NOT EXISTS renewal_event SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS renewal_id ON TABLE renewal_event TYPE record<renewal>;
DEFINE FIELD IF NOT EXISTS ts ON TABLE renewal_event TYPE datetime;
DEFINE FIELD IF NOT EXISTS kind ON TABLE renewal_event TYPE string;
DEFINE FIELD IF NOT EXISTS detail ON TABLE renewal_event TYPE option<string>;
DEFINE INDEX IF NOT EXISTS idx_renewal_event_renewal_id ON TABLE renewal_event COLUMNS renewal_id;

-- Cluster federation lock. Singleton row at cluster_lock:singleton.
-- Coordinators acquire by writing themselves as `holder` when the
-- existing row is missing, expired, or already held by them; refresh
-- by writing again before `expires_at` lapses.
DEFINE TABLE IF NOT EXISTS cluster_lock SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS holder ON TABLE cluster_lock TYPE string;
DEFINE FIELD IF NOT EXISTS acquired_at ON TABLE cluster_lock TYPE datetime;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE cluster_lock TYPE datetime;
