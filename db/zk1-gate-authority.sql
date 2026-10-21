-- Root.ark #65: standalone SHARED PostgreSQL gate substrate.
-- Operator provisioned ONLY. Never run against Root.ark's application DB or
-- auto-bootstrap from a web request. Dedicated PG administrator must create
-- and verify the owner's independently pinned initial head out-of-band.
-- This DDL intentionally grants NO runtime role access. The gate operator must
-- isolate the SQL role/credentials in an independent trusted gate process.
BEGIN;
CREATE SCHEMA IF NOT EXISTS zk1_gate;
REVOKE ALL ON SCHEMA zk1_gate FROM PUBLIC;

CREATE TABLE IF NOT EXISTS zk1_gate.head (
  scope_key text PRIMARY KEY CHECK (length(scope_key) BETWEEN 35 AND 300),
  keyring_id bytea NOT NULL CHECK (octet_length(keyring_id)=16),
  revision bigint NOT NULL CHECK (revision > 0),
  digest bytea NOT NULL CHECK (octet_length(digest)=32),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  phase text NOT NULL DEFAULT 'OPEN' CHECK (phase IN ('OPEN','QUIESCING','PENDING')),
  operation_id bytea CHECK (operation_id IS NULL OR octet_length(operation_id)=16),
  reservation_id bytea CHECK (reservation_id IS NULL OR octet_length(reservation_id)=16),
  CHECK ((phase='OPEN' AND operation_id IS NULL AND reservation_id IS NULL)
       OR (phase<>'OPEN' AND operation_id IS NOT NULL AND reservation_id IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS zk1_gate.admission (
  id bytea PRIMARY KEY CHECK (octet_length(id)=16),
  scope_key text NOT NULL REFERENCES zk1_gate.head(scope_key),
  worker_id bytea NOT NULL CHECK (octet_length(worker_id)=16),
  principal text NOT NULL CHECK (length(principal) BETWEEN 1 AND 128),
  action text NOT NULL CHECK (action IN ('get','put')),
  object_id text NOT NULL CHECK (length(object_id) BETWEEN 1 AND 128),
  revision bigint NOT NULL CHECK (revision>0),
  digest bytea NOT NULL CHECK (octet_length(digest)=32),
  generation bigint NOT NULL CHECK (generation>0),
  state text NOT NULL CHECK (state IN ('ACTIVE','STOP_REQUESTED','FINISHED')),
  UNIQUE(scope_key,worker_id)
);
CREATE INDEX IF NOT EXISTS admission_unfinished
  ON zk1_gate.admission(scope_key,state);
-- This is a fully gated *physical PostgreSQL ciphertext provider*. Every
-- SELECT/UPSERT is executed by the gate service inside the SAME transaction
-- that holds head's FOR UPDATE lock and validates its generation.
CREATE TABLE IF NOT EXISTS zk1_gate.ciphertext_chunk (
  scope_key text NOT NULL REFERENCES zk1_gate.head(scope_key),
  object_id text NOT NULL,
  chunk_index integer NOT NULL CHECK(chunk_index>=0),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 4194304),
  PRIMARY KEY(scope_key,object_id,chunk_index)
);
REVOKE ALL ON ALL TABLES IN SCHEMA zk1_gate FROM PUBLIC;
-- Operator-only setup. The application account must NEVER hold membership
-- in this role. A separately administered login can be granted membership
-- only to the independently operated gate service (not to Root.ark web).
-- This role still trusts the gate service for phase/generation transitions;
-- it is not cryptographic isolation against a compromised gate operator.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='zk1_gate_runtime') THEN
    CREATE ROLE zk1_gate_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;
GRANT USAGE ON SCHEMA zk1_gate TO zk1_gate_runtime;
GRANT SELECT ON zk1_gate.head, zk1_gate.admission,
  zk1_gate.ciphertext_chunk TO zk1_gate_runtime;
GRANT UPDATE (phase, generation, operation_id, reservation_id)
  ON zk1_gate.head TO zk1_gate_runtime;
GRANT INSERT (id, scope_key, worker_id, principal, action, object_id,
  revision, digest, generation, state)
  ON zk1_gate.admission TO zk1_gate_runtime;
GRANT UPDATE (state) ON zk1_gate.admission TO zk1_gate_runtime;
GRANT INSERT (scope_key, object_id, chunk_index, ciphertext)
  ON zk1_gate.ciphertext_chunk TO zk1_gate_runtime;
COMMIT;
