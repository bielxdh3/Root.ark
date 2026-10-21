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
-- A restricted gate runtime is allowed to update ONLY phase/generation and
-- reservation identity columns. Enforce one-way phase and monotonically
-- increasing fencing generation in the DATABASE, not only in JavaScript.
-- OPEN can be restored later ONLY by a separate independently verified CAS
-- terminal-proof transition, which is intentionally NOT implemented yet.
CREATE OR REPLACE FUNCTION zk1_gate.enforce_head_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'gate transition requires READ COMMITTED isolation'
      USING ERRCODE='23514';
  END IF;
  IF NEW.scope_key IS DISTINCT FROM OLD.scope_key
    OR NEW.keyring_id IS DISTINCT FROM OLD.keyring_id
    OR NEW.revision IS DISTINCT FROM OLD.revision
    OR NEW.digest IS DISTINCT FROM OLD.digest THEN
    RAISE EXCEPTION 'gate head identity is immutable under runtime transition'
      USING ERRCODE='23514';
  END IF;
  IF OLD.phase = 'OPEN' AND NEW.phase = 'QUIESCING'
    AND NEW.generation = OLD.generation + 1
    AND OLD.operation_id IS NULL AND OLD.reservation_id IS NULL
    AND NEW.operation_id IS NOT NULL AND NEW.reservation_id IS NOT NULL THEN
    RETURN NEW;
  END IF;
  IF OLD.phase = 'QUIESCING' AND NEW.phase = 'PENDING'
    AND NEW.generation = OLD.generation
    AND NEW.operation_id IS NOT DISTINCT FROM OLD.operation_id
    AND NEW.reservation_id IS NOT DISTINCT FROM OLD.reservation_id THEN
    IF EXISTS (SELECT 1 FROM zk1_gate.admission
      WHERE scope_key=OLD.scope_key AND state <> 'FINISHED') THEN
      RAISE EXCEPTION 'gate workers have not durably drained'
        USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'illegal non-monotonic gate transition'
    USING ERRCODE='23514';
END $$;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
    JOIN pg_catalog.pg_class AS c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='head'
      AND t.tgname='zk1_gate_enforce_head_transition' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_enforce_head_transition
      BEFORE UPDATE ON zk1_gate.head
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.enforce_head_transition();
  END IF;
END $$;
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
-- Physical chunk writes are STAGING until a trusted worker, while OPEN,
-- seals the entire ordered ciphertext sequence against an independently
-- supplied authenticated root. No automatic conversion of old objects.
CREATE TABLE IF NOT EXISTS zk1_gate.sealed_object (
  scope_key text NOT NULL REFERENCES zk1_gate.head(scope_key),
  object_id text NOT NULL,
  revision bigint NOT NULL CHECK(revision > 0),
  digest bytea NOT NULL CHECK(octet_length(digest)=32),
  generation bigint NOT NULL CHECK(generation>0),
  admission_id bytea NOT NULL CHECK(octet_length(admission_id)=16),
  expected_chunks integer NOT NULL CHECK(expected_chunks BETWEEN 1 AND 4096),
  root_hash bytea NOT NULL CHECK(octet_length(root_hash)=32),
  PRIMARY KEY(scope_key,object_id)
);
-- A trusted worker may still possess an ACTIVE admission after sealing.
-- Physically forbid *all* later chunk INSERTs for that object, including
-- direct SQL by the restricted gate role. Lock the same authoritative head
-- to serialize against seal() and gate quiescence across connections.
CREATE OR REPLACE FUNCTION zk1_gate.reject_chunk_after_seal()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  -- A transaction that pinned a REPEATABLE READ/SERIALIZABLE MVCC snapshot
  -- *before* seal could otherwise acquire the head row lock *after* seal,
  -- still see sealed_object as absent, and insert a hidden late ciphertext
  -- chunk using the restricted runtime role. READ COMMITTED's fresh
  -- per-statement predicate check is a required part of this physical fence.
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'ciphertext chunk insertion requires READ COMMITTED isolation'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.head WHERE scope_key=NEW.scope_key FOR UPDATE;
  IF EXISTS (SELECT 1 FROM zk1_gate.sealed_object
             WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id) THEN
    RAISE EXCEPTION 'sealed ciphertext object is immutable'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
    JOIN pg_catalog.pg_class AS c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='ciphertext_chunk'
      AND t.tgname='zk1_gate_enforce_sealed_chunks' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_enforce_sealed_chunks
      BEFORE INSERT ON zk1_gate.ciphertext_chunk
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.reject_chunk_after_seal();
  END IF;
END $$;
-- A restricted gate SQL login can run INSERT directly. The database must
-- independently enforce SEALED completeness and the exact ciphertext root;
-- JavaScript checks alone are insufficient under overprivileged-gateway
-- compromise. PostgreSQL 18 supplies pg_catalog.sha256(bytea), requiring no
-- untrusted extension or backend-generated device signing key.
CREATE OR REPLACE FUNCTION zk1_gate.validate_sealed_object()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE
  item record;
  next_index integer := 0;
  transcript bytea;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'sealed object requires READ COMMITTED isolation'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.head
    WHERE scope_key=NEW.scope_key AND phase='OPEN'
      AND revision=NEW.revision AND digest=NEW.digest
      AND generation=NEW.generation FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'sealed object requires the current OPEN gate head'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.admission
    WHERE id=NEW.admission_id AND scope_key=NEW.scope_key
      AND action='put' AND object_id=NEW.object_id
      AND revision=NEW.revision AND digest=NEW.digest
      AND generation=NEW.generation AND state='ACTIVE';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'sealed object requires an active matching admission'
      USING ERRCODE='23514';
  END IF;
  transcript := pg_catalog.convert_to('Root.ark/zk-1/ciphertext-chunk-root/v1', 'UTF8')
    || pg_catalog.decode('00', 'hex') || pg_catalog.int4send(NEW.expected_chunks);
  -- Only index/length/hash bytes enter the transcript, NOT the potentially
  -- multi-GiB ciphertext itself. The domain/count/index/length ordering
  -- exactly matches rootark-zk-chunk-root-v1.js.
  FOR item IN SELECT chunk_index, ciphertext FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id
    ORDER BY chunk_index LOOP
    IF next_index >= NEW.expected_chunks OR item.chunk_index <> next_index THEN
      RAISE EXCEPTION 'sealed object has missing or excess ciphertext chunks'
        USING ERRCODE='23514';
    END IF;
    transcript := transcript || pg_catalog.int4send(item.chunk_index)
      || pg_catalog.int4send(pg_catalog.octet_length(item.ciphertext))
      || pg_catalog.sha256(item.ciphertext);
    next_index := next_index + 1;
  END LOOP;
  IF next_index <> NEW.expected_chunks
    OR pg_catalog.sha256(transcript) <> NEW.root_hash THEN
    RAISE EXCEPTION 'sealed object ciphertext commitment mismatch'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
    JOIN pg_catalog.pg_class AS c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='sealed_object'
      AND t.tgname='zk1_gate_validate_sealed_object' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_validate_sealed_object
      BEFORE INSERT ON zk1_gate.sealed_object
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.validate_sealed_object();
  END IF;
END $$;
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
  zk1_gate.ciphertext_chunk, zk1_gate.sealed_object TO zk1_gate_runtime;
GRANT UPDATE (phase, generation, operation_id, reservation_id)
  ON zk1_gate.head TO zk1_gate_runtime;
GRANT INSERT (id, scope_key, worker_id, principal, action, object_id,
  revision, digest, generation, state)
  ON zk1_gate.admission TO zk1_gate_runtime;
GRANT UPDATE (state) ON zk1_gate.admission TO zk1_gate_runtime;
GRANT INSERT (scope_key, object_id, chunk_index, ciphertext)
  ON zk1_gate.ciphertext_chunk TO zk1_gate_runtime;
GRANT INSERT (scope_key,object_id,revision,digest,generation,admission_id,
  expected_chunks,root_hash) ON zk1_gate.sealed_object TO zk1_gate_runtime;
COMMIT;
