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
  -- Legacy reference scopes default to non-attested mode. Independently
  -- operator-provisioned zk-1 scopes MUST explicitly enable strict STOP.
  require_stop_proof boolean NOT NULL DEFAULT false,
  -- Nominal dummy column permits PostgreSQL row-lock statements for a
  -- separate STOP recorder role. The head trigger rejects EVERY attempted
  -- UPDATE of this column, including no-op writes.
  stop_lock bigint NOT NULL DEFAULT 0,
  phase text NOT NULL DEFAULT 'OPEN' CHECK (phase IN ('OPEN','QUIESCING','PENDING')),
  operation_id bytea CHECK (operation_id IS NULL OR octet_length(operation_id)=16),
  reservation_id bytea CHECK (reservation_id IS NULL OR octet_length(reservation_id)=16),
  CHECK ((phase='OPEN' AND operation_id IS NULL AND reservation_id IS NULL)
       OR (phase<>'OPEN' AND operation_id IS NOT NULL AND reservation_id IS NOT NULL))
);
ALTER TABLE zk1_gate.head ADD COLUMN IF NOT EXISTS
  require_stop_proof boolean NOT NULL DEFAULT false;
ALTER TABLE zk1_gate.head ADD COLUMN IF NOT EXISTS
  stop_lock bigint NOT NULL DEFAULT 0;
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
  -- Strict physical-stop scopes pin the exact supervised OS process BEFORE
  -- its first physical chunk. Legacy non-strict admissions keep all NULL.
  host_key_id bytea CHECK(host_key_id IS NULL OR octet_length(host_key_id)=16),
  process_epoch bytea CHECK(process_epoch IS NULL OR octet_length(process_epoch)=16),
  process_pid bigint CHECK(process_pid IS NULL OR process_pid>0),
  state text NOT NULL CHECK (state IN ('ACTIVE','STOP_REQUESTED','FINISHED')),
  CHECK ((host_key_id IS NULL AND process_epoch IS NULL AND process_pid IS NULL)
      OR (host_key_id IS NOT NULL AND process_epoch IS NOT NULL AND process_pid IS NOT NULL)),
  UNIQUE(scope_key,worker_id)
);
ALTER TABLE zk1_gate.admission ADD COLUMN IF NOT EXISTS
  host_key_id bytea CHECK(host_key_id IS NULL OR octet_length(host_key_id)=16);
ALTER TABLE zk1_gate.admission ADD COLUMN IF NOT EXISTS
  process_epoch bytea CHECK(process_epoch IS NULL OR octet_length(process_epoch)=16);
ALTER TABLE zk1_gate.admission ADD COLUMN IF NOT EXISTS
  process_pid bigint CHECK(process_pid IS NULL OR process_pid>0);
CREATE INDEX IF NOT EXISTS admission_unfinished
  ON zk1_gate.admission(scope_key,state);
-- Separate STOP-witness evidence channel: the data-plane gate SQL login is
-- intentionally not allowed to INSERT here. A separate operator-owned
-- runtime must independently validate trusted physical worker termination
-- before depositing an immutable signed proof. A DB row alone does NOT attest
-- to OS process termination unless that separate recorder is trustworthy.
CREATE TABLE IF NOT EXISTS zk1_gate.physical_stop_receipt (
  admission_id bytea PRIMARY KEY REFERENCES zk1_gate.admission(id)
    CHECK(octet_length(admission_id)=16),
  scope_key text NOT NULL REFERENCES zk1_gate.head(scope_key),
  worker_id bytea NOT NULL CHECK(octet_length(worker_id)=16),
  generation bigint NOT NULL CHECK(generation>0),
  host_key_id bytea NOT NULL CHECK(octet_length(host_key_id)=16),
  process_epoch bytea NOT NULL CHECK(octet_length(process_epoch)=16),
  process_pid bigint NOT NULL CHECK(process_pid>0),
  stopped_at bigint NOT NULL CHECK(stopped_at>0),
  proof_digest bytea NOT NULL CHECK(octet_length(proof_digest)=32),
  signed_proof bytea NOT NULL CHECK(octet_length(signed_proof) BETWEEN 100 AND 4096)
);
CREATE INDEX IF NOT EXISTS physical_stop_by_scope
  ON zk1_gate.physical_stop_receipt(scope_key,generation);
CREATE OR REPLACE FUNCTION zk1_gate.validate_physical_stop_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'physical stop receipt requires READ COMMITTED isolation'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.head WHERE scope_key=NEW.scope_key
    AND require_stop_proof=TRUE AND phase IN ('OPEN','QUIESCING') FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no strict trusted worker-stop authority for scope'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.admission
    WHERE id=NEW.admission_id AND scope_key=NEW.scope_key
      AND worker_id=NEW.worker_id AND generation=NEW.generation
      AND host_key_id=NEW.host_key_id AND process_epoch=NEW.process_epoch
      AND process_pid=NEW.process_pid
      AND state IN ('ACTIVE','STOP_REQUESTED');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'STOP receipt is not bound to an unfinished admission'
      USING ERRCODE='23514';
  END IF;
  IF pg_catalog.sha256(NEW.signed_proof) <> NEW.proof_digest THEN
    RAISE EXCEPTION 'STOP receipt wire digest mismatch'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
    JOIN pg_catalog.pg_class AS c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='physical_stop_receipt'
      AND t.tgname='zk1_gate_validate_physical_stop_receipt' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_validate_physical_stop_receipt
      BEFORE INSERT ON zk1_gate.physical_stop_receipt
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.validate_physical_stop_receipt();
  END IF;
END $$;
CREATE OR REPLACE FUNCTION zk1_gate.validate_admission_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE
  strict_mode boolean;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'admission transition requires READ COMMITTED isolation'
      USING ERRCODE='23514';
  END IF;
  IF TG_OP='INSERT' THEN
    -- This lock fences direct restricted-role SQL INSERT during QUIESCING.
    SELECT require_stop_proof INTO strict_mode FROM zk1_gate.head
      WHERE scope_key=NEW.scope_key AND phase='OPEN'
        AND generation=NEW.generation AND revision=NEW.revision
        AND digest=NEW.digest FOR UPDATE;
    IF NOT FOUND OR NEW.state <> 'ACTIVE' THEN
      RAISE EXCEPTION 'admission requires a current OPEN gate head'
        USING ERRCODE='23514';
    END IF;
    IF (strict_mode AND (NEW.host_key_id IS NULL
      OR NEW.process_epoch IS NULL OR NEW.process_pid IS NULL))
      OR (NOT strict_mode AND (NEW.host_key_id IS NOT NULL
        OR NEW.process_epoch IS NOT NULL OR NEW.process_pid IS NOT NULL)) THEN
      RAISE EXCEPTION 'worker process identity does not match STOP policy'
        USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
    OR NEW.scope_key IS DISTINCT FROM OLD.scope_key
    OR NEW.worker_id IS DISTINCT FROM OLD.worker_id
    OR NEW.principal IS DISTINCT FROM OLD.principal
    OR NEW.action IS DISTINCT FROM OLD.action
    OR NEW.object_id IS DISTINCT FROM OLD.object_id
    OR NEW.revision IS DISTINCT FROM OLD.revision
    OR NEW.digest IS DISTINCT FROM OLD.digest
    OR NEW.generation IS DISTINCT FROM OLD.generation
    OR NEW.host_key_id IS DISTINCT FROM OLD.host_key_id
    OR NEW.process_epoch IS DISTINCT FROM OLD.process_epoch
    OR NEW.process_pid IS DISTINCT FROM OLD.process_pid THEN
    RAISE EXCEPTION 'worker identity and generation are immutable'
      USING ERRCODE='23514';
  END IF;
  IF OLD.state='ACTIVE' AND NEW.state='STOP_REQUESTED' THEN
    PERFORM 1 FROM zk1_gate.head WHERE scope_key=NEW.scope_key
      AND phase='QUIESCING';
    IF FOUND THEN RETURN NEW; END IF;
  END IF;
  IF OLD.state IN ('ACTIVE','STOP_REQUESTED') AND NEW.state='FINISHED' THEN
    SELECT require_stop_proof INTO strict_mode
      FROM zk1_gate.head WHERE scope_key=NEW.scope_key;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'missing gate scope for completion'
        USING ERRCODE='23514';
    END IF;
    IF strict_mode AND NOT EXISTS (SELECT 1
      FROM zk1_gate.physical_stop_receipt AS ack
      WHERE ack.admission_id=NEW.id AND ack.scope_key=NEW.scope_key
        AND ack.worker_id=NEW.worker_id AND ack.generation=NEW.generation) THEN
      RAISE EXCEPTION 'independent physical STOP receipt required'
        USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'illegal worker admission state transition'
    USING ERRCODE='23514';
END $$;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
    JOIN pg_catalog.pg_class AS c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='admission'
      AND t.tgname='zk1_gate_validate_admission_transition' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_validate_admission_transition
      BEFORE INSERT OR UPDATE ON zk1_gate.admission
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.validate_admission_transition();
  END IF;
END $$;
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
    OR NEW.digest IS DISTINCT FROM OLD.digest
    OR NEW.require_stop_proof IS DISTINCT FROM OLD.require_stop_proof
    OR NEW.stop_lock IS DISTINCT FROM OLD.stop_lock THEN
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
    IF OLD.require_stop_proof AND EXISTS (
      SELECT 1 FROM zk1_gate.admission AS a
      WHERE a.scope_key=OLD.scope_key AND NOT EXISTS (
        SELECT 1 FROM zk1_gate.physical_stop_receipt AS ack
        WHERE ack.admission_id=a.id AND ack.scope_key=a.scope_key
          AND ack.worker_id=a.worker_id AND ack.generation=a.generation)) THEN
      RAISE EXCEPTION 'independent physical STOP evidence is incomplete'
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
-- to serialize against seal() and gate quiescence across connections. The
-- physical fence also requires OPEN + a matching current-generation ACTIVE
-- PUT admission; an unsealed object must not be a way around quiescence.
CREATE OR REPLACE FUNCTION zk1_gate.reject_chunk_after_seal()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  current_head record;
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
  -- This exact trigger is operator-owned SECURITY DEFINER so a restricted
  -- physical writer can INSERT ciphertext without UPDATE privilege on the
  -- gate head. It still acquires a real FOR UPDATE row lock before the
  -- effect. Caller-controlled identifiers remain bound parameters and
  -- every referenced object is schema-qualified with pinned search_path.
  SELECT revision,digest,generation INTO current_head FROM zk1_gate.head
    WHERE scope_key=NEW.scope_key AND phase='OPEN' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ciphertext chunk insertion requires current OPEN gate'
      USING ERRCODE='23514';
  END IF;
  IF NEW.chunk_index > 4095 THEN
    RAISE EXCEPTION 'ciphertext chunk index exceeds the committed format limit'
      USING ERRCODE='23514';
  END IF;
  IF EXISTS (SELECT 1 FROM zk1_gate.sealed_object
             WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id) THEN
    RAISE EXCEPTION 'sealed ciphertext object is immutable'
      USING ERRCODE='23514';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM zk1_gate.admission
                 WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id
                   AND action='put' AND state='ACTIVE'
                   AND revision=current_head.revision
                   AND digest=current_head.digest
                   AND generation=current_head.generation) THEN
    RAISE EXCEPTION 'ciphertext chunk insertion requires active admission'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION zk1_gate.reject_chunk_after_seal() FROM PUBLIC;
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
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='zk1_gate_runtime') THEN
    CREATE ROLE zk1_gate_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='zk1_stop_runtime') THEN
    CREATE ROLE zk1_stop_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='zk1_chunk_writer_runtime') THEN
    CREATE ROLE zk1_chunk_writer_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;
GRANT USAGE ON SCHEMA zk1_gate TO zk1_gate_runtime;
GRANT SELECT ON zk1_gate.head, zk1_gate.admission,
  zk1_gate.ciphertext_chunk, zk1_gate.sealed_object,
  zk1_gate.physical_stop_receipt TO zk1_gate_runtime;
GRANT UPDATE (phase, generation, operation_id, reservation_id)
  ON zk1_gate.head TO zk1_gate_runtime;
GRANT INSERT (id, scope_key, worker_id, principal, action, object_id,
  revision, digest, generation, state, host_key_id, process_epoch, process_pid)
  ON zk1_gate.admission TO zk1_gate_runtime;
GRANT UPDATE (state) ON zk1_gate.admission TO zk1_gate_runtime;
GRANT INSERT (scope_key, object_id, chunk_index, ciphertext)
  ON zk1_gate.ciphertext_chunk TO zk1_gate_runtime;
GRANT INSERT (scope_key,object_id,revision,digest,generation,admission_id,
  expected_chunks,root_hash) ON zk1_gate.sealed_object TO zk1_gate_runtime;
GRANT USAGE ON SCHEMA zk1_gate TO zk1_stop_runtime;
GRANT SELECT ON zk1_gate.head, zk1_gate.admission,
  zk1_gate.physical_stop_receipt TO zk1_stop_runtime;
GRANT UPDATE (stop_lock) ON zk1_gate.head TO zk1_stop_runtime;
GRANT INSERT (admission_id,scope_key,worker_id,generation,host_key_id,
  process_epoch,process_pid,stopped_at,proof_digest,signed_proof)
  ON zk1_gate.physical_stop_receipt TO zk1_stop_runtime;
-- A supervised physical writer gets a different credential from the gate
-- controller: it may inspect *only ciphertext-side* state and insert bounded
-- staging bytes. It MUST NOT mint admissions, advance head generation,
-- publish SEALED, record STOP receipts or impersonate the gate controller.
GRANT USAGE ON SCHEMA zk1_gate TO zk1_chunk_writer_runtime;
GRANT SELECT ON zk1_gate.head, zk1_gate.admission,
  zk1_gate.ciphertext_chunk, zk1_gate.sealed_object
  TO zk1_chunk_writer_runtime;
GRANT INSERT (scope_key,object_id,chunk_index,ciphertext)
  ON zk1_gate.ciphertext_chunk TO zk1_chunk_writer_runtime;
COMMIT;
