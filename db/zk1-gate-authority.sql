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
  -- Opt-in per *new* scope only. This cannot be toggled by runtime SQL and
  -- prevents restricted gate/child INSERT and SEALED bypassing exact prewrite
  -- operation intent. Legacy scopes remain explicitly non-strict.
  require_physical_inventory_intent boolean NOT NULL DEFAULT false,
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
  require_physical_inventory_intent boolean NOT NULL DEFAULT false;
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
-- A separately provisioned physical writer LOGIN may be bound by the trusted
-- gate to exactly ONE strict admission/object/process. This binding is
-- operator-inserted and immutable; the writer login is never allowed to
-- SELECT, INSERT, UPDATE or DELETE it. session_user (not mutable SET ROLE or
-- caller-supplied application_name) identifies that exact authenticated
-- PostgreSQL login inside the physical chunk trigger.
CREATE TABLE IF NOT EXISTS zk1_gate.writer_binding (
  writer_login name PRIMARY KEY,
  admission_id bytea NOT NULL UNIQUE REFERENCES zk1_gate.admission(id),
  scope_key text NOT NULL REFERENCES zk1_gate.head(scope_key),
  object_id text NOT NULL,
  worker_id bytea NOT NULL CHECK(octet_length(worker_id)=16),
  generation bigint NOT NULL CHECK(generation>0),
  process_epoch bytea NOT NULL CHECK(octet_length(process_epoch)=16),
  process_pid bigint NOT NULL CHECK(process_pid>0)
);
CREATE OR REPLACE FUNCTION zk1_gate.validate_writer_binding()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed'
    OR NOT pg_catalog.pg_has_role(NEW.writer_login,'zk1_chunk_writer_runtime','USAGE')
    OR pg_catalog.pg_has_role(NEW.writer_login,'zk1_gate_runtime','MEMBER')
    OR pg_catalog.pg_has_role(NEW.writer_login,'zk1_stop_runtime','MEMBER') THEN
    RAISE EXCEPTION 'writer identity requires independently restricted runtime'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.head WHERE scope_key=NEW.scope_key
    AND require_stop_proof=TRUE AND phase='OPEN' AND generation=NEW.generation FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'writer binding requires current strict OPEN generation'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.admission WHERE id=NEW.admission_id
    AND scope_key=NEW.scope_key AND worker_id=NEW.worker_id
    AND object_id=NEW.object_id AND action='put' AND state='ACTIVE'
    AND generation=NEW.generation AND process_epoch=NEW.process_epoch
    AND process_pid=NEW.process_pid;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'writer binding requires exact active supervised admission'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION zk1_gate.validate_writer_binding() FROM PUBLIC;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
    JOIN pg_catalog.pg_class AS c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='writer_binding'
      AND t.tgname='zk1_gate_validate_writer_binding' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_validate_writer_binding
      BEFORE INSERT ON zk1_gate.writer_binding
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.validate_writer_binding();
  END IF;
END $$;
-- Only a yes/no check with an exact, independently pinned tuple crosses the
-- privileged binding table boundary. A client-provided session claim has no
-- authority because session_user is the authenticated PostgreSQL login.
CREATE OR REPLACE FUNCTION zk1_gate.verify_chunk_writer_binding(
  p_scope_key text, p_admission_id bytea, p_object_id text,
  p_generation bigint, p_worker_id bytea, p_process_epoch bytea,
  p_process_pid bigint, p_revision bigint, p_digest bytea,
  p_keyring_id bytea, p_principal text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT EXISTS (
    SELECT 1 FROM zk1_gate.writer_binding AS b
    JOIN zk1_gate.admission AS a ON a.id=b.admission_id
    JOIN zk1_gate.head AS h ON h.scope_key=b.scope_key
    WHERE b.writer_login=session_user
      AND b.scope_key=p_scope_key AND b.admission_id=p_admission_id
      AND b.object_id=p_object_id AND b.generation=p_generation
      AND b.worker_id=p_worker_id AND b.process_epoch=p_process_epoch
      AND b.process_pid=p_process_pid
      AND h.phase='OPEN' AND h.require_stop_proof=TRUE
      AND h.generation=p_generation AND h.revision=p_revision
      AND h.digest=p_digest AND h.keyring_id=p_keyring_id
      AND a.scope_key=b.scope_key AND a.worker_id=b.worker_id
      AND a.object_id=b.object_id AND a.generation=b.generation
      AND a.process_epoch=b.process_epoch AND a.process_pid=b.process_pid
      AND a.principal=p_principal AND a.action='put' AND a.state='ACTIVE'
      AND a.revision=p_revision AND a.digest=p_digest
  )
$$;
REVOKE ALL ON FUNCTION zk1_gate.verify_chunk_writer_binding(
  text,bytea,text,bigint,bytea,bytea,bigint,bigint,bytea,bytea,text) FROM PUBLIC;
-- Only SQL physical effect exposed to a delegated child. Its authenticated
-- PostgreSQL session_user resolves a single immutable operator-owned
-- admission. No caller-provided scope, object or process identifier can
-- select another tenant or admission.
CREATE OR REPLACE FUNCTION zk1_gate.write_bound_chunk(
  p_chunk_index integer, p_ciphertext bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  bound record;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed'
    OR p_chunk_index IS NULL OR p_chunk_index < 0 OR p_chunk_index > 4095
    OR p_ciphertext IS NULL
    OR pg_catalog.octet_length(p_ciphertext) NOT BETWEEN 1 AND 4194304
    OR NOT pg_catalog.pg_has_role(session_user,'zk1_chunk_writer_runtime','USAGE')
    OR pg_catalog.pg_has_role(session_user,'zk1_gate_runtime','MEMBER')
    OR pg_catalog.pg_has_role(session_user,'zk1_stop_runtime','MEMBER') THEN
    RAISE EXCEPTION 'physical writer runtime or chunk invalid'
      USING ERRCODE='23514';
  END IF;
  SELECT writer_login,admission_id,scope_key,object_id,worker_id,generation,
    process_epoch,process_pid INTO bound
    FROM zk1_gate.writer_binding WHERE writer_login=session_user;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'physical writer has no trusted admission binding'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.head WHERE scope_key=bound.scope_key
    AND require_stop_proof=TRUE AND phase='OPEN'
    AND generation=bound.generation FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'physical writer generation is closed'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_gate.admission
    WHERE id=bound.admission_id AND scope_key=bound.scope_key
    AND object_id=bound.object_id AND worker_id=bound.worker_id
    AND generation=bound.generation AND process_epoch=bound.process_epoch
    AND process_pid=bound.process_pid AND action='put' AND state='ACTIVE';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'physical writer admission is not ACTIVE'
      USING ERRCODE='23514';
  END IF;
  INSERT INTO zk1_gate.ciphertext_chunk(scope_key,object_id,chunk_index,ciphertext)
    VALUES(bound.scope_key,bound.object_id,p_chunk_index,p_ciphertext);
  RETURN TRUE;
END $$;
REVOKE ALL ON FUNCTION zk1_gate.write_bound_chunk(integer,bytea) FROM PUBLIC;
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
    OR NEW.require_physical_inventory_intent IS DISTINCT FROM OLD.require_physical_inventory_intent
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
  -- Populated and checked by SQL trigger on opted-in physical-intent scopes.
  -- NULL on legacy scopes, which are not claimed as operation-bound.
  operation_id bytea CHECK(operation_id IS NULL OR octet_length(operation_id)=16),
  PRIMARY KEY(scope_key,object_id)
);
ALTER TABLE zk1_gate.sealed_object ADD COLUMN IF NOT EXISTS
  operation_id bytea CHECK(operation_id IS NULL OR octet_length(operation_id)=16);
-- The exact owner-authorized inventory operation must be recorded *before*
-- the first ciphertext chunk. Without this prewrite immutable binding, a
-- recovered SEALED object could be relabeled under an unrelated operation ID.
CREATE TABLE IF NOT EXISTS zk1_gate.physical_inventory_intent (
  scope_key text NOT NULL REFERENCES zk1_gate.head(scope_key),
  object_id text NOT NULL,
  operation_id bytea NOT NULL UNIQUE CHECK(octet_length(operation_id)=16),
  expected_inventory_sequence bigint NOT NULL CHECK(expected_inventory_sequence>=0),
  expected_inventory_root bytea NOT NULL CHECK(octet_length(expected_inventory_root)=32),
  keyring_id bytea NOT NULL CHECK(octet_length(keyring_id)=16),
  revision bigint NOT NULL CHECK(revision>0),
  epoch bigint NOT NULL CHECK(epoch>=0),
  digest bytea NOT NULL CHECK(octet_length(digest)=32),
  generation bigint NOT NULL CHECK(generation>0),
  ciphertext_sha256 bytea NOT NULL CHECK(octet_length(ciphertext_sha256)=32),
  expected_root_hash bytea NOT NULL CHECK(octet_length(expected_root_hash)=32),
  expected_chunks integer NOT NULL CHECK(expected_chunks BETWEEN 1 AND 16),
  PRIMARY KEY(scope_key,object_id)
);
-- Separate second-phase binding: the owner-operation intent MUST exist before
-- the first strict PUT admission. The PostgreSQL admission trigger pins its
-- exact admission ID atomically under the same gate head row lock. No client
-- or gate login may insert or relabel a binding directly. A competing PUT is
-- denied, not permitted to seal under another admission.
CREATE TABLE IF NOT EXISTS zk1_gate.physical_inventory_admission (
  scope_key text NOT NULL REFERENCES zk1_gate.head(scope_key),
  object_id text NOT NULL,
  operation_id bytea NOT NULL UNIQUE CHECK(octet_length(operation_id)=16),
  admission_id bytea NOT NULL UNIQUE REFERENCES zk1_gate.admission(id),
  generation bigint NOT NULL CHECK(generation>0),
  PRIMARY KEY(scope_key,object_id)
);
CREATE OR REPLACE FUNCTION zk1_gate.pin_physical_inventory_admission()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  h record;
  i record;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'physical admission requires READ COMMITTED' USING ERRCODE='23514';
  END IF;
  SELECT require_physical_inventory_intent,generation INTO h FROM zk1_gate.head
    WHERE scope_key=NEW.scope_key AND phase='OPEN' FOR UPDATE;
  IF NOT FOUND OR h.generation<>NEW.generation THEN
    RAISE EXCEPTION 'physical admission requires current OPEN head' USING ERRCODE='23514';
  END IF;
  IF h.require_physical_inventory_intent AND NEW.action='put' THEN
    SELECT operation_id,revision,digest,generation INTO i
      FROM zk1_gate.physical_inventory_intent
      WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id;
    IF NOT FOUND OR i.revision<>NEW.revision OR i.digest<>NEW.digest
      OR i.generation<>NEW.generation THEN
      RAISE EXCEPTION 'strict PUT admission requires exact prewrite intent'
        USING ERRCODE='23514';
    END IF;
    INSERT INTO zk1_gate.physical_inventory_admission
      (scope_key,object_id,operation_id,admission_id,generation)
      VALUES(NEW.scope_key,NEW.object_id,i.operation_id,NEW.id,NEW.generation);
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION zk1_gate.pin_physical_inventory_admission() FROM PUBLIC;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t
    JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='admission'
      AND t.tgname='zk1_gate_zz_pin_physical_admission' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_zz_pin_physical_admission
      AFTER INSERT ON zk1_gate.admission
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.pin_physical_inventory_admission();
  END IF;
END $$;
CREATE OR REPLACE FUNCTION zk1_gate.reject_physical_inventory_admission_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'physical admission binding is immutable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION zk1_gate.reject_physical_inventory_admission_mutation() FROM PUBLIC;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t
    JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='physical_inventory_admission'
      AND t.tgname='zk1_gate_physical_inventory_admission_immutable' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_physical_inventory_admission_immutable
      BEFORE UPDATE OR DELETE ON zk1_gate.physical_inventory_admission
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.reject_physical_inventory_admission_mutation();
  END IF;
END $$;
CREATE OR REPLACE FUNCTION zk1_gate.validate_physical_inventory_intent()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  h record;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'physical inventory intent requires READ COMMITTED' USING ERRCODE='23514';
  END IF;
  SELECT generation,revision,digest,keyring_id INTO h FROM zk1_gate.head
    WHERE scope_key=NEW.scope_key AND phase='OPEN' FOR UPDATE;
  IF NOT FOUND OR h.generation<>NEW.generation OR h.revision<>NEW.revision
    OR h.digest<>NEW.digest OR h.keyring_id<>NEW.keyring_id THEN
    RAISE EXCEPTION 'physical inventory intent requires current OPEN generation'
      USING ERRCODE='23514';
  END IF;
  IF EXISTS(SELECT 1 FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id)
    OR EXISTS(SELECT 1 FROM zk1_gate.sealed_object
    WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id) THEN
    RAISE EXCEPTION 'physical intent cannot relabel previously written bytes'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION zk1_gate.validate_physical_inventory_intent() FROM PUBLIC;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t
    JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='physical_inventory_intent'
      AND t.tgname='zk1_gate_validate_physical_inventory_intent' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_validate_physical_inventory_intent
      BEFORE INSERT ON zk1_gate.physical_inventory_intent
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.validate_physical_inventory_intent();
  END IF;
END $$;
CREATE OR REPLACE FUNCTION zk1_gate.reject_physical_inventory_intent_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'physical inventory intent is immutable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION zk1_gate.reject_physical_inventory_intent_mutation() FROM PUBLIC;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t
    JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='zk1_gate' AND c.relname='physical_inventory_intent'
      AND t.tgname='zk1_gate_physical_inventory_intent_immutable' AND NOT t.tgisinternal) THEN
    CREATE TRIGGER zk1_gate_physical_inventory_intent_immutable
      BEFORE UPDATE OR DELETE ON zk1_gate.physical_inventory_intent
      FOR EACH ROW EXECUTE FUNCTION zk1_gate.reject_physical_inventory_intent_mutation();
  END IF;
END $$;
-- Independently flush every WAL record up to the snapshot taken *after* the
-- attestor observes a physically committed sealed row. A writer's own
-- synchronous_commit setting cannot be trusted: it may be SET LOCAL off.
-- Merely polling pg_current_wal_flush_lsn can time out during delayed WAL
-- writer fsync even when the sealed operation itself was committed. PostgreSQL
-- 18's nontransactional, flush=true logical message invokes XLogFlush for all
-- earlier WAL (including asynchronously committed transactions). Its fixed
-- empty payload is not caller input. Only the operator-owned function may
-- emit this marker; callers receive no WAL internals or privileged SQL broker.
CREATE OR REPLACE FUNCTION zk1_gate.physical_inventory_wal_flush_barrier()
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  barrier pg_catalog.pg_lsn;
  expires timestamptz;
BEGIN
  barrier := pg_catalog.pg_current_wal_insert_lsn();
  expires := pg_catalog.clock_timestamp() + interval '2 seconds';
  IF pg_catalog.pg_current_wal_flush_lsn() >= barrier THEN RETURN true; END IF;
  PERFORM pg_catalog.pg_logical_emit_message(
    false, 'zk1-physical-wal-flush-barrier', ''::pg_catalog.text, true);
  RETURN pg_catalog.clock_timestamp() <= expires
    AND pg_catalog.pg_current_wal_flush_lsn() >= barrier;
END $$;
REVOKE ALL ON FUNCTION zk1_gate.physical_inventory_wal_flush_barrier() FROM PUBLIC;
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
  SELECT revision,digest,generation,require_physical_inventory_intent INTO current_head FROM zk1_gate.head
    WHERE scope_key=NEW.scope_key AND phase='OPEN' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ciphertext chunk insertion requires current OPEN gate'
      USING ERRCODE='23514';
  END IF;
  IF NEW.chunk_index > 4095 THEN
    RAISE EXCEPTION 'ciphertext chunk index exceeds the committed format limit'
      USING ERRCODE='23514';
  END IF;
  IF current_head.require_physical_inventory_intent AND NOT EXISTS (
    SELECT 1 FROM zk1_gate.physical_inventory_intent AS i
    WHERE i.scope_key=NEW.scope_key AND i.object_id=NEW.object_id
      AND i.generation=current_head.generation
      AND i.revision=current_head.revision AND i.digest=current_head.digest
      AND NEW.chunk_index<i.expected_chunks
  ) THEN
    RAISE EXCEPTION 'strict chunk requires exact prewrite physical operation intent'
      USING ERRCODE='23514';
  END IF;
  IF current_head.require_physical_inventory_intent AND NOT EXISTS (
    SELECT 1 FROM zk1_gate.physical_inventory_admission AS b
      JOIN zk1_gate.admission AS a ON a.id=b.admission_id
    WHERE b.scope_key=NEW.scope_key AND b.object_id=NEW.object_id
      AND b.generation=current_head.generation
      AND a.state='ACTIVE' AND a.action='put'
      AND a.scope_key=NEW.scope_key AND a.object_id=NEW.object_id
      AND a.generation=b.generation
  ) THEN
    RAISE EXCEPTION 'strict chunk requires bound physical PUT admission'
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
  -- PostgreSQL superusers can appear to have every role privilege even
  -- without ordinary membership. This dedicated-child branch must not
  -- reinterpret an explicitly trusted DB administrator as a child login.
  IF pg_catalog.pg_has_role(session_user,'zk1_chunk_writer_runtime','MEMBER')
    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname=session_user AND rolsuper=TRUE) THEN
    -- A delegated child cannot inherit either controller role or write to an
    -- unrelated tenant's active object. The independently provisioned SQL
    -- LOGIN, not caller-supplied WorkerId, indexes an immutable binding.
    IF pg_catalog.pg_has_role(session_user,'zk1_gate_runtime','MEMBER')
      OR pg_catalog.pg_has_role(session_user,'zk1_stop_runtime','MEMBER') THEN
      RAISE EXCEPTION 'writer runtime cannot hold gate or STOP authority'
        USING ERRCODE='23514';
    END IF;
    PERFORM 1 FROM zk1_gate.writer_binding AS b
      JOIN zk1_gate.admission AS a ON a.id=b.admission_id
      WHERE b.writer_login=session_user
        AND b.scope_key=NEW.scope_key AND b.object_id=NEW.object_id
        AND b.generation=current_head.generation
        AND a.scope_key=b.scope_key AND a.object_id=b.object_id
        AND a.worker_id=b.worker_id AND a.generation=b.generation
        AND a.process_epoch=b.process_epoch AND a.process_pid=b.process_pid
        AND a.action='put' AND a.state='ACTIVE'
        AND a.revision=current_head.revision AND a.digest=current_head.digest;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'physical child writer lacks bound active admission'
        USING ERRCODE='23514';
    END IF;
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
  h record;
  i record;
  b record;
  next_index integer := 0;
  transcript bytea;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'sealed object requires READ COMMITTED isolation'
      USING ERRCODE='23514';
  END IF;
  SELECT require_physical_inventory_intent INTO h FROM zk1_gate.head
    WHERE scope_key=NEW.scope_key AND phase='OPEN'
      AND revision=NEW.revision AND digest=NEW.digest
      AND generation=NEW.generation FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'sealed object requires the current OPEN gate head'
      USING ERRCODE='23514';
  END IF;
  IF h.require_physical_inventory_intent THEN
    SELECT operation_id,revision,digest,generation,expected_chunks,
      expected_root_hash INTO i FROM zk1_gate.physical_inventory_intent
      WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id;
    IF NOT FOUND OR i.revision<>NEW.revision OR i.digest<>NEW.digest
      OR i.generation<>NEW.generation OR i.expected_chunks<>NEW.expected_chunks
      OR i.expected_root_hash<>NEW.root_hash
      OR (NEW.operation_id IS NOT NULL AND NEW.operation_id<>i.operation_id) THEN
      RAISE EXCEPTION 'strict seal requires exact prewrite operation binding'
        USING ERRCODE='23514';
    END IF;
    NEW.operation_id := i.operation_id;
    SELECT operation_id,admission_id,generation INTO b
      FROM zk1_gate.physical_inventory_admission
      WHERE scope_key=NEW.scope_key AND object_id=NEW.object_id;
    IF NOT FOUND OR b.operation_id<>i.operation_id
      OR b.admission_id<>NEW.admission_id OR b.generation<>NEW.generation THEN
      RAISE EXCEPTION 'strict seal requires the operation-bound physical admission'
        USING ERRCODE='23514';
    END IF;
  ELSIF NEW.operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'non-strict seal cannot impersonate a physical operation'
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
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='zk1_physical_attestor_runtime') THEN
    CREATE ROLE zk1_physical_attestor_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
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
GRANT INSERT (writer_login,admission_id,scope_key,object_id,worker_id,
  generation,process_epoch,process_pid)
  ON zk1_gate.writer_binding TO zk1_gate_runtime;
GRANT INSERT (scope_key,object_id,revision,digest,generation,admission_id,
  expected_chunks,root_hash) ON zk1_gate.sealed_object TO zk1_gate_runtime;
GRANT SELECT ON zk1_gate.physical_inventory_intent,
  zk1_gate.physical_inventory_admission TO zk1_gate_runtime;
GRANT INSERT (scope_key,object_id,operation_id,expected_inventory_sequence,
  expected_inventory_root,keyring_id,revision,epoch,digest,generation,
  ciphertext_sha256,expected_root_hash,expected_chunks)
  ON zk1_gate.physical_inventory_intent TO zk1_gate_runtime;
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
REVOKE SELECT ON zk1_gate.head,zk1_gate.admission,
  zk1_gate.ciphertext_chunk,zk1_gate.sealed_object
  FROM zk1_chunk_writer_runtime;
REVOKE SELECT (chunk_index) ON zk1_gate.ciphertext_chunk
  FROM zk1_chunk_writer_runtime;
REVOKE INSERT ON zk1_gate.ciphertext_chunk FROM zk1_chunk_writer_runtime;
GRANT EXECUTE ON FUNCTION zk1_gate.verify_chunk_writer_binding(
  text,bytea,text,bigint,bytea,bytea,bigint,bigint,bytea,bytea,text)
  TO zk1_chunk_writer_runtime;
GRANT EXECUTE ON FUNCTION zk1_gate.write_bound_chunk(integer,bytea)
  TO zk1_chunk_writer_runtime;
-- Separate, read-only physical readback identity. Never co-grant this with
-- gate/stop/writer roles; the verifier rejects even latent SET ROLE access.
GRANT USAGE ON SCHEMA zk1_gate TO zk1_physical_attestor_runtime;
GRANT SELECT ON zk1_gate.head,zk1_gate.sealed_object,
  zk1_gate.ciphertext_chunk,zk1_gate.physical_inventory_intent,
  zk1_gate.physical_inventory_admission TO zk1_physical_attestor_runtime;
GRANT EXECUTE ON FUNCTION zk1_gate.physical_inventory_wal_flush_barrier()
  TO zk1_physical_attestor_runtime;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER
  ON zk1_gate.head,zk1_gate.sealed_object,zk1_gate.ciphertext_chunk,
    zk1_gate.physical_inventory_intent,zk1_gate.physical_inventory_admission
  FROM zk1_physical_attestor_runtime;
COMMIT;
