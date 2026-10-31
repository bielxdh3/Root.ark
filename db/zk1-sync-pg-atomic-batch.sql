-- DEV-OFF NONAUTHORIZING trusted-runtime PostgreSQL 18 prototype.
-- Provision scopes, device pins and initial object states independently.
-- NO-GO for security authority: current runtime role has raw table writes,
-- and SQL does not independently authenticate Ed25519. A compromised writer
-- can fabricate coherent rows/markers; only an independently verified
-- DB-side admission boundary can turn this into a security authority.
-- DO NOT attach this to JSON Sync, trust its head, or remove HTTP 503.
-- Run once as an operator on a disposable/dedicated PG cluster, never on app DB.
BEGIN;
CREATE SCHEMA IF NOT EXISTS zk1_sync_batch;
REVOKE ALL ON SCHEMA zk1_sync_batch FROM PUBLIC;

CREATE TABLE zk1_sync_batch.scope_policy (
  -- PostgreSQL ARE bounds must not exceed 255; enforce 256 via length.
  scope text PRIMARY KEY CHECK (length(scope) BETWEEN 1 AND 256
    AND scope ~ '^[A-Za-z0-9._:-]+$'),
  username text NOT NULL CHECK (length(username) BETWEEN 1 AND 512),
  compartment_id text NOT NULL CHECK (compartment_id ~ '^[A-Za-z0-9._:-]{1,160}$'),
  key_epoch text NOT NULL CHECK (key_epoch ~ '^[A-Za-z0-9._:-]{1,160}$'),
  enabled boolean NOT NULL DEFAULT false,
  allow_delete boolean NOT NULL DEFAULT false,
  policy_epoch bigint NOT NULL DEFAULT 1 CHECK (policy_epoch > 0)
);
CREATE TABLE zk1_sync_batch.scope_head (
  scope text PRIMARY KEY REFERENCES zk1_sync_batch.scope_policy(scope),
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  head bytea NOT NULL DEFAULT decode(repeat('00',32),'hex') CHECK (octet_length(head)=32)
);
CREATE TABLE zk1_sync_batch.device_grant (
  scope text NOT NULL REFERENCES zk1_sync_batch.scope_policy(scope),
  device_id text NOT NULL CHECK (device_id ~ '^[A-Za-z0-9._:-]{1,160}$'),
  public_key text NOT NULL CHECK (length(public_key) BETWEEN 40 AND 512),
  revoked boolean NOT NULL DEFAULT true,
  PRIMARY KEY(scope, device_id),
  -- Sync v2 device authorization signs username/compartment/epoch, not this
  -- new PG scope. Refuse reuse of the SAME signing key under another scope
  -- until a future protocol signs a scope-specific domain directly.
  UNIQUE(public_key)
);
-- Independently enforce that a grant's scope can NEVER be reassigned. A
-- DELETE of the old scoped grant and a fresh operator-authorized INSERT in
-- the new scope are distinct policy events; UPDATE OLD->NEW must not skip
-- locking and fencing the OLD authority. PostgreSQL fires same-type BEFORE
-- triggers in name order, so this runs before lock_device_policy below.
CREATE FUNCTION zk1_sync_batch.deny_device_grant_scope_reassignment()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.scope IS DISTINCT FROM OLD.scope THEN
    RAISE EXCEPTION 'device grant scope is immutable'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER deny_device_grant_scope_reassignment
BEFORE UPDATE ON zk1_sync_batch.device_grant FOR EACH ROW
EXECUTE FUNCTION zk1_sync_batch.deny_device_grant_scope_reassignment();
-- Every operator policy/grant mutation acquires the SAME scope_head row lock
-- used by an admitted batch. Revocation therefore cannot overtake a batch
-- between its live-pinned Ed25519 verification and SQL COMMIT.
CREATE FUNCTION zk1_sync_batch.lock_policy_head() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE checked_scope text;
BEGIN
  -- UPDATE/DELETE lock the ORIGINAL scope, never a caller-supplied NEW scope.
  -- INSERT has no old row and locks only the target scope by construction.
  checked_scope := CASE WHEN TG_OP = 'INSERT' THEN NEW.scope ELSE OLD.scope END;
  IF TG_OP = 'UPDATE' AND NEW.scope IS DISTINCT FROM OLD.scope THEN
    RAISE EXCEPTION 'scope reassignment forbidden' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM zk1_sync_batch.scope_head WHERE scope=checked_scope FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'scope authority head missing' USING ERRCODE='23514';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER lock_device_policy BEFORE INSERT OR UPDATE OR DELETE
ON zk1_sync_batch.device_grant FOR EACH ROW
EXECUTE FUNCTION zk1_sync_batch.lock_policy_head();
CREATE TRIGGER lock_scope_policy BEFORE UPDATE OR DELETE
ON zk1_sync_batch.scope_policy FOR EACH ROW
EXECUTE FUNCTION zk1_sync_batch.lock_policy_head();
-- Every policy mutation MUST fence signed batches by increasing the scope
-- epoch, regardless of the caller's attempted new value. Grant changes must
-- also increase the same epoch while holding the shared scope_head lock.
CREATE FUNCTION zk1_sync_batch.advance_policy_epoch() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.policy_epoch = 9223372036854775807 THEN
    RAISE EXCEPTION 'scope policy epoch exhausted' USING ERRCODE='23514';
  END IF;
  NEW.policy_epoch := OLD.policy_epoch + 1;
  RETURN NEW;
END $$;
CREATE TRIGGER bump_scope_policy_epoch BEFORE UPDATE
ON zk1_sync_batch.scope_policy FOR EACH ROW
EXECUTE FUNCTION zk1_sync_batch.advance_policy_epoch();
CREATE FUNCTION zk1_sync_batch.bump_epoch_on_grant_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE changed_scope text;
BEGIN
  -- For existing grants, bump the ORIGINAL authority's epoch even if a
  -- future trigger regression ever attempts to rewrite NEW.scope.
  changed_scope := CASE WHEN TG_OP='INSERT' THEN NEW.scope ELSE OLD.scope END;
  UPDATE zk1_sync_batch.scope_policy SET policy_epoch=policy_epoch+1
  WHERE scope=changed_scope;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'scope policy not provisioned' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER bump_epoch_on_grant_change AFTER INSERT OR UPDATE OR DELETE
ON zk1_sync_batch.device_grant FOR EACH ROW
EXECUTE FUNCTION zk1_sync_batch.bump_epoch_on_grant_change();

CREATE TABLE zk1_sync_batch.batch_commit (
  scope text NOT NULL REFERENCES zk1_sync_batch.scope_policy(scope),
  sequence bigint NOT NULL CHECK (sequence > 0),
  commit_id uuid NOT NULL,
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  previous_head bytea NOT NULL CHECK (octet_length(previous_head)=32),
  head bytea NOT NULL CHECK (octet_length(head)=32),
  delete_id text NOT NULL CHECK (delete_id ~ '^[A-Za-z0-9._:-]{1,160}$'),
  move_id text NOT NULL CHECK (move_id ~ '^[A-Za-z0-9._:-]{1,160}$'),
  delete_digest bytea NOT NULL CHECK (octet_length(delete_digest)=32),
  move_digest bytea NOT NULL CHECK (octet_length(move_digest)=32),
  state_digest bytea NOT NULL CHECK (octet_length(state_digest)=32),
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(scope, sequence),
  UNIQUE(scope, commit_id),
  UNIQUE(scope, sequence, head),
  CHECK (delete_id <> move_id)
);
-- Fixed fields cannot contain '|'; the domain and field order are mandatory.
-- PostgreSQL computes and CHECKs this commitment, not the application alone.
CREATE FUNCTION zk1_sync_batch.commit_head(
  p_scope text, p_sequence bigint, p_id uuid, p_epoch bigint,
  p_previous bytea, p_delete_id text, p_move_id text,
  p_delete_digest bytea, p_move_digest bytea, p_state bytea
) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
  SELECT pg_catalog.sha256(pg_catalog.convert_to(
    'Root.ark/sync-pg-batch-commit/v1|' || p_scope || '|' ||
    p_sequence::text || '|' || p_id::text || '|' || p_epoch::text || '|' ||
    pg_catalog.encode(p_previous,'hex') || '|' || p_delete_id || '|' ||
    p_move_id || '|' || pg_catalog.encode(p_delete_digest,'hex') || '|' ||
    pg_catalog.encode(p_move_digest,'hex') || '|' ||
    pg_catalog.encode(p_state,'hex'), 'UTF8'));
$$;
ALTER TABLE zk1_sync_batch.batch_commit ADD CONSTRAINT batch_commit_head_valid
CHECK (head = zk1_sync_batch.commit_head(scope,sequence,commit_id,policy_epoch,
  previous_head,delete_id,move_id,delete_digest,move_digest,state_digest));

-- PostgreSQL binds each persisted BYTEA ciphertext to the ciphertext bytes
-- embedded in the *same* exact canonical signed envelope. This prevents a
-- worker with table-write capability from making a truthful-looking marker
-- over one signed envelope while persisting unrelated physical ciphertext.
CREATE FUNCTION zk1_sync_batch.envelope_ciphertext(p_canonical text)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
  SELECT pg_catalog.decode(
    pg_catalog.translate(p_canonical::jsonb->>'ciphertext','-_','+/')
    || pg_catalog.repeat('=',
      (4 - pg_catalog.length(p_canonical::jsonb->>'ciphertext') % 4) % 4),
    'base64');
$$;
CREATE TABLE zk1_sync_batch.seen_envelope (
  scope text NOT NULL,
  operation_id text NOT NULL CHECK (operation_id ~ '^[A-Za-z0-9._:-]{1,160}$'),
  replay_id text NOT NULL CHECK (length(replay_id) BETWEEN 1 AND 192),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 192),
  commit_id uuid NOT NULL,
  ordinal smallint NOT NULL CHECK (ordinal IN (0,1)),
  kind text NOT NULL CHECK (kind IN ('delete','move')),
  canonical_envelope text NOT NULL,
  envelope_digest bytea NOT NULL CHECK (octet_length(envelope_digest)=32
    AND envelope_digest=pg_catalog.sha256(pg_catalog.convert_to(canonical_envelope,'UTF8'))),
  ciphertext bytea NOT NULL CHECK (
    (ciphertext=zk1_sync_batch.envelope_ciphertext(canonical_envelope)) IS TRUE),
  PRIMARY KEY(scope,operation_id),
  UNIQUE(scope,replay_id),
  UNIQUE(scope,idempotency_key),
  UNIQUE(scope,commit_id,ordinal),
  FOREIGN KEY(scope,commit_id) REFERENCES zk1_sync_batch.batch_commit(scope,commit_id),
  CHECK ((ordinal=0 AND kind='delete') OR (ordinal=1 AND kind='move')),
  -- PostgreSQL CHECK accepts UNKNOWN, so every JSON-derived predicate must
  -- explicitly reject NULL/missing fields instead of silently succeeding.
  CHECK ((pg_catalog.jsonb_typeof(canonical_envelope::jsonb)='object') IS TRUE),
  CHECK ((pg_catalog.jsonb_typeof(canonical_envelope::jsonb->'authorization')='object') IS TRUE),
  CHECK ((canonical_envelope::jsonb->>'operationId'=operation_id) IS TRUE),
  CHECK ((canonical_envelope::jsonb->>'operation'=kind) IS TRUE),
  CHECK ((canonical_envelope::jsonb->'authorization'->>'replayId'=replay_id) IS TRUE),
  CHECK ((canonical_envelope::jsonb->'authorization'->>'idempotencyKey'=idempotency_key) IS TRUE),
  CHECK ((pg_catalog.length(canonical_envelope::jsonb->'authorization'->>'signature')>0) IS TRUE),
  CHECK ((pg_catalog.length(canonical_envelope::jsonb->'authorization'->>'publicKey')>0) IS TRUE)
);
CREATE TABLE zk1_sync_batch.object_state (
  scope text NOT NULL REFERENCES zk1_sync_batch.scope_policy(scope),
  object_id text NOT NULL CHECK (object_id ~ '^[A-Za-z0-9._:-]{1,160}$'),
  file_id text NOT NULL,
  version_id text NOT NULL,
  device_id text NOT NULL,
  revision_counter bigint NOT NULL CHECK (revision_counter >= 0),
  revision_device text NOT NULL,
  compartment_id text NOT NULL,
  key_epoch text NOT NULL,
  logical_path text NOT NULL,
  tombstone boolean NOT NULL,
  canonical_envelope text NOT NULL,
  envelope_digest bytea NOT NULL CHECK (octet_length(envelope_digest)=32
    AND envelope_digest=pg_catalog.sha256(pg_catalog.convert_to(canonical_envelope,'UTF8'))),
  ciphertext bytea NOT NULL CHECK (
    (ciphertext=zk1_sync_batch.envelope_ciphertext(canonical_envelope)) IS TRUE),
  last_commit_id uuid,
  PRIMARY KEY(scope,object_id),
  FOREIGN KEY(scope,last_commit_id) REFERENCES zk1_sync_batch.batch_commit(scope,commit_id)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK ((pg_catalog.jsonb_typeof(canonical_envelope::jsonb)='object') IS TRUE),
  CHECK ((pg_catalog.jsonb_typeof(canonical_envelope::jsonb->'revision')='object') IS TRUE),
  CHECK ((pg_catalog.jsonb_typeof(canonical_envelope::jsonb->'metadata')='object') IS TRUE),
  CHECK ((canonical_envelope::jsonb->>'objectId'=object_id) IS TRUE),
  CHECK ((canonical_envelope::jsonb->>'fileId'=file_id) IS TRUE),
  CHECK ((canonical_envelope::jsonb->>'versionId'=version_id) IS TRUE),
  CHECK ((canonical_envelope::jsonb->>'deviceId'=device_id) IS TRUE),
  CHECK ((canonical_envelope::jsonb->'revision'->>'deviceId'=revision_device) IS TRUE),
  CHECK (((canonical_envelope::jsonb->'revision'->>'counter')::bigint=revision_counter) IS TRUE),
  CHECK ((canonical_envelope::jsonb->>'compartmentId'=compartment_id) IS TRUE),
  CHECK ((canonical_envelope::jsonb->>'keyEpoch'=key_epoch) IS TRUE),
  CHECK ((canonical_envelope::jsonb->'metadata'->>'path'=logical_path) IS TRUE),
  CHECK (((canonical_envelope::jsonb->>'tombstone')::boolean=tombstone) IS TRUE)
);
-- An already finalized object cannot be overwritten in-place under the old
-- marker. A legitimate later batch must link its new marker in the same SQL
-- transaction (the deferred FK guarantees that marker actually exists).
CREATE FUNCTION zk1_sync_batch.reject_same_commit_object_rewrite()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.last_commit_id IS NOT NULL
    AND (NEW.last_commit_id IS NULL
      OR NEW.last_commit_id=OLD.last_commit_id) THEN
    RAISE EXCEPTION 'finalized Sync object requires distinct new commit'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER object_revision_requires_new_commit BEFORE UPDATE
ON zk1_sync_batch.object_state FOR EACH ROW
EXECUTE FUNCTION zk1_sync_batch.reject_same_commit_object_rewrite();
-- The digest is derived from the actual newly written SQL object state, not
-- trusted as a client-provided JSON/hash-only assertion. The full original
-- envelopes are also physically in seen_envelope in this SAME SQL transaction.
CREATE FUNCTION zk1_sync_batch.state_digest(p_scope text, p_delete_id text, p_move_id text)
RETURNS bytea LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT pg_catalog.sha256(pg_catalog.convert_to(
    'Root.ark/sync-pg-batch-state/v1|' ||
    pg_catalog.encode(pg_catalog.convert_to(d.object_id,'UTF8'),'hex') || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(d.file_id,'UTF8'),'hex') || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(d.version_id,'UTF8'),'hex') || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(d.logical_path,'UTF8'),'hex') || '|' ||
    d.revision_counter::text || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(d.revision_device,'UTF8'),'hex') || '|' ||
    d.tombstone::text || '|' || pg_catalog.encode(d.envelope_digest,'hex') || '|' ||
    pg_catalog.encode(pg_catalog.sha256(d.ciphertext),'hex') || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(m.object_id,'UTF8'),'hex') || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(m.file_id,'UTF8'),'hex') || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(m.version_id,'UTF8'),'hex') || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(m.logical_path,'UTF8'),'hex') || '|' ||
    m.revision_counter::text || '|' ||
    pg_catalog.encode(pg_catalog.convert_to(m.revision_device,'UTF8'),'hex') || '|' ||
    m.tombstone::text || '|' || pg_catalog.encode(m.envelope_digest,'hex') || '|' ||
    pg_catalog.encode(pg_catalog.sha256(m.ciphertext),'hex'), 'UTF8'))
  FROM zk1_sync_batch.object_state d
  JOIN zk1_sync_batch.object_state m ON m.scope=d.scope
  WHERE d.scope=p_scope AND d.object_id=p_delete_id
    AND m.object_id=p_move_id AND d.tombstone=true AND m.tombstone=false;
$$;
CREATE FUNCTION zk1_sync_batch.assert_commit_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE members integer; states integer; actual_digest bytea;
BEGIN
  SELECT count(*) INTO members FROM zk1_sync_batch.seen_envelope s
  WHERE s.scope=NEW.scope AND s.commit_id=NEW.commit_id
    AND ((s.ordinal=0 AND s.operation_id=NEW.delete_id
      AND s.envelope_digest=NEW.delete_digest AND s.kind='delete')
    OR (s.ordinal=1 AND s.operation_id=NEW.move_id
      AND s.envelope_digest=NEW.move_digest AND s.kind='move'));
  -- Compare EACH resulting physical object to the precise original signed
  -- envelope recorded in seen_envelope, including the full canonical bytes,
  -- digest and ciphertext. Two independently self-consistent hashes are NOT
  -- enough. An attacker cannot swap a different valid envelope/state pair
  -- while preserving this marker and still pass the deferred constraint.
  SELECT count(*) INTO states
  FROM zk1_sync_batch.seen_envelope s
  JOIN zk1_sync_batch.object_state o ON o.scope=s.scope
    AND o.object_id=s.canonical_envelope::jsonb->>'objectId'
  WHERE s.scope=NEW.scope AND s.commit_id=NEW.commit_id
    AND o.last_commit_id=NEW.commit_id
    AND o.canonical_envelope=s.canonical_envelope
    AND o.envelope_digest=s.envelope_digest
    AND o.ciphertext=s.ciphertext
    AND o.tombstone=(s.kind='delete')
    AND ((s.ordinal=0 AND s.operation_id=NEW.delete_id
      AND s.envelope_digest=NEW.delete_digest)
      OR (s.ordinal=1 AND s.operation_id=NEW.move_id
      AND s.envelope_digest=NEW.move_digest));
  SELECT zk1_sync_batch.state_digest(NEW.scope,
    (SELECT s.canonical_envelope::jsonb->>'objectId'
     FROM zk1_sync_batch.seen_envelope s
     WHERE s.scope=NEW.scope AND s.commit_id=NEW.commit_id AND s.ordinal=0),
    (SELECT s.canonical_envelope::jsonb->>'objectId'
     FROM zk1_sync_batch.seen_envelope s
     WHERE s.scope=NEW.scope AND s.commit_id=NEW.commit_id AND s.ordinal=1))
    INTO actual_digest;
  IF members <> 2 OR states <> 2 OR actual_digest IS NULL
    OR actual_digest IS DISTINCT FROM NEW.state_digest
    OR NOT (
      (NEW.sequence=1 AND NEW.previous_head=pg_catalog.decode(pg_catalog.repeat('00',32),'hex'))
      OR (NEW.sequence>1 AND EXISTS(
        SELECT 1 FROM zk1_sync_batch.batch_commit previous
        WHERE previous.scope=NEW.scope AND previous.sequence=NEW.sequence-1
          AND previous.head=NEW.previous_head)))
    OR NOT EXISTS(SELECT 1 FROM zk1_sync_batch.scope_head h
       WHERE h.scope=NEW.scope AND h.sequence=NEW.sequence AND h.head=NEW.head)
  THEN
    RAISE EXCEPTION 'incomplete physical Sync batch commit'
      USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER batch_complete_on_commit
AFTER INSERT ON zk1_sync_batch.batch_commit DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION zk1_sync_batch.assert_commit_complete();
-- An admitted proof or commit is immutable even if runtime code is faulty.
CREATE FUNCTION zk1_sync_batch.reject_history_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'committed Sync batch history is append-only' USING ERRCODE='23514';
END $$;
CREATE TRIGGER immutable_commit BEFORE UPDATE OR DELETE ON zk1_sync_batch.batch_commit
FOR EACH ROW EXECUTE FUNCTION zk1_sync_batch.reject_history_mutation();
CREATE TRIGGER immutable_seen BEFORE UPDATE OR DELETE ON zk1_sync_batch.seen_envelope
FOR EACH ROW EXECUTE FUNCTION zk1_sync_batch.reject_history_mutation();

REVOKE ALL ON ALL TABLES IN SCHEMA zk1_sync_batch FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zk1_sync_batch FROM PUBLIC;
-- Deliberately NO runtime GRANT or CREATE ROLE. Operator provisions a least-
-- privilege DB principal separately; no web request may initialize authority.
COMMIT;
