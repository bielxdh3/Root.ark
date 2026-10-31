-- DEV-OFF, SECURITY NO-GO: DB-enforced single-entrypoint batch write.
-- Applied by the dedicated DB OWNER after base migration and before roles.
-- A distinct and independently trusted admission agent must verify BOTH
-- original Ed25519 signatures using live pinned grants and durable policy
-- state, then INSERT its precise admission row through a separate credential.
-- NO such independently deployed agent or independently signed physical
-- witness/CAS floor ships here. NEVER treat a ticket as a witness.
BEGIN;

CREATE TABLE zk1_sync_batch.admission_ticket (
  ticket_id uuid PRIMARY KEY,
  scope text NOT NULL REFERENCES zk1_sync_batch.scope_policy(scope),
  username text NOT NULL,
  device_id text NOT NULL,
  public_key text NOT NULL,
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_head bytea NOT NULL CHECK (octet_length(previous_head)=32),
  delete_digest bytea NOT NULL CHECK (octet_length(delete_digest)=32),
  move_digest bytea NOT NULL CHECK (octet_length(move_digest)=32),
  expires_at timestamptz NOT NULL,
  consumed boolean NOT NULL DEFAULT false,
  superseded boolean NOT NULL DEFAULT false,
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '2 minutes')
);

-- Bound issuance even when the same valid Ed25519 pair is retried many times.
-- Only an EXPIRED, UNCONSUMED ticket may be superseded for reissue; retain
-- it for audit/replay rejection. The issuer still has INSERT ONLY privileges.
CREATE UNIQUE INDEX admission_ticket_active_pair ON zk1_sync_batch.admission_ticket
  (scope,sequence,policy_epoch,previous_head,delete_digest,move_digest)
  WHERE superseded=false;
CREATE FUNCTION zk1_sync_batch.supersede_expired_admission_ticket()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $body$
BEGIN
  -- INSERT-only credentials must not bypass the active-pair uniqueness by
  -- supplying superseded=true, pre-consumed handles or far-future issuance.
  IF NEW.superseded IS DISTINCT FROM FALSE
    OR NEW.consumed IS DISTINCT FROM FALSE
    OR NEW.issued_at > clock_timestamp() + interval '1 second'
    OR NEW.issued_at < clock_timestamp() - interval '2 minutes'
    OR NEW.expires_at > NEW.issued_at + interval '31 seconds'
    OR NEW.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'invalid admission ticket lifecycle' USING ERRCODE='23514';
  END IF;
  -- Same lock order as commit_admitted_pair: scope_head then ticket. Concurrent
  -- retry/commit/revocation therefore cannot bypass expiry, CAS or fencing.
  PERFORM 1 FROM zk1_sync_batch.scope_head
    WHERE scope=NEW.scope FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'missing admission scope head' USING ERRCODE='23514';
  END IF;
  UPDATE zk1_sync_batch.admission_ticket SET superseded=true
    WHERE scope=NEW.scope AND sequence=NEW.sequence
      AND policy_epoch=NEW.policy_epoch AND previous_head=NEW.previous_head
      AND delete_digest=NEW.delete_digest AND move_digest=NEW.move_digest
      AND superseded=false AND consumed=false
      AND expires_at <= clock_timestamp();
  RETURN NEW;
END $body$;
CREATE TRIGGER supersede_expired_admission_ticket
BEFORE INSERT ON zk1_sync_batch.admission_ticket FOR EACH ROW
EXECUTE FUNCTION zk1_sync_batch.supersede_expired_admission_ticket();

CREATE FUNCTION zk1_sync_batch.commit_admitted_pair(
  p_scope text, p_username text, p_ticket uuid,
  p_delete text, p_move text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog AS $body$
DECLARE
  d jsonb; m jsonb; r record; h record; pol record; grant_row record;
  c_id uuid; sequence_next bigint; epoch_current bigint;
  d_hash bytea; m_hash bytea; d_state bytea; new_head bytea;
  entry jsonb; canonical text; idx integer; old_state record;
  expires_ms numeric; d_id text; m_id text; webdav_event text;
BEGIN
  -- The caller owns NO table-write privilege; all writes below are bounded
  -- by the DB owner's SECURITY DEFINER procedure, not caller-controlled SQL.
  IF p_scope IS NULL OR p_username IS NULL OR p_ticket IS NULL
    OR p_delete IS NULL OR p_move IS NULL
    OR length(p_scope) NOT BETWEEN 1 AND 256
    OR p_scope !~ '^[A-Za-z0-9._:-]+$'
    OR length(p_username) NOT BETWEEN 1 AND 512
    OR octet_length(p_delete) + octet_length(p_move) > 9437184 THEN
    RAISE EXCEPTION 'invalid admission envelope' USING ERRCODE='23514';
  END IF;
  d := p_delete::jsonb; m := p_move::jsonb;
  IF jsonb_typeof(d) IS DISTINCT FROM 'object'
    OR jsonb_typeof(m) IS DISTINCT FROM 'object'
    OR jsonb_typeof(d->'tombstone') IS DISTINCT FROM 'boolean'
    OR jsonb_typeof(m->'tombstone') IS DISTINCT FROM 'boolean'
    OR (d->>'operation'='delete') IS NOT TRUE
    OR (m->>'operation'='move') IS NOT TRUE
    OR (d->>'tombstone'='true') IS NOT TRUE
    OR (m->>'tombstone'='false') IS NOT TRUE
    OR (d->>'objectId'<>m->>'objectId') IS NOT TRUE
    OR (d->>'fileId'<>m->>'fileId') IS NOT TRUE
    OR (d->>'deviceId'=m->>'deviceId') IS NOT TRUE
    OR (d->>'compartmentId'=m->>'compartmentId') IS NOT TRUE
    OR (d->>'keyEpoch'=m->>'keyEpoch') IS NOT TRUE
    OR (d->'metadata'->>'path'=m->'metadata'->>'path') IS NOT TRUE
    OR (d->'authorization'->>'username'=p_username) IS NOT TRUE
    OR (m->'authorization'->>'username'=p_username) IS NOT TRUE
    OR (d->>'operationId'<>m->>'operationId') IS NOT TRUE
    OR (d->'authorization'->>'replayId'<>m->'authorization'->>'replayId') IS NOT TRUE
    OR (d->'authorization'->>'idempotencyKey'<>m->'authorization'->>'idempotencyKey') IS NOT TRUE
    OR jsonb_typeof(d->'revision') IS DISTINCT FROM 'object'
    OR jsonb_typeof(m->'revision') IS DISTINCT FROM 'object'
    OR jsonb_typeof(d->'baseRevision') IS DISTINCT FROM 'object'
    OR jsonb_typeof(m->'baseRevision') IS DISTINCT FROM 'object'
    OR jsonb_typeof(d->'revision'->'counter') IS DISTINCT FROM 'number'
    OR jsonb_typeof(m->'revision'->'counter') IS DISTINCT FROM 'number'
    OR jsonb_typeof(d->'baseRevision'->'counter') IS DISTINCT FROM 'number'
    OR jsonb_typeof(m->'baseRevision'->'counter') IS DISTINCT FROM 'number'
    OR jsonb_typeof(d->'authorization') IS DISTINCT FROM 'object'
    OR jsonb_typeof(m->'authorization') IS DISTINCT FROM 'object'
    OR (d->'revision'->>'deviceId'=d->>'deviceId') IS NOT TRUE
    OR (m->'revision'->>'deviceId'=m->>'deviceId') IS NOT TRUE
    OR (d->'revision'->>'counter') IS NULL
    OR (m->'revision'->>'counter') IS NULL THEN
    RAISE EXCEPTION 'misaligned signed pair' USING ERRCODE='23514';
  END IF;
  -- Original protected WebDAV overwrite MOVE, not two unrelated but validly
  -- signed DELETE/MOVE operations aimed at the same destination. The one
  -- canonical journal event MUST derive BOTH signed operation IDs:
  -- webdav-<event>-sha256('delete:'||path)[0:24] and matching 'move:'.
  webdav_event := pg_catalog.substring(d->>'operationId',
    '^webdav-([A-Za-z0-9._:-]{1,100})-[0-9a-f]{24}$');
  IF webdav_event IS NULL
    OR (d->>'operationId' = 'webdav-' || webdav_event || '-' ||
      pg_catalog.substring(pg_catalog.encode(pg_catalog.sha256(
        pg_catalog.convert_to('delete:' || (d->'metadata'->>'path'),'UTF8')),
        'hex'),1,24)) IS NOT TRUE
    OR (m->>'operationId' = 'webdav-' || webdav_event || '-' ||
      pg_catalog.substring(pg_catalog.encode(pg_catalog.sha256(
        pg_catalog.convert_to('move:' || (m->'metadata'->>'path'),'UTF8')),
        'hex'),1,24)) IS NOT TRUE
    OR (m->'metadata'->>'sourcePath' IS NOT NULL) IS NOT TRUE THEN
    RAISE EXCEPTION 'unbound signed WebDAV overwrite event' USING ERRCODE='23514';
  END IF;
  d_hash := pg_catalog.sha256(pg_catalog.convert_to(p_delete,'UTF8'));
  m_hash := pg_catalog.sha256(pg_catalog.convert_to(p_move,'UTF8'));

  -- Lock serializes all competing batches and policy/grant changes. A stale
  -- ticket is denied AFTER acquiring this lock, so revocation cannot race.
  SELECT * INTO h FROM zk1_sync_batch.scope_head
    WHERE scope=p_scope FOR UPDATE;
  IF NOT FOUND OR h.sequence=9223372036854775807 THEN
    RAISE EXCEPTION 'missing or exhausted scope head' USING ERRCODE='23514';
  END IF;
  sequence_next := h.sequence + 1;
  SELECT * INTO pol FROM zk1_sync_batch.scope_policy WHERE scope=p_scope;
  SELECT * INTO grant_row FROM zk1_sync_batch.device_grant
    WHERE scope=p_scope AND device_id=d->>'deviceId';
  IF pol.enabled IS DISTINCT FROM TRUE
    OR pol.allow_delete IS DISTINCT FROM TRUE
    OR pol.username IS DISTINCT FROM p_username
    OR pol.compartment_id IS DISTINCT FROM d->>'compartmentId'
    OR pol.key_epoch IS DISTINCT FROM d->>'keyEpoch'
    OR grant_row.revoked IS DISTINCT FROM FALSE
    OR grant_row.public_key IS NULL
    OR (d->'authorization'->>'publicKey'=grant_row.public_key) IS NOT TRUE
    OR (m->'authorization'->>'publicKey'=grant_row.public_key) IS NOT TRUE THEN
    RAISE EXCEPTION 'policy, grant or key revoked' USING ERRCODE='23514';
  END IF;
  SELECT * INTO r FROM zk1_sync_batch.admission_ticket
    WHERE ticket_id=p_ticket AND scope=p_scope FOR UPDATE;
  IF NOT FOUND OR r.consumed IS DISTINCT FROM FALSE
    OR r.superseded IS DISTINCT FROM FALSE
    OR r.expires_at <= clock_timestamp()
    OR r.username IS DISTINCT FROM p_username
    OR r.device_id IS DISTINCT FROM d->>'deviceId'
    OR r.public_key IS DISTINCT FROM grant_row.public_key
    OR r.policy_epoch IS DISTINCT FROM pol.policy_epoch
    OR r.sequence IS DISTINCT FROM sequence_next
    OR r.previous_head IS DISTINCT FROM h.head
    OR r.delete_digest IS DISTINCT FROM d_hash
    OR r.move_digest IS DISTINCT FROM m_hash THEN
    RAISE EXCEPTION 'missing, revoked, expired or mismatched admission'
      USING ERRCODE='23514';
  END IF;
  -- Freshness is enforced inside the DB transaction, not by mutable JS.
  -- A nonnumeric/missing field causes a conversion error (fail closed).
  FOREACH entry IN ARRAY ARRAY[d,m] LOOP
    expires_ms := (entry->'authorization'->>'expiresAt')::numeric;
    IF expires_ms IS NULL OR expires_ms::text IN ('NaN','Infinity','-Infinity')
      OR expires_ms <= (extract(epoch FROM clock_timestamp()) * 1000)
      OR expires_ms > (extract(epoch FROM clock_timestamp()) * 1000) + 120000 THEN
      RAISE EXCEPTION 'original signed operation expired' USING ERRCODE='23514';
    END IF;
  END LOOP;

  -- Ensure original operation/replay/idempotency IDs remain unreused.
  IF EXISTS(SELECT 1 FROM zk1_sync_batch.seen_envelope s WHERE s.scope=p_scope
    AND (s.operation_id IN (d->>'operationId',m->>'operationId')
      OR s.replay_id IN (d->'authorization'->>'replayId',
                         m->'authorization'->>'replayId')
      OR s.idempotency_key IN (d->'authorization'->>'idempotencyKey',
                               m->'authorization'->>'idempotencyKey'))) THEN
    RAISE EXCEPTION 'replayed signed envelope' USING ERRCODE='23505';
  END IF;
  d_id := d->>'objectId'; m_id := m->>'objectId';
  FOR idx IN 1..2 LOOP
    entry := CASE WHEN idx=1 THEN d ELSE m END;
    canonical := CASE WHEN idx=1 THEN p_delete ELSE p_move END;
    SELECT * INTO old_state FROM zk1_sync_batch.object_state
      WHERE scope=p_scope AND object_id=entry->>'objectId';
    IF NOT FOUND OR old_state.tombstone IS DISTINCT FROM FALSE
      OR old_state.file_id IS DISTINCT FROM entry->>'fileId'
      OR old_state.compartment_id IS DISTINCT FROM entry->>'compartmentId'
      OR old_state.key_epoch IS DISTINCT FROM entry->>'keyEpoch'
      OR old_state.revision_counter IS DISTINCT FROM
          (entry->'baseRevision'->>'counter')::bigint
      OR old_state.revision_device IS DISTINCT FROM
          entry->'baseRevision'->>'deviceId'
      OR (entry->'revision'->>'counter')::bigint <= old_state.revision_counter
      OR (idx=1 AND old_state.logical_path IS DISTINCT FROM entry->'metadata'->>'path')
      OR (idx=2 AND old_state.logical_path IS DISTINCT FROM entry->'metadata'->>'sourcePath') THEN
      RAISE EXCEPTION 'stale or mismatched original object' USING ERRCODE='23514';
    END IF;
  END LOOP;
  c_id := pg_catalog.gen_random_uuid();
  FOR idx IN 1..2 LOOP
    entry := CASE WHEN idx=1 THEN d ELSE m END;
    canonical := CASE WHEN idx=1 THEN p_delete ELSE p_move END;
    UPDATE zk1_sync_batch.object_state SET
      version_id=entry->>'versionId',
      device_id=entry->>'deviceId',
      revision_counter=(entry->'revision'->>'counter')::bigint,
      revision_device=entry->'revision'->>'deviceId',
      compartment_id=entry->>'compartmentId',
      key_epoch=entry->>'keyEpoch',
      logical_path=entry->'metadata'->>'path',
      tombstone=(entry->>'tombstone')::boolean,
      canonical_envelope=canonical,
      envelope_digest=CASE WHEN idx=1 THEN d_hash ELSE m_hash END,
      ciphertext=zk1_sync_batch.envelope_ciphertext(canonical),
      last_commit_id=c_id
    WHERE scope=p_scope AND object_id=entry->>'objectId';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'missing original object' USING ERRCODE='23514';
    END IF;
  END LOOP;
  d_state := zk1_sync_batch.state_digest(p_scope,d_id,m_id);
  IF d_state IS NULL THEN
    RAISE EXCEPTION 'physical batch state incomplete' USING ERRCODE='23514';
  END IF;
  new_head := zk1_sync_batch.commit_head(p_scope,sequence_next,c_id,
    pol.policy_epoch,h.head,d->>'operationId',m->>'operationId',
    d_hash,m_hash,d_state);
  INSERT INTO zk1_sync_batch.batch_commit
    (scope,sequence,commit_id,policy_epoch,previous_head,head,
     delete_id,move_id,delete_digest,move_digest,state_digest)
  VALUES (p_scope,sequence_next,c_id,pol.policy_epoch,h.head,new_head,
    d->>'operationId',m->>'operationId',d_hash,m_hash,d_state);
  FOR idx IN 1..2 LOOP
    entry := CASE WHEN idx=1 THEN d ELSE m END;
    canonical := CASE WHEN idx=1 THEN p_delete ELSE p_move END;
    INSERT INTO zk1_sync_batch.seen_envelope
      (scope,operation_id,replay_id,idempotency_key,commit_id,ordinal,kind,
       canonical_envelope,envelope_digest,ciphertext)
    VALUES (p_scope,entry->>'operationId',
      entry->'authorization'->>'replayId',
      entry->'authorization'->>'idempotencyKey',
      c_id,idx-1,entry->>'operation',canonical,
      CASE WHEN idx=1 THEN d_hash ELSE m_hash END,
      zk1_sync_batch.envelope_ciphertext(canonical));
  END LOOP;
  UPDATE zk1_sync_batch.scope_head SET sequence=sequence_next,head=new_head
    WHERE scope=p_scope AND sequence=h.sequence AND head=h.head;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'scope CAS denied' USING ERRCODE='23514';
  END IF;
  UPDATE zk1_sync_batch.admission_ticket SET consumed=true
    WHERE ticket_id=p_ticket AND consumed=false;
  IF NOT FOUND OR r.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'expired/reused admission at commit' USING ERRCODE='23514';
  END IF;
  -- The deferred marker constraint still rechecks 2 original envelopes and
  -- both actual physical states at SQL COMMIT. Only local store evidence.
  RETURN pg_catalog.jsonb_build_object('commitId',c_id,'sequence',sequence_next,
    'storeHeadSha256',pg_catalog.encode(new_head,'hex'),
    'witnessVerified',false,'clientAckAuthorized',false);
END $body$;

REVOKE ALL ON zk1_sync_batch.admission_ticket FROM PUBLIC;
REVOKE ALL ON FUNCTION zk1_sync_batch.commit_admitted_pair(text,text,uuid,text,text)
  FROM PUBLIC;
COMMIT;
