\set ON_ERROR_STOP on

-- Test-only PostgreSQL model. Names here are internal lab records, not wire
-- types, receipts, signed proofs, or product schema exports.
DROP SCHEMA IF EXISTS p65_lab CASCADE;
DROP SCHEMA IF EXISTS p65_red CASCADE;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'p65_cas') THEN
    CREATE ROLE p65_cas NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'p65_gate') THEN
    CREATE ROLE p65_gate NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'p65_status') THEN
    CREATE ROLE p65_status NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'p65_test') THEN
    CREATE ROLE p65_test NOLOGIN;
  END IF;
END
$roles$;

CREATE SCHEMA p65_lab AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA p65_lab FROM PUBLIC;
GRANT USAGE ON SCHEMA p65_lab TO p65_cas, p65_gate, p65_status, p65_test;

CREATE TYPE p65_lab.request_input AS (
  account_id text,
  compartment_id text,
  keyring_id text,
  operation_id text,
  reservation_id text,
  expected_revision bigint,
  expected_digest bytea,
  proposed_revision bigint,
  proposed_digest bytea,
  request_digest bytea,
  package_digest bytea,
  expires_at timestamptz,
  request_bytes bytea,
  transition_bytes bytea
);

CREATE TABLE p65_lab.keyring_head (
  account_id text NOT NULL,
  compartment_id text NOT NULL,
  keyring_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision >= 0),
  manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
  gate_state text NOT NULL CHECK (gate_state IN ('OPEN', 'PENDING', 'QUIESCING')),
  generation bigint NOT NULL CHECK (generation > 0),
  active_epoch integer NOT NULL CHECK (active_epoch BETWEEN 1 AND 64),
  device_count integer NOT NULL CHECK (device_count BETWEEN 0 AND 256),
  epoch_count integer NOT NULL CHECK (epoch_count BETWEEN 1 AND 64),
  transition_count integer NOT NULL CHECK (transition_count BETWEEN 0 AND 4096),
  transition_bytes bigint NOT NULL CHECK (transition_bytes BETWEEN 0 AND 67108864),
  PRIMARY KEY (account_id, compartment_id, keyring_id),
  CHECK (active_epoch <= epoch_count)
);

-- The global lab-local operation id is deliberate: it lets the regression
-- suite detect an attempted same-id retry with a changed scope. Protocol
-- uniqueness semantics remain unapproved and are outside this model.
CREATE TABLE p65_lab.operation_request (
  operation_id text PRIMARY KEY,
  account_id text NOT NULL,
  compartment_id text NOT NULL,
  keyring_id text NOT NULL,
  reservation_id text NOT NULL,
  expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
  expected_digest bytea NOT NULL CHECK (octet_length(expected_digest) = 32),
  proposed_revision bigint NOT NULL CHECK (proposed_revision >= 1),
  proposed_digest bytea NOT NULL CHECK (octet_length(proposed_digest) = 32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  package_digest bytea CHECK (package_digest IS NULL OR octet_length(package_digest) = 32),
  expires_at timestamptz NOT NULL,
  request_bytes bytea NOT NULL CHECK (octet_length(request_bytes) > 0),
  transition_bytes bytea NOT NULL CHECK (octet_length(transition_bytes) BETWEEN 1 AND 8388608),
  status text NOT NULL CHECK (status IN ('RESERVED', 'COMMITTED', 'NO_COMMIT_FINAL')),
  generation bigint NOT NULL CHECK (generation > 0),
  reserved_at timestamptz NOT NULL,
  UNIQUE (account_id, compartment_id, keyring_id, reservation_id),
  FOREIGN KEY (account_id, compartment_id, keyring_id)
    REFERENCES p65_lab.keyring_head(account_id, compartment_id, keyring_id)
);

CREATE TABLE p65_lab.operation_terminal (
  operation_id text PRIMARY KEY REFERENCES p65_lab.operation_request(operation_id),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  request_bytes bytea NOT NULL CHECK (octet_length(request_bytes) > 0),
  terminal_status text NOT NULL CHECK (terminal_status IN ('COMMITTED', 'NO_COMMIT_FINAL')),
  result jsonb NOT NULL,
  terminal_at timestamptz NOT NULL
);

CREATE TABLE p65_lab.transition_log (
  account_id text NOT NULL,
  compartment_id text NOT NULL,
  keyring_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  operation_id text NOT NULL UNIQUE REFERENCES p65_lab.operation_request(operation_id),
  reservation_id text NOT NULL,
  expected_digest bytea NOT NULL CHECK (octet_length(expected_digest) = 32),
  proposed_digest bytea NOT NULL CHECK (octet_length(proposed_digest) = 32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  transition_bytes bytea NOT NULL CHECK (octet_length(transition_bytes) BETWEEN 1 AND 8388608),
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (account_id, compartment_id, keyring_id, revision),
  FOREIGN KEY (account_id, compartment_id, keyring_id)
    REFERENCES p65_lab.keyring_head(account_id, compartment_id, keyring_id)
);

CREATE TABLE p65_lab.no_commit_fence (
  operation_id text PRIMARY KEY REFERENCES p65_lab.operation_request(operation_id),
  account_id text NOT NULL,
  compartment_id text NOT NULL,
  keyring_id text NOT NULL,
  reservation_id text NOT NULL,
  expected_revision bigint NOT NULL,
  expected_digest bytea NOT NULL CHECK (octet_length(expected_digest) = 32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  generation bigint NOT NULL CHECK (generation > 0),
  fenced_at timestamptz NOT NULL,
  UNIQUE (account_id, compartment_id, keyring_id, reservation_id),
  FOREIGN KEY (account_id, compartment_id, keyring_id)
    REFERENCES p65_lab.keyring_head(account_id, compartment_id, keyring_id)
);

CREATE TABLE p65_lab.permit_ledger (
  account_id text NOT NULL,
  compartment_id text NOT NULL,
  keyring_id text NOT NULL,
  permit_id text NOT NULL,
  operation_id text NOT NULL,
  reservation_id text NOT NULL,
  expected_revision bigint NOT NULL,
  expected_digest bytea NOT NULL CHECK (octet_length(expected_digest) = 32),
  expected_epoch integer NOT NULL CHECK (expected_epoch BETWEEN 1 AND 64),
  generation bigint NOT NULL CHECK (generation > 0),
  state text NOT NULL CHECK (state IN ('ISSUED', 'CONSUMED')),
  effect_id text,
  issued_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (account_id, compartment_id, keyring_id, permit_id),
  FOREIGN KEY (account_id, compartment_id, keyring_id)
    REFERENCES p65_lab.keyring_head(account_id, compartment_id, keyring_id),
  CHECK ((state = 'ISSUED' AND effect_id IS NULL AND consumed_at IS NULL)
      OR (state = 'CONSUMED' AND effect_id IS NOT NULL AND consumed_at IS NOT NULL))
);

CREATE TABLE p65_lab.active_effect (
  account_id text NOT NULL,
  compartment_id text NOT NULL,
  keyring_id text NOT NULL,
  effect_id text NOT NULL,
  operation_id text NOT NULL,
  reservation_id text NOT NULL,
  expected_revision bigint NOT NULL,
  expected_digest bytea NOT NULL CHECK (octet_length(expected_digest) = 32),
  expected_epoch integer NOT NULL CHECK (expected_epoch BETWEEN 1 AND 64),
  generation bigint NOT NULL CHECK (generation > 0),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'STOPPED')),
  started_at timestamptz NOT NULL,
  stopped_at timestamptz,
  PRIMARY KEY (account_id, compartment_id, keyring_id, effect_id),
  FOREIGN KEY (account_id, compartment_id, keyring_id)
    REFERENCES p65_lab.keyring_head(account_id, compartment_id, keyring_id),
  CHECK ((state = 'ACTIVE' AND stopped_at IS NULL) OR (state = 'STOPPED' AND stopped_at IS NOT NULL))
);

CREATE TABLE p65_lab.stop_ack_requests (
  account_id text NOT NULL,
  compartment_id text NOT NULL,
  keyring_id text NOT NULL,
  effect_id text NOT NULL,
  operation_id text NOT NULL,
  reservation_id text NOT NULL,
  expected_ack_id text NOT NULL,
  generation bigint NOT NULL CHECK (generation > 0),
  acknowledged boolean NOT NULL DEFAULT false,
  acknowledged_at timestamptz,
  PRIMARY KEY (account_id, compartment_id, keyring_id, effect_id),
  UNIQUE (account_id, compartment_id, keyring_id, expected_ack_id),
  FOREIGN KEY (account_id, compartment_id, keyring_id, effect_id)
    REFERENCES p65_lab.active_effect(account_id, compartment_id, keyring_id, effect_id),
  CHECK ((acknowledged = false AND acknowledged_at IS NULL)
      OR (acknowledged = true AND acknowledged_at IS NOT NULL))
);

CREATE TABLE p65_lab.test_clock (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  offset_seconds integer NOT NULL CHECK (offset_seconds BETWEEN -3600 AND 3600)
);
INSERT INTO p65_lab.test_clock(singleton, offset_seconds) VALUES (true, 0);

-- This is a logical witness high-water fixture stored in the same database.
-- It is not an independent witness, signer, append-only external ledger, or
-- rollback-resistant checkpoint.
CREATE TABLE p65_lab.mock_witness_highwater (
  account_id text NOT NULL,
  compartment_id text NOT NULL,
  keyring_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision >= 0),
  manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (account_id, compartment_id, keyring_id),
  FOREIGN KEY (account_id, compartment_id, keyring_id)
    REFERENCES p65_lab.keyring_head(account_id, compartment_id, keyring_id)
);

CREATE FUNCTION p65_lab.lab_now()
RETURNS timestamptz
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
  SELECT clock_timestamp() + make_interval(secs => offset_seconds)
  FROM p65_lab.test_clock WHERE singleton
$$;

CREATE FUNCTION p65_lab.protect_immutable_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, p65_lab
AS $$
BEGIN
  RAISE EXCEPTION 'P65_IMMUTABLE_RECORD';
END
$$;

CREATE TRIGGER transition_log_immutable
BEFORE UPDATE OR DELETE ON p65_lab.transition_log
FOR EACH ROW EXECUTE FUNCTION p65_lab.protect_immutable_row();
CREATE TRIGGER operation_terminal_immutable
BEFORE UPDATE OR DELETE ON p65_lab.operation_terminal
FOR EACH ROW EXECUTE FUNCTION p65_lab.protect_immutable_row();
CREATE TRIGGER no_commit_fence_immutable
BEFORE UPDATE OR DELETE ON p65_lab.no_commit_fence
FOR EACH ROW EXECUTE FUNCTION p65_lab.protect_immutable_row();

CREATE FUNCTION p65_lab.request_matches(p_stored p65_lab.operation_request, p_request p65_lab.request_input)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, p65_lab
AS $$
  -- SQL comparisons involving NULL can be UNKNOWN. Exact request equality
  -- must always be a two-valued predicate: only TRUE permits a retry.
  SELECT (p_stored.operation_id = (p_request).operation_id
     AND p_stored.account_id = (p_request).account_id
     AND p_stored.compartment_id = (p_request).compartment_id
     AND p_stored.keyring_id = (p_request).keyring_id
     AND p_stored.reservation_id = (p_request).reservation_id
     AND p_stored.expected_revision = (p_request).expected_revision
     AND p_stored.expected_digest = (p_request).expected_digest
     AND p_stored.proposed_revision = (p_request).proposed_revision
     AND p_stored.proposed_digest = (p_request).proposed_digest
     AND p_stored.request_digest = (p_request).request_digest
     AND p_stored.package_digest IS NOT DISTINCT FROM (p_request).package_digest
     AND p_stored.expires_at = (p_request).expires_at
     AND p_stored.request_bytes = (p_request).request_bytes
     AND p_stored.transition_bytes = (p_request).transition_bytes) IS TRUE
$$;

CREATE FUNCTION p65_lab.test_seed_keyring(
  p_account text,
  p_compartment text,
  p_keyring text,
  p_initial_digest bytea,
  p_device_count integer,
  p_epoch_count integer,
  p_transition_count integer DEFAULT 0,
  p_transition_bytes bigint DEFAULT 0
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
BEGIN
  IF p_initial_digest IS NULL OR octet_length(p_initial_digest) <> 32 THEN
    RETURN jsonb_build_object('status', 'INVALID_DIGEST');
  END IF;
  IF p_device_count < 0 OR p_device_count > 256 THEN
    RETURN jsonb_build_object('status', 'DEVICE_LIMIT');
  END IF;
  IF p_epoch_count < 1 OR p_epoch_count > 64 THEN
    RETURN jsonb_build_object('status', 'EPOCH_LIMIT');
  END IF;
  IF p_transition_count < 0 OR p_transition_count > 4096
     OR p_transition_bytes < 0 OR p_transition_bytes > 67108864 THEN
    RETURN jsonb_build_object('status', 'HISTORY_LIMIT');
  END IF;
  INSERT INTO p65_lab.keyring_head(
    account_id, compartment_id, keyring_id, revision, manifest_digest, gate_state,
    generation, active_epoch, device_count, epoch_count, transition_count, transition_bytes
  ) VALUES (
    p_account, p_compartment, p_keyring, 0, p_initial_digest, 'OPEN',
    1, 1, p_device_count, p_epoch_count, p_transition_count, p_transition_bytes
  );
  RETURN jsonb_build_object('status', 'SEEDED', 'revision', 0, 'generation', 1);
EXCEPTION WHEN unique_violation THEN
  RETURN jsonb_build_object('status', 'KEYRING_EXISTS');
END
$$;

CREATE FUNCTION p65_lab.set_test_clock_offset(p_seconds integer)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
BEGIN
  IF p_seconds < -3600 OR p_seconds > 3600 THEN
    RETURN jsonb_build_object('status', 'OFFSET_LIMIT');
  END IF;
  UPDATE p65_lab.test_clock SET offset_seconds = p_seconds WHERE singleton;
  RETURN jsonb_build_object('status', 'SET', 'offset_seconds', p_seconds, 'database_clock', clock_timestamp());
END
$$;

CREATE FUNCTION p65_lab.reserve_operation(p_request p65_lab.request_input)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE
  h p65_lab.keyring_head%ROWTYPE;
  existing p65_lab.operation_request%ROWTYPE;
  inserted_operation text;
BEGIN
  SELECT * INTO existing FROM p65_lab.operation_request
  WHERE operation_id = (p_request).operation_id FOR UPDATE;
  IF FOUND THEN
    IF p65_lab.request_matches(existing, p_request) IS NOT TRUE THEN
      RETURN jsonb_build_object('status', 'OPERATION_CONFLICT');
    END IF;
    IF existing.status <> 'RESERVED' THEN
      RETURN (SELECT result FROM p65_lab.operation_terminal WHERE operation_id = existing.operation_id);
    END IF;
    RETURN jsonb_build_object('status', 'RESERVED', 'generation', existing.generation, 'operation_id', existing.operation_id);
  END IF;

  IF (p_request).operation_id IS NULL OR btrim((p_request).operation_id) = ''
     OR (p_request).reservation_id IS NULL OR btrim((p_request).reservation_id) = ''
     OR (p_request).expected_revision < 0
     OR (p_request).proposed_revision <> (p_request).expected_revision + 1
     OR octet_length((p_request).expected_digest) <> 32
     OR octet_length((p_request).proposed_digest) <> 32
     OR ((p_request).package_digest IS NOT NULL AND octet_length((p_request).package_digest) <> 32)
     OR octet_length((p_request).transition_bytes) NOT BETWEEN 1 AND 8388608
     OR octet_length((p_request).request_bytes) = 0
     OR public.digest((p_request).request_bytes, 'sha256') <> (p_request).request_digest THEN
    RETURN jsonb_build_object('status', 'INVALID_REQUEST');
  END IF;

  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = (p_request).account_id
    AND compartment_id = (p_request).compartment_id
    AND keyring_id = (p_request).keyring_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('status', 'SCOPE_NOT_FOUND');
  END IF;
  IF h.gate_state <> 'OPEN' THEN
    RETURN jsonb_build_object('status', 'GATE_CLOSED', 'gate_state', h.gate_state);
  END IF;
  IF h.revision <> (p_request).expected_revision OR h.manifest_digest <> (p_request).expected_digest THEN
    RETURN jsonb_build_object('status', 'HEAD_MISMATCH', 'revision', h.revision);
  END IF;
  IF h.transition_count >= 4096 OR h.transition_bytes + octet_length((p_request).transition_bytes) > 67108864 THEN
    RETURN jsonb_build_object('status', 'HISTORY_LIMIT');
  END IF;

  INSERT INTO p65_lab.operation_request(
    operation_id, account_id, compartment_id, keyring_id, reservation_id,
    expected_revision, expected_digest, proposed_revision, proposed_digest,
    request_digest, package_digest, expires_at, request_bytes, transition_bytes,
    status, generation, reserved_at
  ) VALUES (
    (p_request).operation_id, (p_request).account_id, (p_request).compartment_id,
    (p_request).keyring_id, (p_request).reservation_id, (p_request).expected_revision,
    (p_request).expected_digest, (p_request).proposed_revision, (p_request).proposed_digest,
    (p_request).request_digest, (p_request).package_digest, (p_request).expires_at,
    (p_request).request_bytes, (p_request).transition_bytes, 'RESERVED', h.generation, p65_lab.lab_now()
  ) ON CONFLICT DO NOTHING RETURNING operation_id INTO inserted_operation;
  IF inserted_operation IS NULL THEN
    SELECT * INTO existing FROM p65_lab.operation_request
    WHERE operation_id = (p_request).operation_id FOR UPDATE;
    IF FOUND AND p65_lab.request_matches(existing, p_request) THEN
      RETURN jsonb_build_object('status', existing.status, 'generation', existing.generation, 'operation_id', existing.operation_id);
    END IF;
    RETURN jsonb_build_object('status', 'OPERATION_CONFLICT');
  END IF;
  UPDATE p65_lab.keyring_head SET gate_state = 'PENDING'
  WHERE account_id = h.account_id AND compartment_id = h.compartment_id AND keyring_id = h.keyring_id;
  RETURN jsonb_build_object('status', 'RESERVED', 'generation', h.generation, 'operation_id', (p_request).operation_id);
EXCEPTION WHEN unique_violation THEN
  RETURN jsonb_build_object('status', 'RESERVATION_CONFLICT');
END
$$;

CREATE FUNCTION p65_lab.read_head(p_account text, p_compartment text, p_keyring text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE h p65_lab.keyring_head%ROWTYPE;
BEGIN
  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'SCOPE_NOT_FOUND'); END IF;
  IF h.gate_state <> 'OPEN' THEN
    RETURN jsonb_build_object('status', 'GATE_CLOSED', 'gate_state', h.gate_state);
  END IF;
  RETURN jsonb_build_object('status', 'HEAD', 'revision', h.revision, 'manifest_digest', encode(h.manifest_digest, 'hex'));
END
$$;

CREATE FUNCTION p65_lab.issue_permit(
  p_account text, p_compartment text, p_keyring text,
  p_operation text, p_reservation text, p_revision bigint, p_digest bytea,
  p_epoch integer, p_generation bigint, p_permit_id text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE h p65_lab.keyring_head%ROWTYPE;
BEGIN
  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
  FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH'); END IF;
  IF h.gate_state <> 'OPEN' THEN RETURN jsonb_build_object('status', 'GATE_CLOSED'); END IF;
  IF h.revision <> p_revision OR h.manifest_digest <> p_digest OR h.active_epoch <> p_epoch
     OR h.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'STALE_HEAD_OR_GENERATION');
  END IF;
  INSERT INTO p65_lab.permit_ledger(
    account_id, compartment_id, keyring_id, permit_id, operation_id, reservation_id,
    expected_revision, expected_digest, expected_epoch, generation, state, issued_at
  ) VALUES (
    p_account, p_compartment, p_keyring, p_permit_id, p_operation, p_reservation,
    p_revision, p_digest, p_epoch, p_generation, 'ISSUED', p65_lab.lab_now()
  );
  RETURN jsonb_build_object('status', 'PERMIT_ISSUED', 'generation', p_generation);
EXCEPTION WHEN unique_violation THEN
  RETURN jsonb_build_object('status', 'PERMIT_COLLISION');
END
$$;

CREATE FUNCTION p65_lab.consume_permit(
  p_account text, p_compartment text, p_keyring text, p_permit_id text,
  p_operation text, p_reservation text, p_revision bigint, p_digest bytea,
  p_epoch integer, p_generation bigint, p_effect_id text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE
  h p65_lab.keyring_head%ROWTYPE;
  permit_row p65_lab.permit_ledger%ROWTYPE;
BEGIN
  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
  FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH'); END IF;
  SELECT * INTO permit_row FROM p65_lab.permit_ledger
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
    AND permit_id = p_permit_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH'); END IF;
  IF permit_row.operation_id <> p_operation OR permit_row.reservation_id <> p_reservation
     OR permit_row.expected_revision <> p_revision OR permit_row.expected_digest <> p_digest
     OR permit_row.expected_epoch <> p_epoch OR permit_row.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  IF permit_row.state = 'CONSUMED' THEN RETURN jsonb_build_object('status', 'PERMIT_REPLAY'); END IF;
  IF h.gate_state <> 'OPEN' THEN RETURN jsonb_build_object('status', 'GATE_CLOSED'); END IF;
  IF h.revision <> p_revision OR h.manifest_digest <> p_digest OR h.active_epoch <> p_epoch
     OR h.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'STALE_HEAD_OR_GENERATION');
  END IF;
  UPDATE p65_lab.permit_ledger SET state = 'CONSUMED', effect_id = p_effect_id, consumed_at = p65_lab.lab_now()
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring AND permit_id = p_permit_id;
  INSERT INTO p65_lab.active_effect(
    account_id, compartment_id, keyring_id, effect_id, operation_id, reservation_id,
    expected_revision, expected_digest, expected_epoch, generation, state, started_at
  ) VALUES (
    p_account, p_compartment, p_keyring, p_effect_id, p_operation, p_reservation,
    p_revision, p_digest, p_epoch, p_generation, 'ACTIVE', p65_lab.lab_now()
  );
  RETURN jsonb_build_object('status', 'CONSUMED', 'effect_id', p_effect_id, 'generation', p_generation);
EXCEPTION WHEN unique_violation THEN
  RETURN jsonb_build_object('status', 'EFFECT_COLLISION');
END
$$;

CREATE FUNCTION p65_lab.allow_simulated_io(
  p_account text, p_compartment text, p_keyring text,
  p_operation text, p_reservation text, p_effect_id text, p_generation bigint
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE h p65_lab.keyring_head%ROWTYPE; e p65_lab.active_effect%ROWTYPE;
BEGIN
  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
  FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH'); END IF;
  SELECT * INTO e FROM p65_lab.active_effect
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
    AND effect_id = p_effect_id FOR UPDATE;
  IF NOT FOUND OR e.operation_id <> p_operation OR e.reservation_id <> p_reservation
     OR e.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  IF h.gate_state <> 'OPEN' OR h.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'BLOCKED_GATE', 'gate_state', h.gate_state);
  END IF;
  IF e.state <> 'ACTIVE' THEN RETURN jsonb_build_object('status', 'EFFECT_STOPPED'); END IF;
  RETURN jsonb_build_object('status', 'ALLOW_SIMULATED_ONLY');
END
$$;

CREATE FUNCTION p65_lab.begin_quiesce(
  p_account text, p_compartment text, p_keyring text,
  p_operation text, p_reservation text, p_revision bigint, p_digest bytea, p_generation bigint
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE
  h p65_lab.keyring_head%ROWTYPE;
  op p65_lab.operation_request%ROWTYPE;
  foreign_effects integer;
  stop_count integer;
BEGIN
  SELECT * INTO op FROM p65_lab.operation_request WHERE operation_id = p_operation FOR UPDATE;
  IF NOT FOUND OR op.account_id <> p_account OR op.compartment_id <> p_compartment
     OR op.keyring_id <> p_keyring OR op.reservation_id <> p_reservation
     OR op.expected_revision <> p_revision OR op.expected_digest <> p_digest
     OR op.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
  FOR UPDATE;
  IF NOT FOUND OR h.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  IF op.status <> 'RESERVED' THEN RETURN jsonb_build_object('status', 'OPERATION_TERMINAL'); END IF;
  IF h.gate_state NOT IN ('PENDING', 'QUIESCING') THEN
    RETURN jsonb_build_object('status', 'GATE_STATE_MISMATCH', 'gate_state', h.gate_state);
  END IF;
  SELECT count(*) INTO foreign_effects FROM p65_lab.active_effect
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
    AND state = 'ACTIVE'
    AND (operation_id <> p_operation OR reservation_id <> p_reservation OR generation <> p_generation);
  IF foreign_effects <> 0 THEN RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH'); END IF;
  UPDATE p65_lab.keyring_head SET gate_state = 'QUIESCING'
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring;
  INSERT INTO p65_lab.stop_ack_requests(
    account_id, compartment_id, keyring_id, effect_id, operation_id, reservation_id,
    expected_ack_id, generation
  )
  SELECT p_account, p_compartment, p_keyring, e.effect_id, p_operation, p_reservation,
    'ack-' || md5(p_account || '|' || p_compartment || '|' || p_keyring || '|'
      || e.effect_id || '|' || p_operation || '|' || p_reservation || '|' || p_generation::text),
    p_generation
  FROM p65_lab.active_effect e
  WHERE e.account_id = p_account AND e.compartment_id = p_compartment AND e.keyring_id = p_keyring
    AND e.state = 'ACTIVE'
  ON CONFLICT DO NOTHING;
  SELECT count(*) INTO stop_count FROM p65_lab.stop_ack_requests
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
    AND operation_id = p_operation AND reservation_id = p_reservation AND generation = p_generation;
  RETURN jsonb_build_object('status', 'QUIESCING', 'generation', p_generation, 'stopCount', stop_count);
END
$$;

CREATE FUNCTION p65_lab.acknowledge_stop(
  p_account text, p_compartment text, p_keyring text,
  p_operation text, p_reservation text, p_effect_id text, p_ack_id text, p_generation bigint
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE h p65_lab.keyring_head%ROWTYPE; ack p65_lab.stop_ack_requests%ROWTYPE;
BEGIN
  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
  FOR UPDATE;
  IF NOT FOUND OR h.gate_state <> 'QUIESCING' OR h.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  SELECT * INTO ack FROM p65_lab.stop_ack_requests
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
    AND effect_id = p_effect_id FOR UPDATE;
  IF NOT FOUND OR ack.operation_id <> p_operation OR ack.reservation_id <> p_reservation
     OR ack.generation <> p_generation THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  IF ack.expected_ack_id <> p_ack_id THEN RETURN jsonb_build_object('status', 'STOP_ACK_MISMATCH'); END IF;
  IF ack.acknowledged THEN RETURN jsonb_build_object('status', 'STOP_ACK_REPLAY'); END IF;
  UPDATE p65_lab.stop_ack_requests SET acknowledged = true, acknowledged_at = p65_lab.lab_now()
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring AND effect_id = p_effect_id;
  UPDATE p65_lab.active_effect SET state = 'STOPPED', stopped_at = p65_lab.lab_now()
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
    AND effect_id = p_effect_id AND state = 'ACTIVE';
  RETURN jsonb_build_object('status', 'ACKNOWLEDGED');
END
$$;

CREATE FUNCTION p65_lab.commit_operation(p_request p65_lab.request_input, p_inject_fault boolean DEFAULT false)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE
  op p65_lab.operation_request%ROWTYPE;
  h p65_lab.keyring_head%ROWTYPE;
  terminal p65_lab.operation_terminal%ROWTYPE;
  incomplete integer;
  result jsonb;
BEGIN
  SELECT * INTO op FROM p65_lab.operation_request
  WHERE operation_id = (p_request).operation_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'NOT_RESERVED'); END IF;
  IF p65_lab.request_matches(op, p_request) IS NOT TRUE THEN
    RETURN jsonb_build_object('status', 'OPERATION_CONFLICT');
  END IF;
  SELECT * INTO terminal FROM p65_lab.operation_terminal WHERE operation_id = op.operation_id;
  IF FOUND THEN RETURN terminal.result; END IF;

  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = op.account_id AND compartment_id = op.compartment_id AND keyring_id = op.keyring_id
  FOR UPDATE;
  IF NOT FOUND OR h.gate_state <> 'QUIESCING' OR h.generation <> op.generation THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  IF h.revision <> op.expected_revision OR h.manifest_digest <> op.expected_digest THEN
    RETURN jsonb_build_object('status', 'HEAD_MISMATCH');
  END IF;
  IF op.status <> 'RESERVED' THEN RETURN jsonb_build_object('status', 'OPERATION_TERMINAL'); END IF;
  SELECT count(*) INTO incomplete FROM p65_lab.stop_ack_requests
  WHERE account_id = op.account_id AND compartment_id = op.compartment_id AND keyring_id = op.keyring_id
    AND operation_id = op.operation_id AND reservation_id = op.reservation_id
    AND generation = op.generation AND acknowledged = false;
  IF incomplete <> 0 OR EXISTS (
    SELECT 1 FROM p65_lab.active_effect
    WHERE account_id = op.account_id AND compartment_id = op.compartment_id AND keyring_id = op.keyring_id
      AND operation_id = op.operation_id AND reservation_id = op.reservation_id
      AND generation = op.generation AND state = 'ACTIVE'
  ) THEN
    RETURN jsonb_build_object('status', 'STOP_ACKS_INCOMPLETE');
  END IF;
  IF h.transition_count >= 4096 OR h.transition_bytes + octet_length(op.transition_bytes) > 67108864
     OR octet_length(op.transition_bytes) > 8388608 THEN
    RETURN jsonb_build_object('status', 'HISTORY_LIMIT');
  END IF;

  INSERT INTO p65_lab.transition_log(
    account_id, compartment_id, keyring_id, revision, operation_id, reservation_id,
    expected_digest, proposed_digest, request_digest, transition_bytes, recorded_at
  ) VALUES (
    op.account_id, op.compartment_id, op.keyring_id, op.proposed_revision, op.operation_id,
    op.reservation_id, op.expected_digest, op.proposed_digest, op.request_digest, op.transition_bytes,
    p65_lab.lab_now()
  );
  IF p_inject_fault THEN RAISE EXCEPTION 'LAB_INJECTED_BEFORE_HEAD_AND_TERMINAL_COMMIT'; END IF;

  UPDATE p65_lab.keyring_head SET revision = op.proposed_revision,
    manifest_digest = op.proposed_digest, gate_state = 'OPEN', generation = generation + 1,
    transition_count = transition_count + 1,
    transition_bytes = transition_bytes + octet_length(op.transition_bytes)
  WHERE account_id = op.account_id AND compartment_id = op.compartment_id AND keyring_id = op.keyring_id;
  UPDATE p65_lab.operation_request SET status = 'COMMITTED' WHERE operation_id = op.operation_id;
  result := jsonb_build_object('status', 'COMMITTED', 'operation_id', op.operation_id,
    'revision', op.proposed_revision, 'manifest_digest', encode(op.proposed_digest, 'hex'));
  INSERT INTO p65_lab.operation_terminal(operation_id, request_digest, request_bytes, terminal_status, result, terminal_at)
  VALUES (op.operation_id, op.request_digest, op.request_bytes, 'COMMITTED', result, p65_lab.lab_now());
  RETURN result;
END
$$;

CREATE FUNCTION p65_lab.seal_no_commit(p_request p65_lab.request_input)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE
  op p65_lab.operation_request%ROWTYPE;
  h p65_lab.keyring_head%ROWTYPE;
  terminal p65_lab.operation_terminal%ROWTYPE;
  incomplete integer;
  result jsonb;
BEGIN
  SELECT * INTO op FROM p65_lab.operation_request
  WHERE operation_id = (p_request).operation_id FOR UPDATE;
  IF NOT FOUND OR op.account_id <> (p_request).account_id
     OR op.compartment_id <> (p_request).compartment_id OR op.keyring_id <> (p_request).keyring_id
     OR op.reservation_id <> (p_request).reservation_id THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  IF p65_lab.request_matches(op, p_request) IS NOT TRUE THEN
    RETURN jsonb_build_object('status', 'OPERATION_CONFLICT');
  END IF;
  SELECT * INTO terminal FROM p65_lab.operation_terminal WHERE operation_id = op.operation_id;
  IF FOUND THEN
    IF terminal.terminal_status = 'COMMITTED' THEN RETURN jsonb_build_object('status', 'COMMIT_ALREADY_EXISTS'); END IF;
    RETURN terminal.result;
  END IF;
  IF EXISTS (SELECT 1 FROM p65_lab.transition_log WHERE operation_id = op.operation_id) THEN
    RETURN jsonb_build_object('status', 'COMMIT_ALREADY_EXISTS');
  END IF;
  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = op.account_id AND compartment_id = op.compartment_id AND keyring_id = op.keyring_id
  FOR UPDATE;
  IF NOT FOUND OR h.gate_state <> 'QUIESCING' OR h.generation <> op.generation THEN
    RETURN jsonb_build_object('status', 'GATE_BINDING_MISMATCH');
  END IF;
  IF h.revision <> op.expected_revision OR h.manifest_digest <> op.expected_digest THEN
    RETURN jsonb_build_object('status', 'HEAD_MISMATCH');
  END IF;
  IF p65_lab.lab_now() < op.expires_at + interval '30 seconds' THEN
    RETURN jsonb_build_object('status', 'WAIT_EXPIRY_BOUND');
  END IF;
  SELECT count(*) INTO incomplete FROM p65_lab.stop_ack_requests
  WHERE account_id = op.account_id AND compartment_id = op.compartment_id AND keyring_id = op.keyring_id
    AND operation_id = op.operation_id AND reservation_id = op.reservation_id
    AND generation = op.generation AND acknowledged = false;
  IF incomplete <> 0 OR EXISTS (
    SELECT 1 FROM p65_lab.active_effect
    WHERE account_id = op.account_id AND compartment_id = op.compartment_id AND keyring_id = op.keyring_id
      AND operation_id = op.operation_id AND reservation_id = op.reservation_id
      AND generation = op.generation AND state = 'ACTIVE'
  ) THEN
    RETURN jsonb_build_object('status', 'STOP_ACKS_INCOMPLETE');
  END IF;

  INSERT INTO p65_lab.no_commit_fence(
    operation_id, account_id, compartment_id, keyring_id, reservation_id,
    expected_revision, expected_digest, request_digest, generation, fenced_at
  ) VALUES (
    op.operation_id, op.account_id, op.compartment_id, op.keyring_id, op.reservation_id,
    op.expected_revision, op.expected_digest, op.request_digest, op.generation, p65_lab.lab_now()
  );
  result := jsonb_build_object('status', 'NO_COMMIT_FINAL', 'operation_id', op.operation_id,
    'revision', op.expected_revision, 'manifest_digest', encode(op.expected_digest, 'hex'));
  INSERT INTO p65_lab.operation_terminal(operation_id, request_digest, request_bytes, terminal_status, result, terminal_at)
  VALUES (op.operation_id, op.request_digest, op.request_bytes, 'NO_COMMIT_FINAL', result, p65_lab.lab_now());
  UPDATE p65_lab.operation_request SET status = 'NO_COMMIT_FINAL' WHERE operation_id = op.operation_id;
  UPDATE p65_lab.keyring_head SET gate_state = 'OPEN', generation = generation + 1
  WHERE account_id = op.account_id AND compartment_id = op.compartment_id AND keyring_id = op.keyring_id;
  RETURN result;
END
$$;

CREATE FUNCTION p65_lab.set_mock_witness_highwater(
  p_account text, p_compartment text, p_keyring text, p_revision bigint, p_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE current_revision bigint;
BEGIN
  SELECT revision INTO current_revision FROM p65_lab.mock_witness_highwater
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring
  FOR UPDATE;
  IF FOUND AND p_revision < current_revision THEN
    RETURN jsonb_build_object('status', 'WITNESS_HIGH_WATER_REGRESSION');
  END IF;
  INSERT INTO p65_lab.mock_witness_highwater(account_id, compartment_id, keyring_id, revision, manifest_digest, recorded_at)
  VALUES (p_account, p_compartment, p_keyring, p_revision, p_digest, p65_lab.lab_now())
  ON CONFLICT (account_id, compartment_id, keyring_id) DO UPDATE
    SET revision = EXCLUDED.revision, manifest_digest = EXCLUDED.manifest_digest, recorded_at = EXCLUDED.recorded_at;
  RETURN jsonb_build_object('status', 'WITNESS_HIGH_WATER_SET', 'revision', p_revision);
END
$$;

CREATE FUNCTION p65_lab.validate_fresh_response(
  p_account text, p_compartment text, p_keyring text, p_revision bigint, p_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, p65_lab
AS $$
DECLARE h p65_lab.keyring_head%ROWTYPE; w p65_lab.mock_witness_highwater%ROWTYPE;
BEGIN
  SELECT * INTO h FROM p65_lab.keyring_head
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring;
  SELECT * INTO w FROM p65_lab.mock_witness_highwater
  WHERE account_id = p_account AND compartment_id = p_compartment AND keyring_id = p_keyring;
  IF NOT FOUND OR w.account_id IS NULL THEN RETURN jsonb_build_object('status', 'FAIL_CLOSED_NO_WITNESS'); END IF;
  IF NOT FOUND OR h.account_id IS NULL OR w.revision < h.revision OR p_revision < w.revision
     OR p_revision <> h.revision OR p_digest <> h.manifest_digest OR p_digest <> w.manifest_digest THEN
    RETURN jsonb_build_object('status', 'FAIL_CLOSED_STALE');
  END IF;
  RETURN jsonb_build_object('status', 'FRESH_INTERNAL_ONLY', 'revision', p_revision);
END
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA p65_lab FROM PUBLIC, p65_cas, p65_gate, p65_status, p65_test;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA p65_lab FROM PUBLIC;
GRANT EXECUTE ON FUNCTION p65_lab.test_seed_keyring(text, text, text, bytea, integer, integer, integer, bigint) TO p65_test;
GRANT EXECUTE ON FUNCTION p65_lab.set_test_clock_offset(integer) TO p65_test;
GRANT EXECUTE ON FUNCTION p65_lab.set_mock_witness_highwater(text, text, text, bigint, bytea) TO p65_test;
GRANT EXECUTE ON FUNCTION p65_lab.reserve_operation(p65_lab.request_input) TO p65_cas;
GRANT EXECUTE ON FUNCTION p65_lab.commit_operation(p65_lab.request_input, boolean) TO p65_cas;
GRANT EXECUTE ON FUNCTION p65_lab.read_head(text, text, text) TO p65_cas, p65_gate;
GRANT EXECUTE ON FUNCTION p65_lab.issue_permit(text, text, text, text, text, bigint, bytea, integer, bigint, text) TO p65_gate;
GRANT EXECUTE ON FUNCTION p65_lab.consume_permit(text, text, text, text, text, text, bigint, bytea, integer, bigint, text) TO p65_gate;
GRANT EXECUTE ON FUNCTION p65_lab.allow_simulated_io(text, text, text, text, text, text, bigint) TO p65_gate;
GRANT EXECUTE ON FUNCTION p65_lab.begin_quiesce(text, text, text, text, text, bigint, bytea, bigint) TO p65_gate;
GRANT EXECUTE ON FUNCTION p65_lab.acknowledge_stop(text, text, text, text, text, text, text, bigint) TO p65_gate;
GRANT EXECUTE ON FUNCTION p65_lab.seal_no_commit(p65_lab.request_input) TO p65_status;
GRANT EXECUTE ON FUNCTION p65_lab.validate_fresh_response(text, text, text, bigint, bytea) TO p65_status;

GRANT EXECUTE ON FUNCTION p65_lab.protect_immutable_row() TO postgres;
REVOKE ALL ON ALL TABLES IN SCHEMA p65_lab FROM p65_cas, p65_gate, p65_status, p65_test;
