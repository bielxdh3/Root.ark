\set ON_ERROR_STOP on

-- Deliberately unsafe in-database negative control. This schema is disposable,
-- never used by the corrected lab model, and exists only to reproduce the two
-- known mock-fidelity gaps before the GREEN implementation is installed.
CREATE SCHEMA p65_red;

CREATE TABLE p65_red.operation_request (
  operation_id text PRIMARY KEY,
  payload_digest bytea NOT NULL,
  expected_revision bigint NOT NULL,
  outcome text NOT NULL DEFAULT 'COMMITTED'
);

CREATE FUNCTION p65_red.commit_request(p_operation_id text, p_payload_digest bytea, p_expected_revision bigint)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
  existing p65_red.operation_request%ROWTYPE;
BEGIN
  SELECT * INTO existing FROM p65_red.operation_request WHERE operation_id = p_operation_id;
  IF FOUND THEN
    -- RED: payload digest is checked, but expected revision is ignored.
    IF existing.payload_digest = p_payload_digest THEN
      RETURN existing.outcome;
    END IF;
    RETURN 'OPERATION_CONFLICT';
  END IF;
  INSERT INTO p65_red.operation_request(operation_id, payload_digest, expected_revision)
  VALUES (p_operation_id, p_payload_digest, p_expected_revision);
  RETURN 'COMMITTED';
END
$$;

CREATE TABLE p65_red.gate_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  scope_account text NOT NULL,
  scope_compartment text NOT NULL,
  scope_keyring text NOT NULL,
  operation_id text NOT NULL,
  reservation_id text NOT NULL,
  generation bigint NOT NULL,
  acknowledged boolean NOT NULL DEFAULT false
);

CREATE FUNCTION p65_red.prepare_gate(
  p_operation_id text,
  p_reservation_id text,
  p_account text,
  p_compartment text,
  p_keyring text,
  p_head_revision bigint,
  p_generation bigint
)
RETURNS text
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO p65_red.gate_state(singleton, scope_account, scope_compartment, scope_keyring,
    operation_id, reservation_id, generation, acknowledged)
  VALUES (true, p_account, p_compartment, p_keyring, p_operation_id, p_reservation_id, p_generation, true)
  ON CONFLICT (singleton) DO UPDATE SET
    scope_account = EXCLUDED.scope_account,
    scope_compartment = EXCLUDED.scope_compartment,
    scope_keyring = EXCLUDED.scope_keyring,
    operation_id = EXCLUDED.operation_id,
    reservation_id = EXCLUDED.reservation_id,
    generation = EXCLUDED.generation,
    acknowledged = EXCLUDED.acknowledged;
  RETURN 'READY';
END
$$;

CREATE FUNCTION p65_red.seal_no_commit(p_operation_id text)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
  has_ack boolean;
BEGIN
  SELECT acknowledged INTO has_ack FROM p65_red.gate_state WHERE singleton;
  IF has_ack THEN
    -- RED: the supplied operation is not compared with the quiesced operation.
    RETURN 'NO_COMMIT_FINAL';
  END IF;
  RETURN 'STOP_ACKS_INCOMPLETE';
END
$$;
