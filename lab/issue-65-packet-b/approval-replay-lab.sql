-- Issue #65: EXPERIMENTAL, disposable-only device-approval replay ledger.
-- NOT a production migration or authority. Apply only inside the labeled
-- loopback PostgreSQL container created by run-approval-replay-postgres.js.
BEGIN;
CREATE SCHEMA zk1_approval_replay_lab;
REVOKE ALL ON SCHEMA zk1_approval_replay_lab FROM PUBLIC;
CREATE TABLE zk1_approval_replay_lab.consumed (
  scope_key text NOT NULL CHECK (length(scope_key) BETWEEN 35 AND 300),
  nonce bytea NOT NULL CHECK (octet_length(nonce)=32),
  keyring_id bytea NOT NULL CHECK (octet_length(keyring_id)=16),
  approval_digest bytea NOT NULL CHECK (octet_length(approval_digest)=32),
  device_key_id bytea NOT NULL CHECK (octet_length(device_key_id)=16),
  manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest)=32),
  manifest_revision bigint NOT NULL CHECK (manifest_revision>0),
  witness_sequence bigint NOT NULL CHECK (witness_sequence>0),
  expires_at bigint NOT NULL CHECK (expires_at>0),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(scope_key, nonce)
);
REVOKE ALL ON zk1_approval_replay_lab.consumed FROM PUBLIC;
-- The role itself cannot LOGIN. A distinct, disposable fixture login may
-- inherit INSERT only; it cannot read, update, delete or truncate tombstones.
CREATE ROLE zk1_approval_replay_writer NOLOGIN;
GRANT USAGE ON SCHEMA zk1_approval_replay_lab TO zk1_approval_replay_writer;
GRANT INSERT(scope_key,nonce,keyring_id,approval_digest,device_key_id,
  manifest_digest,manifest_revision,witness_sequence,expires_at)
  ON zk1_approval_replay_lab.consumed TO zk1_approval_replay_writer;
COMMIT;
