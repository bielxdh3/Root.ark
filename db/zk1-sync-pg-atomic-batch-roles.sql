-- DEV-OFF/NO-GO: role split for the independent trusted-verifier prototype.
-- Install as a dedicated DB owner AFTER zk1-sync-pg-atomic-batch.sql. Do NOT
-- grant the verifier login to the HTTP server, worker, browser or Sync runtime.
-- Ed25519 verification is currently JS-only and these roles alone are NOT
-- an authorization/witness proof or a substitute for a separate attestor.
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='zk1_sync_batch_runtime') THEN
    CREATE ROLE zk1_sync_batch_runtime NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='zk1_sync_batch_verifier') THEN
    CREATE ROLE zk1_sync_batch_verifier NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='zk1_sync_batch_attestor_reader') THEN
    CREATE ROLE zk1_sync_batch_attestor_reader NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='zk1_sync_batch_admission_issuer') THEN
    CREATE ROLE zk1_sync_batch_admission_issuer NOLOGIN NOINHERIT;
  END IF;
END $$;

-- Revoke historical grants at BOTH relation and column level. PostgreSQL
-- table-level REVOKE alone does not erase preexisting per-column grants.
-- Schema objects are created only by the DB operator, never the login.
REVOKE ALL ON SCHEMA zk1_sync_batch FROM PUBLIC,
  zk1_sync_batch_runtime, zk1_sync_batch_verifier,
  zk1_sync_batch_attestor_reader, zk1_sync_batch_admission_issuer;
REVOKE ALL ON ALL TABLES IN SCHEMA zk1_sync_batch FROM PUBLIC,
  zk1_sync_batch_runtime, zk1_sync_batch_verifier,
  zk1_sync_batch_attestor_reader, zk1_sync_batch_admission_issuer;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zk1_sync_batch FROM PUBLIC,
  zk1_sync_batch_runtime, zk1_sync_batch_verifier,
  zk1_sync_batch_attestor_reader, zk1_sync_batch_admission_issuer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA zk1_sync_batch FROM PUBLIC,
  zk1_sync_batch_runtime, zk1_sync_batch_verifier,
  zk1_sync_batch_attestor_reader, zk1_sync_batch_admission_issuer;
DO $$
DECLARE attribute record;
BEGIN
  FOR attribute IN SELECT cls.relname, att.attname
    FROM pg_catalog.pg_class cls
    JOIN pg_catalog.pg_namespace ns ON ns.oid=cls.relnamespace
    JOIN pg_catalog.pg_attribute att ON att.attrelid=cls.oid
    WHERE ns.nspname='zk1_sync_batch' AND cls.relkind IN ('r','p')
      AND att.attnum > 0 AND NOT att.attisdropped
  LOOP
    EXECUTE pg_catalog.format(
      'REVOKE SELECT (%1$I), INSERT (%1$I), UPDATE (%1$I), REFERENCES (%1$I) ON TABLE zk1_sync_batch.%2$I FROM PUBLIC, zk1_sync_batch_runtime, zk1_sync_batch_verifier, zk1_sync_batch_attestor_reader, zk1_sync_batch_admission_issuer',
      attribute.attname, attribute.relname);
  END LOOP;
END $$;

-- The untrusted runtime is read-only even for the chain head. It has NO
-- EXECUTE rights on any SECURITY DEFINER procedure and NO role inheritance
-- or SET ROLE path to the verifier. The actual login/credential is provisioned
-- out of band by the operator; never store its password in this migration.
GRANT USAGE ON SCHEMA zk1_sync_batch TO zk1_sync_batch_runtime,
  zk1_sync_batch_verifier, zk1_sync_batch_attestor_reader,
  zk1_sync_batch_admission_issuer;
GRANT SELECT ON zk1_sync_batch.scope_policy, zk1_sync_batch.device_grant,
  zk1_sync_batch.scope_head TO zk1_sync_batch_runtime;

-- The physically independent readback principal can inspect committed
-- ciphertext/envelopes/policy but cannot change any PG state or policy.
GRANT SELECT ON zk1_sync_batch.scope_policy, zk1_sync_batch.device_grant,
  zk1_sync_batch.scope_head, zk1_sync_batch.object_state,
  zk1_sync_batch.seen_envelope, zk1_sync_batch.batch_commit
  TO zk1_sync_batch_attestor_reader;
GRANT EXECUTE ON FUNCTION zk1_sync_batch.state_digest(text,text,text),
  zk1_sync_batch.commit_head(text,bigint,uuid,bigint,bytea,text,text,bytea,bytea,bytea)
  TO zk1_sync_batch_attestor_reader;

-- Independently trusted admission issuer may ONLY write bound short-lived
-- tickets (after verifying Ed25519 and current pinned grants outside SQL).
-- It has NO protected table DML and NO access to the owner-only consumption
-- mechanism; no verifier/runtime/reader credentials can INSERT a ticket.
GRANT INSERT ON zk1_sync_batch.admission_ticket
  TO zk1_sync_batch_admission_issuer;

-- The verifier CANNOT UPDATE/INSERT protected state/head/history or tickets.
-- It can execute only the fixed owner-owned SECURITY DEFINER transaction,
-- which requires a prior single-use, epoch/head/envelope-bound ticket.
GRANT SELECT ON zk1_sync_batch.scope_policy, zk1_sync_batch.device_grant
  TO zk1_sync_batch_verifier;
GRANT SELECT ON zk1_sync_batch.scope_head, zk1_sync_batch.object_state
  TO zk1_sync_batch_verifier;
GRANT SELECT ON zk1_sync_batch.batch_commit,
  zk1_sync_batch.seen_envelope TO zk1_sync_batch_verifier;
GRANT EXECUTE ON FUNCTION zk1_sync_batch.commit_admitted_pair(text,text,uuid,text,text)
  TO zk1_sync_batch_verifier;
GRANT EXECUTE ON FUNCTION zk1_sync_batch.state_digest(text,text,text),
  zk1_sync_batch.envelope_ciphertext(text),
  zk1_sync_batch.commit_head(text,bigint,uuid,bigint,bytea,text,text,bytea,bytea,bytea)
  TO zk1_sync_batch_verifier;
-- PostgreSQL grants EXECUTE to PUBLIC on NEW functions by GLOBAL default.
-- A schema-scoped REVOKE cannot subtract that global grant. The migration
-- MUST execute as the same dedicated owner who creates all future functions;
-- revoke GLOBAL owner defaults, then assert the effective future ACL in PG18.
ALTER DEFAULT PRIVILEGES
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- No role membership grants between any of the four roles.
COMMIT;
