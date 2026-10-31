"use strict";

// DEV-OFF / NO-GO: the verifier principal has NO protected table DML.
// A physically separate, privately credentialed issuer MUST verify original
// Ed25519 envelopes against pinned current grants and issue one short-lived
// PG admission ticket bound to exact pair bytes + head + policy epoch. The
// verifier never mints a ticket or sees issuer credentials. No issuer service,
// independently signed physical witness, or external CAS floor ships here.
// Do not wire to HTTP, claim physical durability or authorize client ACK.
const crypto = require("node:crypto");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { verifyAuthorizationProof } = require("../../sync-client/rootark-sync-authorization");
const { verifyWebdavOverwriteProvenance } = require("./zk1SyncPgWebdavProvenance");

const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const MAX_SIGNED_BATCH_BYTES = 9 * 1024 * 1024;
const fail = (code) => Object.assign(new Error(code), { code });
const sha = (text) => crypto.createHash("sha256").update(text, "utf8").digest();

function prepare(operations) {
  if (!Array.isArray(operations) || operations.length !== 2) throw fail("SYNC_PG_BATCH_INVALID");
  // Detach every mutable caller object before the first await. Fresh signature
  // validation includes exact fields, ciphertext/AAD and proof digest binding.
  const pair = operations.map((raw) =>
    protocol.validateFreshSignedOperation(JSON.parse(protocol.canonicalJson(raw))));
  if (Buffer.byteLength(protocol.canonicalJson(pair), "utf8") > MAX_SIGNED_BATCH_BYTES) {
    throw fail("SYNC_PG_BATCH_TOO_LARGE");
  }
  const [deleted, moved] = pair;
  if (deleted.operation !== "delete" || moved.operation !== "move"
    || !deleted.tombstone || moved.tombstone
    || !deleted.authorization || !moved.authorization
    || deleted.deviceId !== moved.deviceId
    || deleted.compartmentId !== moved.compartmentId
    || deleted.keyEpoch !== moved.keyEpoch
    || deleted.metadata.path !== moved.metadata.path
    || deleted.objectId === moved.objectId || deleted.fileId === moved.fileId
    || deleted.operationId === moved.operationId
    || deleted.authorization.replayId === moved.authorization.replayId
    || deleted.authorization.idempotencyKey === moved.authorization.idempotencyKey
    || !verifyWebdavOverwriteProvenance(deleted, moved)) {
    throw fail("SYNC_PG_BATCH_INVALID");
  }
  return pair.map((operation) => {
    const canonical = protocol.canonicalJson(operation);
    return Object.freeze({
      operation, canonical, digest: sha(canonical),
      ciphertext: Buffer.from(operation.ciphertext, "base64url"),
    });
  });
}

function createZk1SyncPgAtomicBatchStore({ verifierPool } = {}) {
  if (!verifierPool || typeof verifierPool.connect !== "function") {
    throw fail("SYNC_PG_BATCH_UNAVAILABLE");
  }
  return Object.freeze({
    async commitSignedOverwritePair({ scope, username, operations, admissionTicket } = {}) {
      if (typeof scope !== "string" || !SCOPE.test(scope)
        || typeof username !== "string" || username.length < 1 || username.length > 512
        || typeof admissionTicket !== "string"
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
          .test(admissionTicket)) {
        throw fail("SYNC_PG_BATCH_INVALID");
      }
      const pair = prepare(operations);
      const [deleted, moved] = pair.map((entry) => entry.operation);
      if (deleted.authorization.username !== username
        || moved.authorization.username !== username) throw fail("SYNC_PG_BATCH_UNAUTHORIZED");
      let client;
      let begun = false;
      let committing = false;
      try {
        client = await verifierPool.connect();
        await client.query("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED");
        begun = true;
        await client.query("SET LOCAL statement_timeout = '8000ms'");
        await client.query("SET LOCAL lock_timeout = '3000ms'");
        await client.query("SET LOCAL synchronous_commit = 'on'");
        const settings = await client.query(`SELECT current_setting('fsync') AS fsync,
          current_setting('full_page_writes') AS full_page_writes,
          current_setting('synchronous_commit') AS synchronous_commit,
          r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
          pg_catalog.pg_has_role(current_user,'pg_write_all_data','MEMBER') AS universal_writer,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_verifier','USAGE') AS verifier_role,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_runtime','MEMBER') AS runtime_member,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_admission_issuer','MEMBER') AS issuer_member,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','UPDATE') AS head_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','UPDATE') AS object_write,
          pg_catalog.has_column_privilege(current_user,'zk1_sync_batch.object_state','ciphertext','UPDATE') AS cipher_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.batch_commit','INSERT') AS marker_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.seen_envelope','INSERT') AS seen_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','INSERT') AS issuer_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS object_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS object_truncate,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','DELETE') AS head_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','TRUNCATE') AS head_truncate,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','DELETE') AS ticket_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','TRUNCATE') AS ticket_truncate
          FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
        const s = settings.rows[0];
        if (!s || s.fsync !== "on" || s.full_page_writes !== "on"
          || s.synchronous_commit !== "on" || s.rolsuper || s.rolcreaterole
          || s.rolcreatedb || s.rolreplication || s.rolbypassrls || s.universal_writer
          || s.verifier_role !== true || s.runtime_member !== false
          || s.issuer_member !== false || s.head_write || s.object_write
          || s.cipher_write || s.marker_write || s.seen_write || s.issuer_write
          || s.object_delete || s.object_truncate || s.head_delete || s.head_truncate
          || s.ticket_delete || s.ticket_truncate) {
          throw fail("SYNC_PG_BATCH_UNTRUSTED_DATABASE_ROLE");
        }
        // Read-only defense in depth before one controlled owner transaction.
        // The stored function acquires the authoritative scope_head FOR UPDATE
        // lock and RECHECKS all grant, epoch, ticket and CAS conditions.
        const policy = await client.query(`SELECT p.username,p.compartment_id,p.key_epoch,
          p.enabled,p.allow_delete,p.policy_epoch,g.public_key,g.revoked
          FROM zk1_sync_batch.scope_policy p
          JOIN zk1_sync_batch.device_grant g ON g.scope=p.scope AND g.device_id=$2
          WHERE p.scope=$1`, [scope, deleted.deviceId]);
        const grant = policy.rows[0];
        if (policy.rowCount !== 1 || !grant || grant.enabled !== true
          || grant.allow_delete !== true || grant.revoked !== false
          || grant.username !== username || grant.compartment_id !== deleted.compartmentId
          || grant.key_epoch !== deleted.keyEpoch
          || !Number.isSafeInteger(Number(grant.policy_epoch))
          || Number(grant.policy_epoch) < 1) {
          throw fail("SYNC_PG_BATCH_UNAUTHORIZED");
        }
        for (const item of pair) {
          try {
            await verifyAuthorizationProof(item.operation.authorization, item.operation, {
              username, trustedDevicePublicKeys: { [deleted.deviceId]: grant.public_key },
              revokedDeviceIds: [],
            });
          } catch { throw fail("SYNC_PG_BATCH_UNAUTHORIZED"); }
        }
        // No direct UPDATE/INSERT anywhere in this service. PostgreSQL checks
        // the separately issued ticket against exact original signed BYTES.
        const admitted = await client.query(`SELECT
          zk1_sync_batch.commit_admitted_pair($1,$2,$3,$4,$5) AS receipt`, [
          scope, username, admissionTicket, pair[0].canonical, pair[1].canonical,
        ]);
        const receipt = admitted.rows[0]?.receipt;
        if (!receipt || typeof receipt.commitId !== "string"
          || !Number.isSafeInteger(Number(receipt.sequence))
          || !/^[0-9a-f]{64}$/.test(receipt.storeHeadSha256)
          || receipt.witnessVerified !== false
          || receipt.clientAckAuthorized !== false) {
          throw fail("SYNC_PG_BATCH_INVALID_HEAD");
        }
        // COMMIT fires the SQL deferred original-envelope/physical marker
        // constraints and consumes the independent ticket atomically.
        committing = true;
        await client.query("COMMIT");
        begun = false;
        committing = false;
        return Object.freeze({
          commitId: receipt.commitId, sequence: Number(receipt.sequence),
          storeHeadSha256: receipt.storeHeadSha256,
          envelopeDigests: pair.map((x) => x.digest.toString("hex")),
          operationIds: pair.map((x) => x.operation.operationId),
          // This is local PG SQL evidence, NOT an independent signed physical
          // witness; clients must NOT mark their outbox seen from this alone.
          witnessVerified: false, clientAckAuthorized: false,
        });
      } catch (error) {
        if (begun && client) {
          try { await client.query("ROLLBACK"); } catch { /* preserve first error */ }
        }
        if (committing) throw fail("SYNC_PG_BATCH_COMMIT_INDETERMINATE");
        if (error?.code && error.code.startsWith("SYNC_PG_BATCH_")) throw error;
        throw fail("SYNC_PG_BATCH_UNAVAILABLE");
      } finally {
        client?.release?.();
      }
    },
  });
}

module.exports = { createZk1SyncPgAtomicBatchStore };
