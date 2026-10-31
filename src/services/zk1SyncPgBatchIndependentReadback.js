"use strict";

// DEV-OFF: independent READ-ONLY PG18 evidence inspection, not an attestation
// service. A separate credential/host must own attestorPool. No signing key,
// CAS floor, Ed25519 witness receipt or physicalDurable claim is provided.
const crypto = require("node:crypto");
const { verifyWebdavOverwriteProvenance } = require("./zk1SyncPgWebdavProvenance");
const { hasUnexpectedProtectedDml } = require("./zk1SyncPgProtectedRoleAudit");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { verifyHistoricalAuthorizationProof } =
  require("../../sync-client/rootark-sync-authorization");

const error = () => Object.assign(new Error("ZK1_SYNC_PG_READBACK_UNVERIFIED"),
  { code: "ZK1_SYNC_PG_READBACK_UNVERIFIED" });
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest();
const equal = (one, two) => Buffer.isBuffer(one) && Buffer.isBuffer(two)
  && one.length === two.length && crypto.timingSafeEqual(one, two);

function createZk1SyncPgBatchIndependentReadback({ attestorPool } = {}) {
  if (!attestorPool || typeof attestorPool.connect !== "function") throw error();
  async function inspectSignedPair({ scope, commitId, operationIds = null,
    envelopeDigests = null } = {}) {
      if (typeof scope !== "string" || !/^[A-Za-z0-9._:-]{1,256}$/.test(scope)
        || (operationIds === null
          ? (typeof commitId !== "string"
            || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(commitId))
          : (commitId !== null || !Array.isArray(operationIds) || operationIds.length !== 2
            || operationIds.some((id) => typeof id !== "string" || !/^[A-Za-z0-9._:-]{1,160}$/.test(id))
            || operationIds[0] === operationIds[1]
            || !Array.isArray(envelopeDigests) || envelopeDigests.length !== 2
            || envelopeDigests.some((digest) => typeof digest !== "string"
              || !/^[a-f0-9]{64}$/.test(digest))))) {
        throw error();
      }
      let client;
      let begun = false;
      try {
        client = await attestorPool.connect();
        await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
        begun = true;
        await client.query("SET LOCAL statement_timeout = '8000ms'");
        const privileges = await client.query(`SELECT
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_attestor_reader','USAGE') AS reader,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_verifier','MEMBER') AS writer_member,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_runtime','MEMBER') AS runtime_member,
          pg_catalog.pg_has_role(current_user,'pg_write_all_data','MEMBER') AS universal_writer,
          r.rolsuper, r.rolcreaterole, r.rolbypassrls,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','UPDATE') AS object_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','INSERT') AS object_insert,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS object_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS object_truncate,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','DELETE') AS head_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','TRUNCATE') AS head_truncate,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.batch_commit','INSERT') AS marker_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','UPDATE') AS head_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.device_grant','UPDATE') AS grant_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_policy','UPDATE') AS policy_write,
          pg_catalog.has_column_privilege(current_user,'zk1_sync_batch.object_state','ciphertext','UPDATE') AS ciphertext_write,
          (SELECT COALESCE(pg_catalog.bool_or(
            pg_catalog.has_function_privilege(current_user, f.oid, 'EXECUTE')),false)
            FROM pg_catalog.pg_proc f
            JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
            WHERE n.nspname='zk1_sync_batch' AND f.prosecdef) AS definer_execute,
          current_setting('fsync') AS fsync, current_setting('full_page_writes') AS full_page_writes
          FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
        const privilege = privileges.rows[0];
        if (!privilege || privilege.reader !== true
          || privilege.writer_member || privilege.runtime_member || privilege.universal_writer
          || privilege.rolsuper || privilege.rolcreaterole || privilege.rolbypassrls
          || privilege.object_write || privilege.object_insert || privilege.object_delete
          || privilege.object_truncate || privilege.head_delete || privilege.head_truncate
          || privilege.marker_write || privilege.head_write || privilege.grant_write
          || privilege.policy_write || privilege.ciphertext_write || privilege.definer_execute
          || privilege.fsync !== "on"
          || privilege.full_page_writes !== "on") throw error();
        if (await hasUnexpectedProtectedDml(client)) throw error();
        if (operationIds !== null) {
          // Resolve the current physical SQL batch from the two exact signed
          // envelopes in ONE read-only REPEATABLE READ snapshot. A caller's
          // commitId or an untrusted HTTP ACK must never select the batch.
          const resolved = await client.query(`SELECT m.commit_id
            FROM zk1_sync_batch.batch_commit m
            JOIN zk1_sync_batch.scope_head h ON h.scope=m.scope
              AND h.sequence=m.sequence AND h.head=m.head
            WHERE m.scope=$1 AND m.delete_id=$2 AND m.move_id=$3
              AND m.delete_digest=pg_catalog.decode($4,'hex')
              AND m.move_digest=pg_catalog.decode($5,'hex')`, [
            scope, ...operationIds, ...envelopeDigests,
          ]);
          if (resolved.rowCount !== 1) throw error();
          commitId = resolved.rows[0].commit_id;
          if (typeof commitId !== "string") throw error();
        }
        const evidence = await client.query(`SELECT m.*, h.sequence AS latest_sequence,
          h.head AS latest_head, p.username, p.compartment_id, p.key_epoch,
          p.enabled,p.allow_delete,p.policy_epoch AS current_epoch
          FROM zk1_sync_batch.batch_commit m
          JOIN zk1_sync_batch.scope_head h ON h.scope=m.scope
          JOIN zk1_sync_batch.scope_policy p ON p.scope=m.scope
          WHERE m.scope=$1 AND m.commit_id=$2`, [scope, commitId]);
        if (evidence.rowCount !== 1) throw error();
        const m = evidence.rows[0];
        if (!Number.isSafeInteger(Number(m.sequence)) || Number(m.sequence) < 1
          || !m.enabled || !m.allow_delete || m.policy_epoch !== m.current_epoch
          || m.sequence !== m.latest_sequence || !equal(m.head, m.latest_head)) throw error();
        const originalRows = await client.query(`SELECT s.ordinal, s.operation_id,
          s.canonical_envelope, s.envelope_digest, s.ciphertext,
          o.canonical_envelope AS state_envelope,
          o.envelope_digest AS state_digest, o.ciphertext AS state_ciphertext,
          o.object_id,o.file_id,o.version_id,o.device_id,o.revision_counter,
          o.revision_device,o.compartment_id,o.key_epoch,o.logical_path,
          o.tombstone,o.last_commit_id
          FROM zk1_sync_batch.seen_envelope s
          JOIN zk1_sync_batch.object_state o ON o.scope=s.scope
            AND o.object_id=s.canonical_envelope::jsonb->>'objectId'
          WHERE s.scope=$1 AND s.commit_id=$2
          ORDER BY s.ordinal`, [scope, commitId]);
        if (originalRows.rowCount !== 2) throw error();
        const operations = [];
        for (const [index, row] of originalRows.rows.entries()) {
          const op = JSON.parse(row.canonical_envelope);
          const digest = sha(Buffer.from(row.canonical_envelope, "utf8"));
          const bytes = Buffer.from(op.ciphertext, "base64url");
          if (row.ordinal !== index || row.operation_id !== op.operationId
            || row.last_commit_id !== commitId || row.device_id !== op.deviceId
            || row.file_id !== op.fileId || row.version_id !== op.versionId
            || row.object_id !== op.objectId || row.compartment_id !== op.compartmentId
            || row.key_epoch !== op.keyEpoch || row.logical_path !== op.metadata?.path
            || Number(row.revision_counter) !== op.revision.counter
            || row.revision_device !== op.revision.deviceId
            || row.tombstone !== op.tombstone
            || row.state_envelope !== row.canonical_envelope
            || protocol.canonicalJson(op) !== row.canonical_envelope
            || !equal(row.envelope_digest, digest)
            || !equal(row.envelope_digest, row.state_digest)
            || !equal(row.ciphertext, row.state_ciphertext)
            || !equal(row.ciphertext, bytes)
            || !equal(digest, index === 0 ? m.delete_digest : m.move_digest)
            || op.operationId !== (index === 0 ? m.delete_id : m.move_id)) throw error();
          operations.push(op);
        }
        const [deleted, moved] = operations;
        if (operationIds !== null && operations.some((op, i) =>
          op.operationId !== operationIds[i]
          || originalRows.rows[i].envelope_digest.toString("hex") !== envelopeDigests[i])) throw error();
        if (deleted.operation !== "delete" || moved.operation !== "move"
          || !verifyWebdavOverwriteProvenance(deleted, moved)
          || !deleted.tombstone || moved.tombstone
          || deleted.deviceId !== moved.deviceId
          || deleted.metadata.path !== moved.metadata.path
          || deleted.compartmentId !== m.compartment_id
          || moved.compartmentId !== m.compartment_id
          || deleted.keyEpoch !== m.key_epoch || moved.keyEpoch !== m.key_epoch
          || deleted.objectId === moved.objectId
          || deleted.authorization?.username !== m.username
          || moved.authorization?.username !== m.username) throw error();
        const grant = await client.query(`SELECT public_key,revoked
          FROM zk1_sync_batch.device_grant WHERE scope=$1 AND device_id=$2`,
          [scope, deleted.deviceId]);
        if (grant.rowCount !== 1 || grant.rows[0].revoked) throw error();
        for (const op of operations) {
          // Readback checks the independently pinned CURRENT device key and
          // revocation again; historical expiry is not a new ingress grant.
          protocol.validateStoredOperation(op);
          await verifyHistoricalAuthorizationProof(op.authorization, op, {
            username: m.username, trustedDevicePublicKeys: {
              [deleted.deviceId]: grant.rows[0].public_key,
            }, revokedDeviceIds: [],
          });
        }
        const state = await client.query(`SELECT
          zk1_sync_batch.state_digest($1,$2,$3) AS digest,
          zk1_sync_batch.commit_head($1,$4,$5,$6,$7,$8,$9,$10,$11,$12) AS head`, [
          scope, deleted.objectId, moved.objectId,
          m.sequence, commitId, m.policy_epoch, m.previous_head,
          m.delete_id, m.move_id, m.delete_digest, m.move_digest, m.state_digest,
        ]);
        if (!equal(state.rows[0]?.digest, m.state_digest)
          || !equal(state.rows[0]?.head, m.head)) throw error();
        const prior = await client.query(`SELECT head FROM zk1_sync_batch.batch_commit
          WHERE scope=$1 AND sequence=$2`, [scope, Number(m.sequence) - 1]);
        if (Number(m.sequence) === 1
          ? (prior.rowCount !== 0 || !equal(m.previous_head, Buffer.alloc(32)))
          : (prior.rowCount !== 1 || !equal(prior.rows[0].head, m.previous_head))) throw error();
        await client.query("COMMIT");
        begun = false;
        return Object.freeze({
          scope, commitId, sequence: Number(m.sequence),
          head: m.head.toString("hex"),
          operationIds: operations.map((op) => op.operationId),
          envelopeDigests: originalRows.rows.map((row) => row.envelope_digest.toString("hex")),
          localPgRowsConsistent: true,
          witnessVerified: false, clientAckAuthorized: false,
          // NO PG commit readback can establish independent physical durability,
          // WAL fence, custody or external monotonic CAS floor on its own.
        });
      } catch {
        if (begun && client) {
          try { await client.query("ROLLBACK"); } catch { /* preserve failure */ }
        }
        throw error();
      } finally {
        client?.release?.();
      }
  }
  return Object.freeze({
    verifyLatestSignedPair({ scope, commitId } = {}) {
      return inspectSignedPair({ scope, commitId });
    },
    async verifyCurrentSignedPair(input = {}) {
      // Capture the challenge once. A getter/Proxy cannot retarget the
      // requested pair between look-up, verification and final return.
      let request;
      try {
        request = JSON.parse(protocol.canonicalJson(input));
        if (!request || typeof request !== "object" || Array.isArray(request)
          || Object.keys(request).sort().join(",")
            !== ["scope", "operationIds", "envelopeDigests"].sort().join(",")) throw error();
      } catch { throw error(); }
      return inspectSignedPair({ scope: request.scope, commitId: null,
        operationIds: request.operationIds, envelopeDigests: request.envelopeDigests });
    },
  });
}

module.exports = { createZk1SyncPgBatchIndependentReadback };
