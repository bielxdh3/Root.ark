"use strict";

// DEV-OFF / SECURITY NO-GO: execute ONLY in an independently isolated issuer
// environment with two non-writer DB credentials (read-only inspector and
// admission INSERT-only). Never give these to the HTTP server or PG writer.
// This is NO independent physical witness and no external CAS floor.
const crypto = require("node:crypto");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { verifyAuthorizationProof } = require("../../sync-client/rootark-sync-authorization");
const { verifyWebdavOverwriteProvenance } = require("./zk1SyncPgWebdavProvenance");

const fail = () => Object.assign(new Error("SYNC_PG_ISSUER_DENIED"),
  { code: "SYNC_PG_ISSUER_DENIED" });
const validScope = /^[A-Za-z0-9._:-]{1,256}$/;
const signedDigest = (value) =>
  crypto.createHash("sha256").update(protocol.canonicalJson(value), "utf8").digest();

function createZk1SyncPgIndependentAdmissionIssuer({ readerPool, issuerPool } = {}) {
  if (!readerPool?.connect || !issuerPool?.connect) throw fail();
  return Object.freeze({
    async issueTicket({ scope, username, operations } = {}) {
      if (typeof scope !== "string" || !validScope.test(scope)
        || typeof username !== "string" || !username || username.length > 512
        || !Array.isArray(operations) || operations.length !== 2) throw fail();
      let reader;
      let issuer;
      let snapshot = false;
      try {
        const pair = operations.map((item) =>
          protocol.validateFreshSignedOperation(JSON.parse(protocol.canonicalJson(item))));
        if (Buffer.byteLength(protocol.canonicalJson(pair), "utf8") > 9437184) throw fail();
        const [deleted, moved] = pair;
        if (deleted.operation !== "delete" || moved.operation !== "move"
          || !deleted.tombstone || moved.tombstone
          || deleted.deviceId !== moved.deviceId
          || deleted.objectId === moved.objectId || deleted.fileId === moved.fileId
          || deleted.compartmentId !== moved.compartmentId
          || deleted.keyEpoch !== moved.keyEpoch
          || deleted.metadata?.path !== moved.metadata?.path
          || deleted.authorization?.username !== username
          || moved.authorization?.username !== username
          || deleted.authorization.replayId === moved.authorization.replayId
          || deleted.authorization.idempotencyKey === moved.authorization.idempotencyKey
          || deleted.operationId === moved.operationId
          || !verifyWebdavOverwriteProvenance(deleted, moved)) throw fail();

        reader = await readerPool.connect();
        await reader.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
        snapshot = true;
        await reader.query("SET LOCAL statement_timeout = '8000ms'");
        const role = await reader.query(`SELECT
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_attestor_reader','USAGE') AS reader,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_verifier','MEMBER') AS verifier,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_admission_issuer','MEMBER') AS issuer,
          pg_catalog.pg_has_role(current_user,'pg_write_all_data','MEMBER') AS universal_writer,
          r.rolsuper, r.rolcreaterole, r.rolbypassrls,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','UPDATE') AS state_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','UPDATE') AS head_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS state_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS state_truncate,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','DELETE') AS head_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','TRUNCATE') AS head_truncate
          FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
        const r = role.rows[0];
        if (!r?.reader || r.verifier || r.issuer || r.universal_writer
          || r.rolsuper || r.rolcreaterole || r.rolbypassrls
          || r.state_write || r.head_write || r.state_delete || r.state_truncate
          || r.head_delete || r.head_truncate) throw fail();
        const pinned = await reader.query(`SELECT p.username,p.compartment_id,p.key_epoch,
          p.enabled,p.allow_delete,p.policy_epoch,g.device_id,g.public_key,g.revoked,
          h.sequence,h.head FROM zk1_sync_batch.scope_policy p
          JOIN zk1_sync_batch.scope_head h ON h.scope=p.scope
          JOIN zk1_sync_batch.device_grant g ON g.scope=p.scope AND g.device_id=$2
          WHERE p.scope=$1`, [scope, deleted.deviceId]);
        if (pinned.rowCount !== 1) throw fail();
        const row = pinned.rows[0];
        if (!row.enabled || !row.allow_delete || row.revoked || row.username !== username
          || row.compartment_id !== deleted.compartmentId
          || row.key_epoch !== deleted.keyEpoch
          || row.device_id !== deleted.deviceId
          || deleted.authorization.publicKey !== row.public_key
          || moved.authorization.publicKey !== row.public_key
          || !Buffer.isBuffer(row.head) || row.head.length !== 32
          || !Number.isSafeInteger(Number(row.sequence) + 1)) throw fail();
        for (const op of pair) {
          await verifyAuthorizationProof(op.authorization, op, {
            username, trustedDevicePublicKeys: { [row.device_id]: row.public_key },
            revokedDeviceIds: [],
          });
        }
        await reader.query("COMMIT");
        snapshot = false;
        reader.release();
        reader = undefined;

        // The independent issuer can only INSERT, not UPDATE/DELETE/read the
        // ticket or modify any protected state. The DB owner verifies the
        // policy_epoch/head/key/ticket AGAIN during admission consumption.
        issuer = await issuerPool.connect();
        const privileges = await issuer.query(`SELECT
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_admission_issuer','USAGE') AS issuer,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_verifier','MEMBER') AS verifier,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_attestor_reader','MEMBER') AS reader,
          pg_catalog.pg_has_role(current_user,'pg_write_all_data','MEMBER') AS universal_writer,
          r.rolsuper, r.rolcreaterole, r.rolbypassrls,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','INSERT') AS ticket_insert,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','UPDATE') AS ticket_update,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','UPDATE') AS head_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','UPDATE') AS state_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.batch_commit','INSERT') AS marker_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','DELETE') AS ticket_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','TRUNCATE') AS ticket_truncate,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS state_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS state_truncate
          FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
        const a = privileges.rows[0];
        if (!a?.issuer || a.verifier || a.reader || a.universal_writer
          || a.rolsuper || a.rolcreaterole || a.rolbypassrls
          || !a.ticket_insert || a.ticket_update
          || a.head_write || a.state_write || a.marker_write
          || a.ticket_delete || a.ticket_truncate || a.state_delete
          || a.state_truncate) throw fail();
        const ticket = crypto.randomUUID();
        await issuer.query(`INSERT INTO zk1_sync_batch.admission_ticket
          (ticket_id,scope,username,device_id,public_key,policy_epoch,
           sequence,previous_head,delete_digest,move_digest,expires_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
            clock_timestamp() + interval '30 seconds')`, [
          ticket, scope, username, row.device_id, row.public_key,
          row.policy_epoch, Number(row.sequence) + 1, row.head,
          signedDigest(deleted), signedDigest(moved),
        ]);
        // This is a short-lived DB admission handle, NOT a witness.
        return Object.freeze({ admissionTicket: ticket,
          witnessVerified: false, clientAckAuthorized: false });
      } catch { throw fail(); } finally {
        if (snapshot && reader) {
          try { await reader.query("ROLLBACK"); } catch { /* fail closed */ }
        }
        reader?.release?.();
        issuer?.release?.();
      }
    },
  });
}

module.exports = { createZk1SyncPgIndependentAdmissionIssuer };
