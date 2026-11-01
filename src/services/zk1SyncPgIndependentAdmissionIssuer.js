"use strict";

// DEV-OFF / SECURITY NO-GO: execute ONLY in an independently isolated issuer
// environment with two non-writer DB credentials (read-only inspector and
// admission INSERT-only). Never give these to the HTTP server or PG writer.
// This is NO independent physical witness and no external CAS floor.
const crypto = require("node:crypto");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { verifyAuthorizationProof } = require("../../sync-client/rootark-sync-authorization");
const { verifyWebdavOverwriteProvenance } = require("./zk1SyncPgWebdavProvenance");
const { hasUnexpectedProtectedDml, hasUnexpectedRoleMembership } =
  require("./zk1SyncPgProtectedRoleAudit");

const fail = () => Object.assign(new Error("SYNC_PG_ISSUER_DENIED"),
  { code: "SYNC_PG_ISSUER_DENIED" });
const validScope = /^[A-Za-z0-9._:-]{1,256}$/;
const signedDigest = (value) =>
  crypto.createHash("sha256").update(protocol.canonicalJson(value), "utf8").digest();

function createZk1SyncPgIndependentAdmissionIssuer({ readerPool, issuerPool,
  connectTimeoutMs = 6000, operationTimeoutMs = 25000 } = {}) {
  if (!readerPool?.connect || !issuerPool?.connect
    || !Number.isSafeInteger(connectTimeoutMs)
    || connectTimeoutMs < 50 || connectTimeoutMs > 7000
    || !Number.isSafeInteger(operationTimeoutMs)
    || operationTimeoutMs < 50 || operationTimeoutMs > 30000) throw fail();
  // A pool checkout may hang before PostgreSQL's statement_timeout begins.
  // A wall-clock timeout does not cancel an in-flight checkout: count it until
  // the real pool settles, then release any late client without using it.
  const connecting = new Set();
  // A connection may be checked out yet remain stalled in BEGIN/COMMIT or a
  // network query before statement_timeout is installed. Count the COMPLETE
  // operation until its driver Promise really settles, not just its timeout.
  const pendingOperations = new Set();
  async function acquire(pool) {
    if (connecting.size >= 8) throw fail();
    let abandoned = false;
    const attempt = Promise.resolve().then(() => pool.connect());
    connecting.add(attempt);
    attempt.then((client) => {
      connecting.delete(attempt);
      if (abandoned) {
        try { client?.release?.(); } catch { /* late checkout is unusable */ }
      }
    }, () => connecting.delete(attempt));
    let timer;
    try {
      return await Promise.race([attempt, new Promise((_, reject) => {
        timer = setTimeout(() => { abandoned = true; reject(fail()); }, connectTimeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  }
  async function executeTicket({ scope, username, operations } = {}, assertLive,
    isCancelled) {
      if (typeof scope !== "string" || !validScope.test(scope)
        || typeof username !== "string" || !username || username.length > 512
        || !Array.isArray(operations) || operations.length !== 2) throw fail();
      async function queryLive(client, ...args) {
        assertLive();
        const result = await client.query(...args);
        assertLive();
        return result;
      }
      let reader;
      let issuer;
      let snapshot = false;
      let issuing = false;
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

        assertLive();
        reader = await acquire(readerPool);
        assertLive();
        snapshot = true;
        await queryLive(reader, "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
        await queryLive(reader, "SET LOCAL statement_timeout = '8000ms'");
        const role = await queryLive(reader, `SELECT
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_attestor_reader','USAGE') AS reader,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_verifier','MEMBER') AS verifier,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_admission_issuer','MEMBER') AS issuer,
          pg_catalog.pg_has_role(current_user,'pg_write_all_data','MEMBER') AS universal_writer,
          pg_catalog.pg_has_role(current_user,'pg_read_server_files','MEMBER') AS server_file_reader,
          pg_catalog.pg_has_role(current_user,'pg_write_server_files','MEMBER') AS server_file_writer,
          pg_catalog.pg_has_role(current_user,'pg_execute_server_program','MEMBER') AS server_program,
          pg_catalog.pg_has_role(current_user,'pg_maintain','MEMBER') AS universal_maintainer,
          r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','UPDATE') AS state_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','UPDATE') AS head_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS state_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS state_truncate,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','DELETE') AS head_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','TRUNCATE') AS head_truncate,
          (SELECT COALESCE(pg_catalog.bool_or(
            pg_catalog.has_function_privilege(current_user,f.oid,'EXECUTE')),false)
            FROM pg_catalog.pg_proc f
            JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
            WHERE n.nspname NOT IN ('pg_catalog','information_schema')
              AND n.nspname NOT LIKE 'pg_toast%'
              AND n.nspname NOT LIKE 'pg_temp_%'
              AND f.prosecdef) AS definer_execute
          FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
        const r = role.rows[0];
        if (!r?.reader || r.verifier || r.issuer || r.universal_writer
          || r.server_file_reader || r.server_file_writer || r.server_program
          || r.universal_maintainer || r.rolsuper || r.rolcreaterole
          || r.rolcreatedb || r.rolreplication || r.rolbypassrls
          || r.definer_execute
          || r.state_write || r.head_write || r.state_delete || r.state_truncate
          || r.head_delete || r.head_truncate) throw fail();
        const readerEscalation = await hasUnexpectedRoleMembership(
          reader, "zk1_sync_batch_attestor_reader");
        assertLive();
        if (readerEscalation) throw fail();
        const readerDml = await hasUnexpectedProtectedDml(reader);
        assertLive();
        if (readerDml) throw fail();
        const pinned = await queryLive(reader, `SELECT p.username,p.compartment_id,p.key_epoch,
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
          assertLive();
          await verifyAuthorizationProof(op.authorization, op, {
            username, trustedDevicePublicKeys: { [row.device_id]: row.public_key },
            revokedDeviceIds: [],
          });
          assertLive();
        }
        await queryLive(reader, "COMMIT");
        snapshot = false;
        reader.release();
        reader = undefined;

        // The independent issuer can only INSERT, not UPDATE/DELETE/read the
        // ticket or modify any protected state. The DB owner verifies the
        // policy_epoch/head/key/ticket AGAIN during admission consumption.
        assertLive();
        issuer = await acquire(issuerPool);
        assertLive();
        issuing = true;
        await queryLive(issuer, "BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED");
        await queryLive(issuer, "SET LOCAL statement_timeout = '8000ms'");
        await queryLive(issuer, "SET LOCAL lock_timeout = '3000ms'");
        const privileges = await queryLive(issuer, `SELECT
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_admission_issuer','USAGE') AS issuer,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_verifier','MEMBER') AS verifier,
          pg_catalog.pg_has_role(current_user,'zk1_sync_batch_attestor_reader','MEMBER') AS reader,
          pg_catalog.pg_has_role(current_user,'pg_write_all_data','MEMBER') AS universal_writer,
          pg_catalog.pg_has_role(current_user,'pg_read_server_files','MEMBER') AS server_file_reader,
          pg_catalog.pg_has_role(current_user,'pg_write_server_files','MEMBER') AS server_file_writer,
          pg_catalog.pg_has_role(current_user,'pg_execute_server_program','MEMBER') AS server_program,
          pg_catalog.pg_has_role(current_user,'pg_maintain','MEMBER') AS universal_maintainer,
          r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','INSERT') AS ticket_insert,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','UPDATE') AS ticket_update,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','UPDATE') AS head_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','UPDATE') AS state_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.batch_commit','INSERT') AS marker_write,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','DELETE') AS ticket_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','TRUNCATE') AS ticket_truncate,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS state_delete,
          pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS state_truncate,
          (SELECT COALESCE(pg_catalog.bool_or(
            pg_catalog.has_function_privilege(current_user,f.oid,'EXECUTE')),false)
            FROM pg_catalog.pg_proc f
            JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
            WHERE n.nspname NOT IN ('pg_catalog','information_schema')
              AND n.nspname NOT LIKE 'pg_toast%'
              AND n.nspname NOT LIKE 'pg_temp_%'
              AND f.prosecdef) AS definer_execute
          FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
        const a = privileges.rows[0];
        if (!a?.issuer || a.verifier || a.reader || a.universal_writer
          || a.server_file_reader || a.server_file_writer || a.server_program
          || a.universal_maintainer || a.rolsuper || a.rolcreaterole
          || a.rolcreatedb || a.rolreplication || a.rolbypassrls
          || a.definer_execute
          || !a.ticket_insert || a.ticket_update
          || a.head_write || a.state_write || a.marker_write
          || a.ticket_delete || a.ticket_truncate || a.state_delete
          || a.state_truncate) throw fail();
        const issuerEscalation = await hasUnexpectedRoleMembership(
          issuer, "zk1_sync_batch_admission_issuer");
        assertLive();
        if (issuerEscalation) throw fail();
        const issuerDml = await hasUnexpectedProtectedDml(
          issuer, { allowTicketInsert: true });
        assertLive();
        if (issuerDml) throw fail();
        assertLive();
        const ticket = crypto.randomUUID();
        await queryLive(issuer, `INSERT INTO zk1_sync_batch.admission_ticket
          (ticket_id,scope,username,device_id,public_key,policy_epoch,
           sequence,previous_head,delete_digest,move_digest,expires_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
            clock_timestamp() + interval '30 seconds')`, [
          ticket, scope, username, row.device_id, row.public_key,
          row.policy_epoch, Number(row.sequence) + 1, row.head,
          signedDigest(deleted), signedDigest(moved),
        ]);
        await queryLive(issuer, "COMMIT");
        issuing = false;
        // This is a short-lived DB admission handle, NOT a witness.
        return Object.freeze({ admissionTicket: ticket,
          witnessVerified: false, clientAckAuthorized: false });
      } catch { throw fail(); } finally {
        let readerRollbackFailed = false;
        let issuerRollbackFailed = false;
        if (snapshot && reader) {
          try { await reader.query("ROLLBACK"); }
          catch { readerRollbackFailed = true; }
        }
        if (issuing && issuer) {
          try { await issuer.query("ROLLBACK"); }
          catch { issuerRollbackFailed = true; }
        }
        // A timed-out or unsuccessfully rolled-back connection has uncertain
        // session state; ask node-postgres to DESTROY it instead of pooling it.
        try { reader?.release?.(isCancelled() || readerRollbackFailed ? fail() : undefined); }
        catch { /* original denial is authoritative */ }
        try { issuer?.release?.(isCancelled() || issuerRollbackFailed ? fail() : undefined); }
        catch { /* original denial is authoritative */ }
      }
  }
  return Object.freeze({
    async issueTicket(input) {
      if (pendingOperations.size >= 8) throw fail();
      let cancelled = false;
      const assertLive = () => { if (cancelled) throw fail(); };
      const operation = Promise.resolve().then(() =>
        executeTicket(input, assertLive, () => cancelled));
      pendingOperations.add(operation);
      const settle = () => { pendingOperations.delete(operation); };
      operation.then(settle, settle);
      let timer;
      try {
        return await Promise.race([operation, new Promise((_, reject) => {
          timer = setTimeout(() => { cancelled = true; reject(fail()); },
            operationTimeoutMs);
        })]);
      } catch { throw fail(); } finally { clearTimeout(timer); }
    },
  });
}

module.exports = { createZk1SyncPgIndependentAdmissionIssuer };
