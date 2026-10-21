"use strict";

// Experimental issue #65 anti-replay persistence primitive; NOT an approval
// authorizer or release gate. A separate trusted actor must verify the signed
// owner/device/witness transcript and gate before invoking this lab component.
// PostgreSQL role + pool are pre-provisioned out-of-band for disposable tests.
const crypto = require("node:crypto");
// A matching prototype is not proof of a real SQL-backed ledger. Keep the
// instance and its original pool binding inside this module's private custody.
const mintedLedgers = new WeakSet();
const mintedPools = new WeakMap();

function deny() {
  const e = new Error("ZK_APPROVAL_REPLAY_LAB_DENIED");
  e.code = e.message;
  throw e;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) deny();
}
function bytes(value, length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength !== length) deny();
  return Buffer.from(value);
}
function integer(value) {
  if (!Number.isSafeInteger(value) || value < 1) deny();
  return value;
}
function normalize(input) {
  exact(input, ["scope", "nonce", "rawSignedApproval", "deviceKeyId",
    "manifestRevision", "manifestDigest", "witnessSequence", "expiresAt"]);
  exact(input.scope, ["account_id", "compartment_id", "keyring_id"]);
  const accountId = bytes(input.scope.account_id, 16);
  const compartmentId = input.scope.compartment_id;
  if ((!Buffer.isBuffer(compartmentId) && !(compartmentId instanceof Uint8Array))
    || compartmentId.byteLength < 1 || compartmentId.byteLength > 128) deny();
  const compartment = Buffer.from(compartmentId);
  const raw = input.rawSignedApproval;
  if ((!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array))
    || raw.byteLength < 100 || raw.byteLength > 4096) deny();
  return {
    scopeKey: accountId.toString("hex") + ":" + compartment.length.toString(16)
      + ":" + compartment.toString("hex"),
    nonce: bytes(input.nonce, 32),
    keyringId: bytes(input.scope.keyring_id, 16),
    approvalDigest: crypto.createHash("sha256").update(Buffer.from(raw)).digest(),
    deviceKeyId: bytes(input.deviceKeyId, 16),
    manifestRevision: integer(input.manifestRevision),
    manifestDigest: bytes(input.manifestDigest, 32),
    witnessSequence: integer(input.witnessSequence),
    expiresAt: integer(input.expiresAt),
  };
}

async function verifyDisposableReplayWriterClient(client) {
  if (!client || typeof client.query !== "function") deny();
  try {
    const { rows, rowCount } = await client.query(`SELECT
      session_user AS session_identity, current_user AS active_identity,
      r.rolcanlogin AS can_login,r.rolsuper AS superuser,
      r.rolcreaterole AS create_role,r.rolcreatedb AS create_db,
      pg_catalog.pg_has_role(current_user,'zk1_approval_replay_writer','USAGE') AS writer,
      pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','MEMBER') AS gate_member,
      pg_catalog.pg_has_role(current_user,'zk1_stop_runtime','MEMBER') AS stop_member,
      pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','SET') AS gate_set,
      pg_catalog.pg_has_role(current_user,'zk1_stop_runtime','SET') AS stop_set,
      pg_catalog.has_schema_privilege(current_user,'zk1_approval_replay_lab','USAGE') AS schema_read,
      pg_catalog.has_schema_privilege(current_user,'zk1_approval_replay_lab','CREATE') AS schema_write,
      pg_catalog.has_table_privilege(current_user,'zk1_approval_replay_lab.consumed','SELECT') AS read_ledger,
      pg_catalog.has_table_privilege(current_user,'zk1_approval_replay_lab.consumed','UPDATE') AS edit_ledger,
      pg_catalog.has_table_privilege(current_user,'zk1_approval_replay_lab.consumed','DELETE') AS delete_ledger,
      pg_catalog.has_table_privilege(current_user,'zk1_approval_replay_lab.consumed','TRUNCATE') AS truncate_ledger,
      pg_catalog.has_any_column_privilege(current_user,'zk1_approval_replay_lab.consumed','SELECT') AS read_any_column,
      pg_catalog.has_any_column_privilege(current_user,'zk1_approval_replay_lab.consumed','UPDATE') AS edit_any_column,
      pg_catalog.has_any_column_privilege(current_user,'zk1_approval_replay_lab.consumed','REFERENCES') AS reference_any_column,
      pg_catalog.has_column_privilege(current_user,'zk1_approval_replay_lab.consumed','nonce','INSERT') AS insert_nonce
    FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
    const x = rows[0];
    if (rowCount !== 1 || !x || x.active_identity !== x.session_identity
      || !/^zkreplayfixture_[a-f0-9]{12}$/.test(x.active_identity)
      || x.can_login !== true || x.superuser !== false
      || x.create_role !== false || x.create_db !== false
      || x.writer !== true || x.gate_member !== false || x.stop_member !== false
      || x.gate_set !== false || x.stop_set !== false
      || x.schema_read !== true || x.schema_write !== false
      || x.read_ledger !== false || x.edit_ledger !== false
      || x.delete_ledger !== false || x.truncate_ledger !== false
      || x.read_any_column !== false || x.edit_any_column !== false
      || x.reference_any_column !== false
      || x.insert_nonce !== true) deny();
    return Object.freeze({ verified: true, labOnly: true });
  } catch (_) { deny(); }
}
async function verifyDisposableReplayWriterPool(pool) {
  if (!pool || typeof pool.connect !== "function") deny();
  let client;
  try {
    client = await pool.connect();
    return await verifyDisposableReplayWriterClient(client);
  } catch (_) { deny(); }
  finally { if (client) client.release(); }
}

class Zk1ExperimentalPgApprovalReplayLedger {
  constructor({ pool } = {}) {
    if (!pool || typeof pool.connect !== "function") deny();
    mintedLedgers.add(this);
    mintedPools.set(this, pool);
  }

  async consumeCandidate(input) {
    if (!mintedLedgers.has(this)) deny();
    // Snapshot all caller-owned bytes before the first network await.
    const record = normalize(input);
    let client;
    let inTransaction = false;
    let failed = true;
    try {
      client = await mintedPools.get(this).connect();
      // Cannot run inside an inherited transaction. DISCARD ALL succeeds only
      // in idle sessions and rejects a client still in someone else's BEGIN.
      // Do not silently COMMIT or ROLLBACK another borrower's pending work.
      await client.query("DISCARD ALL");
      // Important: attest the SAME physical SQL connection used to insert;
      // a mixed/poisoned Pool cannot swap in an admin connection afterwards.
      await verifyDisposableReplayWriterClient(client);
      await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
      inTransaction = true;
      // PostgreSQL clock is checked IN the same physical SQL effect. No
      // client-supplied current time or expiry-based tombstone reclamation.
      const result = await client.query(`INSERT INTO zk1_approval_replay_lab.consumed
        (scope_key,nonce,keyring_id,approval_digest,device_key_id,
          manifest_digest,manifest_revision,witness_sequence,expires_at)
        SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9::bigint
        WHERE $9::bigint > floor(extract(epoch from clock_timestamp()))
          AND $9::bigint <= floor(extract(epoch from clock_timestamp()))+300`,
      [record.scopeKey, record.nonce, record.keyringId, record.approvalDigest,
        record.deviceKeyId, record.manifestDigest, record.manifestRevision,
        record.witnessSequence, record.expiresAt]);
      if (result.rowCount !== 1) deny();
      await client.query("COMMIT");
      inTransaction = false;
      failed = false;
      return Object.freeze({ replayRecordCommitted: true,
        cryptographicApprovalVerified: false, liveAuthorityVerified: false,
        authorizesRelease: false, protectedIoAdmission: false });
    } catch (_) {
      // COMMIT may have succeeded even if its reply was lost. Any uncertainty
      // is denial; a later identical nonce will not be accepted twice.
      if (inTransaction && client) {
        try { await client.query("ROLLBACK"); } catch (_) { /* fail closed */ }
      }
      deny();
    } finally { if (client) client.release(failed); }
  }
}

// Never trust an injected instance's method property, even when instanceof
// succeeds. The only acceptable implementation is this module's native
// consumeCandidate with its privately captured PostgreSQL pool.
const authenticConsumeCandidate = Zk1ExperimentalPgApprovalReplayLedger.prototype.consumeCandidate;
function consumeAuthenticExperimentalReplayCandidate(ledger, input) {
  if (!mintedLedgers.has(ledger)
    || Object.getPrototypeOf(ledger) !== Zk1ExperimentalPgApprovalReplayLedger.prototype
    || Object.hasOwn(ledger, "consumeCandidate")
    || Zk1ExperimentalPgApprovalReplayLedger.prototype.consumeCandidate !== authenticConsumeCandidate) deny();
  return authenticConsumeCandidate.call(ledger, input);
}

module.exports = { Zk1ExperimentalPgApprovalReplayLedger,
  verifyDisposableReplayWriterPool, consumeAuthenticExperimentalReplayCandidate };
