"use strict";

// Isolated opt-in v2 authority protocol, deliberately NOT wired to the v1
// catalog or browser. Two physically separate SQLite databases / Ed25519 keys.
// Ordered floor PREPARE -> CAS COMMIT -> floor FINALIZE -> CAS ACK/readback.
// Partial inter-authority commits are fenced as PENDING until reconciliation;
// no claim of a distributed atomic disk transaction or remote/cloud durability.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const tls = require("node:tls");
const net = require("node:net");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const archiveV2 = require("../crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const { isZk1OpaqueCatalogIndependentFloorClient } =
  require("./zk1OpaqueCatalogIndependentFloor");
const { isZk1OpaqueCatalogCasHttpsClient } =
  require("./zk1OpaqueCatalogCasHttpsClient");
const { Zk1V2CheckpointFloorHttpsClient } =
  require("./zk1V2CheckpointFloorHttps");
const { catalogCasDomain } = require("./zk1OpaqueCatalog");
const ownerHistory = require("../crypto/rootark-zk-recovery-history-v2");
const ownerManifest = require("../crypto/rootark-zk-recovery-manifest-v2");
const { inspectVerifiedWitnessFreshHeadV1 } =
  require("../crypto/rootark-zk-witness-head-wire-v1");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteAuthorityDirectory } =
  require("./zk1PrivateSqlitePath");
const { nativeEd25519Spki } =
  require("../crypto/rootark-zk1-native-ed25519-public-key");
const { assertSafeSqliteSidecars, requireCheckpointV2Triggers,
  withReadonlySqliteSnapshot } =
  require("./zk1OpaqueCheckpointV2SqliteGuard");

const PREFIX = "Root.ark/zk-1/opaque-checkpoint-remote/";
const INTENT_DOMAIN = Buffer.from(PREFIX + "intent/v2\0");
const APPROVAL_DOMAIN = Buffer.from(PREFIX + "owner-approval/v2\0");
const RECEIPT_DOMAIN = Buffer.from(PREFIX + "receipt/v2\0");
const LEGACY_MIGRATION_DOMAIN = Buffer.from(
  "Root.ark/zk-1/opaque-checkpoint-v2-legacy-archive-migration/v1\0");
const LEGACY_READBACK_DOMAIN = Buffer.from(
  "Root.ark/zk-1/opaque-checkpoint-v2-legacy-archive-readback/v1\0");
const ROLE_CAS = "CAS";
const ROLE_FLOOR = "FLOOR";
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const LEGACY_MIGRATION_FIELDS = ["type", ...SCOPE, "legacy_base_digest",
  "legacy_base_checkpoint", "legacy_sequence", "legacy_head_digest",
  "legacy_checkpoint_digest", "legacy_operation_id", "full_archive_root",
  "full_archive_checkpoint", "cas_signer_fp", "floor_signer_fp",
  "owner_revision", "owner_digest", "owner_epoch", "nonce",
  "issued_at", "expires_at"];
const LEGACY_READBACK_FIELDS = ["type", ...SCOPE, "role", "state",
  "legacy_base_digest", "legacy_base_checkpoint", "legacy_sequence",
  "legacy_head_digest", "legacy_checkpoint_digest", "legacy_operation_id",
  "full_archive_root", "full_archive_checkpoint", "cas_signer_fp",
  "floor_signer_fp", "owner_consent_hash", "terminal_receipt", "nonce",
  "issued_at"];
const INTENT_FIELDS = ["type", ...SCOPE, "operation_id", "checkpoint_bytes",
  "checkpoint_signature", "records", "previous_sequence",
  "previous_digest", "previous_checkpoint_digest", "owner_approval",
  "owner_signature", "owner_evidence"];
const PREDECESSOR_FIELDS = ["predecessor_cas_receipt", "predecessor_floor_receipt"];
const APPROVAL_FIELDS = ["type", ...SCOPE, "operation_id", "checkpoint_digest",
  "previous_sequence", "previous_digest", "previous_checkpoint_digest",
  "final_sequence", "final_digest", "cas_signer_fp", "floor_signer_fp",
  "checkpoint_signer_fp", "issued_at"];
const RECEIPT_FIELDS = ["type", ...SCOPE, "role", "state", "sequence", "head_digest",
  "checkpoint_digest", "operation_id", "cas_signer_fp", "floor_signer_fp",
  "nonce", "issued_at"];
const OWNER_EVIDENCE = ["baseManifest", "baseReceipt", "transitions",
  "packageEnvelopes", "witnessHeadRaw"];
const HEAD_FIELDS = ["type", ...SCOPE, "sequence", "previous_digest",
  "manifest_revision", "manifest_digest", "epoch", "signer_device_id",
  "total_count", "page_digests", "issued_at"];
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_WIRE = 10 * 1024 * 1024;
const MAX_OWNER = 2 * 1024 * 1024;
const CERT_PIN = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i;
const ZERO = Buffer.alloc(32);
const MAX_V2_SEQUENCE = 1000000;
const MAX_LEGACY_READBACK_TRANSITIONS = 1024;
// A coordinator must never accept caller-supplied stand-ins whose head()
// advertises FINALIZED without independently verifying a remote receipt.
const pinnedV2Clients = new WeakSet();
const domain = (part) => Buffer.from(PREFIX + part + "/v2\0");
const AUTHORITY_SCHEMA = `
        CREATE TABLE IF NOT EXISTS config(
          marker INTEGER PRIMARY KEY CHECK(marker=1), role TEXT NOT NULL,
          scope TEXT NOT NULL, pins BLOB NOT NULL, base_digest BLOB NOT NULL,
          base_checkpoint BLOB NOT NULL, genesis_digest BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transitions(
          sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 129 AND 1000000),
          intent_hash BLOB NOT NULL, operation_id BLOB NOT NULL UNIQUE,
          checkpoint_digest BLOB NOT NULL UNIQUE, final_digest BLOB NOT NULL,
          intent BLOB NOT NULL, signer_spki BLOB NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('PREPARED','CAS_COMMITTED','FINALIZED')),
          floor_prepare BLOB, cas_commit BLOB, floor_finalize BLOB,
          CHECK (
            (state='PREPARED' AND floor_prepare IS NULL
              AND cas_commit IS NULL AND floor_finalize IS NULL)
            OR (state='CAS_COMMITTED' AND floor_prepare IS NOT NULL
              AND cas_commit IS NULL AND floor_finalize IS NULL)
            OR (state='FINALIZED' AND (
              (cas_commit IS NOT NULL AND floor_prepare IS NULL
                AND floor_finalize IS NULL)
              OR (floor_finalize IS NOT NULL AND floor_prepare IS NOT NULL
                AND cas_commit IS NULL)))
          )
        );
        CREATE TRIGGER IF NOT EXISTS no_config_change
          BEFORE UPDATE ON config BEGIN SELECT RAISE(ABORT,'CONFIG_LOCKED'); END;
        CREATE TRIGGER IF NOT EXISTS no_config_delete
          BEFORE DELETE ON config BEGIN SELECT RAISE(ABORT,'CONFIG_LOCKED'); END;
        CREATE TRIGGER IF NOT EXISTS no_transition_delete
          BEFORE DELETE ON transitions BEGIN SELECT RAISE(ABORT,'TRANSITION_LOCKED'); END;
        CREATE TRIGGER IF NOT EXISTS no_transition_gap
          BEFORE INSERT ON transitions WHEN
            NEW.sequence!=(SELECT COALESCE(MAX(sequence),128)+1 FROM transitions)
            OR EXISTS(SELECT 1 FROM transitions WHERE state!='FINALIZED')
          BEGIN SELECT RAISE(ABORT,'MONOTONIC_CHECKPOINT'); END;
        CREATE TRIGGER IF NOT EXISTS no_transition_replace
          BEFORE UPDATE ON transitions WHEN
            OLD.sequence!=NEW.sequence OR OLD.intent_hash!=NEW.intent_hash
            OR OLD.operation_id!=NEW.operation_id
            OR OLD.checkpoint_digest!=NEW.checkpoint_digest
            OR OLD.final_digest!=NEW.final_digest
            OR OLD.intent!=NEW.intent OR OLD.signer_spki!=NEW.signer_spki
          BEGIN SELECT RAISE(ABORT,'TRANSITION_LOCKED'); END;
        CREATE TRIGGER IF NOT EXISTS no_transition_downgrade
          BEFORE UPDATE ON transitions WHEN
            OLD.state='FINALIZED' OR NEW.state!='FINALIZED'
            OR ((SELECT role FROM config WHERE marker=1)='FLOOR'
              AND (OLD.state!='PREPARED'
                OR OLD.cas_commit IS NOT NULL OR NEW.cas_commit IS NULL
                OR OLD.floor_prepare IS NOT NEW.floor_prepare
                OR OLD.floor_finalize IS NOT NEW.floor_finalize))
            OR ((SELECT role FROM config WHERE marker=1)='CAS'
              AND (OLD.state!='CAS_COMMITTED'
                OR OLD.floor_finalize IS NOT NULL OR NEW.floor_finalize IS NULL
                OR OLD.floor_prepare IS NOT NEW.floor_prepare
                OR OLD.cas_commit IS NOT NEW.cas_commit))
          BEGIN SELECT RAISE(ABORT,'MONOTONIC_CHECKPOINT'); END;
      `;
const AUTHORITY_TRIGGERS = [
  ["no_config_change", "config"], ["no_config_delete", "config"],
  ["no_transition_delete", "transitions"],
  ["no_transition_gap", "transitions"],
  ["no_transition_replace", "transitions"],
  ["no_transition_downgrade", "transitions"],
];
// Additive guard for strict, owner-approved FULL 128-head rollovers. Its
// immutable local pin survives process restart; an expired owner handoff can
// be renewed but a strict authority cannot be reopened in legacy write mode.
const STRICT_ROLLOVER_SCHEMA = `CREATE TABLE strict_rollover (
    id INTEGER PRIMARY KEY CHECK(id=1),
    archive_root BLOB NOT NULL CHECK(length(archive_root)=32),
    archive_checkpoint BLOB NOT NULL CHECK(length(archive_checkpoint)=32));
  CREATE TRIGGER strict_rollover_immutable_update BEFORE UPDATE ON strict_rollover
    BEGIN SELECT RAISE(ABORT,'STRICT_ROLLOVER_LOCKED'); END;
  CREATE TRIGGER strict_rollover_immutable_delete BEFORE DELETE ON strict_rollover
    BEGIN SELECT RAISE(ABORT,'STRICT_ROLLOVER_LOCKED'); END;`;
// One-way, local PHASE-1 migration barrier. This does NOT reanchor old signed
// 129+ receipts or authorize any new writes. In particular the FULL archive
// checkpoint is deliberately distinct from immutable config.base_checkpoint.
const LEGACY_MIGRATION_STAGE_SCHEMA = `CREATE TABLE legacy_archive_migration_stage (
    id INTEGER PRIMARY KEY CHECK(id=1),
    legacy_sequence INTEGER NOT NULL CHECK(legacy_sequence BETWEEN 128 AND 1000000),
    legacy_head_digest BLOB NOT NULL CHECK(length(legacy_head_digest)=32),
    legacy_checkpoint_digest BLOB NOT NULL CHECK(length(legacy_checkpoint_digest)=32),
    legacy_operation_id BLOB NOT NULL CHECK(length(legacy_operation_id)=32),
    full_archive_root BLOB NOT NULL CHECK(length(full_archive_root)=32),
    full_archive_checkpoint BLOB NOT NULL CHECK(length(full_archive_checkpoint)=32),
    owner_consent BLOB NOT NULL,
    owner_signature BLOB NOT NULL CHECK(length(owner_signature)=64));
  CREATE TRIGGER legacy_archive_stage_immutable_update
    BEFORE UPDATE ON legacy_archive_migration_stage
    BEGIN SELECT RAISE(ABORT,'LEGACY_MIGRATION_LOCKED'); END;
  CREATE TRIGGER legacy_archive_stage_immutable_delete
    BEFORE DELETE ON legacy_archive_migration_stage
    BEGIN SELECT RAISE(ABORT,'LEGACY_MIGRATION_LOCKED'); END;
  CREATE TRIGGER legacy_archive_stage_block_transition_insert
    BEFORE INSERT ON transitions
    BEGIN SELECT RAISE(ABORT,'LEGACY_MIGRATION_PENDING'); END;
  CREATE TRIGGER legacy_archive_stage_block_transition_update
    BEFORE UPDATE ON transitions
    BEGIN SELECT RAISE(ABORT,'LEGACY_MIGRATION_PENDING'); END;`;

function fail(code = "ZK_CHECKPOINT_V2_UNAVAILABLE") {
  const error = new Error(code); error.code = code; throw error;
}
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![null, Object.prototype].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) fail();
  return value;
}
function bytes(value, low, high = low) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < low || value.byteLength > high) fail();
  return Buffer.from(value);
}
function num(value, min, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail();
  return value;
}
function same(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function canonical32(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) fail();
  const valueBytes = Buffer.from(value, "base64url");
  if (valueBytes.length !== 32 || valueBytes.toString("base64url") !== value) fail();
  return valueBytes;
}
function hash(...parts) {
  const h = crypto.createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
}
function key(value, role = "public") {
  if (!(value instanceof crypto.KeyObject) || value.type !== role
    || value.asymmetricKeyType !== "ed25519") fail();
  return value;
}
function fp(value) {
  return hash(nativeEd25519Spki(key(value)));
}
function scopeOf(value) {
  exact(value, SCOPE);
  return Object.fromEntries(SCOPE.map((field) => [field,
    bytes(value[field], field === "compartment_id" ? 1 : 16,
      field === "compartment_id" ? 128 : 16)]));
}
function matchesScope(value, scope) {
  for (const field of SCOPE) if (!same(bytes(value[field],
    field === "compartment_id" ? 1 : 16,
    field === "compartment_id" ? 128 : 16), scope[field])) fail();
}
function fileSecurity(filename, bootstrapNew) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) fail();
  const parent = fs.lstatSync(path.dirname(filename));
  if (!parent.isDirectory() || parent.isSymbolicLink()
    || (process.platform !== "win32"
      && (parent.uid !== process.getuid() || parent.mode & 0o077))) fail();
  const exists = fs.existsSync(filename);
  if (exists === bootstrapNew) fail();
  if (exists) {
    const st = fs.lstatSync(filename);
    if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1
      || (process.platform !== "win32"
        && (st.uid !== process.getuid() || st.mode & 0o077))) fail();
  } else {
    const fd = fs.openSync(filename, fs.constants.O_EXCL | fs.constants.O_CREAT
      | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
    try {
      // Pin the inode created by O_EXCL before closing its descriptor. A
      // single-link foreign SQLite can be renamed onto this pathname after
      // close and would otherwise be trusted by the next pathname stat.
      const st = fs.fstatSync(fd, { bigint: true });
      if (!st.isFile() || st.nlink !== 1n) fail();
      return Object.freeze({ dev: st.dev, ino: st.ino });
    } finally { fs.closeSync(fd); }
  }
}
function verifyAuthorityIdentity(db, { role, scopeText, allPins, v1Digest,
  v1Checkpoint, genesisDigest }) {
  requireCheckpointV2Triggers(db, AUTHORITY_SCHEMA, AUTHORITY_TRIGGERS, fail);
  const conf = db.prepare("SELECT * FROM config").all();
  if (conf.length !== 1 || conf[0].role !== role
    || conf[0].scope !== scopeText
    || !Buffer.isBuffer(conf[0].pins) || !same(conf[0].pins, allPins)
    || !Buffer.isBuffer(conf[0].base_digest) || !same(conf[0].base_digest, v1Digest)
    || !Buffer.isBuffer(conf[0].base_checkpoint)
    || !same(conf[0].base_checkpoint, v1Checkpoint)
    || !Buffer.isBuffer(conf[0].genesis_digest)
    || !same(conf[0].genesis_digest, genesisDigest)) fail();
}
function receiptMatches(raw, { scope, role, state, sequence, headDigest,
  checkpointDigest, operationId, casFp, floorFp, signer, nonce, fresh }) {
  return (async () => {
    const data = await z.decodeDeterministic(bytes(raw, 1, 4096));
    exact(data, [...RECEIPT_FIELDS, "signature"]);
    const { signature, ...statement } = data;
    exact(statement, RECEIPT_FIELDS);
    if (statement.type !== "rootark-opaque-checkpoint-remote-receipt/v2"
      || statement.role !== role || (state && statement.state !== state)
      || statement.sequence !== sequence
      || !same(bytes(statement.head_digest, 32), headDigest)
      || !same(bytes(statement.checkpoint_digest, 32), checkpointDigest)
      || !same(bytes(statement.operation_id, 32), operationId)
      || !same(bytes(statement.cas_signer_fp, 32), casFp)
      || !same(bytes(statement.floor_signer_fp, 32), floorFp)
      || (nonce && !same(bytes(statement.nonce, 32), nonce))) fail();
    matchesScope(statement, scope);
    num(statement.issued_at, 0);
    if (fresh && Math.abs(Date.now() / 1000 - statement.issued_at) > 30) fail();
    if (!crypto.verify(null, Buffer.concat([RECEIPT_DOMAIN,
      Buffer.from(await z.encodeDeterministic(statement))]),
    key(signer), bytes(signature, 64))) fail();
    return { ...statement, raw: Buffer.from(raw) };
  })();
}
async function inspectLegacyArchiveReadback(raw, { scope, signer, role, casFp,
  floorFp, nonce }) {
  const signed = await z.decodeDeterministic(bytes(raw, 1, 8192));
  exact(signed, [...LEGACY_READBACK_FIELDS, "signature"]);
  const { signature, ...body } = signed;
  exact(body, LEGACY_READBACK_FIELDS);
  matchesScope(body, scope);
  if (body.type !== "rootark-opaque-checkpoint-v2-legacy-archive-readback/v1"
    || body.role !== role || body.state !== "STAGED_READ_ONLY"
    || !same(bytes(body.cas_signer_fp, 32), casFp)
    || !same(bytes(body.floor_signer_fp, 32), floorFp)
    || !same(bytes(body.nonce, 32), nonce)
    || Math.abs(Math.floor(Date.now() / 1000) - num(body.issued_at, 0)) > 30
    || !crypto.verify(null, Buffer.concat([LEGACY_READBACK_DOMAIN,
      Buffer.from(await z.encodeDeterministic(body))]),
    key(signer), bytes(signature, 64))) fail();
  for (const name of ["legacy_base_digest", "legacy_base_checkpoint",
    "legacy_head_digest", "legacy_checkpoint_digest",
    "legacy_operation_id", "full_archive_root", "full_archive_checkpoint",
    "owner_consent_hash"]) bytes(body[name], 32);
  const sequence = num(body.legacy_sequence, 128, MAX_V2_SEQUENCE);
  const state = sequence === 128 ? "V1_BASELINE" : "FINALIZED";
  await receiptMatches(body.terminal_receipt, { scope, role, state,
    sequence, headDigest: body.legacy_head_digest,
    checkpointDigest: body.legacy_checkpoint_digest,
    operationId: body.legacy_operation_id, casFp, floorFp, signer,
    nonce, fresh: true });
  return { ...body, raw: Buffer.from(raw) };
}

async function signCheckpointOwnerApprovalV2(statement, privateKey) {
  exact(statement, APPROVAL_FIELDS);
  const { type, ...rest } = statement;
  if (type !== "rootark-opaque-checkpoint-remote-owner-approval/v2") fail();
  scopeOf(Object.fromEntries(SCOPE.map((name) => [name, statement[name]])));
  num(rest.previous_sequence, 128, MAX_V2_SEQUENCE - 1);
  if (rest.final_sequence !== rest.previous_sequence + 1) fail();
  for (const field of ["operation_id", "checkpoint_digest", "previous_digest",
    "previous_checkpoint_digest", "final_digest", "cas_signer_fp",
    "floor_signer_fp", "checkpoint_signer_fp"]) bytes(rest[field], 32);
  num(statement.issued_at, 0);
  const raw = Buffer.from(await z.encodeDeterministic(statement));
  return { raw, signature: crypto.sign(null, Buffer.concat([APPROVAL_DOMAIN, raw]),
    key(privateKey, "private")) };
}

async function verifyOwnerRooted(intent, opts, { historical = false } = {}) {
  const approval = await z.decodeDeterministic(bytes(intent.owner_approval, 1, 4096));
  exact(approval, APPROVAL_FIELDS);
  if (approval.type !== "rootark-opaque-checkpoint-remote-owner-approval/v2") fail();
  matchesScope(approval, opts.scope);
  if (approval.previous_sequence !== intent.previous_sequence
    || approval.final_sequence !== intent.previous_sequence + 1
    || !same(bytes(approval.operation_id, 32), intent.operation_id)
    || !same(bytes(approval.previous_digest, 32), intent.previous_digest)
    || !same(bytes(approval.previous_checkpoint_digest, 32), intent.previous_checkpoint_digest)
    || !same(bytes(approval.checkpoint_digest, 32), opts.checkpointDigest)
    || !same(bytes(approval.final_digest, 32), opts.finalDigest)
    || !same(bytes(approval.cas_signer_fp, 32), opts.casFp)
    || !same(bytes(approval.floor_signer_fp, 32), opts.floorFp)
    || !same(bytes(approval.checkpoint_signer_fp, 32), opts.checkpointFp)
    || (!historical && Math.abs(Date.now() / 1000 - num(approval.issued_at, 0)) > 300)) fail();
  num(approval.issued_at, 0);
  const evidence = await z.decodeDeterministic(bytes(intent.owner_evidence, 1, MAX_OWNER));
  exact(evidence, OWNER_EVIDENCE);
  if (!Array.isArray(evidence.transitions) || !Array.isArray(evidence.packageEnvelopes)) fail();
  const trust = opts.ownerTrust;
  const verified = await ownerHistory.verifyRecoveryHistoryPublicV2({
    expectedScope: opts.scope, baseManifest: evidence.baseManifest,
    baseReceipt: evidence.baseReceipt, transitions: evidence.transitions,
    packageEnvelopes: evidence.packageEnvelopes, pinnedWitness: trust.pinnedWitness,
    now: Math.floor(Date.now() / 1000),
  });
  if (!await ownerHistory.isVerifiedPublicRecoveryHistoryV2(verified)
    || !same(Buffer.from(await ownerManifest.recoveryManifestDigestV2(verified.baseManifest)),
      trust.genesisDigest)) fail();
  const challenge = bytes((await z.decodeDeterministic(evidence.witnessHeadRaw)).nonce, 32);
  const seenWitness = await inspectVerifiedWitnessFreshHeadV1({
    raw: bytes(evidence.witnessHeadRaw, 1, 8192), nonce: challenge,
    scope: opts.scope, pinned: trust.pinnedWitness, minimumHead: trust.minimumHead,
  });
  // The signed, independently pinned witness is the authority for which owner
  // epoch was current when this exact immutable intent was approved. Replays
  // cannot choose a newer epoch or manufacture enrollment/revocation facts.
  const recorded = await z.decodeDeterministic(evidence.witnessHeadRaw);
  if (!seenWitness || Number(recorded.current_revision) !== Number(verified.revision)
    || !same(bytes(recorded.current_manifest_digest, 32), verified.headDigest)
    || Math.abs(Number(recorded.observed_at) - approval.issued_at) > 300) fail();
  if (!historical) {
    const liveNonce = crypto.randomBytes(32);
    const liveRaw = bytes(await trust.freshWitnessHead({ nonce: liveNonce,
      scope: opts.scope }), 1, 8192);
    await inspectVerifiedWitnessFreshHeadV1({
      raw: liveRaw, nonce: liveNonce, scope: opts.scope,
      pinned: trust.pinnedWitness, minimumHead: trust.minimumHead,
    });
    const live = await z.decodeDeterministic(liveRaw);
    if (Math.abs(Date.now() / 1000 - live.observed_at) > 30
      || Number(live.current_revision) !== Number(verified.revision)
      || !same(bytes(live.current_manifest_digest, 32), verified.headDigest)) fail();
  }
  // Never accept an owner key advertised by the intent. Independently verify
  // the owner recovery chain and select only an active enrolled signer whose
  // Ed25519 signature authenticates this exact owner approval at its epoch.
  const approvalMessage = Buffer.concat([APPROVAL_DOMAIN, intent.owner_approval]);
  const approvalSignature = bytes(intent.owner_signature, 64);
  const matchingOwnerKeys = verified.headManifest.devices.filter((device) => {
    if (device.revoked_at_epoch !== null
      || Number(device.enrolled_epoch) > Number(verified.headManifest.current_epoch))
      return false;
    const signer = crypto.createPublicKey({ key: Buffer.concat([
      SPKI_PREFIX, bytes(device.authorization_public_key, 32)]),
    format: "der", type: "spki" });
    return crypto.verify(null, approvalMessage, signer, approvalSignature);
  });
  if (matchingOwnerKeys.length !== 1) fail();
  const header = await z.decodeDeterministic(bytes(intent.records[0].header, 1, 16384));
  exact(header, HEAD_FIELDS);
  if (header.manifest_revision !== Number(verified.revision)
    || header.epoch !== Number(verified.headManifest.current_epoch)
    || !same(bytes(header.manifest_digest, 32), verified.headDigest)) fail();
  const authorized = verified.headManifest.devices.find((device) =>
    device.device_id === header.signer_device_id
    && device.revoked_at_epoch === null
    && Number(device.enrolled_epoch) <= Number(header.epoch));
  if (!authorized) fail();
  const signer = crypto.createPublicKey({ key: Buffer.concat([
    SPKI_PREFIX, bytes(authorized.authorization_public_key, 32)]),
  format: "der", type: "spki" });
  return { signer, proof: verified, ownerApprovalSigner: crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX,
      bytes(matchingOwnerKeys[0].authorization_public_key, 32)]),
    format: "der", type: "spki" }) };
}

async function inspectIntent(raw, opts, { freshOwner = true, historicalOwner = false } = {}) {
  const body = await z.decodeDeterministic(bytes(raw, 1, MAX_WIRE));
  const previousSequence = num(body.previous_sequence, 128, MAX_V2_SEQUENCE - 1);
  exact(body, previousSequence === 128 ? INTENT_FIELDS
    : [...INTENT_FIELDS, ...PREDECESSOR_FIELDS]);
  if (body.type !== "rootark-opaque-checkpoint-remote-intent/v2") fail();
  matchesScope(body, opts.scope);
  bytes(body.operation_id, 32);
  if (!Array.isArray(body.records) || body.records.length !== 1
    || body.records[0].sequence !== body.previous_sequence + 1) fail();
  if (!same(bytes(body.previous_digest, 32), opts.baseDigest)
    || !same(bytes(body.previous_checkpoint_digest, 32), opts.baseCheckpoint)) fail();
  if (previousSequence > 128) {
    const predecessorOperation = bytes(opts.previousOperationId, 32);
    for (const [field, role, signer] of [
      [PREDECESSOR_FIELDS[0], ROLE_CAS, opts.casKey],
      [PREDECESSOR_FIELDS[1], ROLE_FLOOR, opts.floorKey],
    ]) {
      const signed = bytes(body[field], 1, 4096);
      const data = await z.decodeDeterministic(signed);
      await receiptMatches(signed, { scope: opts.scope, role, state: "FINALIZED",
        sequence: previousSequence, headDigest: opts.baseDigest,
        checkpointDigest: opts.baseCheckpoint, operationId: predecessorOperation,
        casFp: opts.casFp, floorFp: opts.floorFp, signer,
        nonce: bytes(data.nonce, 32), fresh: false });
    }
  }
  // Verify pinned owner root/witness *before* resolving historical signers.
  const checkpointDigest = hash(Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-digest/v2\0"),
    bytes(body.checkpoint_bytes, 1, 16384), bytes(body.checkpoint_signature, 64));
  const parsedHeader = await z.decodeDeterministic(body.records[0].header);
  const finalDigest = hash(Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0"),
    body.records[0].header, body.records[0].signature);
  let signer;
  let ownerApprovalSigner = null;
  if (freshOwner || historicalOwner) {
    const trusted = await verifyOwnerRooted(body, { ...opts,
      checkpointDigest, finalDigest }, { historical: !freshOwner });
    signer = trusted.signer;
    // Independent owner-history + witness evidence determines the signer.
    // A cached SQLite key can only corroborate that independent identity;
    // offline historical issuers need no cache and must not trust a supplied key.
    if (historicalOwner && opts.cachedSigner !== undefined
      && !crypto.KeyObject.prototype.equals.call(signer,
        key(opts.cachedSigner))) fail();
    ownerApprovalSigner = trusted.ownerApprovalSigner;
  } else signer = key(opts.cachedSigner); // caller may only use for exact immutable reread
  const verified = await archiveV2.verifyAuthenticatedOpaqueCatalogArchiveV2({
    checkpointBytes: body.checkpoint_bytes,
    checkpointSignature: body.checkpoint_signature,
    pinnedCheckpointPublicKey: opts.checkpointKey, scope: opts.scope,
    records: body.records, previousSequence: body.previous_sequence,
    previousDigest: opts.baseDigest,
    previousCheckpointDigest: opts.baseCheckpoint,
    expectedFinalSequence: body.previous_sequence + 1, expectedFinalDigest: finalDigest,
    resolveCatalogSigner: async (header) => {
      if (header.signer_device_id !== parsedHeader.signer_device_id) fail();
      return signer;
    },
  });
  return { body, raw: Buffer.from(raw), intentHash: hash(INTENT_DOMAIN, raw),
    operationId: bytes(body.operation_id, 32), checkpointDigest, finalDigest,
    verified, signerSpki: nativeEd25519Spki(signer),
    ownerApprovalSignerSpki: ownerApprovalSigner
      ? nativeEd25519Spki(ownerApprovalSigner) : undefined };
}

class OpaqueCheckpointV2Authority {
  #settings;
  #db;
  #queue = Promise.resolve();
  #strictRollover = null;
  constructor(filename, { role, bootstrapNew, scope, signingPrivateKey,
    casSignerPublicKey, floorSignerPublicKey, checkpointPublicKey,
    ownerPublicKey, ownerTrust, baseDigest, baseCheckpoint,
    requireFullV1ArchiveRollover = false, fullV1ArchiveRollover }) {
    if (![ROLE_CAS, ROLE_FLOOR].includes(role) || typeof bootstrapNew !== "boolean"
      || !ownerTrust || typeof ownerTrust.freshWitnessHead !== "function") fail();
    const scoped = scopeOf(scope);
    const signer = key(signingPrivateKey, "private");
    const casKey = key(casSignerPublicKey);
    const floorKey = key(floorSignerPublicKey);
    const checkpointKey = key(checkpointPublicKey);
    const ownerKey = key(ownerPublicKey);
    const keys = [casKey, floorKey, checkpointKey, ownerKey];
    const pins = keys.map(fp);
    if (new Set(pins.map((item) => item.toString("hex"))).size !== 4
      || !same(fp(crypto.createPublicKey(signer)),
        role === ROLE_CAS ? pins[0] : pins[1])) fail();
    const v1Digest = bytes(baseDigest, 32);
    const v1Checkpoint = bytes(baseCheckpoint, 32);
    if (same(v1Digest, ZERO) || same(v1Checkpoint, ZERO)) fail();
    if (typeof requireFullV1ArchiveRollover !== "boolean"
      || requireFullV1ArchiveRollover !== !!fullV1ArchiveRollover) fail();
    const pinnedStrict = requireFullV1ArchiveRollover ? {
      archiveRoot: Buffer.from(fullV1ArchiveRollover.handoff?.v1_archive_root || "",
        "base64url"),
      checkpoint: Buffer.from(fullV1ArchiveRollover.v2PredecessorCheckpointPin || "",
        "base64url"),
    } : null;
    if (pinnedStrict && (pinnedStrict.archiveRoot.length !== 32
      || pinnedStrict.checkpoint.length !== 32
      || !same(pinnedStrict.checkpoint, v1Checkpoint))) fail();
    const trust = {
      genesisDigest: bytes(ownerTrust.genesisDigest, 32),
      pinnedWitness: ownerTrust.pinnedWitness,
      minimumHead: ownerTrust.minimumHead,
      freshWitnessHead: ownerTrust.freshWitnessHead,
    };
    if (!trust.pinnedWitness || !trust.minimumHead) fail();
    if (typeof filename !== "string" || !path.isAbsolute(filename)
      || !fs.existsSync(path.dirname(filename))) fail();
    if (bootstrapNew) ensurePrivateSqliteDirectory(filename);
    else assertPrivateSqliteFile(filename);
    try { assertPrivateSqliteAuthorityDirectory(filename); } catch (_) { fail(); }
    assertSafeSqliteSidecars(filename, fail);
    const createdPin = fileSecurity(filename, bootstrapNew);
    const scopeText = SCOPE.map((n) => scoped[n].toString("hex")).join(":");
    const allPins = Buffer.concat(pins);
    const identity = { role, scopeText, allPins, v1Digest, v1Checkpoint,
      genesisDigest: trust.genesisDigest };
    // Read-only preflight must reject a swapped database before opening a
    // writable handle, changing journal mode, or running any CREATE statement.
    const pinned = bootstrapNew ? createdPin
      : withReadonlySqliteSnapshot(filename,
        (probe) => {
          verifyAuthorityIdentity(probe, identity);
          this.#verifyStrictPin(probe, pinnedStrict);
        }, fail,
        MAX_WIRE * 2 + 8 * 1024 * 1024);
    const beforeOpen = assertPrivateSqliteFile(filename);
    if (beforeOpen.dev !== pinned.dev || beforeOpen.ino !== pinned.ino) fail();
    assertSafeSqliteSidecars(filename, fail);
    const db = new Database(filename, { fileMustExist: true, timeout: 3000 });
    try {
      const opened = assertPrivateSqliteFile(filename);
      if (opened.dev !== pinned.dev || opened.ino !== pinned.ino) fail();
      assertSafeSqliteSidecars(filename, fail);
      if (!bootstrapNew) {
        verifyAuthorityIdentity(db, identity);
        this.#verifyStrictPin(db, pinnedStrict);
      }
      db.pragma("journal_mode = WAL");
      db.pragma("synchronous = FULL");
      if (bootstrapNew) db.exec(AUTHORITY_SCHEMA);
      const conf = db.prepare("SELECT * FROM config").all();
      if (bootstrapNew) {
        if (conf.length || db.prepare("SELECT COUNT(*) as count FROM transitions").get().count) fail();
        db.prepare("INSERT INTO config VALUES (1,?,?,?,?,?,?)").run(role,
          scopeText, allPins, v1Digest, v1Checkpoint, trust.genesisDigest);
        if (pinnedStrict) {
          db.exec(STRICT_ROLLOVER_SCHEMA);
          db.prepare("INSERT INTO strict_rollover VALUES(1,?,?)")
            .run(pinnedStrict.archiveRoot, pinnedStrict.checkpoint);
        }
      }
      this.#db = db;
    } catch (error) { db.close(); throw error; }
    this.#settings = { role, signer, casKey, floorKey, checkpointKey, ownerKey,
      ownerTrust: trust, scope: scoped, casFp: pins[0], floorFp: pins[1],
      checkpointFp: pins[2], baseDigest: v1Digest, baseCheckpoint: v1Checkpoint };
    this.#strictRollover = pinnedStrict ? {
      pinned: pinnedStrict, proof: fullV1ArchiveRollover,
    } : null;
  }
  #verifyStrictPin(db, pinned) {
    const table = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='strict_rollover'").get();
    if (!!table !== !!pinned) fail("ZK_CHECKPOINT_V2_ROLLOVER_DOWNGRADE");
    if (!pinned) return;
    for (const trigger of ["strict_rollover_immutable_update",
      "strict_rollover_immutable_delete"]) {
      const row = db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND name=?")
        .get(trigger);
      if (!row) fail();
    }
    const rows = db.prepare("SELECT * FROM strict_rollover").all();
    if (rows.length !== 1 || rows[0].id !== 1
      || !same(bytes(rows[0].archive_root, 32), pinned.archiveRoot)
      || !same(bytes(rows[0].archive_checkpoint, 32), pinned.checkpoint)) fail();
  }
  #legacyMigrationStage() {
    const db = this.#db, s = this.#settings;
    const schema = new Set(db.prepare("SELECT name FROM sqlite_master"
      + " WHERE type IN ('table','trigger')").all().map((row) => row.name));
    const table = schema.has("legacy_archive_migration_stage");
    const triggers = ["legacy_archive_stage_immutable_update",
      "legacy_archive_stage_immutable_delete",
      "legacy_archive_stage_block_transition_insert",
      "legacy_archive_stage_block_transition_update"];
    if (!table) {
      if (triggers.some((name) => schema.has(name))) fail();
      return null;
    }
    // Name-only checks permit replacing a deny trigger with a same-name
    // no-op. Verify the exact application-authored SQL for every write fence.
    const canonicalSql = (sql) => sql.trim().replace(/;$/, "").replace(/\s+/g, " ");
    const expectedTable = LEGACY_MIGRATION_STAGE_SCHEMA.split("CREATE TRIGGER")[0];
    const getDdl = db.prepare("SELECT type,tbl_name,sql FROM sqlite_master WHERE name=?");
    const storedTable = getDdl.get("legacy_archive_migration_stage");
    if (storedTable?.type !== "table"
      || canonicalSql(storedTable.sql) !== canonicalSql(expectedTable)) fail();
    const definitions = [...LEGACY_MIGRATION_STAGE_SCHEMA.matchAll(
      /CREATE TRIGGER (legacy_archive_stage_[a-z_]+)\s+BEFORE (?:INSERT|UPDATE|DELETE) ON ([a-z_]+)[\s\S]*?END;/g)];
    if (definitions.length !== triggers.length) fail();
    for (const [name, target] of definitions.map((match) => [match[1], match[2]])) {
      const current = getDdl.get(name);
      const expected = definitions.find((match) => match[1] === name);
      if (!triggers.includes(name) || current?.type !== "trigger"
        || current.tbl_name !== target
        || canonicalSql(current.sql) !== canonicalSql(expected[0])) fail();
    }
    const rows = db.prepare("SELECT * FROM legacy_archive_migration_stage").all();
    if (rows.length !== 1 || rows[0].id !== 1) fail();
    const row = rows[0];
    const latest = db.prepare("SELECT sequence,final_digest,checkpoint_digest,"
      + "operation_id,state FROM transitions ORDER BY sequence DESC LIMIT 1").get();
    if ((latest?.sequence || 128) !== row.legacy_sequence
      || (latest?.state || "FINALIZED") !== "FINALIZED"
      || !same(latest?.final_digest || s.baseDigest, bytes(row.legacy_head_digest, 32))
      || !same(latest?.checkpoint_digest || s.baseCheckpoint,
        bytes(row.legacy_checkpoint_digest, 32))
      || !same(latest?.operation_id || ZERO, bytes(row.legacy_operation_id, 32))) fail();
    const consent = JSON.parse(bytes(row.owner_consent, 1, 4096).toString("utf8"));
    exact(consent, LEGACY_MIGRATION_FIELDS);
    if (consent.type !== "rootark-opaque-checkpoint-v2-legacy-archive-migration/v1"
      || !SCOPE.every((field) => consent[field] === s.scope[field].toString("base64url"))
      || !same(canonical32(consent.legacy_base_digest), s.baseDigest)
      || !same(canonical32(consent.legacy_base_checkpoint), s.baseCheckpoint)
      || !same(canonical32(consent.cas_signer_fp), s.casFp)
      || !same(canonical32(consent.floor_signer_fp), s.floorFp)
      || !same(canonical32(consent.legacy_head_digest), bytes(row.legacy_head_digest, 32))
      || !same(canonical32(consent.legacy_checkpoint_digest), bytes(row.legacy_checkpoint_digest, 32))
      || !same(canonical32(consent.legacy_operation_id), bytes(row.legacy_operation_id, 32))
      || !same(canonical32(consent.full_archive_root), bytes(row.full_archive_root, 32))
      || !same(canonical32(consent.full_archive_checkpoint), bytes(row.full_archive_checkpoint, 32))
      || consent.legacy_sequence !== row.legacy_sequence
      || !crypto.verify(null, Buffer.concat([LEGACY_MIGRATION_DOMAIN,
        row.owner_consent]), s.ownerKey, bytes(row.owner_signature, 64))) fail();
    return row;
  }
  async #verifyStrictAdmission() {
    if (this.#legacyMigrationStage())
      fail("ZK_CHECKPOINT_V2_LEGACY_MIGRATION_PENDING");
    // A newly provisioned STRICT authority binds this obligation in its
    // immutable SQLite identity. Existing legacy V2 authorities are not
    // retroactively upgraded by guessing an archive or repinning their head.
    if (!this.#strictRollover) return;
    const p = this.#strictRollover.proof, s = this.#settings;
    const pinned = this.#strictRollover.pinned;
    if (!p || !same(fp(key(p.ownerKey)), fp(s.ownerKey))
      || !same(fp(key(p.checkpointKey)), s.checkpointFp)
      || !same(fp(key(p.v2CasKey)), s.casFp)
      || !same(fp(key(p.v2FloorKey)), s.floorFp)
      || !same(bytes(Buffer.from(p.v2PredecessorCheckpointPin, "base64url"), 32),
        pinned.checkpoint)
      || !same(bytes(Buffer.from(p.handoff.v1_archive_root, "base64url"), 32),
        pinned.archiveRoot)
      || !same(bytes(Buffer.from(p.handoff.v1_digest, "base64url"), 32),
        s.baseDigest)
      || !SCOPE.every((field) => same(bytes(p.scope[field], s.scope[field].length),
        s.scope[field]))) fail("ZK_CHECKPOINT_V2_FULL_ARCHIVE_REQUIRED");
    const nonce = crypto.randomBytes(32);
    const observed = bytes(await s.ownerTrust.freshWitnessHead({
      scope: s.scope, nonce }), 1, 8192);
    await inspectVerifiedWitnessFreshHeadV1({ raw: observed, nonce,
      scope: s.scope, pinned: s.ownerTrust.pinnedWitness,
      minimumHead: s.ownerTrust.minimumHead });
    const head = await z.decodeDeterministic(observed);
    if (Math.abs(Math.floor(Date.now() / 1000) - head.observed_at) > 30
      || head.current_revision !== p.ownerHead.revision
      || !same(bytes(head.current_manifest_digest, 32),
        bytes(p.ownerHead.digest, 32))) fail("ZK_CHECKPOINT_V2_OWNER_ROLLOVER_STALE");
    const { verifyRolloverPreflight } = require("./zk1OpaqueCatalogV1RolloverPreflight");
    await verifyRolloverPreflight(p);
    // A changing proof object must not make the immutable SQLite anchor
    // appear different after asynchronous witness / CAS verification.
    if (!same(bytes(Buffer.from(p.handoff.v1_archive_root, "base64url"), 32),
      pinned.archiveRoot)) fail();
  }
  async renewFullV1ArchiveOwnerHandoff({ handoff, ownerSignature, ownerHead }) {
    if (!this.#strictRollover) fail("ZK_CHECKPOINT_V2_FULL_ARCHIVE_REQUIRED");
    return this.#serial(async () => {
      const old = this.#strictRollover.proof;
      const next = { ...old, handoff, ownerSignature, ownerHead };
      this.#strictRollover.proof = next;
      try { await this.#verifyStrictAdmission(); }
      catch (error) { this.#strictRollover.proof = old; throw error; }
      return Object.freeze({ renewed: true, v2WriteAuthorized: false });
    });
  }
  // Operator-local PHASE-1 only: both authorities MUST independently stage
  // this exact owner consent while the signed legacy head is still unchanged.
  // Until a separately reviewed dual-authority protocol exists, this is a
  // PERMANENT write quarantine, never an implicit V2 epoch activation.
  async stageLegacyArchiveMigration({ fullV1ArchiveRollover, ownerConsent,
    ownerSignature, peerClient } = {}) {
    return this.#serial(async () => {
      if (this.#strictRollover || this.#legacyMigrationStage()
        || !fullV1ArchiveRollover || !pinnedV2Clients.has(peerClient)
        || peerClient.role === this.role) fail("ZK_CHECKPOINT_V2_LEGACY_MIGRATION_DENIED");
      const s = this.#settings;
      const proof = fullV1ArchiveRollover;
      if (!same(fp(key(proof.ownerKey)), fp(s.ownerKey))
        || !same(fp(key(proof.checkpointKey)), s.checkpointFp)
        || !same(fp(key(proof.v2CasKey)), s.casFp)
        || !same(fp(key(proof.v2FloorKey)), s.floorFp)
        || !same(canonical32(proof.handoff.v1_digest), s.baseDigest)
        || !SCOPE.every((field) =>
          same(bytes(proof.scope[field], s.scope[field].length), s.scope[field]))) fail();
      const { verifyRolloverPreflight } = require("./zk1OpaqueCatalogV1RolloverPreflight");
      const inspected = await verifyRolloverPreflight(proof);
      if (inspected.sequence !== 128 || inspected.archivesRetained !== 128
        || inspected.v2WriteAuthorized !== false
        || !same(canonical32(inspected.digest), s.baseDigest)) fail();
      const nonce = crypto.randomBytes(32);
      const observed = bytes(await s.ownerTrust.freshWitnessHead({
        scope: s.scope, nonce }), 1, 8192);
      await inspectVerifiedWitnessFreshHeadV1({ raw: observed, nonce,
        scope: s.scope, pinned: s.ownerTrust.pinnedWitness,
        minimumHead: s.ownerTrust.minimumHead });
      const witness = await z.decodeDeterministic(observed);
      const ownRows = await this.#history();
      const last = ownRows.at(-1);
      if (last && last.state !== "FINALIZED") fail("ZK_CHECKPOINT_V2_LEGACY_MIGRATION_PENDING");
      if (last) {
        const priorIntent = await z.decodeDeterministic(bytes(last.intent, 1, MAX_WIRE));
        const signedHead = await z.decodeDeterministic(
          bytes(priorIntent.records?.[0]?.header, 1, 16384));
        // Owner approval cannot recast a newer legacy V2 epoch as a prior
        // epoch, even when that older owner signed a complete V1 archive.
        if (!Number.isSafeInteger(signedHead.epoch)
          || signedHead.epoch > proof.ownerHead.epoch) fail();
      }
      const snapshot = {
        sequence: last?.sequence || 128,
        head: last?.final_digest || s.baseDigest,
        checkpoint: last?.checkpoint_digest || s.baseCheckpoint,
        operation: last?.operation_id || ZERO,
      };
      if (!same(fp(key(peerClient.publicKey)),
        this.role === ROLE_CAS ? s.floorFp : s.casFp)) fail();
      const peer = await peerClient.head();
      if (peer.state !== (last ? "FINALIZED" : "V1_BASELINE")
        || peer.sequence !== snapshot.sequence
        || !same(bytes(peer.head_digest || peer.headDigest, 32), snapshot.head)
        || !same(bytes(peer.checkpoint_digest || peer.checkpointDigest, 32), snapshot.checkpoint)
        || (last && !same(bytes(peer.operation_id, 32), snapshot.operation))) fail();
      exact(ownerConsent, LEGACY_MIGRATION_FIELDS);
      const consent = Buffer.from(JSON.stringify(ownerConsent));
      const signature = bytes(ownerSignature, 64);
      const now = Math.floor(Date.now() / 1000);
      for (const field of SCOPE)
        if (ownerConsent[field] !== s.scope[field].toString("base64url")) fail();
      if (ownerConsent.type !== "rootark-opaque-checkpoint-v2-legacy-archive-migration/v1"
        || !same(canonical32(ownerConsent.legacy_base_digest), s.baseDigest)
        || !same(canonical32(ownerConsent.legacy_base_checkpoint), s.baseCheckpoint)
        || ownerConsent.legacy_sequence !== snapshot.sequence
        || !same(canonical32(ownerConsent.legacy_head_digest), snapshot.head)
        || !same(canonical32(ownerConsent.legacy_checkpoint_digest), snapshot.checkpoint)
        || !same(canonical32(ownerConsent.legacy_operation_id), snapshot.operation)
        || !same(canonical32(ownerConsent.full_archive_root), canonical32(inspected.archiveRoot))
        || !same(canonical32(ownerConsent.full_archive_checkpoint),
          canonical32(inspected.checkpointDigest))
        || !same(canonical32(ownerConsent.cas_signer_fp), s.casFp)
        || !same(canonical32(ownerConsent.floor_signer_fp), s.floorFp)
        || ownerConsent.owner_revision !== proof.ownerHead.revision
        || !same(canonical32(ownerConsent.owner_digest), bytes(proof.ownerHead.digest, 32))
        || ownerConsent.owner_epoch !== proof.ownerHead.epoch
        || witness.current_revision !== ownerConsent.owner_revision
        || !same(bytes(witness.current_manifest_digest, 32),
          canonical32(ownerConsent.owner_digest))
        || !Number.isSafeInteger(ownerConsent.issued_at)
        || !Number.isSafeInteger(ownerConsent.expires_at)
        || ownerConsent.issued_at > now + 30 || ownerConsent.expires_at < now
        || ownerConsent.issued_at < 1
        || ownerConsent.expires_at <= ownerConsent.issued_at
        || ownerConsent.expires_at - ownerConsent.issued_at > 300
        || !crypto.verify(null, Buffer.concat([LEGACY_MIGRATION_DOMAIN, consent]),
          s.ownerKey, signature)) fail();
      canonical32(ownerConsent.nonce);
      // Fence competing processes that use this SAME SQLite DB, including an
      // older binary without awareness of the staged state, by SQLite triggers.
      this.#db.transaction(() => {
        if (this.#legacyMigrationStage()) fail();
        const count = this.#db.prepare("SELECT COUNT(*) AS n FROM transitions").get().n;
        const current = this.#db.prepare(
          "SELECT sequence,final_digest,checkpoint_digest,operation_id,state"
          + " FROM transitions ORDER BY sequence DESC LIMIT 1").get();
        if (count !== ownRows.length || (current?.sequence || 128) !== snapshot.sequence
          || (current?.state || "FINALIZED") !== "FINALIZED"
          || (current && (!same(current.final_digest, snapshot.head)
            || !same(current.checkpoint_digest, snapshot.checkpoint)
            || !same(current.operation_id, snapshot.operation)))) fail();
        this.#db.exec(LEGACY_MIGRATION_STAGE_SCHEMA);
        this.#db.prepare("INSERT INTO legacy_archive_migration_stage"
          + " VALUES(1,?,?,?,?,?,?,?,?)").run(snapshot.sequence, snapshot.head,
          snapshot.checkpoint, snapshot.operation,
          canonical32(inspected.archiveRoot), canonical32(inspected.checkpointDigest),
          consent, signature);
      }).immediate();
      return Object.freeze({ state: "LEGACY_ARCHIVE_MIGRATION_STAGED_READ_ONLY",
        legacySequence: snapshot.sequence, v2WriteAuthorized: false,
        independentlyReconciledAcrossAuthorities: false });
    });
  }
  // Non-mutating, challenge-bound operator evidence for an already fenced
  // SQLite stage. The statement is signed by this role's independent key.
  // It is NOT a durable witness anchor or a dual-authority activation.
  async legacyArchiveReadback(nonce) {
    return this.#serial(async () => {
      const challenge = bytes(nonce, 32);
      const stage = this.#legacyMigrationStage();
      if (!stage) fail("ZK_CHECKPOINT_V2_LEGACY_READBACK_NOT_STAGED");
      if (stage.legacy_sequence > 128 + MAX_LEGACY_READBACK_TRANSITIONS)
        fail("ZK_CHECKPOINT_V2_LEGACY_READBACK_BOUNDED");
      const rows = await this.#history();
      const last = rows.at(-1);
      if (last && last.state !== "FINALIZED")
        fail("ZK_CHECKPOINT_V2_LEGACY_MIGRATION_PENDING");
      const current = this.#legacyMigrationStage();
      const s = this.#settings;
      if (!current || !same(stage.owner_consent, current.owner_consent)
        || !same(stage.owner_signature, current.owner_signature)) fail();
      const terminal = last || { final_digest: s.baseDigest,
        checkpoint_digest: s.baseCheckpoint, operation_id: ZERO };
      const receipt = await this.#signed(terminal,
        last ? "FINALIZED" : "V1_BASELINE", challenge);
      const statement = { type: "rootark-opaque-checkpoint-v2-legacy-archive-readback/v1",
        ...s.scope, role: s.role, state: "STAGED_READ_ONLY",
        legacy_base_digest: s.baseDigest, legacy_base_checkpoint: s.baseCheckpoint,
        legacy_sequence: current.legacy_sequence,
        legacy_head_digest: bytes(current.legacy_head_digest, 32),
        legacy_checkpoint_digest: bytes(current.legacy_checkpoint_digest, 32),
        legacy_operation_id: bytes(current.legacy_operation_id, 32),
        full_archive_root: bytes(current.full_archive_root, 32),
        full_archive_checkpoint: bytes(current.full_archive_checkpoint, 32),
        cas_signer_fp: s.casFp, floor_signer_fp: s.floorFp,
        owner_consent_hash: hash(LEGACY_MIGRATION_DOMAIN, current.owner_consent,
          current.owner_signature), terminal_receipt: receipt,
        nonce: challenge, issued_at: Math.floor(Date.now() / 1000) };
      const raw = Buffer.from(await z.encodeDeterministic(statement));
      return Buffer.from(await z.encodeDeterministic({ ...statement,
        signature: crypto.sign(null, Buffer.concat([LEGACY_READBACK_DOMAIN, raw]),
          s.signer) }));
    });
  }
  get role() { return this.#settings.role; }
  get publicKey() { return crypto.createPublicKey(this.#settings.signer); }
  async #signed(row, state, nonce) {
    const s = this.#settings;
    const statement = { type: "rootark-opaque-checkpoint-remote-receipt/v2",
      ...s.scope, role: s.role, state,
      sequence: state === "V1_BASELINE" ? 128 : row.sequence,
      head_digest: row.final_digest, checkpoint_digest: row.checkpoint_digest,
      operation_id: row.operation_id, cas_signer_fp: s.casFp,
      floor_signer_fp: s.floorFp, nonce: bytes(nonce, 32),
      issued_at: Math.floor(Date.now() / 1000) };
    const raw = Buffer.from(await z.encodeDeterministic(statement));
    return Buffer.from(await z.encodeDeterministic({ ...statement,
      signature: crypto.sign(null, Buffer.concat([RECEIPT_DOMAIN, raw]), s.signer) }));
  }
  #serial(action) {
    const pending = this.#queue.then(action);
    this.#queue = pending.catch(() => {});
    return pending;
  }
  async #history() {
    const rows = this.#db.prepare("SELECT * FROM transitions ORDER BY sequence").all();
    if (rows.length > MAX_V2_SEQUENCE - 128) fail();
    let previous = { sequence: 128, final_digest: this.#settings.baseDigest,
      checkpoint_digest: this.#settings.baseCheckpoint, state: "FINALIZED" };
    for (const [index, row] of rows.entries()) {
      if (row.sequence !== previous.sequence + 1
        || (index > 0 && previous.state !== "FINALIZED")) fail();
      await this.#inspect(row, false, previous);
      previous = row;
    }
    return rows;
  }
  async #inspect(row, freshness, previous) {
    const s = this.#settings;
    if (!row) return null;
    if (!["PREPARED", "CAS_COMMITTED", "FINALIZED"].includes(row.state)
      || (s.role === ROLE_FLOOR && row.state === "CAS_COMMITTED")
      || (s.role === ROLE_CAS && row.state === "PREPARED")) fail();
    if (previous && (row.sequence !== previous.sequence + 1
      || previous.state !== "FINALIZED")) fail();
    const inspected = await inspectIntent(row.intent, { ...s,
      baseDigest: previous?.final_digest || s.baseDigest,
      baseCheckpoint: previous?.checkpoint_digest || s.baseCheckpoint,
      previousOperationId: previous?.operation_id || ZERO,
      cachedSigner: crypto.createPublicKey({ key: row.signer_spki,
        format: "der", type: "spki" }) },
    { freshOwner: freshness, historicalOwner: !freshness });
    if (row.sequence !== inspected.body.previous_sequence + 1) fail();
    if (!same(inspected.intentHash, row.intent_hash)
      || !same(inspected.operationId, row.operation_id)
      || !same(inspected.checkpointDigest, row.checkpoint_digest)
      || !same(inspected.finalDigest, row.final_digest)
      || !same(inspected.signerSpki, row.signer_spki)) fail();
    const verifySavedReceipt = async (raw, role, state, signer) => {
      const statement = await z.decodeDeterministic(bytes(raw, 1, 4096));
      await receiptMatches(raw, { scope: s.scope, role, state, sequence: row.sequence,
        headDigest: row.final_digest, checkpointDigest: row.checkpoint_digest,
        operationId: row.operation_id, casFp: s.casFp, floorFp: s.floorFp,
        signer, nonce: bytes(statement.nonce, 32), fresh: false });
    };
    if (s.role === ROLE_CAS) {
      await verifySavedReceipt(row.floor_prepare, ROLE_FLOOR, "PREPARED", s.floorKey);
      if (row.state === "FINALIZED")
        await verifySavedReceipt(row.floor_finalize, ROLE_FLOOR, "FINALIZED", s.floorKey);
    } else if (row.state === "FINALIZED") {
      await verifySavedReceipt(row.cas_commit, ROLE_CAS, "CAS_COMMITTED", s.casKey);
    }
    return inspected;
  }
  async prepare(raw, nonce) {
    if (this.role !== ROLE_FLOOR) fail();
    return this.#serial(async () => {
      await this.#verifyStrictAdmission();
      const rows = await this.#history();
      const proposed = await z.decodeDeterministic(bytes(raw, 1, MAX_WIRE));
      const target = num(proposed.previous_sequence, 128, MAX_V2_SEQUENCE - 1) + 1;
      const row = rows.at(-1);
      const predecessor = row?.sequence === target ? rows.at(-2) : row;
      if ((predecessor?.sequence || 128) !== target - 1
        || (predecessor && predecessor.state !== "FINALIZED")) fail("ZK_CHECKPOINT_V2_CONFLICT");
      const intent = await inspectIntent(raw, { ...this.#settings,
        baseDigest: predecessor?.final_digest || this.#settings.baseDigest,
        baseCheckpoint: predecessor?.checkpoint_digest || this.#settings.baseCheckpoint,
        previousOperationId: predecessor?.operation_id || ZERO });
      if (row) {
        if (row.sequence === target) {
          if (!same(row.intent_hash, intent.intentHash)) fail("ZK_CHECKPOINT_V2_CONFLICT");
          return this.#signed(row, row.state === "FINALIZED" ? "FINALIZED" : "PREPARED", nonce);
        }
      }
      this.#db.prepare(`INSERT INTO transitions
        (sequence,intent_hash,operation_id,checkpoint_digest,final_digest,
        intent,signer_spki,state) VALUES (?,?,?,?,?,?,?,'PREPARED')`)
        .run(target, intent.intentHash, intent.operationId, intent.checkpointDigest,
          intent.finalDigest, intent.raw, intent.signerSpki);
      const saved = (await this.#history()).at(-1);
      return this.#signed(saved, "PREPARED", nonce);
    });
  }
  async commit(raw, floorPrepare, nonce) {
    if (this.role !== ROLE_CAS) fail();
    return this.#serial(async () => {
      await this.#verifyStrictAdmission();
      const rows = await this.#history();
      const proposed = await z.decodeDeterministic(bytes(raw, 1, MAX_WIRE));
      const target = num(proposed.previous_sequence, 128, MAX_V2_SEQUENCE - 1) + 1;
      let row = rows.at(-1);
      const predecessor = row?.sequence === target ? rows.at(-2) : row;
      if ((predecessor?.sequence || 128) !== target - 1
        || (predecessor && predecessor.state !== "FINALIZED")) fail("ZK_CHECKPOINT_V2_CONFLICT");
      const intent = await inspectIntent(raw, { ...this.#settings,
        baseDigest: predecessor?.final_digest || this.#settings.baseDigest,
        baseCheckpoint: predecessor?.checkpoint_digest || this.#settings.baseCheckpoint,
        previousOperationId: predecessor?.operation_id || ZERO });
      await receiptMatches(floorPrepare, { scope: this.#settings.scope,
        role: ROLE_FLOOR, sequence: target,
        headDigest: intent.finalDigest, checkpointDigest: intent.checkpointDigest,
        operationId: intent.operationId, casFp: this.#settings.casFp,
        floorFp: this.#settings.floorFp, signer: this.#settings.floorKey,
        fresh: true });
      if (row?.sequence === target && !same(row.intent_hash, intent.intentHash))
        fail("ZK_CHECKPOINT_V2_CONFLICT");
      if (!row || row.sequence !== target) {
        this.#db.prepare(`INSERT INTO transitions
          (sequence,intent_hash,operation_id,checkpoint_digest,final_digest,intent,
          signer_spki,state,floor_prepare)
          VALUES(?,?,?,?,?,?,?,'CAS_COMMITTED',?)`)
          .run(target, intent.intentHash, intent.operationId, intent.checkpointDigest,
            intent.finalDigest, intent.raw, intent.signerSpki, floorPrepare);
        row = (await this.#history()).at(-1);
      }
      return this.#signed(row, "CAS_COMMITTED", nonce);
    });
  }
  async finalize(casCommit, nonce) {
    if (this.role !== ROLE_FLOOR) fail();
    return this.#serial(async () => {
      await this.#verifyStrictAdmission();
      const rows = await this.#history();
      const row = rows.at(-1);
      if (!row) fail("ZK_CHECKPOINT_V2_CONFLICT");
      // Revocation may land after PREPARE or CAS_COMMIT. Before advancing a
      // pending intent into FINALIZED, require the owner approval's witnessed
      // epoch to STILL be the live witnessed head. A local pending receipt
      // from an obsolete epoch must not authorize new finalization.
      if (row.state === "PREPARED") await this.#inspect(row, true, rows.at(-2));
      await receiptMatches(casCommit, { scope: this.#settings.scope,
        role: ROLE_CAS, state: "CAS_COMMITTED", sequence: row.sequence,
        headDigest: row.final_digest, checkpointDigest: row.checkpoint_digest,
        operationId: row.operation_id, casFp: this.#settings.casFp,
        floorFp: this.#settings.floorFp, signer: this.#settings.casKey,
        fresh: true });
      if (row.state === "PREPARED") this.#db.prepare(`UPDATE transitions
        SET state='FINALIZED',cas_commit=? WHERE sequence=? AND state='PREPARED'`)
        .run(casCommit, row.sequence);
      return this.#signed((await this.#history()).at(-1), "FINALIZED", nonce);
    });
  }
  async attestFinalized(floorFinalized, nonce) {
    if (this.role !== ROLE_CAS) fail();
    return this.#serial(async () => {
      await this.#verifyStrictAdmission();
      const rows = await this.#history();
      const row = rows.at(-1);
      if (!row) fail("ZK_CHECKPOINT_V2_CONFLICT");
      if (row.state === "CAS_COMMITTED") await this.#inspect(row, true, rows.at(-2));
      await receiptMatches(floorFinalized, { scope: this.#settings.scope,
        role: ROLE_FLOOR, state: "FINALIZED", sequence: row.sequence,
        headDigest: row.final_digest, checkpointDigest: row.checkpoint_digest,
        operationId: row.operation_id, casFp: this.#settings.casFp,
        floorFp: this.#settings.floorFp, signer: this.#settings.floorKey,
        fresh: true });
      if (row.state === "CAS_COMMITTED") this.#db.prepare(`UPDATE transitions
        SET state='FINALIZED', floor_finalize=?
        WHERE sequence=? AND state='CAS_COMMITTED'`).run(floorFinalized, row.sequence);
      return this.#signed((await this.#history()).at(-1), "FINALIZED", nonce);
    });
  }
  async head(nonce) {
    return this.#serial(async () => {
      const row = (await this.#history()).at(-1);
      if (!row) {
        // Even the ABSENCE of v2 state must be freshly authenticated. An
        // unsigned baseline lets a transport-only compromise conceal a
        // previously finalized checkpoint and falsely advertise rollback.
        const baseline = {
          final_digest: this.#settings.baseDigest,
          checkpoint_digest: this.#settings.baseCheckpoint,
          operation_id: ZERO,
        };
        return { state: "V1_BASELINE", sequence: 128,
          headDigest: Buffer.from(this.#settings.baseDigest),
          checkpointDigest: Buffer.from(this.#settings.baseCheckpoint),
          proof: await this.#signed(baseline, "V1_BASELINE", nonce) };
      }
      return { state: row.state, sequence: row.sequence, headDigest: Buffer.from(row.final_digest),
        checkpointDigest: Buffer.from(row.checkpoint_digest),
        operationId: Buffer.from(row.operation_id),
        proof: await this.#signed(row, row.state, nonce) };
    });
  }
  close() { if (this.#db.open) this.#db.close(); }
}

function createOpaqueCheckpointV2HttpsServer({ ledger, tlsKey, tlsCert, clientCa,
  clientFingerprint256, dropAfterCommitOnce = false, dropAfterFinalizeOnce = false }) {
  if (!(ledger instanceof OpaqueCheckpointV2Authority) || !tlsKey || !tlsCert
    || !clientCa || !CERT_PIN.test(clientFingerprint256)) fail();
  const pin = clientFingerprint256.toUpperCase();
  let dropCommit = dropAfterCommitOnce;
  let dropFinal = dropAfterFinalizeOnce;
  const server = https.createServer({ key: tlsKey, cert: tlsCert, ca: clientCa,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3" }, async (req, res) => {
    try {
      if (!req.socket.authorized
        || req.socket.getPeerCertificate()?.fingerprint256?.toUpperCase() !== pin
        || req.method !== "POST" || req.headers["content-type"] !== "application/json"
        || !["/v2/prepare", "/v2/commit", "/v2/finalize", "/v2/attest",
          "/v2/head", "/v2/legacy-readback"]
          .includes(req.url)) fail();
      const parts = []; let count = 0;
      for await (const chunk of req) {
        count += chunk.length;
        if (count > MAX_WIRE * 2) fail();
        parts.push(chunk);
      }
      const obj = JSON.parse(Buffer.concat(parts).toString("utf8"));
      exact(obj, ["raw", "proof", "nonce"]);
      const decode = (string, min, max) => {
        if (string === null) return null;
        if (typeof string !== "string" || !/^[A-Za-z0-9_-]+$/.test(string)) fail();
        const raw = Buffer.from(string, "base64url");
        if (raw.length < min || raw.length > max || raw.toString("base64url") !== string) fail();
        return raw;
      };
      const nonce = decode(obj.nonce, 32, 32);
      const raw = decode(obj.raw, 1, MAX_WIRE);
      const proof = decode(obj.proof, 1, 4096);
      let result;
      if (req.url === "/v2/prepare") result = await ledger.prepare(raw, nonce);
      else if (req.url === "/v2/commit") result = await ledger.commit(raw, proof, nonce);
      else if (req.url === "/v2/finalize") result = await ledger.finalize(proof, nonce);
      else if (req.url === "/v2/attest") result = await ledger.attestFinalized(proof, nonce);
      else if (req.url === "/v2/legacy-readback")
        result = await ledger.legacyArchiveReadback(nonce);
      else result = await ledger.head(nonce);
      if ((req.url === "/v2/commit" && dropCommit)
        || (req.url === "/v2/finalize" && dropFinal)) {
        if (req.url === "/v2/commit") dropCommit = false;
        if (req.url === "/v2/finalize") dropFinal = false;
        req.socket.destroy(); return;
      }
      const response = Buffer.from(JSON.stringify(Buffer.isBuffer(result)
        ? { proof: result.toString("base64url") }
        : { state: result.state, sequence: result.sequence,
          headDigest: result.headDigest.toString("base64url"),
          checkpointDigest: result.checkpointDigest.toString("base64url"),
          operationId: result.operationId?.toString("base64url") || null,
          proof: result.proof?.toString("base64url") || null }));
      res.writeHead(200, { "content-type": "application/json",
        "content-length": response.length, "cache-control": "no-store" });
      res.end(response);
    } catch (_) {
      if (req.socket.destroyed) return;
      res.writeHead(409, { "content-type": "application/json" });
      res.end('{"error":"V2_AUTHORITY_REJECTED"}');
    }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  return server;
}

function createOpaqueCheckpointV2HttpsClient({ endpoint, ca, clientKey, clientCert,
  serverFingerprint256, authorityPublicKey, casPublicKey, floorPublicKey, scope,
  timeoutMs = 3000 }) {
  const url = new URL(endpoint);
  if (url.protocol !== "https:" || !url.port || url.pathname !== "/"
    || url.search || url.hash || url.username || url.password
    || !CERT_PIN.test(serverFingerprint256) || !ca || !clientKey || !clientCert
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) fail();
  const signer = key(authorityPublicKey);
  const cas = key(casPublicKey), floor = key(floorPublicKey);
  const scopeBytes = scopeOf(scope);
  const casFp = fp(cas), floorFp = fp(floor);
  if (same(casFp, floorFp)
    || (!same(fp(signer), casFp) && !same(fp(signer), floorFp))) fail();
  const pin = serverFingerprint256.toUpperCase();
  async function request(route, raw, proof, headChallenge) {
    const nonce = headChallenge === undefined
      ? crypto.randomBytes(32) : bytes(headChallenge, 32);
    const encoded = Buffer.from(JSON.stringify({ raw: raw?.toString("base64url") || null,
      proof: proof?.toString("base64url") || null, nonce: nonce.toString("base64url") }));
    const outcome = await new Promise((resolve, reject) => {
      const req = https.request({ hostname: url.hostname, port: url.port, path: route,
        method: "POST", agent: false, ca, key: clientKey, cert: clientCert,
        rejectUnauthorized: true, minVersion: "TLSv1.3",
        servername: net.isIP(url.hostname) ? "" : url.hostname,
        checkServerIdentity(host, cert) {
          const invalid = tls.checkServerIdentity(host, cert);
          return invalid || (cert.fingerprint256?.toUpperCase() === pin ? undefined
            : new Error("CHECKPOINT_SERVER_NOT_PINNED"));
        },
        headers: { "content-type": "application/json", "content-length": encoded.length },
      }, (response) => {
        if (response.statusCode !== 200) {
          response.resume(); reject(new Error("CHECKPOINT_REMOTE_CONFLICT")); return;
        }
        const parts = []; let count = 0;
        response.on("data", (part) => {
          count += part.length;
          if (count > 8192) { req.destroy(); reject(new Error("CHECKPOINT_BODY_LIMIT")); }
          else parts.push(part);
        });
        response.on("error", reject);
        response.on("end", () => {
          try { resolve(JSON.parse(Buffer.concat(parts).toString("utf8"))); }
          catch (error) { reject(error); }
        });
      });
      req.setTimeout(timeoutMs, () => req.destroy());
      req.on("error", reject);
      req.end(encoded);
    }).catch(() => fail("ZK_CHECKPOINT_V2_ACK_UNCERTAIN"));
    const rawProof = outcome.proof ? Buffer.from(outcome.proof, "base64url") : null;
    if (route === "/v2/legacy-readback") {
      if (!rawProof) fail();
      return inspectLegacyArchiveReadback(rawProof, { scope: scopeBytes,
        signer, role: same(fp(signer), casFp) ? ROLE_CAS : ROLE_FLOOR,
        casFp, floorFp, nonce });
    }
    if (route === "/v2/head") {
      if (outcome.state === "V1_BASELINE") {
          if (outcome.sequence !== 128 || !rawProof) fail();
          const baseline = await z.decodeDeterministic(rawProof);
          if (!same(bytes(baseline.nonce, 32), nonce)) fail();
          const digest = bytes(Buffer.from(outcome.headDigest, "base64url"), 32);
          const checkpoint = bytes(
            Buffer.from(outcome.checkpointDigest, "base64url"), 32);
          await receiptMatches(rawProof, { scope: scopeBytes,
            role: same(fp(signer), casFp) ? ROLE_CAS : ROLE_FLOOR,
            state: "V1_BASELINE", sequence: 128,
            headDigest: digest, checkpointDigest: checkpoint,
            operationId: ZERO, casFp, floorFp, signer, nonce, fresh: true });
          if (outcome.operationId !== null) fail();
          return { state: "V1_BASELINE", sequence: 128, raw: Buffer.from(rawProof),
            headDigest: digest, checkpointDigest: checkpoint };
      }
      if (!rawProof || !["PREPARED", "CAS_COMMITTED", "FINALIZED"].includes(outcome.state)) fail();
    }
    if (!rawProof) fail();
    const data = await z.decodeDeterministic(rawProof);
    if (!same(bytes(data.nonce, 32), nonce)) fail();
    const receipt = await receiptMatches(rawProof, { scope: scopeBytes,
      role: same(fp(signer), casFp) ? ROLE_CAS : ROLE_FLOOR,
      state: route === "/v2/head" ? outcome.state
        : ({ "/v2/prepare": "PREPARED", "/v2/commit": "CAS_COMMITTED",
          "/v2/finalize": "FINALIZED", "/v2/attest": "FINALIZED" })[route],
      sequence: num(data.sequence, 129, MAX_V2_SEQUENCE), headDigest: data.head_digest,
      checkpointDigest: data.checkpoint_digest, operationId: data.operation_id,
      casFp, floorFp, signer, nonce, fresh: true });
    if (route === "/v2/head") {
      if (outcome.sequence !== receipt.sequence
        || !same(bytes(Buffer.from(outcome.headDigest, "base64url"), 32),
          receipt.head_digest)
        || !same(bytes(Buffer.from(outcome.checkpointDigest, "base64url"), 32),
          receipt.checkpoint_digest)) fail();
    }
    return { ...receipt, state: receipt.state };
  }
  const client = Object.freeze({
    publicKey: signer, role: same(fp(signer), casFp) ? ROLE_CAS : ROLE_FLOOR,
    prepare: (raw) => request("/v2/prepare", raw),
    commit: (raw, floorPrepare) => request("/v2/commit", raw, floorPrepare),
    finalize: (casCommit) => request("/v2/finalize", null, casCommit),
    attest: (floorFinalized) => request("/v2/attest", null, floorFinalized),
    head: (challenge) => request("/v2/head", null, null, challenge),
    legacyArchiveReadback: (challenge) =>
      request("/v2/legacy-readback", null, null, challenge),
  });
  pinnedV2Clients.add(client);
  return client;
}
function isOpaqueCheckpointV2PinnedClient(client) {
  return pinnedV2Clients.has(client);
}

// PHASE-2 bounded evidence gate: two independently signed, nonce-fresh,
// owner-consent-bound stage snapshots plus full historical V1 cryptographic
// verification and a fresh separately pinned owner witness. No writes.
async function verifyLegacyArchiveDualReadback(input) {
  try {
    exact(input, ["fullV1ArchiveRollover", "ownerConsent", "ownerSignature",
      "casClient", "floorClient", "ownerTrust", "operatorPins"]);
    const { fullV1ArchiveRollover: proof, ownerConsent: suppliedConsent, ownerSignature,
      casClient, floorClient, ownerTrust, operatorPins } = input;
    if (!pinnedV2Clients.has(casClient) || casClient.role !== ROLE_CAS
      || !pinnedV2Clients.has(floorClient) || floorClient.role !== ROLE_FLOOR
      || !proof || typeof ownerTrust?.freshWitnessHead !== "function"
      || !ownerTrust.pinnedWitness || !ownerTrust.minimumHead) fail();
    if (!isZk1OpaqueCatalogCasHttpsClient(proof.v1CasClient)
      || !isZk1OpaqueCatalogIndependentFloorClient(proof.v1FloorClient)
      || !same(fp(key(proof.v1CasClient.publicKey)), fp(key(proof.v1CasKey)))
      || !same(fp(key(proof.v1FloorClient.publicKey)), fp(key(proof.v1FloorKey))))
      fail();
    // These are operator-custodied public keys, injected independently from
    // the candidate rollover proof. A proof's self-declared pins alone
    // cannot bootstrap trust in a different owner/archive/authority.
    exact(operatorPins, ["ownerPublicKey", "archiveCheckpointPublicKey",
      "v1CasPublicKey", "v1FloorPublicKey", "v2CasPublicKey", "v2FloorPublicKey"]);
    for (const [provided, candidate] of [
      ["ownerPublicKey", proof.ownerKey],
      ["archiveCheckpointPublicKey", proof.checkpointKey],
      ["v1CasPublicKey", proof.v1CasKey],
      ["v1FloorPublicKey", proof.v1FloorKey],
      ["v2CasPublicKey", proof.v2CasKey],
      ["v2FloorPublicKey", proof.v2FloorKey],
    ]) if (!same(fp(key(operatorPins[provided])), fp(key(candidate)))) fail();
    const scope = scopeOf(proof.scope);
    if (!same(fp(key(proof.v2CasKey)), fp(casClient.publicKey))
      || !same(fp(key(proof.v2FloorKey)), fp(floorClient.publicKey))
      || !same(fp(key(proof.ownerKey)), canonical32(proof.independentSpkiPins.owner)))
      fail();
    const { verifyRolloverPreflight } =
      require("./zk1OpaqueCatalogV1RolloverPreflight");
    const archive = await verifyRolloverPreflight(proof);
    if (archive.sequence !== 128 || archive.archivesRetained !== 128
      || archive.v2WriteAuthorized !== false) fail();
    exact(suppliedConsent, LEGACY_MIGRATION_FIELDS);
    // The input may be held by a mutable UI/coordinator. Snapshot exactly
    // what was signed before the first asynchronous mTLS or witness check.
    const ownerConsent = JSON.parse(JSON.stringify(suppliedConsent));
    exact(ownerConsent, LEGACY_MIGRATION_FIELDS);
    const consent = Buffer.from(JSON.stringify(ownerConsent));
    const signature = bytes(ownerSignature, 64);
    const now = Math.floor(Date.now() / 1000);
    if (ownerConsent.type !== "rootark-opaque-checkpoint-v2-legacy-archive-migration/v1"
      || !SCOPE.every((field) => ownerConsent[field] === scope[field].toString("base64url"))
      || !same(canonical32(ownerConsent.legacy_base_digest), canonical32(archive.digest))
      || !same(canonical32(ownerConsent.full_archive_root), canonical32(archive.archiveRoot))
      || !same(canonical32(ownerConsent.full_archive_checkpoint),
        canonical32(archive.checkpointDigest))
      || !same(canonical32(ownerConsent.cas_signer_fp), fp(casClient.publicKey))
      || !same(canonical32(ownerConsent.floor_signer_fp), fp(floorClient.publicKey))
      || ownerConsent.owner_revision !== proof.ownerHead.revision
      || !same(canonical32(ownerConsent.owner_digest), bytes(proof.ownerHead.digest, 32))
      || ownerConsent.owner_epoch !== proof.ownerHead.epoch
      || !Number.isSafeInteger(ownerConsent.issued_at)
      || !Number.isSafeInteger(ownerConsent.expires_at)
      || ownerConsent.issued_at < 1 || ownerConsent.issued_at > now + 30
      || ownerConsent.expires_at <= ownerConsent.issued_at
      || ownerConsent.expires_at - ownerConsent.issued_at > 300
      || !crypto.verify(null, Buffer.concat([LEGACY_MIGRATION_DOMAIN, consent]),
        key(proof.ownerKey), signature)) fail();
    canonical32(ownerConsent.nonce);
    const consentHash = hash(LEGACY_MIGRATION_DOMAIN, consent, signature);
    const expected = { legacy_base_digest: canonical32(ownerConsent.legacy_base_digest),
      legacy_base_checkpoint: canonical32(ownerConsent.legacy_base_checkpoint),
      legacy_head_digest: canonical32(ownerConsent.legacy_head_digest),
      legacy_checkpoint_digest: canonical32(ownerConsent.legacy_checkpoint_digest),
      legacy_operation_id: canonical32(ownerConsent.legacy_operation_id),
      full_archive_root: canonical32(ownerConsent.full_archive_root),
      full_archive_checkpoint: canonical32(ownerConsent.full_archive_checkpoint),
      owner_consent_hash: consentHash };
    if (same(expected.legacy_base_checkpoint, expected.full_archive_checkpoint)
      || ownerConsent.legacy_sequence < 128
      || ownerConsent.legacy_sequence > 128 + MAX_LEGACY_READBACK_TRANSITIONS
      || (ownerConsent.legacy_sequence === 128
        && !same(expected.legacy_operation_id, ZERO))) fail();
    const checkedReadback = async () => {
      const challenges = [crypto.randomBytes(32), crypto.randomBytes(32)];
      const clients = [casClient, floorClient];
      const seen = await Promise.all(clients.map((client, i) =>
        client.legacyArchiveReadback(challenges[i])));
      for (const [i, report] of seen.entries()) {
        const identity = { scope, signer: clients[i].publicKey,
          role: i ? ROLE_FLOOR : ROLE_CAS,
          casFp: fp(casClient.publicKey), floorFp: fp(floorClient.publicKey),
          nonce: challenges[i] };
        // Re-verify the raw cryptographic bytes even if a client object
        // has been mutated after its TLS / Ed25519 verification.
        const result = await inspectLegacyArchiveReadback(report.raw, identity);
        if (result.legacy_sequence !== ownerConsent.legacy_sequence
          || Object.entries(expected).some(([name, value]) =>
            !same(bytes(result[name], 32), value))) fail();
      }
    };
    await checkedReadback();
    const assertOwnerCurrent = async () => {
      const challenge = crypto.randomBytes(32);
      const fresh = bytes(await ownerTrust.freshWitnessHead({
        scope, nonce: challenge }), 1, 8192);
      await inspectVerifiedWitnessFreshHeadV1({
        raw: fresh, scope, nonce: challenge,
        pinned: ownerTrust.pinnedWitness, minimumHead: ownerTrust.minimumHead });
      const witnessed = await z.decodeDeterministic(fresh);
      if (Math.abs(Math.floor(Date.now() / 1000) - witnessed.observed_at) > 30
        || witnessed.current_revision !== ownerConsent.owner_revision
        || !same(bytes(witnessed.current_manifest_digest, 32),
          canonical32(ownerConsent.owner_digest))) fail();
    };
    await assertOwnerCurrent();
    await checkedReadback();
    // A real signed V1 provider rollback between the initial archive proof
    // and stage interrogation must not be hidden by otherwise valid V2
    // operator receipts. Repeat the two V1 remote heads at the end.
    const finalArchive = await verifyRolloverPreflight(proof);
    if (finalArchive.sequence !== 128 || finalArchive.archivesRetained !== 128
      || !same(canonical32(finalArchive.archiveRoot),
        expected.full_archive_root)
      || !same(canonical32(finalArchive.checkpointDigest),
        expected.full_archive_checkpoint)) fail();
    await checkedReadback();
    // A revocation can commit while HTTPS stage or full-128 reads are in
    // flight. Rechallenge the independent owner witness AFTER the final
    // signed readback, before reporting current-owner verification.
    // This still does not provide a distributed atomic cutover fence.
    await assertOwnerCurrent();
    return Object.freeze({ state: "LEGACY_DUAL_ARCHIVE_SIGNED_READBACK_ONLY",
      legacySequence: ownerConsent.legacy_sequence,
      fullArchiveRoot: ownerConsent.full_archive_root,
      fullArchiveCheckpoint: ownerConsent.full_archive_checkpoint,
      v2WriteAuthorized: false, restoreAuthorized: false,
      destructiveCutoverAuthorized: false,
      independentMonotonicStageWitnessProven: false,
      externalProviderDurabilityProven: false });
  } catch (_) { fail("ZK_CHECKPOINT_V2_LEGACY_READBACK_UNVERIFIED"); }
}

function createOpaqueCheckpointV2Coordinator({ casClient, floorClient,
  trustedScope, expectedV1Digest, expectedV1Checkpoint,
  v1CasClient, v1FloorClient, requireFullV1ArchiveRollover = false,
  fullV1ArchiveRollover, pinnedOwnerPublicKey, pinnedCheckpointPublicKey,
  requiredV2FloorClient = null }) {
  if (!pinnedV2Clients.has(casClient) || casClient.role !== ROLE_CAS
    || !pinnedV2Clients.has(floorClient) || floorClient.role !== ROLE_FLOOR
    || same(fp(casClient.publicKey), fp(floorClient.publicKey))
    || !v1CasClient || typeof v1CasClient.readHead !== "function"
    || !isZk1OpaqueCatalogIndependentFloorClient(v1FloorClient)
    || same(fp(key(v1CasClient.publicKey)), fp(key(v1FloorClient.publicKey)))
    || (requiredV2FloorClient !== null
      && !(requiredV2FloorClient instanceof Zk1V2CheckpointFloorHttpsClient))) fail();
  const scope = scopeOf(trustedScope);
  const oldDigest = bytes(expectedV1Digest, 32);
  const oldCheckpoint = bytes(expectedV1Checkpoint, 32);
  // Opt-in strict transition for newly owner-pinned FULL 1..128 baselines.
  // The legacy single-head #128 predecessor remains DEV/NO-GO; never treat
  // its independently signed digest as proof of the complete V1 archive.
  if (typeof requireFullV1ArchiveRollover !== "boolean"
    || (requireFullV1ArchiveRollover !== !!fullV1ArchiveRollover)) fail();
  // Strict admission must bind the handoff to the V2 client's independently
  // configured owner and checkpoint keys. Pins carried by the handoff itself
  // cannot establish either trusted identity.
  const strictOwnerFp = requireFullV1ArchiveRollover
    ? fp(key(pinnedOwnerPublicKey)) : null;
  const strictCheckpointFp = requireFullV1ArchiveRollover
    ? fp(key(pinnedCheckpointPublicKey)) : null;
  async function assertFullArchive() {
    if (!requireFullV1ArchiveRollover) fail("ZK_CHECKPOINT_V2_FULL_ARCHIVE_REQUIRED");
    const proof = fullV1ArchiveRollover;
    try {
      if (!proof || !proof.scope || SCOPE.some((field) =>
        !same(bytes(proof.scope[field], scope[field].length), scope[field]))
        || proof.v1CasClient !== v1CasClient || proof.v1FloorClient !== v1FloorClient
        || !same(fp(key(proof.v1CasKey)), fp(key(v1CasClient.publicKey)))
        || !same(fp(key(proof.v1FloorKey)), fp(key(v1FloorClient.publicKey)))
        || !same(fp(key(proof.v2CasKey)), fp(key(casClient.publicKey)))
        || !same(fp(key(proof.v2FloorKey)), fp(key(floorClient.publicKey)))
        || !same(fp(key(proof.ownerKey)), strictOwnerFp)
        || !same(fp(key(proof.v2CheckpointKey)), strictCheckpointFp)
        || !same(bytes(Buffer.from(proof.v2PredecessorCheckpointPin, "base64url"), 32),
          oldCheckpoint)) fail();
      const { verifyRolloverPreflight } =
        require("./zk1OpaqueCatalogV1RolloverPreflight");
      const checked = await verifyRolloverPreflight(proof);
      if (checked.sequence !== 128 || checked.archivesRetained !== 128
        || checked.v2WriteAuthorized !== false
        || !same(bytes(Buffer.from(checked.digest, "base64url"), 32), oldDigest)
        || !same(bytes(Buffer.from(checked.checkpointDigest, "base64url"), 32),
          oldCheckpoint)) fail();
      return checked;
    } catch (_) { fail("ZK_CHECKPOINT_V2_FULL_ARCHIVE_UNVERIFIED"); }
  }
  async function verifyFullArchiveBaseline() {
    const checked = await assertFullArchive();
    const heads = await Promise.all([casClient.head(), floorClient.head()]);
    assertFullBaselineHeads(heads);
    return Object.freeze({ sequence: checked.sequence, archiveRoot: checked.archiveRoot,
      checkpointDigest: checked.checkpointDigest, v2WriteAuthorized: false });
  }
  function assertFullBaselineHeads(heads) {
    if (heads.some((head) => head.state !== "V1_BASELINE"
      || head.sequence !== 128 || !same(bytes(head.headDigest, 32), oldDigest)
      || !same(bytes(head.checkpointDigest, 32), oldCheckpoint))) {
      fail("ZK_CHECKPOINT_V2_FULL_ARCHIVE_BASELINE_CONFLICT");
    }
  }
  async function verifyFullArchiveForLocalAdmission() {
    await assertV1Terminal();
    const checked = await assertFullArchive();
    const heads = await Promise.all([casClient.head(), floorClient.head()]);
    if (heads.some((head) => head.sequence === 128)) assertFullBaselineHeads(heads);
    else if (heads.some((head) => head.state !== "FINALIZED"
      || head.sequence < 129 || head.sequence > MAX_V2_SEQUENCE)
      || heads[0].sequence !== heads[1].sequence
      || !same(bytes(heads[0].checkpoint_digest, 32),
        bytes(heads[1].checkpoint_digest, 32))) {
      fail("ZK_CHECKPOINT_V2_FULL_ARCHIVE_BASELINE_CONFLICT");
    }
    return Object.freeze({ sequence: checked.sequence,
      checkpointDigest: checked.checkpointDigest, v2WriteAuthorized: false });
  }
  async function assertV1Terminal() {
    const nonce = crypto.randomBytes(32);
    const [casRaw, floor] = await Promise.all([
      v1CasClient.readHead({ scope, nonce }), v1FloorClient.readHead({ scope }),
    ]);
    const decoded = await z.decodeDeterministic(bytes(casRaw, 1, 4096));
    const fields = ["type", ...SCOPE, "sequence", "digest", "nonce", "observed_at"];
    exact(decoded, [...fields, "signature"]);
    const { signature, ...statement } = decoded;
    exact(statement, fields);
    matchesScope(statement, scope);
    if (statement.type !== "rootark-zk1-opaque-catalog-cas/v1"
      || statement.sequence !== 128 || floor.sequence !== 128
      || !same(bytes(statement.digest, 32), oldDigest)
      || !same(bytes(floor.digest, 32), oldDigest)
      || !same(bytes(statement.nonce, 32), nonce)
      || Math.abs(Date.now() / 1000 - num(statement.observed_at, 0)) > 30
      || !crypto.verify(null, Buffer.concat([
        catalogCasDomain, Buffer.from(await z.encodeDeterministic(statement))]),
      key(v1CasClient.publicKey), bytes(signature, 64))) fail("ZK_CHECKPOINT_V2_V1_TERMINAL_UNVERIFIED");
    const floorReceipt = await z.decodeDeterministic(bytes(floor.proof, 1, 4096));
    const floorFields = ["type", ...SCOPE, "cas_signer_spki_sha256",
      "sequence", "digest", "nonce", "observed_at"];
    exact(floorReceipt, [...floorFields, "signature"]);
    const { signature: floorSig, ...floorBody } = floorReceipt;
    matchesScope(floorBody, scope);
    if (floorBody.type !== "rootark-zk1-opaque-catalog-independent-floor/v1"
      || floorBody.sequence !== 128 || !same(bytes(floorBody.digest, 32), oldDigest)
      || !same(bytes(floorBody.cas_signer_spki_sha256, 32), fp(v1CasClient.publicKey))
      || Math.abs(Date.now() / 1000 - num(floorBody.observed_at, 0)) > 30
      || !crypto.verify(null, Buffer.concat([
        Buffer.from("Root.ark/zk-1/opaque-catalog-independent-floor/v1\0"),
        Buffer.from(await z.encodeDeterministic(floorBody))]),
      key(v1FloorClient.publicKey), bytes(floorSig, 64))) {
      fail("ZK_CHECKPOINT_V2_V1_TERMINAL_UNVERIFIED");
    }
  }
  async function confirmedState(raw) {
    const body = await z.decodeDeterministic(bytes(raw, 1, MAX_WIRE));
    const previousSequence = num(body.previous_sequence, 128, MAX_V2_SEQUENCE - 1);
    exact(body, previousSequence === 128 ? INTENT_FIELDS
      : [...INTENT_FIELDS, ...PREDECESSOR_FIELDS]);
    matchesScope(body, scope);
    const finalSequence = previousSequence + 1;
    if (!Array.isArray(body.records) || body.records.length !== 1
      || body.records[0].sequence !== finalSequence) fail();
    const op = bytes(body.operation_id, 32);
    const requestedCheckpoint = hash(
      Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-digest/v2\0"),
      bytes(body.checkpoint_bytes, 1, 16384), bytes(body.checkpoint_signature, 64));
    const headDigest = hash(
      Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0"),
      bytes(body.records?.[0]?.header, 1, 16384),
      bytes(body.records?.[0]?.signature, 64));
    const [cas, floor] = await Promise.all([casClient.head(), floorClient.head()]);
    for (const head of [cas, floor]) {
      if (head.sequence === previousSequence) {
        if (head.state !== (previousSequence === 128 ? "V1_BASELINE" : "FINALIZED")
          || !same(bytes(previousSequence === 128 ? head.headDigest : head.head_digest, 32),
            bytes(body.previous_digest, 32))
          || !same(bytes(previousSequence === 128 ? head.checkpointDigest : head.checkpoint_digest, 32),
            bytes(body.previous_checkpoint_digest, 32)))
          fail("ZK_CHECKPOINT_V2_BASELINE_CONFLICT");
      } else {
        if (head.sequence !== finalSequence
          || !same(bytes(head.checkpoint_digest, 32), requestedCheckpoint)
          || !same(bytes(head.head_digest, 32), headDigest)
          || !same(bytes(head.operation_id, 32), op)) fail("ZK_CHECKPOINT_V2_CONFLICT");
      }
    }
    return { cas, floor, previousSequence, finalSequence };
  }
  async function assertIndependentV2Floor(raw, states) {
    if (!requiredV2FloorClient) return;
    // This is a second signed readback gate for *already FINALIZED* CAS and
    // FLOOR. It is not a physical distributed admission fence and does not
    // imply any atomic transaction across three separate authorities.
    if (states.cas.sequence !== states.finalSequence
      || states.floor.sequence !== states.finalSequence
      || states.cas.state !== "FINALIZED" || states.floor.state !== "FINALIZED") {
      fail("ZK_CHECKPOINT_V2_INDEPENDENT_FLOOR_PENDING");
    }
    try {
      const body = await z.decodeDeterministic(bytes(raw, 1, MAX_WIRE));
      const header = await z.decodeDeterministic(bytes(body.records[0].header, 1, 16384));
      const remote = await requiredV2FloorClient.freshHead();
      const { receiptIdentityHash } = require("./zk1V2CheckpointRemoteFloor");
      const casReceiptHash = await receiptIdentityHash(states.cas.raw);
      const floorReceiptHash = await receiptIdentityHash(states.floor.raw);
      if (remote.sequence !== states.finalSequence || remote.epoch !== header.epoch
        || !same(remote.headDigest, bytes(states.cas.head_digest, 32))
        || !same(remote.checkpointDigest, bytes(states.cas.checkpoint_digest, 32))
        || !same(remote.operationId, bytes(body.operation_id, 32))
        || !same(remote.casReceiptIdentityHash, casReceiptHash)
        || !same(remote.floorReceiptIdentityHash, floorReceiptHash)) {
        fail("ZK_CHECKPOINT_V2_INDEPENDENT_FLOOR_MISMATCH");
      }
    } catch (_) { fail("ZK_CHECKPOINT_V2_INDEPENDENT_FLOOR_UNAVAILABLE"); }
  }
  async function reconcile(raw) {
    await assertV1Terminal();
    if (requireFullV1ArchiveRollover) {
      await assertFullArchive();
      const heads = await Promise.all([casClient.head(), floorClient.head()]);
      if (heads[0].sequence === 128 && heads[1].sequence === 128)
        assertFullBaselineHeads(heads);
      // Interrupted #129 writes are handled by confirmedState(), whose
      // immutable, signed predecessor digest remains pinned to the full 128.
    }
    // CAS_COMMITTED and FLOOR_PREPARED are durable, but NOT public until
    // FINALIZED on both independently signed authorities.
    let { cas, floor, previousSequence, finalSequence } = await confirmedState(raw);
    if (cas.sequence === finalSequence && floor.sequence === finalSequence
      && cas.state === "FINALIZED" && floor.state === "FINALIZED") {
      await assertIndependentV2Floor(raw, { cas, floor, previousSequence, finalSequence });
      return Object.freeze({ outcome: "V2_CHECKPOINT_BOTH_FINALIZED_LOCAL_ONLY",
        finalSequence, remoteCloudDurabilityProven: false,
        atomicCrossDatabaseTransactionProven: false, publishedToBrowser: false });
    }
    if (cas.sequence === previousSequence) {
      const prepared = floor.sequence === previousSequence
        ? await floorClient.prepare(raw) : floor;
      floor = prepared;
      cas = await casClient.commit(raw, prepared.raw);
    }
    if (cas.sequence === finalSequence && cas.state === "FINALIZED"
      && (floor.sequence !== finalSequence || floor.state !== "FINALIZED")) {
      fail("ZK_CHECKPOINT_V2_FLOOR_NOT_FINALIZED");
    }
    if (cas.sequence !== finalSequence
      || (cas.state !== "CAS_COMMITTED" && cas.state !== "FINALIZED")) fail();
    if (floor.sequence !== finalSequence || floor.state !== "FINALIZED")
      floor = await floorClient.finalize(cas.raw);
    if (cas.state !== "FINALIZED") cas = await casClient.attest(floor.raw);
    const checked = await confirmedState(raw);
    if (checked.cas.sequence !== finalSequence || checked.floor.sequence !== finalSequence
      || checked.cas.state !== "FINALIZED" || checked.floor.state !== "FINALIZED")
      fail("ZK_CHECKPOINT_V2_ACK_UNCERTAIN");
    await assertIndependentV2Floor(raw, checked);
    return Object.freeze({ outcome: "V2_CHECKPOINT_BOTH_FINALIZED_LOCAL_ONLY",
      finalSequence, remoteCloudDurabilityProven: false,
      atomicCrossDatabaseTransactionProven: false, publishedToBrowser: false });
  }
  return Object.freeze({
    publish: reconcile,
    reconcile,
    verifyFullArchiveBaseline,
    verifyFullArchiveForLocalAdmission,
    predecessorEndorsements: async (raw) => {
      await assertV1Terminal();
      if (requireFullV1ArchiveRollover) await assertFullArchive();
      const states = await confirmedState(raw);
      if (states.cas.sequence !== states.finalSequence
        || states.floor.sequence !== states.finalSequence
        || states.cas.state !== "FINALIZED" || states.floor.state !== "FINALIZED")
        fail("ZK_CHECKPOINT_V2_PENDING");
      await assertIndependentV2Floor(raw, states);
      return Object.freeze({ predecessor_cas_receipt: Buffer.from(states.cas.raw),
        predecessor_floor_receipt: Buffer.from(states.floor.raw) });
    },
    readConsistent: async (raw) => {
      await assertV1Terminal();
      if (requireFullV1ArchiveRollover) await assertFullArchive();
      const states = await confirmedState(raw);
      if (states.cas.sequence !== states.finalSequence
        || states.floor.sequence !== states.finalSequence
        || states.cas.state !== "FINALIZED" || states.floor.state !== "FINALIZED")
        fail("ZK_CHECKPOINT_V2_PENDING");
      await assertIndependentV2Floor(raw, states);
      return { sequence: states.finalSequence, checkpointDigest:
        Buffer.from(states.cas.checkpoint_digest), publishedToBrowser: false };
    },
  });
}

module.exports = { OpaqueCheckpointV2Authority, createOpaqueCheckpointV2HttpsServer,
  createOpaqueCheckpointV2HttpsClient, signCheckpointOwnerApprovalV2,
  createOpaqueCheckpointV2Coordinator, inspectIntent, receiptMatches,
  isOpaqueCheckpointV2PinnedClient, verifyLegacyArchiveDualReadback,
  inspectLegacyArchiveReadback };
