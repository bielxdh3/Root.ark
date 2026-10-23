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
const { catalogCasDomain } = require("./zk1OpaqueCatalog");
const ownerHistory = require("../crypto/rootark-zk-recovery-history-v2");
const ownerManifest = require("../crypto/rootark-zk-recovery-manifest-v2");
const { inspectVerifiedWitnessFreshHeadV1 } =
  require("../crypto/rootark-zk-witness-head-wire-v1");

const PREFIX = "Root.ark/zk-1/opaque-checkpoint-remote/";
const INTENT_DOMAIN = Buffer.from(PREFIX + "intent/v2\0");
const APPROVAL_DOMAIN = Buffer.from(PREFIX + "owner-approval/v2\0");
const RECEIPT_DOMAIN = Buffer.from(PREFIX + "receipt/v2\0");
const ROLE_CAS = "CAS";
const ROLE_FLOOR = "FLOOR";
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const INTENT_FIELDS = ["type", ...SCOPE, "operation_id", "checkpoint_bytes",
  "checkpoint_signature", "records", "previous_sequence",
  "previous_digest", "previous_checkpoint_digest", "owner_approval",
  "owner_signature", "owner_evidence"];
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
// A coordinator must never accept caller-supplied stand-ins whose head()
// advertises FINALIZED without independently verifying a remote receipt.
const pinnedV2Clients = new WeakSet();
const domain = (part) => Buffer.from(PREFIX + part + "/v2\0");

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
  return hash(key(value).export({ format: "der", type: "spki" }));
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
    fs.closeSync(fd);
  }
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

async function signCheckpointOwnerApprovalV2(statement, privateKey) {
  exact(statement, APPROVAL_FIELDS);
  const { type, ...rest } = statement;
  if (type !== "rootark-opaque-checkpoint-remote-owner-approval/v2") fail();
  scopeOf(Object.fromEntries(SCOPE.map((name) => [name, statement[name]])));
  num(rest.previous_sequence, 128, 128);
  num(rest.final_sequence, 129, 129);
  for (const field of ["operation_id", "checkpoint_digest", "previous_digest",
    "previous_checkpoint_digest", "final_digest", "cas_signer_fp",
    "floor_signer_fp", "checkpoint_signer_fp"]) bytes(rest[field], 32);
  num(statement.issued_at, 0);
  const raw = Buffer.from(await z.encodeDeterministic(statement));
  return { raw, signature: crypto.sign(null, Buffer.concat([APPROVAL_DOMAIN, raw]),
    key(privateKey, "private")) };
}

async function verifyOwnerRooted(intent, opts) {
  const approval = await z.decodeDeterministic(bytes(intent.owner_approval, 1, 4096));
  exact(approval, APPROVAL_FIELDS);
  if (approval.type !== "rootark-opaque-checkpoint-remote-owner-approval/v2") fail();
  matchesScope(approval, opts.scope);
  if (!crypto.verify(null, Buffer.concat([APPROVAL_DOMAIN, intent.owner_approval]),
    opts.ownerKey, bytes(intent.owner_signature, 64))) fail();
  if (approval.previous_sequence !== 128 || approval.final_sequence !== 129
    || !same(bytes(approval.operation_id, 32), intent.operation_id)
    || !same(bytes(approval.previous_digest, 32), intent.previous_digest)
    || !same(bytes(approval.previous_checkpoint_digest, 32), intent.previous_checkpoint_digest)
    || !same(bytes(approval.checkpoint_digest, 32), opts.checkpointDigest)
    || !same(bytes(approval.final_digest, 32), opts.finalDigest)
    || !same(bytes(approval.cas_signer_fp, 32), opts.casFp)
    || !same(bytes(approval.floor_signer_fp, 32), opts.floorFp)
    || !same(bytes(approval.checkpoint_signer_fp, 32), opts.checkpointFp)
    || Math.abs(Date.now() / 1000 - num(approval.issued_at, 0)) > 300) fail();
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
    || !same(bytes(live.current_manifest_digest, 32), verified.headDigest)
    || !seenWitness) fail();
  // Owner approval signer must itself be currently authorized by the
  // independently witnessed owner-recovery history. A merely supplied
  // Ed25519 public key cannot unilaterally declare itself the owner.
  const approvedOwnerSigner = verified.headManifest.devices.some((device) =>
    device.revoked_at_epoch === null
    && Number(device.enrolled_epoch) <= Number(verified.headManifest.current_epoch)
    && same(bytes(device.authorization_public_key, 32),
      opts.ownerKey.export({ type: "spki", format: "der" }).subarray(-32)));
  if (!approvedOwnerSigner) fail();
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
  return { signer, proof: verified };
}

async function inspectIntent(raw, opts, { freshOwner = true } = {}) {
  const body = await z.decodeDeterministic(bytes(raw, 1, MAX_WIRE));
  exact(body, INTENT_FIELDS);
  if (body.type !== "rootark-opaque-checkpoint-remote-intent/v2") fail();
  matchesScope(body, opts.scope);
  bytes(body.operation_id, 32);
  if (body.previous_sequence !== 128) fail();
  if (!Array.isArray(body.records) || body.records.length !== 1
    || body.records[0].sequence !== 129) fail();
  if (!same(bytes(body.previous_digest, 32), opts.baseDigest)
    || !same(bytes(body.previous_checkpoint_digest, 32), opts.baseCheckpoint)) fail();
  // Verify pinned owner root/witness *before* resolving historical signers.
  const checkpointDigest = hash(Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-digest/v2\0"),
    bytes(body.checkpoint_bytes, 1, 16384), bytes(body.checkpoint_signature, 64));
  const parsedHeader = await z.decodeDeterministic(body.records[0].header);
  const finalDigest = hash(Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0"),
    body.records[0].header, body.records[0].signature);
  let signer;
  if (freshOwner) ({ signer } = await verifyOwnerRooted(body, { ...opts,
    checkpointDigest, finalDigest }));
  else signer = key(opts.cachedSigner); // caller may only use for exact immutable reread
  const verified = await archiveV2.verifyAuthenticatedOpaqueCatalogArchiveV2({
    checkpointBytes: body.checkpoint_bytes,
    checkpointSignature: body.checkpoint_signature,
    pinnedCheckpointPublicKey: opts.checkpointKey, scope: opts.scope,
    records: body.records, previousSequence: 128,
    previousDigest: opts.baseDigest,
    previousCheckpointDigest: opts.baseCheckpoint,
    expectedFinalSequence: 129, expectedFinalDigest: finalDigest,
    resolveCatalogSigner: async (header) => {
      if (header.signer_device_id !== parsedHeader.signer_device_id) fail();
      return signer;
    },
  });
  return { body, raw: Buffer.from(raw), intentHash: hash(INTENT_DOMAIN, raw),
    operationId: bytes(body.operation_id, 32), checkpointDigest, finalDigest,
    verified, signerSpki: signer.export({ type: "spki", format: "der" }) };
}

class OpaqueCheckpointV2Authority {
  #settings;
  #db;
  #queue = Promise.resolve();
  constructor(filename, { role, bootstrapNew, scope, signingPrivateKey,
    casSignerPublicKey, floorSignerPublicKey, checkpointPublicKey,
    ownerPublicKey, ownerTrust, baseDigest, baseCheckpoint }) {
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
    const trust = {
      genesisDigest: bytes(ownerTrust.genesisDigest, 32),
      pinnedWitness: ownerTrust.pinnedWitness,
      minimumHead: ownerTrust.minimumHead,
      freshWitnessHead: ownerTrust.freshWitnessHead,
    };
    if (!trust.pinnedWitness || !trust.minimumHead) fail();
    fileSecurity(filename, bootstrapNew);
    const db = new Database(filename, { fileMustExist: true, timeout: 3000 });
    try {
      db.pragma("journal_mode = WAL");
      db.pragma("synchronous = FULL");
      db.exec(`
        CREATE TABLE IF NOT EXISTS config(
          marker INTEGER PRIMARY KEY CHECK(marker=1), role TEXT NOT NULL,
          scope TEXT NOT NULL, pins BLOB NOT NULL, base_digest BLOB NOT NULL,
          base_checkpoint BLOB NOT NULL, genesis_digest BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transitions(
          sequence INTEGER PRIMARY KEY CHECK(sequence=129),
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
      `);
      const conf = db.prepare("SELECT * FROM config").all();
      const scopeText = SCOPE.map((n) => scoped[n].toString("hex")).join(":");
      const allPins = Buffer.concat(pins);
      if (bootstrapNew) {
        if (conf.length || db.prepare("SELECT COUNT(*) as count FROM transitions").get().count) fail();
        db.prepare("INSERT INTO config VALUES (1,?,?,?,?,?,?)").run(role,
          scopeText, allPins, v1Digest, v1Checkpoint, trust.genesisDigest);
      } else if (conf.length !== 1 || conf[0].role !== role
        || conf[0].scope !== scopeText
        || !same(conf[0].pins, allPins)
        || !same(conf[0].base_digest, v1Digest)
        || !same(conf[0].base_checkpoint, v1Checkpoint)
        || !same(conf[0].genesis_digest, trust.genesisDigest)) fail();
      this.#db = db;
    } catch (error) { db.close(); throw error; }
    this.#settings = { role, signer, casKey, floorKey, checkpointKey, ownerKey,
      ownerTrust: trust, scope: scoped, casFp: pins[0], floorFp: pins[1],
      checkpointFp: pins[2], baseDigest: v1Digest, baseCheckpoint: v1Checkpoint };
  }
  get role() { return this.#settings.role; }
  get publicKey() { return crypto.createPublicKey(this.#settings.signer); }
  async #signed(row, state, nonce) {
    const s = this.#settings;
    const statement = { type: "rootark-opaque-checkpoint-remote-receipt/v2",
      ...s.scope, role: s.role, state,
      sequence: state === "V1_BASELINE" ? 128 : 129,
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
  #saved() { return this.#db.prepare("SELECT * FROM transitions WHERE sequence=129").get(); }
  async #inspect(row, freshness) {
    const s = this.#settings;
    if (!row) return null;
    if (!["PREPARED", "CAS_COMMITTED", "FINALIZED"].includes(row.state)
      || (s.role === ROLE_FLOOR && row.state === "CAS_COMMITTED")
      || (s.role === ROLE_CAS && row.state === "PREPARED")) fail();
    const inspected = await inspectIntent(row.intent, { ...s,
      cachedSigner: crypto.createPublicKey({ key: row.signer_spki,
        format: "der", type: "spki" }) }, { freshOwner: freshness });
    if (!same(inspected.intentHash, row.intent_hash)
      || !same(inspected.operationId, row.operation_id)
      || !same(inspected.checkpointDigest, row.checkpoint_digest)
      || !same(inspected.finalDigest, row.final_digest)
      || !same(inspected.signerSpki, row.signer_spki)) fail();
    const verifySavedReceipt = async (raw, role, state, signer) => {
      const statement = await z.decodeDeterministic(bytes(raw, 1, 4096));
      await receiptMatches(raw, { scope: s.scope, role, state, sequence: 129,
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
      const intent = await inspectIntent(raw, this.#settings);
      const row = this.#saved();
      if (row) {
        await this.#inspect(row, false);
        if (!same(row.intent_hash, intent.intentHash)) fail("ZK_CHECKPOINT_V2_CONFLICT");
        return this.#signed(row, row.state === "FINALIZED" ? "FINALIZED" : "PREPARED", nonce);
      }
      this.#db.prepare(`INSERT INTO transitions
        (sequence,intent_hash,operation_id,checkpoint_digest,final_digest,
        intent,signer_spki,state) VALUES (129,?,?,?,?,?,?,'PREPARED')`)
        .run(intent.intentHash, intent.operationId, intent.checkpointDigest,
          intent.finalDigest, intent.raw, intent.signerSpki);
      const saved = this.#saved();
      await this.#inspect(saved, false);
      return this.#signed(saved, "PREPARED", nonce);
    });
  }
  async commit(raw, floorPrepare, nonce) {
    if (this.role !== ROLE_CAS) fail();
    return this.#serial(async () => {
      const intent = await inspectIntent(raw, this.#settings);
      await receiptMatches(floorPrepare, { scope: this.#settings.scope,
        role: ROLE_FLOOR, sequence: 129,
        headDigest: intent.finalDigest, checkpointDigest: intent.checkpointDigest,
        operationId: intent.operationId, casFp: this.#settings.casFp,
        floorFp: this.#settings.floorFp, signer: this.#settings.floorKey,
        fresh: true });
      let row = this.#saved();
      if (row) {
        await this.#inspect(row, false);
        if (!same(row.intent_hash, intent.intentHash)) fail("ZK_CHECKPOINT_V2_CONFLICT");
      } else {
        this.#db.prepare(`INSERT INTO transitions
          (sequence,intent_hash,operation_id,checkpoint_digest,final_digest,intent,
          signer_spki,state,floor_prepare)
          VALUES(129,?,?,?,?,?,?,'CAS_COMMITTED',?)`)
          .run(intent.intentHash, intent.operationId, intent.checkpointDigest,
            intent.finalDigest, intent.raw, intent.signerSpki, floorPrepare);
        row = this.#saved();
      }
      return this.#signed(row, "CAS_COMMITTED", nonce);
    });
  }
  async finalize(casCommit, nonce) {
    if (this.role !== ROLE_FLOOR) fail();
    return this.#serial(async () => {
      const row = this.#saved();
      if (!row) fail("ZK_CHECKPOINT_V2_CONFLICT");
      await this.#inspect(row, false);
      await receiptMatches(casCommit, { scope: this.#settings.scope,
        role: ROLE_CAS, state: "CAS_COMMITTED", sequence: 129,
        headDigest: row.final_digest, checkpointDigest: row.checkpoint_digest,
        operationId: row.operation_id, casFp: this.#settings.casFp,
        floorFp: this.#settings.floorFp, signer: this.#settings.casKey,
        fresh: true });
      if (row.state === "PREPARED") this.#db.prepare(`UPDATE transitions
        SET state='FINALIZED',cas_commit=? WHERE sequence=129 AND state='PREPARED'`)
        .run(casCommit);
      return this.#signed(this.#saved(), "FINALIZED", nonce);
    });
  }
  async attestFinalized(floorFinalized, nonce) {
    if (this.role !== ROLE_CAS) fail();
    return this.#serial(async () => {
      const row = this.#saved();
      if (!row) fail("ZK_CHECKPOINT_V2_CONFLICT");
      await this.#inspect(row, false);
      await receiptMatches(floorFinalized, { scope: this.#settings.scope,
        role: ROLE_FLOOR, state: "FINALIZED", sequence: 129,
        headDigest: row.final_digest, checkpointDigest: row.checkpoint_digest,
        operationId: row.operation_id, casFp: this.#settings.casFp,
        floorFp: this.#settings.floorFp, signer: this.#settings.floorKey,
        fresh: true });
      if (row.state === "CAS_COMMITTED") this.#db.prepare(`UPDATE transitions
        SET state='FINALIZED', floor_finalize=?
        WHERE sequence=129 AND state='CAS_COMMITTED'`).run(floorFinalized);
      return this.#signed(this.#saved(), "FINALIZED", nonce);
    });
  }
  async head(nonce) {
    return this.#serial(async () => {
      const row = this.#saved();
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
      await this.#inspect(row, false);
      return { state: row.state, sequence: 129, headDigest: Buffer.from(row.final_digest),
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
        || !["/v2/prepare", "/v2/commit", "/v2/finalize", "/v2/attest", "/v2/head"]
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
      sequence: 129, headDigest: data.head_digest,
      checkpointDigest: data.checkpoint_digest, operationId: data.operation_id,
      casFp, floorFp, signer, nonce, fresh: true });
    if (route === "/v2/head") {
      if (outcome.sequence !== 129
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
  });
  pinnedV2Clients.add(client);
  return client;
}
function isOpaqueCheckpointV2PinnedClient(client) {
  return pinnedV2Clients.has(client);
}

function createOpaqueCheckpointV2Coordinator({ casClient, floorClient,
  trustedScope, expectedV1Digest, expectedV1Checkpoint,
  v1CasClient, v1FloorClient }) {
  if (!pinnedV2Clients.has(casClient) || casClient.role !== ROLE_CAS
    || !pinnedV2Clients.has(floorClient) || floorClient.role !== ROLE_FLOOR
    || same(fp(casClient.publicKey), fp(floorClient.publicKey))
    || !v1CasClient || typeof v1CasClient.readHead !== "function"
    || !isZk1OpaqueCatalogIndependentFloorClient(v1FloorClient)
    || same(fp(key(v1CasClient.publicKey)), fp(key(v1FloorClient.publicKey)))) fail();
  const scope = scopeOf(trustedScope);
  const oldDigest = bytes(expectedV1Digest, 32);
  const oldCheckpoint = bytes(expectedV1Checkpoint, 32);
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
    exact(body, INTENT_FIELDS);
    matchesScope(body, scope);
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
      if (head.sequence === 128) {
        if (head.state !== "V1_BASELINE"
          || !same(head.headDigest, oldDigest)
          || !same(head.checkpointDigest, oldCheckpoint)) fail("ZK_CHECKPOINT_V2_BASELINE_CONFLICT");
      } else {
        if (head.sequence !== 129
          || !same(bytes(head.checkpoint_digest, 32), requestedCheckpoint)
          || !same(bytes(head.head_digest, 32), headDigest)
          || !same(bytes(head.operation_id, 32), op)) fail("ZK_CHECKPOINT_V2_CONFLICT");
      }
    }
    return { cas, floor };
  }
  async function reconcile(raw) {
    await assertV1Terminal();
    // CAS_COMMITTED and FLOOR_PREPARED are durable, but NOT public until
    // FINALIZED on both independently signed authorities.
    let { cas, floor } = await confirmedState(raw);
    if (cas.state === "FINALIZED" && floor.state === "FINALIZED") {
      return Object.freeze({ outcome: "V2_CHECKPOINT_BOTH_FINALIZED_LOCAL_ONLY",
        finalSequence: 129, remoteCloudDurabilityProven: false,
        atomicCrossDatabaseTransactionProven: false, publishedToBrowser: false });
    }
    if (cas.sequence === 128) {
      const prepared = floor.sequence === 128
        ? await floorClient.prepare(raw) : floor;
      cas = await casClient.commit(raw, prepared.raw);
    }
    if (cas.state === "FINALIZED" && floor.state !== "FINALIZED") {
      fail("ZK_CHECKPOINT_V2_FLOOR_NOT_FINALIZED");
    }
    if (cas.state !== "CAS_COMMITTED" && cas.state !== "FINALIZED") fail();
    if (floor.state !== "FINALIZED") floor = await floorClient.finalize(cas.raw);
    if (cas.state !== "FINALIZED") cas = await casClient.attest(floor.raw);
    const checked = await confirmedState(raw);
    if (checked.cas.state !== "FINALIZED" || checked.floor.state !== "FINALIZED")
      fail("ZK_CHECKPOINT_V2_ACK_UNCERTAIN");
    return Object.freeze({ outcome: "V2_CHECKPOINT_BOTH_FINALIZED_LOCAL_ONLY",
      finalSequence: 129, remoteCloudDurabilityProven: false,
      atomicCrossDatabaseTransactionProven: false, publishedToBrowser: false });
  }
  return Object.freeze({
    publish: reconcile,
    reconcile,
    readConsistent: async (raw) => {
      await assertV1Terminal();
      const states = await confirmedState(raw);
      if (states.cas.state !== "FINALIZED" || states.floor.state !== "FINALIZED")
        fail("ZK_CHECKPOINT_V2_PENDING");
      return { sequence: 129, checkpointDigest:
        Buffer.from(states.cas.checkpoint_digest), publishedToBrowser: false };
    },
  });
}

module.exports = { OpaqueCheckpointV2Authority, createOpaqueCheckpointV2HttpsServer,
  createOpaqueCheckpointV2HttpsClient, signCheckpointOwnerApprovalV2,
  createOpaqueCheckpointV2Coordinator, inspectIntent, receiptMatches,
  isOpaqueCheckpointV2PinnedClient };
