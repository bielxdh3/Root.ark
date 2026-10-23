"use strict";

// Opt-in, LOCAL STAGING ONLY. Never calls CAS/floor compareAndSwap; never
// authorizes a browser write, recovery, publication, or sequence >128.
// Independent authorities remain on their existing pinned mTLS v1 endpoints.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const {
  verifyAuthenticatedOpaqueCatalogArchiveV2,
} = require("../crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const { isZk1OpaqueCatalogIndependentFloorClient } =
  require("./zk1OpaqueCatalogIndependentFloor");
const { catalogCasDomain } = require("./zk1OpaqueCatalog");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile } =
  require("./zk1PrivateSqlitePath");
const { assertSafeSqliteSidecars, requireCheckpointV2Triggers,
  withReadonlySqliteSnapshot } =
  require("./zk1OpaqueCheckpointV2SqliteGuard");

const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-owner-approval/v2\0");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-independent-floor/v1\0");
const PAYLOAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-stage-payload/v2\0");
const TYPE = "rootark-zk1-opaque-catalog-checkpoint-owner-approval/v2";
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const OWNER_FIELDS = ["type", ...SCOPE, "checkpoint_digest",
  "previous_sequence", "previous_checkpoint_digest", "final_sequence",
  "final_digest", "cas_signer_spki_sha256", "floor_signer_spki_sha256",
  "checkpoint_signer_spki_sha256", "nonce", "issued_at"];
const CAS_FIELDS = ["type", ...SCOPE, "sequence", "digest", "nonce", "observed_at"];
const FLOOR_FIELDS = ["type", ...SCOPE, "cas_signer_spki_sha256",
  "sequence", "digest", "nonce", "observed_at"];
const PAYLOAD_FIELDS = ["type", "checkpoint_bytes", "checkpoint_signature",
  "records", "previous_sequence", "previous_digest",
  "previous_checkpoint_digest", "owner_approval_bytes", "owner_approval_signature"];
const MAX_BUNDLE = 9 * 1024 * 1024;
const ZERO = Buffer.alloc(32);
const MAX_V1_SEQUENCE = 128;
const STAGE_SCHEMA = `
        CREATE TABLE IF NOT EXISTS stage_config (
          scope TEXT PRIMARY KEY, owner_fp BLOB NOT NULL, checkpoint_fp BLOB NOT NULL,
          cas_fp BLOB NOT NULL, floor_fp BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS checkpoint_stages (
          final_sequence INTEGER PRIMARY KEY,
          checkpoint_digest BLOB NOT NULL UNIQUE,
          payload_digest BLOB NOT NULL, payload BLOB NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PENDING','STAGED')),
          cas_proof BLOB, floor_proof BLOB, cas_nonce BLOB,
          CHECK ((status='PENDING' AND cas_proof IS NULL
            AND floor_proof IS NULL AND cas_nonce IS NULL)
            OR (status='STAGED' AND cas_proof IS NOT NULL
            AND floor_proof IS NOT NULL AND cas_nonce IS NOT NULL))
        );
        CREATE TRIGGER IF NOT EXISTS checkpoint_stage_no_delete
          BEFORE DELETE ON checkpoint_stages BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
        CREATE TRIGGER IF NOT EXISTS checkpoint_stage_no_rewrite
          BEFORE UPDATE ON checkpoint_stages WHEN
            OLD.status!='PENDING' OR NEW.status!='STAGED'
            OR OLD.final_sequence!=NEW.final_sequence
            OR OLD.checkpoint_digest!=NEW.checkpoint_digest
            OR OLD.payload_digest!=NEW.payload_digest
            OR OLD.payload!=NEW.payload
          BEGIN SELECT RAISE(ABORT,'IMMUTABLE_CHECKPOINT'); END;
        CREATE TRIGGER IF NOT EXISTS checkpoint_stage_config_no_update
          BEFORE UPDATE ON stage_config BEGIN SELECT RAISE(ABORT,'PIN_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS checkpoint_stage_config_no_delete
          BEFORE DELETE ON stage_config BEGIN SELECT RAISE(ABORT,'PIN_IMMUTABLE'); END;
      `;
const STAGE_TRIGGERS = [
  ["checkpoint_stage_no_delete", "checkpoint_stages"],
  ["checkpoint_stage_no_rewrite", "checkpoint_stages"],
  ["checkpoint_stage_config_no_update", "stage_config"],
  ["checkpoint_stage_config_no_delete", "stage_config"],
];
function fail(code = "ZK_OPAQUE_CHECKPOINT_STAGE_DENIED") {
  const error = new Error(code); error.code = code; throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
  return value;
}
function bytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}
function integer(value, min, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail();
  return value;
}
function same(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function sha(...parts) {
  const h = crypto.createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
}
function key(input, role) {
  if (!(input instanceof crypto.KeyObject)
    || input.type !== role || input.asymmetricKeyType !== "ed25519") fail();
  return input;
}
function pin(input) {
  return sha(key(input, "public").export({ type: "spki", format: "der" }));
}
function scopeBytes(input) {
  exact(input, SCOPE);
  return Object.fromEntries(SCOPE.map((name) => [name,
    bytes(input[name], name === "compartment_id" ? 1 : 16,
      name === "compartment_id" ? 128 : 16)]));
}
function scopeId(scope) {
  return SCOPE.map((field) => scope[field].toString("hex")).join(":");
}
function sameScope(a, b) {
  return SCOPE.every((field) => same(bytes(a[field],
    field === "compartment_id" ? 1 : 16, field === "compartment_id" ? 128 : 16),
  b[field]));
}
function ownerMessage(statement) {
  exact(statement, OWNER_FIELDS);
  if (statement.type !== TYPE) fail();
  return statement;
}
async function createSignedOpaqueCheckpointOwnerApprovalV2(statement, ownerPrivateKey) {
  const scoped = scopeBytes(Object.fromEntries(SCOPE.map((field) => [field, statement[field]])));
  const normalized = ownerMessage({ ...statement, ...scoped });
  integer(normalized.previous_sequence, 0, 127);
  integer(normalized.final_sequence, normalized.previous_sequence + 1, 128);
  integer(normalized.issued_at, 0);
  for (const field of ["checkpoint_digest", "previous_checkpoint_digest",
    "final_digest", "cas_signer_spki_sha256", "floor_signer_spki_sha256",
    "checkpoint_signer_spki_sha256", "nonce"]) bytes(normalized[field], 32);
  const approvalBytes = Buffer.from(await z.encodeDeterministic(normalized));
  const approvalSignature = crypto.sign(null, Buffer.concat([OWNER_DOMAIN, approvalBytes]),
    key(ownerPrivateKey, "private"));
  return { approvalBytes, approvalSignature };
}
function fileCheck(filename, bootstrapNew) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) fail();
  const folder = fs.lstatSync(path.dirname(filename));
  if (!folder.isDirectory() || folder.isSymbolicLink()
    || (process.platform !== "win32"
    && (folder.uid !== process.getuid() || (folder.mode & 0o077)))) fail();
  const exists = fs.existsSync(filename);
  if (bootstrapNew !== !exists) fail();
  if (exists) {
    const stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || (process.platform !== "win32"
      && (stat.uid !== process.getuid() || (stat.mode & 0o077)))) fail();
  } else {
    const handle = fs.openSync(filename, fs.constants.O_CREAT | fs.constants.O_EXCL
      | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
    try {
      // Pin the file created by O_EXCL while its handle is still open. A
      // pathname lookup after close could instead pin a single-link SQLite
      // swapped in by another actor, then write WAL/schema to that database.
      const stat = fs.fstatSync(handle, { bigint: true });
      if (!stat.isFile() || stat.nlink !== 1n) fail();
      return Object.freeze({ dev: stat.dev, ino: stat.ino });
    } finally { fs.closeSync(handle); }
  }
}
function verifyStageIdentity(db, id, pins) {
  requireCheckpointV2Triggers(db, STAGE_SCHEMA, STAGE_TRIGGERS, fail);
  const saved = db.prepare("SELECT * FROM stage_config").all();
  if (saved.length !== 1 || saved[0].scope !== id
    || !["owner_fp", "checkpoint_fp", "cas_fp", "floor_fp"]
      .every((field, i) => Buffer.isBuffer(saved[0][field])
        && same(saved[0][field], pins[i]))) fail();
}
class Zk1OpaqueCatalogCheckpointV2Stage {
  #serialized = Promise.resolve();
  #scope;
  #id;
  #ownerPublicKey;
  #checkpointPublicKey;
  #casPublicKey;
  #floorPublicKey;
  #pins;
  #casClient;
  #floorClient;
  #resolveCatalogSigner;
  #queue(action) {
    const result = this.#serialized.then(action);
    this.#serialized = result.catch(() => {});
    return result;
  }
  constructor(filename, { bootstrapNew, trustedScope, ownerPublicKey,
    checkpointPublicKey, casClient, floorClient, resolveCatalogSigner }) {
    if (typeof bootstrapNew !== "boolean"
      || typeof resolveCatalogSigner !== "function"
      || !casClient || typeof casClient.readHead !== "function"
      || !isZk1OpaqueCatalogIndependentFloorClient(floorClient)) fail();
    this.#scope = scopeBytes(trustedScope);
    this.#id = scopeId(this.#scope);
    this.#ownerPublicKey = key(ownerPublicKey, "public");
    this.#checkpointPublicKey = key(checkpointPublicKey, "public");
    this.#casPublicKey = key(casClient.publicKey, "public");
    this.#floorPublicKey = key(floorClient.publicKey, "public");
    this.#pins = [this.#ownerPublicKey, this.#checkpointPublicKey,
      this.#casPublicKey, this.#floorPublicKey].map(pin);
    if (new Set(this.#pins.map((item) => item.toString("hex"))).size !== 4) fail();
    this.#casClient = casClient;
    this.#floorClient = floorClient;
    this.#resolveCatalogSigner = resolveCatalogSigner;
    if (typeof filename !== "string" || !path.isAbsolute(filename)
      || !fs.existsSync(path.dirname(filename))) fail();
    if (bootstrapNew) ensurePrivateSqliteDirectory(filename);
    else assertPrivateSqliteFile(filename);
    assertSafeSqliteSidecars(filename, fail);
    const createdPin = fileCheck(filename, bootstrapNew);
    // Validate even the trigger bodies in read-only mode before SQLite can
    // change WAL, create a schema object, or touch the wrong authority's DB.
    const pinned = bootstrapNew ? createdPin
      : withReadonlySqliteSnapshot(filename,
        (probe) => verifyStageIdentity(probe, this.#id, this.#pins), fail,
        MAX_V1_SEQUENCE * MAX_BUNDLE + 64 * 1024 * 1024);
    const beforeOpen = assertPrivateSqliteFile(filename);
    if (beforeOpen.dev !== pinned.dev || beforeOpen.ino !== pinned.ino) fail();
    assertSafeSqliteSidecars(filename, fail);
    this.db = new Database(filename, { fileMustExist: true, timeout: 3000 });
    try {
      const opened = assertPrivateSqliteFile(filename);
      if (opened.dev !== pinned.dev || opened.ino !== pinned.ino) fail();
      assertSafeSqliteSidecars(filename, fail);
      if (!bootstrapNew) verifyStageIdentity(this.db, this.#id, this.#pins);
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = FULL");
      this.db.pragma("foreign_keys = ON");
      if (bootstrapNew) this.db.exec(STAGE_SCHEMA);
      const saved = this.db.prepare("SELECT * FROM stage_config").all();
      if (bootstrapNew) {
        if (saved.length || this.db.prepare("SELECT COUNT(*) AS n FROM checkpoint_stages").get().n) fail();
        this.db.prepare(`INSERT INTO stage_config
          (scope, owner_fp, checkpoint_fp, cas_fp, floor_fp) VALUES (?,?,?,?,?)`)
          .run(this.#id, ...this.#pins);
      }
    } catch (error) { this.db.close(); throw error; }
  }
  async #verifyOwner(raw, signature, verified, requireFresh) {
    const approvalBytes = bytes(raw, 1, 4096);
    const sig = bytes(signature, 64);
    if (!crypto.verify(null, Buffer.concat([OWNER_DOMAIN, approvalBytes]),
      this.#ownerPublicKey, sig)) fail();
    const statement = ownerMessage(await z.decodeDeterministic(approvalBytes));
    if (!sameScope(statement, this.#scope)
      || !same(bytes(statement.checkpoint_digest, 32), verified.checkpointDigest)
      || statement.previous_sequence !== verified.previousSequence
      || statement.final_sequence !== verified.finalSequence
      || !same(bytes(statement.previous_checkpoint_digest, 32),
        verified.previousCheckpointDigest)
      || !same(bytes(statement.final_digest, 32), verified.finalDigest)
      || !same(bytes(statement.cas_signer_spki_sha256, 32), this.#pins[2])
      || !same(bytes(statement.floor_signer_spki_sha256, 32), this.#pins[3])
      || !same(bytes(statement.checkpoint_signer_spki_sha256, 32), this.#pins[1])) fail();
    bytes(statement.nonce, 32);
    integer(statement.issued_at, 0);
    if (requireFresh && Math.abs(Date.now() / 1000 - statement.issued_at) > 300) fail();
  }
  async #decodePayload(raw, requireFresh = false) {
    const payload = await z.decodeDeterministic(bytes(raw, 1, MAX_BUNDLE));
    exact(payload, PAYLOAD_FIELDS);
    if (payload.type !== "rootark-zk1-opaque-catalog-stage-payload/v2") fail();
    const verified = await verifyAuthenticatedOpaqueCatalogArchiveV2({
      checkpointBytes: bytes(payload.checkpoint_bytes, 1, 16384),
      checkpointSignature: bytes(payload.checkpoint_signature, 64),
      pinnedCheckpointPublicKey: this.#checkpointPublicKey,
      scope: this.#scope, records: payload.records,
      previousSequence: payload.previous_sequence,
      previousDigest: bytes(payload.previous_digest, 32),
      previousCheckpointDigest: bytes(payload.previous_checkpoint_digest, 32),
      resolveCatalogSigner: this.#resolveCatalogSigner,
    });
    // It is physically impossible to stage v2 publication 129 here; v1
    // authorities continue their original hard ceiling.
    if (verified.finalSequence > MAX_V1_SEQUENCE) fail();
    const normalized = { ...verified,
      previousCheckpointDigest: bytes(payload.previous_checkpoint_digest, 32) };
    await this.#verifyOwner(payload.owner_approval_bytes,
      payload.owner_approval_signature, normalized, requireFresh);
    return normalized;
  }
  async #verifyAuthority(raw, signer, domain, expected, casNonce, freshness) {
    const proof = await z.decodeDeterministic(bytes(raw, 1, 4096));
    const fields = domain === FLOOR_DOMAIN ? FLOOR_FIELDS : CAS_FIELDS;
    exact(proof, [...fields, "signature"]);
    const { signature, ...statement } = proof;
    const expectedType = domain === FLOOR_DOMAIN
      ? "rootark-zk1-opaque-catalog-independent-floor/v1"
      : "rootark-zk1-opaque-catalog-cas/v1";
    if (statement.type !== expectedType || !sameScope(statement, this.#scope)
      || statement.sequence !== expected.finalSequence
      || !same(bytes(statement.digest, 32), expected.finalDigest)
      || (domain === FLOOR_DOMAIN && !same(
        bytes(statement.cas_signer_spki_sha256, 32), this.#pins[2]))
      || (casNonce !== undefined
      && !same(bytes(statement.nonce, 32), casNonce))
      || (domain === FLOOR_DOMAIN
      && !same(bytes(statement.nonce, 32), expected.floorNonce))
      || !crypto.verify(null, Buffer.concat([domain,
        Buffer.from(await z.encodeDeterministic(statement))]), signer,
      bytes(signature, 64))) fail();
    bytes(statement.nonce, 32);
    integer(statement.observed_at, 0);
    if (freshness && Math.abs(Date.now() / 1000 - statement.observed_at) > 30) fail();
    return { sequence: statement.sequence, digest: statement.digest,
      nonce: statement.nonce };
  }
  async #readHeads(target) {
    const nonce = crypto.randomBytes(32);
    let casRaw, floorState;
    try {
      [casRaw, floorState] = await Promise.all([
        this.#casClient.readHead({ scope: this.#scope, nonce }),
        this.#floorClient.readHead({ scope: this.#scope }),
      ]);
    } catch (_) { fail("ZK_OPAQUE_CHECKPOINT_STAGE_ACK_UNCERTAIN"); }
    try {
      const cas = await this.#verifyAuthority(casRaw, this.#casPublicKey,
        catalogCasDomain, target, nonce, true);
      const floor = await this.#verifyAuthority(floorState.proof, this.#floorPublicKey,
        FLOOR_DOMAIN, { ...target, floorNonce: (await z.decodeDeterministic(
          floorState.proof)).nonce }, undefined, true);
      if (floorState.sequence !== floor.sequence
        || !same(bytes(floorState.digest, 32), floor.digest)
        || cas.sequence !== floor.sequence || !same(cas.digest, floor.digest)) fail();
      return { casProof: Buffer.from(casRaw), floorProof: Buffer.from(floorState.proof),
        casNonce: nonce };
    } catch (_) { fail("ZK_OPAQUE_CHECKPOINT_STAGE_AUTHORITY_CONFLICT"); }
  }
  async #checkSavedRow(row) {
    if (!same(sha(PAYLOAD_DOMAIN, row.payload), row.payload_digest)) fail();
    const detail = await this.#decodePayload(row.payload);
    if (detail.finalSequence !== row.final_sequence
      || !same(detail.checkpointDigest, row.checkpoint_digest)) fail();
    if (row.status === "STAGED") {
      const expected = { finalSequence: detail.finalSequence,
        finalDigest: detail.finalDigest };
      await this.#verifyAuthority(row.cas_proof, this.#casPublicKey,
        catalogCasDomain, expected, row.cas_nonce, false);
      const floor = await z.decodeDeterministic(row.floor_proof);
      await this.#verifyAuthority(row.floor_proof, this.#floorPublicKey,
        FLOOR_DOMAIN, { ...expected, floorNonce: floor.nonce }, undefined, false);
    } else if (row.status !== "PENDING") fail();
    return detail;
  }
  async audit() {
    const rows = this.db.prepare("SELECT * FROM checkpoint_stages ORDER BY final_sequence").all();
    let prior = { finalSequence: 0, finalDigest: ZERO, checkpointDigest: ZERO };
    let pending = false;
    for (const row of rows) {
      if (pending) fail();
      const current = await this.#checkSavedRow(row);
      if (current.previousSequence !== prior.finalSequence
        || !same(current.previousCheckpointDigest, prior.checkpointDigest)
        || (prior.finalSequence !== 0
        && !same(bytes((await z.decodeDeterministic(row.payload)).previous_digest, 32),
          prior.finalDigest))) fail();
      if (row.status === "PENDING") pending = true;
      prior = { ...current };
    }
    return { count: rows.length, pending,
      lastSequence: prior.finalSequence, lastCheckpointDigest: prior.checkpointDigest,
      publishedV2: false, remoteCloudDurabilityProven: false };
  }
  async stage({ checkpointBytes, checkpointSignature, records,
    previousSequence, previousDigest, previousCheckpointDigest,
    ownerApprovalBytes, ownerApprovalSignature }) {
    return this.#queue(async () => {
      await this.audit();
      if (!Array.isArray(records) || !records.length || records.length > 128) fail();
      let upperBytes = 16384 + 4096;
      for (const record of records) {
        exact(record, ["sequence", "header", "signature", "page_bodies"]);
        bytes(record.header, 1, 16384);
        bytes(record.signature, 64);
        if (!Array.isArray(record.page_bodies) || record.page_bodies.length > 128) fail();
        upperBytes += record.header.length + record.signature.length + 256;
        for (const page of record.page_bodies) upperBytes += bytes(page, 1, 16384).length + 32;
        if (upperBytes > MAX_BUNDLE) fail();
      }
      const payload = Buffer.from(await z.encodeDeterministic({
        type: "rootark-zk1-opaque-catalog-stage-payload/v2",
        checkpoint_bytes: bytes(checkpointBytes, 1, 16384),
        checkpoint_signature: bytes(checkpointSignature, 64),
        records, previous_sequence: previousSequence,
        previous_digest: bytes(previousDigest, 32),
        previous_checkpoint_digest: bytes(previousCheckpointDigest, 32),
        owner_approval_bytes: bytes(ownerApprovalBytes, 1, 4096),
        owner_approval_signature: bytes(ownerApprovalSignature, 64),
      }));
      if (payload.length > MAX_BUNDLE) fail();
      const digest = sha(PAYLOAD_DOMAIN, payload);
      const details = await this.#decodePayload(payload, true);
      const rows = this.db.prepare("SELECT * FROM checkpoint_stages ORDER BY final_sequence").all();
      const last = rows.at(-1);
      if (last) {
        if (last.final_sequence === details.finalSequence
          && same(last.payload_digest, digest)) {
          return last.status === "STAGED"
            ? this.revalidateRemote(details.finalSequence)
            : this.#reconcileNoQueue();
        }
        if (last.status !== "STAGED") fail("ZK_OPAQUE_CHECKPOINT_STAGE_PENDING");
        const previous = await this.#checkSavedRow(last);
        if (details.previousSequence !== previous.finalSequence
          || !same(details.previousCheckpointDigest, previous.checkpointDigest)
          || !same(bytes(previousDigest, 32), previous.finalDigest)) fail();
      } else if (details.previousSequence !== 0
        || !same(bytes(previousDigest, 32), ZERO)
        || !same(details.previousCheckpointDigest, ZERO)) fail();
      try {
        this.db.prepare(`INSERT INTO checkpoint_stages
          (final_sequence, checkpoint_digest, payload_digest, payload, status)
          VALUES (?, ?, ?, ?, 'PENDING')`).run(details.finalSequence,
          details.checkpointDigest, digest, payload);
      } catch (_) {
        const competing = this.db.prepare(
          "SELECT * FROM checkpoint_stages WHERE final_sequence=?")
          .get(details.finalSequence);
        if (!competing || !same(competing.payload_digest, digest))
          fail("ZK_OPAQUE_CHECKPOINT_STAGE_CONFLICT");
        return this.#reconcileNoQueue();
      }
      // Full durable local write of the intent precedes any remote head I/O.
      const stored = this.db.prepare("SELECT * FROM checkpoint_stages WHERE final_sequence=?")
        .get(details.finalSequence);
      if (!stored || !same(stored.payload_digest, digest)) fail();
      return this.#reconcileNoQueue();
    });
  }
  async #reconcileNoQueue() {
    await this.audit();
    const rows = this.db.prepare("SELECT * FROM checkpoint_stages ORDER BY final_sequence").all();
    const last = rows.at(-1);
    if (!last) fail();
    const details = await this.#checkSavedRow(last);
    if (last.status === "STAGED") return this.revalidateRemote(details.finalSequence);
    // A weeks-old pending signature is not authority for a new observation.
    // Lapsed owner approvals fail closed; an owner-history-aware recovery path
    // is required rather than silently refreshing an old intent.
    await this.#decodePayload(last.payload, true);
    // Two fresh independently authenticated reads before claiming even
    // STAGED. This does not prove that remote CAS/floor durably committed v2.
    await this.#readHeads(details);
    const confirmation = await this.#readHeads(details);
    try {
      this.db.prepare(`UPDATE checkpoint_stages
        SET status='STAGED', cas_proof=?, floor_proof=?, cas_nonce=?
        WHERE final_sequence=? AND status='PENDING'`)
        .run(confirmation.casProof, confirmation.floorProof, confirmation.casNonce,
          details.finalSequence);
    } catch (_) { fail("ZK_OPAQUE_CHECKPOINT_STAGE_ACK_UNCERTAIN"); }
    const stored = this.db.prepare("SELECT * FROM checkpoint_stages WHERE final_sequence=?")
      .get(details.finalSequence);
    if (!stored || stored.status !== "STAGED") fail("ZK_OPAQUE_CHECKPOINT_STAGE_ACK_UNCERTAIN");
    await this.#checkSavedRow(stored);
    return { outcome: "LOCAL_STAGED_NOT_PUBLISHED", finalSequence: details.finalSequence,
      checkpointDigest: Buffer.from(details.checkpointDigest), publishedV2: false,
      remoteCloudDurabilityProven: false };
  }
  async reconcilePending() { return this.#queue(() => this.#reconcileNoQueue()); }
  async revalidateRemote(sequence) {
    await this.audit();
    const row = this.db.prepare("SELECT * FROM checkpoint_stages WHERE final_sequence=?")
      .get(integer(sequence, 1, MAX_V1_SEQUENCE));
    if (!row || row.status !== "STAGED") fail();
    const details = await this.#checkSavedRow(row);
    await this.#readHeads(details);
    return { outcome: "LOCAL_STAGED_NOT_PUBLISHED", finalSequence: details.finalSequence,
      checkpointDigest: Buffer.from(details.checkpointDigest),
      publishedV2: false, remoteCloudDurabilityProven: false };
  }
  close() { this.db.close(); }
}
module.exports = {
  Zk1OpaqueCatalogCheckpointV2Stage,
  createSignedOpaqueCheckpointOwnerApprovalV2,
};
