"use strict";

// An isolated, server-blind *local* content plane. Only sealed bytes cross
// this interface. Each request requires a fresh independently signed witness
// head, the exact manifest at that head and the active device's Ed25519 proof.
// Not installed into legacy routes. Does NOT provide cross-host linearizable
// revocation, external monotonic storage, multi-provider I/O, or production ZK.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const manifestV2 = require("../crypto/rootark-zk-recovery-manifest-v2");
const { inspectVerifiedWitnessFreshHeadV1 } = require("../crypto/rootark-zk-witness-head-wire-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/protected-object-operation/v1\0", "ascii");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "device_id", "operation",
  "object_id", "expected_object_revision", "manifest_revision", "manifest_digest",
  "epoch", "nonce", "issued_at", "expires_at", "ciphertext_digest",
]);
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_LIFETIME_OBJECTS = 4096;
const MAX_NONCES = 100_000;

function fail(code = "ZK_CONTENT_DENIED") {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function bytes(input, min, max = min) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
    || input.byteLength < min || input.byteLength > max) fail();
  return Buffer.from(input);
}
function equal(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}
function positive(value) {
  if (!Number.isSafeInteger(value) || value < 1) fail();
  return value;
}
function strict(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))
    || Reflect.ownKeys(value).some((field) => !fields.includes(field))) fail();
}
function normalizeScope(input) {
  strict(input, ["account_id", "compartment_id", "keyring_id"]);
  return {
    account_id: bytes(input.account_id, 16),
    compartment_id: bytes(input.compartment_id, 1, 128),
    keyring_id: bytes(input.keyring_id, 16),
  };
}
function scopeKey(scope) {
  return scope.account_id.toString("hex") + ":" + scope.compartment_id.toString("hex")
    + ":" + scope.keyring_id.toString("hex");
}
function normalizeAuthorization(value) {
  strict(value, FIELDS);
  const result = {
    account_id: bytes(value.account_id, 16),
    compartment_id: bytes(value.compartment_id, 1, 128),
    keyring_id: bytes(value.keyring_id, 16),
    device_id: value.device_id,
    operation: value.operation,
    object_id: value.object_id,
    expected_object_revision: value.expected_object_revision === null
      ? null : positive(value.expected_object_revision),
    manifest_revision: positive(value.manifest_revision),
    manifest_digest: bytes(value.manifest_digest, 32),
    epoch: positive(value.epoch),
    nonce: bytes(value.nonce, 32),
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    ciphertext_digest: value.ciphertext_digest === null
      ? null : bytes(value.ciphertext_digest, 32),
  };
  if (typeof result.device_id !== "string" || result.device_id.length < 1
    || result.device_id.length > 64 || /[\u0000-\u001f\u007f]/.test(result.device_id)
    || !["put", "get"].includes(result.operation)
    || typeof result.object_id !== "string"
    || !/^[A-Za-z0-9_-]{22}$/.test(result.object_id)
    || Buffer.from(result.object_id, "base64url").toString("base64url") !== result.object_id
    || !Number.isSafeInteger(result.issued_at) || result.issued_at < 0
    || !Number.isSafeInteger(result.expires_at) || result.expires_at <= result.issued_at
    || result.expires_at - result.issued_at > 60
    || (result.operation === "get" && (result.ciphertext_digest !== null
      || result.expected_object_revision !== null))
    || (result.operation === "put" && result.ciphertext_digest === null)) fail();
  return result;
}
async function contentAuthorizationMessageV1(input) {
  return Buffer.concat([DOMAIN, Buffer.from(await z.encodeDeterministic(
    normalizeAuthorization(input),
  ))]);
}
function currentTime(nowSeconds) {
  const now = nowSeconds();
  if (!Number.isSafeInteger(now) || now < 0) fail("ZK_CONTENT_UNAVAILABLE");
  return now;
}

function verifyStoreIdentity(db, expected) {
  let row;
  try {
    // Check schema and identity without modifying SQLite's journal mode or
    // creating any tables. An unrelated pre-existing database is NOT ours.
    const table = db.prepare(`SELECT name FROM sqlite_master
      WHERE type='table' AND name='zk_content_identity'`).get();
    if (!table) fail("ZK_CONTENT_IDENTITY_MISSING");
    row = db.prepare("SELECT * FROM zk_content_identity WHERE id=1").get();
  } catch (error) {
    if (error.code === "ZK_CONTENT_IDENTITY_MISSING") throw error;
    fail("ZK_CONTENT_IDENTITY_MISSING");
  }
  if (!row) fail("ZK_CONTENT_IDENTITY_MISSING");
  if (row.scope !== expected.scope
    || !equal(row.witness_key_id, expected.keyId)
    || !equal(row.witness_fingerprint, expected.fingerprint)
    || row.floor_revision !== expected.revision
    || !equal(row.floor_digest, expected.digest)) {
    fail("ZK_CONTENT_IDENTITY_MISMATCH");
  }
}

function statIdentity(stat) {
  if (!stat.isFile()) fail("ZK_CONTENT_BOOTSTRAP_REQUIRED");
  return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
}
function fileIdentity(filename) {
  return statIdentity(fs.statSync(filename, { bigint: true }));
}

class Zk1ProtectedObjectStore {
  constructor(filename, { witnessProvider, witnessPinned, manifestProvider,
    trustedScope, minimumHead, bootstrapNew = false,
    admissionRequired = false,
    nowSeconds = () => Math.floor(Date.now() / 1000) } = {}) {
    if (typeof filename !== "string" || !filename || !witnessProvider
      || typeof witnessProvider.freshHead !== "function"
      || typeof manifestProvider !== "function" || typeof nowSeconds !== "function"
      || !(witnessPinned?.publicKey instanceof crypto.KeyObject)
      || witnessPinned.publicKey.type !== "public"
      || witnessPinned.publicKey.asymmetricKeyType !== "ed25519"
      || typeof admissionRequired !== "boolean"
      || (admissionRequired && (typeof witnessProvider.beginIoAdmission !== "function"
        || typeof witnessProvider.finishIoAdmission !== "function"))) fail();
    // The external owner/account authentication boundary must select ONE
    // immutable keyring scope. A watermark for a different account or
    // compartment is not interchangeable with this genesis floor.
    this.trustedScope = normalizeScope(trustedScope);
    this.witnessPinned = Object.freeze({ keyId: bytes(witnessPinned.keyId, 16),
      publicKey: witnessPinned.publicKey });
    if (!minimumHead || !Number.isSafeInteger(minimumHead.revision)
      || minimumHead.revision < 1
      || minimumHead.witnessSequence !== minimumHead.revision) fail();
    this.minimumHead = Object.freeze({ revision: minimumHead.revision,
      witnessSequence: minimumHead.witnessSequence, digest: bytes(minimumHead.digest, 32) });
    this.witnessProvider = witnessProvider;
    this.admissionRequired = admissionRequired;
    this.manifestProvider = manifestProvider;
    this.nowSeconds = nowSeconds;
    const absolute = path.resolve(filename);
    if (bootstrapNew !== true && bootstrapNew !== false) fail();
    const existed = fs.existsSync(absolute);
    if (existed === bootstrapNew) fail("ZK_CONTENT_BOOTSTRAP_REQUIRED");
    if (existed && !fs.lstatSync(absolute).isFile()) fail();
    const expectedIdentity = {
      scope: scopeKey(this.trustedScope),
      keyId: this.witnessPinned.keyId,
      fingerprint: crypto.createHash("sha256").update(
        this.witnessPinned.publicKey.export({ type: "spki", format: "der" })).digest(),
      revision: this.minimumHead.revision,
      digest: this.minimumHead.digest,
    };
    let inspectedIdentity;
    if (existed) {
      inspectedIdentity = fileIdentity(absolute);
      // Must complete the preflight on a read-only connection. Opening an
      // unknown SQLite in write mode / enabling WAL mutates foreign data.
      const readonly = new Database(absolute, { readonly: true, fileMustExist: true });
      try { verifyStoreIdentity(readonly, expectedIdentity); }
      finally { readonly.close(); }
      if (fileIdentity(absolute) !== inspectedIdentity) {
        fail("ZK_CONTENT_BOOTSTRAP_REQUIRED");
      }
    } else {
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      // Never race another bootstrap into overwriting an existing database.
      const fd = fs.openSync(absolute, fs.constants.O_CREAT | fs.constants.O_EXCL
        | fs.constants.O_RDWR, 0o600);
      try { inspectedIdentity = statIdentity(fs.fstatSync(fd, { bigint: true })); }
      finally { fs.closeSync(fd); }
    }
    this.db = new Database(absolute, { fileMustExist: true });
    try {
      // Cover replacement after exclusive creation and before SQLite opens.
      if (fileIdentity(absolute) !== inspectedIdentity) {
        fail("ZK_CONTENT_BOOTSTRAP_REQUIRED");
      }
      // Repeat on the very connection that will perform DDL, before the first
      // mutating statement, to reject a file swapped during the read-only check.
      if (existed) {
        verifyStoreIdentity(this.db, expectedIdentity);
      }
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = FULL");
      this.db.exec(`
      CREATE TABLE IF NOT EXISTS zk_content_identity (
        id INTEGER PRIMARY KEY CHECK(id=1), scope TEXT NOT NULL,
        witness_key_id BLOB NOT NULL, witness_fingerprint BLOB NOT NULL,
        floor_revision INTEGER NOT NULL, floor_digest BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS zk_content_head (
        scope TEXT PRIMARY KEY, revision INTEGER NOT NULL, digest BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS zk_content_nonce (
        scope TEXT NOT NULL, nonce BLOB NOT NULL, expires_at INTEGER,
        PRIMARY KEY(scope,nonce)
      );
      CREATE TABLE IF NOT EXISTS zk_content_clock (
        scope TEXT PRIMARY KEY, last_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS zk_content_object (
        scope TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
        epoch INTEGER NOT NULL, ciphertext BLOB NOT NULL, PRIMARY KEY(scope,id)
      );
    `);
    if (!existed) {
      this.db.prepare(`INSERT INTO zk_content_identity
        (id,scope,witness_key_id,witness_fingerprint,floor_revision,floor_digest)
        VALUES(1,?,?,?,?,?)`).run(expectedIdentity.scope, expectedIdentity.keyId,
        expectedIdentity.fingerprint, expectedIdentity.revision, expectedIdentity.digest);
    }
    // Upgrade earlier disposable/local content planes without erasing any
    // durable replay state. Unattributed legacy nonces remain permanently
    // fenced (NULL expires_at), since their lifetimes cannot be reconstructed.
    if (!this.db.prepare("PRAGMA table_info(zk_content_nonce)").all()
      .some((field) => field.name === "expires_at")) {
      this.db.exec("ALTER TABLE zk_content_nonce ADD COLUMN expires_at INTEGER");
    }
    this.db.exec(`CREATE INDEX IF NOT EXISTS zk_content_nonce_expiry
      ON zk_content_nonce(scope, expires_at)`);
    this.getHead = this.db.prepare("SELECT revision,digest FROM zk_content_head WHERE scope=?");
    this.getObject = this.db.prepare("SELECT revision,epoch,ciphertext FROM zk_content_object WHERE scope=? AND id=?");
    this.nonceCount = this.db.prepare("SELECT COUNT(*) AS n FROM zk_content_nonce WHERE scope=?");
    this.objectCount = this.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object WHERE scope=?");
    this.clockRow = this.db.prepare("SELECT last_at FROM zk_content_clock WHERE scope=?");
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  async authorize({ scope, authorization, signature, ciphertext }, operation) {
    const canonicalScope = normalizeScope(scope);
    const request = normalizeAuthorization(authorization);
    const key = scopeKey(canonicalScope);
    if (!equal(canonicalScope.account_id, this.trustedScope.account_id)
      || !equal(canonicalScope.compartment_id, this.trustedScope.compartment_id)
      || !equal(canonicalScope.keyring_id, this.trustedScope.keyring_id)
      || !equal(request.account_id, canonicalScope.account_id)
      || !equal(request.compartment_id, canonicalScope.compartment_id)
      || !equal(request.keyring_id, canonicalScope.keyring_id)
      || request.operation !== operation) fail();
    const proofSignature = bytes(signature, 64);
    const sealed = operation === "put" ? bytes(ciphertext, 16, MAX_BYTES) : null;
    if (operation === "put" && !equal(crypto.createHash("sha256").update(sealed).digest(),
      request.ciphertext_digest)) fail();
    const now = currentTime(this.nowSeconds);
    if (now < request.issued_at - 5 || now > request.expires_at) fail();
    let manifest, head;
    try {
      const nonce = crypto.randomBytes(32);
      const rawHead = Buffer.from(await this.witnessProvider.freshHead({
        scope: canonicalScope, nonce: Buffer.from(nonce),
      }));
      const row = this.getHead.get(key);
      const floor = row && row.revision >= this.minimumHead.revision
        ? { revision: row.revision, witnessSequence: row.revision, digest: row.digest }
        : this.minimumHead;
      await inspectVerifiedWitnessFreshHeadV1({ raw: rawHead, nonce,
        scope: canonicalScope, pinned: this.witnessPinned, minimumHead: floor });
      head = await z.decodeDeterministic(rawHead);
      const rawManifest = bytes(await this.manifestProvider(canonicalScope), 1, 262144);
      manifest = await z.decodeDeterministic(rawManifest);
      manifestV2.validateManifestShape(manifest);
      if (!equal(await manifestV2.recoveryManifestDigestV2(manifest),
        Buffer.from(head.current_manifest_digest))) fail();
      if (Number(manifest.revision) !== Number(head.current_revision)) fail();
      if (!equal(request.manifest_digest, Buffer.from(head.current_manifest_digest))
        || request.manifest_revision !== Number(head.current_revision)
        || request.epoch !== Number(manifest.current_epoch)
        || !equal(Buffer.from(manifest.account_id), canonicalScope.account_id)
        || !equal(Buffer.from(manifest.compartment_id), canonicalScope.compartment_id)
        || !equal(Buffer.from(manifest.keyring_id), canonicalScope.keyring_id)
        || Math.abs(Number(head.observed_at) - currentTime(this.nowSeconds)) > 30) fail();
    } catch (_) { fail("ZK_CONTENT_UNAVAILABLE"); }
    const device = manifest.devices.find((entry) => entry.device_id === request.device_id);
    if (!device || device.revoked_at_epoch !== null
      || Number(device.enrolled_epoch) > request.epoch) fail();
    let valid = false;
    try {
      const publicKey = crypto.createPublicKey({
        key: Buffer.concat([ED25519_SPKI, bytes(device.authorization_public_key, 32)]),
        format: "der", type: "spki",
      });
      valid = crypto.verify(null, await contentAuthorizationMessageV1(request),
        publicKey, proofSignature);
    } catch (_) { fail(); }
    if (!valid) fail();
    return { key, request, head, sealed };
  }

  perform({ key, request, head, sealed }, operation) {
    return this.db.transaction(() => {
      // Never use the time from the first auth check after an asynchronous
      // network/crypto operation. The request must be valid at the physical
      // read/write effect boundary, not merely when it entered the process.
      const now = currentTime(this.nowSeconds);
      if (now < request.issued_at - 5 || now > request.expires_at) fail();
      const clock = this.clockRow.get(key);
      if (clock && now < clock.last_at) fail("ZK_CONTENT_UNAVAILABLE");
      const known = this.getHead.get(key);
      const minimum = known && known.revision >= this.minimumHead.revision
        ? known : this.minimumHead;
      const revision = Number(head.current_revision);
      const digest = Buffer.from(head.current_manifest_digest);
      if (revision < minimum.revision
        || (revision === minimum.revision && !equal(digest, Buffer.from(minimum.digest)))) {
        fail("ZK_CONTENT_UNAVAILABLE");
      }
      // Reclaim only already expired nonce tombstones. All signed requests
      // have a <=60s lifetime; the persistently monotonic local clock above
      // prevents a time rollback from revalidating a retired nonce.
      this.db.prepare(`DELETE FROM zk_content_nonce
        WHERE scope=? AND expires_at IS NOT NULL AND expires_at < ?`).run(key, now);
      if (this.db.prepare("SELECT 1 FROM zk_content_nonce WHERE scope=? AND nonce=?")
        .get(key, request.nonce)) fail("ZK_CONTENT_REPLAY");
      if (this.nonceCount.get(key).n >= MAX_NONCES) fail("ZK_CONTENT_UNAVAILABLE");
      const row = this.getObject.get(key, request.object_id);
      let result;
      if (operation === "get") {
        if (!row) fail("ZK_CONTENT_NOT_FOUND");
        result = { id: request.object_id, revision: row.revision,
          epoch: row.epoch, ciphertext: Buffer.from(row.ciphertext) };
      } else {
        if (row && row.revision !== request.expected_object_revision) fail("ZK_CONTENT_CONFLICT");
        if (!row && request.expected_object_revision !== null) fail("ZK_CONTENT_CONFLICT");
        if (!row && this.objectCount.get(key).n >= MAX_LIFETIME_OBJECTS) {
          fail("ZK_CONTENT_UNAVAILABLE");
        }
        const nextRevision = row ? row.revision + 1 : 1;
        if (!Number.isSafeInteger(nextRevision)) fail("ZK_CONTENT_UNAVAILABLE");
        this.db.prepare(`INSERT INTO zk_content_object(scope,id,revision,epoch,ciphertext)
          VALUES(?,?,?,?,?) ON CONFLICT(scope,id) DO UPDATE SET
          revision=excluded.revision, epoch=excluded.epoch, ciphertext=excluded.ciphertext`)
          .run(key, request.object_id, nextRevision, request.epoch, sealed);
        result = { id: request.object_id, revision: nextRevision };
      }
      this.db.prepare("INSERT INTO zk_content_nonce(scope,nonce,expires_at) VALUES(?,?,?)")
        .run(key, request.nonce, request.expires_at);
      this.db.prepare(`INSERT INTO zk_content_clock(scope,last_at) VALUES(?,?)
        ON CONFLICT(scope) DO UPDATE SET last_at=excluded.last_at`).run(key, now);
      this.db.prepare(`INSERT INTO zk_content_head(scope,revision,digest) VALUES(?,?,?)
        ON CONFLICT(scope) DO UPDATE SET revision=excluded.revision,digest=excluded.digest`)
        .run(key, revision, digest);
      return result;
    }).immediate();
  }

  async put(input) {
    if (this.admissionRequired) fail("ZK_CONTENT_GATE_REQUIRED");
    return this.perform(await this.authorize(input, "put"), "put");
  }
  async get(input) {
    if (this.admissionRequired) fail("ZK_CONTENT_GATE_REQUIRED");
    return this.perform(await this.authorize(input, "get"), "get");
  }
  async runWithAdmission(input, operation, emit) {
    if (typeof emit !== "function" || !["put", "get"].includes(operation)) fail();
    const authenticated = await this.authorize(input, operation);
    if (!this.admissionRequired) {
      return emit(this.perform(authenticated, operation));
    }
    const workerId = crypto.randomBytes(16);
    let admissionId;
    const start = { scope: this.trustedScope,
      revision: authenticated.request.manifest_revision,
      digest: authenticated.request.manifest_digest,
      action: operation, objectId: authenticated.request.object_id, workerId };
    try {
      let receipt;
      try { receipt = await this.witnessProvider.beginIoAdmission(start); }
      catch (_) {
        // A lost start ACK must retry with the exact SAME worker identifier:
        // the witness returns the prior active admission idempotently. Never
        // start an unrelated second worker after a transport failure.
        receipt = await this.witnessProvider.beginIoAdmission(start);
      }
      admissionId = bytes(receipt.admissionId, 16);
    } catch (_) { fail("ZK_CONTENT_UNAVAILABLE"); }
    try {
      // The caller's emit() must settle only when response bytes have crossed
      // the trusted application egress boundary, or the socket was closed.
      // The witness refuses to reserve while this admission is ACTIVE.
      return await emit(this.perform(authenticated, operation));
    } finally {
      const finish = { scope: this.trustedScope, admissionId, workerId };
      try {
        try { await this.witnessProvider.finishIoAdmission(finish); }
        catch (_) { await this.witnessProvider.finishIoAdmission(finish); }
      } catch (_) {
        // Never silently clear an unknown active worker. A lost finish ACK
        // leaves the durable witness fence closed until reconciliation.
        fail("ZK_CONTENT_UNAVAILABLE");
      }
    }
  }
  close() { if (this.db.open) this.db.close(); }
}

module.exports = { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 };
