"use strict";

// Independent, opt-in CAS signing process for opaque catalog snapshots.
// The authority stores the complete owner/device-signed opaque snapshot in
// SQLite WAL/FULL before producing a CAS receipt. This proves THIS durable
// SQLite commit, never physical cloud durability or a distributed witness.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const { catalogHeadDigest, catalogCasDomain } = require("./zk1OpaqueCatalog");
const ownerHistory = require("../crypto/rootark-zk-recovery-history-v2");
const ownerManifest = require("../crypto/rootark-zk-recovery-manifest-v2");
const { inspectVerifiedWitnessFreshHeadV1 } =
  require("../crypto/rootark-zk-witness-head-wire-v1");
const { isZk1OpaqueCatalogIndependentFloorClient } =
  require("./zk1OpaqueCatalogIndependentFloor");
const { requireImmutableTriggers } = require("./zk1OpaqueCatalogSqliteIntegrity");
const { assertPrivateSqliteDirectory, assertPrivateSqliteFile } = require("./zk1PrivateSqlitePath");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const PAGE_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0");
const SNAPSHOT_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-snapshot-fetch/v1\0");
const EMPTY = Buffer.alloc(32);
const MAX_SEQUENCE = 128;
const HEAD_TYPE = "rootark-zk1-opaque-catalog/v1";
const CAS_TYPE = "rootark-zk1-opaque-catalog-cas/v1";
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const OWNER_EVIDENCE = ["baseManifest", "baseReceipt", "transitions",
  "packageEnvelopes", "witnessHeadRaw"];
const HEAD_FIELDS = ["type", ...SCOPE, "sequence", "previous_digest",
  "manifest_revision", "manifest_digest", "epoch", "signer_device_id",
  "total_count", "page_digests", "issued_at"];
function fail(code = "ZK_OPAQUE_CAS_UNAVAILABLE") {
  const error = new Error(code); error.code = code; throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
}
function bytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}
function same(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail();
  return value;
}
function scopeInput(value) {
  exact(value, SCOPE);
  return Object.fromEntries(SCOPE.map((key) =>
    [key, bytes(value[key], key === "compartment_id" ? 1 : 16,
      key === "compartment_id" ? 128 : 16)]));
}
function scopeId(scope) {
  return SCOPE.map((key) => scope[key].toString("hex")).join(":");
}
function scopeEquals(a, b) {
  return SCOPE.every((key) => same(bytes(a[key],
    key === "compartment_id" ? 1 : 16, key === "compartment_id" ? 128 : 16), b[key]));
}
function publicFingerprint(key) {
  return crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
}
function privateDir(filename) {
  const folder = path.dirname(filename);
  const current = fs.lstatSync(folder);
  if (!current.isDirectory() || current.isSymbolicLink()) fail();
  if (process.platform !== "win32"
    && (current.uid !== process.getuid() || (current.mode & 0o077) !== 0)) fail();
  // SQLite follows ancestor junctions while opening the DB and WAL/SHM paths.
  // Reject aliases even when the immediate parent itself is a real directory.
  try { assertPrivateSqliteDirectory(filename); } catch (_) { fail(); }
}
function requireExistingCatalogSchema(db, identity, hasOwner) {
  // A restart must inspect the existing file read-only before switching WAL
  // mode or installing any schema. Otherwise rejecting a foreign SQLite still
  // permanently writes CAS tables into that foreign database.
  if (db.pragma("quick_check", { simple: true }) !== "ok") fail();
  const objects = new Set(db.prepare("SELECT type, name FROM sqlite_master").all()
    .map((entry) => `${entry.type}:${entry.name}`));
  for (const name of ["identity", "heads", "snapshots", "signer_history",
    "owner_authority"]) if (!objects.has(`table:${name}`)) fail();
  for (const name of ["immutable_opaque_signer_update", "immutable_opaque_signer_delete",
    "immutable_opaque_snapshot_update", "immutable_opaque_snapshot_delete"])
    if (!objects.has(`trigger:${name}`)) fail();
  if (!objects.has("index:uq_opaque_cas_nonce")) fail();
  const saved = db.prepare("SELECT * FROM identity WHERE id=1").get();
  if (!saved || saved.authority_fp !== identity[0]
    || saved.catalog_fp !== identity[1] || saved.scope !== identity[2]) fail();
  const owner = db.prepare("SELECT * FROM owner_authority WHERE scope=?")
    .get(identity[2]);
  if (Boolean(owner) !== hasOwner) fail();
}

class Zk1OpaqueCatalogCasLedger {
  #minimum;
  #floor;
  #ownerTrust;
  #floorSync;
  #serialized = Promise.resolve();
  #serialize(operation) {
    // A local FULL commit cannot overlap a signed read or another CAS before
    // its independent floor is durably advanced and read back.
    const pending = this.#serialized.then(operation);
    this.#serialized = pending.catch(() => {});
    return pending;
  }
  constructor(filename, { bootstrapNew, signingPrivateKey, catalogSignerPublicKey,
    trustedScope, minimumHead, ownerTrust, independentFloor } = {}) {
    if (typeof filename !== "string" || !path.isAbsolute(filename)
      || !(signingPrivateKey instanceof crypto.KeyObject)
      || signingPrivateKey.type !== "private" || signingPrivateKey.asymmetricKeyType !== "ed25519"
      || !(catalogSignerPublicKey instanceof crypto.KeyObject)
      || catalogSignerPublicKey.type !== "public" || catalogSignerPublicKey.asymmetricKeyType !== "ed25519"
      || !minimumHead || !isZk1OpaqueCatalogIndependentFloorClient(independentFloor)) fail();
    this.scope = scopeInput(trustedScope);
    this.scopeId = scopeId(this.scope);
    this.signer = signingPrivateKey;
    this.publicKey = crypto.createPublicKey(signingPrivateKey);
    this.catalogSigner = catalogSignerPublicKey;
    if (ownerTrust !== undefined) {
      exact(ownerTrust, ["genesisDigest", "pinnedWitness", "minimumHead", "freshWitnessHead"]);
      exact(ownerTrust.pinnedWitness, ["keyId", "publicKey"]);
      exact(ownerTrust.minimumHead, ["revision", "witnessSequence", "digest"]);
      if (!(ownerTrust.pinnedWitness.publicKey instanceof crypto.KeyObject)
        || ownerTrust.pinnedWitness.publicKey.type !== "public"
        || ownerTrust.pinnedWitness.publicKey.asymmetricKeyType !== "ed25519"
        || typeof ownerTrust.freshWitnessHead !== "function") fail();
      const revision = integer(ownerTrust.minimumHead.revision, 1, Number.MAX_SAFE_INTEGER);
      if (ownerTrust.minimumHead.witnessSequence !== revision) fail();
      this.#ownerTrust = {
        genesisDigest: bytes(ownerTrust.genesisDigest, 32),
        pinnedWitness: {
          keyId: bytes(ownerTrust.pinnedWitness.keyId, 16),
          publicKey: ownerTrust.pinnedWitness.publicKey,
        },
        minimumHead: { revision, witnessSequence: revision,
          digest: bytes(ownerTrust.minimumHead.digest, 32) },
        freshWitnessHead: ownerTrust.freshWitnessHead,
      };
    }
    this.independentFloor = independentFloor;
    if (publicFingerprint(this.publicKey) === publicFingerprint(this.catalogSigner)) fail();
    if (publicFingerprint(this.publicKey) === publicFingerprint(independentFloor.publicKey)
      || publicFingerprint(this.catalogSigner) === publicFingerprint(independentFloor.publicKey)) fail();
    this.#minimum = {
      sequence: integer(minimumHead.sequence, 0, MAX_SEQUENCE),
      digest: bytes(minimumHead.digest, 32),
    };
    if (this.#minimum.sequence === 0 && !same(this.#minimum.digest, EMPTY)) fail();
    this.#floor = { sequence: this.#minimum.sequence, digest: Buffer.from(this.#minimum.digest) };
    const identity = [publicFingerprint(this.publicKey),
      publicFingerprint(this.catalogSigner), this.scopeId];
    privateDir(filename);
    const exists = fs.existsSync(filename);
    if (bootstrapNew !== !exists || (bootstrapNew && this.#minimum.sequence !== 0)) fail();
    let filePin;
    if (exists) {
      try { filePin = assertPrivateSqliteFile(filename); } catch (_) { fail(); }
      const stat = fs.lstatSync(filename);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
        || (process.platform !== "win32"
          && (stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0))) fail();
      let probe;
      try {
        probe = new Database(filename, { readonly: true, fileMustExist: true });
        requireExistingCatalogSchema(probe, identity, Boolean(this.#ownerTrust));
      } catch (_) { fail(); }
      finally { probe?.close(); }
    }
    // SQLite ordinarily creates a new database with the process umask (often
    // 0644 on Linux). A later restart then correctly rejects that same file as
    // non-private. Create the file exclusively with mode 0600 *before* SQLite
    // opens it; the 0700 parent directory was checked above. O_EXCL also
    // refuses dangling symlinks and concurrent bootstrap attempts.
    if (!exists) {
      let descriptor;
      try {
        descriptor = fs.openSync(filename, fs.constants.O_CREAT | fs.constants.O_EXCL
          | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
        const pinned = fs.fstatSync(descriptor, { bigint: true });
        if (!pinned.isFile() || pinned.nlink !== 1n) fail();
        filePin = { dev: pinned.dev, ino: pinned.ino };
      } catch (_) { fail(); }
      finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
    }
    // A foreign hardlink/replacement may be installed after O_EXCL (or after
    // read-only restart preflight), before SQLite reopens the pathname. Never
    // run WAL pragmas or authority DDL on a different inode.
    const checkFilePin = () => {
      try {
        const current = assertPrivateSqliteFile(filename);
        if (current.dev !== filePin.dev || current.ino !== filePin.ino) fail();
      } catch (_) { fail(); }
    };
    checkFilePin();
    this.db = new Database(filename, { fileMustExist: true, timeout: 3000 });
    try {
      checkFilePin();
      if (exists) {
        requireExistingCatalogSchema(this.db, identity, Boolean(this.#ownerTrust));
        this.#inspectSync();
      }
      checkFilePin();
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = FULL");
      this.db.pragma("foreign_keys = ON");
      if (!exists) this.db.exec(`CREATE TABLE IF NOT EXISTS identity (
        id INTEGER PRIMARY KEY CHECK (id=1), authority_fp TEXT NOT NULL,
        catalog_fp TEXT NOT NULL, scope TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS heads (
        scope TEXT PRIMARY KEY, sequence INTEGER NOT NULL, digest BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS snapshots (
        scope TEXT NOT NULL, sequence INTEGER NOT NULL, digest BLOB NOT NULL,
        header BLOB NOT NULL, signature BLOB NOT NULL, pages BLOB NOT NULL,
        nonce BLOB NOT NULL, committed_at INTEGER NOT NULL,
        PRIMARY KEY (scope, sequence)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS uq_opaque_cas_nonce ON snapshots(scope,nonce);
      CREATE TABLE IF NOT EXISTS signer_history (
        scope TEXT NOT NULL, sequence INTEGER NOT NULL, signer_spki BLOB NOT NULL,
        owner_revision INTEGER NOT NULL, owner_digest BLOB NOT NULL,
        owner_evidence BLOB NOT NULL, PRIMARY KEY(scope,sequence)
      );
      CREATE TABLE IF NOT EXISTS owner_authority (
        scope TEXT PRIMARY KEY, genesis_digest BLOB NOT NULL,
        witness_fp TEXT NOT NULL, witness_key_id BLOB NOT NULL,
        revision INTEGER NOT NULL, digest BLOB NOT NULL
      );
      CREATE TRIGGER IF NOT EXISTS immutable_opaque_signer_update
        BEFORE UPDATE ON signer_history BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS immutable_opaque_signer_delete
        BEFORE DELETE ON signer_history BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS immutable_opaque_snapshot_update
        BEFORE UPDATE ON snapshots BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS immutable_opaque_snapshot_delete
        BEFORE DELETE ON snapshots BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
      requireImmutableTriggers(this.db, [
        ["immutable_opaque_signer_update", "signer_history", "UPDATE"],
        ["immutable_opaque_signer_delete", "signer_history", "DELETE"],
        ["immutable_opaque_snapshot_update", "snapshots", "UPDATE"],
        ["immutable_opaque_snapshot_delete", "snapshots", "DELETE"],
      ], fail);
      if (!exists) this.db.prepare("INSERT INTO identity VALUES (1,?,?,?)").run(...identity);
      const saved = this.db.prepare("SELECT * FROM identity WHERE id=1").get();
      if (!saved || saved.authority_fp !== identity[0]
        || saved.catalog_fp !== identity[1] || saved.scope !== identity[2]) fail();
      if (!exists && this.#ownerTrust) {
        this.db.prepare("INSERT INTO owner_authority VALUES (?,?,?,?,?,?)").run(
          this.scopeId, this.#ownerTrust.genesisDigest,
          publicFingerprint(this.#ownerTrust.pinnedWitness.publicKey),
          this.#ownerTrust.pinnedWitness.keyId,
          this.#ownerTrust.minimumHead.revision, this.#ownerTrust.minimumHead.digest);
      }
      const savedOwner = this.db.prepare("SELECT * FROM owner_authority WHERE scope=?")
        .get(this.scopeId);
      if (Boolean(savedOwner) !== Boolean(this.#ownerTrust)) fail();
      if (savedOwner && (!same(savedOwner.genesis_digest, this.#ownerTrust.genesisDigest)
        || savedOwner.witness_fp !== publicFingerprint(this.#ownerTrust.pinnedWitness.publicKey)
        || !same(savedOwner.witness_key_id, this.#ownerTrust.pinnedWitness.keyId)
        || savedOwner.revision < this.#ownerTrust.minimumHead.revision
        || (savedOwner.revision === this.#ownerTrust.minimumHead.revision
          && !same(savedOwner.digest, this.#ownerTrust.minimumHead.digest)))) fail();
      // Parsing deterministic CBOR uses the project's verified async ESM
      // codec. Callers MUST await ready before admitting TLS requests.
      // Startup is barred until a newly nonce-challenged, independently signed
      // head has been fetched. Static minimumHead is only a lower bound.
      this.ready = this.#syncFloor();
    } catch (error) { this.db.close(); throw error; }
  }
  #inspectSync() {
    const rows = this.db.prepare("SELECT * FROM snapshots WHERE scope=? ORDER BY sequence")
      .all(this.scopeId);
    if (rows.length > MAX_SEQUENCE) fail();
    let digest = EMPTY;
    let lastOwner = null;
    for (let i = 0; i < rows.length; ++i) {
      const row = rows[i];
      if (row.sequence !== i + 1 || row.digest.length !== 32
        || row.header.length < 1 || row.header.length > 16384
        || row.signature.length !== 64 || row.pages.length > 3 * 1024 * 1024
        || row.nonce.length !== 32
        || !same(catalogHeadDigest(row.header, row.signature), row.digest)) fail();
      const packed = JSON.parse(row.pages.toString("utf8"));
      if (!Array.isArray(packed) || packed.length > 128) fail();
      const pages = packed.map((encoded) => {
        const raw = Buffer.from(encoded, "base64url");
        if (!encoded || raw.length > 16384 || raw.toString("base64url") !== encoded) fail();
        return raw;
      });
      // Synchronous cryptographic signature verification; in the normal
      // network path the asynchronous CBOR decoder is run before insertion.
      const signerRow = this.db.prepare("SELECT * FROM signer_history WHERE scope=? AND sequence=?")
        .get(this.scopeId, row.sequence);
      if (Boolean(signerRow) !== Boolean(this.#ownerTrust)) fail();
      let key = this.catalogSigner;
      if (signerRow) {
        if (signerRow.signer_spki.length !== 44
          || signerRow.owner_digest.length !== 32
          || !Number.isSafeInteger(signerRow.owner_revision)
          || signerRow.owner_evidence.length < 1
          || signerRow.owner_evidence.length > 2 * 1024 * 1024) fail();
        if (lastOwner && (signerRow.owner_revision < lastOwner.revision
          || (signerRow.owner_revision === lastOwner.revision
            && !same(signerRow.owner_digest, lastOwner.digest)))) fail();
        lastOwner = { revision: signerRow.owner_revision,
          digest: Buffer.from(signerRow.owner_digest) };
        key = crypto.createPublicKey({ key: signerRow.signer_spki,
          format: "der", type: "spki" });
      }
      if (!crypto.verify(null, Buffer.concat([HEAD_DOMAIN, row.header]),
        key, row.signature)) fail();
      digest = row.digest;
    }
    const head = this.db.prepare("SELECT sequence,digest FROM heads WHERE scope=?").get(this.scopeId);
    if (this.#ownerTrust) {
      const total = this.db.prepare("SELECT COUNT(*) AS n FROM signer_history WHERE scope=?")
        .get(this.scopeId).n;
      if (total !== rows.length) fail();
      const owner = this.db.prepare("SELECT revision,digest FROM owner_authority WHERE scope=?")
        .get(this.scopeId);
      const latest = lastOwner || this.#ownerTrust.minimumHead;
      if (!owner || owner.revision !== latest.revision
        || !same(bytes(owner.digest, 32), latest.digest)) fail();
    }
    if ((head && (head.sequence !== rows.length || !same(head.digest, digest)))
      || (!head && rows.length)) fail();
    const sequence = head?.sequence || 0;
    if (sequence < this.#floor.sequence
      || (sequence === this.#floor.sequence && !same(digest, this.#floor.digest))) fail();
    return { sequence, digest: Buffer.from(digest) };
  }
  async #inspect() {
    const current = this.#inspectSync();
    let previous = EMPTY;
    const rows = this.db.prepare("SELECT * FROM snapshots WHERE scope=? ORDER BY sequence")
      .all(this.scopeId);
    for (const row of rows) {
      const header = await z.decodeDeterministic(row.header);
      exact(header, HEAD_FIELDS);
      const packed = JSON.parse(row.pages.toString("utf8"));
      if (header.type !== HEAD_TYPE || header.sequence !== row.sequence
        || !scopeEquals(header, this.scope)
        || !same(bytes(header.previous_digest, 32), previous)
        || !Array.isArray(header.page_digests)
        || header.page_digests.length !== packed.length
        || !Number.isSafeInteger(header.total_count)
        || header.total_count > 4096 || header.total_count < 0) fail();
      let count = 0;
      for (let i = 0; i < packed.length; ++i) {
        const body = Buffer.from(packed[i], "base64url");
        if (!same(crypto.createHash("sha256").update(PAGE_DOMAIN).update(body).digest(),
          bytes(header.page_digests[i], 32))) fail();
        const page = await z.decodeDeterministic(body);
        if (!Array.isArray(page) || page.length < 1 || page.length > 32
          || (i < packed.length - 1 && page.length !== 32)) fail();
        count += page.length;
      }
      if (count !== header.total_count) fail();
      if (this.#ownerTrust) {
        const signer = this.db.prepare("SELECT * FROM signer_history WHERE scope=? AND sequence=?")
          .get(this.scopeId, row.sequence);
        const confirmed = await this.#verifyOwnerEvidence({
          evidenceRaw: signer.owner_evidence, nonce: row.nonce, header,
          signerKey: crypto.createPublicKey({ key: signer.signer_spki,
            format: "der", type: "spki" }), historical: true });
        if (confirmed.revision !== signer.owner_revision
          || !same(confirmed.digest, signer.owner_digest)) fail();
      }
      previous = row.digest;
    }
    // A second sync check detects a concurrent head change between full
    // signed history validation and receipt creation.
    const latest = this.#inspectSync();
    if (latest.sequence !== current.sequence || !same(latest.digest, current.digest)) fail();
    return latest;
  }
  async #verifyOwnerEvidence({ evidenceRaw, nonce, header, signerKey, historical }) {
    if (!this.#ownerTrust) fail();
    const evidence = await z.decodeDeterministic(bytes(evidenceRaw, 1, 2 * 1024 * 1024));
    exact(evidence, OWNER_EVIDENCE);
    if (!Array.isArray(evidence.transitions) || !Array.isArray(evidence.packageEnvelopes)) fail();
    const pinned = this.#ownerTrust;
    const verified = await ownerHistory.verifyRecoveryHistoryPublicV2({
      expectedScope: this.scope, baseManifest: evidence.baseManifest,
      baseReceipt: evidence.baseReceipt, pinnedWitness: pinned.pinnedWitness,
      transitions: evidence.transitions, packageEnvelopes: evidence.packageEnvelopes,
      now: Math.floor(Date.now() / 1000),
    });
    if (!await ownerHistory.isVerifiedPublicRecoveryHistoryV2(verified)
      || !same(await ownerManifest.recoveryManifestDigestV2(verified.baseManifest),
        pinned.genesisDigest)) fail();
    const witness = bytes(evidence.witnessHeadRaw, 1, 8192);
    const floor = historical ? { revision: 1, witnessSequence: 1,
      digest: pinned.genesisDigest } : this.#currentOwnerFloor();
    await inspectVerifiedWitnessFreshHeadV1({
      raw: witness, nonce: bytes(nonce, 32), scope: this.scope,
      pinned: pinned.pinnedWitness, minimumHead: floor,
    });
    const signed = await z.decodeDeterministic(witness);
    const now = Math.floor(Date.now() / 1000);
    if ((!historical && Math.abs(signed.observed_at - now) > 30)
      || Number(signed.current_revision) !== Number(verified.revision)
      || !same(bytes(signed.current_manifest_digest, 32), verified.headDigest)
      || Number(header.manifest_revision) !== Number(verified.revision)
      || !same(bytes(header.manifest_digest, 32), verified.headDigest)
      || Number(header.epoch) !== Number(verified.headManifest.current_epoch)) fail();
    if (!historical) {
      // Fetch the current signed head independently on the CAS host. A caller
      // cannot keep authoring with A using a still-time-valid pre-revocation
      // witness receipt once the external witness has committed the revoke.
      const independentRaw = bytes(await pinned.freshWitnessHead({
        scope: this.scope, nonce: Buffer.from(nonce),
      }), 1, 8192);
      await inspectVerifiedWitnessFreshHeadV1({
        raw: independentRaw, nonce: bytes(nonce, 32), scope: this.scope,
        pinned: pinned.pinnedWitness, minimumHead: floor,
      });
      const latest = await z.decodeDeterministic(independentRaw);
      if (Math.abs(latest.observed_at - Math.floor(Date.now() / 1000)) > 30
        || Number(latest.current_revision) !== Number(verified.revision)
        || !same(bytes(latest.current_manifest_digest, 32), verified.headDigest)) fail();
    }
    const device = verified.headManifest.devices.find((entry) =>
      entry.device_id === header.signer_device_id
      && entry.revoked_at_epoch === null
      && Number(entry.enrolled_epoch) <= Number(header.epoch));
    if (!device) fail();
    const trustedKey = crypto.createPublicKey({ key: Buffer.concat([
      ED_SPKI, bytes(device.authorization_public_key, 32)]),
    format: "der", type: "spki" });
    if (publicFingerprint(trustedKey) !== publicFingerprint(signerKey)) fail();
    return { revision: Number(verified.revision),
      digest: Buffer.from(verified.headDigest), deviceId: device.device_id };
  }
  #currentOwnerFloor() {
    const saved = this.db.prepare("SELECT revision,digest FROM owner_authority WHERE scope=?")
      .get(this.scopeId);
    if (!saved || saved.revision < this.#ownerTrust.minimumHead.revision) fail();
    if (saved.revision === this.#ownerTrust.minimumHead.revision
      && !same(saved.digest, this.#ownerTrust.minimumHead.digest)) fail();
    return { revision: saved.revision, witnessSequence: saved.revision,
      digest: Buffer.from(saved.digest) };
  }
  async #syncFloor() {
    // Coalesce concurrent reconciliation, and never derive a trusted floor
    // solely from the local database that an attacker can roll back.
    if (this.#floorSync) return this.#floorSync;
    const running = this.#syncFloorInternal();
    this.#floorSync = running;
    try { return await running; }
    finally { if (this.#floorSync === running) this.#floorSync = null; }
  }
  async #syncFloorInternal() {
    let remote = await this.independentFloor.readHead({ scope: this.scope });
    if (remote.sequence < this.#minimum.sequence
      || (remote.sequence === this.#minimum.sequence
        && !same(remote.digest, this.#minimum.digest))
      || remote.sequence < this.#floor.sequence
      || (remote.sequence === this.#floor.sequence
        && !same(remote.digest, this.#floor.digest))) fail();
    this.#floor = { sequence: remote.sequence, digest: Buffer.from(remote.digest) };
    const local = await this.#inspect();
    if (local.sequence < remote.sequence
      || (local.sequence === remote.sequence && !same(local.digest, remote.digest))) fail();
    // FULL local commit may have survived while power loss or a dropped floor
    // acknowledgement prevented signing a receipt. Reconcile from VERIFIED
    // owner-signed immutable rows, one monotonic remote CAS per missing head.
    while (remote.sequence < local.sequence) {
      const row = this.db.prepare("SELECT * FROM snapshots WHERE scope=? AND sequence=?")
        .get(this.scopeId, remote.sequence + 1);
      if (!row) fail();
      const ownerSignerRow = this.#ownerTrust
        ? this.db.prepare("SELECT owner_evidence FROM signer_history WHERE scope=? AND sequence=?")
          .get(this.scopeId, row.sequence) : null;
      if (this.#ownerTrust && !ownerSignerRow) fail();
      const desired = { sequence: row.sequence, digest: Buffer.from(row.digest) };
      try {
        remote = await this.independentFloor.compareAndSwap({
          scope: this.scope, expectedSequence: remote.sequence,
          expectedDigest: remote.digest, nextSequence: desired.sequence,
          nextDigest: desired.digest, headBytes: row.header,
          headSignature: row.signature,
          ownerEvidence: this.#ownerTrust ? ownerSignerRow.owner_evidence : undefined,
          ownerNonce: this.#ownerTrust ? row.nonce : undefined,
        });
      } catch (_) {
        // An absent CAS ACK says nothing about durability. A NEW signed read
        // may establish that the exact digest was already accepted.
        remote = await this.independentFloor.readHead({ scope: this.scope });
      }
      if (remote.sequence !== desired.sequence || !same(remote.digest, desired.digest)) fail();
      this.#floor = { sequence: remote.sequence, digest: Buffer.from(remote.digest) };
    }
    const confirmed = await this.#inspect();
    if (confirmed.sequence !== remote.sequence || !same(confirmed.digest, remote.digest)) fail();
    return confirmed;
  }
  async #receipt(nonce, current) {
    const statement = { type: CAS_TYPE, ...this.scope,
      sequence: current.sequence, digest: Buffer.from(current.digest),
      nonce: bytes(nonce, 32), observed_at: Math.floor(Date.now() / 1000) };
    const signature = crypto.sign(null,
      Buffer.concat([catalogCasDomain, Buffer.from(await z.encodeDeterministic(statement))]),
      this.signer);
    return Buffer.from(await z.encodeDeterministic({ ...statement, signature }));
  }
  async readHead({ scope, nonce }) {
    if (!scopeEquals(scopeInput(scope), this.scope)) fail();
    await this.ready;
    return this.#serialize(async () => {
      const current = await this.#syncFloor();
      return this.#receipt(nonce, current);
    });
  }
  // Authenticated historical bytes are returned with a fresh Ed25519
  // signature binding the request nonce, scope, snapshot and CURRENT CAS head.
  // A stored digest alone can never repair a missing local snapshot.
  async fetchSnapshot({ scope, sequence, nonce }) {
    if (!scopeEquals(scopeInput(scope), this.scope)) fail();
    const wanted = integer(sequence, 1, MAX_SEQUENCE);
    const challenge = bytes(nonce, 32);
    await this.ready;
    return this.#serialize(async () => {
    await this.#syncFloor();
    const current = await this.#inspect();
    if (wanted > current.sequence) fail();
    const row = this.db.prepare("SELECT * FROM snapshots WHERE scope=? AND sequence=?")
      .get(this.scopeId, wanted);
    if (!row) fail();
    const packed = JSON.parse(row.pages.toString("utf8"));
    if (!Array.isArray(packed) || packed.length > 128) fail();
    const statement = {
      type: "rootark-zk1-opaque-catalog-snapshot-fetch/v1",
      ...this.scope, sequence: wanted, digest: Buffer.from(row.digest),
      head_sequence: current.sequence, head_digest: Buffer.from(current.digest),
      nonce: challenge, observed_at: Math.floor(Date.now() / 1000),
      header: Buffer.from(row.header), header_signature: Buffer.from(row.signature),
      page_bodies: packed.map((encoded) => Buffer.from(encoded, "base64url")),
    };
    // Refuse a concurrent CAS advance while preparing the signed response.
    const latest = this.#inspectSync();
    if (latest.sequence !== current.sequence || !same(latest.digest, current.digest)) fail();
    const signature = crypto.sign(null, Buffer.concat([
      SNAPSHOT_DOMAIN, Buffer.from(await z.encodeDeterministic(statement))]), this.signer);
    return Buffer.from(await z.encodeDeterministic({ ...statement, signature }));
    });
  }
  async compareAndSwap({ scope, expectedSequence, expectedDigest,
    nextSequence, nextDigest, nonce, headBytes, headSignature, pageBodies,
    ownerEvidence }) {
    if (!scopeEquals(scopeInput(scope), this.scope)) fail();
    await this.ready;
    return this.#serialize(async () => {
    await this.#syncFloor();
    const old = integer(expectedSequence, 0, MAX_SEQUENCE);
    const next = integer(nextSequence, 1, MAX_SEQUENCE);
    const previous = bytes(expectedDigest, 32);
    const wanted = bytes(nextDigest, 32);
    const challenge = bytes(nonce, 32);
    const headerRaw = bytes(headBytes, 1, 16384);
    const signature = bytes(headSignature, 64);
    if (next !== old + 1 || same(wanted, previous)
      || !Array.isArray(pageBodies) || pageBodies.length > 128) fail("ZK_OPAQUE_CAS_CONFLICT");
    if (!same(catalogHeadDigest(headerRaw, signature), wanted)) fail();
    const header = await z.decodeDeterministic(headerRaw);
    exact(header, HEAD_FIELDS);
    let activeSigner = this.catalogSigner;
    let verifiedOwner = null;
    let evidenceRaw = null;
    if (this.#ownerTrust) {
      evidenceRaw = bytes(ownerEvidence, 1, 2 * 1024 * 1024);
      // The signer key comes ONLY from a verified owner-rooted V2 history.
      const evidence = await z.decodeDeterministic(evidenceRaw);
      exact(evidence, OWNER_EVIDENCE);
      const trust = this.#ownerTrust;
      const proof = await ownerHistory.verifyRecoveryHistoryPublicV2({
        expectedScope: this.scope, baseManifest: evidence.baseManifest,
        baseReceipt: evidence.baseReceipt, transitions: evidence.transitions,
        packageEnvelopes: evidence.packageEnvelopes,
        pinnedWitness: trust.pinnedWitness, now: Math.floor(Date.now() / 1000),
      });
      if (!await ownerHistory.isVerifiedPublicRecoveryHistoryV2(proof)
        || !same(await ownerManifest.recoveryManifestDigestV2(proof.baseManifest),
          trust.genesisDigest)) fail();
      const device = proof.headManifest.devices.find((entry) =>
        entry.device_id === header.signer_device_id);
      if (!device) fail();
      activeSigner = crypto.createPublicKey({ key: Buffer.concat([
        ED_SPKI, bytes(device.authorization_public_key, 32)]),
      format: "der", type: "spki" });
      verifiedOwner = await this.#verifyOwnerEvidence({
        evidenceRaw, nonce: challenge, header, signerKey: activeSigner,
        historical: false });
    }
    if (!crypto.verify(null, Buffer.concat([HEAD_DOMAIN, headerRaw]),
      activeSigner, signature)) fail();
    if (header.type !== HEAD_TYPE || !scopeEquals(header, this.scope)
      || header.sequence !== next || !same(bytes(header.previous_digest, 32), previous)
      || !Number.isSafeInteger(header.issued_at)
      || Math.abs(header.issued_at - Math.floor(Date.now() / 1000)) > 60
      || !Number.isSafeInteger(header.total_count) || header.total_count > 4096
      || header.total_count < 0 || !Array.isArray(header.page_digests)
      || header.page_digests.length !== pageBodies.length
      || header.page_digests.length !== Math.ceil(header.total_count / 32)) fail();
    const packed = [];
    for (let i = 0; i < pageBodies.length; i++) {
      const body = bytes(pageBodies[i], 1, 16384);
      if (!same(crypto.createHash("sha256").update(PAGE_DOMAIN).update(body).digest(),
        bytes(header.page_digests[i], 32))) fail();
      const page = await z.decodeDeterministic(body);
      if (!Array.isArray(page) || page.length < 1 || page.length > 32
        || (i !== pageBodies.length - 1 && page.length !== 32)) fail();
      packed.push(body.toString("base64url"));
    }
    if (pageBodies.length && header.total_count !==
      (pageBodies.length - 1) * 32
        + (await z.decodeDeterministic(pageBodies.at(-1))).length) fail();
    const packedBytes = Buffer.from(JSON.stringify(packed));
    // IMMEDIATE obtains SQLite's process-wide writer lock BEFORE comparing
    // the head and burning the nonce. FULL commits the complete snapshot
    // transaction before the independent Ed25519 receipt is produced.
    const transaction = this.db.transaction(() => {
      const current = this.#inspectSync();
      if (current.sequence !== old || !same(current.digest, previous)) fail("ZK_OPAQUE_CAS_CONFLICT");
      if (this.db.prepare("SELECT 1 FROM snapshots WHERE scope=? AND nonce=?")
        .get(this.scopeId, challenge)) fail("ZK_OPAQUE_CAS_REPLAY");
      if (verifiedOwner) {
        const floor = this.#currentOwnerFloor();
        if (verifiedOwner.revision < floor.revision
          || (verifiedOwner.revision === floor.revision
            && !same(verifiedOwner.digest, floor.digest))) fail("ZK_OPAQUE_CAS_CONFLICT");
        const prior = this.db.prepare("SELECT * FROM signer_history WHERE scope=? AND sequence=?")
          .get(this.scopeId, old);
        if (old === 0 && publicFingerprint(activeSigner) !== publicFingerprint(this.catalogSigner)) fail();
        if (prior && !same(prior.signer_spki,
          activeSigner.export({ format: "der", type: "spki" }))
          && verifiedOwner.revision <= prior.owner_revision) fail("ZK_OPAQUE_CAS_CONFLICT");
      }
      this.db.prepare("INSERT INTO snapshots VALUES (?,?,?,?,?,?,?,?)").run(
        this.scopeId, next, wanted, headerRaw, signature, packedBytes,
        challenge, Math.floor(Date.now() / 1000));
      if (verifiedOwner) {
        this.db.prepare("INSERT INTO signer_history VALUES (?,?,?,?,?,?)").run(
          this.scopeId, next, activeSigner.export({ type: "spki", format: "der" }),
          verifiedOwner.revision, verifiedOwner.digest, evidenceRaw);
        this.db.prepare("UPDATE owner_authority SET revision=?,digest=? WHERE scope=?")
          .run(verifiedOwner.revision, verifiedOwner.digest, this.scopeId);
      }
      this.db.prepare(`INSERT INTO heads(scope,sequence,digest) VALUES(?,?,?)
        ON CONFLICT(scope) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest`)
        .run(this.scopeId, next, wanted);
    });
    transaction.immediate();
    // Fault injection is available only to the separate-process test harness.
    // It simulates abrupt power loss after SQLite FULL commit and before floor
    // contact, proving startup reconciliation cannot issue an unanchored ACK.
    if (process.env.NODE_ENV === "test" && typeof this.testOnlyAfterLocalCommit === "function") {
      this.testOnlyAfterLocalCommit();
    }
    const confirmed = await this.#syncFloor();
    if (confirmed.sequence !== next || !same(confirmed.digest, wanted)) fail();
    return this.#receipt(challenge, confirmed);
    });
  }
  close() { if (this.db.open) this.db.close(); }
}

module.exports = { Zk1OpaqueCatalogCasLedger };
