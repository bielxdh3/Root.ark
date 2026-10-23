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

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const PAGE_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0");
const EMPTY = Buffer.alloc(32);
const MAX_SEQUENCE = 128;
const HEAD_TYPE = "rootark-zk1-opaque-catalog/v1";
const CAS_TYPE = "rootark-zk1-opaque-catalog-cas/v1";
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
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
}

class Zk1OpaqueCatalogCasLedger {
  #minimum;
  #floor;
  constructor(filename, { bootstrapNew, signingPrivateKey, catalogSignerPublicKey,
    trustedScope, minimumHead } = {}) {
    if (typeof filename !== "string" || !path.isAbsolute(filename)
      || !(signingPrivateKey instanceof crypto.KeyObject)
      || signingPrivateKey.type !== "private" || signingPrivateKey.asymmetricKeyType !== "ed25519"
      || !(catalogSignerPublicKey instanceof crypto.KeyObject)
      || catalogSignerPublicKey.type !== "public" || catalogSignerPublicKey.asymmetricKeyType !== "ed25519"
      || !minimumHead) fail();
    this.scope = scopeInput(trustedScope);
    this.scopeId = scopeId(this.scope);
    this.signer = signingPrivateKey;
    this.publicKey = crypto.createPublicKey(signingPrivateKey);
    this.catalogSigner = catalogSignerPublicKey;
    if (publicFingerprint(this.publicKey) === publicFingerprint(this.catalogSigner)) fail();
    this.#minimum = {
      sequence: integer(minimumHead.sequence, 0, MAX_SEQUENCE),
      digest: bytes(minimumHead.digest, 32),
    };
    if (this.#minimum.sequence === 0 && !same(this.#minimum.digest, EMPTY)) fail();
    this.#floor = { sequence: this.#minimum.sequence, digest: Buffer.from(this.#minimum.digest) };
    privateDir(filename);
    const exists = fs.existsSync(filename);
    if (bootstrapNew !== !exists || (bootstrapNew && this.#minimum.sequence !== 0)) fail();
    if (exists) {
      const stat = fs.lstatSync(filename);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
        || (process.platform !== "win32"
          && (stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0))) fail();
    }
    this.db = new Database(filename, { fileMustExist: exists, timeout: 3000 });
    try {
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = FULL");
      this.db.pragma("foreign_keys = ON");
      this.db.exec(`CREATE TABLE IF NOT EXISTS identity (
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
      CREATE TRIGGER IF NOT EXISTS immutable_opaque_snapshot_update
        BEFORE UPDATE ON snapshots BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS immutable_opaque_snapshot_delete
        BEFORE DELETE ON snapshots BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
      const identity = [publicFingerprint(this.publicKey),
        publicFingerprint(this.catalogSigner), this.scopeId];
      if (!exists) this.db.prepare("INSERT INTO identity VALUES (1,?,?,?)").run(...identity);
      const saved = this.db.prepare("SELECT * FROM identity WHERE id=1").get();
      if (!saved || saved.authority_fp !== identity[0]
        || saved.catalog_fp !== identity[1] || saved.scope !== identity[2]) fail();
      // Parsing deterministic CBOR uses the project's verified async ESM
      // codec. Callers MUST await ready before admitting TLS requests.
      this.ready = this.#inspect();
    } catch (error) { this.db.close(); throw error; }
  }
  #inspectSync() {
    const rows = this.db.prepare("SELECT * FROM snapshots WHERE scope=? ORDER BY sequence")
      .all(this.scopeId);
    if (rows.length > MAX_SEQUENCE) fail();
    let digest = EMPTY;
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
      if (!crypto.verify(null, Buffer.concat([HEAD_DOMAIN, row.header]),
        this.catalogSigner, row.signature)) fail();
      digest = row.digest;
    }
    const head = this.db.prepare("SELECT sequence,digest FROM heads WHERE scope=?").get(this.scopeId);
    if ((head && (head.sequence !== rows.length || !same(head.digest, digest)))
      || (!head && rows.length)) fail();
    const sequence = head?.sequence || 0;
    if (sequence < this.#floor.sequence
      || (sequence === this.#floor.sequence && !same(digest, this.#floor.digest))) fail();
    if (sequence > this.#floor.sequence) this.#floor = { sequence, digest: Buffer.from(digest) };
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
      previous = row.digest;
    }
    // A second sync check detects a concurrent head change between full
    // signed history validation and receipt creation.
    const latest = this.#inspectSync();
    if (latest.sequence !== current.sequence || !same(latest.digest, current.digest)) fail();
    return latest;
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
    const current = await this.#inspect();
    return this.#receipt(nonce, current);
  }
  async compareAndSwap({ scope, expectedSequence, expectedDigest,
    nextSequence, nextDigest, nonce, headBytes, headSignature, pageBodies }) {
    if (!scopeEquals(scopeInput(scope), this.scope)) fail();
    await this.ready;
    const old = integer(expectedSequence, 0, MAX_SEQUENCE);
    const next = integer(nextSequence, 1, MAX_SEQUENCE);
    const previous = bytes(expectedDigest, 32);
    const wanted = bytes(nextDigest, 32);
    const challenge = bytes(nonce, 32);
    const headerRaw = bytes(headBytes, 1, 16384);
    const signature = bytes(headSignature, 64);
    if (next !== old + 1 || same(wanted, previous)
      || !Array.isArray(pageBodies) || pageBodies.length > 128) fail("ZK_OPAQUE_CAS_CONFLICT");
    if (!same(catalogHeadDigest(headerRaw, signature), wanted)
      || !crypto.verify(null, Buffer.concat([HEAD_DOMAIN, headerRaw]), this.catalogSigner, signature)) fail();
    const header = await z.decodeDeterministic(headerRaw);
    exact(header, HEAD_FIELDS);
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
      this.db.prepare("INSERT INTO snapshots VALUES (?,?,?,?,?,?,?,?)").run(
        this.scopeId, next, wanted, headerRaw, signature, packedBytes,
        challenge, Math.floor(Date.now() / 1000));
      this.db.prepare(`INSERT INTO heads(scope,sequence,digest) VALUES(?,?,?)
        ON CONFLICT(scope) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest`)
        .run(this.scopeId, next, wanted);
    });
    transaction.immediate();
    const confirmed = await this.#inspect();
    if (confirmed.sequence !== next || !same(confirmed.digest, wanted)) fail();
    return this.#receipt(challenge, confirmed);
  }
  close() { if (this.db.open) this.db.close(); }
}

module.exports = { Zk1OpaqueCatalogCasLedger };
