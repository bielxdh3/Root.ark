"use strict";

// Opt-in encrypted-name catalog. Entries are public opaque object IDs and
// ciphertext digests; paths, names, keys and file contents never enter here.
// A device authorized by the owner-rooted V2 history signs the complete
// paged inventory. An INDEPENDENT pinned Ed25519 CAS authority witnesses its
// monotonically advancing head. Local SQLite is never a head authority.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0", "ascii");
const PAGE_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0", "ascii");
const CAS_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0", "ascii");
const ID_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-operation-id/v1\0", "ascii");
const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const EMPTY = Buffer.alloc(32);
const PAGE_SIZE = 32;
const MAX_ENTRIES = 4096;
const MAX_HEADS = 128;
const MAX_HEAD_BYTES = 16 * 1024;
const MAX_PAGE_BYTES = 16 * 1024;
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const HEADER = ["type", ...SCOPE, "sequence", "previous_digest", "manifest_revision",
  "manifest_digest", "epoch", "signer_device_id", "total_count", "page_digests", "issued_at"];
const ITEM = ["object_id", "revision", "epoch", "ciphertext_digest", "metadata_ciphertext"];
const CAS_FIELDS = ["type", ...SCOPE, "sequence", "digest", "nonce", "observed_at"];
const TYPE = "rootark-zk1-opaque-catalog/v1";
const CAS_TYPE = "rootark-zk1-opaque-catalog-cas/v1";

function fail(code = "ZK_CATALOG_DENIED") {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) fail();
}
function buf(value, length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength !== length) fail();
  return Buffer.from(value);
}
function same(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b)
    && a.length === b.length && crypto.timingSafeEqual(a, b);
}
function number(value, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail();
  return value;
}
function normScope(raw) {
  exact(raw, SCOPE);
  if (!raw.compartment_id || ![Buffer, Uint8Array].some((c) => raw.compartment_id instanceof c)
    || raw.compartment_id.byteLength < 1 || raw.compartment_id.byteLength > 128) fail();
  return { account_id: buf(raw.account_id, 16),
    compartment_id: Buffer.from(raw.compartment_id), keyring_id: buf(raw.keyring_id, 16) };
}
function scopeKey(scope) {
  return SCOPE.map((key) => scope[key].toString("hex")).join(":");
}
function checkScope(raw, wanted) {
  for (const key of SCOPE) {
    if ((!Buffer.isBuffer(raw[key]) && !(raw[key] instanceof Uint8Array))
      || !same(Buffer.from(raw[key]), wanted[key])) fail();
  }
}
function objectId(scope, operation, page = 0) {
  if (!["catalog-commit", "catalog-read"].includes(operation)) fail();
  number(page, 0, MAX_ENTRIES / PAGE_SIZE);
  return crypto.createHash("sha256").update(ID_DOMAIN)
    .update(Buffer.from(scopeKey(normScope(scope)), "utf8"))
    .update(Buffer.from(operation, "ascii"))
    .update(Buffer.from(":" + page, "ascii"))
    .digest().subarray(0, 16).toString("base64url");
}
async function digestPage(entries) {
  return crypto.createHash("sha256").update(PAGE_DOMAIN)
    .update(Buffer.from(await z.encodeDeterministic(entries))).digest();
}
async function headerMessage(header) {
  return Buffer.concat([HEAD_DOMAIN, Buffer.from(await z.encodeDeterministic(header))]);
}
function headDigest(headerBytes, signature) {
  return crypto.createHash("sha256").update(HEAD_DOMAIN)
    .update(headerBytes).update(signature).digest();
}
async function normalizePages(pages) {
  if (!Array.isArray(pages) || pages.length > MAX_ENTRIES / PAGE_SIZE) fail();
  const normalized = [];
  let previous = null;
  for (const page of pages) {
    if (!Array.isArray(page) || page.length < 1 || page.length > PAGE_SIZE) fail();
    const result = [];
    for (const raw of page) {
      exact(raw, ITEM);
      const id = raw.object_id;
      if (typeof id !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(id)
        || Buffer.from(id, "base64url").toString("base64url") !== id) fail();
      const revision = number(raw.revision, 1);
      const epoch = number(raw.epoch, 1);
      const order = id + ":" + String(revision).padStart(17, "0");
      if (previous && previous >= order) fail();
      previous = order;
      result.push({ object_id: id, revision, epoch,
        ciphertext_digest: buf(raw.ciphertext_digest, 32),
        metadata_ciphertext: buf(raw.metadata_ciphertext, 284) });
    }
    normalized.push(result);
  }
  if (normalized.some((page, i) => i < normalized.length - 1 && page.length !== PAGE_SIZE)) fail();
  return normalized;
}
function validateHeader(header, scope) {
  exact(header, HEADER);
  if (header.type !== TYPE) fail();
  checkScope(header, scope);
  number(header.sequence, 1, MAX_HEADS);
  buf(header.previous_digest, 32);
  number(header.manifest_revision, 1);
  buf(header.manifest_digest, 32);
  number(header.epoch, 1);
  number(header.issued_at, 0);
  number(header.total_count, 0, MAX_ENTRIES);
  if (typeof header.signer_device_id !== "string"
    || header.signer_device_id.length < 1 || header.signer_device_id.length > 64
    || /[\u0000-\u001f\u007f]/.test(header.signer_device_id)) fail();
  if (!Array.isArray(header.page_digests)
    || header.page_digests.length !== Math.ceil(header.total_count / PAGE_SIZE)
    || header.page_digests.some((x) => !same(buf(x, 32), Buffer.from(x)))) fail();
}
async function verifyCas(raw, scope, nonce, authority, now) {
  if ((!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array)) || raw.byteLength > 8192) {
    fail("ZK_CATALOG_UNAVAILABLE");
  }
  try {
    const signed = await z.decodeDeterministic(raw);
    exact(signed, [...CAS_FIELDS, "signature"]);
    const { signature, ...statement } = signed;
    exact(statement, CAS_FIELDS);
    if (statement.type !== CAS_TYPE) fail();
    checkScope(statement, scope);
    number(statement.sequence, 0, MAX_HEADS);
    buf(statement.digest, 32);
    if (!same(buf(statement.nonce, 32), nonce)
      || Math.abs(number(statement.observed_at) - now) > 30) fail();
    if (statement.sequence === 0 && !same(Buffer.from(statement.digest), EMPTY)) fail();
    const payload = Buffer.concat([CAS_DOMAIN, Buffer.from(await z.encodeDeterministic(statement))]);
    if (!crypto.verify(null, payload, authority.publicKey, buf(signature, 64))) fail();
    return { sequence: statement.sequence, digest: Buffer.from(statement.digest),
      proof: Buffer.from(raw) };
  } catch (_) { fail("ZK_CATALOG_UNAVAILABLE"); }
}

class Zk1OpaqueCatalog {
  constructor({ store, authority }) {
    if (!store?.signedHistoryRequired || store.admissionRequired !== true || !store.db
      || typeof store.runCatalogWithAdmission !== "function"
      || typeof authority?.readHead !== "function"
      || typeof authority?.compareAndSwap !== "function"
      || !(authority.publicKey instanceof crypto.KeyObject)
      || authority.publicKey.type !== "public"
      || authority.publicKey.asymmetricKeyType !== "ed25519") fail();
    this.store = store;
    this.authority = authority;
    const db = store.db;
    db.exec(`CREATE TABLE IF NOT EXISTS zk_content_catalog_head (
      scope TEXT PRIMARY KEY, sequence INTEGER NOT NULL, digest BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS zk_content_catalog_snapshot (
      scope TEXT NOT NULL, sequence INTEGER NOT NULL,
      digest BLOB NOT NULL, header BLOB NOT NULL, signature BLOB NOT NULL,
      PRIMARY KEY(scope,sequence)
    );
    CREATE TABLE IF NOT EXISTS zk_content_catalog_page (
      scope TEXT NOT NULL, sequence INTEGER NOT NULL, page INTEGER NOT NULL,
      body BLOB NOT NULL, PRIMARY KEY(scope,sequence,page)
    );
    CREATE TRIGGER IF NOT EXISTS zk_catalog_snapshot_no_update
      BEFORE UPDATE ON zk_content_catalog_snapshot
      BEGIN SELECT RAISE(ABORT,'ZK_CATALOG_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS zk_catalog_snapshot_no_delete
      BEFORE DELETE ON zk_content_catalog_snapshot
      BEGIN SELECT RAISE(ABORT,'ZK_CATALOG_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS zk_catalog_page_no_update
      BEFORE UPDATE ON zk_content_catalog_page
      BEGIN SELECT RAISE(ABORT,'ZK_CATALOG_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS zk_catalog_page_no_delete
      BEFORE DELETE ON zk_content_catalog_page
      BEGIN SELECT RAISE(ABORT,'ZK_CATALOG_IMMUTABLE'); END;`);
    this.head = db.prepare("SELECT sequence,digest FROM zk_content_catalog_head WHERE scope=?");
    this.snapshot = db.prepare("SELECT * FROM zk_content_catalog_snapshot WHERE scope=? AND sequence=?");
    this.page = db.prepare("SELECT body FROM zk_content_catalog_page WHERE scope=? AND sequence=? AND page=?");
  }
  // Consume signed device challenge in the SAME persistent nonce and owner
  // head watermark as protected put/get. Never rewind the local wall clock.
  consume(auth) {
    const store = this.store;
    store.db.transaction(() => {
      const { key, request, head } = auth;
      const now = number(store.nowSeconds(), 0);
      if (now < request.issued_at - 5 || now > request.expires_at) fail();
      const clock = store.clockRow.get(key);
      if (clock && now < clock.last_at) fail("ZK_CATALOG_UNAVAILABLE");
      const old = store.getHead.get(key);
      const floor = old && old.revision >= store.minimumHead.revision
        ? old : store.minimumHead;
      const revision = Number(head.current_revision);
      const digest = Buffer.from(head.current_manifest_digest);
      if (revision < floor.revision
        || (revision === floor.revision && !same(digest, Buffer.from(floor.digest)))) {
        fail("ZK_CATALOG_UNAVAILABLE");
      }
      store.db.prepare("DELETE FROM zk_content_nonce WHERE scope=? AND expires_at IS NOT NULL AND expires_at<?")
        .run(key, now);
      if (store.db.prepare("SELECT 1 FROM zk_content_nonce WHERE scope=? AND nonce=?")
        .get(key, request.nonce)) fail("ZK_CATALOG_REPLAY");
      if (store.nonceCount.get(key).n >= 100000) fail("ZK_CATALOG_UNAVAILABLE");
      store.db.prepare("INSERT INTO zk_content_nonce(scope,nonce,expires_at) VALUES(?,?,?)")
        .run(key, request.nonce, request.expires_at);
      store.db.prepare("INSERT INTO zk_content_clock(scope,last_at) VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET last_at=excluded.last_at")
        .run(key, now);
      store.db.prepare("INSERT INTO zk_content_head(scope,revision,digest) VALUES(?,?,?) ON CONFLICT(scope) DO UPDATE SET revision=excluded.revision,digest=excluded.digest")
        .run(key, revision, digest);
    }).immediate();
  }
  async fresh(auth) {
    const now = number(this.store.nowSeconds(), 0);
    return verifyCas(await this.authority.readHead({
      scope: this.store.trustedScope, nonce: Buffer.from(auth.request.nonce) }),
    this.store.trustedScope, auth.request.nonce, this.authority, now);
  }
  localMatches(key, current) {
    const local = this.head.get(key);
    if ((!local && current.sequence !== 0)
      || (local && (local.sequence !== current.sequence || !same(local.digest, current.digest)))) {
      fail("ZK_CATALOG_UNAVAILABLE");
    }
  }
  async verifyStoredChain(key, current) {
    let previous = Buffer.from(EMPTY);
    for (let seq = 1; seq <= current.sequence; seq++) {
      const saved = this.snapshot.get(key, seq);
      if (!saved || saved.header.length > MAX_HEAD_BYTES
        || !same(saved.digest, headDigest(saved.header, saved.signature))) {
        fail("ZK_CATALOG_UNAVAILABLE");
      }
      const header = await z.decodeDeterministic(saved.header);
      validateHeader(header, this.store.trustedScope);
      if (header.sequence !== seq || !same(Buffer.from(header.previous_digest), previous)) {
        fail("ZK_CATALOG_UNAVAILABLE");
      }
      const pageCount = this.store.db.prepare(
        "SELECT COUNT(*) AS n FROM zk_content_catalog_page WHERE scope=? AND sequence=?")
        .get(key, seq).n;
      if (pageCount !== header.page_digests.length) fail("ZK_CATALOG_UNAVAILABLE");
      previous = Buffer.from(saved.digest);
    }
    if (!same(previous, current.digest)) fail("ZK_CATALOG_UNAVAILABLE");
  }
  async commit({ scope, authorization, signature, header, headerSignature, pages,
    emit = (result) => result }) {
    return this.store.runCatalogWithAdmission({ scope, authorization, signature },
      "catalog-commit", async (auth) => {
        const wanted = this.store.trustedScope;
        validateHeader(header, wanted);
        const request = auth.request;
        if (request.object_id !== objectId(wanted, "catalog-commit")
          || request.device_id !== header.signer_device_id
          || request.manifest_revision !== header.manifest_revision
          || !same(request.manifest_digest, Buffer.from(header.manifest_digest))
          || request.epoch !== header.epoch
          || (request.expected_object_revision ?? 0) !== header.sequence - 1
          || header.issued_at !== request.issued_at) fail();
        const normalized = await normalizePages(pages);
        if (normalized.reduce((n, page) => n + page.length, 0) !== header.total_count) fail();
        const bodies = await Promise.all(normalized.map((page) => z.encodeDeterministic(page)));
        for (let i = 0; i < bodies.length; i++) {
          if (bodies[i].byteLength > MAX_PAGE_BYTES
            || !same(await digestPage(normalized[i]), buf(header.page_digests[i], 32))) fail();
        }
        const publicKey = crypto.createPublicKey({ key: Buffer.concat([
          ED_SPKI, buf(auth.deviceAuthorizationPublicKey, 32)]), format: "der", type: "spki" });
        const signed = buf(headerSignature, 64);
        if (!crypto.verify(null, await headerMessage(header), publicKey, signed)) fail();
        const headerBytes = Buffer.from(await z.encodeDeterministic(header));
        if (headerBytes.length > MAX_HEAD_BYTES) fail();
        const digest = headDigest(headerBytes, signed);
        if (!same(request.ciphertext_digest, digest)) fail();
        const key = scopeKey(wanted);
        const current = await this.fresh(auth);
        this.localMatches(key, current);
        await this.verifyStoredChain(key, current);
        if (current.sequence >= MAX_HEADS
          || header.sequence !== current.sequence + 1
          || !same(buf(header.previous_digest, 32), current.digest)) fail("ZK_CATALOG_CONFLICT");
        // Owner-authorized signer cannot attest a conveniently omitted list:
        // compare every immutable locally archived ciphertext VERSION exactly.
        const rows = this.store.db.prepare("SELECT id,revision,epoch,ciphertext_digest FROM zk_content_version WHERE scope=? ORDER BY id COLLATE BINARY,revision").all(key);
        const listed = normalized.flat();
        if (rows.length !== listed.length || rows.length > MAX_ENTRIES) fail("ZK_CATALOG_CONFLICT");
        for (let i = 0; i < rows.length; i++) {
          if (rows[i].id !== listed[i].object_id
            || rows[i].revision !== listed[i].revision || rows[i].epoch !== listed[i].epoch
            || !same(rows[i].ciphertext_digest, listed[i].ciphertext_digest)) fail("ZK_CATALOG_CONFLICT");
        }
        this.consume(auth);
        // Authority must atomically CAS independently of local SQLite. A
        // lost ACK may leave the catalog unavailable until audited recovery.
        const receipt = await this.authority.compareAndSwap({
          scope: wanted, expectedSequence: current.sequence,
          expectedDigest: current.digest, nextSequence: header.sequence,
          nextDigest: digest, nonce: request.nonce,
        });
        const witnessed = await verifyCas(receipt, wanted, request.nonce,
          this.authority, number(this.store.nowSeconds(), 0));
        if (witnessed.sequence !== header.sequence || !same(witnessed.digest, digest)) {
          fail("ZK_CATALOG_UNAVAILABLE");
        }
        this.store.db.transaction(() => {
          this.localMatches(key, current);
          this.store.db.prepare("INSERT INTO zk_content_catalog_snapshot(scope,sequence,digest,header,signature) VALUES(?,?,?,?,?)")
            .run(key, header.sequence, digest, headerBytes, signed);
          for (let i = 0; i < bodies.length; i++) {
            this.store.db.prepare("INSERT INTO zk_content_catalog_page(scope,sequence,page,body) VALUES(?,?,?,?)")
              .run(key, header.sequence, i, Buffer.from(bodies[i]));
          }
          this.store.db.prepare("INSERT INTO zk_content_catalog_head(scope,sequence,digest) VALUES(?,?,?) ON CONFLICT(scope) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest")
            .run(key, header.sequence, digest);
        }).immediate();
        return emit({ sequence: header.sequence, catalogDigest: digest.toString("base64url"),
          authorityProofBase64: witnessed.proof.toString("base64url") });
      });
  }
  async read({ scope, authorization, signature, pageIndex, emit = (result) => result }) {
    return this.store.runCatalogWithAdmission({ scope, authorization, signature },
      "catalog-read", async (auth) => {
        const page = number(pageIndex, 0, MAX_ENTRIES / PAGE_SIZE);
        if (auth.request.object_id !== objectId(this.store.trustedScope, "catalog-read", page)) fail();
        const current = await this.fresh(auth);
        const key = scopeKey(this.store.trustedScope);
        this.localMatches(key, current);
        await this.verifyStoredChain(key, current);
        if (current.sequence < 1) fail("ZK_CATALOG_NOT_FOUND");
        if (auth.request.expected_object_revision !== current.sequence
          || !same(auth.request.ciphertext_digest, current.digest)) fail("ZK_CATALOG_CONFLICT");
        const record = this.snapshot.get(key, current.sequence);
        if (!record || !same(record.digest, current.digest)
          || !same(headDigest(record.header, record.signature), current.digest)) {
          fail("ZK_CATALOG_UNAVAILABLE");
        }
        const header = await z.decodeDeterministic(record.header);
        validateHeader(header, this.store.trustedScope);
        const totalVersions = this.store.db.prepare(
          "SELECT COUNT(*) AS n FROM zk_content_version WHERE scope=?").get(key).n;
        if (totalVersions !== header.total_count) fail("ZK_CATALOG_UNAVAILABLE");
        if (header.sequence !== current.sequence || header.manifest_revision > auth.request.manifest_revision
          || page >= Math.max(1, header.page_digests.length)) fail("ZK_CATALOG_CONFLICT");
        const signer = auth.verifiedHeadManifest.devices.find((device) =>
          device.device_id === header.signer_device_id
          && device.revoked_at_epoch === null && Number(device.enrolled_epoch) <= auth.request.epoch);
        if (!signer) fail("ZK_CATALOG_DENIED");
        const publicKey = crypto.createPublicKey({ key: Buffer.concat([
          ED_SPKI, buf(signer.authorization_public_key, 32)]), format: "der", type: "spki" });
        if (!crypto.verify(null, Buffer.concat([HEAD_DOMAIN, record.header]),
          publicKey, record.signature)) fail("ZK_CATALOG_DENIED");
        const payload = this.page.get(key, current.sequence, page);
        const entries = payload ? await z.decodeDeterministic(payload.body) : [];
        if ((header.total_count === 0 && page !== 0)
          || (header.total_count !== 0 && !payload)
          || (payload && !same(await digestPage(entries), Buffer.from(header.page_digests[page])))) {
          fail("ZK_CATALOG_UNAVAILABLE");
        }
        this.consume(auth);
        return emit({ sequence: current.sequence, totalCount: header.total_count, pageIndex: page,
          pageCount: header.page_digests.length, catalogDigest: current.digest.toString("base64url"),
          headerBase64: record.header.toString("base64url"),
          headerSignatureBase64: record.signature.toString("base64url"),
          entries: entries.map((entry) => ({
            objectId: entry.object_id, revision: entry.revision, epoch: entry.epoch,
            ciphertextDigestBase64: Buffer.from(entry.ciphertext_digest).toString("base64url"),
            metadataCiphertextBase64: Buffer.from(entry.metadata_ciphertext).toString("base64url"),
          })), authorityProofBase64: current.proof.toString("base64url") });
      });
  }
}
module.exports = { Zk1OpaqueCatalog, catalogOperationObjectId: objectId,
  catalogHeaderMessage: headerMessage, catalogHeadDigest: headDigest,
  catalogPageDigest: digestPage, catalogCasDomain: CAS_DOMAIN };
