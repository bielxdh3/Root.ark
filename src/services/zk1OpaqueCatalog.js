"use strict";

// Opt-in encrypted-name catalog. Entries are public opaque object IDs and
// ciphertext digests; paths, names, keys and file contents never enter here.
// A device authorized by the owner-rooted V2 history signs the complete
// paged inventory. An INDEPENDENT pinned Ed25519 CAS authority witnesses its
// monotonically advancing head. Local SQLite is never a head authority.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const { auditZk1CatalogReendorsement } = require("./zk1CatalogReendorsement");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0", "ascii");
const PAGE_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0", "ascii");
const CAS_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0", "ascii");
const SNAPSHOT_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-snapshot-fetch/v1\0", "ascii");
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
const SNAPSHOT_TYPE = "rootark-zk1-opaque-catalog-snapshot-fetch/v1";
const SNAPSHOT_FIELDS = ["type", ...SCOPE, "sequence", "digest",
  "head_sequence", "head_digest", "nonce", "observed_at",
  "header", "header_signature", "page_bodies"];

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
async function verifiedRemoteSnapshot(raw, scope, nonce, current, authority, now) {
  if ((!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array))
    || raw.byteLength < 1 || raw.byteLength > 3 * 1024 * 1024) {
    fail("ZK_CATALOG_UNAVAILABLE");
  }
  try {
    const signed = await z.decodeDeterministic(raw);
    exact(signed, [...SNAPSHOT_FIELDS, "signature"]);
    const { signature, ...statement } = signed;
    exact(statement, SNAPSHOT_FIELDS);
    if (statement.type !== SNAPSHOT_TYPE) fail();
    checkScope(statement, scope);
    number(statement.sequence, 1, MAX_HEADS);
    number(statement.head_sequence, 1, MAX_HEADS);
    if (statement.sequence !== current.sequence
      || statement.head_sequence !== current.sequence
      || !same(buf(statement.digest, 32), current.digest)
      || !same(buf(statement.head_digest, 32), current.digest)
      || !same(buf(statement.nonce, 32), nonce)
      || Math.abs(number(statement.observed_at) - now) > 30) fail();
    if (!crypto.verify(null, Buffer.concat([SNAPSHOT_DOMAIN,
      Buffer.from(await z.encodeDeterministic(statement))]),
    authority.publicKey, buf(signature, 64))) fail();
    const headerBytes = buf(statement.header, statement.header.byteLength);
    const headSignature = buf(statement.header_signature, 64);
    if (!headerBytes.length || headerBytes.length > MAX_HEAD_BYTES
      || !same(headDigest(headerBytes, headSignature), current.digest)) fail();
    const header = await z.decodeDeterministic(headerBytes);
    validateHeader(header, scope);
    if (header.sequence !== current.sequence) fail();
    if (!same(Buffer.from(await z.encodeDeterministic(header)), headerBytes)) fail();
    if (!Array.isArray(statement.page_bodies)
      || statement.page_bodies.length !== header.page_digests.length) fail();
    const bodies = [];
    const pages = [];
    for (let i = 0; i < statement.page_bodies.length; i++) {
      const body = buf(statement.page_bodies[i], statement.page_bodies[i].byteLength);
      if (!body.length || body.length > MAX_PAGE_BYTES
        || !same(crypto.createHash("sha256").update(PAGE_DOMAIN).update(body).digest(),
          buf(header.page_digests[i], 32))) fail();
      const page = await z.decodeDeterministic(body);
      if (!same(Buffer.from(await z.encodeDeterministic(page)), body)) fail();
      bodies.push(body); pages.push(page);
    }
    const normalized = await normalizePages(pages);
    if (normalized.flat().length !== header.total_count) fail();
    return { header, headerBytes, headSignature, bodies, pages: normalized };
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
  rejectRollback(key, current) {
    const local = this.head.get(key);
    if (local && (local.sequence > current.sequence
      || (local.sequence === current.sequence && !same(local.digest, current.digest)))) {
      fail("ZK_CATALOG_UNAVAILABLE");
    }
  }
  assertMetadataContinuity(previousPages, nextPages) {
    const indexed = new Map(nextPages.flat().map((entry) =>
      [entry.object_id + ":" + entry.revision, entry]));
    for (const entry of previousPages.flat()) {
      const latest = indexed.get(entry.object_id + ":" + entry.revision);
      if (!latest || latest.epoch !== entry.epoch
        || !same(latest.ciphertext_digest, entry.ciphertext_digest)
        || !same(latest.metadata_ciphertext, entry.metadata_ciphertext)) {
        fail("ZK_CATALOG_UNAVAILABLE");
      }
    }
  }
  async verifyStoredChain(key, current, activeManifest) {
    let previous = Buffer.from(EMPTY);
    let previousPages = [];
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
      if (!same(Buffer.from(await z.encodeDeterministic(header)), saved.header)
        || header.manifest_revision > Number(activeManifest.revision)
        || header.epoch > Number(activeManifest.current_epoch)) fail("ZK_CATALOG_UNAVAILABLE");
      // A revoked signer remains valid ONLY for a head committed in an older
      // epoch. Its historical signature is verified against the owner-rooted
      // roster, but that key is never accepted to authorize fresh catalog I/O.
      const signer = activeManifest.devices.find((device) =>
        device.device_id === header.signer_device_id
        && Number(device.enrolled_epoch) <= header.epoch
        && (device.revoked_at_epoch === null
          || header.epoch < Number(device.revoked_at_epoch)));
      if (!signer || !crypto.verify(null, Buffer.concat([HEAD_DOMAIN, saved.header]),
        crypto.createPublicKey({ key: Buffer.concat([
          ED_SPKI, buf(signer.authorization_public_key, 32)]), format: "der", type: "spki" }),
        buf(saved.signature, 64))) fail("ZK_CATALOG_UNAVAILABLE");
      const pageCount = this.store.db.prepare(
        "SELECT COUNT(*) AS n FROM zk_content_catalog_page WHERE scope=? AND sequence=?")
        .get(key, seq).n;
      if (pageCount !== header.page_digests.length) fail("ZK_CATALOG_UNAVAILABLE");
      const archivedPages = [];
      for (let page = 0; page < pageCount; page++) {
        const stored = this.page.get(key, seq, page);
        if (!stored || stored.body.length > MAX_PAGE_BYTES) fail("ZK_CATALOG_UNAVAILABLE");
        const entries = await z.decodeDeterministic(stored.body);
        if (!same(Buffer.from(await z.encodeDeterministic(entries)), stored.body)
          || !same(await digestPage(entries), Buffer.from(header.page_digests[page]))) {
          fail("ZK_CATALOG_UNAVAILABLE");
        }
        archivedPages.push(entries);
      }
      const normalized = await normalizePages(archivedPages);
      if (normalized.flat().length !== header.total_count) fail("ZK_CATALOG_UNAVAILABLE");
      if (seq > 1) {
        try {
          auditZk1CatalogReendorsement({ previousPages, proposedPages: normalized });
        } catch (_) { fail("ZK_CATALOG_UNAVAILABLE"); }
      }
      previousPages = normalized;
      previous = Buffer.from(saved.digest);
    }
    if (!same(previous, current.digest)) fail("ZK_CATALOG_UNAVAILABLE");
    return previousPages;
  }
  verifyPhysicalVersions(key, pages) {
    const rows = this.store.db.prepare("SELECT id,revision,epoch,ciphertext,ciphertext_digest FROM zk_content_version WHERE scope=? ORDER BY id COLLATE BINARY,revision").all(key);
    const listed = pages.flat();
    // The signed snapshot is immutable, but a later authorized PUT can add a
    // physical version before a lost CAS ACK is reconciled. Every version in
    // the signed snapshot must still exist with identical bytes and epoch.
    // Newer physical rows must also have intact ciphertext digests; the NEXT
    // signed commit independently requires exact full-inventory equality.
    if (rows.length < listed.length || rows.length > MAX_ENTRIES) fail("ZK_CATALOG_UNAVAILABLE");
    const physical = new Map();
    for (const row of rows) {
      const version = row.id + ":" + row.revision;
      if (physical.has(version) || !Buffer.isBuffer(row.ciphertext)
        || !same(crypto.createHash("sha256").update(row.ciphertext).digest(), row.ciphertext_digest)) {
        fail("ZK_CATALOG_UNAVAILABLE");
      }
      physical.set(version, row);
    }
    for (const entry of listed) {
      const row = physical.get(entry.object_id + ":" + entry.revision);
      if (!row || row.epoch !== entry.epoch
        || !same(row.ciphertext_digest, entry.ciphertext_digest)) fail("ZK_CATALOG_UNAVAILABLE");
    }
  }
  async reconcileMissing(key, current, auth) {
    const local = this.head.get(key);
    if ((!local && current.sequence === 0)
      || (local && local.sequence === current.sequence
        && same(local.digest, current.digest))) {
      return this.verifyStoredChain(key, current, auth.verifiedHeadManifest);
    }
    // Only the missing tail of an independently committed snapshot can be
    // recovered. Never repair a fork, a rollback or an altered local row.
    if (typeof this.authority.fetchSnapshot !== "function"
      || current.sequence < 1
      || (local && (local.sequence !== current.sequence - 1))
      || (!local && current.sequence !== 1)) fail("ZK_CATALOG_UNAVAILABLE");
    const predecessor = local
      ? { sequence: local.sequence, digest: Buffer.from(local.digest) }
      : { sequence: 0, digest: Buffer.from(EMPTY) };
    const previousPages = await this.verifyStoredChain(key, predecessor,
      auth.verifiedHeadManifest);
    const orphan = this.store.db.prepare(
      "SELECT COUNT(*) AS n FROM zk_content_catalog_page WHERE scope=? AND sequence=?")
      .get(key, current.sequence).n;
    if (this.snapshot.get(key, current.sequence) || orphan) fail("ZK_CATALOG_UNAVAILABLE");
    const wanted = this.store.trustedScope;
    const raw = await this.authority.fetchSnapshot({
      scope: wanted, sequence: current.sequence, nonce: Buffer.from(auth.request.nonce) });
    const remote = await verifiedRemoteSnapshot(raw, wanted, auth.request.nonce,
      current, this.authority, number(this.store.nowSeconds(), 0));
    if (!same(buf(remote.header.previous_digest, 32), predecessor.digest)
      || remote.header.manifest_revision > auth.request.manifest_revision
      || remote.header.epoch > auth.request.epoch
      || (remote.header.manifest_revision === auth.request.manifest_revision
        && !same(buf(remote.header.manifest_digest, 32), auth.request.manifest_digest))) {
      fail("ZK_CATALOG_UNAVAILABLE");
    }
    // The signed device must still have an OWNER CURRENT V2 grant. Historical
    // revocation, stale epoch, or signer substitution never gains authority by
    // being present in the external operator's database.
    const signer = auth.verifiedHeadManifest.devices.find((device) =>
      device.device_id === remote.header.signer_device_id
      && device.revoked_at_epoch === null
      && Number(device.enrolled_epoch) <= remote.header.epoch);
    if (!signer) fail("ZK_CATALOG_DENIED");
    const signerKey = crypto.createPublicKey({ key: Buffer.concat([
      ED_SPKI, buf(signer.authorization_public_key, 32)]), format: "der", type: "spki" });
    if (!crypto.verify(null, Buffer.concat([HEAD_DOMAIN, remote.headerBytes]),
      signerKey, remote.headSignature)) fail("ZK_CATALOG_DENIED");
    this.assertMetadataContinuity(previousPages, remote.pages);
    this.verifyPhysicalVersions(key, remote.pages);
    // Confirm the independently signed head is still the intended CAS head.
    const confirmed = await this.fresh(auth);
    if (confirmed.sequence !== current.sequence || !same(confirmed.digest, current.digest)) {
      fail("ZK_CATALOG_UNAVAILABLE");
    }
    await this.verifyStoredChain(key, predecessor, auth.verifiedHeadManifest);
    this.store.db.transaction(() => {
      const latest = this.head.get(key);
      if ((!latest && predecessor.sequence !== 0)
        || (latest && (latest.sequence !== predecessor.sequence
          || !same(latest.digest, predecessor.digest)))
        || this.snapshot.get(key, current.sequence)
        || this.store.db.prepare("SELECT 1 FROM zk_content_catalog_page WHERE scope=? AND sequence=?")
          .get(key, current.sequence)) fail("ZK_CATALOG_UNAVAILABLE");
      // Physical rows may have changed during the remote network call.
      this.verifyPhysicalVersions(key, remote.pages);
      this.store.db.prepare("INSERT INTO zk_content_catalog_snapshot(scope,sequence,digest,header,signature) VALUES(?,?,?,?,?)")
        .run(key, current.sequence, current.digest, remote.headerBytes, remote.headSignature);
      for (let i = 0; i < remote.bodies.length; i++) {
        this.store.db.prepare("INSERT INTO zk_content_catalog_page(scope,sequence,page,body) VALUES(?,?,?,?)")
          .run(key, current.sequence, i, remote.bodies[i]);
      }
      this.store.db.prepare("INSERT INTO zk_content_catalog_head(scope,sequence,digest) VALUES(?,?,?) ON CONFLICT(scope) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest")
        .run(key, current.sequence, current.digest);
    }).immediate();
    return this.verifyStoredChain(key, current, auth.verifiedHeadManifest);
  }
  async commit({ scope, authorization, signature, header, headerSignature, pages,
    ownerEvidence, guard = null, emit = (result) => result }) {
    if (guard !== null && typeof guard !== "function") fail();
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
        this.rejectRollback(key, current);
        if (current.sequence >= MAX_HEADS
          || header.sequence !== current.sequence + 1
          || !same(buf(header.previous_digest, 32), current.digest)) fail("ZK_CATALOG_CONFLICT");
        const previousPages = await this.reconcileMissing(key, current, auth);
        // Owner-authorized signer cannot attest a conveniently omitted list:
        // compare every immutable locally archived ciphertext VERSION exactly.
        const rows = this.store.db.prepare("SELECT id,revision,epoch,ciphertext,ciphertext_digest FROM zk_content_version WHERE scope=? ORDER BY id COLLATE BINARY,revision").all(key);
        if (rows.length > MAX_ENTRIES) fail("ZK_CATALOG_CONFLICT");
        auditZk1CatalogReendorsement({ previousPages, proposedPages: normalized,
          physicalVersions: rows });
        // Async manifest/CAS checks above may outlive the initiating web
        // session. Recheck immediately before durable local/external effects.
        if (guard) guard();
        this.consume(auth);
        // Authority must atomically CAS independently of local SQLite. A
        // lost ACK may leave the catalog unavailable until audited recovery.
        const receipt = await this.authority.compareAndSwap({
          scope: wanted, expectedSequence: current.sequence,
          expectedDigest: current.digest, nextSequence: header.sequence,
          nextDigest: digest, nonce: request.nonce,
          // An independently operated signer must verify and durably retain
          // these signed opaque bytes BEFORE attesting their head digest.
          // A digest supplied alone is not evidence of committed data.
          headBytes: headerBytes, headSignature: signed,
          pageBodies: bodies.map((body) => Buffer.from(body)),
          ownerEvidence,
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
      }, guard);
  }
  async read({ scope, authorization, signature, pageIndex, emit = (result) => result }) {
    return this.store.runCatalogWithAdmission({ scope, authorization, signature },
      "catalog-read", async (auth) => {
        const page = number(pageIndex, 0, MAX_ENTRIES / PAGE_SIZE);
        if (auth.request.object_id !== objectId(this.store.trustedScope, "catalog-read", page)) fail();
        const current = await this.fresh(auth);
        const key = scopeKey(this.store.trustedScope);
        this.rejectRollback(key, current);
        if (current.sequence < 1) fail("ZK_CATALOG_NOT_FOUND");
        if (auth.request.expected_object_revision !== current.sequence
          || !same(auth.request.ciphertext_digest, current.digest)) fail("ZK_CATALOG_CONFLICT");
        const historicalPages = await this.reconcileMissing(key, current, auth);
        const record = this.snapshot.get(key, current.sequence);
        if (!record || !same(record.digest, current.digest)
          || !same(headDigest(record.header, record.signature), current.digest)) {
          fail("ZK_CATALOG_UNAVAILABLE");
        }
        const header = await z.decodeDeterministic(record.header);
        validateHeader(header, this.store.trustedScope);
        const totalVersions = this.store.db.prepare(
          "SELECT COUNT(*) AS n FROM zk_content_version WHERE scope=?").get(key).n;
        // The head attests its own snapshot. A physical PUT after that head
        // can remain pending until the next signed catalog commit.
        if (totalVersions < header.total_count) fail("ZK_CATALOG_UNAVAILABLE");
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
        // A signed catalog does not prove the physical historical ciphertext
        // survived a trash/restore. Verify every archived version before
        // releasing metadata, including ciphertext hidden on other pages.
        this.verifyPhysicalVersions(key, historicalPages);
        const payload = this.page.get(key, current.sequence, page);
        const entries = payload ? await z.decodeDeterministic(payload.body) : [];
        if ((header.total_count === 0 && page !== 0)
          || (header.total_count !== 0 && !payload)
          || (payload && !same(await digestPage(entries), Buffer.from(header.page_digests[page])))) {
          fail("ZK_CATALOG_UNAVAILABLE");
        }
        // Page decoding and hashing above await async work. A physical writer
        // could alter a historical version after the earlier inventory check.
        // Revalidate the entire inventory and burn the signed nonce in one
        // synchronous SQLite transaction immediately before response egress.
        this.store.db.transaction(() => {
          this.verifyPhysicalVersions(key, historicalPages);
          this.consume(auth);
        }).immediate();
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
