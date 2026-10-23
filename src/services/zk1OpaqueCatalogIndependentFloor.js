"use strict";

// Operate this authority on a different administrative host with its own
// SQLite, TLS credentials and Ed25519 key. The catalog CAS process receives
// only this service's pinned public key, never its private signing key.
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const tls = require("node:tls");
const net = require("node:net");
const path = require("node:path");
const Database = require("better-sqlite3");
const { requireImmutableTriggers } = require("./zk1OpaqueCatalogSqliteIntegrity");
const z = require("../crypto/rootark-zk-1");
const { catalogHeadDigest } = require("./zk1OpaqueCatalog");
const ownerHistory = require("../crypto/rootark-zk-recovery-history-v2");
const ownerManifest = require("../crypto/rootark-zk-recovery-manifest-v2");
const { inspectVerifiedWitnessFreshHeadV1 } =
  require("../crypto/rootark-zk-witness-head-wire-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-independent-floor/v1\0");
const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const FIELDS = ["type", "account_id", "compartment_id", "keyring_id",
  "cas_signer_spki_sha256", "sequence", "digest", "nonce", "observed_at"];
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const TYPE = "rootark-zk1-opaque-catalog-independent-floor/v1";
const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const OWNER_FIELDS = ["genesisDigest", "pinnedWitness", "minimumHead", "freshWitnessHead"];
const OWNER_EVIDENCE = ["baseManifest", "baseReceipt", "transitions",
  "packageEnvelopes", "witnessHeadRaw"];
const PIN = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i;
const clients = new WeakSet();
function fail(code = "ZK_OPAQUE_FLOOR_UNAVAILABLE") {
  const error = new Error(code); error.code = code; throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
}
function bytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}
function whole(v, min, max) {
  if (!Number.isSafeInteger(v) || v < min || v > max) fail();
  return v;
}
function same(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function scopeBytes(raw) {
  exact(raw, SCOPE);
  return Object.fromEntries(SCOPE.map((k) => [k,
    bytes(raw[k], k === "compartment_id" ? 1 : 16,
      k === "compartment_id" ? 128 : 16)]));
}
function scopeWire(raw) {
  const scope = scopeBytes(raw);
  return Object.fromEntries(SCOPE.map((k) => [k, scope[k].toString("base64url")]));
}
function decode(v, min, max = min) {
  if (typeof v !== "string" || !/^[A-Za-z0-9_-]+$/.test(v)) fail();
  const b = Buffer.from(v, "base64url");
  if (b.length < min || b.length > max || b.toString("base64url") !== v) fail();
  return b;
}
function fromWire(s) {
  exact(s, SCOPE);
  return { account_id: decode(s.account_id, 16),
    compartment_id: decode(s.compartment_id, 1, 128),
    keyring_id: decode(s.keyring_id, 16) };
}
function scopeId(s) { return SCOPE.map((k) => s[k].toString("hex")).join(":"); }
function fingerprint(key) {
  return crypto.createHash("sha256")
    .update(key.export({ format: "der", type: "spki" })).digest();
}
function keyIs(key, type) {
  return key instanceof crypto.KeyObject && key.type === type
    && key.asymmetricKeyType === "ed25519";
}
function requirePrivateFile(filename, exists) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) fail();
  const dir = fs.lstatSync(path.dirname(filename));
  if (!dir.isDirectory() || dir.isSymbolicLink()) fail();
  if (process.platform !== "win32" && (dir.uid !== process.getuid() || (dir.mode & 0o077))) fail();
  if (fs.existsSync(filename) !== exists) fail();
  if (exists) {
    const st = fs.lstatSync(filename);
    if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1
      || (process.platform !== "win32"
        && (st.uid !== process.getuid() || (st.mode & 0o077)))) fail();
  }
}
function requireExistingFloorSchema(db, identity, hasOwner) {
  // Validate in read-only mode before WAL pragmas or CREATE TABLE can modify
  // an unrelated, rolled-back, or partially restored SQLite file.
  if (db.pragma("quick_check", { simple: true }) !== "ok") fail();
  const objects = new Set(db.prepare("SELECT type, name FROM sqlite_master").all()
    .map((entry) => `${entry.type}:${entry.name}`));
  for (const name of ["identity", "floor", "transitions", "owner_identity",
    "owner_authority"]) if (!objects.has(`table:${name}`)) fail();
  for (const name of ["immutable_floor_transition_update",
    "immutable_floor_transition_delete"]) if (!objects.has(`trigger:${name}`)) fail();
  const saved = db.prepare("SELECT * FROM identity WHERE id=1").get();
  if (!saved || saved.scope !== identity[0] || !same(saved.floor_fp, identity[1])
    || !same(saved.cas_fp, identity[2]) || !same(saved.catalog_fp, identity[3])) fail();
  const owner = db.prepare("SELECT * FROM owner_identity WHERE id=1").get();
  if (Boolean(owner) !== hasOwner) fail();
}
async function signed(state, nonce, signingKey, scope, fp) {
  const body = { type: TYPE, ...scope, cas_signer_spki_sha256: fp,
    sequence: state.sequence, digest: Buffer.from(state.digest),
    nonce: bytes(nonce, 32), observed_at: Math.floor(Date.now() / 1000) };
  const encoded = Buffer.from(await z.encodeDeterministic(body));
  const signature = crypto.sign(null, Buffer.concat([DOMAIN, encoded]), signingKey);
  return Buffer.from(await z.encodeDeterministic({ ...body, signature }));
}
async function verify(raw, nonce, scope, fp, key) {
  const v = await z.decodeDeterministic(bytes(raw, 1, 4096));
  exact(v, [...FIELDS, "signature"]);
  const { signature, ...body } = v;
  if (body.type !== TYPE || !SCOPE.every((k) =>
    same(bytes(body[k], k === "compartment_id" ? 1 : 16,
      k === "compartment_id" ? 128 : 16), scope[k]))
    || !same(bytes(body.cas_signer_spki_sha256, 32), fp)
    || !same(bytes(body.nonce, 32), nonce)
    || !Number.isSafeInteger(body.observed_at)
    || Math.abs(body.observed_at - Math.floor(Date.now() / 1000)) > 30
    || !crypto.verify(null, Buffer.concat([DOMAIN,
      Buffer.from(await z.encodeDeterministic(body))]), key, bytes(signature, 64))) fail();
  const sequence = whole(body.sequence, 0, 128);
  const digest = bytes(body.digest, 32);
  if (sequence === 0 && !same(digest, Buffer.alloc(32))) fail();
  return Object.freeze({ sequence, digest, proof: Buffer.from(raw) });
}

class Zk1OpaqueCatalogIndependentFloorLedger {
  constructor(filename, { bootstrapNew, trustedScope, signingPrivateKey,
    casSignerPublicKey, catalogSignerPublicKey, ownerTrust }) {
    if (!keyIs(signingPrivateKey, "private") || !keyIs(casSignerPublicKey, "public")
      || !keyIs(catalogSignerPublicKey, "public")) fail();
    this.scope = scopeBytes(trustedScope);
    this.id = scopeId(this.scope);
    this.signer = signingPrivateKey;
    this.casPublicKey = casSignerPublicKey;
    this.catalogPublicKey = catalogSignerPublicKey;
    if (ownerTrust !== undefined) {
      exact(ownerTrust, OWNER_FIELDS);
      exact(ownerTrust.pinnedWitness, ["keyId", "publicKey"]);
      exact(ownerTrust.minimumHead, ["revision", "witnessSequence", "digest"]);
      if (!keyIs(ownerTrust.pinnedWitness.publicKey, "public")
        || typeof ownerTrust.freshWitnessHead !== "function"
        || ownerTrust.minimumHead.witnessSequence !== ownerTrust.minimumHead.revision) fail();
      this.ownerTrust = {
        genesisDigest: bytes(ownerTrust.genesisDigest, 32),
        pinnedWitness: { keyId: bytes(ownerTrust.pinnedWitness.keyId, 16),
          publicKey: ownerTrust.pinnedWitness.publicKey },
        minimumHead: { revision: whole(ownerTrust.minimumHead.revision, 1, Number.MAX_SAFE_INTEGER),
          witnessSequence: ownerTrust.minimumHead.revision,
          digest: bytes(ownerTrust.minimumHead.digest, 32) },
        freshWitnessHead: ownerTrust.freshWitnessHead,
      };
    }
    this.casFingerprint = fingerprint(casSignerPublicKey);
    const own = fingerprint(crypto.createPublicKey(signingPrivateKey));
    const expected = [this.id, own, this.casFingerprint,
      fingerprint(this.catalogPublicKey)];
    if (same(own, this.casFingerprint) || same(own, fingerprint(catalogSignerPublicKey))
      || (this.ownerTrust && [own, this.casFingerprint, fingerprint(catalogSignerPublicKey)]
        .some((fp) => same(fp, fingerprint(this.ownerTrust.pinnedWitness.publicKey))))) fail();
    const exists = fs.existsSync(filename);
    if (bootstrapNew !== !exists) fail();
    requirePrivateFile(filename, exists);
    if (exists) {
      let probe;
      try {
        probe = new Database(filename, { readonly: true, fileMustExist: true });
        requireExistingFloorSchema(probe, expected, Boolean(this.ownerTrust));
      } catch (_) { fail(); }
      finally { probe?.close(); }
    }
    if (!exists) {
      let fd;
      try { fd = fs.openSync(filename, fs.constants.O_CREAT | fs.constants.O_EXCL
        | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600); }
      catch (_) { fail(); }
      finally { if (fd !== undefined) fs.closeSync(fd); }
    }
    this.db = new Database(filename, { fileMustExist: true, timeout: 3000 });
    try {
      if (exists) {
        requireExistingFloorSchema(this.db, expected, Boolean(this.ownerTrust));
        this.inspect();
      }
      this.db.pragma("journal_mode=WAL");
      this.db.pragma("synchronous=FULL");
      if (!exists) this.db.exec(`CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1),
        scope TEXT NOT NULL, floor_fp BLOB NOT NULL, cas_fp BLOB NOT NULL,
        catalog_fp BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS floor (scope TEXT PRIMARY KEY,
          sequence INTEGER NOT NULL, digest BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS transitions (scope TEXT NOT NULL,
          sequence INTEGER NOT NULL, digest BLOB NOT NULL, previous_digest BLOB NOT NULL,
          owner_revision INTEGER, owner_digest BLOB, signer_spki BLOB,
          PRIMARY KEY(scope,sequence));
        CREATE TABLE IF NOT EXISTS owner_identity (
          id INTEGER PRIMARY KEY CHECK(id=1), genesis_digest BLOB NOT NULL,
          witness_fp BLOB NOT NULL, witness_key_id BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS owner_authority (
          scope TEXT PRIMARY KEY, revision INTEGER NOT NULL, digest BLOB NOT NULL);
        CREATE TRIGGER IF NOT EXISTS immutable_floor_transition_update BEFORE UPDATE
          ON transitions BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS immutable_floor_transition_delete BEFORE DELETE
          ON transitions BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
      requireImmutableTriggers(this.db, [
        ["immutable_floor_transition_update", "transitions", "UPDATE"],
        ["immutable_floor_transition_delete", "transitions", "DELETE"],
      ], fail);
      if (!exists) this.db.prepare("INSERT INTO identity VALUES(1,?,?,?,?)").run(...expected);
      const saved = this.db.prepare("SELECT * FROM identity WHERE id=1").get();
      if (!saved || saved.scope !== this.id || !same(saved.floor_fp, expected[1])
        || !same(saved.cas_fp, expected[2]) || !same(saved.catalog_fp, expected[3])) fail();
      if (!exists && this.ownerTrust) {
        this.db.prepare("INSERT INTO owner_identity VALUES (1,?,?,?)").run(
          this.ownerTrust.genesisDigest, fingerprint(this.ownerTrust.pinnedWitness.publicKey),
          this.ownerTrust.pinnedWitness.keyId);
        this.db.prepare("INSERT INTO owner_authority VALUES (?,?,?)").run(this.id,
          this.ownerTrust.minimumHead.revision, this.ownerTrust.minimumHead.digest);
      }
      const owner = this.db.prepare("SELECT * FROM owner_identity WHERE id=1").get();
      if (Boolean(owner) !== Boolean(this.ownerTrust)) fail();
      if (owner && (!same(owner.genesis_digest, this.ownerTrust.genesisDigest)
        || !same(owner.witness_fp, fingerprint(this.ownerTrust.pinnedWitness.publicKey))
        || !same(owner.witness_key_id, this.ownerTrust.pinnedWitness.keyId))) fail();
      this.inspect();
    } catch (error) { this.db.close(); throw error; }
  }
  inspect() {
    const rows = this.db.prepare("SELECT * FROM transitions WHERE scope=? ORDER BY sequence").all(this.id);
    let digest = Buffer.alloc(32);
    if (rows.length > 128) fail();
    for (let i = 0; i < rows.length; ++i) {
      if (rows[i].sequence !== i + 1 || !same(rows[i].previous_digest, digest)
        || rows[i].digest.length !== 32 || same(rows[i].digest, digest)) fail();
      digest = rows[i].digest;
    }
    const owner = this.db.prepare("SELECT revision,digest FROM owner_authority WHERE scope=?")
      .get(this.id);
    if (Boolean(owner) !== Boolean(this.ownerTrust)) fail();
    if (owner && (owner.revision < this.ownerTrust.minimumHead.revision
      || (owner.revision === this.ownerTrust.minimumHead.revision
        && !same(owner.digest, this.ownerTrust.minimumHead.digest)))) fail();
    let previousRevision = this.ownerTrust?.minimumHead.revision || 0;
    let previousOwnerDigest = this.ownerTrust?.minimumHead.digest;
    for (const row of rows) {
      if (this.ownerTrust) {
        if (!Number.isSafeInteger(row.owner_revision) || row.owner_revision < previousRevision
          || row.owner_digest?.length !== 32 || row.signer_spki?.length !== 44
          || (row.owner_revision === previousRevision
            && !same(row.owner_digest, previousOwnerDigest))) fail();
        previousRevision = row.owner_revision;
        previousOwnerDigest = row.owner_digest;
      } else if (row.owner_revision !== null || row.owner_digest !== null
        || row.signer_spki !== null) fail();
    }
    if (owner && (owner.revision !== previousRevision
      || !same(owner.digest, previousOwnerDigest))) fail();
    const head = this.db.prepare("SELECT sequence,digest FROM floor WHERE scope=?").get(this.id);
    if ((head && (head.sequence !== rows.length || !same(head.digest, digest)))
      || (!head && rows.length)) fail();
    return { sequence: rows.length, digest: Buffer.from(digest) };
  }
  async readHead({ scope, nonce }) {
    if (scopeId(scopeBytes(scope)) !== this.id) fail();
    return signed(this.inspect(), nonce, this.signer, this.scope, this.casFingerprint);
  }
  async compareAndSwap({ scope, expectedSequence, expectedDigest,
    nextSequence, nextDigest, headBytes, headSignature, nonce,
    ownerEvidence, ownerNonce }) {
    if (scopeId(scopeBytes(scope)) !== this.id) fail();
    const old = whole(expectedSequence, 0, 127);
    const next = whole(nextSequence, 1, 128);
    const previous = bytes(expectedDigest, 32);
    const wanted = bytes(nextDigest, 32);
    const raw = bytes(headBytes, 1, 16384);
    const signature = bytes(headSignature, 64);
    const challenge = bytes(nonce, 32);
    if (next !== old + 1 || same(previous, wanted)
      || !same(catalogHeadDigest(raw, signature), wanted)) fail("ZK_OPAQUE_FLOOR_CONFLICT");
    const header = await z.decodeDeterministic(raw);
    const required = ["type", ...SCOPE, "sequence", "previous_digest",
      "manifest_revision", "manifest_digest", "epoch", "signer_device_id",
      "total_count", "page_digests", "issued_at"];
    exact(header, required);
    if (header.type !== "rootark-zk1-opaque-catalog/v1" || header.sequence !== next
      || scopeId(scopeBytes(Object.fromEntries(SCOPE.map((k) => [k, header[k]])))) !== this.id
      || !same(bytes(header.previous_digest, 32), previous)) fail("ZK_OPAQUE_FLOOR_CONFLICT");
    let authorizedSigner = this.catalogPublicKey;
    let authorizedOwner = null;
    if (this.ownerTrust) {
      const evidence = await z.decodeDeterministic(bytes(ownerEvidence, 1, 2 * 1024 * 1024));
      exact(evidence, OWNER_EVIDENCE);
      if (!Array.isArray(evidence.transitions) || !Array.isArray(evidence.packageEnvelopes)) fail();
      const trust = this.ownerTrust;
      const proof = await ownerHistory.verifyRecoveryHistoryPublicV2({
        expectedScope: this.scope, baseManifest: evidence.baseManifest,
        baseReceipt: evidence.baseReceipt, transitions: evidence.transitions,
        packageEnvelopes: evidence.packageEnvelopes, pinnedWitness: trust.pinnedWitness,
        now: Math.floor(Date.now() / 1000),
      });
      if (!await ownerHistory.isVerifiedPublicRecoveryHistoryV2(proof)
        || !same(await ownerManifest.recoveryManifestDigestV2(proof.baseManifest),
          trust.genesisDigest)) fail();
      const originalNonce = bytes(ownerNonce, 32);
      const savedOwner = this.db.prepare("SELECT revision,digest FROM owner_authority WHERE scope=?")
        .get(this.id);
      const floor = { revision: savedOwner.revision, witnessSequence: savedOwner.revision,
        digest: Buffer.from(savedOwner.digest) };
      await inspectVerifiedWitnessFreshHeadV1({
        raw: bytes(evidence.witnessHeadRaw, 1, 8192), nonce: originalNonce,
        scope: this.scope, pinned: trust.pinnedWitness, minimumHead: floor,
      });
      const latestNonce = crypto.randomBytes(32);
      const remote = bytes(await trust.freshWitnessHead({ scope: this.scope,
        nonce: latestNonce }), 1, 8192);
      await inspectVerifiedWitnessFreshHeadV1({ raw: remote, nonce: latestNonce,
        scope: this.scope, pinned: trust.pinnedWitness, minimumHead: floor });
      const now = Math.floor(Date.now() / 1000);
      const latest = await z.decodeDeterministic(remote);
      if (Math.abs(latest.observed_at - now) > 30
        || Number(latest.current_revision) !== Number(proof.revision)
        || !same(bytes(latest.current_manifest_digest, 32), proof.headDigest)
        || header.manifest_revision !== Number(proof.revision)
        || !same(bytes(header.manifest_digest, 32), proof.headDigest)
        || header.epoch !== Number(proof.headManifest.current_epoch)) fail();
      const device = proof.headManifest.devices.find((d) =>
        d.device_id === header.signer_device_id && d.revoked_at_epoch === null
        && Number(d.enrolled_epoch) <= Number(header.epoch));
      if (!device) fail();
      authorizedSigner = crypto.createPublicKey({ key: Buffer.concat([
        ED_SPKI, bytes(device.authorization_public_key, 32)]),
      format: "der", type: "spki" });
      if (old === 0 && !same(fingerprint(authorizedSigner),
        fingerprint(this.catalogPublicKey))) fail();
      authorizedOwner = { revision: Number(proof.revision), digest: Buffer.from(proof.headDigest) };
      if (authorizedOwner.revision < savedOwner.revision
        || (authorizedOwner.revision === savedOwner.revision
          && !same(authorizedOwner.digest, savedOwner.digest))) fail();
      if (old > 0) {
        const prior = this.db.prepare("SELECT signer_spki,owner_revision FROM transitions WHERE scope=? AND sequence=?")
          .get(this.id, old);
        if (!prior || (!same(prior.signer_spki,
          authorizedSigner.export({ type: "spki", format: "der" }))
          && authorizedOwner.revision <= prior.owner_revision)) fail();
      }
    } else if (ownerEvidence !== undefined || ownerNonce !== undefined) fail();
    if (!crypto.verify(null, Buffer.concat([HEAD_DOMAIN, raw]),
      authorizedSigner, signature)) fail("ZK_OPAQUE_FLOOR_CONFLICT");
    const transaction = this.db.transaction(() => {
      const current = this.inspect();
      if (current.sequence !== old || !same(current.digest, previous)) fail("ZK_OPAQUE_FLOOR_CONFLICT");
      this.db.prepare("INSERT INTO transitions VALUES (?,?,?,?,?,?,?)")
        .run(this.id, next, wanted, previous, authorizedOwner?.revision ?? null,
          authorizedOwner?.digest ?? null, authorizedOwner
            ? authorizedSigner.export({ type: "spki", format: "der" }) : null);
      if (authorizedOwner) this.db.prepare("UPDATE owner_authority SET revision=?,digest=? WHERE scope=?")
        .run(authorizedOwner.revision, authorizedOwner.digest, this.id);
      this.db.prepare(`INSERT INTO floor(scope,sequence,digest) VALUES (?,?,?)
        ON CONFLICT(scope) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest`)
        .run(this.id, next, wanted);
    });
    transaction.immediate();
    return signed(this.inspect(), challenge, this.signer, this.scope, this.casFingerprint);
  }
  close() { if (this.db.open) this.db.close(); }
}

function createZk1OpaqueCatalogIndependentFloorHttpsServer({ ledger, key, cert,
  clientCa, authorizedClientFingerprint256, testOnlyDropAckOnce = false }) {
  if (!(ledger instanceof Zk1OpaqueCatalogIndependentFloorLedger)
    || !key || !cert || !clientCa || !PIN.test(authorizedClientFingerprint256)
    || (testOnlyDropAckOnce && process.env.NODE_ENV !== "test")) fail();
  let dropAck = testOnlyDropAckOnce;
  const pin = authorizedClientFingerprint256.toUpperCase();
  const server = https.createServer({ key, cert, ca: clientCa, requestCert: true,
    rejectUnauthorized: true, minVersion: "TLSv1.3" }, async (req, res) => {
    let status = 200; let result;
    try {
      if (!req.socket.authorized || req.socket.getPeerCertificate()?.fingerprint256?.toUpperCase() !== pin) fail();
      if (req.method !== "POST" || !["/v1/floor/head", "/v1/floor/cas"].includes(req.url)) fail();
      if (req.headers["content-type"] !== "application/json") fail();
      const chunks = []; let count = 0;
      for await (const chunk of req) {
        count += chunk.length;
        if (count > 3 * 1024 * 1024) fail();
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (req.url === "/v1/floor/head") {
        exact(body, ["scope", "nonce"]);
        result = await ledger.readHead({ scope: fromWire(body.scope), nonce: decode(body.nonce, 32) });
      } else {
        exact(body, ledger.ownerTrust
          ? ["scope", "expectedSequence", "expectedDigest", "nextSequence",
            "nextDigest", "nonce", "headBytes", "headSignature", "ownerEvidence", "ownerNonce"]
          : ["scope", "expectedSequence", "expectedDigest", "nextSequence",
            "nextDigest", "nonce", "headBytes", "headSignature"]);
        result = await ledger.compareAndSwap({ scope: fromWire(body.scope),
          expectedSequence: body.expectedSequence, expectedDigest: decode(body.expectedDigest, 32),
          nextSequence: body.nextSequence, nextDigest: decode(body.nextDigest, 32),
          nonce: decode(body.nonce, 32), headBytes: decode(body.headBytes, 1, 16384),
          headSignature: decode(body.headSignature, 64),
          ownerEvidence: body.ownerEvidence === undefined ? undefined
            : decode(body.ownerEvidence, 1, 2 * 1024 * 1024),
          ownerNonce: body.ownerNonce === undefined ? undefined : decode(body.ownerNonce, 32) });
        if (dropAck) { dropAck = false; req.socket.destroy(); return; }
      }
    } catch (error) { status = error?.code === "ZK_OPAQUE_FLOOR_CONFLICT" ? 409 : 503; }
    if (req.socket.destroyed) return;
    const raw = Buffer.from(JSON.stringify(status === 200
      ? { proofBase64: result.toString("base64url") } : { error: "FLOOR_UNAVAILABLE" }));
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store",
      "content-length": raw.length });
    res.end(raw);
  });
  server.requestTimeout = 5000; server.headersTimeout = 5000;
  server.timeout = 5000; server.keepAliveTimeout = 1000;
  return server;
}

function createZk1OpaqueCatalogIndependentFloorHttpsClient({ endpoint, ca,
  clientKey, clientCert, serverFingerprint256, floorPublicKey,
  casSignerPublicKey, trustedScope, timeoutMs = 3000 }) {
  let url;
  try { url = new URL(endpoint); } catch (_) { fail(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port || url.pathname !== "/"
    || url.username || url.password || url.search || url.hash
    || !PIN.test(serverFingerprint256) || !ca || !clientKey || !clientCert
    || !keyIs(floorPublicKey, "public") || !keyIs(casSignerPublicKey, "public")
    || same(fingerprint(floorPublicKey), fingerprint(casSignerPublicKey))
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) fail();
  const scope = scopeBytes(trustedScope);
  const fp = fingerprint(casSignerPublicKey);
  const pin = serverFingerprint256.toUpperCase();
  async function request(route, body, nonce) {
    const payload = Buffer.from(JSON.stringify(body));
    if (payload.length > 3 * 1024 * 1024) fail();
    const raw = await new Promise((resolve, reject) => {
      const req = https.request({ hostname: url.hostname, port: url.port,
        path: route, method: "POST", agent: false, ca, key: clientKey,
        cert: clientCert, rejectUnauthorized: true, minVersion: "TLSv1.3",
        servername: net.isIP(url.hostname) ? "" : url.hostname,
        checkServerIdentity(host, cert) {
          const invalid = tls.checkServerIdentity(host, cert);
          return invalid || (cert.fingerprint256?.toUpperCase() === pin ? undefined
            : new Error("FLOOR_PEER_PIN_MISMATCH"));
        }, headers: { "content-type": "application/json", "content-length": payload.length },
      }, (response) => {
        if (response.statusCode !== 200 || response.headers["content-type"] !== "application/json") {
          response.resume(); reject(new Error("FLOOR_HTTP_REJECTED")); return;
        }
        const chunks = []; let count = 0;
        response.on("data", (chunk) => {
          count += chunk.length;
          if (count > 8192) { req.destroy(); reject(new Error("FLOOR_BODY_TOO_LONG")); }
          else chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("end", () => {
          try { const data = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            exact(data, ["proofBase64"]); resolve(decode(data.proofBase64, 1, 4096)); }
          catch (error) { reject(error); }
        });
      });
      req.setTimeout(timeoutMs, () => req.destroy(new Error("FLOOR_TIMEOUT")));
      req.on("error", reject);
      req.end(payload);
    }).catch(() => fail());
    return verify(raw, nonce, scope, fp, floorPublicKey).catch(() => fail());
  }
  function checkScope(input) {
    if (scopeId(scopeBytes(input)) !== scopeId(scope)) fail();
  }
  const client = Object.freeze({
    publicKey: floorPublicKey,
    async readHead({ scope: target }) {
      checkScope(target);
      const nonce = crypto.randomBytes(32);
      return request("/v1/floor/head", { scope: scopeWire(scope),
        nonce: nonce.toString("base64url") }, nonce);
    },
    async compareAndSwap({ scope: target, expectedSequence, expectedDigest,
      nextSequence, nextDigest, headBytes, headSignature, ownerEvidence, ownerNonce }) {
      checkScope(target);
      const nonce = crypto.randomBytes(32);
      const body = { scope: scopeWire(scope), expectedSequence,
        expectedDigest: bytes(expectedDigest, 32).toString("base64url"),
        nextSequence, nextDigest: bytes(nextDigest, 32).toString("base64url"),
        headBytes: bytes(headBytes, 1, 16384).toString("base64url"),
        headSignature: bytes(headSignature, 64).toString("base64url"),
        nonce: nonce.toString("base64url") };
      if (ownerEvidence !== undefined || ownerNonce !== undefined) {
        body.ownerEvidence = bytes(ownerEvidence, 1, 2 * 1024 * 1024).toString("base64url");
        body.ownerNonce = bytes(ownerNonce, 32).toString("base64url");
      }
      return request("/v1/floor/cas", body, nonce);
    },
  });
  clients.add(client);
  return client;
}
function isZk1OpaqueCatalogIndependentFloorClient(client) { return clients.has(client); }
module.exports = { Zk1OpaqueCatalogIndependentFloorLedger,
  createZk1OpaqueCatalogIndependentFloorHttpsServer,
  createZk1OpaqueCatalogIndependentFloorHttpsClient,
  isZk1OpaqueCatalogIndependentFloorClient };
