"use strict";

// Separate-process-ready Sync v2 retained high-water PROTOTYPE.
// This is NOT a physical witness, independently operated off-host custody,
// or approval to issue protected ACKs. Do not mount it in the normal server.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { ANCHOR_DOMAIN, GENESIS } = require("./zk1SyncAtomicCasFloorLedgerDevOff");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteAuthorityDirectory } = require("./zk1PrivateSqlitePath");

const CHAIN_DOMAIN = "rootark-sync-atomic-retained-anchor-chain-dev-off-v1\0";
const SEAL_DOMAIN = "rootark-sync-atomic-retained-anchor-seal-dev-off-v1\0";
const BINDING_DOMAIN = "rootark-sync-atomic-retained-binding-dev-off-v2\0";
const CHAIN_GENESIS = crypto.createHash("sha256")
  .update("rootark-sync-atomic-retained-anchor-genesis-dev-off-v1\0").digest("hex");
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const HEX = /^[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function deny() {
  return Object.assign(new Error("SYNC_ATOMIC_RETAINED_ANCHOR_DEV_OFF_DENIED"),
    { code: "SYNC_ATOMIC_RETAINED_ANCHOR_DEV_OFF_DENIED" });
}
function requireValid(value) { if (!value) throw deny(); }
function exact(value, names) {
  requireValid(value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === names.length
    && names.every((name) => Object.hasOwn(value, name)));
}
function snapshot(value) {
  try {
    const canonical = protocol.canonicalJson(value);
    requireValid(typeof canonical === "string" && canonical.length < 8192);
    return JSON.parse(canonical);
  }
  catch { throw deny(); }
}
function binding(value) {
  const copy = snapshot(value);
  exact(copy, ["scope", "accountId", "storeId"]);
  requireValid(typeof copy.scope === "string" && SCOPE.test(copy.scope)
    && typeof copy.accountId === "string" && UUID.test(copy.accountId)
    && typeof copy.storeId === "string" && UUID.test(copy.storeId));
  return Object.freeze(copy);
}
function floor(value) {
  const copy = snapshot(value);
  exact(copy, ["scope", "sequence", "headHash"]);
  requireValid(typeof copy.scope === "string" && SCOPE.test(copy.scope)
    && Number.isSafeInteger(copy.sequence) && copy.sequence >= 0
    && typeof copy.headHash === "string" && HEX.test(copy.headHash)
    && (copy.sequence !== 0 || copy.headHash === GENESIS));
  return Object.freeze(copy);
}
function fingerprint(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("hex");
}
function chainStatement(scope, bindingValue, sequence, previousHash, previousChain, headHash) {
  return { scope, accountId: bindingValue.accountId,
    storeId: bindingValue.storeId, sequence, previousHash, previousChain, headHash };
}
function chainHash(statement) {
  return crypto.createHash("sha256").update(CHAIN_DOMAIN
    + protocol.canonicalJson(statement)).digest("hex");
}
function assertStorage(db, bindings, minimumFingerprint = null) {
  // A trigger, view or an unexpected table is outside this fixed authority.
  const objects = db.prepare(`SELECT name,type FROM sqlite_schema
    WHERE name NOT LIKE 'sqlite_%' ORDER BY name`).all();
  requireValid(objects.length === (minimumFingerprint ? 5 : 4)
    && objects.every((object) => object.type === "table")
    && objects.map((object) => object.name).join(",") === [
      "atomic_anchor_binding", "atomic_anchor_head", "atomic_anchor_history",
      "atomic_anchor_identity", ...(minimumFingerprint ? ["atomic_anchor_minimum_fence"] : [])
    ].join(","));
  for (const [table, columns] of [
    ["atomic_anchor_identity", ["id", "signer_fingerprint"]],
    ["atomic_anchor_binding", ["scope", "account_id", "store_id"]],
    ["atomic_anchor_head", ["scope", "sequence", "head_hash", "chain_hash"]],
    ["atomic_anchor_history", ["scope", "sequence", "previous_hash",
      "previous_chain", "head_hash", "chain_hash", "seal"]],
    ...(minimumFingerprint ? [["atomic_anchor_minimum_fence",
      ["id", "minimum_fingerprint"]]] : []),
  ]) {
    const actual = db.pragma(`table_info("${table}")`);
    requireValid(actual.length === columns.length && actual.every((col, i) =>
      col.name === columns[i] && col.pk === (table === "atomic_anchor_history"
        ? (i === 0 ? 1 : i === 1 ? 2 : 0) : (i === 0 ? 1 : 0))
      && (col.notnull === 1 || (col.pk > 0 && col.type === "INTEGER"))));
  }
  // For TEXT PRIMARY KEY, notnull may be reported as zero by SQLite rowid
  // tables. The canonical DDL guard below is still authoritative.
  const expectedDDL = [
    `CREATE TABLE atomic_anchor_identity (id INTEGER PRIMARY KEY CHECK(id=1),
      signer_fingerprint TEXT NOT NULL)`,
    `CREATE TABLE atomic_anchor_binding (scope TEXT PRIMARY KEY NOT NULL,
      account_id TEXT NOT NULL, store_id TEXT NOT NULL)`,
    `CREATE TABLE atomic_anchor_head (scope TEXT PRIMARY KEY NOT NULL,
      sequence INTEGER NOT NULL, head_hash TEXT NOT NULL, chain_hash TEXT NOT NULL)`,
    `CREATE TABLE atomic_anchor_history (scope TEXT NOT NULL, sequence INTEGER NOT NULL,
      previous_hash TEXT NOT NULL, previous_chain TEXT NOT NULL,
      head_hash TEXT NOT NULL, chain_hash TEXT NOT NULL, seal TEXT NOT NULL,
      PRIMARY KEY(scope,sequence), UNIQUE(scope,head_hash))`,
    ...(minimumFingerprint ? [`CREATE TABLE atomic_anchor_minimum_fence (
      id INTEGER PRIMARY KEY CHECK(id=1), minimum_fingerprint TEXT NOT NULL)`] : []),
  ];
  const normalize = (sql) => sql.replace(/\s+/g, " ")
    .replace(/\(\s+/g, "(").replace(/\s+\)/g, ")")
    .replace(/^CREATE TABLE IF NOT EXISTS /i, "CREATE TABLE ").trim();
  for (let i = 0; i < objects.length; i++) {
    const expected = expectedDDL.find((sql) => sql.includes(` ${objects[i].name} (`));
    const stored = db.prepare(`SELECT sql FROM sqlite_schema WHERE name=?`).get(objects[i].name);
    requireValid(expected && typeof stored?.sql === "string"
      && normalize(expected) === normalize(stored.sql));
  }
  const persistedBindings = db.prepare("SELECT * FROM atomic_anchor_binding").all();
  requireValid(persistedBindings.length === bindings.size);
  for (const row of persistedBindings) {
    const trusted = bindings.get(row.scope);
    requireValid(trusted && trusted.accountId === row.account_id
      && trusted.storeId === row.store_id);
  }
  if (minimumFingerprint) {
    const minima = db.prepare("SELECT * FROM atomic_anchor_minimum_fence").all();
    requireValid(minima.length === 1 && minima[0].id === 1
      && minima[0].minimum_fingerprint === minimumFingerprint);
  }
}
function current(db, trusted, signerPublicKey) {
  const row = db.prepare("SELECT * FROM atomic_anchor_head WHERE scope=?")
    .get(trusted.scope);
  let sequence = 0, headHash = GENESIS, hash = CHAIN_GENESIS;
  for (const entry of db.prepare(`SELECT * FROM atomic_anchor_history
    WHERE scope=? ORDER BY sequence`).iterate(trusted.scope)) {
    const statement = chainStatement(trusted.scope, trusted, sequence + 1,
      headHash, hash, entry.head_hash);
    requireValid(typeof entry.seal === "string"
      && /^[A-Za-z0-9_-]{86}$/.test(entry.seal));
    const signature = Buffer.from(entry.seal, "base64url");
    requireValid(entry.sequence === ++sequence && entry.previous_hash === headHash
      && entry.previous_chain === hash && HEX.test(entry.head_hash)
      && entry.head_hash !== headHash && HEX.test(entry.chain_hash)
      && entry.chain_hash === chainHash(statement)
      && signature.length === 64 && signature.toString("base64url") === entry.seal
      && crypto.verify(null, Buffer.from(SEAL_DOMAIN
        + protocol.canonicalJson(statement)), signerPublicKey, signature));
    headHash = entry.head_hash;
    hash = entry.chain_hash;
  }
  requireValid(row ? (row.sequence === sequence && sequence > 0
    && row.head_hash === headHash && row.chain_hash === hash)
    : sequence === 0);
  return Object.freeze({ scope: trusted.scope, sequence, headHash });
}
function enforceMinimum(db, trusted, minimum, signerPublicKey) {
  const actual = current(db, trusted, signerPublicKey);
  requireValid(actual.sequence >= minimum.sequence);
  if (minimum.sequence === 0) return actual;
  const atMinimum = db.prepare(`SELECT head_hash FROM atomic_anchor_history
    WHERE scope=? AND sequence=?`).get(trusted.scope, minimum.sequence);
  requireValid(atMinimum?.head_hash === minimum.headHash);
  return actual;
}

class Zk1SyncAtomicRetainedAnchorDevOff {
  #db;
  #key;
  #publicKey;
  #bindings;
  #minimum;
  #minimumFenceFingerprint;
  #closed = false;

  get requiresMinimumFence() { return this.#minimumFenceFingerprint !== null; }
  get minimumFenceFingerprint() { return this.#minimumFenceFingerprint; }

  constructor({ filename, bootstrapNew = false, signerPrivateKey,
    ownerBindings, trustedMinimumHeads, minimumFencePublicKey = null } = {}) {
    requireValid(signerPrivateKey instanceof crypto.KeyObject
      && signerPrivateKey.type === "private"
      && signerPrivateKey.asymmetricKeyType === "ed25519"
      && typeof filename === "string" && path.isAbsolute(filename)
      && Array.isArray(ownerBindings) && ownerBindings.length > 0
      && Array.isArray(trustedMinimumHeads)
      && trustedMinimumHeads.length === ownerBindings.length);
    this.#key = signerPrivateKey;
    this.#publicKey = crypto.createPublicKey(signerPrivateKey);
    requireValid(minimumFencePublicKey === null
      || (minimumFencePublicKey instanceof crypto.KeyObject
        && minimumFencePublicKey.type === "public"
        && minimumFencePublicKey.asymmetricKeyType === "ed25519"));
    this.#minimumFenceFingerprint = minimumFencePublicKey === null
      ? null : fingerprint(minimumFencePublicKey);
    requireValid(this.#minimumFenceFingerprint !== fingerprint(this.#publicKey));
    this.#bindings = new Map();
    this.#minimum = new Map();
    for (const item of ownerBindings) {
      const record = binding(item);
      requireValid(!this.#bindings.has(record.scope));
      this.#bindings.set(record.scope, record);
    }
    for (const item of trustedMinimumHeads) {
      const head = floor(item);
      requireValid(this.#bindings.has(head.scope) && !this.#minimum.has(head.scope));
      this.#minimum.set(head.scope, head);
    }
    const filenameAbs = path.resolve(filename);
    const existed = fs.existsSync(filenameAbs);
    requireValid(existed || bootstrapNew === true);
    const signer = fingerprint(crypto.createPublicKey(signerPrivateKey));
    let observed;
    try {
      if (existed) {
        observed = assertPrivateSqliteFile(filenameAbs);
        assertPrivateSqliteAuthorityDirectory(filenameAbs);
        const observer = new Database(filenameAbs, { readonly: true, fileMustExist: true });
        try {
          observer.exec("BEGIN TRANSACTION");
          assertStorage(observer, this.#bindings, this.#minimumFenceFingerprint);
          const identity = observer.prepare("SELECT * FROM atomic_anchor_identity").all();
          requireValid(identity.length === 1 && identity[0].id === 1
            && identity[0].signer_fingerprint === signer);
          for (const trusted of this.#bindings.values()) {
            enforceMinimum(observer, trusted, this.#minimum.get(trusted.scope),
              this.#publicKey);
          }
          observer.exec("COMMIT");
        } finally { observer.close(); }
        const after = assertPrivateSqliteFile(filenameAbs);
        requireValid(after.dev === observed.dev && after.ino === observed.ino);
      } else {
        requireValid([...this.#minimum.values()].every((head) =>
          head.sequence === 0 && head.headHash === GENESIS));
        ensurePrivateSqliteDirectory(filenameAbs);
        const fd = fs.openSync(filenameAbs, fs.constants.O_CREAT | fs.constants.O_EXCL
          | fs.constants.O_RDWR, 0o600);
        fs.closeSync(fd);
      }
      assertPrivateSqliteAuthorityDirectory(filenameAbs);
      assertPrivateSqliteFile(filenameAbs);
      this.#db = new Database(filenameAbs, { fileMustExist: true });
      requireValid(this.#db.pragma("journal_mode = WAL", { simple: true }) === "wal");
      this.#db.pragma("synchronous = FULL");
      requireValid(this.#db.pragma("synchronous", { simple: true }) === 2);
      this.#db.exec(`CREATE TABLE IF NOT EXISTS atomic_anchor_identity (
        id INTEGER PRIMARY KEY CHECK(id=1), signer_fingerprint TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS atomic_anchor_binding (
          scope TEXT PRIMARY KEY NOT NULL, account_id TEXT NOT NULL,
          store_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS atomic_anchor_head (
          scope TEXT PRIMARY KEY NOT NULL, sequence INTEGER NOT NULL,
          head_hash TEXT NOT NULL, chain_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS atomic_anchor_history (
          scope TEXT NOT NULL, sequence INTEGER NOT NULL,
          previous_hash TEXT NOT NULL, previous_chain TEXT NOT NULL,
          head_hash TEXT NOT NULL, chain_hash TEXT NOT NULL,
          seal TEXT NOT NULL,
          PRIMARY KEY(scope,sequence), UNIQUE(scope,head_hash));`);
      if (this.#minimumFenceFingerprint) {
        this.#db.exec(`CREATE TABLE IF NOT EXISTS atomic_anchor_minimum_fence (
          id INTEGER PRIMARY KEY CHECK(id=1), minimum_fingerprint TEXT NOT NULL);`);
      }
      if (!existed) {
        this.#db.transaction(() => {
          this.#db.prepare(`INSERT INTO atomic_anchor_identity
            (id,signer_fingerprint) VALUES(1,?)`).run(signer);
          for (const value of this.#bindings.values()) {
            this.#db.prepare(`INSERT INTO atomic_anchor_binding
              (scope,account_id,store_id) VALUES(?,?,?)`).run(
              value.scope, value.accountId, value.storeId);
          }
          if (this.#minimumFenceFingerprint) {
            this.#db.prepare(`INSERT INTO atomic_anchor_minimum_fence
              (id,minimum_fingerprint) VALUES(1,?)`).run(
              this.#minimumFenceFingerprint);
          }
        }).immediate();
      }
      this.#db.transaction(() => this.#assertTrusted(signer)).immediate();
    } catch { this.#db?.close(); throw deny(); }
  }

  #assertTrusted(signer = fingerprint(crypto.createPublicKey(this.#key))) {
    assertStorage(this.#db, this.#bindings, this.#minimumFenceFingerprint);
    const identity = this.#db.prepare("SELECT * FROM atomic_anchor_identity").all();
    requireValid(identity.length === 1 && identity[0].id === 1
      && identity[0].signer_fingerprint === signer);
    const heads = this.#db.prepare("SELECT scope FROM atomic_anchor_head").all();
    requireValid(heads.length <= this.#bindings.size
      && heads.every(({ scope }) => this.#bindings.has(scope)));
    requireValid(!this.#db.prepare(`SELECT 1 FROM atomic_anchor_history h
      WHERE NOT EXISTS (SELECT 1 FROM atomic_anchor_binding b
        WHERE b.scope=h.scope) LIMIT 1`).get());
    for (const trusted of this.#bindings.values()) {
      enforceMinimum(this.#db, trusted, this.#minimum.get(trusted.scope),
        this.#publicKey);
    }
  }

  readSignedHead(input) {
    const request = snapshot(input);
    exact(request, ["scope", "nonce"]);
    requireValid(!this.#closed && this.#bindings.has(request.scope)
      && typeof request.nonce === "string" && NONCE.test(request.nonce)
      && Buffer.from(request.nonce, "base64url").length === 32
      && Buffer.from(request.nonce, "base64url").toString("base64url") === request.nonce);
    try {
      return this.#db.transaction(() => {
        this.#assertTrusted();
        const tip = current(this.#db, this.#bindings.get(request.scope),
          this.#publicKey);
        const statement = { version: 1, scope: request.scope,
          nonce: request.nonce, sequence: tip.sequence, headHash: tip.headHash };
        return Object.freeze({ statement: Object.freeze(statement),
          signature: crypto.sign(null, Buffer.from(ANCHOR_DOMAIN
            + protocol.canonicalJson(statement)), this.#key).toString("base64url") });
      }).immediate();
    } catch { throw deny(); }
  }

  readSignedBindingHead(input) {
    const request = snapshot(input);
    exact(request, ["scope", "nonce"]);
    requireValid(!this.#closed && this.#bindings.has(request.scope)
      && typeof request.nonce === "string" && NONCE.test(request.nonce)
      && Buffer.from(request.nonce, "base64url").length === 32
      && Buffer.from(request.nonce, "base64url").toString("base64url") === request.nonce);
    try {
      return this.#db.transaction(() => {
        this.#assertTrusted();
        const owner = this.#bindings.get(request.scope);
        const tip = current(this.#db, owner, this.#publicKey);
        // Unlike the legacy head, this domain binds the immutable account
        // and storage identities. A second anchor with the same scope but a
        // different owner cannot be misinterpreted as the trusted minimum.
        const statement = { version: 2, scope: request.scope,
          accountId: owner.accountId, storeId: owner.storeId,
          nonce: request.nonce, sequence: tip.sequence, headHash: tip.headHash };
        return Object.freeze({ statement: Object.freeze(statement),
          signature: crypto.sign(null, Buffer.from(BINDING_DOMAIN
            + protocol.canonicalJson(statement)), this.#key).toString("base64url") });
      }).immediate();
    } catch { throw deny(); }
  }

  compareAndAdvance(input) {
    const request = snapshot(input);
    exact(request, ["scope", "expectedSequence", "expectedHeadHash", "sequence", "headHash"]);
    requireValid(!this.#closed && this.#bindings.has(request.scope)
      && Number.isSafeInteger(request.expectedSequence) && request.expectedSequence >= 0
      && Number.isSafeInteger(request.sequence)
      && request.sequence === request.expectedSequence + 1
      && typeof request.expectedHeadHash === "string" && HEX.test(request.expectedHeadHash)
      && typeof request.headHash === "string" && HEX.test(request.headHash)
      && request.headHash !== request.expectedHeadHash);
    try {
      return this.#db.transaction(() => {
        this.#assertTrusted();
        const trusted = this.#bindings.get(request.scope);
        const tip = current(this.#db, trusted, this.#publicKey);
        if (tip.sequence !== request.expectedSequence
          || tip.headHash !== request.expectedHeadHash) return false;
        const prev = this.#db.prepare(`SELECT chain_hash FROM atomic_anchor_history
          WHERE scope=? AND sequence=?`).get(request.scope, tip.sequence);
        const previousChain = prev?.chain_hash || CHAIN_GENESIS;
        const chain = chainStatement(request.scope, trusted, request.sequence,
          tip.headHash, previousChain, request.headHash);
        const newChain = chainHash(chain);
        // A recomputable SHA-256 chain cannot authenticate new rows against
        // an SQLite writer with arbitrary DML. Seal EVERY append with the
        // separately held Ed25519 key before publishing the new high-water.
        const seal = crypto.sign(null, Buffer.from(SEAL_DOMAIN
          + protocol.canonicalJson(chain)), this.#key).toString("base64url");
        this.#db.prepare(`INSERT INTO atomic_anchor_history
          (scope,sequence,previous_hash,previous_chain,head_hash,chain_hash,seal)
          VALUES(?,?,?,?,?,?,?)`).run(request.scope, request.sequence,
          tip.headHash, previousChain, request.headHash, newChain, seal);
        this.#db.prepare(`INSERT INTO atomic_anchor_head
          (scope,sequence,head_hash,chain_hash) VALUES(?,?,?,?)
          ON CONFLICT(scope) DO UPDATE SET sequence=excluded.sequence,
            head_hash=excluded.head_hash,chain_hash=excluded.chain_hash`).run(
          request.scope, request.sequence, request.headHash, newChain);
        return true;
      }).immediate();
    } catch { throw deny(); }
  }
  close() { this.#closed = true; this.#db?.close(); }
}

module.exports = { Zk1SyncAtomicRetainedAnchorDevOff, CHAIN_DOMAIN,
  SEAL_DOMAIN, BINDING_DOMAIN };
