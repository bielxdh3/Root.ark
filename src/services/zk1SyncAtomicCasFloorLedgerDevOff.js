"use strict";

// Strict DEV-OFF authority boundary for the Sync v2 atomic CAS floor.
// This module cannot manufacture physical proofs or an external high-water.
// Neither its SQLite file nor a writer-provided callback is an independent
// physical witness. It MUST NOT be wired to production ACKs.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteAuthorityDirectory } = require("./zk1PrivateSqlitePath");

const WITNESS_DOMAIN = "rootark-sync-atomic-batch-witness-v2\0";
const CAS_DOMAIN = "rootark-sync-atomic-batch-external-cas-floor-v2\0";
const ANCHOR_DOMAIN = "rootark-sync-atomic-batch-retained-highwater-v1\0";
const LINEAGE_DOMAIN = "rootark-sync-atomic-batch-physical-lineage-v1\0";
const GENESIS = crypto.createHash("sha256")
  .update("rootark-sync-atomic-batch-cas-genesis-v1\0").digest("hex");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const OP = /^[A-Za-z0-9._:-]{1,160}$/;
const HEX = /^[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const COMMIT = /^[A-Za-z0-9_-]{16,128}$/;
const ID_FIELDS = ["scope", "accountId", "storeId", "username", "compartmentId"];
const PHYSICAL_FIELDS = ["version", ...ID_FIELDS, "nonce", "operationIds",
  "envelopeDigests", "commitId", "storeHeadSha256", "fencingEpoch", "physicalDurable"];
const ANCHOR_FIELDS = ["version", "scope", "nonce", "sequence", "headHash"];
const LINEAGE_FIELDS = ["version", "scope", "accountId", "storeId", "nonce",
  "previousCommitId", "previousHeadSha256", "previousFencingEpoch",
  "commitId", "storeHeadSha256", "fencingEpoch", "physicalDurable"];

function deny() {
  return Object.assign(new Error("SYNC_ATOMIC_CAS_DEV_OFF_UNVERIFIED"),
    { code: "SYNC_ATOMIC_CAS_DEV_OFF_UNVERIFIED" });
}
function requireValid(ok) { if (!ok) throw deny(); }
function exact(value, keys) {
  requireValid(value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key)));
}
function detached(value) {
  try {
    const data = protocol.canonicalJson(value);
    requireValid(typeof data === "string" && data.length < 8192);
    return JSON.parse(data);
  } catch { throw deny(); }
}
function assertKey(key, type) {
  requireValid(key instanceof crypto.KeyObject && key.type === type
    && key.asymmetricKeyType === "ed25519");
  return type === "private" ? crypto.createPublicKey(key) : key;
}
function fingerprint(key) {
  return assertKey(key, "public").export({ type: "spki", format: "der" }).toString("hex");
}
function verifySigned(receipt, keys, domain, publicKey) {
  const copy = detached(receipt);
  exact(copy, ["statement", "signature"]);
  exact(copy.statement, keys);
  requireValid(typeof copy.signature === "string"
    && /^[A-Za-z0-9_-]{86}$/.test(copy.signature));
  const signature = Buffer.from(copy.signature, "base64url");
  requireValid(signature.length === 64
    && signature.toString("base64url") === copy.signature
    && crypto.verify(null, Buffer.from(domain + protocol.canonicalJson(copy.statement), "utf8"),
      publicKey, signature));
  return copy.statement;
}
function freshNonce() { return crypto.randomBytes(32).toString("base64url"); }
function assertNonce(value) {
  requireValid(typeof value === "string" && NONCE.test(value)
    && Buffer.from(value, "base64url").toString("base64url") === value);
}
function assertIdentity(value) {
  exact(value, ID_FIELDS);
  requireValid(SCOPE.test(value.scope) && UUID.test(value.accountId)
    && UUID.test(value.storeId) && typeof value.username === "string"
    && value.username.length > 0 && value.username.length <= 512
    && typeof value.compartmentId === "string" && value.compartmentId.length > 0
    && value.compartmentId.length <= 512);
}
function assertPair(value) {
  requireValid(Array.isArray(value.operationIds) && value.operationIds.length === 2
    && value.operationIds.every((id) => typeof id === "string" && OP.test(id))
    && value.operationIds[0] !== value.operationIds[1]
    && Array.isArray(value.envelopeDigests) && value.envelopeDigests.length === 2
    && value.envelopeDigests.every((digest) => typeof digest === "string" && HEX.test(digest)));
}
function same(a, b) { return protocol.canonicalJson(a) === protocol.canonicalJson(b); }
async function requireExternalHead(anchor, anchorKey, scope, expected) {
  const nonce = freshNonce();
  const statement = verifySigned(await anchor.readSignedHead({ scope, nonce }),
    ANCHOR_FIELDS, ANCHOR_DOMAIN, anchorKey);
  requireValid(statement.version === 1 && statement.scope === scope
    && statement.nonce === nonce && Number.isSafeInteger(statement.sequence)
    && statement.sequence >= 0 && HEX.test(statement.headHash)
    && statement.sequence === expected.sequence
    && statement.headHash === expected.headHash);
}
function currentOf(row) {
  return row ? {
    sequence: row.sequence, headHash: row.head_hash,
    commitId: row.commit_id, storeHeadSha256: row.store_head,
    fencingEpoch: row.fencing_epoch,
    operationIds: JSON.parse(row.operation_ids), envelopeDigests: JSON.parse(row.envelope_digests),
  } : { sequence: 0, headHash: GENESIS };
}

class Zk1SyncAtomicCasFloorLedgerDevOff {
  #db;
  #bindings;
  #casPrivateKey;
  #witnessPublicKey;
  #anchorPublicKey;
  #physicalFence;
  #retainedAnchor;
  #queue = Promise.resolve();
  #uncertain = false;
  #poisoned = false;

  constructor({ filename, bootstrapNew = false, casPrivateKey, witnessPublicKey,
    anchorPublicKey, ownerBindings, physicalFence, retainedAnchor } = {}) {
    const casKey = assertKey(casPrivateKey, "private");
    const witnessKey = assertKey(witnessPublicKey, "public");
    const anchorKey = assertKey(anchorPublicKey, "public");
    requireValid(new Set([fingerprint(casKey), fingerprint(witnessKey),
      fingerprint(anchorKey)]).size === 3);
    requireValid(typeof filename === "string" && path.isAbsolute(filename)
      && typeof physicalFence?.withCurrentRead === "function"
      && typeof retainedAnchor?.readSignedHead === "function"
      && typeof retainedAnchor?.compareAndAdvance === "function"
      && Array.isArray(ownerBindings) && ownerBindings.length > 0);
    this.#bindings = new Map();
    for (const input of ownerBindings) {
      const binding = detached(input);
      assertIdentity(binding);
      requireValid(!this.#bindings.has(binding.scope));
      this.#bindings.set(binding.scope, Object.freeze(binding));
    }
    this.#casPrivateKey = casPrivateKey;
    this.#witnessPublicKey = witnessKey;
    this.#anchorPublicKey = anchorKey;
    this.#physicalFence = physicalFence;
    this.#retainedAnchor = retainedAnchor;
    const absolute = path.resolve(filename);
    const existed = fs.existsSync(absolute);
    requireValid(existed || bootstrapNew === true);
    try {
      if (existed) assertPrivateSqliteFile(absolute);
      else {
        ensurePrivateSqliteDirectory(absolute);
        const fd = fs.openSync(absolute, fs.constants.O_CREAT | fs.constants.O_EXCL
          | fs.constants.O_RDWR, 0o600);
        fs.closeSync(fd);
      }
      assertPrivateSqliteAuthorityDirectory(absolute);
      assertPrivateSqliteFile(absolute);
    } catch { throw deny(); }
    try {
      this.#db = new Database(absolute, { fileMustExist: true });
      requireValid(this.#db.pragma("journal_mode = WAL", { simple: true }) === "wal");
      this.#db.pragma("synchronous = FULL");
      requireValid(this.#db.pragma("synchronous", { simple: true }) === 2);
      this.#db.pragma("foreign_keys = ON");
      this.#db.exec(`CREATE TABLE IF NOT EXISTS atomic_cas_identity (
        id INTEGER PRIMARY KEY CHECK(id=1),
        cas_fingerprint TEXT NOT NULL, witness_fingerprint TEXT NOT NULL,
        anchor_fingerprint TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS atomic_cas_head (
        scope TEXT PRIMARY KEY, account_id TEXT NOT NULL, store_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK(sequence>0), head_hash TEXT NOT NULL,
        commit_id TEXT NOT NULL, store_head TEXT NOT NULL,
        fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch>0),
        operation_ids TEXT NOT NULL, envelope_digests TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS atomic_cas_history (
        scope TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>0),
        previous_hash TEXT NOT NULL, head_hash TEXT NOT NULL UNIQUE,
        commit_id TEXT NOT NULL, store_head TEXT NOT NULL,
        fencing_epoch INTEGER NOT NULL, PRIMARY KEY(scope,sequence),
        UNIQUE(scope,commit_id), UNIQUE(scope,store_head)
      );`);
      if (!existed) {
        this.#db.prepare(`INSERT INTO atomic_cas_identity
          (id,cas_fingerprint,witness_fingerprint,anchor_fingerprint)
          VALUES(1,?,?,?)`).run(fingerprint(casKey),
          fingerprint(witnessKey), fingerprint(anchorKey));
      }
      const identity = this.#db.prepare(
        "SELECT * FROM atomic_cas_identity WHERE id=1").get();
      requireValid(identity && identity.cas_fingerprint === fingerprint(casKey)
        && identity.witness_fingerprint === fingerprint(witnessKey)
        && identity.anchor_fingerprint === fingerprint(anchorKey));
    } catch {
      this.#db?.close();
      throw deny();
    }
  }

  static async open(options) {
    // Before ANY writable SQLite opening, demand a fresh signed external
    // high-water for each requested owner binding, and verify the persisted
    // authority identities through read-only inspection. A recovered old
    // local snapshot must not be checkpointed or mutated before refusal.
    let before = null;
    try {
      const filename = options?.filename;
      requireValid(typeof filename === "string" && path.isAbsolute(filename)
        && typeof options?.retainedAnchor?.readSignedHead === "function");
      const anchorKey = assertKey(options.anchorPublicKey, "public");
      const casKey = assertKey(options.casPrivateKey, "private");
      const witnessKey = assertKey(options.witnessPublicKey, "public");
      const owner = new Map();
      requireValid(Array.isArray(options.ownerBindings)
        && options.ownerBindings.length > 0);
      for (const value of options.ownerBindings) {
        const binding = detached(value);
        assertIdentity(binding);
        requireValid(!owner.has(binding.scope));
        owner.set(binding.scope, binding);
      }
      const present = fs.existsSync(filename);
      let rows = new Map();
      if (present) {
        before = assertPrivateSqliteFile(filename);
        assertPrivateSqliteAuthorityDirectory(filename);
        const observer = new Database(filename, { readonly: true,
          fileMustExist: true });
        try {
          const authority = observer.prepare(
            "SELECT * FROM atomic_cas_identity WHERE id=1").get();
          requireValid(authority
            && authority.cas_fingerprint === fingerprint(casKey)
            && authority.witness_fingerprint === fingerprint(witnessKey)
            && authority.anchor_fingerprint === fingerprint(anchorKey));
          rows = new Map(observer.prepare(`SELECT scope,sequence,head_hash
            FROM atomic_cas_head`).all().map((row) =>
            [row.scope, { sequence: row.sequence, headHash: row.head_hash }]));
          requireValid(rows.size <= owner.size);
          for (const scope of rows.keys()) requireValid(owner.has(scope));
        } finally { observer.close(); }
        const afterRead = assertPrivateSqliteFile(filename);
        requireValid(before.dev === afterRead.dev && before.ino === afterRead.ino);
      }
      for (const scope of owner.keys()) {
        await requireExternalHead(options.retainedAnchor, anchorKey,
          scope, rows.get(scope) || { sequence: 0, headHash: GENESIS });
      }
      if (before) {
        const afterAnchor = assertPrivateSqliteFile(filename);
        requireValid(before.dev === afterAnchor.dev && before.ino === afterAnchor.ino);
      }
    } catch { throw deny(); }
    const ledger = new Zk1SyncAtomicCasFloorLedgerDevOff(options);
    try {
      for (const binding of ledger.#bindings.values()) {
        await ledger.#requireRetainedHead(binding.scope, ledger.#current(binding.scope));
      }
      return ledger;
    } catch (error) {
      ledger.close();
      throw error;
    }
  }
  close() { this.#db?.close(); }
  #current(scope) {
    const row = this.#db.prepare("SELECT * FROM atomic_cas_head WHERE scope=?").get(scope);
    if (row) {
      const binding = this.#bindings.get(scope);
      requireValid(binding && row.account_id === binding.accountId
        && row.store_id === binding.storeId
        && Number.isSafeInteger(row.sequence) && row.sequence >= 1
        && HEX.test(row.head_hash) && HEX.test(row.store_head)
        && COMMIT.test(row.commit_id) && Number.isSafeInteger(row.fencing_epoch)
        && row.fencing_epoch >= 1);
      const pair = currentOf(row);
      assertPair(pair);
      const prior = this.#db.prepare(`SELECT * FROM atomic_cas_history
        WHERE scope=? AND sequence=?`).get(scope, row.sequence);
      requireValid(prior && prior.commit_id === row.commit_id
        && prior.store_head === row.store_head
        && prior.fencing_epoch === row.fencing_epoch
        && prior.head_hash === row.head_hash && HEX.test(prior.previous_hash));
      const calculated = crypto.createHash("sha256").update(
        "rootark-sync-atomic-batch-cas-chain-v1\0"
        + protocol.canonicalJson({ scope, sequence: row.sequence,
          previousHash: prior.previous_hash, accountId: row.account_id,
          storeId: row.store_id, commitId: row.commit_id,
          storeHeadSha256: row.store_head,
          fencingEpoch: row.fencing_epoch, operationIds: pair.operationIds,
          envelopeDigests: pair.envelopeDigests })).digest("hex");
      requireValid(calculated === row.head_hash
        && (row.sequence > 1 || prior.previous_hash === GENESIS));
    }
    return currentOf(row);
  }
  #binding(input) {
    const scope = input?.scope;
    const trusted = this.#bindings.get(scope);
    requireValid(trusted && input?.accountId === trusted.accountId
      && input?.storeId === trusted.storeId);
    return trusted;
  }
  async #requireRetainedHead(scope, expected) {
    return requireExternalHead(this.#retainedAnchor, this.#anchorPublicKey,
      scope, expected);
  }
  async #withPhysicalProof(binding, pair, fn, previous = null) {
    const nonce = freshNonce();
    let called = false;
    let closed = false;
    let completed = false;
    let callbackSucceeded = false;
    let enteredCritical = false;
    let callbackResult;
    let returned;
    try { returned = await this.#physicalFence.withCurrentRead({
      ...binding, operationIds: pair.operationIds,
      envelopeDigests: pair.envelopeDigests, nonce,
      expectedPrevious: previous?.sequence > 0 ? {
        commitId: previous.commitId, storeHeadSha256: previous.storeHeadSha256,
        fencingEpoch: previous.fencingEpoch,
      } : null,
    }, async (bundle, lease) => {
      requireValid(!closed);
      requireValid(!called);
      called = true;
      try {
      requireValid(lease && typeof lease.assertHeld === "function");
      const assertHeld = () => {
        let held = false;
        try { held = lease.assertHeld(); } catch { throw deny(); }
        requireValid(held === true);
      };
      assertHeld();
      const copy = detached(bundle);
      exact(copy, ["receipt", "lineage"]);
      const proof = verifySigned(copy.receipt, PHYSICAL_FIELDS, WITNESS_DOMAIN,
        this.#witnessPublicKey);
      requireValid(proof.version === 2 && proof.physicalDurable === true
        && proof.nonce === nonce && COMMIT.test(proof.commitId)
        && HEX.test(proof.storeHeadSha256)
        && Number.isSafeInteger(proof.fencingEpoch) && proof.fencingEpoch >= 1
        && ID_FIELDS.every((field) => proof[field] === binding[field])
        && same(proof.operationIds, pair.operationIds)
        && same(proof.envelopeDigests, pair.envelopeDigests));
      if (previous?.sequence > 0
        && (proof.commitId !== previous.commitId
          || proof.storeHeadSha256 !== previous.storeHeadSha256)) {
        const lineage = verifySigned(copy.lineage, LINEAGE_FIELDS, LINEAGE_DOMAIN,
          this.#witnessPublicKey);
        requireValid(lineage.version === 1 && lineage.physicalDurable === true
          && lineage.nonce === nonce && lineage.scope === binding.scope
          && lineage.accountId === binding.accountId
          && lineage.storeId === binding.storeId
          && lineage.previousCommitId === previous.commitId
          && lineage.previousHeadSha256 === previous.storeHeadSha256
          && lineage.previousFencingEpoch === previous.fencingEpoch
          && lineage.commitId === proof.commitId
          && lineage.storeHeadSha256 === proof.storeHeadSha256
          && lineage.fencingEpoch === proof.fencingEpoch);
      } else {
        requireValid(copy.lineage === null);
      }
      callbackResult = await fn(proof, assertHeld,
        () => { enteredCritical = true; });
      assertHeld();
      callbackSucceeded = true;
      return callbackResult;
      } finally { completed = true; }
    });
    } catch {
      // A detached continuation can outlive its lock: no positive response.
      closed = true;
      if (enteredCritical || !called) {
        this.#uncertain = true;
        this.#poisoned = true;
      }
      throw deny();
    }
    closed = true;
    if (!called || !completed || !callbackSucceeded || returned !== callbackResult) {
      // The fence must await and return the exact continuation result. An
      // early-returning provider may have committed an ambiguous local row.
      this.#uncertain = true;
      this.#poisoned = true;
      throw deny();
    }
    return returned;
  }
  async #ordered(fn) {
    const previous = this.#queue;
    let release;
    this.#queue = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      requireValid(!this.#uncertain && !this.#poisoned);
      return await fn();
    } finally { release(); }
  }
  async recordPhysicalPair(input) {
    const request = detached(input);
    exact(request, ["scope", "accountId", "storeId", "operationIds", "envelopeDigests"]);
    const binding = this.#binding(request);
    assertPair(request);
    return this.#ordered(async () => {
      const old = this.#current(binding.scope);
      await this.#requireRetainedHead(binding.scope, old);
      return this.#withPhysicalProof(binding, request,
        async (proof, assertHeld, markCritical) => {
      assertHeld();
      requireValid(!this.#uncertain && !this.#poisoned);
      if (old.sequence > 0 && old.commitId === proof.commitId
        && old.storeHeadSha256 === proof.storeHeadSha256
        && old.fencingEpoch === proof.fencingEpoch
        && same(old.operationIds, proof.operationIds)
        && same(old.envelopeDigests, proof.envelopeDigests)) {
        return Object.freeze({ sequence: old.sequence, headHash: old.headHash });
      }
      // Every different physical head requires a strictly newer fencing
      // authority, never an old but freshly re-signed rollback.
      requireValid(old.sequence < Number.MAX_SAFE_INTEGER
        && (old.sequence === 0 || proof.fencingEpoch > old.fencingEpoch)
        && (old.sequence === 0 || (proof.commitId !== old.commitId
          && proof.storeHeadSha256 !== old.storeHeadSha256)));
      const sequence = old.sequence + 1;
      const headHash = crypto.createHash("sha256").update(
        "rootark-sync-atomic-batch-cas-chain-v1\0"
        + protocol.canonicalJson({ scope: binding.scope, sequence,
          previousHash: old.headHash, accountId: binding.accountId,
          storeId: binding.storeId, commitId: proof.commitId,
          storeHeadSha256: proof.storeHeadSha256,
          fencingEpoch: proof.fencingEpoch, operationIds: proof.operationIds,
          envelopeDigests: proof.envelopeDigests })).digest("hex");
      const tx = this.#db.transaction(() => {
        assertHeld();
        requireValid(same(this.#current(binding.scope), old));
        this.#db.prepare(`INSERT INTO atomic_cas_history
          (scope,sequence,previous_hash,head_hash,commit_id,store_head,fencing_epoch)
          VALUES(?,?,?,?,?,?,?)`).run(binding.scope, sequence, old.headHash,
          headHash, proof.commitId, proof.storeHeadSha256, proof.fencingEpoch);
        this.#db.prepare(`INSERT INTO atomic_cas_head
          (scope,account_id,store_id,sequence,head_hash,commit_id,store_head,
            fencing_epoch,operation_ids,envelope_digests)
          VALUES(?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(scope) DO UPDATE SET
            account_id=excluded.account_id, store_id=excluded.store_id,
            sequence=excluded.sequence, head_hash=excluded.head_hash,
            commit_id=excluded.commit_id, store_head=excluded.store_head,
            fencing_epoch=excluded.fencing_epoch,
            operation_ids=excluded.operation_ids, envelope_digests=excluded.envelope_digests`)
          .run(binding.scope, binding.accountId, binding.storeId, sequence,
            headHash, proof.commitId, proof.storeHeadSha256, proof.fencingEpoch,
            protocol.canonicalJson(proof.operationIds),
            protocol.canonicalJson(proof.envelopeDigests));
      });
      // If the physical store advances but either durable write is ambiguous,
      // retain the committed local row and latch unavailable. Never sign an
      // older floor, repair from an untrusted writer, or claim an ACK.
      markCritical();
      this.#uncertain = true;
      try {
        assertHeld();
        tx.immediate();
        assertHeld();
        const accepted = await this.#retainedAnchor.compareAndAdvance({
          scope: binding.scope, expectedSequence: old.sequence,
          expectedHeadHash: old.headHash, sequence, headHash,
        });
        requireValid(accepted === true);
        assertHeld();
        await this.#requireRetainedHead(binding.scope, { sequence, headHash });
        assertHeld();
        requireValid(!this.#poisoned);
        this.#uncertain = false;
      } catch { throw deny(); }
      return Object.freeze({ sequence, headHash });
      }, old);
    });
  }
  async freshCurrent(input) {
    const request = detached(input);
    exact(request, ["scope", "accountId", "storeId", "nonce",
      "commitId", "storeHeadSha256", "fencingEpoch"]);
    const binding = this.#binding(request);
    assertNonce(request.nonce);
    requireValid(COMMIT.test(request.commitId) && HEX.test(request.storeHeadSha256)
      && Number.isSafeInteger(request.fencingEpoch) && request.fencingEpoch >= 1);
    return this.#ordered(async () => {
      const current = this.#current(binding.scope);
      requireValid(current.sequence > 0 && current.commitId === request.commitId
        && current.storeHeadSha256 === request.storeHeadSha256
        && current.fencingEpoch === request.fencingEpoch);
      return this.#withPhysicalProof(binding, {
        operationIds: current.operationIds,
        envelopeDigests: current.envelopeDigests,
      }, async (physical, assertHeld, markCritical) => {
        assertHeld();
        requireValid(physical.commitId === current.commitId
          && physical.storeHeadSha256 === current.storeHeadSha256
          && physical.fencingEpoch === current.fencingEpoch);
        await this.#requireRetainedHead(binding.scope, current);
        assertHeld();
        requireValid(!this.#poisoned);
        markCritical();
        const statement = {
          version: 2, scope: binding.scope, accountId: binding.accountId,
          storeId: binding.storeId, nonce: request.nonce,
          commitId: current.commitId, storeHeadSha256: current.storeHeadSha256,
          fencingEpoch: current.fencingEpoch, sequence: current.sequence, current: true,
        };
        return Object.freeze({ statement: Object.freeze(statement),
          signature: crypto.sign(null, Buffer.from(CAS_DOMAIN
            + protocol.canonicalJson(statement), "utf8"), this.#casPrivateKey)
            .toString("base64url") });
      });
    });
  }
}

module.exports = { Zk1SyncAtomicCasFloorLedgerDevOff, WITNESS_DOMAIN,
  CAS_DOMAIN, ANCHOR_DOMAIN, LINEAGE_DOMAIN, GENESIS };
