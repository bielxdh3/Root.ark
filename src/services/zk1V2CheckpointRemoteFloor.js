"use strict";

// Experimental independently hosted V2 high-water *readback*. Its signature is
// evidence about this floor's SQLite, NOT a two-phase commit or cloud fsync.
// Identity/owner pins and any externally retained minimum require out-of-band
// custody. Keep this module independent of the witness's SQLite connection.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const z = require("../crypto/rootark-zk-1");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile } =
  require("./zk1PrivateSqlitePath");

const DOMAIN = Buffer.from("Root.ark/zk-1/v2-independent-checkpoint-floor/v1\0");
const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/v2-checkpoint-floor-owner-advance/v1\0");
const TYPE = "rootark-zk1-v2-independent-checkpoint-floor/v1";
const ZERO = Buffer.alloc(32);
const FIELDS = ["type", "account_id", "compartment_id", "keyring_id", "sequence",
  "epoch", "head_digest", "checkpoint_digest", "chain_hash", "operation_id",
  "cas_receipt_hash", "floor_receipt_hash", "cas_receipt_identity_hash",
  "floor_receipt_identity_hash", "ancestry", "nonce", "issued_at"];
const ANCESTRY_FIELDS = ["sequence", "epoch", "head_digest", "checkpoint_digest",
  "previous_head_digest", "previous_checkpoint_digest", "operation_id",
  "cas_receipt_hash", "floor_receipt_hash", "owner_signature"];
const RETAINED_ID_FIELDS = ["operationId", "casReceiptHash", "floorReceiptHash",
  "casReceiptIdentityHash", "floorReceiptIdentityHash"];
const MAX_ANCESTRY = 8;
const ENTRY_DOMAIN = Buffer.from("v2-independent-floor-entry\0");
const RECEIPT_ID_DOMAIN = Buffer.from("v2-independent-floor-receipt-identity\0");
function deny() { const e = new Error("ZK_V2_INDEPENDENT_FLOOR_DENIED"); e.code = e.message; throw e; }
function byte(v, length) {
  if ((!Buffer.isBuffer(v) && !(v instanceof Uint8Array))
    || v.length !== length) deny();
  return Buffer.from(v);
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((name) => !Object.hasOwn(value, name))) deny();
}
function scopeOf(scope) {
  if (!scope || typeof scope !== "object") deny();
  return { account_id: byte(scope.account_id, 16),
    compartment_id: Buffer.from(scope.compartment_id),
    keyring_id: byte(scope.keyring_id, 16) };
}
function fullRetainedMinimum(minimum) {
  if (!minimum || !Number.isSafeInteger(minimum.sequence)
    || minimum.sequence < 128
    || !Number.isSafeInteger(minimum.epoch)
    || minimum.epoch < (minimum.sequence === 128 ? 0 : 1)) deny();
  const genesis = minimum.sequence === 128;
  const baseFields = ["sequence", "epoch", "chainHash", "headDigest", "checkpointDigest"];
  const extra = genesis && Reflect.ownKeys(minimum).length === baseFields.length
    ? [] : RETAINED_ID_FIELDS;
  exact(minimum, [...baseFields, ...extra]);
  const pinned = { sequence: minimum.sequence, epoch: minimum.epoch,
    chainHash: byte(minimum.chainHash, 32),
    headDigest: byte(minimum.headDigest, 32),
    checkpointDigest: byte(minimum.checkpointDigest, 32) };
  if (genesis) {
    if (pinned.epoch !== 0 || !same(pinned.chainHash, ZERO)) deny();
    if (extra.length && RETAINED_ID_FIELDS.some((name) =>
      !same(byte(minimum[name], 32), ZERO))) deny();
    return { ...pinned, ...Object.fromEntries(RETAINED_ID_FIELDS
      .map((name) => [name, Buffer.from(ZERO)])) };
  }
  for (const name of RETAINED_ID_FIELDS) pinned[name] = byte(minimum[name], 32);
  return pinned;
}
function key(value, kind = "public") {
  if (!(value instanceof crypto.KeyObject) || value.type !== kind
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function hash(...items) {
  const sha = crypto.createHash("sha256");
  for (const item of items) sha.update(item);
  return sha.digest();
}
function snapshotDigest(rows) {
  const sha = crypto.createHash("sha256");
  const columns = ["sequence", "epoch", "head_digest", "checkpoint_digest",
    "previous_head_digest", "previous_checkpoint_digest",
    "chain_hash", "previous_hash", "operation_id", "cas_receipt",
    "floor_receipt", "owner_signature"];
  for (const row of rows) for (const column of columns) {
    const data = Buffer.isBuffer(row[column]) ? row[column]
      : Buffer.from(String(row[column]));
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    sha.update(length).update(data);
  }
  return sha.digest();
}
function same(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function identity(scope, casKey, floorKey, ownerKey, witnessKey, base) {
  return hash(Buffer.from("v2-floor-identity\0"), ...Object.values(scope),
    ...[casKey, floorKey, ownerKey, witnessKey].map((v) =>
      v.export({ type: "spki", format: "der" })), base.headDigest, base.checkpointDigest);
}
function advanceStatement(v) {
  exact(v, ["scope", "sequence", "epoch", "headDigest", "checkpointDigest",
    "previousHeadDigest", "previousCheckpointDigest", "operationId", "casReceipt", "floorReceipt"]);
  const scope = scopeOf(v.scope);
  if (!Number.isSafeInteger(v.sequence) || v.sequence < 129
    || !Number.isSafeInteger(v.epoch) || v.epoch < 1) deny();
  return { ...scope, sequence: v.sequence, epoch: v.epoch,
    head_digest: byte(v.headDigest, 32), checkpoint_digest: byte(v.checkpointDigest, 32),
    previous_head_digest: byte(v.previousHeadDigest, 32),
    previous_checkpoint_digest: byte(v.previousCheckpointDigest, 32),
    operation_id: byte(v.operationId, 32),
    cas_receipt_hash: hash(byte(v.casReceipt, Buffer.from(v.casReceipt).length)),
    floor_receipt_hash: hash(byte(v.floorReceipt, Buffer.from(v.floorReceipt).length)) };
}
async function receiptIdentityHash(raw) {
  const signed = await z.decodeDeterministic(byte(raw, Buffer.from(raw).length));
  const { signature, nonce, issued_at, ...stable } = signed;
  byte(signature, 64);
  byte(nonce, 32);
  if (!Number.isSafeInteger(issued_at)) deny();
  return hash(RECEIPT_ID_DOMAIN,
    Buffer.from(await z.encodeDeterministic(stable)));
}
function compactStatement(scope, step) {
  exact(step, ANCESTRY_FIELDS);
  if (!Number.isSafeInteger(step.sequence) || step.sequence < 129
    || !Number.isSafeInteger(step.epoch) || step.epoch < 1) deny();
  return { ...scope, sequence: step.sequence, epoch: step.epoch,
    head_digest: byte(step.head_digest, 32),
    checkpoint_digest: byte(step.checkpoint_digest, 32),
    previous_head_digest: byte(step.previous_head_digest, 32),
    previous_checkpoint_digest: byte(step.previous_checkpoint_digest, 32),
    operation_id: byte(step.operation_id, 32),
    cas_receipt_hash: byte(step.cas_receipt_hash, 32),
    floor_receipt_hash: byte(step.floor_receipt_hash, 32) };
}
async function signOwnerAdvance(v, ownerPrivateKey) {
  key(ownerPrivateKey, "private");
  const statement = advanceStatement(v);
  return crypto.sign(null, Buffer.concat([OWNER_DOMAIN,
    Buffer.from(await z.encodeDeterministic(statement))]), ownerPrivateKey);
}
function headStatement(scope, row, nonce, ancestry = []) {
  return { type: TYPE, ...scope, sequence: row.sequence, epoch: row.epoch,
    head_digest: row.head_digest, checkpoint_digest: row.checkpoint_digest,
    chain_hash: row.chain_hash, operation_id: row.operation_id || ZERO,
    cas_receipt_hash: row.cas_receipt_hash || ZERO,
    floor_receipt_hash: row.floor_receipt_hash || ZERO,
    cas_receipt_identity_hash: row.cas_receipt_identity_hash || ZERO,
    floor_receipt_identity_hash: row.floor_receipt_identity_hash || ZERO,
    ancestry, nonce: byte(nonce, 32), issued_at: Math.floor(Date.now() / 1000) };
}
function assertIndependentV2Predecessor(head, { previousSequence, previousDigest,
  previousCheckpointDigest, proposedEpoch } = {}) {
  if (!head || !Number.isSafeInteger(head.sequence) || head.sequence !== previousSequence
    || !Number.isSafeInteger(head.epoch) || !Number.isSafeInteger(proposedEpoch)
    || proposedEpoch < head.epoch || proposedEpoch < 1
    || !same(byte(head.headDigest, 32), byte(previousDigest, 32))
    || !same(byte(head.checkpointDigest, 32), byte(previousCheckpointDigest, 32))) deny();
  return true;
}
async function verifySignedHead(raw, { scope, pinnedFloorPublicKey,
  pinnedOwnerPublicKey, nonce, minimum } = {}) {
  try {
    const proof = await z.decodeDeterministic(byte(raw, Buffer.from(raw).length));
    exact(proof, [...FIELDS, "signature"]);
    const { signature, ...unsigned } = proof;
    const expected = scopeOf(scope);
    if (unsigned.type !== TYPE || !Number.isSafeInteger(unsigned.sequence)
      || unsigned.sequence < 128 || !Number.isSafeInteger(unsigned.epoch)
      || unsigned.epoch < 0 || !Number.isSafeInteger(unsigned.issued_at)
      || Math.abs(Date.now() / 1000 - unsigned.issued_at) > 30
      || !["account_id", "compartment_id", "keyring_id"].every((field) =>
        same(Buffer.from(unsigned[field]), expected[field]))
      || !same(byte(unsigned.nonce, 32), byte(nonce, 32))) deny();
    const head = { sequence: proof.sequence, epoch: proof.epoch,
      headDigest: byte(proof.head_digest, 32),
      checkpointDigest: byte(proof.checkpoint_digest, 32),
      chainHash: byte(proof.chain_hash, 32),
      operationId: byte(proof.operation_id, 32),
      casReceiptHash: byte(proof.cas_receipt_hash, 32),
      floorReceiptHash: byte(proof.floor_receipt_hash, 32),
      casReceiptIdentityHash: byte(proof.cas_receipt_identity_hash, 32),
      floorReceiptIdentityHash: byte(proof.floor_receipt_identity_hash, 32) };
    // Only an externally retained minimum or a genesis #128 head authorizes
    // bootstrap. A valid signature over a larger forked sequence is NOT a
    // proof that a previously pinned lower head is its ancestor.
    if (!minimum && head.sequence !== 128) deny();
    if (!Array.isArray(proof.ancestry) || proof.ancestry.length > MAX_ANCESTRY) deny();
    if (minimum) {
      const pinned = fullRetainedMinimum(minimum);
      if (head.sequence < pinned.sequence) deny();
      const delta = head.sequence - pinned.sequence;
      if (proof.ancestry.length !== delta || delta > MAX_ANCESTRY) deny();
      if (!delta && (!same(head.headDigest, pinned.headDigest)
        || !same(head.checkpointDigest, pinned.checkpointDigest)
        || !same(head.operationId, pinned.operationId)
        || !same(head.casReceiptHash, pinned.casReceiptHash)
        || !same(head.floorReceiptHash, pinned.floorReceiptHash)
        || !same(head.casReceiptIdentityHash, pinned.casReceiptIdentityHash)
        || !same(head.floorReceiptIdentityHash, pinned.floorReceiptIdentityHash)
        || head.epoch !== pinned.epoch)) deny();
      let sequence = pinned.sequence;
      let chainHash = pinned.chainHash;
      let previousHeadDigest = pinned.headDigest;
      let previousCheckpointDigest = pinned.checkpointDigest;
      let epoch = pinned.epoch;
      for (const step of proof.ancestry) {
        const statement = compactStatement(expected, step);
        if (statement.sequence !== ++sequence || statement.epoch < epoch
          || (previousHeadDigest && !same(statement.previous_head_digest, previousHeadDigest))
          || (previousCheckpointDigest && !same(statement.previous_checkpoint_digest,
            previousCheckpointDigest))) deny();
        const ownerSignature = byte(step.owner_signature, 64);
        if (!crypto.verify(null, Buffer.concat([OWNER_DOMAIN,
          Buffer.from(await z.encodeDeterministic(statement))]),
        key(pinnedOwnerPublicKey), ownerSignature)) deny();
        chainHash = hash(ENTRY_DOMAIN, chainHash,
          Buffer.from(await z.encodeDeterministic(statement)), ownerSignature);
        previousHeadDigest = statement.head_digest;
        previousCheckpointDigest = statement.checkpoint_digest;
        epoch = statement.epoch;
        if (sequence === head.sequence && (!same(head.operationId, statement.operation_id)
          || !same(head.casReceiptHash, statement.cas_receipt_hash)
          || !same(head.floorReceiptHash, statement.floor_receipt_hash))) deny();
      }
      if (!same(chainHash, head.chainHash) || epoch !== head.epoch
        || (delta && (!same(previousHeadDigest, head.headDigest)
          || !same(previousCheckpointDigest, head.checkpointDigest)))) deny();
    } else if (proof.ancestry.length || !same(head.chainHash, ZERO)
      || !same(head.operationId, ZERO) || !same(head.casReceiptHash, ZERO)
      || !same(head.floorReceiptHash, ZERO)
      || !same(head.casReceiptIdentityHash, ZERO)
      || !same(head.floorReceiptIdentityHash, ZERO)) deny();
    if (!crypto.verify(null, Buffer.concat([DOMAIN,
      Buffer.from(await z.encodeDeterministic(unsigned))]),
    key(pinnedFloorPublicKey), byte(signature, 64))) deny();
    return head;
  } catch (_) { deny(); }
}

class Zk1V2CheckpointRemoteFloor {
  #db;
  #scope;
  #cas;
  #floor;
  #owner;
  #witness;
  #base;
  #minimum;
  #trusted;
  constructor(filename, { bootstrapNew = false, scope, casPublicKey,
    floorPublicKey, ownerPublicKey, witnessPrivateKey, baseHeadDigest,
    baseCheckpointDigest, minimum } = {}) {
    if (typeof filename !== "string" || !path.isAbsolute(filename)) deny();
    this.#scope = scopeOf(scope);
    if (this.#scope.compartment_id.length < 1
      || this.#scope.compartment_id.length > 128) deny();
    this.#cas = key(casPublicKey);
    this.#floor = key(floorPublicKey);
    this.#owner = key(ownerPublicKey);
    this.#witness = key(witnessPrivateKey, "private");
    const witnessPublic = crypto.createPublicKey(this.#witness);
    this.#base = { sequence: 128, epoch: 0,
      head_digest: byte(baseHeadDigest, 32),
      checkpoint_digest: byte(baseCheckpointDigest, 32), chain_hash: ZERO };
    if (minimum) {
      if (!Number.isSafeInteger(minimum.sequence) || minimum.sequence < 128) deny();
      this.#minimum = { sequence: minimum.sequence,
        chainHash: byte(minimum.chainHash, 32) };
    }
    const identityDigest = identity(this.#scope, this.#cas, this.#floor,
      this.#owner, witnessPublic, { headDigest: this.#base.head_digest,
        checkpointDigest: this.#base.checkpoint_digest });
    const existed = fs.existsSync(filename);
    if (!existed && !bootstrapNew) deny();
    if (existed) assertPrivateSqliteFile(filename);
    else ensurePrivateSqliteDirectory(filename);
    const Database = require("better-sqlite3");
    this.#db = new Database(filename);
    this.#db.pragma("journal_mode = WAL");
    this.#db.pragma("synchronous = FULL");
    this.#db.exec(`CREATE TABLE IF NOT EXISTS floor_identity(id INTEGER PRIMARY KEY,
      identity BLOB NOT NULL, CHECK(id=1));
      CREATE TABLE IF NOT EXISTS floor_event(sequence INTEGER PRIMARY KEY, epoch INTEGER NOT NULL,
      head_digest BLOB NOT NULL, checkpoint_digest BLOB NOT NULL,
      previous_head_digest BLOB NOT NULL, previous_checkpoint_digest BLOB NOT NULL,
      chain_hash BLOB NOT NULL, previous_hash BLOB NOT NULL,
      operation_id BLOB NOT NULL, cas_receipt BLOB NOT NULL, floor_receipt BLOB NOT NULL,
      owner_signature BLOB NOT NULL);`);
    if (!existed) this.#db.prepare("INSERT INTO floor_identity VALUES(1,?)").run(identityDigest);
    const record = this.#db.prepare("SELECT identity FROM floor_identity WHERE id=1").get();
    if (!record || !same(record.identity, identityDigest)) deny();
    this.#trusted = this.#quickVerify();
  }
  async #verifyReceipts(v) {
    const { receiptMatches } = require("./zk1OpaqueCheckpointV2Remote");
    const fp = (pub) => hash(pub.export({ type: "spki", format: "der" }));
    await Promise.all([["CAS", v.casReceipt, this.#cas], ["FLOOR", v.floorReceipt,
      this.#floor]].map(async ([role, raw, signer]) => receiptMatches(raw, {
        scope: this.#scope, role, state: "FINALIZED", sequence: v.sequence,
        headDigest: v.headDigest, checkpointDigest: v.checkpointDigest,
        operationId: v.operationId, casFp: fp(this.#cas), floorFp: fp(this.#floor),
        signer, fresh: false,
      })));
    const statement = advanceStatement({ scope: v.scope,
      sequence: v.sequence, epoch: v.epoch, headDigest: v.headDigest,
      checkpointDigest: v.checkpointDigest, previousHeadDigest: v.previousHeadDigest,
      previousCheckpointDigest: v.previousCheckpointDigest, operationId: v.operationId,
      casReceipt: v.casReceipt, floorReceipt: v.floorReceipt });
    if (!crypto.verify(null, Buffer.concat([OWNER_DOMAIN,
      Buffer.from(await z.encodeDeterministic(statement))]),
    this.#owner, byte(v.ownerSignature, 64))) deny();
  }
  #quickVerify() {
    const rows = this.#db.prepare("SELECT * FROM floor_event ORDER BY sequence").all();
    if (rows.length > 100000) deny();
    let head = { ...this.#base };
    for (const row of rows) {
      if (row.sequence !== head.sequence + 1 || row.epoch < head.epoch
        || !same(row.previous_hash, head.chain_hash)
        || !same(row.previous_head_digest, head.head_digest)
        || !same(row.previous_checkpoint_digest, head.checkpoint_digest)) deny();
      // The constructor performs only a cheap continuity check. An authenticated
      // full-history pass happens on EVERY externally visible signed readback.
      head = { sequence: row.sequence, epoch: row.epoch,
        head_digest: row.head_digest, checkpoint_digest: row.checkpoint_digest,
        chain_hash: row.chain_hash };
    }
    if (this.#minimum) {
      const atFloor = this.#minimum.sequence === 128 ? this.#base.chain_hash
        : head.sequence === this.#minimum.sequence ? head.chain_hash
          : rows.find((row) => row.sequence === this.#minimum.sequence)?.chain_hash;
      if (head.sequence < this.#minimum.sequence
        || !atFloor || !same(atFloor, this.#minimum.chainHash)) deny();
    }
    return head;
  }
  async #verify() {
    const rows = this.#db.prepare("SELECT * FROM floor_event ORDER BY sequence").all();
    if (rows.length > 4096) deny(); // deliberately bounded DEV full-history verification
    const before = snapshotDigest(rows);
    const version = this.#db.pragma("data_version", { simple: true });
    let head = { ...this.#base };
    for (const row of rows) {
      if (row.sequence !== head.sequence + 1 || row.epoch < head.epoch
        || !same(row.previous_hash, head.chain_hash)
        || !same(row.previous_head_digest, head.head_digest)
        || !same(row.previous_checkpoint_digest, head.checkpoint_digest)) deny();
      const data = { scope: this.#scope, sequence: row.sequence,
        epoch: row.epoch, headDigest: row.head_digest,
        checkpointDigest: row.checkpoint_digest,
        previousHeadDigest: row.previous_head_digest,
        previousCheckpointDigest: row.previous_checkpoint_digest,
        operationId: row.operation_id,
        casReceipt: row.cas_receipt, floorReceipt: row.floor_receipt,
        ownerSignature: row.owner_signature };
      await this.#verifyReceipts(data);
      const expectedHash = hash(Buffer.from("v2-independent-floor-entry\0"),
        head.chain_hash, Buffer.from(await z.encodeDeterministic(
          advanceStatement({ scope: data.scope, sequence: data.sequence,
            epoch: data.epoch, headDigest: data.headDigest,
            checkpointDigest: data.checkpointDigest,
            previousHeadDigest: data.previousHeadDigest,
            previousCheckpointDigest: data.previousCheckpointDigest,
            operationId: data.operationId,
            casReceipt: data.casReceipt, floorReceipt: data.floorReceipt }))),
        data.ownerSignature);
      if (!same(expectedHash, row.chain_hash)) deny();
      head = { sequence: row.sequence, epoch: row.epoch,
        head_digest: row.head_digest, checkpoint_digest: row.checkpoint_digest,
        chain_hash: row.chain_hash };
    }
    if (this.#minimum) {
      const atFloor = this.#minimum.sequence === 128 ? this.#base.chain_hash
        : head.sequence === this.#minimum.sequence ? head.chain_hash
          : rows.find((row) => row.sequence === this.#minimum.sequence)?.chain_hash;
      if (head.sequence < this.#minimum.sequence
        || !atFloor || !same(atFloor, this.#minimum.chainHash)) deny();
    }
    const after = this.#db.prepare("SELECT * FROM floor_event ORDER BY sequence").all();
    if (!same(before, snapshotDigest(after))
      || this.#db.pragma("data_version", { simple: true }) !== version) deny();
    return head;
  }
  async advance(v) {
    // Only a complete pinned owner+CAS+FLOOR signed FINALIZED package advances.
    const statement = advanceStatement({ scope: this.#scope, sequence: v.sequence,
      epoch: v.epoch, headDigest: v.headDigest, checkpointDigest: v.checkpointDigest,
      previousHeadDigest: v.previousHeadDigest,
      previousCheckpointDigest: v.previousCheckpointDigest,
      operationId: v.operationId, casReceipt: v.casReceipt,
      floorReceipt: v.floorReceipt });
    const normalized = { scope: this.#scope, sequence: statement.sequence,
      epoch: statement.epoch, headDigest: statement.head_digest,
      checkpointDigest: statement.checkpoint_digest,
      previousHeadDigest: statement.previous_head_digest,
      previousCheckpointDigest: statement.previous_checkpoint_digest,
      operationId: statement.operation_id, casReceipt: byte(v.casReceipt,
        Buffer.from(v.casReceipt).length), floorReceipt: byte(v.floorReceipt,
        Buffer.from(v.floorReceipt).length), ownerSignature: byte(v.ownerSignature, 64) };
    await this.#verifyReceipts(normalized);
    const head = await this.#verify();
    if (head.sequence !== this.#trusted.sequence
      || !same(head.chain_hash, this.#trusted.chain_hash)) deny();
    if (normalized.sequence === head.sequence) {
      const existing = this.#db.prepare("SELECT * FROM floor_event WHERE sequence=?")
        .get(normalized.sequence);
      if (!existing || !same(existing.head_digest, normalized.headDigest)
        || !same(existing.checkpoint_digest, normalized.checkpointDigest)
        || !same(existing.owner_signature, normalized.ownerSignature)) deny();
      return head;
    }
    if (normalized.sequence !== head.sequence + 1 || normalized.epoch < head.epoch
      || !same(normalized.previousHeadDigest, head.head_digest)
      || !same(normalized.previousCheckpointDigest, head.checkpoint_digest)) deny();
    const chain = hash(Buffer.from("v2-independent-floor-entry\0"), head.chain_hash,
      Buffer.from(await z.encodeDeterministic(statement)), normalized.ownerSignature);
    this.#db.transaction(() => {
      const row = this.#db.prepare("SELECT MAX(sequence) AS seq FROM floor_event").get();
      if ((row.seq || 128) !== head.sequence) deny();
      this.#db.prepare("INSERT INTO floor_event VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").run(
        normalized.sequence, normalized.epoch, normalized.headDigest,
        normalized.checkpointDigest, normalized.previousHeadDigest,
        normalized.previousCheckpointDigest, chain, head.chain_hash,
        normalized.operationId, normalized.casReceipt, normalized.floorReceipt,
        normalized.ownerSignature);
    }).immediate();
    this.#trusted = { sequence: normalized.sequence, epoch: normalized.epoch,
      head_digest: normalized.headDigest, checkpoint_digest: normalized.checkpointDigest,
      chain_hash: chain };
    return this.#trusted;
  }
  async freshHead(nonce, minimum) {
    const head = await this.#verify();
    if (head.sequence !== this.#trusted.sequence
      || !same(head.chain_hash, this.#trusted.chain_hash)) deny();
    if (!minimum || !Number.isSafeInteger(minimum.sequence)
      || minimum.sequence < 128 || minimum.sequence > head.sequence
      || head.sequence - minimum.sequence > MAX_ANCESTRY) deny();
    const previousHash = minimum.sequence === 128 ? ZERO
      : this.#db.prepare("SELECT chain_hash FROM floor_event WHERE sequence=?")
        .get(minimum.sequence)?.chain_hash;
    if (!previousHash || !same(previousHash, byte(minimum.chainHash, 32))) deny();
    const rows = this.#db.prepare("SELECT * FROM floor_event WHERE sequence>? ORDER BY sequence")
      .all(minimum.sequence);
    const ancestry = [];
    for (const row of rows) ancestry.push({
      sequence: row.sequence, epoch: row.epoch, head_digest: row.head_digest,
      checkpoint_digest: row.checkpoint_digest,
      previous_head_digest: row.previous_head_digest,
      previous_checkpoint_digest: row.previous_checkpoint_digest,
      operation_id: row.operation_id,
      cas_receipt_hash: hash(row.cas_receipt),
      floor_receipt_hash: hash(row.floor_receipt),
      owner_signature: row.owner_signature });
    const current = head.sequence === 128 ? null
      : rows.at(-1) || this.#db.prepare("SELECT * FROM floor_event WHERE sequence=?")
        .get(head.sequence);
    if (head.sequence !== 128 && !current) deny();
    const statement = headStatement(this.#scope, {
      ...head, operation_id: current?.operation_id || ZERO,
      cas_receipt_hash: current ? hash(current.cas_receipt) : ZERO,
      floor_receipt_hash: current ? hash(current.floor_receipt) : ZERO,
      cas_receipt_identity_hash: current
        ? await receiptIdentityHash(current.cas_receipt) : ZERO,
      floor_receipt_identity_hash: current
        ? await receiptIdentityHash(current.floor_receipt) : ZERO,
    }, nonce, ancestry);
    const signature = crypto.sign(null, Buffer.concat([DOMAIN,
      Buffer.from(await z.encodeDeterministic(statement))]), this.#witness);
    return Buffer.from(await z.encodeDeterministic({ ...statement, signature }));
  }
  close() { this.#db.close(); }
}

module.exports = { Zk1V2CheckpointRemoteFloor, verifySignedHead, signOwnerAdvance,
  assertIndependentV2Predecessor, receiptIdentityHash, fullRetainedMinimum,
  DOMAIN, TYPE };
