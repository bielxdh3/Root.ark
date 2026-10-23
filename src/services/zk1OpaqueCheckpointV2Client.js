"use strict";

// Opt-in device-side V1->V2 transition. A durable pending owner-signed intent
// precedes remote publication; only two freshly signed FINALIZED remote heads
// authorize readback. This is a local client API, not browser activation.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const archive = require("../crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const { createOpaqueCheckpointV2Coordinator, signCheckpointOwnerApprovalV2,
  inspectIntent } = require("./zk1OpaqueCheckpointV2Remote");

const APPROVAL_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-checkpoint-remote/owner-approval/v2\0");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const ZERO = Buffer.alloc(32);
function deny() {
  const err = new Error("ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE");
  err.code = "ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE";
  throw err;
}
function key(k, type = "public") {
  if (!(k instanceof crypto.KeyObject) || k.type !== type
    || k.asymmetricKeyType !== "ed25519") deny();
  return k;
}
function bytes(input, size) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
    || input.byteLength !== size) deny();
  return Buffer.from(input);
}
function equal(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function fp(k) {
  return crypto.createHash("sha256").update(key(k)
    .export({ type: "spki", format: "der" })).digest();
}
function scopeOf(v) {
  if (!v || Reflect.ownKeys(v).length !== 3) deny();
  return Object.fromEntries(SCOPE.map((n) => {
    if (!Buffer.isBuffer(v[n]) && !(v[n] instanceof Uint8Array)) deny();
    const b = Buffer.from(v[n]);
    if (b.length < (n === "compartment_id" ? 1 : 16)
      || b.length > (n === "compartment_id" ? 128 : 16)) deny();
    return [n, b];
  }));
}
function privateFile(filename, bootstrapNew) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) deny();
  const parent = fs.lstatSync(path.dirname(filename));
  if (!parent.isDirectory() || parent.isSymbolicLink()
    || (process.platform !== "win32"
      && (parent.uid !== process.getuid() || parent.mode & 0o077))) deny();
  const exists = fs.existsSync(filename);
  if (exists === bootstrapNew) deny();
  if (exists) {
    const st = fs.lstatSync(filename);
    if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1
      || (process.platform !== "win32"
        && (st.uid !== process.getuid() || st.mode & 0o077))) deny();
  } else {
    const fd = fs.openSync(filename, fs.constants.O_EXCL | fs.constants.O_CREAT
      | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
    fs.closeSync(fd);
  }
}

class Zk1OpaqueCheckpointV2Client {
  #db;
  #trust;
  #coordinator;
  #queue = Promise.resolve();
  constructor({ journalPath, bootstrapNew, trustedScope, expectedV1Digest,
    expectedV1Checkpoint, v1CasClient, v1FloorClient, casClient, floorClient,
    checkpointPublicKey, ownerPublicKey, catalogPublicKey, ownerTrust }) {
    const scope = scopeOf(trustedScope);
    const digest = bytes(expectedV1Digest, 32);
    const checkpoint = bytes(expectedV1Checkpoint, 32);
    if (equal(digest, ZERO) || equal(checkpoint, ZERO)
      || !casClient || !floorClient) deny();
    const cas = key(casClient.publicKey), floor = key(floorClient.publicKey);
    const checkpointKey = key(checkpointPublicKey);
    const ownerKey = key(ownerPublicKey);
    const catalogKey = key(catalogPublicKey);
    const fingerprints = [cas, floor, checkpointKey, ownerKey, catalogKey].map(fp);
    // The owner-approved device may also sign the catalog header.
    if (new Set(fingerprints.slice(0, 4).map((b) => b.toString("hex"))).size !== 4
      || fingerprints.slice(0, 3).some((b) => equal(b, fingerprints[4]))
      || !ownerTrust?.pinnedWitness || !ownerTrust?.minimumHead
      || typeof ownerTrust?.freshWitnessHead !== "function") deny();
    const coordinator = createOpaqueCheckpointV2Coordinator({
      casClient, floorClient, trustedScope: scope,
      expectedV1Digest: digest, expectedV1Checkpoint: checkpoint,
      v1CasClient, v1FloorClient,
    });
    privateFile(journalPath, bootstrapNew);
    const identity = Buffer.from(encodeIdentity(scope, digest, checkpoint, fingerprints));
    const db = new Database(journalPath, { fileMustExist: true, timeout: 3000 });
    try {
      if (!bootstrapNew) {
        if (db.pragma("quick_check", { simple: true }) !== "ok"
          || !db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='intent'").get()
          || !db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='identity'").get()
          || !db.prepare("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='intent_immutable_update'").get()
          || !db.prepare("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='intent_immutable_delete'").get()) deny();
        const pinned = db.prepare("SELECT pins FROM identity WHERE id=1").get();
        if (!pinned || !equal(pinned.pins, identity)) deny();
      }
      db.pragma("journal_mode=WAL");
      db.pragma("synchronous=FULL");
      if (bootstrapNew) {
        db.exec(`CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), pins BLOB NOT NULL);
          CREATE TABLE intent (id INTEGER PRIMARY KEY CHECK(id=1), bytes BLOB NOT NULL);
          CREATE TRIGGER intent_immutable_update BEFORE UPDATE ON intent
            BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
          CREATE TRIGGER intent_immutable_delete BEFORE DELETE ON intent
            BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
        db.prepare("INSERT INTO identity VALUES(1,?)").run(identity);
      }
    } catch (error) { db.close(); throw error; }
    this.#db = db;
    this.#coordinator = coordinator;
    this.#trust = { scope, digest, checkpoint, casFp: fingerprints[0],
      floorFp: fingerprints[1], checkpointFp: fingerprints[2],
      checkpointKey, ownerKey, catalogKey, ownerTrust };
  }
  #serial(fn) {
    const result = this.#queue.then(fn);
    this.#queue = result.catch(() => {});
    return result;
  }
  #saved() {
    const row = this.#db.prepare("SELECT bytes FROM intent WHERE id=1").get();
    return row ? Buffer.from(row.bytes) : null;
  }
  async #inspect(raw, freshOwner) {
    const t = this.#trust;
    const inspected = await inspectIntent(raw, {
      scope: t.scope, baseDigest: t.digest, baseCheckpoint: t.checkpoint,
      casFp: t.casFp, floorFp: t.floorFp, checkpointFp: t.checkpointFp,
      checkpointKey: t.checkpointKey, ownerKey: t.ownerKey,
      ownerTrust: t.ownerTrust, cachedSigner: t.catalogKey,
    }, { freshOwner });
    // Historical reads cannot demand a fresh witness from a device that was
    // revoked AFTER publication. Preserve the signed owner approval binding.
    const approval = await z.decodeDeterministic(inspected.body.owner_approval);
    if (approval.type !== "rootark-opaque-checkpoint-remote-owner-approval/v2"
      || SCOPE.some((name) => !equal(bytes(approval[name], t.scope[name].length), t.scope[name]))
      || !Number.isSafeInteger(approval.issued_at)
      || approval.issued_at < 0
      || !crypto.verify(null, Buffer.concat([APPROVAL_DOMAIN,
      Buffer.from(inspected.body.owner_approval)]), t.ownerKey,
      bytes(inspected.body.owner_signature, 64))
      || !equal(bytes(approval.operation_id, 32), inspected.operationId)
      || !equal(bytes(approval.checkpoint_digest, 32), inspected.checkpointDigest)
      || !equal(bytes(approval.final_digest, 32), inspected.finalDigest)
      || !equal(bytes(approval.cas_signer_fp, 32), t.casFp)
      || !equal(bytes(approval.floor_signer_fp, 32), t.floorFp)
      || !equal(bytes(approval.checkpoint_signer_fp, 32), t.checkpointFp)
      || !equal(bytes(approval.previous_digest, 32), t.digest)
      || !equal(bytes(approval.previous_checkpoint_digest, 32), t.checkpoint)
      || approval.previous_sequence !== 128 || approval.final_sequence !== 129) deny();
    return inspected;
  }
  async #read() {
    const raw = this.#saved();
    if (!raw) deny();
    const checked = await this.#inspect(raw, false);
    const state = await this.#coordinator.readConsistent(raw);
    if (state.sequence !== 129
      || !equal(bytes(state.checkpointDigest, 32), checked.checkpointDigest)) deny();
    const record = checked.body.records[0];
    const head = await z.decodeDeterministic(record.header);
    const pages = [];
    for (const p of record.page_bodies) pages.push(await z.decodeDeterministic(p));
    return Object.freeze({ sequence: 129, digest: checked.finalDigest,
      checkpointDigest: checked.checkpointDigest, head,
      pages, state: "V2_BOTH_FINALIZED", remoteCloudDurabilityProven: false });
  }
  async publish({ record, checkpointPrivateKey, ownerPrivateKey,
    ownerEvidence, operationId = crypto.randomBytes(32),
    issuedAt = Math.floor(Date.now() / 1000), ownerIssuedAt = issuedAt }) {
    return this.#serial(async () => {
      const t = this.#trust;
      if (this.#saved()) deny(); // recovery must reuse the exact durable intent
      if (!equal(fp(crypto.createPublicKey(key(checkpointPrivateKey, "private"))),
        t.checkpointFp) || !equal(fp(crypto.createPublicKey(key(ownerPrivateKey, "private"))),
        fp(t.ownerKey))) deny();
      const archived = await archive.createAuthenticatedOpaqueCatalogArchiveV2({
        scope: t.scope, records: [record], previousSequence: 128,
        previousDigest: t.digest, previousCheckpointDigest: t.checkpoint,
        resolveCatalogSigner: async () => t.catalogKey,
        checkpointPrivateKey, issuedAt,
      });
      if (archived.records[0].sequence !== 129) deny();
      const approval = await signCheckpointOwnerApprovalV2({
        type: "rootark-opaque-checkpoint-remote-owner-approval/v2",
        ...t.scope, operation_id: bytes(operationId, 32),
        checkpoint_digest: archived.checkpointDigest, previous_sequence: 128,
        previous_digest: t.digest, previous_checkpoint_digest: t.checkpoint,
        final_sequence: 129,
        final_digest: crypto.createHash("sha256")
          .update(Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0"))
          .update(archived.records[0].header).update(archived.records[0].signature).digest(),
        cas_signer_fp: t.casFp, floor_signer_fp: t.floorFp,
        checkpoint_signer_fp: t.checkpointFp, issued_at: ownerIssuedAt,
      }, ownerPrivateKey);
      const raw = Buffer.from(await z.encodeDeterministic({
        type: "rootark-opaque-checkpoint-remote-intent/v2", ...t.scope,
        operation_id: bytes(operationId, 32), checkpoint_bytes: archived.checkpointBytes,
        checkpoint_signature: archived.checkpointSignature, records: archived.records,
        previous_sequence: 128, previous_digest: t.digest,
        previous_checkpoint_digest: t.checkpoint,
        owner_approval: approval.raw, owner_signature: approval.signature,
        owner_evidence: Buffer.from(ownerEvidence),
      }));
      await this.#inspect(raw, true);
      this.#db.prepare("INSERT INTO intent(id,bytes) VALUES(1,?)").run(raw);
      await this.#coordinator.publish(raw);
      return this.#read();
    });
  }
  publishSignedIntent(signedIntent) {
    return this.#serial(async () => {
      const raw = Buffer.from(signedIntent);
      await this.#inspect(raw, true);
      const saved = this.#saved();
      if (saved && !equal(saved, raw)) deny();
      if (!saved) this.#db.prepare("INSERT INTO intent(id,bytes) VALUES(1,?)").run(raw);
      await this.#coordinator.publish(raw);
      return this.#read();
    });
  }
  recover() {
    return this.#serial(async () => {
      const raw = this.#saved();
      if (!raw) deny();
      await this.#inspect(raw, false);
      await this.#coordinator.reconcile(raw);
      return this.#read();
    });
  }
  read() { return this.#serial(() => this.#read()); }
  close() { if (this.#db.open) this.#db.close(); }
}
function encodeIdentity(scope, digest, checkpoint, fingerprints) {
  return Buffer.concat([...SCOPE.map((name) => scope[name]), digest, checkpoint,
    ...fingerprints]);
}

module.exports = { Zk1OpaqueCheckpointV2Client };
