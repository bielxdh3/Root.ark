"use strict";

// Witness-owned, independent-of-CAS signed journal high-water store.
// Must run with separate storage and signing-key custody from the CAS host.
// A local SQLite file co-located with CAS offers NO independent rollback proof.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile } = require("./zk1PrivateSqlitePath");
const { Worker } = require("node:worker_threads");
const Database = require("better-sqlite3");

const RECORD_DOMAIN = Buffer.from("Root.ark/zk-1/cas-terminal-anchor/v1\0", "ascii");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk-1/witness-cas-anchor-floor/v1\0", "ascii");
const RECORD_FIELDS = ["sequence", "reservation", "scope", "status", "ticketHash",
  "manifestHash", "terminalSeal", "previousHash", "signature"];
const RECORD_PAYLOAD = RECORD_FIELDS.slice(0, -1);
const ZERO = "0".repeat(64);
function fail() {
  const e = new Error("WITNESS_CAS_FLOOR_DENIED");
  e.code = e.message;
  throw e;
}
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) fail();
  const result = Object.create(null);
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !Object.hasOwn(d, "value")) fail();
    result[key] = d.value;
  }
  return result;
}
function digest(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function rowEvidence(row) {
  // Frame all SQL columns and their types, including historical rows. A single
  // streaming SHA-256 avoids 100k separate hash allocations at the history cap.
  // Newline disambiguates the end of each canonical JSON array.
  return JSON.stringify([row.sequence, row.line, row.hash, row.predecessor]) + "\n";
}
function id(value) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength !== 16) fail();
  return Buffer.from(value);
}
function validHex(value) { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
function spki(publicKey) { return publicKey.export({ type: "spki", format: "der" }); }
function parseRecord(line, pinned) {
  if (typeof line !== "string" || line.length < 100 || line.length > 2048
    || line.includes("\n") || line.includes("\r")) fail();
  let parsed;
  try { parsed = JSON.parse(line); }
  catch (_) { fail(); }
  const record = exact(parsed, RECORD_FIELDS);
  if (JSON.stringify(record) !== line || !Number.isSafeInteger(record.sequence)
    || record.sequence < 1 || record.sequence > 100000
    || typeof record.reservation !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(record.reservation)
    || typeof record.scope !== "string" || !/^[a-f0-9:]{40,400}$/.test(record.scope)
    || !["committed", "not-committed-final"].includes(record.status)
    || !validHex(record.ticketHash)
    || (record.manifestHash !== null && !validHex(record.manifestHash))
    || (record.status === "committed") !== (record.manifestHash !== null)
    || typeof record.terminalSeal !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(record.terminalSeal)
    || !validHex(record.previousHash)
    || typeof record.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(record.signature)) fail();
  const signature = Buffer.from(record.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== record.signature
    || !crypto.verify(null, Buffer.concat([RECORD_DOMAIN, Buffer.from(JSON.stringify(
      Object.fromEntries(RECORD_PAYLOAD.map((field) => [field, record[field]]))))]),
    pinned, signature)) fail();
  return { sequence: record.sequence, previousHash: record.previousHash,
    lastHash: digest(line), line };
}
function verifyFreshWitnessCasFloor({ signed, nonce, pinnedWitnessPublicKey,
  pinnedWitnessKeyId, pinnedStatusKeyId, minimumHead } = {}) {
  const fields = ["type", "witnessKeyId", "statusKeyId", "sequence",
    "lastHash", "nonce", "signature"];
  const value = exact(signed, fields);
  if (!(pinnedWitnessPublicKey instanceof crypto.KeyObject)
    || pinnedWitnessPublicKey.type !== "public"
    || pinnedWitnessPublicKey.asymmetricKeyType !== "ed25519"
    || value.type !== "rootark-zk1-witness-cas-anchor-floor/v1"
    || value.witnessKeyId !== id(pinnedWitnessKeyId).toString("base64url")
    || value.statusKeyId !== id(pinnedStatusKeyId).toString("base64url")
    || (!Buffer.isBuffer(nonce) && !(nonce instanceof Uint8Array))
    || nonce.byteLength !== 32
    || value.nonce !== Buffer.from(nonce).toString("base64url")
    || !Number.isSafeInteger(value.sequence) || value.sequence < 0
    || value.sequence > 100000 || !validHex(value.lastHash)
    || (value.sequence === 0 && value.lastHash !== ZERO)
    || typeof value.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(value.signature)) fail();
  const signature = Buffer.from(value.signature, "base64url");
  const unsigned = Object.fromEntries(fields.slice(0, -1).map((key) => [key, value[key]]));
  if (signature.byteLength !== 64 || signature.toString("base64url") !== value.signature
    || !crypto.verify(null, Buffer.concat([FLOOR_DOMAIN,
      Buffer.from(JSON.stringify(unsigned))]), pinnedWitnessPublicKey, signature)) fail();
  if (minimumHead !== undefined) {
    const minimum = exact(minimumHead, ["sequence", "lastHash"]);
    if (!Number.isSafeInteger(minimum.sequence) || minimum.sequence < 0
      || !validHex(minimum.lastHash) || value.sequence < minimum.sequence
      || (value.sequence === minimum.sequence && value.lastHash !== minimum.lastHash)) fail();
  }
  return Object.freeze({ sequence: value.sequence, lastHash: value.lastHash });
}
class Zk1WitnessCasAnchorFloor {
  #db;
  #status;
  #witness;
  #witnessId;
  #statusId;
  #identity;
  #trustedFloor = { sequence: 0, lastHash: ZERO };
  #verifiedChain = crypto.createHash("sha256");
  #verifiedChainDigest = digest("");
  #externalMinimum;
  #filename;
  #fileIdentity;
  #closed = false;
  #activeHeadVerifications = 0;
  #generation = 0;
  constructor(filename, { bootstrapNew = false, witnessKeyId, witnessPrivateKey,
    statusKeyId, statusPublicKey, trustedMinimumHead } = {}) {
    if (trustedMinimumHead !== undefined) {
      const floor = exact(trustedMinimumHead, ["sequence", "lastHash"]);
      if (!Number.isSafeInteger(floor.sequence) || floor.sequence < 0
        || floor.sequence > 100000 || !validHex(floor.lastHash)
        || (floor.sequence === 0 && floor.lastHash !== ZERO)) fail();
      // A caller-retained owner floor cannot be mutated after construction.
      this.#externalMinimum = Object.freeze({ sequence: floor.sequence,
        lastHash: floor.lastHash });
      if (bootstrapNew && floor.sequence !== 0) fail();
    }
    if (typeof filename !== "string" || !path.isAbsolute(filename)
      || !(witnessPrivateKey instanceof crypto.KeyObject)
      || witnessPrivateKey.type !== "private" || witnessPrivateKey.asymmetricKeyType !== "ed25519"
      || !(statusPublicKey instanceof crypto.KeyObject)
      || statusPublicKey.type !== "public" || statusPublicKey.asymmetricKeyType !== "ed25519") fail();
    this.#witnessId = id(witnessKeyId);
    this.#statusId = id(statusKeyId);
    this.#witness = witnessPrivateKey;
    this.#status = statusPublicKey;
    if (this.#witnessId.equals(this.#statusId)
      || spki(crypto.createPublicKey(witnessPrivateKey)).equals(spki(statusPublicKey))) fail();
    const absolute = path.resolve(filename);
    const exists = fs.existsSync(absolute);
    if (exists === bootstrapNew || (exists && !fs.lstatSync(absolute).isFile())) fail();
    try {
      if (exists) assertPrivateSqliteFile(absolute);
      else ensurePrivateSqliteDirectory(absolute);
    } catch (_) { fail(); }
    if (!exists) {
      const fd = fs.openSync(absolute, "wx", 0o600);
      fs.closeSync(fd);
    }
    try { assertPrivateSqliteFile(absolute); } catch (_) { fail(); }
    const db = new Database(absolute, { fileMustExist: true });
    try {
      assertPrivateSqliteFile(absolute);
      this.#filename = absolute;
      this.#fileIdentity = fs.statSync(absolute, { bigint: true });
      db.pragma("journal_mode = WAL");
      db.pragma("synchronous = FULL");
      db.pragma("foreign_keys = ON");
      if (db.pragma("integrity_check", { simple: true }) !== "ok") fail();
      this.#identity = JSON.stringify({
        type: "rootark-zk1-witness-cas-floor/v1",
        witnessKeyId: this.#witnessId.toString("base64url"),
        witnessFingerprint: digest(spki(crypto.createPublicKey(witnessPrivateKey))),
        statusKeyId: this.#statusId.toString("base64url"),
        statusFingerprint: digest(spki(statusPublicKey)),
      });
      if (exists) {
        const row = db.prepare("SELECT identity FROM witness_cas_floor_identity WHERE id=1").get();
        if (!row || row.identity !== this.#identity) fail();
      } else {
        db.exec(`CREATE TABLE witness_cas_floor_identity (
          id INTEGER PRIMARY KEY CHECK(id=1), identity TEXT NOT NULL);
          CREATE TABLE witness_cas_floor_event (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
            line TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
            predecessor TEXT NOT NULL);`);
        db.prepare("INSERT INTO witness_cas_floor_identity VALUES(1,?)").run(this.#identity);
      }
      const state = db.prepare("SELECT sequence,hash FROM witness_cas_floor_event ORDER BY sequence DESC LIMIT 1").get();
      const count = db.prepare("SELECT COUNT(*) AS n FROM witness_cas_floor_event").get().n;
      if (count !== (state?.sequence || 0) || count > 100000) fail();
      if (this.#externalMinimum) {
        if (count < this.#externalMinimum.sequence) fail();
        if (this.#externalMinimum.sequence > 0) {
          const atMinimum = db.prepare("SELECT hash FROM witness_cas_floor_event WHERE sequence=?")
            .get(this.#externalMinimum.sequence);
          if (atMinimum?.hash !== this.#externalMinimum.lastHash) fail();
        }
      }
      // Verify the entire bounded signed history at startup. A DB editor must
      // not be able to replace a record and forge a consistent SQL hash.
      let previous = ZERO;
      const verifiedChain = crypto.createHash("sha256");
      for (const row of db.prepare("SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event ORDER BY sequence" ).iterate()) {
        const event = parseRecord(row.line, this.#status);
        if (event.sequence !== row.sequence || event.previousHash !== previous
          || row.predecessor !== previous || event.lastHash !== row.hash) fail();
        verifiedChain.update(rowEvidence(row));
        previous = event.lastHash;
      }
      this.#verifiedChain = verifiedChain;
      this.#verifiedChainDigest = verifiedChain.copy().digest("hex");
      this.#trustedFloor = Object.freeze({ sequence: state?.sequence || 0,
        lastHash: state?.hash || ZERO });
      this.#db = db;
    } catch (error) { db.close(); fail(); }
  }
  #quickHeadCheck() {
    return this.#db.transaction(() => {
      const identity = this.#db.prepare(
        "SELECT identity FROM witness_cas_floor_identity WHERE id=1").get();
      const row = this.#db.prepare("SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event"
        + " ORDER BY sequence DESC LIMIT 1").get();
      const count = this.#db.prepare("SELECT COUNT(*) AS n FROM witness_cas_floor_event").get().n;
      const trusted = this.#trustedFloor;
      if (!identity || identity.identity !== this.#identity || count > 100000
        || count !== trusted.sequence || count !== (row?.sequence || 0)
        || (row?.hash || ZERO) !== trusted.lastHash
        || (this.#externalMinimum && (count < this.#externalMinimum.sequence
          || (this.#externalMinimum.sequence > 0
            && this.#db.prepare("SELECT hash FROM witness_cas_floor_event WHERE sequence=?")
              .get(this.#externalMinimum.sequence)?.hash !== this.#externalMinimum.lastHash)))) fail();
      if (row) {
        const signed = parseRecord(row.line, this.#status);
        if (signed.sequence !== row.sequence || signed.lastHash !== row.hash
          || signed.previousHash !== row.predecessor) fail();
      }
      return trusted;
    }).deferred();
  }
  #assertFileIdentity() {
    try { assertPrivateSqliteFile(this.#filename); } catch (_) { fail(); }
    const now = fs.statSync(this.#filename, { bigint: true });
    if (!now.isFile() || now.dev !== this.#fileIdentity.dev
      || now.ino !== this.#fileIdentity.ino) fail();
  }
  #fileMutationStamp() {
    // data_version detects committed SQL changes from another connection.
    // Also detect visible direct file/WAL edits between the worker's snapshot
    // and the signature decision (such writes may bypass SQLite counters).
    const stamp = (filename) => {
      let stat;
      try { stat = fs.lstatSync(filename, { bigint: true }); }
      catch (error) { if (error?.code === "ENOENT") return null; throw error; }
      if (!stat.isFile() || stat.isSymbolicLink()) fail();
      return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs]
        .map((v) => v.toString()).join(":");
    };
    return JSON.stringify([stamp(this.#filename), stamp(this.#filename + "-wal")]);
  }
  #signHead(nonce, value) {
    const unsigned = { type: "rootark-zk1-witness-cas-anchor-floor/v1",
      witnessKeyId: this.#witnessId.toString("base64url"),
      statusKeyId: this.#statusId.toString("base64url"),
      sequence: value.sequence, lastHash: value.lastHash,
      nonce: nonce.toString("base64url") };
    const signature = crypto.sign(null, Buffer.concat([FLOOR_DOMAIN,
      Buffer.from(JSON.stringify(unsigned))]), this.#witness);
    return Object.freeze({ ...unsigned, signature: signature.toString("base64url") });
  }
  // HTTPS-only path. Full SQLite snapshot verification executes off the HTTP
  // thread; the signer private key never enters the worker. Limit concurrent
  // snapshots so hostile clients cannot create an unbounded worker/DB pool.
  async freshHeadAsync({ nonce }) {
    if ((!Buffer.isBuffer(nonce) && !(nonce instanceof Uint8Array))
      || nonce.byteLength !== 32) fail();
    const challenge = Buffer.from(nonce); // pin caller's nonce before any await
    if (this.#closed || this.#activeHeadVerifications >= 2) fail();
    this.#activeHeadVerifications += 1;
    try {
      this.#assertFileIdentity();
      const initialMutationStamp = this.#fileMutationStamp();
      const initialDataVersion = this.#db.pragma("data_version", { simple: true });
      this.#quickHeadCheck();
      const pinned = { sequence: this.#trustedFloor.sequence,
        lastHash: this.#trustedFloor.lastHash,
        chainDigest: this.#verifiedChainDigest, generation: this.#generation };
      const dbInfo = { filename: this.#filename, identity: this.#identity,
        sequence: pinned.sequence, lastHash: pinned.lastHash,
        chainDigest: pinned.chainDigest,
        fileDev: this.#fileIdentity.dev.toString(),
        fileIno: this.#fileIdentity.ino.toString() };
      await new Promise((resolve, reject) => {
        const worker = new Worker(path.join(__dirname, "zk1WitnessCasAnchorHeadVerifierWorker.js"),
          { workerData: dbInfo });
        let verified = false;
        let settled = false;
        const timer = setTimeout(() => { worker.terminate(); finish(false); }, 15000);
        const finish = (ok) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (ok) resolve();
          else reject(new Error("WITNESS_CAS_FLOOR_DENIED"));
        };
        worker.on("message", (result) => { if (result === "VERIFIED") verified = true; else finish(false); });
        worker.once("error", () => finish(false));
        worker.once("exit", (code) => finish(code === 0 && verified));
      });
      // Any CAS append or external SQLite writer during the snapshot invalidates
      // the completed proof. Recheck the authenticated final row before signing.
      if (this.#closed || this.#generation !== pinned.generation
        || this.#verifiedChainDigest !== pinned.chainDigest
        || this.#db.pragma("data_version", { simple: true }) !== initialDataVersion
        || this.#fileMutationStamp() !== initialMutationStamp) fail();
      this.#assertFileIdentity();
      const fresh = this.#quickHeadCheck();
      if (this.#db.pragma("data_version", { simple: true }) !== initialDataVersion
        || this.#fileMutationStamp() !== initialMutationStamp
        || fresh.sequence !== pinned.sequence || fresh.lastHash !== pinned.lastHash) fail();
      return this.#signHead(challenge, fresh);
    } catch (_) { fail(); }
    finally { this.#activeHeadVerifications -= 1; }
  }
  head() {
    try {
      return this.#db.transaction(() => {
      // A hostile SQLite editor may mutate files or rows *after* witness
      // bootstrap. Never sign an unsigned or rewound SQL head. The final
      // signer-verified row and identity are rechecked on EVERY lookup.
      const identity = this.#db.prepare(
        "SELECT identity FROM witness_cas_floor_identity WHERE id=1").get();
      const row = this.#db.prepare(
        "SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event"
          + " ORDER BY sequence DESC LIMIT 1").get();
      const count = this.#db.prepare("SELECT COUNT(*) AS n FROM witness_cas_floor_event").get().n;
      const trusted = this.#trustedFloor;
      if (!identity || identity.identity !== this.#identity
        || count !== (row?.sequence || 0) || count > 100000
        || count !== trusted.sequence
        || (row?.hash || ZERO) !== trusted.lastHash) fail();
      // An attacker with SQL write access can corrupt any *earlier* event and
      // leave the final signed head untouched. Verify the full immutable
      // snapshot before signing a fresh receipt, not only the last SQL row.
      let sequence = 0;
      const liveChain = crypto.createHash("sha256");
      for (const checked of this.#db.prepare(
        "SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event ORDER BY sequence").iterate()) {
        sequence += 1;
        if (checked.sequence !== sequence) fail();
        liveChain.update(rowEvidence(checked));
      }
      if (sequence !== count || liveChain.digest("hex") !== this.#verifiedChainDigest) fail();
      if (this.#externalMinimum && (count < this.#externalMinimum.sequence
        || (this.#externalMinimum.sequence > 0
          && this.#db.prepare("SELECT hash FROM witness_cas_floor_event WHERE sequence=?")
            .get(this.#externalMinimum.sequence)?.hash !== this.#externalMinimum.lastHash))) fail();
      if (row) {
        const signed = parseRecord(row.line, this.#status);
        if (signed.sequence !== row.sequence || signed.lastHash !== row.hash
          || signed.previousHash !== row.predecessor) fail();
      }
      return Object.freeze({ ...trusted });
      }).deferred();
    } catch (_) { fail(); }
  }
  // A signed CAS event is the only admissible means of advancing the floor.
  // A caller may repeat a lost ACK's IDENTICAL signed event, never skip,
  // truncate, fork, or arbitrarily submit an unsigned head number/hash.
  advance({ records }) {
    if (!Array.isArray(records) || records.length < 1 || records.length > 16
      || Reflect.ownKeys(records).length !== records.length + 1) fail();
    const captured = [];
    for (let i = 0; i < records.length; i++) {
      const d = Object.getOwnPropertyDescriptor(records, String(i));
      if (!d || !Object.hasOwn(d, "value")) fail();
      const record = parseRecord(d.value, this.#status);
      if (i > 0 && record.sequence <= captured[i - 1].sequence) fail();
      captured.push(record);
    }
    const priorSequence = this.#trustedFloor.sequence;
    const updated = this.#db.transaction(() => {
      let previous = this.head();
      const existing = this.#db.prepare("SELECT hash,line FROM witness_cas_floor_event WHERE sequence=?");
      const insert = this.#db.prepare("INSERT INTO witness_cas_floor_event VALUES(?,?,?,?)");
      for (const item of captured) {
        if (item.sequence <= previous.sequence) {
          const saved = existing.get(item.sequence);
          if (!saved || saved.hash !== item.lastHash || saved.line !== item.line) fail();
          continue;
        }
        if (item.sequence !== previous.sequence + 1
          || item.previousHash !== previous.lastHash) fail();
        insert.run(item.sequence, item.line, item.lastHash, item.previousHash);
        previous = { sequence: item.sequence, lastHash: item.lastHash };
      }
      return Object.freeze({ ...previous });
    }).immediate();
    for (const item of captured) {
      if (item.sequence > priorSequence) this.#verifiedChain.update(
        rowEvidence({ sequence: item.sequence, line: item.line,
          hash: item.lastHash, predecessor: item.previousHash }));
    }
    this.#verifiedChainDigest = this.#verifiedChain.copy().digest("hex");
    this.#trustedFloor = Object.freeze({ ...updated });
    this.#generation += 1;
    return updated;
  }
  freshHead({ nonce }) {
    if ((!Buffer.isBuffer(nonce) && !(nonce instanceof Uint8Array))
      || nonce.byteLength !== 32) fail();
    const value = this.head();
    return this.#signHead(Buffer.from(nonce), value);
  }
  close() { this.#closed = true; if (this.#db.open) this.#db.close(); }
}
module.exports = { Zk1WitnessCasAnchorFloor, verifyFreshWitnessCasFloor };
