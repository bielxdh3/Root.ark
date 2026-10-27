"use strict";

// Durable *single-host* signed terminal continuity journal, stored OUTSIDE the
// CAS database file and its database-writer authority. It closes the threat
// where SQL rows alone are rewound/rewritten without the status signer key.
// A privileged host operator restoring BOTH files can still rollback; real
// cross-host anti-rollback requires an independently operated anchor/floor.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ensurePrivateSqliteDirectory } = require("./zk1PrivateSqlitePath");
const { verifyWindowsChunkUploadTree } = require("../../services/chunkUploadWindowsAcl");

const DOMAIN = Buffer.from("Root.ark/zk-1/cas-terminal-anchor/v1\0", "ascii");
const INTENT_DOMAIN = Buffer.from("Root.ark/zk-1/cas-terminal-intent/v1\0", "ascii");
const WITNESS_POLICY_DOMAIN = Buffer.from("Root.ark/zk-1/cas-witness-required/v1\0", "ascii");
const MAX_BYTES = 64 * 1024 * 1024;
function fail() {
  const error = new Error("CAS_ANCHOR_INVALID");
  error.code = "CAS_ANCHOR_INVALID";
  throw error;
}
// O_NOFOLLOW protects only the last pathname component. On both Unix and
// Windows, an ancestor may instead be a symlink/junction to the SAME inode;
// the journal's existing FD identity checks alone cannot detect that escape.
// Anchor directories must be private to this service's OS principal. A
// privileged actor able to rename trusted ancestors still needs an external
// owner/witness floor for rollback protection.
function assertPrivateDirectory(filename) {
  let current = path.dirname(filename);
  const containingDirectory = current;
  try {
    while (true) {
      const stat = fs.lstatSync(current, { bigint: true });
      if (!stat.isDirectory() || stat.isSymbolicLink()) fail();
      if (process.platform !== "win32") {
        const owner = BigInt(process.getuid());
        const writableByOthers = (stat.mode & 0o022n) !== 0n;
        const sticky = (stat.mode & 0o1000n) !== 0n;
        if ((current === containingDirectory && (stat.uid !== owner || writableByOthers))
          || (current !== containingDirectory && writableByOthers
            && !(sticky && (stat.uid === 0n || stat.uid === owner)))) fail();
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  } catch (_) { fail(); }
}
function assertWindowsPrivateAnchorDirectory(filename) {
  if (process.platform !== "win32") return;
  try {
    // A valid signed prefix is still replaceable by a local principal with
    // Modify/DELETE_CHILD. Validate the native owner and DACL of the whole
    // anchor directory, including sidecar intents and every ancestor.
    verifyWindowsChunkUploadTree(path.dirname(filename));
  } catch (_) { fail(); }
}
function assertPrivateFile(stat) {
  if (process.platform !== "win32"
    && (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n) !== 0n)) fail();
}
function strict(obj, fields) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)
    || Object.keys(obj).length !== fields.length
    || fields.some((k) => !Object.hasOwn(obj, k))
    || Object.keys(obj).some((k) => !fields.includes(k))) fail();
}
const FIELDS = Object.freeze([
  "sequence", "reservation", "scope", "status", "ticketHash", "manifestHash",
  "terminalSeal", "previousHash", "signature",
]);
const PAYLOAD = FIELDS.filter((field) => field !== "signature");
const INTENT_FIELDS = Object.freeze([
  "type", "keyId", "reservation", "scope", "status", "ticketHash", "manifestHash", "signature",
]);
function base64(value) { return Buffer.from(value).toString("base64url"); }
function digest(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function scopeKey(query) {
  return query.account_id.toString("hex") + ":" + query.compartment_id.byteLength + ":"
    + query.compartment_id.toString("hex") + ":" + query.keyring_id.toString("hex");
}
function signatureInput(record) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(Object.fromEntries(
    PAYLOAD.map((field) => [field, record[field]]))))]);
}
class Zk1CasTerminalAnchor {
  #trustedMinimumHead;
  #verifiedSnapshot = null;
  #verifiedFileIdentity = null;
  constructor(filename, { bootstrapNew, statusKeyId, statusPrivateKey,
    trustedMinimumHead, witnessRequired = false, witnessKeyId,
    normativePhysicalAdmissionRequired = false } = {}) {
    if (typeof filename !== "string" || !path.isAbsolute(filename)
      || !(statusPrivateKey instanceof crypto.KeyObject)
      || statusPrivateKey.asymmetricKeyType !== "ed25519" || statusPrivateKey.type !== "private"
      || !Buffer.isBuffer(statusKeyId) || statusKeyId.length !== 16
      || typeof witnessRequired !== "boolean"
      || typeof normativePhysicalAdmissionRequired !== "boolean"
      || (normativePhysicalAdmissionRequired && !witnessRequired)
      || (witnessRequired && (!Buffer.isBuffer(witnessKeyId)
        || witnessKeyId.length !== 16 || witnessKeyId.equals(statusKeyId)))) fail();
    this.filename = filename;
    this.privateKey = statusPrivateKey;
    this.publicKey = crypto.createPublicKey(statusPrivateKey);
    this.identity = { type: "rootark-zk1-cas-anchor/v1", keyId: base64(statusKeyId),
      fingerprint: digest(this.publicKey.export({ type: "spki", format: "der" })) };
    if (witnessRequired) {
      // Persist an Ed25519-signed enrollment in the *independent signed CAS
      // anchor file*, not the CAS-writable SQLite identity table. A SQL-only
      // attacker cannot erase mandatory witness protection by flipping a bit
      // and then starting the legacy standalone service with missing config.
      const policy = { ...this.identity, witnessRequired: true,
        witnessKeyId: base64(witnessKeyId),
        ...(normativePhysicalAdmissionRequired ? {
          normativePhysicalAdmissionRequired: true,
        } : {}) };
      this.identity = { ...policy, policySignature: base64(crypto.sign(null,
        Buffer.concat([WITNESS_POLICY_DOMAIN, Buffer.from(JSON.stringify(policy))]),
        statusPrivateKey)) };
    }
    this.records = new Map();
    this.anchoredScopes = new Set();
    this.sequence = 0;
    this.previousHash = "0".repeat(64);
    // This floor MUST be provisioned from an independently retained owner /
    // witness checkpoint, never copied from the same mutable anchor file on
    // the next startup. A signed old history is still a rollback without it.
    // Keep the bytes in a private slot: caller mutations cannot lower it.
    if (trustedMinimumHead !== undefined) {
      if (!trustedMinimumHead || typeof trustedMinimumHead !== "object"
        || Array.isArray(trustedMinimumHead)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(trustedMinimumHead))
        || Reflect.ownKeys(trustedMinimumHead).length !== 2) fail();
      const seq = Object.getOwnPropertyDescriptor(trustedMinimumHead, "sequence");
      const hash = Object.getOwnPropertyDescriptor(trustedMinimumHead, "lastHash");
      if (!seq || !Object.hasOwn(seq, "value") || !hash
        || !Object.hasOwn(hash, "value")
        || !Number.isSafeInteger(seq.value) || seq.value < 0
        || typeof hash.value !== "string" || !/^[0-9a-f]{64}$/.test(hash.value)
        || (seq.value === 0 && hash.value !== "0".repeat(64))) fail();
      this.#trustedMinimumHead = Object.freeze({
        sequence: seq.value, lastHash: hash.value,
      });
    }
    const existed = fs.existsSync(filename);
    // An explicit bootstrap may create only a NEW anchor. Accepting an
    // existing validly signed file would silently adopt an old or transplanted
    // terminal history under a fresh authority instead of failing closed.
    if (existed && bootstrapNew === true) fail();
    if (!existed) {
      // A nonempty independently pinned floor means THIS IS A RESTART, not
      // a bootstrap. Refuse before creating even a genesis anchor file.
      if (this.#trustedMinimumHead !== undefined
        && this.#trustedMinimumHead.sequence !== 0) fail();
      if (bootstrapNew !== true) fail();
      // Do not create an implicit new anchor at an unexpected path on restart.
      if (process.platform === "win32") {
        try { ensurePrivateSqliteDirectory(filename); } catch (_) { fail(); }
      } else {
        fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
      }
      assertPrivateDirectory(filename);
      assertWindowsPrivateAnchorDirectory(filename);
      const fd = fs.openSync(filename, "wx", 0o600);
      try {
        fs.writeSync(fd, JSON.stringify(this.identity) + "\n");
        fs.fsyncSync(fd);
      } finally { fs.closeSync(fd); }
      assertPrivateDirectory(filename);
    }
    this.reload(true);
  }

  reload(force = false) {
    let raw;
    let stat;
    try {
      assertWindowsPrivateAnchorDirectory(this.filename);
      assertPrivateDirectory(this.filename);
      const namedBefore = fs.lstatSync(this.filename, { bigint: true });
      if (!namedBefore.isFile() || namedBefore.isSymbolicLink()
        || namedBefore.nlink !== 1n || namedBefore.size > BigInt(MAX_BYTES)) fail();
      assertPrivateFile(namedBefore);
      const fd = fs.openSync(this.filename,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
        | (fs.constants.O_CLOEXEC || 0));
      try {
        const before = fs.fstatSync(fd, { bigint: true });
        if (!before.isFile() || before.nlink !== 1n
          || before.dev !== namedBefore.dev || before.ino !== namedBefore.ino
          || before.size !== namedBefore.size || before.mtimeNs !== namedBefore.mtimeNs
          || before.ctimeNs !== namedBefore.ctimeNs) fail();
        assertPrivateFile(before);
        // Never accept a cached signature on the strength of size/mtime.
        // Keep the pinned descriptor and bounded initial size: a concurrent
        // writer can grow its inode before an unbounded readFileSync(fd)
        // allocates memory, even when the postread check ultimately denies.
        raw = Buffer.alloc(Number(before.size));
        let offset = 0;
        while (offset < raw.length) {
          const count = fs.readSync(fd, raw, offset,
            Math.min(64 * 1024, raw.length - offset), offset);
          if (count <= 0 || count > raw.length - offset) fail();
          offset += count;
        }
        const after = fs.fstatSync(fd, { bigint: true });
        const namedAfter = fs.lstatSync(this.filename, { bigint: true });
        assertPrivateDirectory(this.filename);
        if (raw.length !== Number(before.size)
          || !namedAfter.isFile() || namedAfter.isSymbolicLink()
          || namedAfter.nlink !== 1n || after.nlink !== 1n
          || after.dev !== before.dev || after.ino !== before.ino
          || after.size !== before.size || after.mtimeNs !== before.mtimeNs
          || after.ctimeNs !== before.ctimeNs
          || namedAfter.dev !== before.dev || namedAfter.ino !== before.ino
          || namedAfter.size !== before.size || namedAfter.mtimeNs !== before.mtimeNs
          || namedAfter.ctimeNs !== before.ctimeNs) fail();
        assertPrivateFile(namedAfter);
        stat = { size: raw.length, mtimeMs: Number(after.mtimeMs) };
        this.#verifiedFileIdentity = { dev: before.dev, ino: before.ino,
          size: before.size };
      } finally { fs.closeSync(fd); }
    } catch (_) { fail(); }
    const currentDigest = crypto.createHash("sha256").update(raw).digest();
    if (this.#verifiedSnapshot && crypto.timingSafeEqual(
      currentDigest, this.#verifiedSnapshot.digest)) {
      // Re-parse only if the CONTENT changed. The exact prior bytes were
      // authenticated under the same pinned Ed25519 signer/floor. Rehydrate
      // private immutable verified records so public map/head mutations
      // cannot create a bypass or need a fresh O(n) Ed25519 scan per GET.
      const cached = this.#verifiedSnapshot;
      this.records = new Map(cached.records);
      this.anchoredScopes = new Set(cached.anchoredScopes);
      this.sequence = cached.sequence;
      this.previousHash = cached.previousHash;
      this.lastSize = stat.size;
      this.lastModified = stat.mtimeMs;
      return;
    }
    this.#verifiedSnapshot = null;
    this.records = new Map();
    this.anchoredScopes = new Set();
    this.sequence = 0;
    this.previousHash = "0".repeat(64);
    if (!raw.length || raw.length > MAX_BYTES || raw.at(-1) !== 10) fail();
    const lines = raw.toString("utf8").split("\n");
    lines.pop();
    let identity;
    try { identity = JSON.parse(lines.shift()); }
    catch (_) { fail(); }
    strict(identity, Object.keys(this.identity));
    if (JSON.stringify(identity) !== JSON.stringify(this.identity)) fail();
    for (const line of lines) {
      let item;
      try { item = JSON.parse(line); }
      catch (_) { fail(); }
      this.verify(item);
      if (JSON.stringify(item) !== line) fail();
      this.records.set(item.reservation, Object.freeze(item));
      this.anchoredScopes.add(item.scope);
      this.sequence = item.sequence;
      this.previousHash = digest(line);
      if (this.#trustedMinimumHead?.sequence === item.sequence
        && this.previousHash !== this.#trustedMinimumHead.lastHash) fail();
    }
    if (this.#trustedMinimumHead
      && (this.sequence < this.#trustedMinimumHead.sequence
        || (this.#trustedMinimumHead.sequence === 0
          && this.#trustedMinimumHead.lastHash !== "0".repeat(64)))) fail();
    this.lastSize = stat.size;
    this.lastModified = stat.mtimeMs;
    this.#verifiedSnapshot = {
      digest: currentDigest,
      records: new Map(this.records), anchoredScopes: new Set(this.anchoredScopes),
      sequence: this.sequence, previousHash: this.previousHash,
    };
  }

  headCheckpoint() {
    // This returns a candidate for the caller to pin OUTSIDE this file and
    // outside this host/operator. It is not an independent anchor by itself.
    this.reload(true);
    return Object.freeze({ sequence: this.sequence, lastHash: this.previousHash });
  }

  signedRecordPage({ afterSequence, limit = 16 } = {}) {
    if (!Number.isSafeInteger(afterSequence) || afterSequence < 0
      || !Number.isSafeInteger(limit) || limit < 1 || limit > 16) fail();
    this.reload(true);
    if (afterSequence > this.sequence) fail();
    // Internal records are parsed, signed, canonical JSON objects in strictly
    // ascending sequence order. Never ship raw caller-supplied operation data.
    return Object.freeze([...this.records.values()]
      .filter((entry) => entry.sequence > afterSequence)
      .slice(0, limit)
      .map((entry) => JSON.stringify(entry)));
  }

  verify(item) {
    strict(item, FIELDS);
    if (!Number.isSafeInteger(item.sequence) || item.sequence !== this.sequence + 1
      || typeof item.reservation !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(item.reservation)
      || typeof item.scope !== "string" || !/^[a-f0-9:]{40,400}$/.test(item.scope)
      || !["committed", "not-committed-final"].includes(item.status)
      || typeof item.ticketHash !== "string" || !/^[0-9a-f]{64}$/.test(item.ticketHash)
      || item.manifestHash !== null && (typeof item.manifestHash !== "string" || !/^[0-9a-f]{64}$/.test(item.manifestHash))
      || (item.status === "committed") !== (item.manifestHash !== null)
      || typeof item.terminalSeal !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(item.terminalSeal)
      || item.previousHash !== this.previousHash || this.records.has(item.reservation)
      || typeof item.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(item.signature)) fail();
    const signature = Buffer.from(item.signature, "base64url");
    if (signature.length !== 64 || base64(signature) !== item.signature
      || !crypto.verify(null, signatureInput(item), this.publicKey, signature)) fail();
  }

  get(reservationId) {
    // A trusted read-side floor cannot rely on size + mtime. A malicious
    // writer can change signed bytes and preserve both metadata fields.
    this.reload(true);
    return this.records.get(base64(reservationId)) ?? null;
  }

  hasScope(query) {
    this.reload(true);
    return this.anchoredScopes.has(scopeKey(query));
  }

  scopeEvents(query) {
    // Freshly revalidate the independent signed file, even when its timestamp
    // and length appear unchanged, before using it as a read-side floor.
    this.reload(true);
    const key = scopeKey(query);
    return [...this.records.values()].filter((event) => event.scope === key)
      .map((event) => Object.freeze({ ...event }));
  }

  intentPath(query) { return this.filename + ".intent." + base64(query.reservation_id); }

  intentPayload(query, signedTicket, status, manifestBytes) {
    if (!["committed", "not-committed-final"].includes(status)
      || (status === "committed") !== (manifestBytes !== null)) fail();
    return {
      type: "rootark-zk1-cas-terminal-intent/v1",
      keyId: this.identity.keyId,
      reservation: base64(query.reservation_id),
      scope: scopeKey(query), status,
      ticketHash: digest(signedTicket),
      manifestHash: manifestBytes === null ? null : digest(manifestBytes),
    };
  }

  getIntent(query) {
    const pathname = this.intentPath(query);
    let fd;
    let bytes;
    try {
      assertWindowsPrivateAnchorDirectory(pathname);
      assertPrivateDirectory(pathname);
      let namedBefore;
      try { namedBefore = fs.lstatSync(pathname, { bigint: true }); }
      catch (error) { if (error?.code === "ENOENT") return null; throw error; }
      // An on-disk intent is not yet trusted: do not follow a redirected name,
      // load a foreign hardlink, or read an unbounded file/FIFO into memory.
      if (!namedBefore.isFile() || namedBefore.isSymbolicLink()
        || namedBefore.nlink !== 1n || namedBefore.size < 1n
        || namedBefore.size > 4096n) fail();
      assertPrivateFile(namedBefore);
      fd = fs.openSync(pathname, fs.constants.O_RDONLY
        | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0));
      const opened = fs.fstatSync(fd, { bigint: true });
      if (!opened.isFile() || opened.nlink !== 1n
        || opened.dev !== namedBefore.dev || opened.ino !== namedBefore.ino
        || opened.size !== namedBefore.size
        || opened.mtimeNs !== namedBefore.mtimeNs
        || opened.ctimeNs !== namedBefore.ctimeNs) fail();
      assertPrivateFile(opened);
      bytes = Buffer.alloc(Number(opened.size));
      let offset = 0;
      while (offset < bytes.length) {
        const count = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
        if (count <= 0) fail();
        offset += count;
      }
      if (fs.readSync(fd, Buffer.alloc(1), 0, 1, null) !== 0) fail();
      const after = fs.fstatSync(fd, { bigint: true });
      const namedAfter = fs.lstatSync(pathname, { bigint: true });
      assertPrivateDirectory(pathname);
      if (!namedAfter.isFile() || namedAfter.isSymbolicLink()
        || namedAfter.nlink !== 1n || after.nlink !== 1n
        || after.dev !== opened.dev || after.ino !== opened.ino
        || after.size !== opened.size || after.mtimeNs !== opened.mtimeNs
        || after.ctimeNs !== opened.ctimeNs
        || namedAfter.dev !== opened.dev || namedAfter.ino !== opened.ino
        || namedAfter.size !== opened.size || namedAfter.mtimeNs !== opened.mtimeNs
        || namedAfter.ctimeNs !== opened.ctimeNs) fail();
      assertPrivateFile(after);
      assertPrivateFile(namedAfter);
    } catch (_) { fail(); }
    finally { if (fd !== undefined) fs.closeSync(fd); }
    if (bytes.at(-1) !== 10) fail();
    let intent;
    try { intent = JSON.parse(bytes.toString("utf8")); }
    catch (_) { fail(); }
    strict(intent, INTENT_FIELDS);
    const { signature, ...body } = intent;
    if (typeof signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(signature)
      || JSON.stringify(intent) + "\n" !== bytes.toString("utf8")
      || intent.type !== "rootark-zk1-cas-terminal-intent/v1"
      || intent.keyId !== this.identity.keyId || intent.reservation !== base64(query.reservation_id)
      || intent.scope !== scopeKey(query)
      || !["committed", "not-committed-final"].includes(intent.status)) fail();
    const signatureBytes = Buffer.from(signature, "base64url");
    if (signatureBytes.length !== 64 || base64(signatureBytes) !== signature
      || !crypto.verify(null, Buffer.concat([INTENT_DOMAIN, Buffer.from(JSON.stringify(body))]),
        this.publicKey, signatureBytes)) fail();
    return intent;
  }

  assertIntent(query, signedTicket, status, manifestBytes) {
    const existing = this.getIntent(query);
    const expected = this.intentPayload(query, signedTicket, status, manifestBytes);
    if (!existing || Object.entries(expected).some(([field, value]) => existing[field] !== value)) fail();
    return true;
  }

  prepare(query, signedTicket, status, manifestBytes) {
    assertWindowsPrivateAnchorDirectory(this.filename);
    assertPrivateDirectory(this.filename);
    const payload = this.intentPayload(query, signedTicket, status, manifestBytes);
    if (this.getIntent(query)) return this.assertIntent(query, signedTicket, status, manifestBytes);
    const intent = {
      ...payload,
      signature: base64(crypto.sign(null,
        Buffer.concat([INTENT_DOMAIN, Buffer.from(JSON.stringify(payload))]), this.privateKey)),
    };
    const filename = this.intentPath(query);
    // Never expose a partially-written intent at its authoritative name.
    // Stage and fsync a private complete file, then create its permanent name
    // with an atomic no-overwrite hardlink on the same local filesystem.
    // A crash before linking leaves only an ignorable, non-authoritative temp.
    const temporary = filename + ".stage-" + crypto.randomBytes(16).toString("hex");
    let fd;
    try {
      fd = fs.openSync(temporary, "wx", 0o600);
      fs.writeSync(fd, JSON.stringify(intent) + "\n");
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      try {
        fs.linkSync(temporary, filename);
        assertPrivateDirectory(this.filename);
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        return this.assertIntent(query, signedTicket, status, manifestBytes);
      }
      // fsyncing a directory is supported on Unix; Windows does not expose
      // that portability guarantee in Node, so keep failure closed on write.
      if (process.platform !== "win32") {
        const parentFd = fs.openSync(path.dirname(filename), "r");
        try { fs.fsyncSync(parentFd); } finally { fs.closeSync(parentFd); }
      }
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.unlinkSync(temporary); } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }
    return true;
  }

  assertMatch(query, signedTicket, status, manifestBytes, terminalSeal) {
    const event = this.get(query.reservation_id);
    if (!event || event.scope !== scopeKey(query) || event.status !== status
      || event.ticketHash !== digest(signedTicket)
      || event.manifestHash !== (manifestBytes === null ? null : digest(manifestBytes))
      || event.terminalSeal !== base64(terminalSeal)) fail();
    return true;
  }

  async append(query, signedTicket, status, manifestBytes, terminalSeal) {
    assertWindowsPrivateAnchorDirectory(this.filename);
    assertPrivateDirectory(this.filename);
    this.assertIntent(query, signedTicket, status, manifestBytes);
    // All live handles/processes must reload the signed journal under the
    // same exclusive file-create lock before assigning a new sequence.
    // Never delete a lock created by someone else; stale locks fail closed
    // until independently verified operator recovery.
    const lockPath = this.filename + ".append.lock";
    let lock;
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        assertPrivateDirectory(this.filename);
        lock = fs.openSync(lockPath, "wx", 0o600);
        break;
      } catch (error) {
        if (error?.code !== "EEXIST") fail();
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
    if (lock === undefined) fail();
    try {
      this.reload(true);
      const previous = this.records.get(base64(query.reservation_id));
      if (previous) return this.assertMatch(query, signedTicket, status, manifestBytes, terminalSeal);
      const record = {
        sequence: this.sequence + 1, reservation: base64(query.reservation_id),
        scope: scopeKey(query), status, ticketHash: digest(signedTicket),
        manifestHash: manifestBytes === null ? null : digest(manifestBytes),
        terminalSeal: base64(terminalSeal), previousHash: this.previousHash,
      };
      record.signature = base64(crypto.sign(null, signatureInput(record), this.privateKey));
      this.verify(record);
      const line = JSON.stringify(record);
      const written = Buffer.from(line + "\n");
      const pinned = this.#verifiedFileIdentity;
      if (!pinned || pinned.size + BigInt(written.length) > BigInt(MAX_BYTES)) fail();
      let fd;
      try {
        assertPrivateDirectory(this.filename);
        const before = fs.lstatSync(this.filename, { bigint: true });
        if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
          || before.dev !== pinned.dev || before.ino !== pinned.ino
          || before.size !== pinned.size) fail();
        fd = fs.openSync(this.filename,
          fs.constants.O_WRONLY | fs.constants.O_APPEND
          | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0));
        const opened = fs.fstatSync(fd, { bigint: true });
        const named = fs.lstatSync(this.filename, { bigint: true });
        assertPrivateDirectory(this.filename);
        if (!opened.isFile() || opened.nlink !== 1n
          || opened.dev !== pinned.dev || opened.ino !== pinned.ino
          || opened.size !== pinned.size || named.isSymbolicLink()
          || named.dev !== opened.dev || named.ino !== opened.ino
          || named.nlink !== 1n) fail();
        assertPrivateFile(opened);
        assertPrivateFile(named);
        if (fs.writeSync(fd, written) !== written.length) fail();
        fs.fsyncSync(fd);
        const after = fs.fstatSync(fd, { bigint: true });
        const namedAfter = fs.lstatSync(this.filename, { bigint: true });
        assertPrivateDirectory(this.filename);
        if (after.dev !== opened.dev || after.ino !== opened.ino
          || after.nlink !== 1n || after.size !== opened.size + BigInt(written.length)
          || namedAfter.isSymbolicLink() || namedAfter.nlink !== 1n
          || namedAfter.dev !== opened.dev || namedAfter.ino !== opened.ino
          || namedAfter.size !== after.size) fail();
        assertPrivateFile(after);
        assertPrivateFile(namedAfter);
      } catch (_) { fail(); }
      finally { if (fd !== undefined) fs.closeSync(fd); }
      this.reload(true);
      return true;
    } finally {
      // The append lock protects sequence assignment only while we own the
      // exact inode created with wx. Another local process can replace the
      // pathname before release; blindly unlinking its new lock would admit
      // overlapping writers. Refuse and preserve any unexpected lock.
      const owned = fs.fstatSync(lock, { bigint: true });
      fs.closeSync(lock);
      let current;
      try { current = fs.lstatSync(lockPath, { bigint: true }); }
      catch (_) { fail(); }
      if (!owned.isFile() || owned.nlink !== 1n
        || !current.isFile() || current.isSymbolicLink() || current.nlink !== 1n
        || owned.dev !== current.dev || owned.ino !== current.ino) fail();
      fs.unlinkSync(lockPath);
    }
  }
}

module.exports = { Zk1CasTerminalAnchor };
