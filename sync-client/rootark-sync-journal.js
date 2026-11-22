"use strict";

const crypto = require("node:crypto");
const { types: nodeUtilTypes } = require("node:util");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { canonicalJson } = require("./rootark-sync-protocol");

const nativeJsonParse = JSON.parse.bind(JSON);
const nativeJsonStringify = JSON.stringify.bind(JSON);
const nativeBufferFrom = Buffer.from.bind(Buffer);
const nativeObjectValues = Object.values;
const nativeObjectEntries = Object.entries;
const NativeArray = Array;
const nativeArrayIsArray = Array.isArray;
const nativeObjectKeys = Object.keys;
const nativeObjectCreate = Object.create;
const nativeObjectSetPrototypeOf = Object.setPrototypeOf;
const nativeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const nativeObjectHasOwn = Object.hasOwn;
const nativeObjectAssign = Object.assign;
const nativeObjectFreeze = Object.freeze;
const nativeIsProxy = nodeUtilTypes.isProxy;
const NativeMap = Map;
const NativeSet = Set;
const nativeMapSet = NativeMap.prototype.set;
const nativeMapGet = NativeMap.prototype.get;
const nativeMapHas = NativeMap.prototype.has;
const nativeSetAdd = NativeSet.prototype.add;
const nativeSetHas = NativeSet.prototype.has;
const nativeSetSize = Object.getOwnPropertyDescriptor(NativeSet.prototype, "size").get;
const nativeArrayIncludes = Array.prototype.includes;
const nativeStringStartsWith = String.prototype.startsWith;
const nativeStringSlice = String.prototype.slice;
const nativeRegExpExec = RegExp.prototype.exec;
const nativeNumberIsSafeInteger = Number.isSafeInteger;
const nativeMathMax = Math.max;
const nativePromiseResolve = Promise.resolve.bind(Promise);
const nativePromiseThen = Promise.prototype.then;
const nativePromiseCatch = Promise.prototype.catch;
const NativePromise = Promise;
const nativeSetTimeout = setTimeout;

function regexTest(pattern, value) {
  return nativeReflectApply(nativeRegExpExec, pattern, [value]) !== null;
}

function regexExec(pattern, value) {
  return nativeReflectApply(nativeRegExpExec, pattern, [value]);
}

function stringStartsWith(value, prefix) {
  return nativeReflectApply(nativeStringStartsWith, value, [prefix]);
}

function stringSlice(value, start, end) {
  return nativeReflectApply(nativeStringSlice, value, end === undefined ? [start] : [start, end]);
}

// The journal is the durable authority for pending signed envelope identity.
// Pin its digest primitives before any transport/readback callback can mutate
// the shared crypto module or Hash prototype.
const nativeCreateHash = crypto.createHash.bind(crypto);
const nativeRandomUUID = crypto.randomUUID.bind(crypto);
const nativeHashUpdate = crypto.Hash.prototype.update;
const nativeHashDigest = crypto.Hash.prototype.digest;
const nativeReflectApply = Reflect.apply;

function detachJournalJson(value, ancestors = []) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "function" || typeof value === "symbol"
      || typeof value === "bigint") throw new TypeError("Sync journal requires JSON values");
    return value;
  }
  if (nativeIsProxy(value)) throw new TypeError("Sync journal proxy values are not trusted");
  for (let index = 0; index < ancestors.length; index += 1) {
    if (ancestors[index] === value) throw new TypeError("Circular sync journal value");
  }
  ancestors[ancestors.length] = value;
  if (nativeArrayIsArray(value)) {
    const result = new NativeArray(value.length);
    nativeObjectSetPrototypeOf(result, null);
    for (let index = 0; index < value.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor) continue;
      if (!nativeObjectHasOwn(descriptor, "value")) {
        throw new TypeError("Sync journal arrays cannot contain accessors");
      }
      result[index] = detachJournalJson(descriptor.value, ancestors);
    }
    ancestors.length -= 1;
    return result;
  }
  const result = nativeObjectCreate(null);
  const keys = nativeObjectKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")
      || (key === "toJSON" && typeof descriptor.value === "function")) {
      throw new TypeError("Sync journal objects must contain JSON data properties");
    }
    result[key] = detachJournalJson(descriptor.value, ancestors);
  }
  ancestors.length -= 1;
  return result;
}

function safeJsonStringify(value) {
  // Capturing JSON.stringify alone is insufficient: it still invokes inherited
  // Object.prototype/Array.prototype.toJSON hooks installed by a callback.
  return nativeJsonStringify(detachJournalJson(value));
}

function setAdd(set, value) {
  nativeReflectApply(nativeSetAdd, set, [value]);
}

function setHas(set, value) {
  return nativeReflectApply(nativeSetHas, set, [value]);
}

function setSize(set) {
  return nativeReflectApply(nativeSetSize, set, []);
}

function mapSet(map, key, value) {
  nativeReflectApply(nativeMapSet, map, [key, value]);
}

function mapGet(map, key) {
  return nativeReflectApply(nativeMapGet, map, [key]);
}

function mapHas(map, key) {
  return nativeReflectApply(nativeMapHas, map, [key]);
}

function arrayHas(array, value) {
  return nativeReflectApply(nativeArrayIncludes, array, [value]);
}

function findPendingById(pending, operationId) {
  for (let index = 0; index < pending.length; index += 1) {
    if (pending[index]?.operationId === operationId) return pending[index];
  }
  return null;
}

function findPendingIndexById(pending, operationId) {
  for (let index = 0; index < pending.length; index += 1) {
    if (pending[index]?.operationId === operationId) return index;
  }
  return -1;
}

const JOURNAL_VERSION = 1;
const MAX_PENDING = 10000;
const MAX_OBSERVATIONS = 10000;
// Signed receipts cover both durable pending work and the retained seen window.
// Each partition has its own limit; combining them must not stall a full seen
// history when a new signed operation enters an otherwise empty outbox.
const MAX_SIGNED_RECEIPTS = MAX_PENDING + MAX_OBSERVATIONS;
const VALID_OPERATION_ID = /^[A-Za-z0-9._:-]{1,160}$/;
const VALID_DIGEST = /^[0-9a-f]{64}$/;
const VALID_RESTORE_STAGE_SUFFIX = /^[1-9][0-9]*-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const WINDOWS_RENAME_MAX_ATTEMPTS = 3;
const WINDOWS_RENAME_RETRY_DELAY_MS = 10;

function assertSamePendingEnvelope(existing, incoming) {
  // An operationId is an idempotency key, not permission to replace or drop
  // different signed bytes. Compare canonical JSON so key ordering is inert.
  if (canonicalJson(existing) !== canonicalJson(incoming)) {
        throw nativeObjectAssign(new Error("Conflicting sync journal operationId"), {
      code: "sync_journal_operation_conflict",
    });
  }
}

function sha256Hex(value) {
  const hash = nativeCreateHash("sha256");
  nativeReflectApply(nativeHashUpdate, hash, [value]);
  return nativeReflectApply(nativeHashDigest, hash, ["hex"]);
}

function signedEnvelopeDigest(operation) {
  if (!operation || typeof operation !== "object"
    || !nativeObjectHasOwn(operation, "authorization")) return null;
  return sha256Hex(canonicalJson(operation));
}

function invalidRestoreStaging(staging, pending) {
  if (!staging || typeof staging !== "object" || nativeArrayIsArray(staging)
    || nativeObjectKeys(staging).length > MAX_PENDING) return true;
  const byId = new NativeMap();
  for (let index = 0; index < pending.length; index += 1) {
    const entry = pending[index];
    mapSet(byId, entry.operationId, entry);
  }
  const entries = nativeObjectEntries(staging);
  for (let index = 0; index < entries.length; index += 1) {
    const id = entries[index][0];
    const proof = entries[index][1];
    const operation = mapGet(byId, id);
    const base = typeof operation?.metadata?.path === "string"
      ? path.posix.basename(operation.metadata.path) : null;
    const prefix = base ? `${base}.tmp-` : "";
    // #288 materializes historical restores in a private, non-syncable
    // directory. The alternative prefix is bound to the EXACT signed
    // operation ID, never inferred from a filename or caller-supplied path.
    const privatePrefix = `restore-materialize-${sha256Hex(id)}.tmp-`;
    const stagedName = proof && typeof proof === "object" && typeof proof.name === "string"
      ? proof.name : "";
    const legacyNameValid = stringStartsWith(stagedName, prefix)
      && regexTest(VALID_RESTORE_STAGE_SUFFIX, stringSlice(stagedName, prefix.length));
    const privateNameValid = stringStartsWith(stagedName, privatePrefix)
      && regexTest(VALID_RESTORE_STAGE_SUFFIX, stringSlice(stagedName, privatePrefix.length));
    if (!stringStartsWith(id, "histrestore-") || !regexTest(VALID_OPERATION_ID, id)
      || !operation || !base || !proof || typeof proof !== "object"
      || nativeArrayIsArray(proof) || nativeObjectKeys(proof).length !== 4
      || typeof proof.digest !== "string" || !regexTest(VALID_DIGEST, proof.digest)
      || signedEnvelopeDigest(operation) !== proof.digest
      || typeof proof.name !== "string" || !(legacyNameValid || privateNameValid)
      || !((proof.dev === null && proof.ino === null)
        || (typeof proof.dev === "string" && regexTest(/^[0-9]{1,30}$/, proof.dev)
          && typeof proof.ino === "string" && regexTest(/^[1-9][0-9]{0,29}$/, proof.ino)))) return true;
  }
  return false;
}

function signedWebDavEventId(operation) {
  if (!operation || typeof operation !== "object"
    || !nativeObjectHasOwn(operation, "authorization")
    || !nativeReflectApply(nativeArrayIncludes, ["delete", "move"], [operation.operation])
    || typeof operation.metadata?.path !== "string") return null;
  const match = regexExec(/^webdav-(.+)-([a-f0-9]{24})$/, operation.operationId || "");
  if (!match || match[1].length > 100) return null;
  const expected = stringSlice(sha256Hex(`${operation.operation}:${operation.metadata.path}`), 0, 24);
  return expected === match[2] ? match[1] : null;
}

function atomicSignedWebDavPair(operations) {
  if (!nativeArrayIsArray(operations) || operations.length !== 2) return null;
  const deleted = operations[0];
  const moved = operations[1];
  // A torn/corrupted outbox can still name both IDs in its durable manifest.
  // Missing members are an invalid group, not an uncaught TypeError.
  if (!deleted || typeof deleted !== "object" || !moved || typeof moved !== "object") return null;
  const event = signedWebDavEventId(deleted);
  if (!event || deleted.operation !== "delete" || moved.operation !== "move"
    || signedWebDavEventId(moved) !== event
    || deleted.metadata.path !== moved.metadata.path
    || deleted.deviceId !== moved.deviceId
    || deleted.compartmentId !== moved.compartmentId
    || deleted.keyEpoch !== moved.keyEpoch
    || deleted.objectId === moved.objectId || deleted.fileId === moved.fileId
    || deleted.operationId === moved.operationId) return null;
  return { event, deleteId: deleted.operationId, moveId: moved.operationId };
}

function invalidAtomicSignedGroups(groups, pending, seen) {
  if (!groups || typeof groups !== "object" || nativeArrayIsArray(groups)
    || nativeObjectKeys(groups).length > MAX_OBSERVATIONS) return true;
  const records = new NativeMap();
  for (let index = 0; index < pending.length; index += 1) {
    const entry = pending[index];
    mapSet(records, entry.operationId, entry);
  }
  const seenSet = new NativeSet();
  for (let index = 0; index < seen.length; index += 1) setAdd(seenSet, seen[index]);
  const members = new NativeSet();
  const entries = nativeObjectEntries(groups);
  for (let index = 0; index < entries.length; index += 1) {
    const event = entries[index][0];
    const pair = entries[index][1];
    if (!regexTest(/^[A-Za-z0-9._:-]{1,100}$/, event)
      || !pair || typeof pair !== "object" || nativeArrayIsArray(pair)
      || nativeObjectKeys(pair).length !== 2
      || !nativeObjectHasOwn(pair, "deleteId") || !nativeObjectHasOwn(pair, "moveId")
      || !regexTest(VALID_OPERATION_ID, pair.deleteId || "")
      || !regexTest(VALID_OPERATION_ID, pair.moveId || "")
      || pair.deleteId === pair.moveId || setHas(members, pair.deleteId)
      || setHas(members, pair.moveId) || setHas(seenSet, pair.deleteId)
      || setHas(seenSet, pair.moveId)) return true;
    setAdd(members, pair.deleteId);
    setAdd(members, pair.moveId);
    const actual = atomicSignedWebDavPair([mapGet(records, pair.deleteId), mapGet(records, pair.moveId)]);
    if (!actual || actual.event !== event) return true;
  }
  return false;
}

function recordSignedOutboxReceipt(next, operation) {
  const digest = signedEnvelopeDigest(operation);
  if (!digest) return;
  // JSON.parse() restores ordinary object prototypes. A valid operation ID
  // like "constructor" or "toString" must never resolve to an inherited
  // Object.prototype member instead of an actual durable receipt.
  const previous = nativeObjectHasOwn(next.committedSigned, operation.operationId)
    ? next.committedSigned[operation.operationId] : null;
  if (previous && previous !== digest) {
    throw new Error("Conflicting durable signed outbox receipt");
  }
  if (!previous && nativeObjectKeys(next.committedSigned).length >= MAX_SIGNED_RECEIPTS) {
    throw new Error("Durable signed outbox receipt capacity exceeded");
  }
  // This is evidence of an *already persisted* envelope, not an independent
  // Ed25519 verification service. Protected ingress verifies first; recovery
  // may inspect the receipt but must never treat it as new authorization.
  next.committedSigned[operation.operationId] = digest;
}

function assertEquivalentSeenEnvelope(next, operation) {
  // A legacy seen-only receipt is not proof that any particular signed bytes
  // were ever admitted. Never let a signed enqueue silently disappear just
  // because its operationId happened to be seen before (or let a later
  // unsigned envelope impersonate a previously signed operation).
  const received = signedEnvelopeDigest(operation);
  const original = nativeObjectHasOwn(next.committedSigned, operation.operationId)
    ? next.committedSigned[operation.operationId] : null;
  if ((original !== null || received !== null) && original !== received) {
        throw nativeObjectAssign(new Error("Conflicting or unauthenticated historical signed operationId"), {
      code: "sync_journal_operation_conflict",
    });
  }
}

function invalidPendingSignedReceiptWitness(pending) {
  for (let index = 0; index < pending.length; index += 1) {
    const operation = pending[index];
    if (!operation || typeof operation !== "object") continue;
    const hasReceipts = nativeObjectHasOwn(operation, "signedOutboxReceipts");
    const hasMoveBytes = nativeObjectHasOwn(operation, "moveBytes");
    const hasMoveDigest = nativeObjectHasOwn(operation, "moveSha256");
    // An authenticated MOVE can be acknowledged after restart only if its
    // signed receipt and its independently verified physical content witness
    // were committed together. Reject partial/legacy witness pairs at open
    // and before commit; do not wait for a late recovery phase to discover it.
    if (operation.kind === "move" && (hasReceipts || hasMoveBytes || hasMoveDigest)) {
      if (!hasReceipts || !hasMoveBytes || !hasMoveDigest
        || !nativeNumberIsSafeInteger(operation.moveBytes)
        || operation.moveBytes < 0 || !regexTest(VALID_DIGEST, operation.moveSha256)) return true;
    } else if (hasMoveBytes || hasMoveDigest) return true;
    if (!hasReceipts) continue;
    const receipts = operation.signedOutboxReceipts;
    if (!nativeArrayIsArray(receipts) || !receipts.length || receipts.length > 4) return true;
    const ids = new NativeSet();
    for (let cursor = 0; cursor < receipts.length; cursor += 1) {
      const receipt = receipts[cursor];
      if (!receipt || typeof receipt !== "object" || nativeArrayIsArray(receipt)
        || typeof receipt.operationId !== "string"
        || !regexTest(VALID_OPERATION_ID, receipt.operationId)
        || typeof receipt.digest !== "string" || !regexTest(VALID_DIGEST, receipt.digest)
        || setHas(ids, receipt.operationId)) return true;
      setAdd(ids, receipt.operationId);
    }
  }
  return false;
}

function isUnsupportedDirectorySync(error) {
  return nativeReflectApply(nativeArrayIncludes, ["EINVAL", "ENOTSUP"], [error?.code])
    || (process.platform === "win32" && error?.code === "EPERM");
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await fsp.open(directory, "r");
    await handle.sync();
  } catch (error) {
    if (!isUnsupportedDirectorySync(error)) throw error;
  } finally {
    if (handle) await handle.close();
  }
}

async function renameWithRetry(source, destination) {
  for (let attempt = 1; attempt <= WINDOWS_RENAME_MAX_ATTEMPTS; attempt += 1) {
    try {
      await fsp.rename(source, destination);
      return;
    } catch (error) {
      if (process.platform !== "win32" || error?.code !== "EPERM" || attempt === WINDOWS_RENAME_MAX_ATTEMPTS) throw error;
      await new NativePromise((resolve) => nativeSetTimeout(resolve, WINDOWS_RENAME_RETRY_DELAY_MS));
    }
  }
}

async function durableWrite(filePath, value) {
  const directory = path.dirname(filePath);
  // Prepare bytes before awaiting the filesystem: a transport or witness
  // callback may poison the global Buffer.from used by writeFile(string).
  const serialized = nativeBufferFrom(`${safeJsonStringify(value)}\n`, "utf8");
  await fsp.mkdir(directory, { recursive: true });
  // The journal directory can contain crash leftovers. A predictable
  // temporary name combined with "w" would truncate a preexisting entry
  // before its ownership/identity was checked. Never overwrite a collision:
  // cryptographically randomize the name and require O_EXCL creation.
  const temporary = `${filePath}.tmp-${process.pid}-${nativeRandomUUID()}`;
  const handle = await fsp.open(temporary, "wx", 0o600);
  try {
    for (let offset = 0; offset < serialized.length;) {
      const { bytesWritten } = await handle.write(serialized, offset, serialized.length - offset, offset);
      if (!nativeNumberIsSafeInteger(bytesWritten) || bytesWritten <= 0
        || bytesWritten > serialized.length - offset) {
        throw new Error("Durable sync journal write made no valid progress");
      }
      offset += bytesWritten;
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await renameWithRetry(temporary, filePath);
  } catch (error) {
    await nativeReflectApply(nativePromiseCatch, fsp.unlink(temporary), [() => {}]);
    throw error;
  }
  try {
    await syncDirectory(directory);
  } catch (error) {
    error.journalCommitted = true;
    throw error;
  }
}

class SyncJournal {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.state = { version: JOURNAL_VERSION, pending: [], seen: [],
      admitted: nativeObjectCreate(null), observed: nativeObjectCreate(null),
      committedSigned: nativeObjectCreate(null), atomicSignedGroups: nativeObjectCreate(null),
      materializedRestore: nativeObjectCreate(null), restoreStaging: nativeObjectCreate(null) };
    this.queue = nativePromiseResolve();
  }

  async open({ requireExisting = false } = {}) {
    try {
      this.state = nativeJsonParse(await fsp.readFile(this.filePath, "utf8"));
      if (this.state.version !== JOURNAL_VERSION || !nativeArrayIsArray(this.state.pending)
        || this.state.pending.length > MAX_PENDING || !nativeArrayIsArray(this.state.seen)
        || this.state.seen.length > MAX_OBSERVATIONS) {
        throw new Error("Invalid sync journal");
      }
      const pendingIds = new NativeArray(this.state.pending.length);
      const pendingIdSet = new NativeSet();
      const seenIdSet = new NativeSet();
      let invalidPartition = false;
      for (let index = 0; index < this.state.pending.length; index += 1) {
        const item = this.state.pending[index];
        const id = item && typeof item === "object" && !nativeArrayIsArray(item) ? item.operationId : null;
        pendingIds[index] = id;
        nativeReflectApply(nativeSetAdd, pendingIdSet, [id]);
        if (typeof id !== "string" || !regexTest(VALID_OPERATION_ID, id)) invalidPartition = true;
      }
      for (let index = 0; index < this.state.seen.length; index += 1) {
        const id = this.state.seen[index];
        nativeReflectApply(nativeSetAdd, seenIdSet, [id]);
        if (typeof id !== "string" || !regexTest(VALID_OPERATION_ID, id)
          || nativeReflectApply(nativeSetHas, pendingIdSet, [id])) invalidPartition = true;
      }
      if (invalidPartition
        || nativeReflectApply(nativeSetSize, pendingIdSet, []) !== pendingIds.length
        || nativeReflectApply(nativeSetSize, seenIdSet, []) !== this.state.seen.length
        || invalidPendingSignedReceiptWitness(this.state.pending)) {
        // More than one pending record per operationId would allow the
        // first-match update()/markSeen() path to silently discard another
        // physical mutation. An ID may be pending OR seen, never both.
        throw new Error("Invalid sync journal operationId partition");
      }
      // Legacy operation-ID-only receipts are not proof of prior admission.
      // The new exact signed-envelope fingerprints must be independently
      // observed while the device's write authorization is still fresh.
      if (this.state.admitted === undefined) this.state.admitted = nativeObjectCreate(null);
      if (this.state.observed === undefined) this.state.observed = nativeObjectCreate(null);
      if (this.state.committedSigned === undefined) this.state.committedSigned = nativeObjectCreate(null);
      if (this.state.atomicSignedGroups === undefined) this.state.atomicSignedGroups = nativeObjectCreate(null);
      if (this.state.materializedRestore === undefined) this.state.materializedRestore = nativeObjectCreate(null);
      if (this.state.restoreStaging === undefined) this.state.restoreStaging = nativeObjectCreate(null);
      if (invalidAtomicSignedGroups(this.state.atomicSignedGroups, this.state.pending, this.state.seen)) {
        throw new Error("Invalid atomic signed WebDAV journal group");
      }
      const pendingById = new NativeMap();
      for (let index = 0; index < this.state.pending.length; index += 1) {
        const entry = this.state.pending[index];
        nativeReflectApply(nativeMapSet, pendingById, [entry.operationId, entry]);
      }
      if (!this.state.materializedRestore || typeof this.state.materializedRestore !== "object"
        || nativeArrayIsArray(this.state.materializedRestore)) {
        throw new Error("Invalid durable restore materialization evidence");
      }
      const materializedIds = nativeObjectKeys(this.state.materializedRestore);
      if (materializedIds.length > MAX_PENDING) throw new Error("Invalid durable restore materialization evidence");
      for (let index = 0; index < materializedIds.length; index += 1) {
        const id = materializedIds[index];
        const digest = this.state.materializedRestore[id];
        if (!stringStartsWith(id, "histrestore-") || !regexTest(VALID_OPERATION_ID, id)
          || !regexTest(VALID_DIGEST, digest)
          || signedEnvelopeDigest(nativeReflectApply(nativeMapGet, pendingById, [id])) !== digest) {
          throw new Error("Invalid durable restore materialization evidence");
        }
      }
      if (invalidRestoreStaging(this.state.restoreStaging, this.state.pending)) {
        throw new Error("Invalid durable restore staging intent");
      }
      if (!this.state.committedSigned || typeof this.state.committedSigned !== "object"
        || nativeArrayIsArray(this.state.committedSigned)) {
        throw new Error("Invalid durable signed outbox receipt journal");
      }
      const committedIds = nativeObjectKeys(this.state.committedSigned);
      if (committedIds.length > MAX_SIGNED_RECEIPTS) throw new Error("Invalid durable signed outbox receipt journal");
      for (let index = 0; index < committedIds.length; index += 1) {
        const id = committedIds[index];
        const digest = this.state.committedSigned[id];
        if (!regexTest(VALID_OPERATION_ID, id) || !regexTest(VALID_DIGEST, digest)
          || (!nativeReflectApply(nativeSetHas, seenIdSet, [id])
            && signedEnvelopeDigest(nativeReflectApply(nativeMapGet, pendingById, [id])) !== digest)) {
          throw new Error("Invalid durable signed outbox receipt journal");
        }
      }
      if (!this.state.admitted || typeof this.state.admitted !== "object"
        || nativeArrayIsArray(this.state.admitted)) {
        throw new Error("Invalid previously admitted sync envelope journal");
      }
      const admittedIds = nativeObjectKeys(this.state.admitted);
      if (admittedIds.length > MAX_OBSERVATIONS) throw new Error("Invalid previously admitted sync envelope journal");
      for (let index = 0; index < admittedIds.length; index += 1) {
        const id = admittedIds[index];
        const digest = this.state.admitted[id];
        if (!regexTest(VALID_OPERATION_ID, id) || typeof digest !== "string" || !regexTest(VALID_DIGEST, digest)
          || !nativeReflectApply(nativeArrayIncludes, this.state.seen, [id])) {
          throw new Error("Invalid previously admitted sync envelope journal");
        }
      }
      if (!this.state.observed || typeof this.state.observed !== "object"
        || nativeArrayIsArray(this.state.observed)) {
        throw new Error("Invalid previously observed sync envelope journal");
      }
      const observedIds = nativeObjectKeys(this.state.observed);
      if (observedIds.length > MAX_OBSERVATIONS) throw new Error("Invalid previously observed sync envelope journal");
      for (let index = 0; index < observedIds.length; index += 1) {
        const id = observedIds[index];
        const digest = this.state.observed[id];
        if (!regexTest(VALID_OPERATION_ID, id) || typeof digest !== "string" || !regexTest(VALID_DIGEST, digest)
          || (nativeObjectHasOwn(this.state.admitted, id) && this.state.admitted[id] !== digest)) {
          throw new Error("Invalid previously observed sync envelope journal");
        }
      }
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      // Recovery previews are advisory READS. They must never replace lost
      // journal evidence with an empty outbox if a file vanished after open.
      if (requireExisting) {
        throw Object.assign(new Error("Existing sync journal is unavailable for read-only preview"), {
          code: "history_preview_unavailable",
        });
      }
      await durableWrite(this.filePath, this.state);
    }
    return this;
  }

  async commit(mutator) {
    const transaction = nativeReflectApply(nativePromiseThen, this.queue, [async () => {
      // Mutation callbacks (notably update()) edit pending entry objects.
      // A shallow array copy would mutate the live in-memory state BEFORE
      // the fsync-backed commit succeeds, manufacturing a phase which did
      // not become durable when a later disk write fails.
      const seenCopy = [];
      for (let index = 0; index < this.state.seen.length; index += 1) {
        seenCopy[seenCopy.length] = this.state.seen[index];
      }
      const next = { version: JOURNAL_VERSION,
        pending: nativeJsonParse(safeJsonStringify(this.state.pending)),
        seen: seenCopy,
        admitted: nativeObjectAssign(nativeObjectCreate(null), this.state.admitted),
        observed: nativeObjectAssign(nativeObjectCreate(null), this.state.observed),
        committedSigned: nativeObjectAssign(nativeObjectCreate(null), this.state.committedSigned),
        atomicSignedGroups: nativeObjectAssign(nativeObjectCreate(null), this.state.atomicSignedGroups),
        materializedRestore: nativeObjectAssign(nativeObjectCreate(null), this.state.materializedRestore),
        restoreStaging: nativeObjectAssign(nativeObjectCreate(null), this.state.restoreStaging) };
      await mutator(next);
      // Pending mutations are durable work. Silently keeping the newest items
      // would permanently discard the oldest unsigned or signed operation.
      if (next.pending.length > MAX_PENDING) throw new Error("Sync journal capacity exceeded");
      if (invalidPendingSignedReceiptWitness(next.pending)) {
        throw new Error("Invalid protected WebDAV signed receipt binding");
      }
      const retainedSeen = [];
      const seenStart = nativeMathMax(0, next.seen.length - 10000);
      for (let index = seenStart; index < next.seen.length; index += 1) {
        retainedSeen[retainedSeen.length] = next.seen[index];
      }
      next.seen = retainedSeen;
      const retained = new NativeSet();
      for (let index = 0; index < next.seen.length; index += 1) setAdd(retained, next.seen[index]);
      const admittedKeys = nativeObjectKeys(next.admitted);
      for (let index = 0; index < admittedKeys.length; index += 1) {
        const id = admittedKeys[index];
        if (!setHas(retained, id)) delete next.admitted[id];
      }
      const pendingIds = new NativeSet();
      for (let index = 0; index < next.pending.length; index += 1) {
        setAdd(pendingIds, next.pending[index]?.operationId);
      }
      const committedKeys = nativeObjectKeys(next.committedSigned);
      for (let index = 0; index < committedKeys.length; index += 1) {
        const id = committedKeys[index];
        if (!setHas(retained, id) && !setHas(pendingIds, id)) delete next.committedSigned[id];
      }
      // update()/replace() accept caller-provided patches. Even if enqueue()
      // rejects malformed IDs, a later patch must not persist two pending
      // entries under one ID, overlap an acknowledged ID or detach a signed
      // receipt from the exact bytes it records. Validate the *resulting*
      // transaction before durableWrite, not only at cold open: otherwise a
      // bridge could ACK a write then be unable to reopen its own journal.
      const ids = [];
      const uniquePendingIds = new NativeSet();
      let invalidPartition = setSize(retained) !== next.seen.length;
      for (let index = 0; index < next.seen.length; index += 1) {
        const id = next.seen[index];
        if (typeof id !== "string" || !regexTest(VALID_OPERATION_ID, id)) invalidPartition = true;
      }
      for (let index = 0; index < next.pending.length; index += 1) {
        const entry = next.pending[index];
        const id = entry && typeof entry === "object" && !nativeArrayIsArray(entry)
          ? entry.operationId : null;
        ids[ids.length] = id;
        if (typeof id !== "string" || !regexTest(VALID_OPERATION_ID, id)
          || setHas(uniquePendingIds, id) || setHas(retained, id)) {
          invalidPartition = true;
        }
        setAdd(uniquePendingIds, id);
      }
      if (invalidPartition || setSize(uniquePendingIds) !== ids.length) {
        throw new Error("Invalid sync journal operationId partition");
      }
      if (invalidAtomicSignedGroups(next.atomicSignedGroups, next.pending, next.seen)) {
        throw new Error("Invalid atomic signed WebDAV journal group");
      }
      const pendingById = new NativeMap();
      for (let index = 0; index < next.pending.length; index += 1) {
        const entry = next.pending[index];
        mapSet(pendingById, entry.operationId, entry);
      }
      const materializedKeys = nativeObjectKeys(next.materializedRestore);
      for (let index = 0; index < materializedKeys.length; index += 1) {
        const id = materializedKeys[index];
        if (!mapHas(pendingById, id)) delete next.materializedRestore[id];
      }
      const stagingKeys = nativeObjectKeys(next.restoreStaging);
      for (let index = 0; index < stagingKeys.length; index += 1) {
        const id = stagingKeys[index];
        if (!mapHas(pendingById, id)) delete next.restoreStaging[id];
      }
      const materializedEntries = nativeObjectEntries(next.materializedRestore);
      let invalidMaterialized = materializedEntries.length > MAX_PENDING;
      for (let index = 0; index < materializedEntries.length; index += 1) {
        const id = materializedEntries[index][0];
        const digest = materializedEntries[index][1];
        if (!stringStartsWith(id, "histrestore-") || !regexTest(VALID_OPERATION_ID, id)
          || !regexTest(VALID_DIGEST, digest)
          || signedEnvelopeDigest(mapGet(pendingById, id)) !== digest) invalidMaterialized = true;
      }
      if (invalidMaterialized) {
        throw new Error("Invalid committed restore materialization evidence");
      }
      if (invalidRestoreStaging(next.restoreStaging, next.pending)) {
        throw new Error("Invalid committed restore staging intent");
      }
      const signedEntries = nativeObjectEntries(next.committedSigned);
      let invalidSigned = signedEntries.length > MAX_SIGNED_RECEIPTS;
      for (let index = 0; index < signedEntries.length; index += 1) {
        const id = signedEntries[index][0];
        const digest = signedEntries[index][1];
        if (!regexTest(VALID_OPERATION_ID, id) || !regexTest(VALID_DIGEST, digest)
          || (!setHas(retained, id) && signedEnvelopeDigest(mapGet(pendingById, id)) !== digest)) {
          invalidSigned = true;
        }
      }
      if (invalidSigned) {
        throw new Error("Invalid durable signed outbox receipt journal");
      }
      // mutator() may have inserted references from the caller's envelope,
      // batch or patch. Make the exact JSON value an immutable commit snapshot:
      // later caller mutations must not change memory-only pending bytes while
      // the on-disk journal and the signed-receipt digest remain unchanged.
      const persisted = nativeJsonParse(safeJsonStringify(next));
      // Preserve the exact on-disk bytes of legacy (or fully acknowledged)
      // journals. The optional evidence field exists on disk only while an
      // independently materialized historical restore remains pending.
      if (!nativeObjectKeys(persisted.materializedRestore).length) {
        delete persisted.materializedRestore;
      }
      if (!nativeObjectKeys(persisted.restoreStaging).length) {
        delete persisted.restoreStaging;
      }
      try {
        await durableWrite(this.filePath, persisted);
      } catch (error) {
        if (error.journalCommitted) this.state = persisted;
        throw error;
      }
      this.state = persisted;
    }]);
    this.queue = nativeReflectApply(nativePromiseCatch, transaction, [() => {}]);
    return transaction;
  }

  async enqueue(operation) {
    if (typeof operation?.operationId !== "string"
      || !regexTest(VALID_OPERATION_ID, operation.operationId)) {
      throw new Error("Valid journal operationId required");
    }
    await this.commit((next) => {
      const previous = findPendingById(next.pending, operation.operationId);
      if (previous) {
        assertSamePendingEnvelope(previous, operation);
        recordSignedOutboxReceipt(next, operation);
      } else if (!arrayHas(next.seen, operation.operationId)) {
        if (next.pending.length >= MAX_PENDING) throw new Error("Sync journal capacity exceeded");
        next.pending[next.pending.length] = operation;
        recordSignedOutboxReceipt(next, operation);
      } else {
        assertEquivalentSeenEnvelope(next, operation);
      }
      // Historical unsigned, seen-only retries keep legacy compatibility,
      // but cannot confer authorization or suppress NEW signed envelopes.
    });
    return operation;
  }

  async discardUnsent(operation) {
    // Only the caller that created an exact never-dispatched signed envelope
    // may cancel it after a local preflight conflict. Never erase an admitted,
    // acknowledged, or atomic-group operation.
    const digest = signedEnvelopeDigest(operation);
    if (!digest || !regexTest(VALID_OPERATION_ID, operation.operationId)) {
      throw new Error("A signed outbox operation is required for cancellation");
    }
    await this.commit((next) => {
      const index = findPendingIndexById(next.pending, operation.operationId);
      if (index < 0 || signedEnvelopeDigest(next.pending[index]) !== digest
        || arrayHas(next.seen, operation.operationId)
        || nativeObjectHasOwn(next.admitted, operation.operationId)
        || !nativeObjectHasOwn(next.committedSigned, operation.operationId)
        || next.committedSigned[operation.operationId] !== digest
        || (() => {
          const groups = nativeObjectValues(next.atomicSignedGroups);
          for (let cursor = 0; cursor < groups.length; cursor += 1) {
            if (groups[cursor].deleteId === operation.operationId
              || groups[cursor].moveId === operation.operationId) return true;
          }
          return false;
        })()) {
        throw new Error("Cannot discard an ineligible signed outbox operation");
      }
      const remainingPending = [];
      for (let cursor = 0; cursor < next.pending.length; cursor += 1) {
        if (cursor !== index) remainingPending[remainingPending.length] = next.pending[cursor];
      }
      next.pending = remainingPending;
      delete next.restoreStaging[operation.operationId];
      delete next.committedSigned[operation.operationId];
      delete next.observed[operation.operationId];
    });
  }

  async enqueueMany(operations) {
    if (!nativeArrayIsArray(operations)) throw new Error("Journal operations require valid operationId");
    const operationIds = [];
    const uniqueOperationIds = new NativeSet();
    for (let index = 0; index < operations.length; index += 1) {
      const operation = operations[index];
      if (typeof operation?.operationId !== "string"
        || !regexTest(VALID_OPERATION_ID, operation.operationId)
        || setHas(uniqueOperationIds, operation.operationId)) {
        throw new Error("Journal operations require valid unique operationId");
      }
      operationIds[operationIds.length] = operation.operationId;
      setAdd(uniqueOperationIds, operation.operationId);
    }
    const atomicPair = atomicSignedWebDavPair(operations);
    const signedEvents = [];
    for (let index = 0; index < operations.length; index += 1) {
      const event = signedWebDavEventId(operations[index]);
      if (event) signedEvents[signedEvents.length] = event;
    }
    // An unsigned generic batch may remain a legacy operation set, but a
    // multi-entry batch containing the deterministic signed WebDAV MOVE must
    // not evade the durable DELETE-before-MOVE group marker via reordered,
    // missing, or extra companions. Reject BEFORE persisting either side.
    if (!atomicPair && operations.length > 1) {
      for (let index = 0; index < operations.length; index += 1) {
        if (operations[index].operation === "move" && signedWebDavEventId(operations[index])) {
          throw new Error("Invalid atomic signed WebDAV batch membership");
        }
      }
    }
    if (signedEvents.length > 1 && !atomicPair) {
      throw new Error("Ambiguous signed WebDAV batch identity");
    }
    await this.commit((next) => {
      const pendingById = new NativeMap();
      for (let index = 0; index < next.pending.length; index += 1) {
        const item = next.pending[index];
        mapSet(pendingById, item.operationId, item);
      }
      const additions = [];
      for (let index = 0; index < operations.length; index += 1) {
        const operation = operations[index];
        const previous = mapGet(pendingById, operation.operationId);
        if (previous) {
          assertSamePendingEnvelope(previous, operation);
          recordSignedOutboxReceipt(next, operation);
        } else if (!arrayHas(next.seen, operation.operationId)) {
          additions[additions.length] = operation;
          recordSignedOutboxReceipt(next, operation);
        } else {
          assertEquivalentSeenEnvelope(next, operation);
        }
      }
      if (next.pending.length + additions.length > MAX_PENDING) throw new Error("Sync journal capacity exceeded");
      for (let index = 0; index < additions.length; index += 1) {
        next.pending[next.pending.length] = additions[index];
      }
      if (atomicPair) {
        for (let index = 0; index < operationIds.length; index += 1) {
          if (arrayHas(next.seen, operationIds[index])) {
            throw new Error("Cannot reassemble a partially seen atomic signed WebDAV batch");
          }
        }
        const prior = nativeObjectHasOwn(next.atomicSignedGroups, atomicPair.event)
          ? next.atomicSignedGroups[atomicPair.event] : null;
        if (prior && (prior.deleteId !== atomicPair.deleteId
          || prior.moveId !== atomicPair.moveId)) {
          throw new Error("Conflicting atomic signed WebDAV batch identity");
        }
        next.atomicSignedGroups[atomicPair.event] = {
          deleteId: atomicPair.deleteId, moveId: atomicPair.moveId,
        };
      }
    });
    return operations;
  }

  async markSeen(operationId, admittedDigest = null) {
    if (!regexTest(VALID_OPERATION_ID, operationId)
      || (admittedDigest !== null && (typeof admittedDigest !== "string"
        || !regexTest(VALID_DIGEST, admittedDigest)))) {
      throw new Error("Invalid local sync admission evidence");
    }
    await this.commit((next) => {
      const groups = nativeObjectValues(next.atomicSignedGroups);
      for (let cursor = 0; cursor < groups.length; cursor += 1) {
        if (groups[cursor].deleteId === operationId || groups[cursor].moveId === operationId) {
          throw new Error("Atomic signed WebDAV pair requires markSeenMany");
        }
      }
      const remainingPending = [];
      for (let cursor = 0; cursor < next.pending.length; cursor += 1) {
        if (next.pending[cursor]?.operationId === operationId
          && stringStartsWith(operationId, "histrestore-")) {
          throw new Error("Historical restores require independently verified markSeenExact");
        }
        if (next.pending[cursor]?.operationId !== operationId) {
          remainingPending[remainingPending.length] = next.pending[cursor];
        }
      }
      next.pending = remainingPending;
      delete next.materializedRestore[operationId];
      delete next.restoreStaging[operationId];
      if (!arrayHas(next.seen, operationId)) next.seen[next.seen.length] = operationId;
      if (admittedDigest !== null) {
        const previous = nativeObjectHasOwn(next.admitted, operationId)
          ? next.admitted[operationId] : null;
        const observed = nativeObjectHasOwn(next.observed, operationId)
          ? next.observed[operationId] : null;
        if ((previous !== null && previous !== admittedDigest)
          || (observed !== null && observed !== admittedDigest)) {
          throw new Error("Conflicting local sync admission evidence");
        }
        next.admitted[operationId] = admittedDigest;
        delete next.observed[operationId];
      }
    });
  }
  async markSeenExact(operationId, expectedDigest, admittedDigest = null) {
    if (typeof operationId !== "string" || !regexTest(VALID_OPERATION_ID, operationId)
      || !stringStartsWith(operationId, "histrestore-")
      || typeof expectedDigest !== "string" || !regexTest(VALID_DIGEST, expectedDigest)
      || (admittedDigest !== null && (typeof admittedDigest !== "string"
        || !regexTest(VALID_DIGEST, admittedDigest) || admittedDigest !== expectedDigest))) {
      throw new Error("Invalid exact historical restore acknowledgement");
    }
    await this.commit((next) => {
      let index = -1;
      let matches = 0;
      for (let cursor = 0; cursor < next.pending.length; cursor += 1) {
        if (next.pending[cursor]?.operationId !== operationId) continue;
        index = cursor;
        matches += 1;
      }
      const pending = matches === 1 ? next.pending[index] : null;
      let alreadySeen = false;
      for (let cursor = 0; cursor < next.seen.length; cursor += 1) {
        if (next.seen[cursor] === operationId) alreadySeen = true;
      }
      const previous = nativeObjectHasOwn(next.admitted, operationId)
        ? next.admitted[operationId] : null;
      const observed = nativeObjectHasOwn(next.observed, operationId)
        ? next.observed[operationId] : null;
      const groups = nativeObjectValues(next.atomicSignedGroups);
      let isAtomicGroupMember = false;
      for (let cursor = 0; cursor < groups.length; cursor += 1) {
        if (groups[cursor].deleteId === operationId || groups[cursor].moveId === operationId) {
          isAtomicGroupMember = true;
        }
      }
      if (!pending || pending.operation !== "update" || !pending.authorization
        || signedEnvelopeDigest(pending) !== expectedDigest
        || alreadySeen
        || !nativeObjectHasOwn(next.committedSigned, operationId)
        || next.committedSigned[operationId] !== expectedDigest
        || (previous !== null && previous !== expectedDigest)
        || (observed !== null && observed !== expectedDigest)
        || isAtomicGroupMember) {
      throw nativeObjectAssign(new Error("Exact historical restore is no longer the pending signed envelope"), {
          code: "sync_journal_operation_conflict",
        });
      }
      // Rebuild by indexed assignment: a transport/readback callback may have
      // poisoned Array.prototype.splice/push. A failed seen append must never
      // remove the only durable copy of the original signed restore.
      const remainingPending = [];
      for (let cursor = 0; cursor < next.pending.length; cursor += 1) {
        if (cursor !== index) remainingPending[remainingPending.length] = next.pending[cursor];
      }
      next.pending = remainingPending;
      delete next.materializedRestore[operationId];
      delete next.restoreStaging[operationId];
      next.seen[next.seen.length] = operationId;
      let seenCount = 0;
      let pendingCount = 0;
      for (let cursor = 0; cursor < next.seen.length; cursor += 1) {
        if (next.seen[cursor] === operationId) seenCount += 1;
      }
      for (let cursor = 0; cursor < next.pending.length; cursor += 1) {
        if (next.pending[cursor]?.operationId === operationId) pendingCount += 1;
      }
      if (seenCount !== 1 || pendingCount !== 0) {
      throw nativeObjectAssign(new Error("Exact historical restore ACK partition was not applied"), {
          code: "sync_journal_operation_conflict",
        });
      }
      if (admittedDigest !== null) {
        next.admitted[operationId] = admittedDigest;
        delete next.observed[operationId];
      }
    });
  }
  async markSeenMany(entries) {
    // A DELETE+MOVE pair is ONE externally linearized operation. A crash
    // between two ordinary markSeen calls could leave just the MOVE pending;
    // its next replay would accidentally call the single-operation adapter.
    // Validate both first, then remove/ACK both in ONE durable JSON commit.
    if (!nativeArrayIsArray(entries) || entries.length !== 2) {
      throw new Error("Invalid atomic sync batch acknowledgement");
    }
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      if (!entry || typeof entry !== "object"
        || typeof entry.operationId !== "string"
        || !regexTest(VALID_OPERATION_ID, entry.operationId)
        || (entry.admittedDigest != null && (typeof entry.admittedDigest !== "string"
          || !regexTest(VALID_DIGEST, entry.admittedDigest)))) {
        throw new Error("Invalid atomic sync batch acknowledgement");
      }
    }
    if (entries[0].operationId === entries[1].operationId) {
      throw new Error("Invalid atomic sync batch acknowledgement");
    }
    await this.commit((next) => {
      const matched = [];
      const groupEntries = nativeObjectEntries(next.atomicSignedGroups);
      for (let index = 0; index < groupEntries.length; index += 1) {
        const event = groupEntries[index][0];
        const pair = groupEntries[index][1];
        let intersects = false;
        for (let cursor = 0; cursor < entries.length; cursor += 1) {
          if (entries[cursor].operationId === pair.deleteId
            || entries[cursor].operationId === pair.moveId) intersects = true;
        }
        if (intersects) matched[matched.length] = [event, pair];
      }
      for (let index = 0; index < matched.length; index += 1) {
        const pair = matched[index][1];
        if (entries[0].operationId !== pair.deleteId || entries[1].operationId !== pair.moveId) {
          throw new Error("Incomplete or reordered atomic signed WebDAV acknowledgement");
        }
      }
      for (let index = 0; index < entries.length; index += 1) {
        const { operationId, admittedDigest = null } = entries[index];
        const pending = findPendingById(next.pending, operationId);
        if (!pending || arrayHas(next.seen, operationId)) {
          throw new Error("Atomic sync batch acknowledgement requires both pending envelopes");
        }
        if (admittedDigest !== null) {
          const previous = nativeObjectHasOwn(next.admitted, operationId)
            ? next.admitted[operationId] : null;
          const observed = nativeObjectHasOwn(next.observed, operationId)
            ? next.observed[operationId] : null;
          if ((previous !== null && previous !== admittedDigest)
            || (observed !== null && observed !== admittedDigest)) {
            throw new Error("Conflicting atomic sync admission evidence");
          }
        }
      }
      const ids = new NativeSet();
      for (let index = 0; index < entries.length; index += 1) setAdd(ids, entries[index].operationId);
      const remainingPending = [];
      for (let index = 0; index < next.pending.length; index += 1) {
        if (!setHas(ids, next.pending[index]?.operationId)) {
          remainingPending[remainingPending.length] = next.pending[index];
        }
      }
      next.pending = remainingPending;
      for (let index = 0; index < entries.length; index += 1) {
        const { operationId, admittedDigest = null } = entries[index];
        next.seen[next.seen.length] = operationId;
        if (admittedDigest !== null) {
          next.admitted[operationId] = admittedDigest;
          delete next.observed[operationId];
        }
      }
      for (let index = 0; index < matched.length; index += 1) {
        delete next.atomicSignedGroups[matched[index][0]];
      }
    });
  }

  async update(operationId, patch) {
    await this.commit((next) => {
      const operation = findPendingById(next.pending, operationId);
      if (operation) nativeObjectAssign(operation, patch);
    });
  }

  async replace(operationId, replacement) {
    await this.commit((next) => {
      const index = findPendingIndexById(next.pending, operationId);
      if (index >= 0) next.pending[index] = { ...replacement };
    });
  }

  pending() {
    // The journal is an authority boundary for signed envelope bytes and
    // physical recovery witnesses. Returning only shallow copies exposed
    // nested authorization/metadata/identity objects that callers could
    // mutate without passing through the fsync-backed commit queue.
    return nativeJsonParse(safeJsonStringify(this.state.pending));
  }
  hasPendingEnvelope(operationId, digest) {
    if (typeof operationId !== "string" || !regexTest(VALID_OPERATION_ID, operationId)
      || typeof digest !== "string" || !regexTest(VALID_DIGEST, digest)) return false;
    let found = false;
    for (let index = 0; index < this.state.pending.length; index += 1) {
      const operation = this.state.pending[index];
      if (operation?.operationId !== operationId) continue;
      if (found || signedEnvelopeDigest(operation) !== digest) return false;
      found = true;
    }
    return found;
  }
  hasSeen(operationId) { return arrayHas(this.state.seen, operationId); }
  atomicSignedGroups() {
    return nativeJsonParse(safeJsonStringify(this.state.atomicSignedGroups || {}));
  }
  durableSignedReceiptDigest(operationId) {
    if (!regexTest(VALID_OPERATION_ID, operationId)) return null;
    const digest = this.state.committedSigned
      && nativeObjectHasOwn(this.state.committedSigned, operationId)
      ? this.state.committedSigned[operationId] : null;
    if (!regexTest(VALID_DIGEST, digest || "")) return null;
    const pending = findPendingById(this.state.pending, operationId);
    return (pending ? signedEnvelopeDigest(pending) === digest : this.hasSeen(operationId))
      ? digest : null;
  }
  hasDurableSignedReceipt(operationId) {
    return this.durableSignedReceiptDigest(operationId) !== null;
  }
  async recordRestoreMaterialization(operation) {
    const id = operation?.operationId;
    const digest = signedEnvelopeDigest(operation);
    if (typeof id !== "string" || !stringStartsWith(id, "histrestore-")
      || !regexTest(VALID_OPERATION_ID, id) || !regexTest(VALID_DIGEST, digest || "")) {
      throw new Error("Signed historical restore is required for materialization");
    }
    // Only the caller that has already completed _apply and its durable sync
    // snapshot may persist this LOCAL physical-materialization observation.
    // It is not new authorization, remote receipt or independent custody.
    await this.commit((next) => {
      const pending = findPendingById(next.pending, id);
      if (!pending || signedEnvelopeDigest(pending) !== digest
        || !nativeObjectHasOwn(next.committedSigned, id)
        || next.committedSigned[id] !== digest || arrayHas(next.seen, id)
        || (nativeObjectHasOwn(next.materializedRestore, id)
          && next.materializedRestore[id] !== digest)) {
        throw new Error("Restore materialization has no exact durable signed outbox");
      }
      next.materializedRestore[id] = digest;
      delete next.restoreStaging[id];
    });
  }

  async recordRestoreStagingIntent(operation, name) {
    const id = operation?.operationId;
    const digest = signedEnvelopeDigest(operation);
    if (typeof id !== "string" || !stringStartsWith(id, "histrestore-")
      || !regexTest(VALID_OPERATION_ID, id) || !regexTest(VALID_DIGEST, digest || "")) {
      throw new Error("Signed historical restore required for durable staging intent");
    }
    await this.commit((next) => {
      const pending = findPendingById(next.pending, id);
      const previous = nativeObjectHasOwn(next.restoreStaging, id)
        ? next.restoreStaging[id] : null;
      if (!pending || signedEnvelopeDigest(pending) !== digest
        || next.committedSigned[id] !== digest || arrayHas(next.seen, id)
        || nativeObjectHasOwn(next.materializedRestore, id)
        || previous) {
        throw new Error("Restore staging has no exact durable signed outbox");
      }
      next.restoreStaging[id] = { digest, name, dev: null, ino: null };
    });
  }
  async bindRestoreStagingIdentity(operation, name, identity) {
    const id = operation?.operationId;
    const digest = signedEnvelopeDigest(operation);
    if (typeof id !== "string" || !stringStartsWith(id, "histrestore-")
      || !regexTest(VALID_OPERATION_ID, id) || !regexTest(VALID_DIGEST, digest || "")
      || !identity || typeof identity.dev !== "string" || typeof identity.ino !== "string") {
      throw new Error("Invalid historical restore staging physical identity");
    }
    await this.commit((next) => {
      const intent = next.restoreStaging[id];
      const pending = findPendingById(next.pending, id);
      if (!intent || intent.digest !== digest || intent.name !== name
        || intent.dev !== null || intent.ino !== null
        || signedEnvelopeDigest(pending) !== digest
        || next.committedSigned[id] !== digest || arrayHas(next.seen, id)
        || nativeObjectHasOwn(next.materializedRestore, id)) {
        throw new Error("Historical restore staging identity has no durable intent");
      }
      next.restoreStaging[id] = { digest, name, dev: identity.dev, ino: identity.ino };
    });
  }
  async recordLinkedRestoreStagingIdentity(operation, name, before, linked) {
    const id = operation?.operationId;
    const digest = signedEnvelopeDigest(operation);
    if (typeof id !== "string" || !stringStartsWith(id, "histrestore-")
      || !regexTest(VALID_OPERATION_ID, id) || !regexTest(VALID_DIGEST, digest || "")
      || !before || !linked || before.dev !== linked.dev
      || typeof before.dev !== "string" || typeof before.ino !== "string"
      || typeof linked.ino !== "string") {
      throw new Error("Invalid linked historical restore stage identity");
    }
    await this.commit((next) => {
      const old = next.restoreStaging[id];
      const pending = findPendingById(next.pending, id);
      if (!old || old.digest !== digest || old.name !== name
        || old.dev !== before.dev || old.ino !== before.ino
        || signedEnvelopeDigest(pending) !== digest
        || next.committedSigned[id] !== digest
        || nativeObjectHasOwn(next.materializedRestore, id) || arrayHas(next.seen, id)) {
        throw new Error("Linked staging identity is not bound to exact signed outbox");
      }
      next.restoreStaging[id] = { digest, name, dev: linked.dev, ino: linked.ino };
    });
  }
  restoreStagingInfo(operation) {
    const id = operation?.operationId;
    const digest = signedEnvelopeDigest(operation);
    if (typeof id !== "string" || !regexTest(VALID_OPERATION_ID, id)
      || !regexTest(VALID_DIGEST, digest || "")
      || this.durableSignedReceiptDigest(id) !== digest
      || this.hasMaterializedRestore(operation)) return null;
    const staging = nativeObjectHasOwn(this.state.restoreStaging || {}, id)
      ? this.state.restoreStaging[id] : null;
    return staging?.digest === digest && typeof staging.name === "string"
      ? nativeObjectFreeze({ name: staging.name, dev: staging.dev, ino: staging.ino }) : null;
  }
  hasMaterializedRestore(operation) {
    const id = operation?.operationId;
    const digest = signedEnvelopeDigest(operation);
    return typeof id === "string" && stringStartsWith(id, "histrestore-")
      && regexTest(VALID_OPERATION_ID, id) && regexTest(VALID_DIGEST, digest || "")
      && nativeObjectHasOwn(this.state.materializedRestore || {}, id)
      && this.state.materializedRestore[id] === digest
      && this.durableSignedReceiptDigest(id) === digest;
  }
  assertCompatibleAdmission(operationId, digest) {
    if (!regexTest(VALID_OPERATION_ID, operationId) || !regexTest(VALID_DIGEST, digest)) {
      throw new Error("Invalid local sync admission evidence");
    }
    if ((nativeObjectHasOwn(this.state.admitted, operationId)
        && this.state.admitted[operationId] !== digest)
      || (nativeObjectHasOwn(this.state.observed, operationId)
        && this.state.observed[operationId] !== digest)) {
        throw nativeObjectAssign(new Error("Conflicting local sync admission evidence"),
        { code: "remote_authorization_rejected" });
    }
  }
  async observeAdmission(operationId, digest) {
    this.assertCompatibleAdmission(operationId, digest);
    if (this.hasLocalAdmission(operationId, digest)) return;
    await this.commit((next) => {
      const already = nativeObjectHasOwn(next.observed, operationId);
      if (!already && nativeObjectKeys(next.observed).length >= MAX_OBSERVATIONS) {
        throw new Error("Sync pre-observation journal capacity exceeded");
      }
      if (nativeObjectHasOwn(next.admitted, operationId) && next.admitted[operationId] !== digest) {
        throw new Error("Conflicting local sync admission evidence");
      }
      if (already && next.observed[operationId] !== digest) {
        throw new Error("Conflicting local sync admission evidence");
      }
      next.observed[operationId] = digest;
    });
  }
  hasLocalAdmission(operationId, digest) {
    return regexTest(VALID_OPERATION_ID, operationId) && regexTest(VALID_DIGEST, digest)
      && ((nativeObjectHasOwn(this.state.admitted, operationId)
        && this.state.admitted[operationId] === digest && this.hasSeen(operationId))
        || (nativeObjectHasOwn(this.state.observed, operationId)
          && this.state.observed[operationId] === digest));
  }
  async recover() { return this.pending(); }
}

module.exports = { SyncJournal, durableWrite, renameWithRetry, safeJsonStringify };
