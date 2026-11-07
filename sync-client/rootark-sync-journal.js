"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { canonicalJson } = require("./rootark-sync-protocol");

const JOURNAL_VERSION = 1;
const MAX_PENDING = 10000;
const MAX_OBSERVATIONS = 10000;
// Signed receipts cover both durable pending work and the retained seen window.
// Each partition has its own limit; combining them must not stall a full seen
// history when a new signed operation enters an otherwise empty outbox.
const MAX_SIGNED_RECEIPTS = MAX_PENDING + MAX_OBSERVATIONS;
const VALID_OPERATION_ID = /^[A-Za-z0-9._:-]{1,160}$/;
const VALID_DIGEST = /^[0-9a-f]{64}$/;
const WINDOWS_RENAME_MAX_ATTEMPTS = 3;
const WINDOWS_RENAME_RETRY_DELAY_MS = 10;

function assertSamePendingEnvelope(existing, incoming) {
  // An operationId is an idempotency key, not permission to replace or drop
  // different signed bytes. Compare canonical JSON so key ordering is inert.
  if (canonicalJson(existing) !== canonicalJson(incoming)) {
    throw Object.assign(new Error("Conflicting sync journal operationId"), {
      code: "sync_journal_operation_conflict",
    });
  }
}

function signedEnvelopeDigest(operation) {
  if (!operation || typeof operation !== "object"
    || !Object.hasOwn(operation, "authorization")) return null;
  return crypto.createHash("sha256").update(canonicalJson(operation)).digest("hex");
}

function signedWebDavEventId(operation) {
  if (!operation || typeof operation !== "object"
    || !Object.hasOwn(operation, "authorization")
    || !["delete", "move"].includes(operation.operation)
    || typeof operation.metadata?.path !== "string") return null;
  const match = /^webdav-(.+)-([a-f0-9]{24})$/.exec(operation.operationId || "");
  if (!match || match[1].length > 100) return null;
  const expected = crypto.createHash("sha256")
    .update(`${operation.operation}:${operation.metadata.path}`)
    .digest("hex").slice(0, 24);
  return expected === match[2] ? match[1] : null;
}

function atomicSignedWebDavPair(operations) {
  if (!Array.isArray(operations) || operations.length !== 2) return null;
  const [deleted, moved] = operations;
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
  if (!groups || typeof groups !== "object" || Array.isArray(groups)
    || Object.keys(groups).length > MAX_OBSERVATIONS) return true;
  const records = new Map(pending.map((entry) => [entry.operationId, entry]));
  const seenSet = new Set(seen);
  const members = new Set();
  for (const [event, pair] of Object.entries(groups)) {
    if (!/^[A-Za-z0-9._:-]{1,100}$/.test(event)
      || !pair || typeof pair !== "object" || Array.isArray(pair)
      || Object.keys(pair).length !== 2
      || !Object.hasOwn(pair, "deleteId") || !Object.hasOwn(pair, "moveId")
      || !VALID_OPERATION_ID.test(pair.deleteId || "")
      || !VALID_OPERATION_ID.test(pair.moveId || "")
      || pair.deleteId === pair.moveId || members.has(pair.deleteId)
      || members.has(pair.moveId) || seenSet.has(pair.deleteId)
      || seenSet.has(pair.moveId)) return true;
    members.add(pair.deleteId);
    members.add(pair.moveId);
    const actual = atomicSignedWebDavPair([records.get(pair.deleteId), records.get(pair.moveId)]);
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
  const previous = Object.hasOwn(next.committedSigned, operation.operationId)
    ? next.committedSigned[operation.operationId] : null;
  if (previous && previous !== digest) {
    throw new Error("Conflicting durable signed outbox receipt");
  }
  if (!previous && Object.keys(next.committedSigned).length >= MAX_SIGNED_RECEIPTS) {
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
  const original = Object.hasOwn(next.committedSigned, operation.operationId)
    ? next.committedSigned[operation.operationId] : null;
  if ((original !== null || received !== null) && original !== received) {
    throw Object.assign(new Error("Conflicting or unauthenticated historical signed operationId"), {
      code: "sync_journal_operation_conflict",
    });
  }
}

function invalidPendingSignedReceiptWitness(pending) {
  return pending.some((operation) => {
    if (!operation || typeof operation !== "object") return false;
    const hasReceipts = Object.hasOwn(operation, "signedOutboxReceipts");
    const hasMoveBytes = Object.hasOwn(operation, "moveBytes");
    const hasMoveDigest = Object.hasOwn(operation, "moveSha256");
    // An authenticated MOVE can be acknowledged after restart only if its
    // signed receipt and its independently verified physical content witness
    // were committed together. Reject partial/legacy witness pairs at open
    // and before commit; do not wait for a late recovery phase to discover it.
    if (operation.kind === "move" && (hasReceipts || hasMoveBytes || hasMoveDigest)) {
      if (!hasReceipts || !hasMoveBytes || !hasMoveDigest
        || !Number.isSafeInteger(operation.moveBytes)
        || operation.moveBytes < 0 || !VALID_DIGEST.test(operation.moveSha256)) return true;
    } else if (hasMoveBytes || hasMoveDigest) return true;
    if (!hasReceipts) return false;
    const receipts = operation.signedOutboxReceipts;
    if (!Array.isArray(receipts) || !receipts.length || receipts.length > 4) return true;
    const ids = new Set();
    for (const receipt of receipts) {
      if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)
        || typeof receipt.operationId !== "string"
        || !VALID_OPERATION_ID.test(receipt.operationId)
        || typeof receipt.digest !== "string" || !VALID_DIGEST.test(receipt.digest)
        || ids.has(receipt.operationId)) return true;
      ids.add(receipt.operationId);
    }
    return false;
  });
}

function isUnsupportedDirectorySync(error) {
  return ["EINVAL", "ENOTSUP"].includes(error?.code)
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
      await new Promise((resolve) => setTimeout(resolve, WINDOWS_RENAME_RETRY_DELAY_MS));
    }
  }
}

async function durableWrite(filePath, value) {
  const directory = path.dirname(filePath);
  await fsp.mkdir(directory, { recursive: true });
  // The journal directory can contain crash leftovers. A predictable
  // temporary name combined with "w" would truncate a preexisting entry
  // before its ownership/identity was checked. Never overwrite a collision:
  // cryptographically randomize the name and require O_EXCL creation.
  const temporary = `${filePath}.tmp-${process.pid}-${crypto.randomUUID()}`;
  const handle = await fsp.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await renameWithRetry(temporary, filePath);
  } catch (error) {
    await fsp.unlink(temporary).catch(() => {});
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
      admitted: Object.create(null), observed: Object.create(null),
      committedSigned: Object.create(null), atomicSignedGroups: Object.create(null) };
    this.queue = Promise.resolve();
  }

  async open({ requireExisting = false } = {}) {
    try {
      this.state = JSON.parse(await fsp.readFile(this.filePath, "utf8"));
      if (this.state.version !== JOURNAL_VERSION || !Array.isArray(this.state.pending)
        || this.state.pending.length > MAX_PENDING || !Array.isArray(this.state.seen)
        || this.state.seen.length > MAX_OBSERVATIONS) {
        throw new Error("Invalid sync journal");
      }
      const pendingIds = this.state.pending.map((item) =>
        item && typeof item === "object" && !Array.isArray(item) ? item.operationId : null);
      const pendingIdSet = new Set(pendingIds);
      const seenIdSet = new Set(this.state.seen);
      if (pendingIds.some((id) => typeof id !== "string" || !VALID_OPERATION_ID.test(id))
        || this.state.seen.some((id) => typeof id !== "string" || !VALID_OPERATION_ID.test(id))
        || pendingIdSet.size !== pendingIds.length
        || seenIdSet.size !== this.state.seen.length
        || this.state.seen.some((id) => pendingIdSet.has(id))
        || invalidPendingSignedReceiptWitness(this.state.pending)) {
        // More than one pending record per operationId would allow the
        // first-match update()/markSeen() path to silently discard another
        // physical mutation. An ID may be pending OR seen, never both.
        throw new Error("Invalid sync journal operationId partition");
      }
      // Legacy operation-ID-only receipts are not proof of prior admission.
      // The new exact signed-envelope fingerprints must be independently
      // observed while the device's write authorization is still fresh.
      if (this.state.admitted === undefined) this.state.admitted = Object.create(null);
      if (this.state.observed === undefined) this.state.observed = Object.create(null);
      if (this.state.committedSigned === undefined) this.state.committedSigned = Object.create(null);
      if (this.state.atomicSignedGroups === undefined) this.state.atomicSignedGroups = Object.create(null);
      if (invalidAtomicSignedGroups(this.state.atomicSignedGroups, this.state.pending, this.state.seen)) {
        throw new Error("Invalid atomic signed WebDAV journal group");
      }
      const pendingById = new Map(this.state.pending.map((entry) =>
        [entry.operationId, entry]));
      if (!this.state.committedSigned || typeof this.state.committedSigned !== "object"
        || Array.isArray(this.state.committedSigned)
        || Object.entries(this.state.committedSigned).length > MAX_SIGNED_RECEIPTS
        || Object.entries(this.state.committedSigned).some(([id, digest]) =>
          !VALID_OPERATION_ID.test(id) || !VALID_DIGEST.test(digest)
          || (!seenIdSet.has(id)
            && signedEnvelopeDigest(pendingById.get(id)) !== digest))) {
        throw new Error("Invalid durable signed outbox receipt journal");
      }
      if (!this.state.admitted || typeof this.state.admitted !== "object"
        || Array.isArray(this.state.admitted)
        || Object.entries(this.state.admitted).length > MAX_OBSERVATIONS
        || Object.entries(this.state.admitted).some(([id, digest]) =>
          !VALID_OPERATION_ID.test(id) || typeof digest !== "string"
          || !VALID_DIGEST.test(digest) || !this.state.seen.includes(id))) {
        throw new Error("Invalid previously admitted sync envelope journal");
      }
      if (!this.state.observed || typeof this.state.observed !== "object"
        || Array.isArray(this.state.observed)
        || Object.entries(this.state.observed).length > MAX_OBSERVATIONS
        || Object.entries(this.state.observed).some(([id, digest]) =>
          !VALID_OPERATION_ID.test(id) || typeof digest !== "string"
          || !VALID_DIGEST.test(digest)
          || (Object.hasOwn(this.state.admitted, id) && this.state.admitted[id] !== digest))) {
        throw new Error("Invalid previously observed sync envelope journal");
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
    const transaction = this.queue.then(async () => {
      // Mutation callbacks (notably update()) edit pending entry objects.
      // A shallow array copy would mutate the live in-memory state BEFORE
      // the fsync-backed commit succeeds, manufacturing a phase which did
      // not become durable when a later disk write fails.
      const next = { version: JOURNAL_VERSION,
        pending: JSON.parse(JSON.stringify(this.state.pending)),
        seen: [...this.state.seen],
        admitted: Object.assign(Object.create(null), this.state.admitted),
        observed: Object.assign(Object.create(null), this.state.observed),
        committedSigned: Object.assign(Object.create(null), this.state.committedSigned),
        atomicSignedGroups: Object.assign(Object.create(null), this.state.atomicSignedGroups) };
      await mutator(next);
      // Pending mutations are durable work. Silently keeping the newest items
      // would permanently discard the oldest unsigned or signed operation.
      if (next.pending.length > MAX_PENDING) throw new Error("Sync journal capacity exceeded");
      if (invalidPendingSignedReceiptWitness(next.pending)) {
        throw new Error("Invalid protected WebDAV signed receipt binding");
      }
      next.seen = next.seen.slice(-10000);
      const retained = new Set(next.seen);
      for (const id of Object.keys(next.admitted)) {
        if (!retained.has(id)) delete next.admitted[id];
      }
      const pendingIds = new Set(next.pending.map((operation) => operation.operationId));
      for (const id of Object.keys(next.committedSigned)) {
        if (!retained.has(id) && !pendingIds.has(id)) delete next.committedSigned[id];
      }
      // update()/replace() accept caller-provided patches. Even if enqueue()
      // rejects malformed IDs, a later patch must not persist two pending
      // entries under one ID, overlap an acknowledged ID or detach a signed
      // receipt from the exact bytes it records. Validate the *resulting*
      // transaction before durableWrite, not only at cold open: otherwise a
      // bridge could ACK a write then be unable to reopen its own journal.
      const ids = next.pending.map((entry) =>
        entry && typeof entry === "object" && !Array.isArray(entry)
          ? entry.operationId : null);
      const seen = new Set(next.seen);
      if (ids.some((id) => typeof id !== "string" || !VALID_OPERATION_ID.test(id))
        || seen.size !== next.seen.length
        || next.seen.some((id) => typeof id !== "string" || !VALID_OPERATION_ID.test(id))
        || new Set(ids).size !== ids.length
        || ids.some((id) => seen.has(id))) {
        throw new Error("Invalid sync journal operationId partition");
      }
      if (invalidAtomicSignedGroups(next.atomicSignedGroups, next.pending, next.seen)) {
        throw new Error("Invalid atomic signed WebDAV journal group");
      }
      const pendingById = new Map(next.pending.map((entry) => [entry.operationId, entry]));
      if (Object.entries(next.committedSigned).length > MAX_SIGNED_RECEIPTS
        || Object.entries(next.committedSigned).some(([id, digest]) =>
        !VALID_OPERATION_ID.test(id) || !VALID_DIGEST.test(digest)
        || (!seen.has(id) && signedEnvelopeDigest(pendingById.get(id)) !== digest))) {
        throw new Error("Invalid durable signed outbox receipt journal");
      }
      // mutator() may have inserted references from the caller's envelope,
      // batch or patch. Make the exact JSON value an immutable commit snapshot:
      // later caller mutations must not change memory-only pending bytes while
      // the on-disk journal and the signed-receipt digest remain unchanged.
      const persisted = JSON.parse(JSON.stringify(next));
      try {
        await durableWrite(this.filePath, persisted);
      } catch (error) {
        if (error.journalCommitted) this.state = persisted;
        throw error;
      }
      this.state = persisted;
    });
    this.queue = transaction.catch(() => {});
    return transaction;
  }

  async enqueue(operation) {
    if (typeof operation?.operationId !== "string"
      || !VALID_OPERATION_ID.test(operation.operationId)) {
      throw new Error("Valid journal operationId required");
    }
    await this.commit((next) => {
      const previous = next.pending.find((item) => item.operationId === operation.operationId);
      if (previous) {
        assertSamePendingEnvelope(previous, operation);
        recordSignedOutboxReceipt(next, operation);
      } else if (!next.seen.includes(operation.operationId)) {
        if (next.pending.length >= MAX_PENDING) throw new Error("Sync journal capacity exceeded");
        next.pending.push(operation);
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
    if (!digest || !VALID_OPERATION_ID.test(operation.operationId)) {
      throw new Error("A signed outbox operation is required for cancellation");
    }
    await this.commit((next) => {
      const index = next.pending.findIndex((item) => item.operationId === operation.operationId);
      if (index < 0 || signedEnvelopeDigest(next.pending[index]) !== digest
        || next.seen.includes(operation.operationId)
        || Object.hasOwn(next.admitted, operation.operationId)
        || !Object.hasOwn(next.committedSigned, operation.operationId)
        || next.committedSigned[operation.operationId] !== digest
        || Object.values(next.atomicSignedGroups).some((group) =>
          group.deleteId === operation.operationId || group.moveId === operation.operationId)) {
        throw new Error("Cannot discard an ineligible signed outbox operation");
      }
      next.pending.splice(index, 1);
      delete next.committedSigned[operation.operationId];
      delete next.observed[operation.operationId];
    });
  }

  async enqueueMany(operations) {
    if (!Array.isArray(operations) || operations.some((operation) =>
      typeof operation?.operationId !== "string"
      || !VALID_OPERATION_ID.test(operation.operationId))) {
      throw new Error("Journal operations require valid operationId");
    }
    const operationIds = operations.map((operation) => operation.operationId);
    if (new Set(operationIds).size !== operationIds.length) throw new Error("Journal batch operationIds must be unique");
    const atomicPair = atomicSignedWebDavPair(operations);
    const signedEvents = operations.map(signedWebDavEventId).filter(Boolean);
    // An unsigned generic batch may remain a legacy operation set, but a
    // multi-entry batch containing the deterministic signed WebDAV MOVE must
    // not evade the durable DELETE-before-MOVE group marker via reordered,
    // missing, or extra companions. Reject BEFORE persisting either side.
    if (!atomicPair && operations.length > 1 && operations.some((operation) =>
      operation.operation === "move" && signedWebDavEventId(operation))) {
      throw new Error("Invalid atomic signed WebDAV batch membership");
    }
    if (signedEvents.length > 1 && !atomicPair) {
      throw new Error("Ambiguous signed WebDAV batch identity");
    }
    await this.commit((next) => {
      const pendingById = new Map(next.pending.map((item) => [item.operationId, item]));
      const additions = [];
      for (const operation of operations) {
        const previous = pendingById.get(operation.operationId);
        if (previous) {
          assertSamePendingEnvelope(previous, operation);
          recordSignedOutboxReceipt(next, operation);
        } else if (!next.seen.includes(operation.operationId)) {
          additions.push(operation);
          recordSignedOutboxReceipt(next, operation);
        } else {
          assertEquivalentSeenEnvelope(next, operation);
        }
      }
      if (next.pending.length + additions.length > MAX_PENDING) throw new Error("Sync journal capacity exceeded");
      next.pending.push(...additions);
      if (atomicPair) {
        if (operationIds.some((id) => next.seen.includes(id))) {
          throw new Error("Cannot reassemble a partially seen atomic signed WebDAV batch");
        }
        const prior = Object.hasOwn(next.atomicSignedGroups, atomicPair.event)
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
    if (!VALID_OPERATION_ID.test(operationId)
      || (admittedDigest !== null && (typeof admittedDigest !== "string"
        || !VALID_DIGEST.test(admittedDigest)))) {
      throw new Error("Invalid local sync admission evidence");
    }
    await this.commit((next) => {
      if (Object.values(next.atomicSignedGroups).some((pair) =>
        pair.deleteId === operationId || pair.moveId === operationId)) {
        throw new Error("Atomic signed WebDAV pair requires markSeenMany");
      }
      next.pending = next.pending.filter((item) => item.operationId !== operationId);
      if (!next.seen.includes(operationId)) next.seen.push(operationId);
      if (admittedDigest !== null) {
        const previous = Object.hasOwn(next.admitted, operationId)
          ? next.admitted[operationId] : null;
        const observed = Object.hasOwn(next.observed, operationId)
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
  async markSeenMany(entries) {
    // A DELETE+MOVE pair is ONE externally linearized operation. A crash
    // between two ordinary markSeen calls could leave just the MOVE pending;
    // its next replay would accidentally call the single-operation adapter.
    // Validate both first, then remove/ACK both in ONE durable JSON commit.
    if (!Array.isArray(entries) || entries.length !== 2
      || entries.some((entry) => !entry || typeof entry !== "object"
        || typeof entry.operationId !== "string"
        || !VALID_OPERATION_ID.test(entry.operationId)
        || (entry.admittedDigest != null && (typeof entry.admittedDigest !== "string"
          || !VALID_DIGEST.test(entry.admittedDigest))))
      || entries[0].operationId === entries[1].operationId) {
      throw new Error("Invalid atomic sync batch acknowledgement");
    }
    await this.commit((next) => {
      const matched = Object.entries(next.atomicSignedGroups).filter(([, pair]) =>
        entries.some((entry) => entry.operationId === pair.deleteId
          || entry.operationId === pair.moveId));
      if (matched.some(([, pair]) => entries[0].operationId !== pair.deleteId
        || entries[1].operationId !== pair.moveId)) {
        throw new Error("Incomplete or reordered atomic signed WebDAV acknowledgement");
      }
      for (const { operationId, admittedDigest = null } of entries) {
        const pending = next.pending.find((item) => item.operationId === operationId);
        if (!pending || next.seen.includes(operationId)) {
          throw new Error("Atomic sync batch acknowledgement requires both pending envelopes");
        }
        if (admittedDigest !== null) {
          const previous = Object.hasOwn(next.admitted, operationId)
            ? next.admitted[operationId] : null;
          const observed = Object.hasOwn(next.observed, operationId)
            ? next.observed[operationId] : null;
          if ((previous !== null && previous !== admittedDigest)
            || (observed !== null && observed !== admittedDigest)) {
            throw new Error("Conflicting atomic sync admission evidence");
          }
        }
      }
      const ids = new Set(entries.map((entry) => entry.operationId));
      next.pending = next.pending.filter((entry) => !ids.has(entry.operationId));
      for (const { operationId, admittedDigest = null } of entries) {
        next.seen.push(operationId);
        if (admittedDigest !== null) {
          next.admitted[operationId] = admittedDigest;
          delete next.observed[operationId];
        }
      }
      for (const [event] of matched) delete next.atomicSignedGroups[event];
    });
  }

  async update(operationId, patch) {
    await this.commit((next) => {
      const operation = next.pending.find((item) => item.operationId === operationId);
      if (operation) Object.assign(operation, patch);
    });
  }

  async replace(operationId, replacement) {
    await this.commit((next) => {
      const index = next.pending.findIndex((item) => item.operationId === operationId);
      if (index >= 0) next.pending[index] = { ...replacement };
    });
  }

  pending() {
    // The journal is an authority boundary for signed envelope bytes and
    // physical recovery witnesses. Returning only shallow copies exposed
    // nested authorization/metadata/identity objects that callers could
    // mutate without passing through the fsync-backed commit queue.
    return JSON.parse(JSON.stringify(this.state.pending));
  }
  hasSeen(operationId) { return this.state.seen.includes(operationId); }
  atomicSignedGroups() {
    return JSON.parse(JSON.stringify(this.state.atomicSignedGroups || {}));
  }
  durableSignedReceiptDigest(operationId) {
    if (!VALID_OPERATION_ID.test(operationId)) return null;
    const digest = this.state.committedSigned
      && Object.hasOwn(this.state.committedSigned, operationId)
      ? this.state.committedSigned[operationId] : null;
    if (!VALID_DIGEST.test(digest || "")) return null;
    const pending = this.state.pending.find((entry) => entry.operationId === operationId);
    return (pending ? signedEnvelopeDigest(pending) === digest : this.hasSeen(operationId))
      ? digest : null;
  }
  hasDurableSignedReceipt(operationId) {
    return this.durableSignedReceiptDigest(operationId) !== null;
  }
  assertCompatibleAdmission(operationId, digest) {
    if (!VALID_OPERATION_ID.test(operationId) || !VALID_DIGEST.test(digest)) {
      throw new Error("Invalid local sync admission evidence");
    }
    if ((Object.hasOwn(this.state.admitted, operationId)
        && this.state.admitted[operationId] !== digest)
      || (Object.hasOwn(this.state.observed, operationId)
        && this.state.observed[operationId] !== digest)) {
      throw Object.assign(new Error("Conflicting local sync admission evidence"),
        { code: "remote_authorization_rejected" });
    }
  }
  async observeAdmission(operationId, digest) {
    this.assertCompatibleAdmission(operationId, digest);
    if (this.hasLocalAdmission(operationId, digest)) return;
    await this.commit((next) => {
      const already = Object.hasOwn(next.observed, operationId);
      if (!already && Object.keys(next.observed).length >= MAX_OBSERVATIONS) {
        throw new Error("Sync pre-observation journal capacity exceeded");
      }
      if (Object.hasOwn(next.admitted, operationId) && next.admitted[operationId] !== digest) {
        throw new Error("Conflicting local sync admission evidence");
      }
      if (already && next.observed[operationId] !== digest) {
        throw new Error("Conflicting local sync admission evidence");
      }
      next.observed[operationId] = digest;
    });
  }
  hasLocalAdmission(operationId, digest) {
    return VALID_OPERATION_ID.test(operationId) && VALID_DIGEST.test(digest)
      && ((Object.hasOwn(this.state.admitted, operationId)
        && this.state.admitted[operationId] === digest && this.hasSeen(operationId))
        || (Object.hasOwn(this.state.observed, operationId)
          && this.state.observed[operationId] === digest));
  }
  async recover() { return this.pending(); }
}

module.exports = { SyncJournal, durableWrite, renameWithRetry };
