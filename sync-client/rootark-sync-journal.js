"use strict";

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

const JOURNAL_VERSION = 1;
const MAX_OBSERVATIONS = 10000;
const VALID_OPERATION_ID = /^[A-Za-z0-9._:-]{1,160}$/;
const VALID_DIGEST = /^[0-9a-f]{64}$/;
const WINDOWS_RENAME_MAX_ATTEMPTS = 3;
const WINDOWS_RENAME_RETRY_DELAY_MS = 10;

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
  const temporary = `${filePath}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  const handle = await fsp.open(temporary, "w", 0o600);
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
      admitted: Object.create(null), observed: Object.create(null) };
    this.queue = Promise.resolve();
  }

  async open() {
    try {
      this.state = JSON.parse(await fsp.readFile(this.filePath, "utf8"));
      if (this.state.version !== JOURNAL_VERSION || !Array.isArray(this.state.pending) || !Array.isArray(this.state.seen)) throw new Error("Invalid sync journal");
      // Legacy operation-ID-only receipts are not proof of prior admission.
      // The new exact signed-envelope fingerprints must be independently
      // observed while the device's write authorization is still fresh.
      if (this.state.admitted === undefined) this.state.admitted = Object.create(null);
      if (this.state.observed === undefined) this.state.observed = Object.create(null);
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
      await durableWrite(this.filePath, this.state);
    }
    return this;
  }

  async commit(mutator) {
    const transaction = this.queue.then(async () => {
      const next = { version: JOURNAL_VERSION, pending: [...this.state.pending],
        seen: [...this.state.seen],
        admitted: Object.assign(Object.create(null), this.state.admitted),
        observed: Object.assign(Object.create(null), this.state.observed) };
      await mutator(next);
      next.pending = next.pending.slice(-10000);
      next.seen = next.seen.slice(-10000);
      const retained = new Set(next.seen);
      for (const id of Object.keys(next.admitted)) {
        if (!retained.has(id)) delete next.admitted[id];
      }
      try {
        await durableWrite(this.filePath, next);
      } catch (error) {
        if (error.journalCommitted) this.state = next;
        throw error;
      }
      this.state = next;
    });
    this.queue = transaction.catch(() => {});
    return transaction;
  }

  async enqueue(operation) {
    if (!operation?.operationId) throw new Error("Journal operationId required");
    await this.commit((next) => {
      if (!next.seen.includes(operation.operationId) && !next.pending.some((item) => item.operationId === operation.operationId)) next.pending.push(operation);
    });
    return operation;
  }

  async enqueueMany(operations) {
    if (!Array.isArray(operations) || operations.some((operation) => !operation?.operationId)) throw new Error("Journal operations require operationId");
    const operationIds = operations.map((operation) => operation.operationId);
    if (new Set(operationIds).size !== operationIds.length) throw new Error("Journal batch operationIds must be unique");
    await this.commit((next) => {
      const additions = operations.filter((operation) => !next.seen.includes(operation.operationId) && !next.pending.some((item) => item.operationId === operation.operationId));
      if (next.pending.length + additions.length > 10000) throw new Error("Sync journal capacity exceeded");
      next.pending.push(...additions);
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

  pending() { return this.state.pending.map((operation) => ({ ...operation })); }
  hasSeen(operationId) { return this.state.seen.includes(operationId); }
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
