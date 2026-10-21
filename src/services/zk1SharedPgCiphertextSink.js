"use strict";

// Trusted isolated PostgreSQL ciphertext WRITE adapter. The invoking gateway
// must authenticate/authorize the user and cryptographically validate the
// exact device/scope/keyring request before calling put(). This layer provides
// physical SQL write fencing, NOT device authorization or network GET/egress.
const crypto = require("node:crypto");

function fail() {
  const error = new Error("ZK_GATE_SINK_UNAVAILABLE");
  error.code = "ZK_GATE_SINK_UNAVAILABLE";
  throw error;
}

class Zk1SharedPgCiphertextSink {
  constructor({ gateClient } = {}) {
    if (!gateClient || ["beginIoAdmission", "putCiphertextChunk", "finishIoAdmission"]
      .some((method) => typeof gateClient[method] !== "function")) fail();
    this.gate = gateClient;
  }

  async put({ scope, objectId, revision, digest, chunks } = {}) {
    if (!chunks || !(typeof chunks[Symbol.iterator] === "function"
      || typeof chunks[Symbol.asyncIterator] === "function")
      || typeof objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(objectId)
      || Buffer.from(objectId, "base64url").toString("base64url") !== objectId
      || !Number.isSafeInteger(revision) || revision < 1
      || !(Buffer.isBuffer(digest) || digest instanceof Uint8Array)
      || digest.length !== 32) fail();
    const workerId = crypto.randomBytes(16);
    const operation = { scope, objectId, revision, digest: Buffer.from(digest),
      action: "put", workerId };
    let receipt;
    try {
      // Lost START responses must use exactly the same worker and request.
      try { receipt = await this.gate.beginIoAdmission(operation); }
      catch (_) { receipt = await this.gate.beginIoAdmission(operation); }
      if (!receipt || !(receipt.admissionId instanceof Uint8Array)
        || receipt.admissionId.length !== 16
        || !Number.isSafeInteger(receipt.generation) || receipt.generation < 1
        || typeof receipt.proceed !== "boolean") fail();
    } catch (_) { fail(); }
    const stop = { scope, admissionId: receipt.admissionId, workerId };
    try {
      if (!receipt.proceed) fail();
      const authorized = { ...operation,
        admissionId: receipt.admissionId, generation: receipt.generation };
      let count = 0;
      for await (const data of chunks) {
        if ((!Buffer.isBuffer(data) && !(data instanceof Uint8Array))
          || data.length < 1 || data.length > 4 * 1024 * 1024 || count >= 4096) fail();
        const bytes = Buffer.from(data);
        try {
          // Physical PostgreSQL INSERT + head/generation check are one
          // transaction. A lost response may hide a committed chunk; retry
          // the exact bytes/index under the SAME admission, never a new one.
          try { await this.gate.putCiphertextChunk(authorized, count, bytes); }
          catch (_) { await this.gate.putCiphertextChunk(authorized, count, bytes); }
        } catch (_) { fail(); }
        count += 1;
      }
      if (count === 0) fail();
      return { chunkCount: count };
    } finally {
      try {
        try { await this.gate.finishIoAdmission(stop); }
        catch (_) { await this.gate.finishIoAdmission(stop); }
      } catch (_) {
        // Never call an uncertain FINISH a success: the durable gate remains
        // closed until the trusted worker is independently reconciled.
        fail();
      }
    }
  }
}

module.exports = { Zk1SharedPgCiphertextSink };
