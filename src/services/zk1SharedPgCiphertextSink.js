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

  async put(input = {}) {
    return this.#write(input, null);
  }

  async putSealed(input = {}) {
    const root = input.expectedRootHash;
    if (!root || (!Buffer.isBuffer(root) && !(root instanceof Uint8Array))
      || root.length !== 32 || typeof this.gate.sealCiphertextObject !== "function") fail();
    // This hash must be independently authenticated by the calling gateway
    // against the signed owner/device manifest. Never derive a purported
    // owner commitment by trusting the ciphertext sender alone.
    return this.#write(input, Buffer.from(root));
  }

  async #write({ scope, objectId, revision, digest, chunks, expectedChunkCount } = {}, root) {
    if (!scope || typeof scope !== "object" || Array.isArray(scope)
      || Reflect.ownKeys(scope).length !== 3
      || ["account_id", "compartment_id", "keyring_id"]
        .some((name) => !Object.hasOwn(scope, name))
      || !["account_id", "compartment_id", "keyring_id"].every((name) =>
        Buffer.isBuffer(scope[name]) || scope[name] instanceof Uint8Array)
      || scope.account_id.length !== 16 || scope.keyring_id.length !== 16
      || scope.compartment_id.length < 1 || scope.compartment_id.length > 128) fail();
    if (!chunks || !(typeof chunks[Symbol.iterator] === "function"
      || typeof chunks[Symbol.asyncIterator] === "function")
      || !Number.isSafeInteger(expectedChunkCount)
      || expectedChunkCount < 1 || expectedChunkCount > 4096
      || typeof objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(objectId)
      || Buffer.from(objectId, "base64url").toString("base64url") !== objectId
      || !Number.isSafeInteger(revision) || revision < 1
      || !(Buffer.isBuffer(digest) || digest instanceof Uint8Array)
      || digest.length !== 32) fail();
    // Typed-array fields are mutable across awaits: detach authoritative
    // owner-verified bytes before calling any asynchronous gateway adapter.
    const detachedScope = {
      account_id: Buffer.from(scope.account_id),
      compartment_id: Buffer.from(scope.compartment_id),
      keyring_id: Buffer.from(scope.keyring_id),
    };
    const workerId = crypto.randomBytes(16);
    const approvedDigest = Buffer.from(digest);
    const detached = () => ({ scope: {
      account_id: Buffer.from(detachedScope.account_id),
      compartment_id: Buffer.from(detachedScope.compartment_id),
      keyring_id: Buffer.from(detachedScope.keyring_id),
    }, objectId, revision, digest: Buffer.from(approvedDigest),
    action: "put", workerId: Buffer.from(workerId) });
    let receipt;
    try {
      // Lost START responses must use exactly the same worker and request.
      try { receipt = await this.gate.beginIoAdmission(detached()); }
      catch (_) { receipt = await this.gate.beginIoAdmission(detached()); }
      if (!receipt || !(receipt.admissionId instanceof Uint8Array)
        || receipt.admissionId.length !== 16
        || !Number.isSafeInteger(receipt.generation) || receipt.generation < 1
        || typeof receipt.proceed !== "boolean") fail();
    } catch (_) { fail(); }
    const sealedAdmissionId = Buffer.from(receipt.admissionId);
    const generation = receipt.generation;
    const stop = () => ({ scope: detached().scope,
      admissionId: Buffer.from(sealedAdmissionId), workerId: Buffer.from(workerId) });
    try {
      if (!receipt.proceed) fail();
      const authorized = () => ({ ...detached(),
        admissionId: Buffer.from(sealedAdmissionId), generation });
      let count = 0;
      for await (const data of chunks) {
        if ((!Buffer.isBuffer(data) && !(data instanceof Uint8Array))
          || data.length < 1 || data.length > 4 * 1024 * 1024
          || count >= expectedChunkCount) fail();
        const bytes = Buffer.from(data);
        try {
          // Physical PostgreSQL INSERT + head/generation check are one
          // transaction. A lost response may hide a committed chunk; retry
          // the exact bytes/index under the SAME admission, never a new one.
          let result;
          try { result = await this.gate.putCiphertextChunk(authorized(), count, Buffer.from(bytes)); }
          catch (_) { result = await this.gate.putCiphertextChunk(authorized(), count, Buffer.from(bytes)); }
          if (!result || typeof result.stored !== "boolean"
            || Reflect.ownKeys(result).length !== 1) fail();
        } catch (_) { fail(); }
        count += 1;
      }
      // The gateway must provide expectedChunkCount from independently
      // authenticated object metadata; partial streams are never successes.
      if (count !== expectedChunkCount) fail();
      if (root) {
        let sealed;
        try { sealed = await this.gate.sealCiphertextObject(authorized(), count, Buffer.from(root)); }
        catch (_) { sealed = await this.gate.sealCiphertextObject(authorized(), count, Buffer.from(root)); }
        if (!sealed || sealed.status !== "SEALED" || sealed.chunkCount !== count
          || Reflect.ownKeys(sealed).length !== 2) fail();
        return { status: "SEALED", chunkCount: count };
      }
      return { chunkCount: count };
    } finally {
      try {
        let receipt;
        try { receipt = await this.gate.finishIoAdmission(stop()); }
        catch (_) { receipt = await this.gate.finishIoAdmission(stop()); }
        if (!receipt || receipt.status !== "FINISHED"
          || Reflect.ownKeys(receipt).length !== 1) fail();
      } catch (_) {
        // Never call an uncertain FINISH a success: the durable gate remains
        // closed until the trusted worker is independently reconciled.
        fail();
      }
    }
  }
}

module.exports = { Zk1SharedPgCiphertextSink };
