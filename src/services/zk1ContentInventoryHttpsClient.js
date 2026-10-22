"use strict";

// Fixed-endpoint client for the experimental inventory transport. HTTP status
// is never a content-authority decision; snapshots and terminal proofs are
// independently checked with the separately pinned Ed25519 key.
const https = require("node:https");
const tls = require("node:tls");
const crypto = require("node:crypto");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");

const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const B64U = /^[A-Za-z0-9_-]+$/;
const MAX_METADATA_REQUEST_BYTES = 4096;
const MAX_APPEND_REQUEST_BYTES = 8192;
const MAX_SNAPSHOT_BASE64_BYTES = 3 * 1024 * 1024;
const MAX_SNAPSHOT_RESPONSE_BYTES = MAX_SNAPSHOT_BASE64_BYTES + 16 * 1024;
const MAX_SMALL_RESPONSE_BYTES = 16 * 1024;
const SCOPE_FIELDS = Object.freeze(["account_id", "compartment_id", "keyring_id"]);
const OPERATION_FIELDS = Object.freeze([
  "operation_id", "expected_sequence", "expected_root", "object_id", "revision", "epoch",
  "ciphertext_sha256",
]);
const PENDING_REASONS = new Set([
  "EXPECTED_HEAD_CHANGED", "INVENTORY_LIMIT", "INVALID_CHRONOLOGY",
  "INVALID_CATALOG_TRANSITION", "UNRESOLVED_INTENT", "SEAL_UNCERTAIN",
]);

function fail() {
  const error = new Error("INVENTORY_HTTP_UNAVAILABLE");
  error.code = "INVENTORY_HTTP_UNAVAILABLE";
  throw error;
}

function exact(value, required, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const keys = Reflect.ownKeys(value);
  if (required.some((name) => !keys.includes(name))
    || keys.some((name) => !required.includes(name) && !optional.includes(name))) fail();
  const result = Object.create(null);
  for (const name of [...required, ...optional]) {
    if (!keys.includes(name)) {
      result[name] = undefined;
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
    result[name] = descriptor.value;
  }
  return result;
}

function copyBytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}

function decode(value, min, max) {
  if (typeof value !== "string" || !B64U.test(value) || value.length > max * 2 + 4) fail();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < min || bytes.length > max || bytes.toString("base64url") !== value) fail();
  return bytes;
}

function encodeOperation(operation) {
  return {
    operation_id: operation.operation_id.toString("base64url"),
    expected_sequence: operation.expected_sequence,
    expected_root: operation.expected_root.toString("base64url"),
    object_id: operation.object_id.toString("base64url"),
    revision: operation.revision,
    epoch: operation.epoch,
    ciphertext_sha256: operation.ciphertext_sha256.toString("base64url"),
  };
}

function operationEntry(operation) {
  return {
    object_id: Buffer.from(operation.object_id),
    revision: operation.revision,
    epoch: operation.epoch,
    ciphertext_sha256: Buffer.from(operation.ciphertext_sha256),
  };
}

function normalizeOperation(value) {
  const raw = exact(value, OPERATION_FIELDS);
  if (!Number.isSafeInteger(raw.expected_sequence) || raw.expected_sequence < 0
    || raw.expected_sequence > inventory.MAX_SEQUENCE) fail();
  const entry = inventory.normalizeEntry({
    object_id: copyBytes(raw.object_id, 16),
    revision: raw.revision,
    epoch: raw.epoch,
    ciphertext_sha256: copyBytes(raw.ciphertext_sha256, 32),
  });
  return {
    operation_id: copyBytes(raw.operation_id, 16),
    expected_sequence: raw.expected_sequence,
    expected_root: copyBytes(raw.expected_root, 32),
    ...entry,
  };
}

function parseJson(bytes) {
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch (_) { fail(); }
}

function requestJson({ url, ca, clientKey, clientCert, serverFingerprint, idleTimeoutMs,
  wallTimeoutMs, route, body, responseLimit }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let request;
    const wallTimer = setTimeout(() => abort(), wallTimeoutMs);
    const cleanup = () => clearTimeout(wallTimer);
    const rejectGeneric = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error("INVENTORY_HTTP_UNAVAILABLE"));
    };
    const abort = () => {
      if (request && !request.destroyed) request.destroy();
      rejectGeneric();
    };
    try {
      request = https.request({
        hostname: url.hostname,
        port: Number(url.port),
        path: route,
        method: "POST",
        agent: false,
        ca,
        cert: clientCert,
        key: clientKey,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
        servername: url.hostname,
        checkServerIdentity(hostname, peer) {
          const hostnameError = tls.checkServerIdentity(hostname, peer);
          if (hostnameError) return hostnameError;
          if (!peer.fingerprint256
            || peer.fingerprint256.toUpperCase() !== serverFingerprint) {
            return new Error("INVENTORY_SERVER_NOT_PINNED");
          }
          return undefined;
        },
        headers: {
          "content-type": "application/json",
          "content-length": String(body.length),
          accept: "application/json",
        },
      }, (response) => {
        if (response.statusCode !== 200 || response.headers["content-type"] !== "application/json") {
          // Do not drain an untrusted HTTP error indefinitely. Destroy the
          // physical socket before clearing the absolute request deadline.
          abort();
          return;
        }
        const contentLength = response.headers["content-length"];
        if (contentLength !== undefined
          && (!/^\d+$/.test(contentLength) || !Number.isSafeInteger(Number(contentLength))
            || Number(contentLength) > responseLimit)) {
          abort();
          return;
        }
        const chunks = [];
        let size = 0;
        response.on("data", (chunk) => {
          size += chunk.length;
          if (size > responseLimit) {
            abort();
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          if (settled) return;
          if (!response.complete) {
            rejectGeneric();
            return;
          }
          settled = true;
          cleanup();
          try { resolve(parseJson(Buffer.concat(chunks, size))); }
          catch (_) { reject(new Error("INVENTORY_HTTP_UNAVAILABLE")); }
        });
        response.on("aborted", rejectGeneric);
        response.on("error", rejectGeneric);
      });
      request.setTimeout(idleTimeoutMs, abort);
      request.on("error", rejectGeneric);
      request.end(body);
    } catch (_) {
      rejectGeneric();
    }
  });
}

function createZk1ContentInventoryHttpsClient({
  endpoint,
  ca,
  clientKey,
  clientCert,
  serverFingerprint256,
  inventoryPublicKey,
  inventorySignerKeyId,
  idleTimeoutMs = 2000,
  wallTimeoutMs = 5000,
}) {
  let url;
  try { url = new URL(endpoint); }
  catch (_) { fail(); }
  if (url.protocol !== "https:" || !url.hostname || !/^\d+$/.test(url.port)
    || Number(url.port) < 1 || Number(url.port) > 65535 || url.username || url.password
    || url.pathname !== "/" || url.search || url.hash || !ca || !clientKey || !clientCert
    || !FINGERPRINT.test(serverFingerprint256)
    || !(inventoryPublicKey instanceof crypto.KeyObject)
    || inventoryPublicKey.type !== "public" || inventoryPublicKey.asymmetricKeyType !== "ed25519"
    || !Number.isSafeInteger(idleTimeoutMs) || idleTimeoutMs < 50 || idleTimeoutMs > 10000
    || !Number.isSafeInteger(wallTimeoutMs) || wallTimeoutMs < 100 || wallTimeoutMs > 15000) fail();
  const serverFingerprint = serverFingerprint256.toUpperCase();
  const signerKeyId = copyBytes(inventorySignerKeyId, 16);

  function verifySnapshotResponse(response, { scope, nonce, requested: entry, minimumHead,
    minimumSnapshot, committedProofChain }) {
    const raw = exact(response, ["status", "snapshotBase64"]);
    if (raw.status !== "snapshot") fail();
    const serialized = decode(raw.snapshotBase64, 1, inventory.MAX_SNAPSHOT_BYTES);
    return inventory.verifySnapshot({
      serialized,
      pinnedPublicKey: inventoryPublicKey,
      pinnedSignerKeyId: signerKeyId,
      expectedScope: scope,
      requested: entry,
      minimumHead,
      minimumSnapshot,
      committedProofChain,
      nonce,
    }).then((verification) => ({
      ...verification,
      serializedSnapshot: Buffer.from(serialized),
      authorizesIo: false,
    }));
  }

  function verifyTerminalResponse(response, scope, operation) {
    const raw = exact(response, ["status", "operationId", "proofBase64"]);
    if (raw.status !== "not_committed_final"
      || !sameOperationId(raw.operationId, operation.operation_id)) fail();
    const proof = decode(raw.proofBase64, 1, inventory.MAX_TERMINAL_PROOF_BYTES);
    return inventory.verifyTerminalProof({
      serialized: proof,
      pinnedPublicKey: inventoryPublicKey,
      pinnedSignerKeyId: signerKeyId,
      expectedScope: scope,
      operation,
    }).then((verification) => {
      if (verification.outcome !== "NOT_COMMITTED_FINAL") fail();
      return {
        status: "not_committed_final",
        reason: verification.reason,
        verified: true,
        proof: Buffer.from(proof),
        authorizesIo: false,
      };
    });
  }

  function call(route, requestBody, requestLimit, responseLimit) {
    const body = Buffer.from(JSON.stringify(requestBody), "utf8");
    if (body.length < 1 || body.length > requestLimit) fail();
    return requestJson({
      url,
      ca,
      clientKey,
      clientCert,
      serverFingerprint,
      idleTimeoutMs,
      wallTimeoutMs,
      route,
      body,
      responseLimit,
    }).catch(() => fail());
  }

  return Object.freeze({
    getSnapshot(input) {
      const raw = exact(input, ["scope", "nonce", "requested", "minimumHead"],
        ["minimumSnapshot", "committedProofChain"]);
      const scope = inventory.normalizeScope(raw.scope);
      const nonce = inventory.normalizeNonce(raw.nonce);
      const entry = inventory.normalizeRequested(raw.requested);
      const minimumHead = inventory.normalizeMinimumHead(raw.minimumHead);
      const minimumSnapshot = raw.minimumSnapshot === undefined || raw.minimumSnapshot === null
        ? undefined : copyBytes(raw.minimumSnapshot, 1, inventory.MAX_SNAPSHOT_BYTES);
      // Snapshot all caller-controlled receipts before any TLS/network await.
      const committedProofChain = raw.committedProofChain === undefined || raw.committedProofChain === null
        ? undefined : inventory.normalizeCommittedProofChain(raw.committedProofChain);
      const response = call("/v1/inventory/snapshot", {
        scope: Object.fromEntries(Object.entries(scope).map(([field, value]) =>
          [field, value.toString("base64url")])),
        nonce: nonce.toString("base64url"),
      }, MAX_METADATA_REQUEST_BYTES, MAX_SNAPSHOT_RESPONSE_BYTES);
      return response.then((result) => {
        try {
          const pending = exact(result, ["status", "reason"]);
          if (pending.status === "pending" && pending.reason === "UNRESOLVED_INTENT") {
            return { status: "pending", reason: pending.reason, authorizesIo: false };
          }
        } catch (_) { /* snapshot response is checked below */ }
        return verifySnapshotResponse(result, {
          scope, nonce, requested: entry, minimumHead, minimumSnapshot, committedProofChain,
        }).catch(() => fail());
      });
    },

    append(input) {
      const raw = exact(input, ["scope", "operation", "nonce", "minimumHead"], ["minimumSnapshot"]);
      const scope = inventory.normalizeScope(raw.scope);
      const operation = normalizeOperation(raw.operation);
      const nonce = inventory.normalizeNonce(raw.nonce);
      const minimumHead = inventory.normalizeMinimumHead(raw.minimumHead);
      const minimumSnapshot = raw.minimumSnapshot === undefined || raw.minimumSnapshot === null
        ? undefined : copyBytes(raw.minimumSnapshot, 1, inventory.MAX_SNAPSHOT_BYTES);
      const body = {
        scope: Object.fromEntries(Object.entries(scope).map(([field, value]) =>
          [field, value.toString("base64url")])),
        operation: encodeOperation(operation),
        nonce: nonce.toString("base64url"),
      };
      const response = call("/v1/inventory/append", body,
        MAX_APPEND_REQUEST_BYTES, MAX_SNAPSHOT_RESPONSE_BYTES);
      return response.then((result) => {
        try {
          const pending = exact(result, ["status", "reason", "operationId"]);
          if (pending.status === "pending" && PENDING_REASONS.has(pending.reason)
            && sameOperationId(pending.operationId, operation.operation_id)) {
            return { status: "pending", reason: pending.reason, authorizesIo: false };
          }
        } catch (_) { /* inspect the other exact response forms */ }
        try {
          const rawFinal = exact(result, ["status", "operationId", "proofBase64"]);
          if (rawFinal.status === "not_committed_final") {
            return verifyTerminalResponse(result, scope, operation).catch(() => fail());
          }
        } catch (_) { /* committed response is checked below */ }
        try {
          const committed = exact(result, ["status", "replay", "operationId", "headSequence",
            "headRootBase64", "snapshotBase64", "proofBase64"]);
          if (committed.status !== "committed" || typeof committed.replay !== "boolean"
            || !sameOperationId(committed.operationId, operation.operation_id)
            || !Number.isSafeInteger(committed.headSequence) || committed.headSequence < 1) fail();
          const headRoot = decode(committed.headRootBase64, 32, 32);
          const snapshot = decode(committed.snapshotBase64, 1, inventory.MAX_SNAPSHOT_BYTES);
          const receiptBytes = decode(committed.proofBase64, 1, inventory.MAX_COMMITTED_PROOF_BYTES);
          return Promise.all([inventory.verifySnapshot({
            serialized: snapshot,
            pinnedPublicKey: inventoryPublicKey,
            pinnedSignerKeyId: signerKeyId,
            expectedScope: scope,
            requested: operationEntry(operation),
            minimumHead,
            minimumSnapshot,
            nonce,
          }), inventory.verifyCommittedEntryProof({
            serialized: receiptBytes,
            pinnedPublicKey: inventoryPublicKey,
            pinnedSignerKeyId: signerKeyId,
            expectedScope: scope,
            operation,
          })]).then(([verification, receipt]) => {
            if (verification.sequence !== committed.headSequence
              || !crypto.timingSafeEqual(verification.root, headRoot)
              || verification.outcome !== "PRESENT"
              || receipt.sequence > verification.sequence
              || (receipt.sequence === verification.sequence
                && !crypto.timingSafeEqual(receipt.root, verification.root))) fail();
            // The entry proves the exact operation committed in this signed
            // inventory ledger. It does NOT attest physical ciphertext I/O,
            // independent operation, remote durability or release permission.
            return {
              status: "committed",
              transportReplayReported: committed.replay,
              transportReportedCommittedOnly: false,
              signedLedgerOperationCommitted: true,
              verifiedReceipt: receipt,
              externalDurabilityProven: false,
              sequence: verification.sequence,
              root: Buffer.from(verification.root),
              verification,
              serializedSnapshot: Buffer.from(snapshot),
              authorizesIo: false,
            };
          });
        } catch (_) { return fail(); }
      }).catch(() => fail());
    },

    getOperationStatus(input) {
      const raw = exact(input, ["scope", "operation"]);
      const scope = inventory.normalizeScope(raw.scope);
      const operation = normalizeOperation(raw.operation);
      const response = call("/v1/inventory/operation", {
        scope: Object.fromEntries(Object.entries(scope).map(([field, value]) =>
          [field, value.toString("base64url")])),
        operation: encodeOperation(operation),
      }, MAX_METADATA_REQUEST_BYTES, MAX_SMALL_RESPONSE_BYTES);
      return response.then((result) => {
        try {
          const rawStatus = exact(result, ["status", "operationId"]);
          if ((rawStatus.status === "unknown" || rawStatus.status === "pending")
            && sameOperationId(rawStatus.operationId, operation.operation_id)) {
            return { status: rawStatus.status, authorizesIo: false,
              transportReportedCommittedOnly: false };
          }
        } catch (_) { /* inspect committed and terminal proof forms */ }
        try {
          const rawFinal = exact(result, ["status", "operationId", "proofBase64"]);
          if (rawFinal.status === "not_committed_final") {
            return verifyTerminalResponse(result, scope, operation).catch(() => fail());
          }
        } catch (_) { /* inspect committed form */ }
        try {
          const committed = exact(result, ["status", "operationId", "sequence", "rootBase64", "proofBase64"]);
          if (committed.status !== "committed"
            || !sameOperationId(committed.operationId, operation.operation_id)
            || !Number.isSafeInteger(committed.sequence) || committed.sequence < 1) fail();
          const expectedRoot = decode(committed.rootBase64, 32, 32);
          const serialized = decode(committed.proofBase64, 1, inventory.MAX_COMMITTED_PROOF_BYTES);
          return inventory.verifyCommittedEntryProof({
            serialized,
            pinnedPublicKey: inventoryPublicKey,
            pinnedSignerKeyId: signerKeyId,
            expectedScope: scope,
            operation,
          }).then((verified) => {
            if (verified.sequence !== committed.sequence
              || !crypto.timingSafeEqual(verified.root, expectedRoot)) fail();
            return {
              status: "committed",
              sequence: verified.sequence,
              root: Buffer.from(verified.root),
              verifiedReceipt: verified,
              signedLedgerOperationCommitted: true,
              transportReportedCommittedOnly: false,
              externalDurabilityProven: false,
              authorizesIo: false,
            };
          });
        } catch (_) { return fail(); }
      }).catch(() => fail());
    },
  });
}

function sameOperationId(encoded, expected) {
  try {
    const decoded = decode(encoded, 16, 16);
    return crypto.timingSafeEqual(decoded, expected);
  } catch (_) { return false; }
}

module.exports = { createZk1ContentInventoryHttpsClient };
