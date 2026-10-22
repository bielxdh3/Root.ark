"use strict";

// Standalone mTLS transport for the signed content inventory. This service is
// intentionally not connected to protected content routes or storage I/O.
const https = require("node:https");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("./zk1SharedPgPhysicalCiphertextVerifier");

const MAX_METADATA_REQUEST_BYTES = 4096;
const MAX_APPEND_REQUEST_BYTES = 8192;
const MAX_SNAPSHOT_BASE64_BYTES = 3 * 1024 * 1024;
const MAX_SNAPSHOT_RESPONSE_BYTES = MAX_SNAPSHOT_BASE64_BYTES + 16 * 1024;
const MAX_SMALL_RESPONSE_BYTES = 16 * 1024;
const MAX_CHAIN_RESPONSE_BYTES = 128 * 1024;
const MAX_CHAIN_PAGE_RECEIPTS = 16;
// Physical verification re-reads up to 64 MiB from PostgreSQL twice per
// successful append. A valid but compromised mTLS append certificate must
// not fan out unbounded concurrent hash/readback work. Reject rather than
// queue: pending callers must retry their exact operation independently.
const MAX_ACTIVE_PHYSICAL_APPENDS = 2;
const MAX_PHYSICAL_APPENDS_PER_PRINCIPAL_WINDOW = 4;
const MAX_PHYSICAL_APPENDS_GLOBAL_WINDOW = 16;
const PHYSICAL_WINDOW_NS = 60_000_000_000n;
const B64U = /^[A-Za-z0-9_-]+$/;
const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const SCOPE_FIELDS = Object.freeze(["account_id", "compartment_id", "keyring_id"]);
const OPERATION_FIELDS = Object.freeze([
  "operation_id", "expected_sequence", "expected_root", "object_id", "revision", "epoch",
  "ciphertext_sha256",
]);
const ROUTES = Object.freeze({
  "/v1/inventory/snapshot": { role: "read", kind: "snapshot" },
  "/v1/inventory/append": { role: "append", kind: "append" },
  "/v1/inventory/operation": { role: "status", kind: "operation" },
  "/v1/inventory/chain": { role: "read", kind: "chain" },
});
const PENDING_REASONS = new Set([
  "EXPECTED_HEAD_CHANGED", "INVENTORY_LIMIT", "INVALID_CHRONOLOGY",
  "INVALID_CATALOG_TRANSITION", "UNRESOLVED_INTENT", "SEAL_UNCERTAIN",
]);

function invalid() {
  const error = new Error("INVENTORY_HTTP_INVALID");
  error.code = "INVENTORY_HTTP_INVALID";
  throw error;
}

function forbidden() {
  const error = new Error("INVENTORY_HTTP_FORBIDDEN");
  error.code = "INVENTORY_HTTP_FORBIDDEN";
  throw error;
}

function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || fields.some((field) => !keys.includes(field))) invalid();
  const result = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) invalid();
    result[field] = descriptor.value;
  }
  return result;
}

function decode(value, min, max) {
  if (typeof value !== "string" || !B64U.test(value) || value.length > max * 2 + 4) invalid();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < min || bytes.length > max || bytes.toString("base64url") !== value) invalid();
  return bytes;
}

function scopeKey(scope) {
  return `${scope.account_id.toString("hex")}:${scope.compartment_id.length}:`
    + `${scope.compartment_id.toString("hex")}:${scope.keyring_id.toString("hex")}`;
}

function normalizeScope(value) {
  try {
    const raw = exact(value, SCOPE_FIELDS);
    return inventory.normalizeScope({
      account_id: decode(raw.account_id, 16, 16),
      compartment_id: decode(raw.compartment_id, 1, 128),
      keyring_id: decode(raw.keyring_id, 16, 16),
    });
  } catch (_) { invalid(); }
}

function normalizeOperation(value) {
  try {
    const raw = exact(value, OPERATION_FIELDS);
    if (!Number.isSafeInteger(raw.expected_sequence) || raw.expected_sequence < 0
      || raw.expected_sequence > inventory.MAX_SEQUENCE
      || !Number.isSafeInteger(raw.revision) || raw.revision < 1
      || !Number.isSafeInteger(raw.epoch) || raw.epoch < 1) invalid();
    const entry = inventory.normalizeEntry({
      object_id: decode(raw.object_id, 16, 16),
      revision: raw.revision,
      epoch: raw.epoch,
      ciphertext_sha256: decode(raw.ciphertext_sha256, 32, 32),
    });
    return {
      operation_id: decode(raw.operation_id, 16, 16),
      expected_sequence: raw.expected_sequence,
      expected_root: decode(raw.expected_root, 32, 32),
      ...entry,
    };
  } catch (_) { invalid(); }
}

async function readJson(request, maxBytes) {
  if (request.headers["content-type"] !== "application/json") invalid();
  const contentLength = request.headers["content-length"];
  if (contentLength !== undefined
    && (!/^\d+$/.test(contentLength) || !Number.isSafeInteger(Number(contentLength))
      || Number(contentLength) > maxBytes)) invalid();
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) invalid();
    chunks.push(chunk);
  }
  if (size === 0) invalid();
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)); }
  catch (_) { invalid(); }
  try { return JSON.parse(text); }
  catch (_) { invalid(); }
}

function respond(response, status, object, limit = MAX_SMALL_RESPONSE_BYTES) {
  if (response.destroyed || response.headersSent) return;
  const body = Buffer.from(JSON.stringify(object), "utf8");
  if (body.length > limit) {
    response.writeHead(503, { connection: "close" });
    response.end();
    return;
  }
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(body.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function createZk1ContentInventoryHttpsServer({
  key, cert, clientCa, ledger, principals, physicalVerifier,
}) {
  if (!key || !cert || !clientCa || !ledger
    || typeof ledger.getSnapshot !== "function" || typeof ledger.append !== "function"
    || typeof ledger.getOperationStatus !== "function" || !ledger.scope
    || !principals || typeof principals !== "object" || Array.isArray(principals)
    || Object.keys(principals).length < 1 || Object.keys(principals).length > 128
    || (physicalVerifier !== undefined
      && !(physicalVerifier instanceof Zk1SharedPgPhysicalCiphertextVerifier))) invalid();

  const ledgerScope = inventory.normalizeScope(ledger.scope);
  const ledgerScopeKey = scopeKey(ledgerScope);
  const allowed = new Map();
  const activePhysicalPrincipals = new Set();
  let activePhysicalAppends = 0;
  const physicalPrincipalWindowCounts = new Map();
  let physicalGlobalWindowStarted = process.hrtime.bigint();
  let physicalGlobalWindowCount = 0;
  // Appends and committed-operation lookups share the same limited physical
  // readback budget. A status certificate must not bypass append throttling.
  function acquirePhysicalLease(fingerprint) {
    const id = fingerprint.toUpperCase();
    const now = process.hrtime.bigint();
    if (now - physicalGlobalWindowStarted >= PHYSICAL_WINDOW_NS) {
      physicalGlobalWindowStarted = now;
      physicalGlobalWindowCount = 0;
      physicalPrincipalWindowCounts.clear();
    }
    if (activePhysicalAppends >= MAX_ACTIVE_PHYSICAL_APPENDS
      || activePhysicalPrincipals.has(id)
      || physicalGlobalWindowCount >= MAX_PHYSICAL_APPENDS_GLOBAL_WINDOW
      || (physicalPrincipalWindowCounts.get(id) || 0)
        >= MAX_PHYSICAL_APPENDS_PER_PRINCIPAL_WINDOW) return false;
    physicalGlobalWindowCount += 1;
    physicalPrincipalWindowCounts.set(id,
      (physicalPrincipalWindowCounts.get(id) || 0) + 1);
    activePhysicalAppends += 1;
    activePhysicalPrincipals.add(id);
    return id;
  }
  for (const [fingerprint, configuration] of Object.entries(principals)) {
    const grant = exact(configuration, ["roles", "scopes"]);
    if (!FINGERPRINT.test(fingerprint) || !Array.isArray(grant.roles)
      || grant.roles.length < 1 || grant.roles.length > 3
      || new Set(grant.roles).size !== grant.roles.length
      || grant.roles.some((role) => !["read", "append", "status"].includes(role))
      || !Array.isArray(grant.scopes) || grant.scopes.length < 1 || grant.scopes.length > 64) invalid();
    const scopes = new Set(grant.scopes.map((scope) => scopeKey(normalizeScope(scope))));
    if (scopes.size !== grant.scopes.length || allowed.has(fingerprint.toUpperCase())) invalid();
    allowed.set(fingerprint.toUpperCase(), { roles: new Set(grant.roles), scopes });
  }

  const server = https.createServer({
    key,
    cert,
    ca: clientCa,
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: "TLSv1.3",
    maxHeaderSize: 8192,
    maxHeadersCount: 64,
  }, async (request, response) => {
    let physicalLeasePrincipal;
    try {
      if (request.method !== "POST" || !Object.hasOwn(ROUTES, request.url)) {
        return respond(response, 404, { error: "NOT_FOUND" });
      }
      const route = ROUTES[request.url];
      const peer = request.socket.getPeerCertificate();
      const principal = peer?.fingerprint256 && allowed.get(peer.fingerprint256.toUpperCase());
      if (!request.socket.authorized || !principal || !principal.roles.has(route.role)) forbidden();

      const body = await readJson(request,
        route.kind === "append" ? MAX_APPEND_REQUEST_BYTES : MAX_METADATA_REQUEST_BYTES);
      const expectedFields = route.kind === "snapshot" ? ["scope", "nonce"]
        : route.kind === "chain" ? ["scope", "afterSequence", "limit"]
          : ["scope", "operation"].concat(route.kind === "append" ? ["nonce"] : []);
      const raw = exact(body, expectedFields);
      const scope = normalizeScope(raw.scope);
      const keyForScope = scopeKey(scope);
      if (!principal.scopes.has(keyForScope) || keyForScope !== ledgerScopeKey) forbidden();

      if (route.kind === "chain") {
        if (!Number.isSafeInteger(raw.afterSequence) || raw.afterSequence < 0
          || raw.afterSequence > inventory.MAX_ENTRIES
          || !Number.isSafeInteger(raw.limit) || raw.limit < 1
          || raw.limit > MAX_CHAIN_PAGE_RECEIPTS) invalid();
        const page = await ledger.getCommittedProofPage({
          afterSequence: raw.afterSequence, limit: raw.limit,
        });
        if (page?.status === "pending" && page.reason === "UNRESOLVED_INTENT") {
          return respond(response, 200, { status: "pending", reason: "UNRESOLVED_INTENT" });
        }
        if (page?.status !== "chain_page" || page.afterSequence !== raw.afterSequence
          || !Number.isSafeInteger(page.headSequence) || page.headSequence < 0
          || page.headSequence > inventory.MAX_ENTRIES
          || !Number.isSafeInteger(page.nextSequence)
          || page.nextSequence < page.afterSequence
          || page.nextSequence > page.headSequence
          || !Array.isArray(page.proofs)
          || page.proofs.length !== page.nextSequence - page.afterSequence
          || page.proofs.length > raw.limit
          || (page.nextSequence < page.headSequence && page.proofs.length !== raw.limit)
          || page.proofs.some((item) => !Buffer.isBuffer(item)
            || item.length < 1 || item.length > inventory.MAX_COMMITTED_PROOF_BYTES)) invalid();
        return respond(response, 200, {
          status: "chain_page", afterSequence: page.afterSequence,
          nextSequence: page.nextSequence, headSequence: page.headSequence,
          proofsBase64: page.proofs.map((item) => item.toString("base64url")),
        }, MAX_CHAIN_RESPONSE_BYTES);
      }

      if (route.kind === "snapshot") {
        const nonce = decode(raw.nonce, 32, 32);
        const result = await ledger.getSnapshot({ nonce });
        if (result.status === "pending") {
          return respond(response, 200, { status: "pending", reason: "UNRESOLVED_INTENT" });
        }
        if (result.status !== "snapshot" || !Buffer.isBuffer(result.bytes)
          || result.bytes.length < 1 || result.bytes.length > inventory.MAX_SNAPSHOT_BYTES) invalid();
        const snapshotBase64 = result.bytes.toString("base64url");
        if (snapshotBase64.length > MAX_SNAPSHOT_BASE64_BYTES) invalid();
        return respond(response, 200, { status: "snapshot", snapshotBase64 }, MAX_SNAPSHOT_RESPONSE_BYTES);
      }

      const operation = normalizeOperation(raw.operation);
      // Even an unknown operation may require a full SQLite catalog read.
      // Charge all physical-mode status attempts BEFORE that potentially
      // expensive lookup, not only successful physical readbacks. Otherwise
      // a status certificate can flood random IDs without hitting a quota.
      if (route.kind === "operation" && physicalVerifier) {
        physicalLeasePrincipal = acquirePhysicalLease(peer.fingerprint256);
        if (!physicalLeasePrincipal) {
          return respond(response, 503, { error: "INVENTORY_UNAVAILABLE" });
        }
      }
      if (route.kind === "append") {
        const nonce = decode(raw.nonce, 32, 32);
        // Opt-in strict physical publishing path. mTLS append authorization
        // alone must not turn an arbitrary signed operation into a claim of
        // durable ciphertext. Only a separately provisioned read-only
        // PostgreSQL verifier may read the immutable intent and bytes.
        if (physicalVerifier) {
          physicalLeasePrincipal = acquirePhysicalLease(peer.fingerprint256);
          if (!physicalLeasePrincipal) {
            return respond(response, 503, { error: "INVENTORY_UNAVAILABLE" });
          }
          await physicalVerifier.verifyCommittedInventoryOperation({ scope, operation });
        }
        const result = await ledger.append(operation);
        if (!result || typeof result.status !== "string") invalid();
        const operationId = operation.operation_id.toString("base64url");
        if (result.status === "pending") {
          const reason = PENDING_REASONS.has(result.reason) ? result.reason : "SEAL_UNCERTAIN";
          return respond(response, 200, { status: "pending", reason, operationId });
        }
        if (result.status === "not_committed_final") {
          if (!Buffer.isBuffer(result.proof)
            || result.proof.length > inventory.MAX_TERMINAL_PROOF_BYTES) invalid();
          return respond(response, 200, {
            status: "not_committed_final",
            operationId,
            proofBase64: result.proof.toString("base64url"),
          });
        }
        if (result.status !== "committed" || typeof result.replay !== "boolean"
          || !Number.isSafeInteger(result.sequence) || result.sequence < 1
          || !Buffer.isBuffer(result.root) || result.root.length !== 32) invalid();
        const snapshot = await ledger.getSnapshot({ nonce });
        if (snapshot.status === "pending") {
          return respond(response, 200, { status: "pending", reason: "UNRESOLVED_INTENT", operationId });
        }
        if (snapshot.status !== "snapshot" || !Buffer.isBuffer(snapshot.bytes)
          || snapshot.bytes.length < 1 || snapshot.bytes.length > inventory.MAX_SNAPSHOT_BYTES
          || !Number.isSafeInteger(snapshot.sequence) || snapshot.sequence < result.sequence
          || !Buffer.isBuffer(snapshot.root) || snapshot.root.length !== 32) invalid();
        // The snapshot authenticates the tuple but not the operation ID.
        // Attach the durable, independently signed per-operation entry.
        const receipt = await ledger.getOperationStatus(operation.operation_id);
        if (!receipt || receipt.status !== "committed"
          || receipt.sequence !== result.sequence
          || !Buffer.isBuffer(receipt.root) || !receipt.root.equals(result.root)
          || !Buffer.isBuffer(receipt.proof)
          || receipt.proof.length < 1 || receipt.proof.length > inventory.MAX_COMMITTED_PROOF_BYTES) invalid();
        // A signature may already be durable before a physical corruption is
        // detected. Never return positive transport success unless a fresh
        // readback still passes. A historical receipt is not GET authority.
        if (physicalVerifier) {
          await physicalVerifier.verifyCommittedInventoryOperation({ scope, operation });
        }
        const snapshotBase64 = snapshot.bytes.toString("base64url");
        if (snapshotBase64.length > MAX_SNAPSHOT_BASE64_BYTES) invalid();
        return respond(response, 200, {
          status: "committed",
          replay: result.replay,
          operationId,
          headSequence: snapshot.sequence,
          headRootBase64: snapshot.root.toString("base64url"),
          snapshotBase64,
          proofBase64: receipt.proof.toString("base64url"),
        }, MAX_SNAPSHOT_RESPONSE_BYTES);
      }

      const result = await ledger.getOperationStatus(operation.operation_id);
      if (!result || typeof result.status !== "string") invalid();
      const operationId = operation.operation_id.toString("base64url");
      if (result.status === "unknown" || result.status === "pending") {
        return respond(response, 200, { status: result.status, operationId });
      }
      if (result.status === "not_committed_final") {
        if (!Buffer.isBuffer(result.proof)
          || result.proof.length > inventory.MAX_TERMINAL_PROOF_BYTES) invalid();
        return respond(response, 200, {
          status: "not_committed_final",
          operationId,
          proofBase64: result.proof.toString("base64url"),
        });
      }
      if (result.status !== "committed" || !Number.isSafeInteger(result.sequence)
        || result.sequence < 1 || !Buffer.isBuffer(result.root) || result.root.length !== 32
        || !Buffer.isBuffer(result.proof) || result.proof.length < 1
        || result.proof.length > inventory.MAX_COMMITTED_PROOF_BYTES) invalid();
      // A committed ledger row is historical cryptographic evidence, not
      // evidence that the ciphertext is still physically present. In the
      // opt-in physical mode, status reconciliation also fails closed on
      // changed bytes, stale generation, broken binding or failed WAL flush.
      // No part of this response authorizes GET/release of protected content.
      if (physicalVerifier) {
        await physicalVerifier.verifyCommittedInventoryOperation({ scope, operation });
      }
      return respond(response, 200, {
        status: "committed",
        operationId,
        sequence: result.sequence,
        rootBase64: result.root.toString("base64url"),
        proofBase64: result.proof.toString("base64url"),
      });
    } catch (error) {
      if (response.headersSent || response.destroyed) return;
      if (error?.code === "INVENTORY_HTTP_FORBIDDEN") {
        return respond(response, 403, { error: "FORBIDDEN" });
      }
      if (error?.code === "INVENTORY_HTTP_INVALID") {
        return respond(response, 400, { error: "INVALID_REQUEST" });
      }
      if (["INVENTORY_OPERATION_CONFLICT", "INVENTORY_OPERATION_UNKNOWN"].includes(error?.code)) {
        return respond(response, 409, { error: "OPERATION_CONFLICT" });
      }
      return respond(response, 503, { error: "INVENTORY_UNAVAILABLE" });
    } finally {
      if (physicalLeasePrincipal !== undefined) {
        activePhysicalAppends -= 1;
        activePhysicalPrincipals.delete(physicalLeasePrincipal);
      }
    }
  });

  server.headersTimeout = 5000;
  server.requestTimeout = 10000;
  server.timeout = 10000;
  server.keepAliveTimeout = 1000;
  server.maxHeadersCount = 64;
  return server;
}

function drainZk1ContentInventoryHttpsServer(server, { deadlineMs = 2000 } = {}) {
  if (!server || typeof server.close !== "function"
    || !Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 10000) invalid();
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => server.closeAllConnections(), deadlineMs);
    deadline.unref();
    server.close((error) => {
      clearTimeout(deadline);
      if (error) reject(error);
      else resolve();
    });
    server.closeIdleConnections();
  });
}

module.exports = {
  createZk1ContentInventoryHttpsServer,
  drainZk1ContentInventoryHttpsServer,
};
