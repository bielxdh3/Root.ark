"use strict";

// DEV-OFF ONLY: separate-process Sync v2 retained-anchor mTLS transport.
// Mutual TLS and signed high-water do NOT establish physical durability,
// independent owner custody, or permission to wire protected client ACKs.
const https = require("node:https");
const tls = require("node:tls");
const crypto = require("node:crypto");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { ANCHOR_DOMAIN } = require("./zk1SyncAtomicCasFloorLedgerDevOff");
const { Zk1SyncAtomicRetainedAnchorDevOff, BINDING_DOMAIN } =
  require("./zk1SyncAtomicRetainedAnchorDevOff");

const HEAD_ROUTE = "/v2/sync-atomic/retained/head";
const ADVANCE_ROUTE = "/v2/sync-atomic/retained/advance";
const BINDING_ROUTE = "/v2/sync-atomic/retained/binding";
const FINGERPRINT = /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/;
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const HEX = /^[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES = 1024;

function deniedError() {
  return Object.assign(new Error("SYNC_ATOMIC_RETAINED_HTTPS_DEV_OFF_DENIED"),
    { code: "SYNC_ATOMIC_RETAINED_HTTPS_DEV_OFF_DENIED" });
}
function deny() { throw deniedError(); }
function requireValid(ok) { if (!ok) throw deny(); }
function exact(value, fields) {
  requireValid(value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === fields.length
    && fields.every((field) => Object.hasOwn(value, field)));
}
function detached(value) {
  try {
    const raw = protocol.canonicalJson(value);
    requireValid(typeof raw === "string" && Buffer.byteLength(raw) <= MAX_BYTES);
    return JSON.parse(raw);
  } catch { throw deny(); }
}
function readInput(value) {
  exact(value, ["scope", "nonce"]);
  requireValid(typeof value.scope === "string" && SCOPE.test(value.scope)
    && typeof value.nonce === "string" && NONCE.test(value.nonce)
    && Buffer.from(value.nonce, "base64url").length === 32
    && Buffer.from(value.nonce, "base64url").toString("base64url") === value.nonce);
}
function advanceInput(value) {
  exact(value, ["scope", "expectedSequence", "expectedHeadHash", "sequence", "headHash"]);
  requireValid(typeof value.scope === "string" && SCOPE.test(value.scope)
    && Number.isSafeInteger(value.expectedSequence) && value.expectedSequence >= 0
    && Number.isSafeInteger(value.sequence)
    && value.sequence === value.expectedSequence + 1
    && typeof value.expectedHeadHash === "string" && HEX.test(value.expectedHeadHash)
    && typeof value.headHash === "string" && HEX.test(value.headHash)
    && value.headHash !== value.expectedHeadHash);
}
function grantsOf(principals) {
  requireValid(principals && typeof principals === "object" && !Array.isArray(principals)
    && Object.keys(principals).length > 0 && Object.keys(principals).length <= 32);
  const result = new Map();
  for (const [fingerprint, input] of Object.entries(principals)) {
    requireValid(FINGERPRINT.test(fingerprint) && Array.isArray(input)
      && input.length > 0 && input.length <= 64);
    const byScope = new Map();
    for (const entry of input) {
      exact(entry, ["scope", "canAdvance"]);
      requireValid(typeof entry.scope === "string" && SCOPE.test(entry.scope)
        && typeof entry.canAdvance === "boolean" && !byScope.has(entry.scope));
      byScope.set(entry.scope, entry.canAdvance);
    }
    result.set(fingerprint, byScope);
  }
  return result;
}
function verifiedBindingReceipt(value, input, publicKey) {
  const receipt = detached(value);
  exact(receipt, ["statement", "signature"]);
  exact(receipt.statement, ["version", "scope", "accountId", "storeId",
    "nonce", "sequence", "headHash"]);
  requireValid(receipt.statement.version === 2
    && receipt.statement.scope === input.scope
    && receipt.statement.nonce === input.nonce
    && typeof receipt.statement.accountId === "string"
    && UUID.test(receipt.statement.accountId)
    && typeof receipt.statement.storeId === "string"
    && UUID.test(receipt.statement.storeId)
    && Number.isSafeInteger(receipt.statement.sequence)
    && receipt.statement.sequence >= 0
    && typeof receipt.statement.headHash === "string"
    && HEX.test(receipt.statement.headHash)
    && typeof receipt.signature === "string"
    && /^[A-Za-z0-9_-]{86}$/.test(receipt.signature));
  const signature = Buffer.from(receipt.signature, "base64url");
  requireValid(signature.length === 64
    && signature.toString("base64url") === receipt.signature
    && crypto.verify(null, Buffer.from(BINDING_DOMAIN
      + protocol.canonicalJson(receipt.statement)), publicKey, signature));
  return receipt;
}
async function independentlySignedBindingHead(minimumFence, scope) {
  const nonce = crypto.randomBytes(32).toString("base64url");
  const receipt = await minimumFence.readSignedBindingHead({ scope, nonce });
  return verifiedBindingReceipt(receipt, { scope, nonce },
    minimumFence.publicKey).statement;
}
function send(res, status, data) {
  if (res.destroyed || res.headersSent) return;
  const bytes = Buffer.from(JSON.stringify(data));
  res.writeHead(status, { "content-type": "application/json",
    "content-length": String(bytes.length), "cache-control": "no-store",
    "x-content-type-options": "nosniff" });
  res.end(bytes);
}
async function readBody(req) {
  requireValid(req.headers["content-type"] === "application/json");
  const length = req.headers["content-length"];
  requireValid(length === undefined || (/^\d+$/.test(length)
    && Number(length) > 0 && Number(length) <= MAX_BYTES));
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    requireValid(size <= MAX_BYTES);
    chunks.push(chunk);
  }
  requireValid(size > 0);
  try { return detached(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
  catch { throw deny(); }
}

function createZk1SyncAtomicRetainedAnchorHttpsServerDevOff({ key, cert, clientCa,
  anchor, principals, minimumFence = null } = {}) {
  requireValid(key && cert && clientCa
    && anchor instanceof Zk1SyncAtomicRetainedAnchorDevOff);
  // A v2-pinned database cannot be exposed by a legacy transport that skips
  // its independent minimum. Conversely, a v1 DB cannot impersonate v2.
  requireValid(anchor.requiresMinimumFence === (minimumFence !== null));
  if (minimumFence !== null) {
    requireValid(minimumFence && typeof minimumFence.readSignedBindingHead === "function"
      && typeof minimumFence.compareAndAdvance === "function"
      && minimumFence.publicKey instanceof crypto.KeyObject
      && minimumFence.publicKey.type === "public"
      && minimumFence.publicKey.asymmetricKeyType === "ed25519");
  }
  const grants = grantsOf(principals);
  const active = new Set();
  async function requireTwinHead(scope) {
    const remote = await independentlySignedBindingHead(minimumFence, scope);
    const local = anchor.readSignedBindingHead({ scope,
      nonce: crypto.randomBytes(32).toString("base64url") }).statement;
    requireValid(local.accountId === remote.accountId
      && local.storeId === remote.storeId
      && local.sequence === remote.sequence
      && local.headHash === remote.headHash);
    return remote;
  }
  const server = https.createServer({ key, cert, ca: clientCa,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
    handshakeTimeout: 3000 }, async (req, res) => {
    const peer = req.socket.getPeerCertificate();
    const fingerprint = peer?.fingerprint256?.toUpperCase();
    if (!req.socket.authorized || !fingerprint || !grants.has(fingerprint)) {
      return send(res, 403, { error: "FORBIDDEN" });
    }
    if (req.method !== "POST"
      || ![HEAD_ROUTE, ADVANCE_ROUTE, BINDING_ROUTE].includes(req.url)) {
      return send(res, 404, { error: "NOT_FOUND" });
    }
    if (active.has(fingerprint) || active.size >= 8) {
      return send(res, 503, { error: "BUSY" });
    }
    active.add(fingerprint);
    try {
      const input = await readBody(req);
      const allowed = grants.get(fingerprint);
      if (!allowed.has(input.scope)) return send(res, 403, { error: "FORBIDDEN" });
      if (req.url === HEAD_ROUTE) {
        readInput(input);
        if (minimumFence) await requireTwinHead(input.scope);
        return send(res, 200, { receipt: anchor.readSignedHead(input) });
      }
      if (req.url === BINDING_ROUTE) {
        readInput(input);
        if (minimumFence) await requireTwinHead(input.scope);
        return send(res, 200, { receipt: anchor.readSignedBindingHead(input) });
      }
      advanceInput(input);
      if (!allowed.get(input.scope)) return send(res, 403, { error: "FORBIDDEN" });
      if (minimumFence) {
        const before = await requireTwinHead(input.scope);
        if (before.sequence !== input.expectedSequence
          || before.headHash !== input.expectedHeadHash) {
          return send(res, 200, { advanced: false });
        }
        // Record the independently signed minimum FIRST. A crash or lost ACK
        // after its commit but before local commit MUST leave this operator
        // unavailable on recovery, never silently accept a restored prefix.
        requireValid(await minimumFence.compareAndAdvance(input) === true);
        requireValid(anchor.compareAndAdvance(input) === true);
        await requireTwinHead(input.scope);
        return send(res, 200, { advanced: true });
      }
      return send(res, 200, { advanced: anchor.compareAndAdvance(input) });
    } catch {
      return send(res, 503, { error: "UNAVAILABLE" });
    } finally { active.delete(fingerprint); }
  });
  server.maxConnections = 16;
  server.headersTimeout = 5000;
  server.requestTimeout = 8000;
  server.timeout = 8000;
  server.keepAliveTimeout = 1000;
  server.maxHeadersCount = 32;
  return server;
}

function createZk1SyncAtomicRetainedAnchorHttpsClientDevOff({ hostname = "localhost",
  port, servername = "localhost", ca, cert, key, pinnedServerFingerprint,
  anchorPublicKey, timeoutMs = 5000 } = {}) {
  requireValid(typeof hostname === "string" && hostname.length > 0
    && hostname.length <= 253 && typeof servername === "string"
    && servername.length > 0 && servername.length <= 253
    && Number.isSafeInteger(port) && port >= 1 && port <= 65535
    && Number.isSafeInteger(timeoutMs) && timeoutMs >= 200 && timeoutMs <= 7000
    && ca && cert && key && typeof pinnedServerFingerprint === "string"
    && FINGERPRINT.test(pinnedServerFingerprint)
    && anchorPublicKey instanceof crypto.KeyObject
    && anchorPublicKey.type === "public"
    && anchorPublicKey.asymmetricKeyType === "ed25519");

  function signedReceipt(value, input) {
    exact(value, ["statement", "signature"]);
    exact(value.statement, ["version", "scope", "nonce", "sequence", "headHash"]);
    requireValid(value.statement.version === 1
      && value.statement.scope === input.scope && value.statement.nonce === input.nonce
      && Number.isSafeInteger(value.statement.sequence) && value.statement.sequence >= 0
      && typeof value.statement.headHash === "string" && HEX.test(value.statement.headHash)
      && typeof value.signature === "string" && /^[A-Za-z0-9_-]{86}$/.test(value.signature));
    const signature = Buffer.from(value.signature, "base64url");
    requireValid(signature.length === 64
      && signature.toString("base64url") === value.signature
      && crypto.verify(null, Buffer.from(ANCHOR_DOMAIN
        + protocol.canonicalJson(value.statement)), anchorPublicKey, signature));
    return value;
  }
  async function post(route, input, deadline = null) {
    const data = Buffer.from(protocol.canonicalJson(input));
    requireValid(data.length > 0 && data.length <= MAX_BYTES);
    const budget = deadline === null ? timeoutMs
      : Math.min(timeoutMs, deadline - Date.now());
    requireValid(Number.isSafeInteger(budget) && budget > 0);
    try {
      return await new Promise((resolve, reject) => {
        const req = https.request({ hostname, port, servername, ca, cert, key,
          method: "POST", path: route, agent: false, minVersion: "TLSv1.3",
          rejectUnauthorized: true,
          // Socket inactivity alone is not a deadline: a peer can drip bytes
          // forever, or delay DNS/TLS setup, without tripping setTimeout().
          signal: AbortSignal.timeout(budget),
          checkServerIdentity(name, certificate) {
            const hostnameError = tls.checkServerIdentity(name, certificate);
            if (hostnameError) return hostnameError;
            if (certificate.fingerprint256?.toUpperCase() !== pinnedServerFingerprint) {
              // The TLS hook MUST return an Error, not throw through Node's
              // certificate verifier. Reject as a normal failed handshake.
              return deniedError();
            }
            return undefined;
          },
          headers: { "content-type": "application/json",
            "content-length": String(data.length) },
        }, (response) => {
          const peer = response.socket.getPeerCertificate();
          if (!response.socket.authorized
            || peer?.fingerprint256?.toUpperCase() !== pinnedServerFingerprint
            || response.statusCode !== 200
            || response.headers["content-type"] !== "application/json") {
            response.destroy();
            return reject(deniedError());
          }
          const chunks = [];
          let received = 0;
          response.on("data", (chunk) => {
            received += chunk.length;
            if (received > MAX_BYTES) response.destroy(deniedError());
            else chunks.push(chunk);
          });
          response.on("end", () => {
            try { resolve(detached(JSON.parse(Buffer.concat(chunks).toString("utf8")))); }
            catch { reject(deniedError()); }
          });
          response.on("error", reject);
        });
        req.setTimeout(budget, () => req.destroy(deniedError()));
        req.on("error", reject);
        req.end(data);
      });
    } catch { throw deny(); }
  }
  async function readVerified(value, deadline = null) {
    const input = detached(value);
    readInput(input);
    const result = await post(HEAD_ROUTE, input, deadline);
    exact(result, ["receipt"]);
    return signedReceipt(result.receipt, input);
  }
  return Object.freeze({
    async readSignedHead(value) {
      return readVerified(value);
    },
    async readSignedBindingHead(value) {
      const input = detached(value);
      readInput(input);
      const result = await post(BINDING_ROUTE, input);
      exact(result, ["receipt"]);
      return verifiedBindingReceipt(result.receipt, input, anchorPublicKey);
    },
    async compareAndAdvance(value) {
      // The advance and its required signed readback share ONE deadline.
      // Two individual socket timeouts must never silently double the lease.
      const deadline = Date.now() + timeoutMs;
      const input = detached(value);
      advanceInput(input);
      const result = await post(ADVANCE_ROUTE, input, deadline);
      exact(result, ["advanced"]);
      requireValid(typeof result.advanced === "boolean");
      if (!result.advanced) return false;
      // An unsigned HTTP 200 or {advanced:true} cannot acknowledge a floor.
      // Require a SECOND independent nonce-signed committed readback.
      const receipt = await readVerified({ scope: input.scope,
        nonce: crypto.randomBytes(32).toString("base64url") }, deadline);
      requireValid(receipt.statement.sequence === input.sequence
        && receipt.statement.headHash === input.headHash);
      return true;
    },
  });
}

module.exports = { createZk1SyncAtomicRetainedAnchorHttpsServerDevOff,
  createZk1SyncAtomicRetainedAnchorHttpsClientDevOff };
