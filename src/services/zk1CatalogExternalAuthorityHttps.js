"use strict";

// Opt-in operator-owned protocol adapter. This module has no production
// launcher, default credential, owner-state oracle, or physical commit source.
// A separately operated authority MUST supply BOTH live trust callbacks.
const crypto = require("node:crypto");
const https = require("node:https");
const tls = require("node:tls");
const z = require("../crypto/rootark-zk-1");

const POLICY_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-catalog-policy-grant/v1\0");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-witness-terminal/v1\0");
const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-catalog-admission/v1\0");
const PHYSICAL_DOMAIN = Buffer.from("Root.ark/zk-1/catalog-physical-operation-terminal/v1\0");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const FIELDS = ["scope", "ownerRevision", "ownerDigest", "operationId", "signerDeviceId",
  "epoch", "sequence", "catalogDigest", "floorCasSignerFingerprint", "expiresAt"];
const TICKET_FIELDS = ["type", "witness_key_id", ...SCOPE, "admission_id", "operation_id",
  "owner_revision", "owner_digest", "signer_device_id", "epoch", "sequence",
  "catalog_digest", "cas_signer_spki_sha256", "floor_nonce", "expires_at", "principal", "signature"];
const PHYSICAL_FIELDS = ["type", ...SCOPE, "admission_id", "operation_id",
  "owner_revision", "owner_digest", "signer_device_id", "epoch", "sequence",
  "catalog_digest", "cas_signer_spki_sha256", "floor_nonce", "expires_at",
  "principal", "observed_at", "committed", "signature"];
const PIN = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
function deny() { throw new Error("CATALOG_EXTERNAL_DENIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((f) => !Object.hasOwn(value, f))) deny();
}
function bytes(value, len) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) deny();
  if (value.length !== len) deny();
  return Buffer.from(value);
}
function b64(value, min, max = min) {
  if (typeof value !== "string" || !/^[a-zA-Z0-9_-]+$/.test(value)) deny();
  const data = Buffer.from(value, "base64url");
  if (data.length < min || data.length > max || data.toString("base64url") !== value) deny();
  return data;
}
function eq(a, b) {
  return (Buffer.isBuffer(a) || a instanceof Uint8Array)
    && (Buffer.isBuffer(b) || b instanceof Uint8Array)
    && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function scopeFrom(wire) {
  exact(wire, SCOPE);
  return { account_id: b64(wire.account_id, 16),
    compartment_id: b64(wire.compartment_id, 1, 128),
    keyring_id: b64(wire.keyring_id, 16) };
}
function wireScope(scope) {
  return Object.fromEntries(SCOPE.map((k) => [k, Buffer.from(scope[k]).toString("base64url")]));
}
function key(value, type) {
  return value instanceof crypto.KeyObject && value.type === type
    && value.asymmetricKeyType === "ed25519";
}
function fp(publicKey) {
  return crypto.createHash("sha256").update(publicKey.export({ format: "der", type: "spki" })).digest();
}
async function sign(privateKey, body, domain) {
  const raw = Buffer.from(await z.encodeDeterministic(body));
  const signature = crypto.sign(null, Buffer.concat([domain, raw]), privateKey);
  return Buffer.from(await z.encodeDeterministic({ ...body, signature }));
}
async function verify(raw, publicKey, domain, fields) {
  const data = await z.decodeDeterministic(raw);
  exact(data, fields);
  const { signature, ...body } = data;
  if (!crypto.verify(null, Buffer.concat([domain,
    Buffer.from(await z.encodeDeterministic(body))]), publicKey, bytes(signature, 64))) deny();
  return body;
}
function match(a, b, f) {
  if (f === "principal" || f === "type") return a === b;
  if (Number.isSafeInteger(a) || Number.isSafeInteger(b)) return a === b;
  return eq(a, b);
}
function sameFields(a, b, fields) {
  return fields.every((f) => match(a[f], b[f], f));
}
function requestFromWire(wire) {
  exact(wire, FIELDS);
  const req = { scope: scopeFrom(wire.scope),
    ownerRevision: wire.ownerRevision, ownerDigest: b64(wire.ownerDigest, 32),
    operationId: b64(wire.operationId, 16),
    signerDeviceId: b64(wire.signerDeviceId, 16),
    epoch: wire.epoch, sequence: wire.sequence,
    catalogDigest: b64(wire.catalogDigest, 32),
    floorCasSignerFingerprint: b64(wire.floorCasSignerFingerprint, 32),
    expiresAt: wire.expiresAt };
  if (![req.ownerRevision, req.epoch, req.sequence, req.expiresAt]
    .every((n) => Number.isSafeInteger(n) && n > 0)) deny();
  return req;
}
function requestToWire(req) {
  exact(req, FIELDS);
  const result = { ...req, scope: wireScope(req.scope) };
  for (const k of ["ownerDigest", "operationId", "signerDeviceId",
    "catalogDigest", "floorCasSignerFingerprint"]) result[k] = Buffer.from(req[k]).toString("base64url");
  return result;
}
function peerPrincipal(socket, allowed) {
  const cert = socket.getPeerCertificate();
  const identity = cert?.fingerprint256?.toUpperCase();
  if (!socket.authorized || identity !== allowed) deny();
  return identity;
}
async function bodyJson(req) {
  if (req.headers["content-type"] !== "application/json"
    || (req.headers["content-length"] !== undefined
      && (!/^\d+$/.test(req.headers["content-length"])
        || Number(req.headers["content-length"]) > 8192))) deny();
  const chunks = [];
  let total = 0;
  for await (const part of req) {
    total += part.length;
    if (total > 8192) deny();
    chunks.push(part);
  }
  if (!total) deny();
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch (_) { deny(); }
}
function respond(res, status, message) {
  if (res.destroyed || res.headersSent) return;
  const raw = Buffer.from(JSON.stringify(message));
  res.writeHead(status, { "content-type": "application/json",
    "content-length": raw.length, "cache-control": "no-store" });
  res.end(raw);
}
function createCatalogAuthorityHttpsServer({ key: tlsKey, cert, clientCa,
  authorizedClientFingerprint256, policyPrivateKey, floorPrivateKey,
  witnessPublicKey, physicalPublicKey, trustedOwnerPolicy,
  trustedPhysicalProof, nowSeconds = () => Math.floor(Date.now() / 1000) } = {}) {
  if (!tlsKey || !cert || !clientCa
    || typeof authorizedClientFingerprint256 !== "string"
    || !PIN.test(authorizedClientFingerprint256)
    || !key(policyPrivateKey, "private") || !key(floorPrivateKey, "private")
    || !key(witnessPublicKey, "public") || !key(physicalPublicKey, "public")
    || typeof trustedOwnerPolicy !== "function" || typeof trustedPhysicalProof !== "function"
    || typeof nowSeconds !== "function") deny();
  const signers = [fp(crypto.createPublicKey(policyPrivateKey)),
    fp(crypto.createPublicKey(floorPrivateKey)), fp(witnessPublicKey), fp(physicalPublicKey)];
  for (let i = 0; i < signers.length; i++) for (let j = i + 1; j < signers.length; j++) {
    if (eq(signers[i], signers[j])) deny();
  }
  const server = https.createServer({ key: tlsKey, cert, ca: clientCa,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, async (req, res) => {
    try {
      const principal = peerPrincipal(req.socket, authorizedClientFingerprint256);
      if (req.method !== "POST" || !["/v1/policy", "/v1/terminal"].includes(req.url)) {
        return respond(res, 404, { error: "NOT_FOUND" });
      }
      const wire = await bodyJson(req);
      const now = nowSeconds();
      if (!Number.isSafeInteger(now) || now < 1) deny();
      let result;
      if (req.url === "/v1/policy") {
        const proposed = requestFromWire(wire);
        if (proposed.expiresAt <= now || proposed.expiresAt > now + 60) deny();
        // Only the server's separately trusted LIVE owner-state oracle can
        // affirm this exact principal, device, epoch and CAS/catalog head.
        const authorized = await trustedOwnerPolicy({ ...proposed, principal });
        exact(authorized, [...SCOPE, "owner_revision", "owner_digest",
          "operation_id", "signer_device_id", "epoch", "sequence",
          "catalog_digest", "cas_signer_spki_sha256", "expires_at", "principal"]);
        const expected = { ...proposed.scope, owner_revision: proposed.ownerRevision,
          owner_digest: proposed.ownerDigest, operation_id: proposed.operationId,
          signer_device_id: proposed.signerDeviceId, epoch: proposed.epoch,
          sequence: proposed.sequence, catalog_digest: proposed.catalogDigest,
          cas_signer_spki_sha256: proposed.floorCasSignerFingerprint,
          expires_at: proposed.expiresAt, principal };
        if (!sameFields(authorized, expected, Object.keys(expected))) deny();
        // A policy provider can await slow external storage/transport. Recheck
        // its LIVE decision and clock after the delay, before signing anything.
        const fresh = await trustedOwnerPolicy({ ...proposed, principal });
        exact(fresh, Object.keys(expected));
        const atSign = nowSeconds();
        if (!sameFields(fresh, expected, Object.keys(expected))
          || !Number.isSafeInteger(atSign) || atSign < now
          || proposed.expiresAt <= atSign || proposed.expiresAt > atSign + 60) deny();
        result = await sign(policyPrivateKey, {
          type: "rootark-recovery-witness-catalog-policy-grant/v1", ...expected,
          nonce: crypto.randomBytes(32), issued_at: atSign,
        }, POLICY_DOMAIN);
      } else {
        exact(wire, ["ticket"]);
        const ticket = await verify(b64(wire.ticket, 1, 4096),
          witnessPublicKey, WITNESS_DOMAIN, TICKET_FIELDS);
        if (ticket.type !== "rootark-recovery-witness-catalog-admission/v1"
          || ticket.principal !== principal || !Number.isSafeInteger(ticket.expires_at)
          || ticket.expires_at < now || ticket.expires_at > now + 60) deny();
        bytes(ticket.witness_key_id, 16);
        bytes(ticket.admission_id, 16);
        bytes(ticket.floor_nonce, 32);
        // A signed generic floor HEAD is insufficient. Require separately
        // signed, operation-specific FULL-durable physical terminal evidence.
        const rawProof = await trustedPhysicalProof(ticket);
        const observed = await verify(rawProof, physicalPublicKey, PHYSICAL_DOMAIN, PHYSICAL_FIELDS);
        const fields = [...SCOPE, "admission_id", "operation_id", "owner_revision",
          "owner_digest", "signer_device_id", "epoch", "sequence", "catalog_digest",
          "cas_signer_spki_sha256", "floor_nonce", "expires_at", "principal"];
        if (observed.type !== "rootark-zk1-catalog-physical-operation-terminal/v1"
          || observed.committed !== true || !sameFields(observed, ticket, fields)
          || !Number.isSafeInteger(observed.observed_at)
          || observed.observed_at > ticket.expires_at
          || Math.abs(now - observed.observed_at) > 30) deny();
        const readyAt = nowSeconds();
        if (!Number.isSafeInteger(readyAt) || readyAt < now
          || readyAt > ticket.expires_at
          || Math.abs(readyAt - observed.observed_at) > 30) deny();
        result = await sign(floorPrivateKey, { type: "rootark-zk1-opaque-catalog-witness-terminal/v1",
          ...Object.fromEntries(SCOPE.map((f) => [f, ticket[f]])),
          admission_id: ticket.admission_id, operation_id: ticket.operation_id,
          owner_revision: ticket.owner_revision, owner_digest: ticket.owner_digest,
          signer_device_id: ticket.signer_device_id, epoch: ticket.epoch,
          sequence: ticket.sequence, digest: ticket.catalog_digest,
          cas_signer_spki_sha256: ticket.cas_signer_spki_sha256,
          nonce: ticket.floor_nonce, expires_at: ticket.expires_at,
          observed_at: observed.observed_at }, FLOOR_DOMAIN);
      }
      respond(res, 200, { signedProof: result.toString("base64url") });
    } catch (_) { respond(res, 403, { error: "DENIED" }); }
  });
  return server;
}
function createCatalogAuthorityHttpsClient({ endpoint, ca, key: clientKey, cert,
  serverSpkiSha256 } = {}) {
  let url;
  try { url = new URL(endpoint); } catch (_) { deny(); }
  if (url.protocol !== "https:" || url.username || url.password
    || url.pathname !== "/" || url.search || url.hash
    || !ca || !clientKey || !cert) deny();
  const pinned = bytes(serverSpkiSha256, 32);
  async function send(route, payload) {
    return new Promise((resolve, reject) => {
      const encoded = Buffer.from(JSON.stringify(payload));
      const req = https.request({ hostname: url.hostname, port: url.port || 443,
        path: route, method: "POST", ca, key: clientKey, cert, agent: false,
        minVersion: "TLSv1.3", rejectUnauthorized: true,
        checkServerIdentity(name, peer) {
          const err = tls.checkServerIdentity(name, peer);
          if (err) return err;
          try {
            const actual = fp(new crypto.X509Certificate(peer.raw).publicKey);
            if (!eq(actual, pinned)) return Error("CATALOG_EXTERNAL_DENIED");
          } catch (_) { return Error("CATALOG_EXTERNAL_DENIED"); }
          return undefined;
        },
        headers: { "content-type": "application/json", "content-length": encoded.length },
      }, (res) => {
        let size = 0; const chunks = [];
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size > 8192) res.destroy();
          else chunks.push(chunk);
        });
        res.on("end", () => {
          try {
            if (res.statusCode !== 200) deny();
            const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            exact(result, ["signedProof"]);
            resolve(b64(result.signedProof, 1, 4096));
          } catch (_) { reject(Error("CATALOG_EXTERNAL_DENIED")); }
        });
        res.on("error", () => reject(Error("CATALOG_EXTERNAL_DENIED")));
      });
      // Explicit peer-pin assertion on EVERY secure connection. Relying on
      // checkServerIdentity alone can be skipped by TLS session resumption.
      req.on("socket", (socket) => {
        socket.once("secureConnect", () => {
          try {
            const peer = socket.getPeerCertificate(true);
            if (!socket.authorized || !peer?.raw
              || !eq(fp(new crypto.X509Certificate(peer.raw).publicKey), pinned)) {
              req.destroy(Error("CATALOG_EXTERNAL_DENIED"));
            }
          } catch (_) { req.destroy(Error("CATALOG_EXTERNAL_DENIED")); }
        });
      });
      req.setTimeout(4000, () => req.destroy());
      req.on("error", () => reject(Error("CATALOG_EXTERNAL_DENIED")));
      req.end(encoded);
    });
  }
  return Object.freeze({
    async policyGrant(request) { return send("/v1/policy", requestToWire(request)); },
    async floorTerminal(ticket) {
      return send("/v1/terminal", { ticket: Buffer.from(ticket).toString("base64url") });
    },
  });
}
module.exports = { createCatalogAuthorityHttpsServer, createCatalogAuthorityHttpsClient,
  CATALOG_PHYSICAL_DOMAIN: PHYSICAL_DOMAIN };
