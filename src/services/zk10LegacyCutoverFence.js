"use strict";

// DEV-OFF. No production route mounts this adapter. Operator-supplied TLS,
// signer pins and an independently retained minimum are mandatory. A cohosted
// fixture verifies this protocol but NEVER proves independently owned custody.
const crypto = require("node:crypto");
const https = require("node:https");
const net = require("node:net");
const tls = require("node:tls");
const {
  exact, decode, hex, key, spkiHash, signatureBytes, verifyOwnerCutover,
  digestOwnerCutover, verifyOwnerRotationKeys, verifyOwnerCutoverHistory,
  verifySparseEnrollmentProof,
} = require("../crypto/rootark-zk10-account-cutover-v1");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk10/account-authority-head/v1\0");
const PROOF_DOMAIN = Buffer.from("Root.ark/zk10/account-legacy-admission/v1\0");
const WITNESS_DOMAIN = Buffer.from("Root.ark/zk10/account-current-floor/v1\0");
const HEAD_FIELDS = ["type", "sequence", "previous_head_digest", "enrollment_root"];
const ADMISSION_FIELDS = ["type", "sequence", "head_digest", "immutable_account_id",
  "identity_digest", "operation", "challenge", "nonce", "status",
  "owner_statement", "owner_statement_history", "owner_rotations", "siblings", "lease_id", "issued_at_ms",
  "lease_expires_at_ms"];
const CURRENT_FIELDS = ["type", "sequence", "head_digest", "immutable_account_id",
  "identity_digest", "status", "nonce", "issued_at_ms", "expires_at_ms"];
const FINGERPRINT = /^(?:[a-f0-9]{2}:){31}[a-f0-9]{2}$/i;
const OPER = /^[a-z][a-z0-9:_-]{0,63}$/;
const NATIVE_CRYPTO_VERIFY = crypto.verify;
const NATIVE_HTTPS_REQUEST = https.request;
const NATIVE_NOW = Date.now.bind(Date);
const branded = new WeakSet();
const authenticFences = new WeakSet();

function unavailable() {
  const error = new Error("ZK10_CURRENT_AUTHORITY_UNAVAILABLE");
  error.code = error.message;
  error.status = 503;
  throw error;
}
function blocked() {
  const error = new Error("ZK10_LEGACY_ENFORCED");
  error.code = error.message;
  error.status = 403;
  throw error;
}
function boundedMs(number, lower, upper) {
  if (!Number.isSafeInteger(number) || number < lower || number > upper) unavailable();
  return number;
}
function safeBytes(value, count) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength !== count) unavailable();
  return Buffer.from(value);
}
function canonicalId(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array)
    return safeBytes(value, 16).toString("base64url");
  return decode(value, 16).toString("base64url");
}
function identityHash(identity, username, uuid) {
  const record = exact(identity, ["durableUserId", "authenticatedUsername"]);
  if (record.authenticatedUsername !== username || typeof username !== "string"
    || username.length < 1 || username.length > 256
    || !/^[^\x00-\x1f\x7f]+$/.test(username)) unavailable();
  const durable = canonicalId(record.durableUserId);
  return crypto.createHash("sha256")
    .update("Root.ark/zk10/server-durable-identity/v1\0")
    .update(JSON.stringify([uuid, durable, username]), "utf8").digest("hex");
}
function signer(privateOrPublic) { return key(privateOrPublic, "public"); }
function unsigned(record, fields) {
  const signed = exact(record, [...fields, "signature"]);
  return { payload: Object.fromEntries(fields.map((f) => [f, signed[f]])),
    signature: decode(signed.signature, 64) };
}
function verifySigned(wire, fields, domain, publicKey) {
  const { payload, signature } = unsigned(wire, fields);
  if (!NATIVE_CRYPTO_VERIFY(null, signatureBytes(domain, payload), publicKey, signature)) unavailable();
  return payload;
}
function headDigest(head) {
  const { payload, signature } = unsigned(head, HEAD_FIELDS);
  return crypto.createHash("sha256").update(signatureBytes(HEAD_DOMAIN, payload))
    .update(signature).digest("hex");
}

function pinnedTransport(settings, route) {
  const v = exact(settings, ["endpoint", "ca", "clientCert", "clientKey",
    "serverFingerprint256", "signingPublicKey"]);
  let endpoint;
  try { endpoint = new URL(v.endpoint); } catch (_) { unavailable(); }
  if (endpoint.protocol !== "https:" || !endpoint.port
    || endpoint.pathname !== "/" || endpoint.search || endpoint.hash
    || endpoint.username || endpoint.password || !endpoint.hostname
    || !FINGERPRINT.test(v.serverFingerprint256)
    || !v.ca || !v.clientCert || !v.clientKey) unavailable();
  const pin = v.serverFingerprint256.toUpperCase();
  const signingKey = signer(v.signingPublicKey);
  const call = (path, body, signal) => {
    const bytes = Buffer.from(JSON.stringify(body));
    if (bytes.length > 4096) unavailable();
    return new Promise((resolve, reject) => {
      let completed = false;
      let req;
      let deadline;
      const fail = () => {
        if (completed) return;
        completed = true;
        clearTimeout(deadline);
        req?.destroy();
        reject(new Error("ZK10_CURRENT_AUTHORITY_UNAVAILABLE"));
      };
      deadline = setTimeout(fail, 3000);
      const finish = (value) => {
        if (completed) return;
        completed = true;
        clearTimeout(deadline);
        resolve(value);
      };
      req = NATIVE_HTTPS_REQUEST({
        hostname: endpoint.hostname, port: endpoint.port, path, method: "POST", agent: false,
        ca: v.ca, cert: v.clientCert, key: v.clientKey,
        rejectUnauthorized: true, minVersion: "TLSv1.3",
        servername: net.isIP(endpoint.hostname) ? "" : endpoint.hostname,
        signal,
        checkServerIdentity(host, peer) {
          const error = tls.checkServerIdentity(host, peer);
          if (error) return error;
          return peer.fingerprint256?.toUpperCase() === pin
            ? undefined : new Error("ZK10_TLS_PEER_NOT_PINNED");
        },
        headers: { "content-type": "application/json", "content-length": bytes.length,
          accept: "application/json" }, timeout: 3000,
      }, (res) => {
        if (res.statusCode !== 200 || !/^application\/json(?:;\s*charset=utf-8)?$/i
          .test(res.headers["content-type"] || "")) { res.resume(); fail(); return; }
        const parts = [];
        let size = 0;
        res.on("data", (part) => {
          size += part.length;
          if (size > 80_000) fail();
          else parts.push(part);
        });
        res.on("end", () => {
          try { finish(JSON.parse(Buffer.concat(parts).toString("utf8"))); }
          catch (_) { fail(); }
        });
        res.on("error", fail);
      });
      // checkServerIdentity may be elided by resumed handshakes: pin after every
      // successful TLS connection as well, with a new socket per request.
      req.on("socket", (socket) => socket.once("secureConnect", () => {
        if (!socket.authorized || socket.getPeerCertificate()?.fingerprint256?.toUpperCase() !== pin)
          req.destroy(new Error("ZK10_TLS_PEER_NOT_PINNED"));
      }));
      req.on("error", fail);
      req.on("timeout", fail);
      req.end(bytes);
    });
  };
  return Object.freeze({ signingKey, endpoint: endpoint.href, pin, call, route });
}

function createZk10LegacyCutoverFence({ resolveDurableAccountIdentity,
  independentlyPinnedOwnerRoots, independentlyPinnedIdentityBindings,
  independentlyRetainedFloor, authority, witness } = {}) {
  if (typeof resolveDurableAccountIdentity !== "function"
    || !(independentlyPinnedOwnerRoots instanceof Map)
    || !(independentlyPinnedIdentityBindings instanceof Map)) unavailable();
  const roots = new Map();
  for (const [uuid, rootPin] of independentlyPinnedOwnerRoots) {
    const canonical = canonicalId(uuid);
    if (roots.has(canonical)) unavailable();
    const pin = exact(rootPin, ["publicKey", "canonicalZkAccountId"]);
    roots.set(canonical, Object.freeze({ publicKey: signer(pin.publicKey),
      canonicalZkAccountId: canonicalId(pin.canonicalZkAccountId) }));
  }
  const identities = new Map();
  const durableBindings = new Map();
  const uuidBindings = new Map();
  for (const [username, identityPin] of independentlyPinnedIdentityBindings) {
    if (typeof username !== "string" || !username.length || username.length > 256
      || identities.has(username)) unavailable();
    const pin = exact(identityPin, ["immutableAccountId", "durableUserId"]);
    const uuid = canonicalId(pin.immutableAccountId);
    const durable = canonicalId(pin.durableUserId);
    if ((durableBindings.has(durable) && durableBindings.get(durable) !== uuid)
      || (uuidBindings.has(uuid) && uuidBindings.get(uuid) !== durable)) unavailable();
    durableBindings.set(durable, uuid);
    uuidBindings.set(uuid, durable);
    identities.set(username, Object.freeze({ uuid, durable }));
  }
  const floor = exact(independentlyRetainedFloor, ["sequence", "digest", "enrollmentRoot"]);
  boundedMs(floor.sequence, 0, Number.MAX_SAFE_INTEGER - 1024);
  hex(floor.digest);
  if (floor.enrollmentRoot !== null) hex(floor.enrollmentRoot);
  if (floor.sequence === 0 && (floor.digest !== "0".repeat(64)
    || floor.enrollmentRoot !== null)) unavailable();
  if (floor.sequence > 0 && floor.enrollmentRoot === null) unavailable();
  const pinnedAuthority = pinnedTransport(authority, "/v1/zk10/authorize");
  const pinnedWitness = pinnedTransport(witness, "/v1/zk10/current");
  if (spkiHash(pinnedAuthority.signingKey) === spkiHash(pinnedWitness.signingKey)
    || (pinnedAuthority.endpoint === pinnedWitness.endpoint
      && pinnedAuthority.pin === pinnedWitness.pin)) unavailable();

  async function verifyCurrentAccountLegacyPolicy({ immutableAccountId,
    serverAccountIdentity, authenticatedUsername, operation, signal, freshChallenge }) {
    let candidateLease;
    try {
      if (typeof operation !== "string" || !OPER.test(operation) || signal?.aborted) unavailable();
      const uuid = canonicalId(immutableAccountId);
      const identityDigest = identityHash(serverAccountIdentity, authenticatedUsername, uuid);
      const pinnedIdentity = identities.get(authenticatedUsername);
      if (!pinnedIdentity || pinnedIdentity.uuid !== uuid
        || pinnedIdentity.durable !== canonicalId(serverAccountIdentity.durableUserId)) unavailable();
      const clientChallenge = freshChallenge === undefined
        ? crypto.randomBytes(32) : safeBytes(freshChallenge, 32);
      const nonce = crypto.randomBytes(32).toString("base64url");
      const request = { immutable_account_id: uuid, identity_digest: identityDigest,
        operation, challenge: clientChallenge.toString("base64url"), nonce };
      const authorityReply = exact(await pinnedAuthority.call(
        pinnedAuthority.route, request, signal), ["head_chain", "admission"]);
      const chain = authorityReply.head_chain;
      if (!Array.isArray(chain) || chain.length > 128
        || Reflect.ownKeys(chain).length !== chain.length + 1) unavailable();
      let sequence = floor.sequence;
      let digest = floor.digest;
      let root = floor.enrollmentRoot;
      for (const signedHead of chain) {
        const head = verifySigned(signedHead, HEAD_FIELDS, HEAD_DOMAIN, pinnedAuthority.signingKey);
        if (head.type !== "rootark-zk10-account-authority-head/v1"
          || head.sequence !== ++sequence || head.previous_head_digest !== digest) unavailable();
        root = hex(head.enrollment_root);
        digest = headDigest(signedHead);
      }
      const admission = verifySigned(authorityReply.admission, ADMISSION_FIELDS,
        PROOF_DOMAIN, pinnedAuthority.signingKey);
      if (admission.type !== "rootark-zk10-account-legacy-admission/v1"
        || admission.sequence !== sequence || admission.head_digest !== digest
        || admission.immutable_account_id !== uuid
        || admission.identity_digest !== identityDigest
        || admission.operation !== operation || admission.challenge !== request.challenge
        || admission.nonce !== nonce) unavailable();
      const at = boundedMs(NATIVE_NOW(), 1, Number.MAX_SAFE_INTEGER);
      boundedMs(admission.issued_at_ms, at - 30_000, at + 1_000);
      boundedMs(admission.lease_expires_at_ms, at + 100, at + 10_000);
      decode(admission.lease_id, 16);
      // The signed authority reservation is real even if subsequent owner,
      // witness, or ancestry verification fails. Best-effort release avoids
      // stranding a valid reservation during adversarial rejection.
      candidateLease = { immutable_account_id: uuid, operation,
        lease_id: admission.lease_id };
      if (admission.status !== "never_enrolled" && admission.status !== "protected_enforced") unavailable();
      if (!root) unavailable();
      if (admission.status === "never_enrolled") {
        if (admission.owner_statement !== null || !Array.isArray(admission.owner_rotations)
          || admission.owner_rotations.length !== 0
          || !Array.isArray(admission.owner_statement_history)
          || admission.owner_statement_history.length !== 0) unavailable();
        verifySparseEnrollmentProof(uuid, null, admission.siblings, root);
      } else {
        const pinnedOwner = roots.get(uuid);
        if (!pinnedOwner) unavailable();
        const signingKeys = verifyOwnerRotationKeys(admission.owner_rotations,
          pinnedOwner.publicKey, uuid);
        const history = verifyOwnerCutoverHistory(admission.owner_statement_history,
          signingKeys, uuid);
        if (history.digest !== digestOwnerCutover(admission.owner_statement)) unavailable();
        const statement = verifyOwnerCutover(admission.owner_statement,
          signingKeys[signingKeys.length - 1]);
        if (statement.immutable_account_id !== uuid
          || statement.zk_account_id !== pinnedOwner.canonicalZkAccountId
          || statement.issued_at > Math.floor(admission.issued_at_ms / 1000)) unavailable();
        verifySparseEnrollmentProof(uuid, digestOwnerCutover(admission.owner_statement),
          admission.siblings, root);
      }
      const current = exact(await pinnedWitness.call(pinnedWitness.route,
        request, signal), ["current"]);
      const trustedCurrent = verifySigned(current.current, CURRENT_FIELDS,
        WITNESS_DOMAIN, pinnedWitness.signingKey);
      if (trustedCurrent.type !== "rootark-zk10-account-current-floor/v1"
        || trustedCurrent.sequence !== sequence || trustedCurrent.head_digest !== digest
        || trustedCurrent.immutable_account_id !== uuid
        || trustedCurrent.identity_digest !== identityDigest
        || trustedCurrent.status !== admission.status
        || trustedCurrent.nonce !== nonce
        || trustedCurrent.expires_at_ms < boundedMs(NATIVE_NOW(), 1, Number.MAX_SAFE_INTEGER)
        || trustedCurrent.expires_at_ms > at + 10_000
        || trustedCurrent.issued_at_ms < at - 30_000
        || trustedCurrent.issued_at_ms > at + 1_000) unavailable();
      const result = Object.freeze({ status: admission.status, immutableAccountId: uuid,
        operation, leaseId: admission.lease_id,
        leaseExpiresAtMs: admission.lease_expires_at_ms });
      branded.add(result);
      candidateLease = undefined; // ownership transfers to the verified fence
      return result;
    } catch (_) {
      if (candidateLease) {
        try { await pinnedAuthority.call("/v1/zk10/release", candidateLease); }
        catch (_) { /* an unreachable authority retains its expiring reservation */ }
      }
      unavailable();
    }
  }

  async function withCurrentAccountLegacyPolicy({ authenticatedUsername, operation }, callback) {
    if (typeof callback !== "function") unavailable();
    // This resolver MUST be server-owned, backed by a durable immutable ID;
    // JWT username by itself never is an authoritative account UUID.
    let identity;
    try { identity = exact(await resolveDurableAccountIdentity(authenticatedUsername),
      ["immutableAccountId", "serverAccountIdentity"]); } catch (_) { unavailable(); }
    const decision = await verifyCurrentAccountLegacyPolicy({ ...identity,
      authenticatedUsername, operation });
    if (!branded.has(decision)) unavailable();
    let accepted = false;
    const deadline = decision.leaseExpiresAtMs - NATIVE_NOW() - 100;
    const aborter = new AbortController();
    if (deadline < 1) {
      try { await pinnedAuthority.call("/v1/zk10/release", {
        immutable_account_id: decision.immutableAccountId, operation,
        lease_id: decision.leaseId }); } catch (_) { /* expires externally */ }
      unavailable();
    }
    const deadlineTimer = setTimeout(() => aborter.abort(), deadline);
    const assertActive = () => {
      if (aborter.signal.aborted || NATIVE_NOW() >= decision.leaseExpiresAtMs - 100) unavailable();
    };
    try {
      if (decision.status === "protected_enforced") blocked();
      accepted = true;
      assertActive();
      const value = await callback(Object.freeze({ status: decision.status,
        immutableAccountId: decision.immutableAccountId,
        signal: aborter.signal, assertActive }));
      assertActive();
      return value;
    } finally {
      clearTimeout(deadlineTimer);
      aborter.abort();
      // A failed release cannot make a denied operation allowed; the authority
      // must retain its lease until release or a physically enforced expiry.
      try {
        const released = exact(await pinnedAuthority.call("/v1/zk10/release", {
          immutable_account_id: decision.immutableAccountId,
          operation, lease_id: decision.leaseId,
        }), ["released"]);
        if (released.released !== true) unavailable();
      } catch (error) {
        if (accepted) unavailable();
      }
    }
  }
  const fence = Object.freeze({ withCurrentAccountLegacyPolicy,
    // This software cannot observe who physically owns the witness machines.
    // Operator-provided topology and external custody require separate proof.
    independentOffServerCustodyProven: false });
  authenticFences.add(fence);
  return fence;
}

function isAuthenticZk10LegacyCutoverFence(value) {
  return value !== null && typeof value === "object" && authenticFences.has(value);
}
module.exports = { createZk10LegacyCutoverFence,
  isAuthenticZk10LegacyCutoverFence,
  // Only useful for producing signed disposable fixture packets, not an I/O grant.
  ZK10_HEAD_DOMAIN: HEAD_DOMAIN, ZK10_PROOF_DOMAIN: PROOF_DOMAIN,
  ZK10_WITNESS_DOMAIN: WITNESS_DOMAIN, ZK10_HEAD_FIELDS: HEAD_FIELDS,
  ZK10_ADMISSION_FIELDS: ADMISSION_FIELDS, ZK10_CURRENT_FIELDS: CURRENT_FIELDS };
