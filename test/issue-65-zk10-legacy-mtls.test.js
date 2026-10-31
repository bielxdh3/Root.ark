"use strict";

// All certificates and Ed25519 private keys are generated in disposable
// restricted test storage. This fixture is COHOSTED: it does not establish
// operator independence or external production custody.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const http = require("node:http");
const path = require("node:path");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const registerAuthRoutes = require("../src/routes/auth");
const { createAuthenticate } = require("../src/middlewares/auth");
const { registerSyncRoutes } = require("../src/routes/sync");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const test = require("node:test");
const { generateNativeFixtureCertificates } = require("./support/issue-65-native-openssl-fixture");
const { privateAuthorityDirectory } = require("./support/issue-65-private-authority-directory");
const { signOwnerCutover, digestOwnerCutover, buildSparseEnrollmentProof,
  signatureBytes } = require("../src/crypto/rootark-zk10-account-cutover-v1");
const { createZk10LegacyCutoverFence, ZK10_HEAD_DOMAIN, ZK10_PROOF_DOMAIN,
  ZK10_WITNESS_DOMAIN, ZK10_EXTERNAL_FLOOR_DOMAIN,
  createZk10ExternallyAttestedLegacyFence, isAuthenticZk10LegacyCutoverFence } =
  require("../src/services/zk10LegacyCutoverFence");
const { runZk10LegacyWebDavOperation } = require("../src/services/zk10LegacyWebDavRouteGuard");

const b64 = (v) => Buffer.from(v).toString("base64url");
const ID = (n) => b64(Buffer.alloc(16, n));
const SHA = (n) => Buffer.alloc(32, n).toString("hex");
const H = (v) => crypto.createHash("sha256").update(v).digest("hex");
function sign(payload, signingKey, domain) {
  return { ...payload, signature: b64(crypto.sign(null,
    signatureBytes(domain, payload), signingKey)) };
}
function headDigest(head) {
  const { signature, ...payload } = head;
  return H(Buffer.concat([signatureBytes(ZK10_HEAD_DOMAIN, payload),
    Buffer.from(signature, "base64url")]));
}
function onServer(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}
function closeServer(server) {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(resolve));
}
async function fixture(t) {
  const dir = privateAuthorityDirectory("zk65-zk10-mtls-");
  generateNativeFixtureCertificates(dir, { caSubject: "ZK10 test-only CA",
    servers: ["authority", "witness", "custodian"], clients: ["client", "foreign"] });
  const read = (f) => fs.readFileSync(path.join(dir, f));
  const ca = read("ca.pem");
  const clientCert = read("client.pem");
  const clientKey = read("client.key");
  const clientPin = new crypto.X509Certificate(clientCert).fingerprint256;
  const authorityKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const custodianKeys = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const username = "alice";
  const entries = [];
  let heads = [];
  const leases = new Map();
  const state = { badAuthoritySig: false, badWitnessSig: false, badProof: false,
    witnessRollback: false, unavailable: false, forceEnrolledAsNegative: false,
    authorityRollback: false, witnessFalseStatus: false, replayChallenge: false,
    badHeadSignature: false,
    releaseCount: 0, admittedCount: 0, onRelease: null,
    custodianUnavailable: false, custodianWrongSignature: false,
    custodianWrongHead: false, custodianReplayNonce: false,
    custodianShortExpiry: false,
    witnessShortExpiry: false, custodianResponseDelayMs: 0, leaseDurationMs: 3000,
    custodianIssuedAtOverride: undefined, custodianExpiresAtOverride: undefined,
    witnessIssuedAtOverride: undefined, witnessExpiresAtOverride: undefined };
  const signedHead = (root) => {
    const previous = heads.length ? headDigest(heads[heads.length - 1]) : "0".repeat(64);
    heads.push(sign({ type: "rootark-zk10-account-authority-head/v1",
      sequence: heads.length + 1, previous_head_digest: previous,
      enrollment_root: root }, authorityKeys.privateKey, ZK10_HEAD_DOMAIN));
  };
  signedHead(buildSparseEnrollmentProof([], ID(1)).root);
  const ownerStatement = signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1", immutable_account_id: ID(1),
    zk_account_id: ID(9), generation: 1, previous_cutover_digest: null,
    inventory_head: SHA(4), complete_corpus: true, covered_compartments: [ID(8)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced", grants: [], suite: "zk1-v2",
    nonce: b64(Buffer.alloc(32, 2)), issued_at: Math.floor(Date.now() / 1000) - 5,
  }, ownerKeys.privateKey);
  function cutover() {
    if (leases.size) return false;
    entries.push({ accountId: ID(1), cutoverDigest: digestOwnerCutover(ownerStatement) });
    signedHead(buildSparseEnrollmentProof(entries, ID(1)).root);
    return true;
  }
  function accept(req, res, handler, delayMs = () => 0) {
    if (!req.socket.authorized || req.socket.getProtocol() !== "TLSv1.3"
      || req.socket.getPeerCertificate()?.fingerprint256 !== clientPin) {
      res.writeHead(403); res.end(); return;
    }
    if (state.unavailable) { res.writeHead(503); res.end(); return; }
    let size = 0;
    const parts = [];
    req.on("data", (p) => {
      size += p.length;
      if (size > 4096) req.destroy(); else parts.push(p);
    });
    req.on("end", () => {
      try {
        const result = handler(req.url, JSON.parse(Buffer.concat(parts).toString("utf8")));
        const body = Buffer.from(JSON.stringify(result));
        res.writeHead(200, { "content-type": "application/json", "content-length": body.length });
        const delay = delayMs();
        if (delay > 0) setTimeout(() => res.end(body), delay);
        else res.end(body);
      } catch (_) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end('{"error":"DENIED"}');
      }
    });
  }
  const authorityServer = https.createServer({ key: read("authority.key"),
    cert: read("authority.pem"), ca, requestCert: true,
    rejectUnauthorized: true, minVersion: "TLSv1.3" }, (req, res) => accept(req, res,
    (route, request) => {
      if (route === "/v1/zk10/release") {
        const lease = leases.get(request.lease_id);
        if (!lease || lease.account !== request.immutable_account_id
          || lease.operation !== request.operation) throw Error("bad release");
        if (state.onRelease) state.onRelease(request, lease);
        leases.delete(request.lease_id);
        state.releaseCount += 1;
        return { released: true };
      }
      if (route !== "/v1/zk10/authorize") throw Error("wrong endpoint");
      const authoritativeEntries = state.authorityRollback ? [] : entries;
      const authoritativeHeads = state.authorityRollback ? heads.slice(0, 1) : heads;
      const proof = buildSparseEnrollmentProof(authoritativeEntries, request.immutable_account_id);
      const enrolled = authoritativeEntries.some((r) => r.accountId === request.immutable_account_id);
      const now = Date.now();
      const lease = b64(crypto.randomBytes(16));
      leases.set(lease, { account: request.immutable_account_id, operation: request.operation });
      state.admittedCount += 1;
      const payload = { type: "rootark-zk10-account-legacy-admission/v1",
        sequence: authoritativeHeads.length,
        head_digest: headDigest(authoritativeHeads[authoritativeHeads.length - 1]),
        immutable_account_id: request.immutable_account_id,
        identity_digest: request.identity_digest, operation: request.operation,
        challenge: state.replayChallenge ? b64(Buffer.alloc(32, 9)) : request.challenge,
        nonce: request.nonce,
        status: enrolled && !state.forceEnrolledAsNegative ? "protected_enforced" : "never_enrolled",
        owner_statement: enrolled && !state.forceEnrolledAsNegative ? ownerStatement : null,
        owner_statement_history: enrolled && !state.forceEnrolledAsNegative
          ? [ownerStatement] : [], owner_rotations: [],
        siblings: state.badProof ? proof.siblings.map(() => SHA(3)) : proof.siblings,
        lease_id: lease, issued_at_ms: now,
        lease_expires_at_ms: now + state.leaseDurationMs };
      const signed = sign(payload, state.badAuthoritySig
        ? crypto.generateKeyPairSync("ed25519").privateKey : authorityKeys.privateKey,
      ZK10_PROOF_DOMAIN);
      return { head_chain: state.badHeadSignature ? authoritativeHeads.map((h) => ({
        ...h, signature: b64(Buffer.alloc(64, 7)) })) : authoritativeHeads,
      admission: signed };
    }));
  const witnessServer = https.createServer({ key: read("witness.key"),
    cert: read("witness.pem"), ca, requestCert: true,
    rejectUnauthorized: true, minVersion: "TLSv1.3" }, (req, res) => accept(req, res,
    (route, request) => {
      if (route !== "/v1/zk10/current") throw Error("wrong endpoint");
      const at = Date.now();
      return { current: sign({ type: "rootark-zk10-account-current-floor/v1",
        sequence: state.witnessRollback ? 0 : heads.length,
        head_digest: state.witnessRollback ? "0".repeat(64) : headDigest(heads[heads.length - 1]),
        immutable_account_id: request.immutable_account_id,
        identity_digest: request.identity_digest,
        status: state.witnessFalseStatus ? "never_enrolled"
          : entries.some((r) => r.accountId === request.immutable_account_id)
          ? "protected_enforced" : "never_enrolled",
        nonce: request.nonce,
        issued_at_ms: state.witnessIssuedAtOverride === undefined
          ? at : state.witnessIssuedAtOverride,
        expires_at_ms: state.witnessExpiresAtOverride === undefined
          ? at + (state.witnessShortExpiry ? 500 : 3000)
          : state.witnessExpiresAtOverride }, state.badWitnessSig
        ? crypto.generateKeyPairSync("ed25519").privateKey : witnessKeys.privateKey,
      ZK10_WITNESS_DOMAIN) };
    }));
  const custodianServer = https.createServer({ key: read("custodian.key"),
    cert: read("custodian.pem"), ca, requestCert: true,
    rejectUnauthorized: true, minVersion: "TLSv1.3" }, (req, res) => accept(req, res,
    (route, request) => {
      if (route !== "/v1/zk10/external-floor/current" || state.custodianUnavailable)
        throw Error("floor unavailable");
      const at = Date.now();
      return { floor: sign({ type: "rootark-zk10-external-floor-current/v1",
        sequence: state.custodianWrongHead ? heads.length - 1 : heads.length,
        head_digest: headDigest(heads[heads.length - 1]),
        enrollment_root: heads[heads.length - 1].enrollment_root,
        immutable_account_id: request.immutable_account_id,
        identity_digest: request.identity_digest, operation: request.operation,
        nonce: state.custodianReplayNonce ? b64(Buffer.alloc(32, 3)) : request.nonce,
        lease_id: request.lease_id, lease_expires_at_ms: request.lease_expires_at_ms,
        issued_at_ms: state.custodianIssuedAtOverride === undefined
          ? at : state.custodianIssuedAtOverride,
        expires_at_ms: state.custodianExpiresAtOverride === undefined
          ? (state.custodianShortExpiry ? request.lease_expires_at_ms - 100 : at + 3000)
          : state.custodianExpiresAtOverride,
      }, state.custodianWrongSignature
        ? witnessKeys.privateKey : custodianKeys.privateKey, ZK10_EXTERNAL_FLOOR_DOMAIN) };
    }, () => state.custodianResponseDelayMs));
  const authorityPort = await onServer(authorityServer);
  const witnessPort = await onServer(witnessServer);
  const custodianPort = await onServer(custodianServer);
  t.after(async () => {
    await Promise.all([closeServer(authorityServer), closeServer(witnessServer),
      closeServer(custodianServer)]);
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const endpoints = [
    { endpoint: `https://127.0.0.1:${authorityPort}/`, ca, clientCert, clientKey,
      serverFingerprint256: new crypto.X509Certificate(read("authority.pem")).fingerprint256,
      signingPublicKey: authorityKeys.publicKey },
    { endpoint: `https://127.0.0.1:${witnessPort}/`, ca, clientCert, clientKey,
      serverFingerprint256: new crypto.X509Certificate(read("witness.pem")).fingerprint256,
      signingPublicKey: witnessKeys.publicKey },
  ];
  const makeFence = (overrides = {}) => createZk10LegacyCutoverFence({
    resolveDurableAccountIdentity: async (user) => ({
      immutableAccountId: Buffer.alloc(16, user === "alice" ? 1 : 6),
      serverAccountIdentity: { durableUserId: Buffer.alloc(16, user === "alice" ? 2 : 7),
        authenticatedUsername: user } }),
    independentlyPinnedOwnerRoots: new Map([[ID(1), {
      publicKey: ownerKeys.publicKey, canonicalZkAccountId: ID(9) }]]),
    independentlyPinnedIdentityBindings: new Map([
      ["alice", { immutableAccountId: ID(1), durableUserId: ID(2) }],
      ["bob", { immutableAccountId: ID(6), durableUserId: ID(7) }],
    ]),
    independentlyRetainedFloor: { sequence: 0, digest: "0".repeat(64),
      enrollmentRoot: null },
    authority: endpoints[0], witness: endpoints[1], ...overrides,
  });
  const independentFloor = { endpoint: `https://127.0.0.1:${custodianPort}/`,
    ca, clientCert, clientKey,
    serverFingerprint256: new crypto.X509Certificate(read("custodian.pem")).fingerprint256,
    signingPublicKey: custodianKeys.publicKey };
  const makeAttestedFence = (overrides = {}) =>
    createZk10ExternallyAttestedLegacyFence({
      resolveDurableAccountIdentity: async (user) => ({
        immutableAccountId: Buffer.alloc(16, user === "alice" ? 1 : 6),
        serverAccountIdentity: { durableUserId: Buffer.alloc(16, user === "alice" ? 2 : 7),
          authenticatedUsername: user } }),
      independentlyPinnedOwnerRoots: new Map([[ID(1), {
        publicKey: ownerKeys.publicKey, canonicalZkAccountId: ID(9) }]]),
      independentlyPinnedIdentityBindings: new Map([
        ["alice", { immutableAccountId: ID(1), durableUserId: ID(2) }],
        ["bob", { immutableAccountId: ID(6), durableUserId: ID(7) }],
      ]),
      independentlyRetainedFloor: { sequence: 0, digest: "0".repeat(64),
        enrollmentRoot: null },
      authority: endpoints[0], witness: endpoints[1], independentFloor,
      ...overrides,
    });
  return { state, cutover, makeFence, makeAttestedFence, independentFloor,
    endpoints, leases, username,
    ownerPublicKey: ownerKeys.publicKey };
}

test("ZK10 production-bound admission requires third live pinned external floor", {
  timeout: 90000,
}, async (t) => {
  const f = await fixture(t);
  assert.throws(() => f.makeAttestedFence({ independentFloor: undefined }),
    { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  assert.throws(() => f.makeAttestedFence({ independentFloor: f.endpoints[1] }),
    { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" }, "cannot recycle witness custody");
  assert.throws(() => f.makeAttestedFence({ independentFloor: {
    ...f.independentFloor, signingPublicKey: f.ownerPublicKey,
  } }), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
  "owner signing key cannot double as external monotonic floor custody");
  const fence = f.makeAttestedFence();
  let callbacks = 0;
  const exercise = () => fence.withCurrentAccountLegacyPolicy({
    authenticatedUsername: "alice", operation: "sync:get",
  }, async ({ assertActive }) => {
    callbacks += 1;
    assertActive();
    return "GRANTED";
  });
  assert.equal(await exercise(), "GRANTED");
  for (const flag of ["custodianWrongSignature", "custodianWrongHead",
    "custodianReplayNonce", "custodianUnavailable", "custodianShortExpiry",
    "witnessShortExpiry"]) {
    f.state[flag] = true;
    await assert.rejects(exercise(), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" }, flag);
    f.state[flag] = false;
  }
  for (const flag of ["custodianIssuedAtOverride", "custodianExpiresAtOverride",
    "witnessIssuedAtOverride", "witnessExpiresAtOverride"]) {
    for (const value of ["invalid-date", "1730000000000", null, 1.5]) {
      f.state[flag] = value;
      await assert.rejects(exercise(), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
        `signed ${flag}=${String(value)} must be a bounded safe integer`);
    }
    f.state[flag] = undefined;
  }
  f.state.leaseDurationMs = 900;
  f.state.custodianResponseDelayMs = 1200;
  await assert.rejects(exercise(), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
    "expired lease after signed remote response must never invoke the callback");
  assert.equal(callbacks, 1, "only the initial admitted request can enter the callback");
  f.state.leaseDurationMs = 3000;
  f.state.custodianResponseDelayMs = 0;
  assert.equal(f.cutover(), true);
  await assert.rejects(exercise(), { code: "ZK10_LEGACY_ENFORCED" });
});

test("ZK10 real TLS1.3/mTLS CURRENT, signed negative proof, monotonic cutover and leases", {
  timeout: 90000,
}, async (t) => {
  const f = await fixture(t);
  assert.throws(() => f.makeFence({ independentlyRetainedFloor: {
    sequence: 0, digest: "0".repeat(64), enrollmentRoot: SHA(2),
  } }), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
  "unsigned genesis cannot smuggle a committed enrollment root");
  const fence = f.makeFence();
  assert.equal(isAuthenticZk10LegacyCutoverFence(fence), true);
  assert.equal(isAuthenticZk10LegacyCutoverFence({
    withCurrentAccountLegacyPolicy: fence.withCurrentAccountLegacyPolicy }), false);
  assert.equal(fence.independentOffServerCustodyProven, false);
  const exercise = (user, operation = "sync:list") => fence.withCurrentAccountLegacyPolicy({
    authenticatedUsername: user, operation }, async ({ status, signal, assertActive }) => {
    assert.equal(status, "never_enrolled");
    assert.equal(signal.aborted, false);
    assertActive();
    return "legacy-safe";
  });
  assert.equal(await exercise("alice"), "legacy-safe");
  assert.equal(f.leases.size, 0);
  await fence.withCurrentAccountLegacyPolicy({ authenticatedUsername: "alice",
    operation: "sync:put" }, async ({ assertActive }) => {
    assertActive();
    assert.equal(f.cutover(), false, "external authority serializes cutover against live I/O");
  });
  assert.equal(f.cutover(), true);
  await assert.rejects(exercise("alice"), { code: "ZK10_LEGACY_ENFORCED", status: 403 });
  await assert.rejects(f.makeFence().withCurrentAccountLegacyPolicy({
    authenticatedUsername: "alice", operation: "sync:delete" },
  () => "LEAK AFTER PROCESS RESTART"),
  { code: "ZK10_LEGACY_ENFORCED", status: 403 },
  "recreated process with unchanged external authority still denies old data");
  const wrongCanonicalMapping = f.makeFence({
    independentlyPinnedOwnerRoots: new Map([[ID(1), {
      publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
      canonicalZkAccountId: ID(9) }]]),
  });
  await assert.rejects(wrongCanonicalMapping.withCurrentAccountLegacyPolicy({
    authenticatedUsername: "alice", operation: "sync:get" }, () => "LEAK"),
  { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  const wrongZkAccountMapping = f.makeFence({
    independentlyPinnedOwnerRoots: new Map([[ID(1), {
      publicKey: f.ownerPublicKey, canonicalZkAccountId: ID(3) }]]),
  });
  await assert.rejects(wrongZkAccountMapping.withCurrentAccountLegacyPolicy({
    authenticatedUsername: "alice", operation: "sync:get" }, () => "LEAK"),
  { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  assert.equal(await exercise("bob"), "legacy-safe", "unrelated account has current nonmembership proof");
  assert.equal(f.leases.size, 0);
  assert.ok(f.state.releaseCount >= 4);

  f.state.forceEnrolledAsNegative = true;
  await assert.rejects(exercise("alice"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE", status: 503 });
  f.state.forceEnrolledAsNegative = false;
  f.state.authorityRollback = true;
  await assert.rejects(exercise("alice"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  f.state.authorityRollback = false;
  f.state.witnessRollback = true;
  await assert.rejects(exercise("bob"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  f.state.witnessRollback = false;
  f.state.replayChallenge = true;
  await assert.rejects(exercise("bob"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
    "signed admission replay for a different challenge must fail closed");
  f.state.replayChallenge = false;
  f.state.badHeadSignature = true;
  await assert.rejects(exercise("bob"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
    "a correctly signed admission cannot redeem a forged historical head");
  f.state.badHeadSignature = false;
  f.state.witnessFalseStatus = true;
  await assert.rejects(exercise("alice"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
    "independent witness must deny conflicting ever-enrolled status");
  f.state.witnessFalseStatus = false;
  f.state.badProof = true;
  await assert.rejects(exercise("bob"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  f.state.badProof = false;
  f.state.badWitnessSig = true;
  await assert.rejects(exercise("bob"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  f.state.badWitnessSig = false;
  f.state.badAuthoritySig = true;
  await assert.rejects(exercise("bob"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  f.state.badAuthoritySig = false;
  f.state.unavailable = true;
  await assert.rejects(exercise("bob"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
  f.state.unavailable = false;
  assert.throws(() => f.makeFence({
    independentlyPinnedIdentityBindings: new Map([["alice", {
      immutableAccountId: ID(6), durableUserId: ID(2) }],
    ["bob", { immutableAccountId: ID(6), durableUserId: ID(7) }]]),
  }), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
  "username recycle cannot rebind an existing durable account to another UUID");
  await assert.rejects(f.makeFence({
    resolveDurableAccountIdentity: async () => ({ immutableAccountId: Buffer.alloc(16, 1),
      serverAccountIdentity: { durableUserId: Buffer.alloc(16, 8),
        authenticatedUsername: "alice" } }),
  }).withCurrentAccountLegacyPolicy({ authenticatedUsername: "alice",
    operation: "sync:get" }, () => "LEAK"),
  { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
  "restored local account ID does not override independently pinned identity");
  await assert.rejects(exercise("renamed-alice"), {
    code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" },
  "unregistered username alias cannot silently escape the original enrolled UUID");
  const wrongPin = { ...f.endpoints[0], serverFingerprint256:
    "00:".repeat(31) + "00" };
  await assert.rejects(f.makeFence({ authority: wrongPin })
    .withCurrentAccountLegacyPolicy({ authenticatedUsername: "bob", operation: "sync:get" },
      () => "UNSAFE"), { code: "ZK10_CURRENT_AUTHORITY_UNAVAILABLE" });
});

function httpJson(port, route, method = "GET", body, token) {
  const bytes = body === undefined ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, path: route, method,
      headers: { ...(bytes ? { "content-type": "application/json",
        "content-length": bytes.length } : {}),
      ...(token ? { authorization: "Bearer " + token } : {}) },
      signal: AbortSignal.timeout(10000),
    }, (res) => {
      const chunks = [];
      res.on("data", (part) => chunks.push(part));
      res.on("error", reject);
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers,
            body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        } catch (error) { reject(error); }
      });
    });
    req.on("error", reject);
    req.end(bytes);
  });
}

function httpWebDavRead(port, token) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port,
      path: "/dav/legacy-object", method: "GET",
      headers: { authorization: "Bearer " + token },
      signal: AbortSignal.timeout(10000) }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode,
        body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

test("ZK10 DEV-OFF real Express login/JWT → signed never_enrolled mTLS → durable Sync and post-finish lease release", {
  timeout: 90000,
}, async (t) => {
  // These two separately signed TLS1.3/mTLS endpoints run on the SAME test
  // machine. This tests transport + cryptographic admission, NEVER independent
  // physical custody or durable external monotonic floor in production.
  const f = await fixture(t);
  const dir = privateAuthorityDirectory("zk65-zk10-http-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const storagePath = path.join(dir, "sync.json");
  const users = [
    { username: "alice", password: bcrypt.hashSync("alice-test-only", 4),
      sessionVersion: 0, role: "user", totpEnabled: false,
      permissions: { listFiles: true, upload: true, delete: true } },
    { username: "bob", password: bcrypt.hashSync("bob-test-only", 4),
      sessionVersion: 0, role: "user", totpEnabled: false,
      permissions: { listFiles: true, upload: true, delete: true } },
  ];
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  const authenticate = createAuthenticate({ jwt, jwtSecret,
    loadUser: (name) => users.find((item) => item.username === name),
    normalizeUserPermissions: (item) => item.permissions });
  const permission = (scope) => (req, res, next) => req.user?.permissions?.[scope] === true
    ? next() : res.status(403).json({ error: "Forbidden" });
  let writeResponseFinished = false;
  let cutoverAtResponseFinish = null;
  const writeReleaseObservations = [];
  f.state.onRelease = (request) => {
    if (request.operation !== "write") return;
    const saved = fs.readFileSync(storagePath, "utf8");
    writeReleaseObservations.push({
      responseFinished: writeResponseFinished,
      alreadyDurable: saved.includes('"http-signed-object"')
        && saved.includes('"signed-legacy-name.txt"'),
    });
  };
  const running = new Set();
  t.after(async () => {
    for (const server of running) await closeServer(server);
  });
  async function start(fence) {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
      if (req.method === "POST" && req.path === "/sync/v1/objects")
        res.once("finish", () => {
          writeResponseFinished = true;
          // Even the final HTTP flush must remain inside the signed lease.
          cutoverAtResponseFinish = f.cutover();
        });
      next();
    });
    registerAuthRoutes(app, {
      authenticate, auditLog: () => {}, bcrypt, checkAnomalies: () => {},
      getAuditActor: (_req, username) => ({ username, role: "user", ip: "127.0.0.1" }),
      jwt, jwtSecret, loadUsers: () => users, saveUsers: () => {},
      getTotpKey: () => Buffer.alloc(32, 1), logAnalyticsEvent: () => {},
      normalizeUserPermissions: (item) => item.permissions,
      qrcode: {}, requirePermission: permission,
      sessionCookieOptions: { httpOnly: true, sameSite: "lax" },
    });
    // Exercise the exact WebDAV boundary helper through real JWT auth and
    // the genuine signed mTLS adapter; main server still has no owner bootstrap.
    app.get("/dav/legacy-object", authenticate, (req, res) =>
      runZk10LegacyWebDavOperation({ req, res, strict: true,
        legacyCutoverFence: fence, operation: "webdav:get" },
      () => res.status(200).send("legacy-read-only-object")));
    const { ready } = registerSyncRoutes({ app, authenticate,
      requirePermission: permission, storagePath,
      legacyCutoverStrict: true, legacyCutoverFence: fence,
      bcrypt, loadUsers: () => users,
    });
    await ready;
    const server = http.createServer(app);
    const port = await onServer(server);
    running.add(server);
    return { server, port };
  }
  async function stop(server) {
    running.delete(server);
    await closeServer(server);
  }
  async function login(port, username, password) {
    const response = await httpJson(port, "/auth/login", "POST", { username, password });
    assert.equal(response.status, 200);
    const cookie = response.headers["set-cookie"].find((item) =>
      item.startsWith("rootark_session="));
    assert.ok(cookie, "token must be issued by the real auth/login endpoint");
    const token = cookie.split(";")[0].slice("rootark_session=".length);
    assert.equal(jwt.verify(token, jwtSecret, { algorithms: ["HS256"] }).username, username);
    return token;
  }
  async function awaitRelease(count) {
    const deadline = Date.now() + 5000;
    while (f.state.releaseCount < count && Date.now() < deadline)
      await new Promise((resolve) => setTimeout(resolve, 10));
    assert.ok(f.state.releaseCount >= count, "external lease release must complete");
  }

  const noAuthority = await start(null);
  const prelogin = await login(noAuthority.port, "alice", "alice-test-only");
  const failClosed = await httpJson(noAuthority.port, "/sync/v1/objects", "GET", undefined, prelogin);
  assert.equal(failClosed.status, 503);
  assert.equal(failClosed.body.code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
  await stop(noAuthority.server);

  const fence = f.makeFence();
  assert.equal(isAuthenticZk10LegacyCutoverFence(fence), true);
  assert.equal(fence.independentOffServerCustodyProven, false);
  const enabled = await start(fence);
  const alice = await login(enabled.port, "alice", "alice-test-only");
  const bob = await login(enabled.port, "bob", "bob-test-only");
  assert.deepEqual(await httpWebDavRead(enabled.port, alice),
    { status: 200, body: "legacy-read-only-object" },
    "signed never_enrolled lease admits a read until HTTP response finishes");
  assert.equal((await httpJson(enabled.port, "/sync/v1/objects", "GET", undefined, alice)).status, 200);
  await awaitRelease(f.state.admittedCount);
  const operation = createOperation({ operation: "create", objectId: "http-signed-object",
    fileId: "file-a", versionId: "v1", operationId: "signed-op-a",
    deviceId: "device-a", keyEpoch: "legacy-epoch", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { name: "signed-legacy-name.txt", path: "personal/signed-legacy-name.txt" },
    plaintext: Buffer.from("ciphertext under old client keys"), fileKey: crypto.randomBytes(32),
  });
  const write = await httpJson(enabled.port, "/sync/v1/objects", "POST", operation, alice);
  assert.equal(write.status, 201, JSON.stringify(write.body));
  await awaitRelease(f.state.admittedCount);
  assert.deepEqual(writeReleaseObservations, [{ responseFinished: true, alreadyDurable: true }],
    "authority release must occur AFTER Express response finish and durable file write");
  assert.equal(cutoverAtResponseFinish, false,
    "cohosted test authority must not cut over while HTTP response is finishing");
  assert.equal(f.leases.size, 0);
  const read = await httpJson(enabled.port, "/sync/v1/objects/http-signed-object",
    "GET", undefined, alice);
  assert.equal(read.status, 200);
  assert.equal(read.body.metadata.name, "signed-legacy-name.txt");
  const other = await httpJson(enabled.port, "/sync/v1/objects", "GET", undefined, bob);
  assert.equal(other.status, 200);
  assert.deepEqual(other.body.objects, [], "signed negative proof is account-scoped");
  await awaitRelease(f.state.admittedCount - 0);
  assert.equal(f.leases.size, 0);

  assert.equal(f.cutover(), true, "all prior HTTP leases must have been released");
  const blocked = await httpJson(enabled.port, "/sync/v1/objects/http-signed-object",
    "GET", undefined, alice);
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.code, "ZK10_LEGACY_ENFORCED");
  assert.equal((await httpWebDavRead(enabled.port, alice)).status, 403,
    "signed protected_enforced must close the legacy WebDAV read path");
  assert.equal((await httpWebDavRead(enabled.port, bob)).status, 200,
    "another verified never_enrolled account remains readable");
  const blockedResume = await httpJson(enabled.port,
    "/sync/v1/devices/device-a/resume", "POST", { password: "alice-test-only" }, alice);
  assert.equal(blockedResume.status, 403, "resume must not reopen legacy writes after cutover");
  assert.equal((await httpJson(enabled.port, "/sync/v1/objects", "GET",
    undefined, bob)).status, 200);
  users[0].sessionVersion += 1;
  assert.equal((await httpJson(enabled.port, "/sync/v1/objects", "GET",
    undefined, alice)).status, 401, "real JWT revocation remains effective");
  await stop(enabled.server);

  // Recreating the app/fence is a disposable process-restart simulation: the
  // signed external cutover head remains at the fixture authority.
  const restarted = await start(f.makeFence());
  const freshAlice = await login(restarted.port, "alice", "alice-test-only");
  assert.equal((await httpJson(restarted.port, "/sync/v1/objects", "GET",
    undefined, freshAlice)).status, 403);
  await stop(restarted.server);

  const wrongPin = { ...f.endpoints[0], serverFingerprint256: "00:".repeat(31) + "00" };
  const untrusted = await start(f.makeFence({ authority: wrongPin }));
  const freshBob = await login(untrusted.port, "bob", "bob-test-only");
  assert.equal((await httpJson(untrusted.port, "/sync/v1/objects", "GET",
    undefined, freshBob)).status, 503, "TLS identity pin mismatch fails closed");
  await stop(untrusted.server);

  const missingIdentityBinding = await start(f.makeFence({
    independentlyPinnedIdentityBindings: new Map(),
  }));
  const unsignedBob = await login(missingIdentityBinding.port, "bob", "bob-test-only");
  assert.equal((await httpJson(missingIdentityBinding.port, "/sync/v1/objects",
    "GET", undefined, unsignedBob)).status, 503,
  "without a server-pinned durable account identity, TLS signatures alone do not allow legacy");
  await stop(missingIdentityBinding.server);

  const forged = await start({ withCurrentAccountLegacyPolicy: async (_, callback) =>
    callback({ status: "never_enrolled", assertActive: () => {},
      immutableAccountId: ID(6) }) });
  const fakeBob = await login(forged.port, "bob", "bob-test-only");
  assert.equal((await httpJson(forged.port, "/sync/v1/objects", "GET",
    undefined, fakeBob)).status, 503, "duck-typed attacker function is not a trusted fence");
  await stop(forged.server);
});
