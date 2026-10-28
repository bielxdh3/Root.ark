"use strict";

// All certificates and Ed25519 private keys are generated in disposable
// restricted test storage. This fixture is COHOSTED: it does not establish
// operator independence or external production custody.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const test = require("node:test");
const { generateNativeFixtureCertificates } = require("./support/issue-65-native-openssl-fixture");
const { privateAuthorityDirectory } = require("./support/issue-65-private-authority-directory");
const { signOwnerCutover, digestOwnerCutover, buildSparseEnrollmentProof,
  signatureBytes } = require("../src/crypto/rootark-zk10-account-cutover-v1");
const { createZk10LegacyCutoverFence, ZK10_HEAD_DOMAIN, ZK10_PROOF_DOMAIN,
  ZK10_WITNESS_DOMAIN, isAuthenticZk10LegacyCutoverFence } =
  require("../src/services/zk10LegacyCutoverFence");

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
    servers: ["authority", "witness"], clients: ["client", "foreign"] });
  const read = (f) => fs.readFileSync(path.join(dir, f));
  const ca = read("ca.pem");
  const clientCert = read("client.pem");
  const clientKey = read("client.key");
  const clientPin = new crypto.X509Certificate(clientCert).fingerprint256;
  const authorityKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const username = "alice";
  const entries = [];
  let heads = [];
  const leases = new Map();
  const state = { badAuthoritySig: false, badWitnessSig: false, badProof: false,
    witnessRollback: false, unavailable: false, forceEnrolledAsNegative: false,
    authorityRollback: false, witnessFalseStatus: false, replayChallenge: false,
    badHeadSignature: false,
    releaseCount: 0, admittedCount: 0 };
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
  function accept(req, res, handler) {
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
        res.end(body);
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
        lease_id: lease, issued_at_ms: now, lease_expires_at_ms: now + 3000 };
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
        nonce: request.nonce, issued_at_ms: at,
        expires_at_ms: at + 3000 }, state.badWitnessSig
        ? crypto.generateKeyPairSync("ed25519").privateKey : witnessKeys.privateKey,
      ZK10_WITNESS_DOMAIN) };
    }));
  const authorityPort = await onServer(authorityServer);
  const witnessPort = await onServer(witnessServer);
  t.after(async () => {
    await Promise.all([closeServer(authorityServer), closeServer(witnessServer)]);
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
  return { state, cutover, makeFence, endpoints, leases, username,
    ownerPublicKey: ownerKeys.publicKey };
}

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
