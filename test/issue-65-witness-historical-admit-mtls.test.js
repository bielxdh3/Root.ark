"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../src/services/zk1WitnessHttpsServer");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const z = require("../src/crypto/rootark-zk-1");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { envelopeBinding } =
  require("../sync-client/rootark-sync-zk1-physical-binding");
const { createSyncV2HistoricalEvidenceProvider } =
  require("../sync-client/rootark-sync-v2-historical-evidence-provider");
const { signCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");

const FENCE_DOMAIN = Buffer.from("Root.ark/zk-1/witness-cas-physical-floor/v2\0");
const HISTORICAL_DOMAIN = Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0");
const ENTRY_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");
const random = (n) => crypto.randomBytes(n);
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest();
function scope() { return { account_id: random(16),
  compartment_id: Buffer.from("private"), keyring_id: random(16) }; }
const wireScope = (value) => Object.fromEntries(Object.entries(value)
  .map(([name, bytes]) => [name, bytes.toString("base64url")]));
const signed = (key, domain, unsigned) => crypto.sign(null, Buffer.concat([
  domain, Buffer.from(JSON.stringify(unsigned))]), key).toString("base64url");

test("dedicated witness historical mTLS principal enforces scope, challenge and role", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-historical-mtls-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "W2 Historical Admission Dedicated mTLS CA",
    servers: ["server"], clients: ["historical", "recovery", "anchor", "denied", "wrongscope"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const fingerprint = (name) => new crypto.X509Certificate(read(name + ".pem")).fingerprint256;
  const allowed = scope();
  const forbiddenScope = scope();
  const witness = crypto.generateKeyPairSync("ed25519");
  const device = crypto.generateKeyPairSync("ed25519");
  const inventorySigner = crypto.generateKeyPairSync("ed25519");
  const physicalSigner = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = random(16), statusKeyId = random(16);
  const inventorySignerId = random(16);
  const deviceSpki = device.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const expectedRoot = random(32);
  const syncEnvelope = createOperation({ operation: "create", operationId: "w2-mtls-admission",
    objectId: "w2-mtls-object", deviceId: "device-a", compartmentId: "private",
    keyEpoch: "epoch-7", revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "cipher-only.dat" }, plaintext: Buffer.from("opaque ciphertext"),
    fileKey: random(32) });
  syncEnvelope.authorization = await createAuthorizationProof(syncEnvelope, {
    username: "alice", privateKey: device.privateKey, publicKey: deviceSpki,
    expiresAt: Date.now() + 15000 });
  const bound = envelopeBinding(syncEnvelope, allowed, 0, expectedRoot);
  const unsignedEntry = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: inventorySignerId, scope: allowed,
    sequence: 1, previous_root: expectedRoot, root: random(32),
    operation_id: bound.operation.operation_id, expected_sequence: 0,
    expected_root: expectedRoot,
    request_digest: sha(await z.encodeDeterministic(bound.operation)),
    entry: { object_id: bound.operation.object_id, revision: bound.operation.revision,
      epoch: bound.operation.epoch, ciphertext_sha256: bound.operation.ciphertext_sha256 } };
  const inventoryReceipt = Buffer.from(await z.encodeDeterministic({ ...unsignedEntry,
    signature: crypto.sign(null, Buffer.concat([ENTRY_DOMAIN,
      Buffer.from(await z.encodeDeterministic(unsignedEntry))]), inventorySigner.privateKey) }));
  let called = 0, received;
  let corruptNonce = false, corruptFence = false;
  let corruptProof = "";
  let alreadyIssued = false;
  let issuedState;
  const recoveredNonces = new Set();
  let recoveryCalls = 0;
  const floor = {
    requiresPhysicalAttestation: true,
    supportsClientHistoricalNonce: true,
    advance() { throw Error("UNUSED_LEGACY"); },
    freshHeadAsync() { throw Error("UNUSED_HEAD"); },
    async issueSyncHistoricalAdmission(input) {
      called += 1;
      received = input;
      if (alreadyIssued) throw new Error("WITNESS_CAS_FLOOR_DENIED");
      const head = { type: "rootark-zk1-witness-cas-physical-floor/v2",
        witnessKeyId: witnessKeyId.toString("base64url"),
        statusKeyId: statusKeyId.toString("base64url"),
        sequence: 5, lastHash: random(32).toString("hex"),
        physicalFenceDigest: random(32).toString("hex"),
        nonce: corruptNonce ? random(32).toString("base64url")
          : input.nonce.toString("base64url") };
      const freshFloor = { ...head, signature: signed(witness.privateKey,
        FENCE_DOMAIN, head) };
      const accepted = envelopeBinding(input.envelope, input.scope, input.expectedSequence,
        input.expectedRoot);
      const admissionUnsigned = {
        type: "rootark-sync-v2-historical-witness-admission/v1",
        envelopeSha256: sha(accepted.canonicalEnvelope).toString("base64url"),
        operationId: accepted.operation.operation_id.toString("base64url"),
        deviceId: accepted.envelope.deviceId,
        deviceSpkiSha256: sha(Buffer.from(accepted.envelope.authorization.publicKey,
          "base64url")).toString("base64url"),
        epoch: accepted.operation.epoch,
        checkpointSequence: accepted.operation.expected_sequence,
        checkpointRoot: accepted.operation.expected_root.toString("base64url"),
        inventoryReceiptSha256: sha(input.inventoryReceipt).toString("base64url"),
        admittedAtMs: Date.now(),
        witnessSequence: head.sequence, witnessLastHash: head.lastHash,
        witnessPhysicalFenceDigest: corruptFence ? random(32).toString("hex")
          : head.physicalFenceDigest };
      const readback = { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
        walFlushConfirmed: true, authorizesIo: false, provesIndependentOperator: false,
        generation: 4, admissionId: random(16),
        operationId: accepted.operation.operation_id, revision: accepted.operation.revision,
        epoch: accepted.operation.epoch,
        expectedInventorySequence: accepted.operation.expected_sequence,
        expectedInventoryRoot: accepted.operation.expected_root,
        ciphertextSha256: accepted.operation.ciphertext_sha256,
        digest: random(32), root: random(32), chunkCount: 1 };
      const attestation = await signCommittedPhysicalReadback({
        scope: input.scope, operation: accepted.operation,
        nonce: corruptProof === "wrong-nonce" ? random(32) : input.nonce,
        readback, issuedAt: Math.floor(Date.now() / 1000) }, physicalSigner.privateKey);
      if (!corruptNonce && !corruptFence && !corruptProof) alreadyIssued = true;
      const issued = { freshFloor, admission: { ...admissionUnsigned,
        signature: signed(witness.privateKey, HISTORICAL_DOMAIN, admissionUnsigned) },
      ...(corruptProof === "missing" ? {} : {
        physicalAttestation: corruptProof === "malformed" ? "not-a-buffer"
          : corruptProof === "oversize" ? Buffer.alloc(2049) : attestation,
      }) };
      if (alreadyIssued && !issuedState) issuedState = issued;
      return issued;
    },
    async recoverSyncHistoricalAdmission(input) {
      recoveryCalls += 1;
      if (!issuedState || !Buffer.isBuffer(input.nonce) || input.nonce.length !== 32
        || recoveredNonces.has(input.nonce.toString("base64url"))) {
        throw Error("RECOVERY_UNAVAILABLE");
      }
      const bound = envelopeBinding(input.envelope, input.scope, input.expectedSequence,
        input.expectedRoot);
      if (issuedState.admission.envelopeSha256 !== sha(bound.canonicalEnvelope).toString("base64url")
        || issuedState.admission.inventoryReceiptSha256
          !== sha(input.inventoryReceipt).toString("base64url")) throw Error("RECOVERY_UNAVAILABLE");
      const floorUnsigned = { ...issuedState.freshFloor,
        nonce: input.nonce.toString("base64url") };
      delete floorUnsigned.signature;
      const freshFloor = { ...floorUnsigned,
        signature: signed(witness.privateKey, FENCE_DOMAIN, floorUnsigned) };
      const physicalAttestation = await signCommittedPhysicalReadback({
        scope: input.scope, operation: bound.operation, nonce: input.nonce,
        readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED",
          verified: true, walFlushConfirmed: true, authorizesIo: false,
          provesIndependentOperator: false, generation: 4, admissionId: random(16),
          operationId: bound.operation.operation_id, revision: bound.operation.revision,
          epoch: bound.operation.epoch, expectedInventorySequence: bound.operation.expected_sequence,
          expectedInventoryRoot: bound.operation.expected_root,
          ciphertextSha256: bound.operation.ciphertext_sha256,
          digest: random(32), root: random(32), chunkCount: 1 },
        issuedAt: Math.floor(Date.now() / 1000),
      }, physicalSigner.privateKey);
      recoveredNonces.add(input.nonce.toString("base64url"));
      return { admission: issuedState.admission, freshFloor, physicalAttestation,
        recoveredDurableAdmission: true };
    },
  };
  const none = async () => { throw Error("WRONG_LEDGER_ROLE"); };
  const ledger = { reserve: none, freshHead: none, resolve: none,
    prepareQuiesce: none, cancelExpiredQuiesce: none,
    beginIoAdmission: none, finishIoAdmission: none };
  const make = (roles) => createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    casAnchorFloor: floor, ledger, principals: roles,
  });
  const auth = { [fingerprint("historical")]: {
    roles: ["cas-historical-admit"], scopes: [wireScope(allowed)] },
    [fingerprint("recovery")]: {
      roles: ["cas-historical-admit"], scopes: [wireScope(allowed)] },
    [fingerprint("anchor")]: { roles: ["cas-anchor"], scopes: [] },
    [fingerprint("denied")]: { roles: ["head"], scopes: [wireScope(allowed)] },
    [fingerprint("wrongscope")]: {
      roles: ["cas-historical-admit"], scopes: [wireScope(forbiddenScope)] } };
  assert.throws(() => make({ [fingerprint("historical")]: {
    roles: ["cas-historical-admit", "cas-anchor"], scopes: [wireScope(allowed)] } }),
  /WITNESS_API_INVALID/, "historical-admit must not inherit global CAS-anchor privilege");
  assert.throws(() => make({ [fingerprint("historical")]: {
    roles: ["cas-historical-admit"], scopes: [] } }),
  /WITNESS_API_INVALID/, "historical role cannot authorize wildcard scope");
  assert.throws(() => createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    ledger, casAnchorFloor: { ...floor, requiresPhysicalAttestation: false },
    principals: { [fingerprint("historical")]: auth[fingerprint("historical")] },
  }), /WITNESS_API_INVALID/, "role cannot bind a legacy non-physical witness");
  assert.throws(() => createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    ledger, casAnchorFloor: { ...floor, supportsClientHistoricalNonce: false },
    principals: { [fingerprint("historical")]: auth[fingerprint("historical")] },
  }), /WITNESS_API_INVALID/,
  "old W2 issuer must be rejected before it can commit an unusable server-nonce receipt");
  const server = make(auth);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => drainZk1WitnessHttpsServer(server));
  const challenge = random(32);
  const data = { envelope: syncEnvelope, scope: wireScope(allowed),
    expectedSequence: 0, expectedRoot: expectedRoot.toString("base64url"),
    inventoryReceipt: inventoryReceipt.toString("base64url"),
    nonce: challenge.toString("base64url") };
  const post = (name, body, route = "/v1/cas-anchor/historical-admit", method = "POST") =>
    new Promise((resolve, reject) => {
      const payload = Buffer.from(JSON.stringify(body));
      const req = https.request({ hostname: "127.0.0.1", port: server.address().port,
        servername: "localhost", ca: read("ca.pem"),
        cert: read(name + ".pem"), key: read(name + ".key"),
        minVersion: "TLSv1.3", rejectUnauthorized: true,
        method, path: route, headers: { "content-type": "application/json",
          "content-length": payload.length } }, (res) => {
        const parts = [];
        res.on("data", (chunk) => parts.push(chunk));
        res.once("end", () => resolve({ status: res.statusCode,
          data: JSON.parse(Buffer.concat(parts).toString("utf8")) }));
      });
      req.once("error", reject);
      req.end(payload);
    });
  assert.equal((await post("anchor", data)).status, 403,
    "global CAS status role cannot issue Sync historical receipts");
  assert.equal((await post("denied", data)).status, 403);
  assert.equal((await post("wrongscope", data)).status, 403);
  assert.equal(called, 0, "reject unauthorized callers before invoking issuer");
  assert.equal((await post("historical", { ...data, nonce: random(31).toString("base64url") })).status, 400);
  assert.equal((await post("historical", { ...data, nonce: random(33).toString("base64url") })).status, 400);
  assert.equal((await post("historical", { ...data, nonce: "noncanonical==" })).status, 400);
  assert.equal((await post("historical", { ...data, extra: "rollback" })).status, 400);
  assert.equal((await post("historical", data, "/v1/cas-anchor/historical-admit", "GET")).status, 404);
  assert.equal(called, 0, "invalid nonce/field/method must not invoke issuer");
  corruptNonce = true;
  assert.notEqual((await post("historical", data)).status, 200,
    "fail closed if the issuer generated its own nonce (old W2 backend)");
  corruptNonce = false;
  corruptFence = true;
  assert.notEqual((await post("historical", data)).status, 200,
    "response cannot combine signed admission with a different physical floor");
  corruptFence = false;
  corruptProof = "missing";
  assert.notEqual((await post("historical", data)).status, 200,
    "issuer cannot omit PG attestation from successful HTTP response");
  corruptProof = "malformed";
  assert.notEqual((await post("historical", data)).status, 200,
    "issuer cannot claim success with non-Buffer physical attestation");
  corruptProof = "oversize";
  assert.notEqual((await post("historical", data)).status, 200,
    "signed physical evidence must be bounded to 2048 bytes");
  corruptProof = "wrong-nonce";
  assert.notEqual((await post("historical", data)).status, 200,
    "issuer cannot relay independently signed PG attestation for a different nonce");
  corruptProof = "";
  const answer = await post("historical", data);
  assert.equal(answer.status, 200);
  assert.ok(typeof answer.data.physicalAttestation === "string"
    && answer.data.physicalAttestation.length > 0,
  "successful HTTP result must contain the issuer-supplied signed PG proof");
  assert.equal(answer.data.freshFloor.nonce, data.nonce);
  assert.deepEqual(received.nonce, challenge);
  assert.deepEqual(received.scope, allowed);
  assert.equal(received.inventoryReceipt.toString("base64url"), data.inventoryReceipt);
  assert.equal(received.expectedRoot.toString("base64url"), data.expectedRoot);
  const { signature, ...unsigned } = answer.data.freshFloor;
  assert.equal(crypto.verify(null, Buffer.concat([FENCE_DOMAIN,
    Buffer.from(JSON.stringify(unsigned))]), witness.publicKey,
  Buffer.from(signature, "base64url")), true,
  "fresh floor contains a genuine Ed25519 signature on the *client* nonce");
  assert.equal(answer.data.authority, "WITNESS_SYNC_HISTORICAL_ADMISSION_V1");
  assert.notEqual((await post("historical", data)).status, 200,
    "an exact client nonce and operation replay cannot mint a second historical admission");
  const recoverRoute = "/v1/cas-anchor/historical-recover";
  const freshRecovery = { ...data, nonce: random(32).toString("base64url") };
  assert.equal((await post("denied", freshRecovery, recoverRoute)).status, 403);
  assert.equal((await post("wrongscope", freshRecovery, recoverRoute)).status, 403);
  assert.equal((await post("historical", freshRecovery, recoverRoute, "GET")).status, 404);
  const recovered = await post("recovery", freshRecovery, recoverRoute);
  assert.equal(recovered.status, 200,
    "separate authenticated mTLS route retrieves original signed admission");
  assert.equal(recovered.data.freshFloor.nonce, freshRecovery.nonce);
  assert.deepEqual(recovered.data.admission, answer.data.admission,
    "recovery must not re-sign or alter persisted receipt");
  assert.equal(recoveryCalls, 1, "wrong peer/scope never reaches recovery authority");
  assert.notEqual((await post("recovery", freshRecovery, recoverRoute)).status, 200,
    "replayed challenge cannot recover twice");
  // Exercise the ACTUAL consumer transport adapter, rather than only a
  // hand-built HTTPS POST. Its independent inventory source and signer pin
  // must remain immutable while switching to the recovery route.
  const provider = createSyncV2HistoricalEvidenceProvider({
    endpoint: `https://127.0.0.1:${server.address().port}`,
    ca: read("ca.pem"), clientKey: read("recovery.key"),
    clientCert: read("recovery.pem"),
    serverFingerprint256: fingerprint("server"),
    pinnedInventoryPublicKey: inventorySigner.publicKey,
    pinnedInventorySignerKeyId: inventorySignerId,
    trustedInventoryEvidenceProvider: async () => ({
      scope: allowed, expectedSequence: 0, expectedRoot,
      receipt: inventoryReceipt,
    }),
  });
  const providerChallenge = random(32);
  const recoveredByClient = await provider(syncEnvelope, {
    nonce: providerChallenge, recovery: true,
  });
  assert.deepEqual(recoveredByClient.admission, answer.data.admission);
  assert.equal(recoveredByClient.freshFloor.nonce, providerChallenge.toString("base64url"));
  // This issuer is a crypto fixture, not a replacement for W2's durable
  // SQLite authority. The published consumer itself validates both signatures
  // and an independently challenged signed PG physical readback here.
  const physicalAttestation = Buffer.from(answer.data.physicalAttestation, "base64url");
  const minimum = { sequence: answer.data.freshFloor.sequence,
    lastHash: answer.data.freshFloor.lastHash,
    physicalFenceDigest: answer.data.freshFloor.physicalFenceDigest };
  // The W2 base predates the published strict consumer. Release integration
  // can set ROOTARK_PUBLISHED_SYNC_BINDING to a file from the published commit.
  // A fixture-only mTLS run must not pretend it exercised that consumer.
  const consumerPath = process.env.ROOTARK_PUBLISHED_SYNC_BINDING;
  const realConsumer = consumerPath
    ? require(path.resolve(consumerPath)).verifySyncV2HistoricalWitnessAdmission
    : require("../sync-client/rootark-sync-zk1-physical-binding")
      .verifySyncV2HistoricalWitnessAdmission;
  if (typeof realConsumer !== "function") {
    t.diagnostic("Published strict Sync v2 consumer absent from W2 base; external consumer integration not asserted");
    return;
  }
  const verify = (extra = {}) => realConsumer({
    envelope: syncEnvelope, scope: allowed, expectedSequence: 0, expectedRoot,
    receipt: inventoryReceipt, physicalAttestation, nonce: challenge,
    pinnedInventoryPublicKey: inventorySigner.publicKey,
    pinnedInventorySignerKeyId: inventorySignerId,
    pinnedPhysicalAttestorPublicKey: physicalSigner.publicKey,
    localTrustedDevicePolicy: { username: "alice", trustedDevicePublicKeys: {
      "device-a": deviceSpki }, revokedDeviceIds: [] },
    trustedCurrentDevicePolicyProvider: () => ({ username: "alice",
      trustedDevicePublicKeys: { "device-a": deviceSpki }, revokedDeviceIds: [] }),
    admission: answer.data.admission, freshFloor: answer.data.freshFloor,
    pinnedWitnessPublicKey: witness.publicKey,
    witnessKeyId, statusKeyId, trustedMinimumFloor: minimum, ...extra });
  const wall = Date.now;
  try {
    Date.now = () => syncEnvelope.authorization.expiresAt + 1000;
    assert.equal((await verify()).authorizesHistoricalRead, true,
      "published strict Sync v2 verifier accepts real Ed25519 admission, nonce-bound floor and PG proof");
  } finally { Date.now = wall; }
  await assert.rejects(verify({ nonce: random(32) }),
    /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
  "tampered challenge cannot replay physical signed admission evidence");
  const verifiedRecovery = await verify({
    nonce: providerChallenge, admission: recoveredByClient.admission,
    freshFloor: recoveredByClient.freshFloor,
    physicalAttestation: recoveredByClient.physicalAttestation,
  });
  assert.equal(verifiedRecovery.authorizesHistoricalRead, true,
    "real Sync transport + exact pinned verifier accept recovered receipt and NEW challenge");
});

test("historical mTLS admission limits per principal/global concurrent JSON buffering and request rate", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-historical-capacity-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  generateNativeFixtureCertificates(dir, { caSubject: "Historical Admission Capacity CA",
    servers: ["server"], clients: ["a", "b", "c"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const allowed = scope();
  const role = { roles: ["cas-historical-admit"], scopes: [wireScope(allowed)] };
  const principals = Object.fromEntries(["a", "b", "c"].map((name) =>
    [new crypto.X509Certificate(read(name + ".pem")).fingerprint256, role]));
  let issued = 0;
  let resume;
  const blocked = new Promise((resolve) => { resume = resolve; });
  const unusable = async () => { throw Error("UNUSED"); };
  const floor = { requiresPhysicalAttestation: true, supportsClientHistoricalNonce: true,
    advance: unusable, freshHeadAsync: unusable,
    recoverSyncHistoricalAdmission: unusable,
    async issueSyncHistoricalAdmission() {
      issued += 1;
      await blocked;
      throw new Error("SIMULATED_WITNESS_ISSUER_DENIED");
    } };
  const server = createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    casAnchorFloor: floor,
    ledger: { reserve: unusable, freshHead: unusable, resolve: unusable,
      prepareQuiesce: unusable, cancelExpiredQuiesce: unusable,
      beginIoAdmission: unusable, finishIoAdmission: unusable },
    principals,
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { resume(); await drainZk1WitnessHttpsServer(server); });
  const reqBody = JSON.stringify({ envelope: { ciphertext: "opaque" },
    scope: wireScope(allowed), expectedSequence: 0,
    expectedRoot: random(32).toString("base64url"),
    inventoryReceipt: random(100).toString("base64url"),
    nonce: random(32).toString("base64url") });
  const request = (who, body = reqBody) => new Promise((resolve, reject) => {
    const payload = Buffer.from(body);
    const req = https.request({ hostname: "127.0.0.1", port: server.address().port,
      servername: "localhost", ca: read("ca.pem"), cert: read(who + ".pem"),
      key: read(who + ".key"), method: "POST",
      path: "/v1/cas-anchor/historical-admit",
      headers: { "content-type": "application/json", "content-length": payload.length },
    }, (res) => { res.resume(); res.once("end", () => resolve(res.statusCode)); });
    req.once("error", reject);
    req.end(payload);
  });
  const headersOnly = (who) => new Promise((resolve, reject) => {
    let done = false;
    const req = https.request({ hostname: "127.0.0.1", port: server.address().port,
      servername: "localhost", ca: read("ca.pem"), cert: read(who + ".pem"),
      key: read(who + ".key"), method: "POST",
      path: "/v1/cas-anchor/historical-admit",
      headers: { "content-type": "application/json",
        "content-length": String(12 * 1024 * 1024) },
    }, (res) => { res.resume(); res.once("end", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(res.statusCode);
      req.destroy();
    }); });
    req.once("error", (error) => { if (!done) { done = true; clearTimeout(timer); reject(error); } });
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      req.destroy();
      reject(new Error("historical admission must reject before buffering a 12MiB HTTP body"));
    }, 1500);
    req.flushHeaders(); // deliberately NEVER transmit a body
  });
  const aPending = request("a");
  // A second request from A is rejected even while A's first 12MiB-capable
  // body may be buffered or an expensive physical PG challenge is pending.
  for (let attempts = 0; issued < 1 && attempts < 100; attempts += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(issued, 1, "first W2 issuer must actually be in flight");
  assert.equal(await request("a"), 429,
    "same mTLS principal cannot occupy a second large request buffer");
  const bPending = request("b");
  for (let attempts = 0; issued < 2 && attempts < 100; attempts += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(issued, 2, "two distinct principals can fill the global in-flight budget");
  assert.equal(await headersOnly("c"), 429,
    "third authenticated principal must be rejected before even receiving a 12MiB JSON body");
  resume();
  assert.equal(await aPending, 503);
  assert.equal(await bPending, 503);
  // The fixed monotonic rate budget is independent of in-flight capacity.
  // A and B spent one accepted request each; rejecting over-limit requests
  // must not schedule more signer or PostgreSQL work.
  for (let i = 0; i < 11; i += 1) assert.equal(await request("a"), 503);
  assert.equal(await request("a"), 429,
    "per-principal budget admits at most 12 requests per 60-second window");
  for (let i = 0; i < 11; i += 1) assert.equal(await request("b"), 503);
  assert.equal(await request("c"), 429,
    "global 24/60s budget prevents fresh certificates from bypassing capacity");
  assert.equal(issued, 24,
    "rate-limited HTTP requests never enter the expensive W2 issuer queue");
});
