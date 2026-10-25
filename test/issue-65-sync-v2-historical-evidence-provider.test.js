"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { fork } = require("node:child_process");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { signCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { envelopeBinding, verifySyncV2HistoricalWitnessAdmission } =
  require("../sync-client/rootark-sync-zk1-physical-binding");
const { createSyncV2HistoricalEvidenceProvider } =
  require("../sync-client/rootark-sync-v2-historical-evidence-provider");

const random = crypto.randomBytes;
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("base64url");
const ENTRY_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");
const wireScope = (scope) => Object.fromEntries(Object.entries(scope)
  .map(([key, value]) => [key, value.toString("base64url")]));

function waitForMessage(child, kind) {
  return new Promise((resolve, reject) => {
    const onMessage = (data) => {
      if (data?.kind !== kind) return;
      cleanup(); resolve(data);
    };
    const onExit = () => { cleanup(); reject(new Error("fixture child exited")); };
    const cleanup = () => {
      child.off("message", onMessage);
      child.off("exit", onExit);
    };
    child.on("message", onMessage);
    child.on("exit", onExit);
  });
}
async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server.address().port;
}
async function close(server) {
  await new Promise((resolve, reject) => server.close((error) =>
    error ? reject(error) : resolve()));
}

test("Sync v2 historical provider uses real child witness mTLS and fails closed on hostile replies", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-sync-historical-provider-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "Sync Historical Transport CA", servers: ["server"],
    clients: ["historical", "denied"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const scope = { account_id: random(16), compartment_id: Buffer.from("private"),
    keyring_id: random(16) };
  const device = crypto.generateKeyPairSync("ed25519");
  const inventorySigner = crypto.generateKeyPairSync("ed25519");
  const signerId = random(16), expectedRoot = random(32);
  const deviceSpki = device.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({
    operation: "create", operationId: "historical-transport-1",
    objectId: "opaque-object-1", deviceId: "device-a", compartmentId: "private",
    keyEpoch: "epoch-7", revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "cipher-only.dat" }, plaintext: Buffer.from("only ciphertext"),
    fileKey: random(32),
  });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: device.privateKey, publicKey: deviceSpki,
    expiresAt: Date.now() + 600_000,
  });
  const bound = envelopeBinding(operation, scope, 0, expectedRoot);
  const entry = {
    type: "rootark-content-inventory-entry/v1", version: 1, signer_key_id: signerId,
    scope, sequence: 1, previous_root: expectedRoot, root: random(32),
    operation_id: bound.operation.operation_id, expected_sequence: 0,
    expected_root: expectedRoot,
    request_digest: crypto.createHash("sha256")
      .update(await z.encodeDeterministic(bound.operation)).digest(),
    entry: {
      object_id: bound.operation.object_id, revision: bound.operation.revision,
      epoch: bound.operation.epoch, ciphertext_sha256: bound.operation.ciphertext_sha256,
    },
  };
  const signature = crypto.sign(null,
    Buffer.concat([ENTRY_DOMAIN, await z.encodeDeterministic(entry)]),
    inventorySigner.privateKey);
  const receipt = Buffer.from(await z.encodeDeterministic({ ...entry, signature }));
  const child = fork(path.join(__dirname, "support/issue-65-sync-historical-provider-child.js"),
    [dir, scope.account_id.toString("base64url"), scope.keyring_id.toString("base64url")],
    { stdio: ["ignore", "ignore", "ignore", "ipc"] });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve) => {
        const deadline = setTimeout(() => { child.kill(); resolve(); }, 4000);
        child.once("exit", () => { clearTimeout(deadline); resolve(); });
        child.send("stop");
      });
    }
  });
  const ready = await waitForMessage(child, "ready");
  const fp = new crypto.X509Certificate(read("server.pem")).fingerprint256;
  const trustedSource = async () => ({
    scope, expectedSequence: 0, expectedRoot, receipt,
  });
  const options = {
    endpoint: `https://127.0.0.1:${ready.port}`,
    ca: read("ca.pem"), clientKey: read("historical.key"),
    clientCert: read("historical.pem"), serverFingerprint256: fp,
    trustedInventoryEvidenceProvider: trustedSource,
    pinnedInventoryPublicKey: inventorySigner.publicKey,
    pinnedInventorySignerKeyId: signerId,
    timeoutMs: 3000,
  };
  assert.throws(() => createSyncV2HistoricalEvidenceProvider({
    ...options, trustedInventoryEvidenceProvider: undefined,
  }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/);
  assert.throws(() => createSyncV2HistoricalEvidenceProvider({
    ...options, endpoint: `https://127.0.0.1:${ready.port}/wrong`,
  }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/);
  assert.throws(() => createSyncV2HistoricalEvidenceProvider({
    ...options, serverFingerprint256: "0".repeat(64),
  }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/);
  const provider = createSyncV2HistoricalEvidenceProvider(options);
  const nonce = random(32);
  const observed = waitForMessage(child, "observed");
  const proof = await provider(operation, { nonce });
  const sent = await observed;
  assert.deepEqual(proof.scope, scope);
  assert.equal(proof.expectedSequence, 0);
  assert.deepEqual(proof.expectedRoot, expectedRoot);
  assert.deepEqual(proof.receipt, receipt);
  assert.equal(proof.freshFloor.nonce, nonce.toString("base64url"));
  assert.equal(proof.physicalAttestation instanceof Buffer, true);
  assert.equal(sent.nonce, nonce.toString("base64url"));
  assert.equal(sent.sequence, 0);
  assert.equal(sent.root, expectedRoot.toString("base64url"));
  assert.equal(sent.receipt, sha(receipt));
  assert.equal(sent.envelope, sha(bound.canonicalEnvelope));
  assert.deepEqual(sent.scope, wireScope(scope));
  const originalPolicy = { username: "alice",
    trustedDevicePublicKeys: { "device-a": deviceSpki }, revokedDeviceIds: [] };
  const verified = await verifySyncV2HistoricalWitnessAdmission({
    envelope: operation, ...proof, nonce,
    pinnedInventoryPublicKey: inventorySigner.publicKey,
    pinnedInventorySignerKeyId: signerId,
    pinnedPhysicalAttestorPublicKey: crypto.createPublicKey(ready.physicalPublicKey),
    pinnedWitnessPublicKey: crypto.createPublicKey(ready.witnessPublicKey),
    witnessKeyId: Buffer.from(ready.witnessKeyId, "base64url"),
    statusKeyId: Buffer.from(ready.statusKeyId, "base64url"),
    trustedMinimumFloor: ready.minimum,
    localTrustedDevicePolicy: originalPolicy,
    trustedCurrentDevicePolicyProvider: () => originalPolicy,
  });
  assert.equal(verified.authorizesHistoricalRead, true);
  assert.equal(verified.externalDurabilityProven, false);

  // Authenticated TLS on its own cannot turn untrusted JSON into authority.
  const response = { admission: proof.admission, freshFloor: proof.freshFloor,
    physicalAttestation: proof.physicalAttestation.toString("base64url"),
    authority: "WITNESS_SYNC_HISTORICAL_ADMISSION_V1" };
  let responseMode = "valid";
  const rogue = https.createServer({
    key: read("server.key"), cert: read("server.pem"), ca: read("ca.pem"),
    minVersion: "TLSv1.3", requestCert: true, rejectUnauthorized: true,
  }, (req, res) => {
    const incoming = [];
    req.on("data", (part) => incoming.push(part));
    req.on("end", async () => {
      if (responseMode === "timeout") return;
      const challenge = JSON.parse(Buffer.concat(incoming).toString("utf8")).nonce;
      const mutated = JSON.parse(JSON.stringify(response));
      if (responseMode !== "replay") mutated.freshFloor.nonce = challenge;
      if (responseMode === "wrong-nonce") mutated.freshFloor.nonce = random(32).toString("base64url");
      if (responseMode === "wrong-identity") mutated.admission.deviceId = "intruder";
      if (responseMode === "missing-physical") delete mutated.physicalAttestation;
      if (responseMode === "malformed-physical") mutated.physicalAttestation = "%%%";
      if (responseMode === "wrong-physical-nonce") {
        // Valid deterministic CBOR structure, but bound to a different challenge.
        mutated.physicalAttestation = Buffer.from(await z.encodeDeterministic({
          type: "rootark-zk1-physical-pg-readback-attestation/v1",
          nonce: random(32),
        })).toString("base64url");
      }
      if (responseMode === "forged-signature") mutated.admission.signature = random(64).toString("base64url");
      if (responseMode === "wrong-authority") mutated.authority = "WITNESS_ENGINE_ONLY";
      if (responseMode === "fresh-signed") {
        const currentNonce = Buffer.from(challenge, "base64url");
        const floorUnsigned = { ...proof.freshFloor, nonce: challenge };
        delete floorUnsigned.signature;
        mutated.freshFloor = { ...floorUnsigned,
          signature: crypto.sign(null, Buffer.concat([
            Buffer.from("Root.ark/zk-1/witness-cas-physical-floor/v2\0"),
            Buffer.from(JSON.stringify(floorUnsigned)),
          ]), repeatedWitness.privateKey).toString("base64url"),
        };
        const admissionUnsigned = { ...proof.admission };
        delete admissionUnsigned.signature;
        mutated.admission = { ...admissionUnsigned,
          signature: crypto.sign(null, Buffer.concat([
            Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0"),
            Buffer.from(JSON.stringify(admissionUnsigned)),
          ]), repeatedWitness.privateKey).toString("base64url"),
        };
        mutated.physicalAttestation = Buffer.from(await signCommittedPhysicalReadback({
          scope, operation: bound.operation, nonce: currentNonce,
          readback: {
            status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
            walFlushConfirmed: true, authorizesIo: false,
            provesIndependentOperator: false, generation: 4, admissionId: random(16),
            operationId: bound.operation.operation_id, revision: bound.operation.revision,
            epoch: bound.operation.epoch, expectedInventorySequence: 0,
            expectedInventoryRoot: expectedRoot,
            ciphertextSha256: bound.operation.ciphertext_sha256,
            digest: random(32), root: random(32), chunkCount: 1,
          }, issuedAt: Math.floor(Date.now() / 1000),
        }, repeatedPhysical.privateKey)).toString("base64url");
      }
      let raw = Buffer.from(JSON.stringify(mutated));
      if (responseMode === "oversize") raw = Buffer.alloc(32 * 1024, 65);
      if (responseMode === "invalid-json") raw = Buffer.from("{");
      res.writeHead(200, { "content-type": "application/json",
        "content-length": raw.length }); res.end(raw);
    });
  });
  const roguePort = await listen(rogue);
  t.after(() => close(rogue));
  const repeatedWitness = crypto.generateKeyPairSync("ed25519");
  const repeatedPhysical = crypto.generateKeyPairSync("ed25519");
  const rogueProvider = createSyncV2HistoricalEvidenceProvider({
    ...options, endpoint: `https://127.0.0.1:${roguePort}`, timeoutMs: 350,
  });
  for (const mode of ["wrong-nonce", "replay", "wrong-identity", "missing-physical",
    "malformed-physical", "wrong-physical-nonce", "wrong-authority",
    "oversize", "invalid-json", "timeout"]) {
    responseMode = mode;
    await assert.rejects(rogueProvider(operation, { nonce: random(32) }),
      /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/, mode);
  }
  // Re-verifying previously seen history is routine Sync v2 behavior. A
  // bounded in-flight nonce guard must not accumulate completed attempts.
  responseMode = "fresh-signed";
  let latest, latestNonce;
  for (let iteration = 0; iteration < 4100; iteration += 1) {
    latestNonce = random(32);
    latest = await rogueProvider(operation, { nonce: latestNonce });
  }
  assert.equal(latest.freshFloor.nonce, latestNonce.toString("base64url"));
  assert.equal((await verifySyncV2HistoricalWitnessAdmission({
    envelope: operation, ...latest, nonce: latestNonce,
    pinnedInventoryPublicKey: inventorySigner.publicKey,
    pinnedInventorySignerKeyId: signerId,
    pinnedPhysicalAttestorPublicKey: repeatedPhysical.publicKey,
    pinnedWitnessPublicKey: repeatedWitness.publicKey,
    witnessKeyId: Buffer.from(ready.witnessKeyId, "base64url"),
    statusKeyId: Buffer.from(ready.statusKeyId, "base64url"),
    trustedMinimumFloor: ready.minimum,
    localTrustedDevicePolicy: originalPolicy,
    trustedCurrentDevicePolicyProvider: () => originalPolicy,
  })).authorizesHistoricalRead, true, "late fresh response still passes independent crypto verification");
  // A rejected trust-source attempt must also release its nonce, regardless
  // of the failure point; a second successful attempt must still work.
  let gateMode = "fail", sourceCalls = 0, releaseGate;
  const gate = new Promise((resolve) => { releaseGate = resolve; });
  const gatedProvider = createSyncV2HistoricalEvidenceProvider({
    ...options, endpoint: `https://127.0.0.1:${roguePort}`,
    trustedInventoryEvidenceProvider: async () => {
      sourceCalls += 1;
      const mode = gateMode;
      if (mode === "hold") await gate;
      if (mode === "fail" || mode === "hold") throw Error("SOURCE_UNAVAILABLE");
      return trustedSource();
    },
  });
  for (let iteration = 0; iteration < 4100; iteration += 1) {
    await assert.rejects(gatedProvider(operation, { nonce: random(32) }),
      /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/);
  }
  gateMode = "hold";
  const concurrentNonce = random(32);
  const pending = [gatedProvider(operation, { nonce: concurrentNonce })
    .then(() => false, () => true)];
  await assert.rejects(gatedProvider(operation, { nonce: concurrentNonce }),
    /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/,
  "same nonce cannot enter the trusted callback twice while in flight");
  for (let iteration = 1; iteration < 4096; iteration += 1) {
    pending.push(gatedProvider(operation, { nonce: random(32) })
      .then(() => false, () => true));
  }
  assert.equal(sourceCalls, 4100 + 4096,
    "exactly 4096 admitted calls, no duplicate enters independent source");
  const overCapacity = gatedProvider(operation, { nonce: random(32) })
    .then(() => "BYPASS", (error) => error.message);
  assert.equal(await Promise.race([
    overCapacity, new Promise((resolve) => setTimeout(() => resolve("STUCK"), 500)),
  ]), "SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE",
  "in-flight cap rejects an additional active request promptly");
  assert.equal(sourceCalls, 4100 + 4096, "over-capacity never reaches trust source");
  gateMode = "ready";
  releaseGate();
  assert.equal((await Promise.all(pending)).every(Boolean), true);
  const afterFailures = random(32);
  assert.equal((await gatedProvider(operation, { nonce: afterFailures }))
    .freshFloor.nonce, afterFailures.toString("base64url"),
  "after 4096 overlapping failures, valid historical reads resume");
  // The adapter intentionally transports signed objects without authorizing
  // them; the existing strict verifier catches a forged witness signature.
  responseMode = "forged-signature";
  const forged = await createSyncV2HistoricalEvidenceProvider({
    ...options, endpoint: `https://127.0.0.1:${roguePort}`,
  })(operation, { nonce });
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
    envelope: operation, ...forged, nonce,
    pinnedInventoryPublicKey: inventorySigner.publicKey,
    pinnedInventorySignerKeyId: signerId,
    pinnedPhysicalAttestorPublicKey: crypto.createPublicKey(ready.physicalPublicKey),
    pinnedWitnessPublicKey: crypto.createPublicKey(ready.witnessPublicKey),
    witnessKeyId: Buffer.from(ready.witnessKeyId, "base64url"),
    statusKeyId: Buffer.from(ready.statusKeyId, "base64url"),
    trustedMinimumFloor: ready.minimum,
    localTrustedDevicePolicy: originalPolicy,
    trustedCurrentDevicePolicyProvider: () => originalPolicy,
  }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/);
  await assert.rejects(createSyncV2HistoricalEvidenceProvider({
    ...options, clientCert: read("denied.pem"), clientKey: read("denied.key"),
  })(operation, { nonce: random(32) }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/,
  "scope-less authenticated certificate cannot call historical endpoint");
  await assert.rejects(createSyncV2HistoricalEvidenceProvider({
    ...options, serverFingerprint256: new crypto.X509Certificate(read("denied.pem")).fingerprint256,
  })(operation, { nonce: random(32) }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/,
  "CA-signed server with wrong pinned certificate is rejected");
  await assert.rejects(createSyncV2HistoricalEvidenceProvider({
    ...options, trustedInventoryEvidenceProvider: async () => ({
      scope: { ...scope, account_id: random(16) },
      expectedSequence: 0, expectedRoot, receipt,
    }),
  })(operation, { nonce: random(32) }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/,
  "signed receipt and derived operation must match independently sourced scope");
  await assert.rejects(createSyncV2HistoricalEvidenceProvider({
    ...options, trustedInventoryEvidenceProvider: async () => ({
      scope, expectedSequence: 0, expectedRoot: random(32), receipt,
    }),
  })(operation, { nonce: random(32) }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/,
  "signed receipt must match externally pinned checkpoint");
  const corruptedReceipt = Buffer.from(receipt);
  corruptedReceipt[corruptedReceipt.length - 1] ^= 1;
  await assert.rejects(createSyncV2HistoricalEvidenceProvider({
    ...options, trustedInventoryEvidenceProvider: async () => ({
      scope, expectedSequence: 0, expectedRoot, receipt: corruptedReceipt,
    }),
  })(operation, { nonce: random(32) }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/,
  "damaged independent inventory signature fails before network request");
  await assert.rejects(createSyncV2HistoricalEvidenceProvider(options)(
    operation, { nonce: random(31) }), /SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE/);
});
