"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1DurableCasStatusLedger } = require("../src/services/zk1DurableCasStatusLedger");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { createZk1CasStatusHttpsServer, drainZk1CasStatusHttpsServer } =
  require("../src/services/zk1CasStatusHttpsServer");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../src/services/zk1WitnessHttpsServer");
const { createZk1CasManifestHttpsClient } =
  require("../src/services/zk1CasManifestHttpsClient");
const { createZk1WitnessHttpsClient } =
  require("../src/services/zk1WitnessHttpsClient");
const { inspectZk1ExperimentalRemoteSignedHistory } =
  require("../src/services/zk1ExperimentalRemoteSignedHistory");
const { createZk1SignedHistoryCasProofProvider } =
  require("../src/services/zk1SignedHistoryCasProofProvider");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");

const deny = /ZK_REMOTE_HISTORY_UNVERIFIED/;

test("oversized aggregate package envelopes stop before CAS network I/O or exceeding copy budget", async () => {
  const state = await fixtures.createInitialState(1);
  const anchor = await fixtures.createWitnessAnchor(state);
  let networkCalls = 0;
  const sameLargeBuffer = Buffer.alloc(8 * 1024 * 1024);
  const packageEnvelopes = Array.from({ length: 9 }, (_, index) => ({
    activationRevision: index + 2, envelopeBytes: sameLargeBuffer,
  }));
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory({
    casClient: { async getCommittedHistory() { networkCalls++; throw Error("network reached"); } },
    witnessClient: { async freshHead() { networkCalls++; throw Error("network reached"); } },
    expectedScope: state.scope, baseReceipt: anchor.receipt,
    pinnedWitness: anchor.pinnedWitness,
    minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    packageEnvelopes, nowSeconds: () => 1100,
  }), deny);
  assert.equal(networkCalls, 0,
    "unbounded envelope catalog must be refused synchronously before any network call");
});
function certificates(dir) {
  const commands = [
    "set -eu",
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=isolated fixture CA" -days 1 >/dev/null 2>&1',
    'for name in cas witness; do openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=localhost" >/dev/null 2>&1; printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > "$name.ext"; openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" -days 1 -extfile "$name.ext" >/dev/null 2>&1; done',
    'for name in casreader headreader; do openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" >/dev/null 2>&1; printf "extendedKeyUsage=clientAuth\n" > "$name.ext"; openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" -days 1 -extfile "$name.ext" >/dev/null 2>&1; done',
  ].join("\n");
  if (process.platform === "win32") {
    const unix = execFileSync("wsl.exe", ["-e", "wslpath", "-a", dir], { encoding: "utf8" }).trim();
    execFileSync("wsl.exe", ["-e", "bash", "-lc",
      "cd " + JSON.stringify(unix) + "; " + commands], { timeout: 30000 });
  } else execFileSync("bash", ["-lc", commands], { cwd: dir, timeout: 30000 });
  const read = (n) => fs.readFileSync(path.join(dir, n));
  return { ca: read("ca.pem"), casKey: read("cas.key"), casCert: read("cas.pem"),
    witnessKey: read("witness.key"), witnessCert: read("witness.pem"),
    casReaderKey: read("casreader.key"), casReaderCert: read("casreader.pem"),
    headReaderKey: read("headreader.key"), headReaderCert: read("headreader.pem") };
}
async function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-history-head-mtls-"));
  const close = [];
  const state = await fixtures.createInitialState(1);
  const anchor = await fixtures.createWitnessAnchor(state);
  const tls = certificates(dir);
  const statusKeys = crypto.generateKeyPairSync("ed25519");
  const statusKeyId = crypto.randomBytes(16);
  const scope = state.scope;
  const scopeJson = Object.fromEntries(Object.entries(scope).map(
    ([field, value]) => [field, Buffer.from(value).toString("base64url")]));
  const cas = new Zk1DurableCasStatusLedger(path.join(dir, "cas.sqlite"), {
    bootstrapNew: true, statusPrivateKey: statusKeys.privateKey, statusKeyId,
    witnessPinned: anchor.pinnedWitness,
    anchorPath: path.join(dir, "status-anchor.log"), nowSeconds: () => 1100,
  });
  const witness = new Zk1DurableWitnessLedger(path.join(dir, "witness.sqlite"), {
    bootstrapNew: true, witnessPrivateKey: anchor.signingPrivateKey,
    witnessKeyId: anchor.pinnedWitness.keyId,
    statusPinned: { keyId: statusKeyId, publicKey: statusKeys.publicKey },
    statusProvider: cas, nowSeconds: () => 1100,
  });
  close.push(cas, witness);
  const casPrincipal = new crypto.X509Certificate(tls.casReaderCert).fingerprint256;
  const headPrincipal = new crypto.X509Certificate(tls.headReaderCert).fingerprint256;
  const casServer = createZk1CasStatusHttpsServer({
    key: tls.casKey, cert: tls.casCert, clientCa: tls.ca,
    ledger: cas, principals: { [casPrincipal]: { roles: ["manifest"], scopes: [scopeJson] } },
  });
  const headServer = createZk1WitnessHttpsServer({
    key: tls.witnessKey, cert: tls.witnessCert, clientCa: tls.ca,
    ledger: witness, principals: { [headPrincipal]: { roles: ["head"], scopes: [scopeJson] } },
  });
  await new Promise((resolve) => casServer.listen(0, "127.0.0.1", resolve));
  await new Promise((resolve) => headServer.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await drainZk1WitnessHttpsServer(headServer);
    await drainZk1CasStatusHttpsServer(casServer);
    for (const ledger of close) ledger.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const casClient = createZk1CasManifestHttpsClient({
    endpoint: "https://localhost:" + casServer.address().port + "/v1/manifest",
    ca: tls.ca, clientKey: tls.casReaderKey, clientCert: tls.casReaderCert,
    serverFingerprint256: new crypto.X509Certificate(tls.casCert).fingerprint256,
  });
  const witnessClient = createZk1WitnessHttpsClient({
    endpoint: "https://localhost:" + headServer.address().port,
    ca: tls.ca, clientKey: tls.headReaderKey, clientCert: tls.headReaderCert,
    serverFingerprint256: new crypto.X509Certificate(tls.witnessCert).fingerprint256,
  });
  const append = async (manifest, previous) => {
    const reservation = {
      ...scope, reservation_id: crypto.randomBytes(16),
      operation_id: Buffer.from(manifest.operation.operation_id),
      request_digest: Buffer.from(manifest.operation.request_digest),
      expected_revision: previous ? Number(previous.revision) : null,
      expected_manifest_digest: previous ? await v2.recoveryManifestDigestV2(previous) : null,
      proposed_revision: Number(manifest.revision),
      proposed_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      package_envelope_digest: null,
      expires_at: Number(manifest.operation.expires_at),
    };
    const ticket = await witness.reserve(reservation);
    await cas.registerReservation({ receipt: ticket });
    await cas.commit({ receipt: ticket, manifestBytes: Buffer.from(await z.encodeDeterministic(manifest)) });
    assert.equal((await witness.resolve({ scope })).status, "committed");
  };
  await append(state.baseManifest, null);
  await fixtures.appendDeviceEnrollment(state, 1);
  await append(state.headManifest, state.baseManifest);
  const minimumHead = { revision: 1, witnessSequence: 1,
    digest: await v2.recoveryManifestDigestV2(state.baseManifest) };
  const settings = { casClient, witnessClient, expectedScope: scope,
    baseReceipt: anchor.receipt, pinnedWitness: anchor.pinnedWitness,
    minimumHead, packageEnvelopes: [], nowSeconds: () => 1100 };
  return { casClient, witnessClient, state, scope, minimumHead,
    witness, cas, settings, append, anchor, tls, casServer, headServer };
}

test("two real pinned mTLS services prove full signed history and fresh witness head cryptographically, never authorize protected I/O", async (t) => {
  const f = await fixture(t);
  const result = await inspectZk1ExperimentalRemoteSignedHistory(f.settings);
  assert.deepEqual(result, { revision: 2, digest: await v2.recoveryManifestDigestV2(f.state.headManifest),
    signedPublicHistoryVerified: true, freshWitnessHeadMatchesHistory: true,
    authorizesRecovery: false, authorizesProtectedIo: false,
    independentlyOperatedAuthoritiesVerified: false });
  await fixtures.appendDeviceRevocation(f.state, "trusted-1");
  await f.append(f.state.headManifest, (await z.decodeDeterministic(
    (await f.casClient.getCommittedHistory({ scope: f.scope })).entries[1])));
  const after = await inspectZk1ExperimentalRemoteSignedHistory(f.settings);
  assert.equal(after.revision, 3);
  assert.notDeepEqual(after.digest, result.digest);
  assert.equal(after.authorizesProtectedIo, false);
});

test("tampered signed transition, signed CAS rollback and nonce-replayed witness fail before any authority claim", async (t) => {
  const f = await fixture(t);
  const original = await f.casClient.getCommittedHistory({ scope: f.scope });
  const wrongPin = { ...f.settings, pinnedWitness: {
    keyId: f.anchor.pinnedWitness.keyId,
    publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
  } };
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory(wrongPin), deny);
  const tampered = { ...f.settings, casClient: {
    async getCommittedHistory() {
      const entries = original.entries.map((item) => Buffer.from(item));
      entries[1][Math.floor(entries[1].length / 2)] ^= 1;
      return { ...original, entries };
    },
  } };
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory(tampered), deny);
  const rollback = { ...f.settings, casClient: {
    async getCommittedHistory() {
      return { headRevision: 1, headDigest: await v2.recoveryManifestDigestV2(f.state.baseManifest),
        entries: [original.entries[0]] };
    },
  } };
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory(rollback), deny,
    "CAS rollback to genuine signed genesis must not agree with witnessed current HEAD");
  let prior;
  const oldWitness = { ...f.settings, witnessClient: {
    async freshHead({ scope, nonce }) {
      if (!prior) prior = await f.witnessClient.freshHead({ scope, nonce });
      return prior;
    },
  } };
  assert.equal((await inspectZk1ExperimentalRemoteSignedHistory(oldWitness)).revision, 2);
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory(oldWitness), deny,
    "reused signed HEAD must not pass a new challenge");
});

test("pending live witness reservation, unpinned TLS peer and switched client scope refuse complete history", async (t) => {
  const f = await fixture(t);
  const first = await inspectZk1ExperimentalRemoteSignedHistory(f.settings);
  assert.equal(first.revision, 2);
  const wrongCas = createZk1CasManifestHttpsClient({
    endpoint: "https://localhost:" + f.casServer.address().port + "/v1/manifest",
    ca: f.tls.ca, clientKey: f.tls.casReaderKey, clientCert: f.tls.casReaderCert,
    serverFingerprint256: "00:".repeat(31) + "00",
  });
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory({
    ...f.settings, casClient: wrongCas,
  }), deny, "a TLS CA match cannot replace the pinned CAS certificate identity");
  const wrongWitness = createZk1WitnessHttpsClient({
    endpoint: "https://localhost:" + f.headServer.address().port,
    ca: f.tls.ca, clientKey: f.tls.headReaderKey, clientCert: f.tls.headReaderCert,
    serverFingerprint256: "00:".repeat(31) + "00",
  });
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory({
    ...f.settings, witnessClient: wrongWitness,
  }), deny, "a TLS CA match cannot replace the pinned witness certificate identity");
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory({
    ...f.settings, expectedScope: { ...f.scope, keyring_id: crypto.randomBytes(16) },
  }), deny, "scope cannot be transplanted onto an otherwise authentic signed chain");
  const old = f.state.headManifest;
  await fixtures.appendDeviceRevocation(f.state, "trusted-1");
  const candidate = f.state.headManifest;
  const ticket = await f.witness.reserve({
    ...f.scope, reservation_id: crypto.randomBytes(16),
    operation_id: Buffer.from(candidate.operation.operation_id),
    request_digest: Buffer.from(candidate.operation.request_digest),
    expected_revision: Number(old.revision),
    expected_manifest_digest: await v2.recoveryManifestDigestV2(old),
    proposed_revision: Number(candidate.revision),
    proposed_manifest_digest: await v2.recoveryManifestDigestV2(candidate),
    package_envelope_digest: null,
    expires_at: Number(candidate.operation.expires_at),
  });
  assert.ok(ticket.byteLength > 0, "pending reservation actually persisted before request");
  await assert.rejects(inspectZk1ExperimentalRemoteSignedHistory(f.settings),
    deny, "witness PENDING cannot be mistaken for a committed matching historical HEAD");
  const reread = await f.casClient.getCommittedHistory({ scope: f.scope });
  assert.equal(reread.headRevision, 2, "real CAS remains rev2 until an authorized commit");
});

test("real CAS and witness mTLS history authorizes local encrypted PUT/GET only for signed active devices", async (t) => {
  const f = await fixture(t);
  const contentDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-signed-io-"));
  const genesisDigest = await v2.recoveryManifestDigestV2(f.state.baseManifest);
  const proofProvider = createZk1SignedHistoryCasProofProvider({
    casClient: f.casClient, trustedScope: f.scope,
    trustedGenesisDigest: genesisDigest,
    baseReceipt: f.state.baseReceipt, pinnedBaseWitness: f.state.pinnedWitness,
    packageEnvelopes: [], nowSeconds: () => 1100,
  });
  const store = new Zk1ProtectedObjectStore(path.join(contentDir, "content.sqlite"), {
    bootstrapNew: true, trustedScope: f.scope,
    minimumHead: { revision: 1, witnessSequence: 1, digest: genesisDigest },
    witnessProvider: f.witnessClient, witnessPinned: f.anchor.pinnedWitness,
    manifestProvider: (scope) => f.casClient.getCommittedManifest({ scope }),
    signedHistoryRequired: true, signedHistoryGenesisDigest: genesisDigest,
    verifiedHistoryProvider: proofProvider, nowSeconds: () => 1100,
  });
  t.after(() => {
    store.close();
    fs.rmSync(contentDir, { recursive: true, force: true, maxRetries: 10 });
  });
  const objectId = crypto.randomBytes(16).toString("base64url");
  const ciphertext = crypto.randomBytes(700);
  const signed = async (deviceName, operation) => {
    const manifest = f.state.headManifest;
    const device = manifest.devices.find((item) => item.device_id === deviceName);
    const authorization = {
      ...f.scope, device_id: deviceName, operation, object_id: objectId,
      expected_object_revision: operation === "put" ? null : 1,
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch), nonce: crypto.randomBytes(32),
      issued_at: 1099, expires_at: 1130,
      ciphertext_digest: crypto.createHash("sha256").update(ciphertext).digest(),
    };
    const key = f.state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
    return { scope: f.scope, authorization,
      signature: crypto.sign(null, await contentAuthorizationMessageV1(authorization), key),
      ...(operation === "put" ? { ciphertext } : {}) };
  };
  assert.equal((await store.put(await signed("trusted-0", "put"))).revision, 1);
  assert.deepEqual((await store.get(await signed("trusted-1", "get"))).ciphertext, ciphertext);
  const before = f.state.headManifest;
  await fixtures.appendDeviceRevocation(f.state, "trusted-1");
  await f.append(f.state.headManifest, before);
  await assert.rejects(store.get(await signed("trusted-1", "get")),
    /ZK_CONTENT_DENIED/,
    "a formerly trusted device must not read after revocation is signed and committed");
  assert.deepEqual((await store.get(await signed("trusted-0", "get"))).ciphertext, ciphertext);
});
