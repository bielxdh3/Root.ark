"use strict";

const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

// Three real signed v2 state transitions, durable CAS and witness engines,
// live protected-file I/O with two devices, and concurrent pending revocation.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const fileCrypto = require("../public/client/rootark-zk1-file-content.js");
const { Zk1DurableCasStatusLedger } = require("../src/services/zk1DurableCasStatusLedger");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } = require("../src/services/zk1ProtectedObjectStore");

test("CAS+witness true signed genesis/enrollment/revocation fence cross-device ciphertext and survive restart", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk1-integrated-");
  const ledgers = [];
  t.after(() => {
    for (const ledger of ledgers) ledger.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const state = await fixtures.createInitialState(2);
  const initial = state.baseManifest;
  const enrolled = state.headManifest;
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const statusKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const statusOptions = {
    bootstrapNew: true, statusPrivateKey: statusKeys.privateKey, statusKeyId,
    witnessPinned: { keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
    anchorPath: path.join(dir, "cas-anchor.log"), nowSeconds: () => 1100,
  };
  const casPath = path.join(dir, "cas.sqlite");
  const cas = new Zk1DurableCasStatusLedger(casPath, statusOptions);
  ledgers.push(cas);
  const witnessPath = path.join(dir, "witness.sqlite");
  const witnessOptions = {
    bootstrapNew: true, witnessPrivateKey: witnessKeys.privateKey, witnessKeyId,
    statusPinned: { keyId: statusKeyId, publicKey: statusKeys.publicKey },
    statusProvider: cas, nowSeconds: () => 1100,
  };
  const witness = new Zk1DurableWitnessLedger(witnessPath, witnessOptions);
  ledgers.push(witness);
  const scope = state.scope;
  const propose = async (manifest, prior = null, stopAtPending = false) => {
    const op = {
      ...scope, reservation_id: crypto.randomBytes(16),
      operation_id: Buffer.from(manifest.operation.operation_id),
      request_digest: Buffer.from(manifest.operation.request_digest),
      package_envelope_digest: null,
      expected_revision: prior === null ? null : prior.revision,
      expected_manifest_digest: prior === null ? null : await v2.recoveryManifestDigestV2(prior),
      proposed_revision: manifest.revision,
      proposed_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      expires_at: Number(manifest.operation.expires_at),
    };
    const ticket = await witness.reserve(op);
    if (stopAtPending) return { op, ticket };
    await cas.registerReservation({ receipt: ticket });
    await cas.commit({ receipt: ticket, manifestBytes: Buffer.from(await z.encodeDeterministic(manifest)) });
    assert.equal((await witness.resolve({ scope })).status, "committed");
    return op;
  };
  await propose(initial);
  const floor = { revision: 1, witnessSequence: 1,
    digest: await v2.recoveryManifestDigestV2(initial) };
  const contentPath = path.join(dir, "content.sqlite");
  let loseStartAckOnce = false;
  let simulateStopAfterStart = false;
  const makeStore = (bootstrapNew = false, admissionRequired = false) => {
    const s = new Zk1ProtectedObjectStore(contentPath, {
      trustedScope: scope, minimumHead: floor, bootstrapNew,
      witnessProvider: {
        freshHead: (...args) => witness.freshHead(...args),
        beginIoAdmission: async (request) => {
          const admitted = await witness.beginIoAdmission({ ...request,
            principal: "AA:".repeat(31) + "AA" });
          if (loseStartAckOnce) {
            loseStartAckOnce = false;
            throw new Error("synthetic lost admission ACK after durable start");
          }
          return simulateStopAfterStart ? { ...admitted, proceed: false } : admitted;
        },
        finishIoAdmission: (request) => witness.finishIoAdmission({ ...request,
          principal: "AA:".repeat(31) + "AA" }),
      },
      witnessPinned: { keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
      manifestProvider: (selected) => cas.getCommittedManifest({ scope: selected }),
      nowSeconds: () => 1100, admissionRequired,
    });
    ledgers.push(s);
    return s;
  };
  let content = makeStore(true);
  const objectId = crypto.randomBytes(16).toString("base64url");
  const authorize = async (deviceName, operation, ciphertext = null, expectedRevision = null) => {
    const rawManifest = await cas.getCommittedManifest({ scope });
    const manifest = await z.decodeDeterministic(rawManifest);
    const device = manifest.devices.find((entry) => entry.device_id === deviceName);
    const auth = {
      ...scope, device_id: deviceName, operation, object_id: objectId,
      expected_object_revision: expectedRevision,
      manifest_revision: manifest.revision,
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: manifest.current_epoch, nonce: crypto.randomBytes(32),
      issued_at: 1099, expires_at: 1110,
      ciphertext_digest: ciphertext === null ? null : crypto.createHash("sha256").update(ciphertext).digest(),
    };
    const signer = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
    return { scope, authorization: auth, ciphertext,
      signature: crypto.sign(null, await contentAuthorizationMessageV1(auth), signer) };
  };
  const beforeEnroll = await authorize("trusted-0", "put", crypto.randomBytes(200));
  assert.equal((await content.put(beforeEnroll)).revision, 1);
  const admittedStore = makeStore(false, true);
  simulateStopAfterStart = true;
  let emittedAfterStop = false;
  await assert.rejects(admittedStore.runWithAdmission(await authorize("trusted-0", "get"),
    "get", () => { emittedAfterStop = true; }), /ZK_CONTENT_UNAVAILABLE/);
  assert.equal(emittedAfterStop, false,
    "reconciled START during quiescence may return an admission ID but never authorize egress");
  simulateStopAfterStart = false;
  await assert.rejects(admittedStore.get(await authorize("trusted-0", "get")),
    /ZK_CONTENT_GATE_REQUIRED/, "gate-required stores cannot bypass witness admission via direct get");
  const heldRead = await authorize("trusted-0", "get");
  let sendStarted;
  const sending = new Promise((resolve) => { sendStarted = resolve; });
  let completeEgress;
  const egressHeld = new Promise((resolve) => { completeEgress = resolve; });
  const inflight = admittedStore.runWithAdmission(heldRead, "get", async (result) => {
    assert.deepEqual(result.ciphertext, beforeEnroll.ciphertext);
    sendStarted();
    await egressHeld;
  });
  await sending;
  await assert.rejects(propose(enrolled, initial), /WITNESS_IO_ACTIVE/,
    "revocation/enrollment cannot reserve while a response holds the same durable admission");
  completeEgress();
  await inflight;
  loseStartAckOnce = true;
  await admittedStore.runWithAdmission(await authorize("trusted-0", "get"), "get", (value) => {
    assert.deepEqual(value.ciphertext, beforeEnroll.ciphertext);
  });
  // A *real* randomly generated per-version CEK, bound to the compartment's
  // initial epoch CER via the frozen zk-1 HKDF+AES-GCM one-shot key wrapper.
  // Neither the authenticated HTTP store nor CAS nor witness receives CER,
  // CEK or encrypted filename/content plaintext.
  const firstDevice = initial.devices[0];
  const versionId = crypto.randomBytes(16);
  const fileId = crypto.randomBytes(16);
  const wrapId = crypto.randomBytes(16);
  const cekBytes = crypto.randomBytes(32);
  const fileCek = await fileCrypto.importFileCek(cekBytes);
  const metadata = {
    account_id: scope.account_id.toString("base64url"),
    compartment_id: scope.compartment_id.toString("base64url"),
    keyring_id: scope.keyring_id.toString("base64url"),
    object_id: fileId.toString("base64url"), version_id: versionId.toString("base64url"),
    parent_version_id: null, epoch: 1, kind: "file",
  };
  const plaintext = crypto.randomBytes(300);
  const fileWire = await fileCrypto.encryptFile({ cek: fileCek, metadata,
    name: "hidden-password-list.txt", mediaType: "text/plain", data: plaintext });
  const context = {
    suite: "rootark-zk-1", compartment_id: scope.compartment_id, epoch: 1,
    purpose: "content", object_id: fileId, version_id: versionId,
    key_ref: initial.epochs[0].key_ref,
    recipient_key_id: firstDevice.hpke_key_id, wrap_id: wrapId,
  };
  const aad = Buffer.from(await z.encodeDeterministic({
    ...scope, object_id: fileId, version_id: versionId,
    key_ref: initial.epochs[0].key_ref, wrap_id: wrapId, purpose: "content", epoch: 1,
  }));
  const wrapped = await z.wrapKey({ ...context, cer: state.epochKeys[0].key,
    plaintext: cekBytes, aad });
  assert.equal(wrapped.byteLength, 60);
  cekBytes.fill(0);
  const staged = await authorize("trusted-0", "put", Buffer.from(fileWire));
  staged.authorization.object_id = metadata.object_id;
  staged.signature = crypto.sign(null, await contentAuthorizationMessageV1(staged.authorization),
    state.actors.get(Buffer.from(firstDevice.authorization_key_id).toString("hex")));
  assert.equal((await content.put(staged)).revision, 1);
  const received = await authorize("trusted-0", "get");
  received.authorization.object_id = metadata.object_id;
  received.signature = crypto.sign(null, await contentAuthorizationMessageV1(received.authorization),
    state.actors.get(Buffer.from(firstDevice.authorization_key_id).toString("hex")));
  const loaded = await content.get(received);
  assert.equal(Buffer.from(loaded.ciphertext).toString("utf8").includes("hidden-password"), false);
  const unwrapped = await z.unwrapKey({ ...context, cer: state.epochKeys[0].key,
    wrapped, aad });
  const recoveredCek = await fileCrypto.importFileCek(unwrapped);
  unwrapped.fill(0);
  const opened = await fileCrypto.decryptFile({ cek: recoveredCek, metadata,
    envelopeBytes: loaded.ciphertext });
  assert.equal(opened.name, "hidden-password-list.txt");
  assert.deepEqual(Buffer.from(opened.data), plaintext);
  opened.data.fill(0);
  const modifiedWrap = { ...context, version_id: crypto.randomBytes(16) };
  await assert.rejects(z.unwrapKey({ ...modifiedWrap, cer: state.epochKeys[0].key,
    wrapped, aad }), /AUTHENTICATION_FAILED/);
  await propose(enrolled, initial);
  const historyAfterEnrollment = await cas.getCommittedHistoryPage({
    scope, startRevision: 1,
  });
  assert.equal(historyAfterEnrollment.headRevision, 2);
  assert.deepEqual(historyAfterEnrollment.entries,
    [Buffer.from(await z.encodeDeterministic(initial)),
      Buffer.from(await z.encodeDeterministic(enrolled))],
    "untrusted CAS history pages expose every canonical signed transition");
  assert.equal(historyAfterEnrollment.nextRevision, null);
  assert.deepEqual(historyAfterEnrollment.headDigest,
    await v2.recoveryManifestDigestV2(enrolled));
  const expensiveAudit = cas.getCommittedManifest.bind(cas);
  try {
    cas.getCommittedManifest = async () => {
      throw new Error("full ledger audit must not materialize at EVERY untrusted history page");
    };
    const fetched = await cas.getCommittedHistoryPage({ scope, startRevision: 2 });
    assert.deepEqual(fetched.entries, [Buffer.from(await z.encodeDeterministic(enrolled))]);
  } finally {
    cas.getCommittedManifest = expensiveAudit;
  }
  const readNew = await authorize("trusted-1", "get");
  assert.deepEqual((await content.get(readNew)).ciphertext, beforeEnroll.ciphertext);

  const formerlyAuthorized = await authorize("trusted-1", "get");
  const revoked = await fixtures.appendDeviceRevocation(state, "trusted-1");
  const { ticket } = await propose(revoked, enrolled, true);
  await assert.rejects(content.get(await authorize("trusted-0", "get")),
    /ZK_CONTENT_UNAVAILABLE/, "a real unresolved witness reservation must freeze protected reads");
  await cas.registerReservation({ receipt: ticket });
  await assert.rejects(cas.getCommittedHistoryPage({ scope, startRevision: 1 }),
    /CAS_UNRESOLVED/, "CAS must withhold committed history while its reservation is pending");
  await cas.commit({ receipt: ticket, manifestBytes: Buffer.from(await z.encodeDeterministic(revoked)) });
  await assert.rejects(content.get(formerlyAuthorized), /ZK_CONTENT_UNAVAILABLE/,
    "before witness terminal acknowledgement, a new signed CAS manifest is insufficient");
  assert.equal((await witness.resolve({ scope })).status, "committed");
  const historyAfterRevoke = await cas.getCommittedHistoryPage({
    scope, startRevision: 2,
  });
  assert.equal(historyAfterRevoke.headRevision, 3);
  assert.deepEqual(historyAfterRevoke.entries,
    [Buffer.from(await z.encodeDeterministic(enrolled)),
      Buffer.from(await z.encodeDeterministic(revoked))]);
  assert.equal(historyAfterRevoke.nextRevision, null);
  await assert.rejects(content.get(formerlyAuthorized), /ZK_CONTENT_UNAVAILABLE/);
  await assert.rejects(content.get(await authorize("trusted-1", "get")),
    /ZK_CONTENT_DENIED/);
  assert.deepEqual((await content.get(await authorize("trusted-0", "get"))).ciphertext,
    beforeEnroll.ciphertext);

  content.close();
  content = makeStore();
  await assert.rejects(content.get(formerlyAuthorized), /ZK_CONTENT_UNAVAILABLE/);
  assert.deepEqual((await content.get(await authorize("trusted-0", "get"))).ciphertext,
    beforeEnroll.ciphertext);
});
