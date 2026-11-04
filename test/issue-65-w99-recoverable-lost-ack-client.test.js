"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { strictIndexedDB } = require("./support/issue-65-strict-indexeddb-fixture");

const b64 = (value) => Buffer.from(value).toString("base64url");
const randomId = () => b64(crypto.randomBytes(16));

async function clientFixture({ forgedReadback = false, outage = false,
  refuseStrict = false, advanceDuringValidate = 0, advanceDuringPrepare = 0,
  advanceAfterPut = 0, advanceDuringSending = 0,
  advanceDuringReadbackFloor = 0, refuseStrictAfterPrepare = false } = {}) {
  let puts = 0, gets = 0, stored = null;
  let clockSeconds = 10;
  let floorChecks = 0;
  const browser = {
    crypto: crypto.webcrypto, TextEncoder, TextDecoder, atob, btoa,
    Date: class extends Date { static now() { return clockSeconds * 1000; } },
    ArrayBuffer, Uint8Array,
    RootarkZk1NormalBrowserContent: {
      async verifyOwnerGrant() {
        clockSeconds += advanceDuringValidate;
        return { ownerGrantSignatureVerified: true };
      },
    },
    RootarkZk1NormalBrowserTrustFloor: {
      async verifyExternalAnchor() {
        floorChecks++;
        if (floorChecks === 2) clockSeconds += advanceDuringReadbackFloor;
      },
    },
    RootarkZk1ProtectedHttpClient: {
      async signProtectedContentOperation(request) { return { ...request,
        authorization: { nonce: b64(crypto.randomBytes(32)),
          issued_at: request.nowSeconds, expires_at: request.nowSeconds + 45 },
        signatureBase64: b64(crypto.randomBytes(64)) }; },
      async postProtectedCiphertextPut({ request }) {
        puts++;
        assert.equal(request.operation, "put");
        assert.equal(request.expectedObjectRevision, null);
        if (clockSeconds > request.authorization.expires_at) throw Error("HTTP_401_EXPIRED_PUT");
        const row = pending.values.get(metadata.object_id);
        assert.equal(row.operationId, request.authorization.nonce);
        assert.equal(row.operationSignature, request.signatureBase64);
        stored = Uint8Array.from(request.ciphertext);
        clockSeconds += advanceAfterPut;
        throw Error("ACK_LOST_AFTER_COMMITTED_PUT");
      },
      async postProtectedCiphertextBackupRead({ request, expectedObjectRevision,
        expectedEpoch, expectedRoot }) {
        gets++;
        assert.equal(request.operation, "get");
        if (clockSeconds > request.authorization.expires_at) throw Error("HTTP_401_EXPIRED_GET");
        assert.equal(request.expectedObjectRevision, 1);
        assert.equal(expectedObjectRevision, 1);
        assert.equal(expectedEpoch, 1);
        assert.deepEqual(Buffer.from(request.expectedCiphertextDigest),
          crypto.createHash("sha256").update(stored).digest());
        const root = await browser.RootarkZk1CiphertextRoot.computeCiphertextRoot([stored]);
        assert.deepEqual(Buffer.from(expectedRoot), Buffer.from(root));
        if (outage) throw Error("SIGNED_GET_OFFLINE");
        return { ciphertextBase64: b64(forgedReadback
          ? crypto.randomBytes(stored.length) : stored) };
      },
    },
    RootarkZk1BrowserRecoveryHttp: {},
  };
  vm.createContext(browser);
  for (const name of ["rootark-zk1-file-content",
    "rootark-zk1-ciphertext-chunk-root", "rootark-zk1-portable-file-recovery",
    "rootark-zk1-recoverable-pending-journal",
    "rootark-zk1-recoverable-workspace"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname,
      "../public/client/" + name + ".js"), "utf8"), browser);
  }
  const realm = vm.runInContext("(text) => JSON.parse(text)", browser);
  const scope = { account_id: randomId(),
    compartment_id: b64(Buffer.from("private")), keyring_id: randomId() };
  const metadata = realm(JSON.stringify({ ...scope, object_id: randomId(),
    version_id: randomId(), parent_version_id: null, epoch: 1, kind: "file" }));
  const secret = crypto.randomBytes(32);
  const plaintext = Buffer.from("client plaintext is encrypted before any HTTP operation");
  const pending = strictIndexedDB({ refuseStrict,
    cloneOnRead: (value) => value && realm(JSON.stringify(value)) });
  const openedJournal = browser.RootarkZk1RecoverablePendingJournal.openStore(pending);
  const journal = {
    ...openedJournal,
    async prepare(args) {
      const result = await openedJournal.prepare(args);
      clockSeconds += advanceDuringPrepare;
      if (refuseStrictAfterPrepare) pending.setRefuseStrict(true);
      return result;
    },
    async beginPut(args) {
      const result = await openedJournal.beginPut(args);
      clockSeconds += advanceDuringSending;
      return result;
    },
  };
  const input = Object.assign(realm("{}"), {
    ownerPublicKey: null, pinnedOwnerKeyHash: crypto.randomBytes(32),
    independentOwnerSpkiSha256: crypto.randomBytes(32),
    pinnedCurrentHead: Object.assign(realm("{}"),
      { revision: 1, epoch: 1, digest: crypto.randomBytes(32) }),
    signedDeviceGrant: { ...scope, device_id: "device-one" },
    ownerHistoryCheckpoint: null, devicePublicKey: null, devicePrivateKey: null,
    origin: "http://127.0.0.1/", fetchImpl: () => { throw Error("UNEXPECTED_FETCH"); },
    nowSeconds: 10, clockSeconds: () => clockSeconds, recoverySecret: secret, metadata,
    name: "encrypted.txt", mediaType: "text/plain", data: plaintext, journal,
  });
  return { browser, input, secret, plaintext, pending, realm,
    advanceClock(seconds) { clockSeconds += seconds; },
    currentClock() { return clockSeconds; },
    restoreNetwork() { outage = false; },
    counts: () => ({ puts, gets, stored }) };
}

test("Node WebCrypto with mocked HTTP reconciles a lost PUT ACK using exact GET readback expectations", async () => {
  const fixture = await clientFixture();
  const { browser, input, plaintext, secret } = fixture;
  const result = await browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(input);
  const { puts, gets, stored } = fixture.counts();
  assert.equal(puts, 1, "never retry the initial signed PUT");
  assert.equal(gets, 1, "one exact historical GET proves a committed ciphertext");
  assert.equal(result.lostPutAckReconciled, true);
  assert.equal(result.clientReadbackVerified, true);
  assert.equal(result.authorizesProductionIo, false);
  const afterGetBeforeExport = browser.RootarkZk1RecoverablePendingJournal.openStore(fixture.pending);
  const pendingAgain = await afterGetBeforeExport.load({ recoverySecret: secret,
    objectId: input.metadata.object_id });
  assert.equal(pendingAgain.bundle.ciphertextRoot, result.ciphertextRoot,
    "a browser crash after GET/before download cannot destroy the only sealed CEK");
  assert.equal(Buffer.from(stored).includes(plaintext), false);
  assert.equal(Buffer.from(stored).toString().includes("encrypted.txt"), false);
  const reopened = await browser.RootarkZk1PortableFileRecovery.openWithIndependentRoot({
    recoverySecret: secret, bundle: result.bundle,
    expectedMetadata: input.metadata,
    independentlyPinnedCiphertextRoot: Buffer.from(result.ciphertextRoot, "base64url"),
  });
  assert.deepEqual(Buffer.from(reopened.data), plaintext);
  reopened.data.fill(0);
  secret.fill(0);
  stored.fill(0);
});

test("forged mocked readback after lost ACK cannot release a false recovery bundle", async () => {
  const fixture = await clientFixture({ forgedReadback: true });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(fixture.counts().puts, 1);
  assert.equal(fixture.counts().gets, 1);
  fixture.secret.fill(0);
  fixture.counts().stored.fill(0);
});

test("simulated cold reload after lost ACK retains sealed bundle and resumes without another PUT", async () => {
  const fixture = await clientFixture({ outage: true });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.deepEqual([fixture.counts().puts, fixture.counts().gets], [1, 1]);
  assert.equal(fixture.pending.writes, 2,
    "strict prepared -> sending marker is durable before the first PUT");
  const saved = JSON.stringify([...fixture.pending.values.values()]);
  assert.equal(saved.includes(fixture.plaintext.toString()), false);
  assert.equal(saved.includes(fixture.secret.toString("base64url")), false);
  const restarted = fixture.browser.RootarkZk1RecoverablePendingJournal.openStore(fixture.pending);
  const input = fixture.input;
  const resume = Object.assign(fixture.realm("{}"), {
    ownerPublicKey: input.ownerPublicKey, pinnedOwnerKeyHash: input.pinnedOwnerKeyHash,
    independentOwnerSpkiSha256: input.independentOwnerSpkiSha256,
    pinnedCurrentHead: input.pinnedCurrentHead, signedDeviceGrant: input.signedDeviceGrant,
    ownerHistoryCheckpoint: input.ownerHistoryCheckpoint,
    devicePublicKey: input.devicePublicKey, devicePrivateKey: input.devicePrivateKey,
    origin: input.origin, fetchImpl: input.fetchImpl, nowSeconds: input.nowSeconds,
    recoverySecret: fixture.secret, objectId: input.metadata.object_id, journal: restarted,
  });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .resumePendingProtectedFile(resume), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.deepEqual([fixture.counts().puts, fixture.counts().gets], [1, 2]);
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .resumePendingProtectedFile({ ...resume, recoverySecret: crypto.randomBytes(32) }),
  /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(fixture.counts().gets, 2, "wrong holder secret rejected offline");
  fixture.restoreNetwork();
  const finished = await fixture.browser.RootarkZk1RecoverableWorkspace
    .resumePendingProtectedFile(resume);
  assert.equal(finished.resumedSignedGetOnly, true);
  assert.deepEqual([fixture.counts().puts, fixture.counts().gets], [1, 3]);
  const opened = await fixture.browser.RootarkZk1PortableFileRecovery.openWithIndependentRoot({
    recoverySecret: fixture.secret, bundle: finished.bundle,
    expectedMetadata: input.metadata,
    independentlyPinnedCiphertextRoot: Buffer.from(finished.ciphertextRoot, "base64url"),
  });
  assert.deepEqual(Buffer.from(opened.data), fixture.plaintext);
  opened.data.fill(0);
  fixture.secret.fill(0);
});

test("failed strict IndexedDB fixture before first mocked PUT fails closed", async () => {
  const fixture = await clientFixture({ refuseStrict: true });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(fixture.counts().puts, 0);
  assert.equal(fixture.counts().gets, 0);
  fixture.secret.fill(0);
});

test("50 seconds of strict journal preparation rebinds a fresh PUT signature durably and GET signs later", async () => {
  const fixture = await clientFixture({ advanceDuringPrepare: 50, advanceAfterPut: 50 });
  const result = await fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input);
  assert.equal(result.clientReadbackVerified, true);
  assert.equal(result.lostPutAckReconciled, true);
  assert.deepEqual([fixture.counts().puts, fixture.counts().gets], [1, 1]);
  assert.equal(fixture.currentClock(), 110);
  assert.equal(fixture.pending.writes, 3,
    "strict initial journal, CAS rebind and strict sending marker must all commit");
  const row = fixture.pending.values.get(fixture.input.metadata.object_id);
  assert.equal(row.operationId.length, 43);
  assert.equal(row.operationSignature.length, 86);
  const reopened = await fixture.browser.RootarkZk1RecoverablePendingJournal
    .openStore(fixture.pending).load({ recoverySecret: fixture.secret,
      objectId: fixture.input.metadata.object_id });
  assert.equal(reopened.putAttempted, true);
  fixture.secret.fill(0);
  fixture.counts().stored.fill(0);
});

test("GET after cold restart uses a fresh timestamp even when initial caller timestamp is old", async () => {
  const fixture = await clientFixture({ outage: true });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  fixture.advanceClock(100);
  fixture.restoreNetwork();
  const resume = Object.assign(fixture.realm("{}"), {
    ...Object.fromEntries(["ownerPublicKey", "pinnedOwnerKeyHash",
      "independentOwnerSpkiSha256", "pinnedCurrentHead", "signedDeviceGrant",
      "ownerHistoryCheckpoint", "devicePublicKey", "devicePrivateKey", "origin",
      "fetchImpl", "nowSeconds", "clockSeconds", "recoverySecret"].map(
      (key) => [key, fixture.input[key]])),
    objectId: fixture.input.metadata.object_id,
    journal: fixture.browser.RootarkZk1RecoverablePendingJournal.openStore(fixture.pending),
  });
  const result = await fixture.browser.RootarkZk1RecoverableWorkspace
    .resumePendingProtectedFile(resume);
  assert.equal(result.resumedSignedGetOnly, true);
  assert.deepEqual([fixture.counts().puts, fixture.counts().gets], [1, 2]);
  fixture.secret.fill(0);
});

test("clock rollback during journal preparation denies before PUT", async () => {
  const fixture = await clientFixture({ advanceDuringPrepare: -5 });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(fixture.counts().puts, 0);
  fixture.secret.fill(0);
});

test("50-second owner grant validation does not stale the first signed PUT", async () => {
  const fixture = await clientFixture({ advanceDuringValidate: 50 });
  delete fixture.input.clockSeconds;
  const result = await fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input);
  assert.equal(result.clientReadbackVerified, true);
  assert.deepEqual([fixture.counts().puts, fixture.counts().gets], [1, 1]);
  assert.equal(fixture.pending.writes, 2);
  fixture.secret.fill(0);
});

test("strict rebind transaction refusal cannot allow a stale PUT", async () => {
  const fixture = await clientFixture({
    advanceDuringPrepare: 50, refuseStrictAfterPrepare: true });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(fixture.counts().puts, 0);
  assert.equal(fixture.pending.writes, 1);
  fixture.secret.fill(0);
});

test("strict sending marker refusal denies before PUT", async () => {
  const fixture = await clientFixture({ refuseStrictAfterPrepare: true });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(fixture.counts().puts, 0);
  assert.equal(fixture.pending.writes, 1);
  fixture.secret.fill(0);
});

test("concurrent replacement of the signed journal row fails CAS before PUT", async () => {
  const fixture = await clientFixture({ advanceDuringPrepare: 50 });
  let raced = false;
  fixture.pending.setOnGet((key, reads, values) => {
    if (reads !== 5) return;
    raced = true;
    const row = values.get(key);
    values.set(key, { ...row, operationId: b64(crypto.randomBytes(32)) });
  });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(raced, true);
  assert.equal(fixture.counts().puts, 0);
  assert.equal(fixture.pending.writes, 1);
  fixture.secret.fill(0);
});

test("in-flight durable beginPut blocks a concurrent journal rebind", async () => {
  const fixture = await clientFixture();
  const original = fixture.input.journal.beginPut.bind(fixture.input.journal);
  fixture.input.journal.beginPut = async (args) => {
    const writing = original(args);
    const row = fixture.pending.values.get(args.bundle.metadata.object_id);
    await assert.rejects(fixture.input.journal.rebindBeforePut({
      recoverySecret: fixture.secret, bundle: args.bundle,
      previousOperationId: row.operationId,
      previousOperationSignature: row.operationSignature,
      operationId: b64(crypto.randomBytes(32)),
      operationSignature: b64(crypto.randomBytes(64)),
    }), /ZK_RECOVERABLE_PENDING_UNVERIFIED/);
    return writing;
  };
  const result = await fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input);
  assert.equal(result.clientReadbackVerified, true);
  assert.deepEqual([fixture.counts().puts, fixture.counts().gets], [1, 1]);
  fixture.secret.fill(0);
});

test("browser suspension after durable sending marker denies stale PUT", async () => {
  const fixture = await clientFixture({ advanceDuringSending: 50 });
  await assert.rejects(fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(fixture.counts().puts, 0);
  const pending = await fixture.browser.RootarkZk1RecoverablePendingJournal
    .openStore(fixture.pending).load({ recoverySecret: fixture.secret,
      objectId: fixture.input.metadata.object_id });
  assert.equal(pending.putAttempted, true);
  fixture.secret.fill(0);
});

test("readback signs GET after slow trust-floor verification", async () => {
  const fixture = await clientFixture({ advanceDuringReadbackFloor: 50 });
  const result = await fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input);
  assert.equal(result.clientReadbackVerified, true);
  assert.deepEqual([fixture.counts().puts, fixture.counts().gets], [1, 1]);
  fixture.secret.fill(0);
});

test("cold load remains compatible with original v1 sealed journal records", async () => {
  const fixture = await clientFixture();
  const result = await fixture.browser.RootarkZk1RecoverableWorkspace
    .createRecoverableProtectedFile(fixture.input);
  const objectId = fixture.input.metadata.object_id;
  const row = fixture.pending.values.get(objectId);
  const legacy = { ...row, schema: "rootark-zk1-recoverable-pending/v1" };
  delete legacy.phase;
  const aad = new TextEncoder().encode(
    "Root.ark/zk-1/recoverable-pending-journal/v1\0" + JSON.stringify({
      schema: legacy.schema, operationId: legacy.operationId,
      operationSignature: legacy.operationSignature,
      objectId: legacy.objectId, versionId: legacy.versionId,
      ownerSpkiSha256: legacy.ownerSpkiSha256,
      manifestRevision: legacy.manifestRevision,
      manifestDigest: legacy.manifestDigest, epoch: legacy.epoch,
      ownerHistorySequence: legacy.ownerHistorySequence,
      ciphertextSha256: legacy.ciphertextSha256,
      ciphertextRoot: legacy.ciphertextRoot,
    }));
  legacy.salt = b64(crypto.randomBytes(32));
  legacy.iv = b64(crypto.randomBytes(12));
  const ikm = await crypto.webcrypto.subtle.importKey("raw", fixture.secret,
    "HKDF", false, ["deriveKey"]);
  const aes = await crypto.webcrypto.subtle.deriveKey({
    name: "HKDF", hash: "SHA-256", salt: Buffer.from(legacy.salt, "base64url"),
    info: aad }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  legacy.sealed = b64(Buffer.from(await crypto.webcrypto.subtle.encrypt({
    name: "AES-GCM", iv: Buffer.from(legacy.iv, "base64url"),
    additionalData: aad, tagLength: 128,
  }, aes, new TextEncoder().encode(JSON.stringify(result.bundle)))));
  fixture.pending.values.set(objectId, structuredClone(legacy));
  const reopened = await fixture.browser.RootarkZk1RecoverablePendingJournal
    .openStore(fixture.pending).load({ recoverySecret: fixture.secret, objectId });
  assert.deepEqual(JSON.parse(JSON.stringify(reopened.bundle)),
    JSON.parse(JSON.stringify(result.bundle)));
  assert.equal(reopened.putAttempted, false,
    "v1 pending state is unknown and may only be reconciled by GET");
  fixture.secret.fill(0);
});
