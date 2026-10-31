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
  refuseStrict = false } = {}) {
  let puts = 0, gets = 0, stored = null;
  const browser = {
    crypto: crypto.webcrypto, TextEncoder, TextDecoder, atob, btoa,
    ArrayBuffer, Uint8Array,
    RootarkZk1NormalBrowserContent: {
      async verifyOwnerGrant() { return { ownerGrantSignatureVerified: true }; },
    },
    RootarkZk1NormalBrowserTrustFloor: {
      async verifyExternalAnchor() {},
    },
    RootarkZk1ProtectedHttpClient: {
      async signProtectedContentOperation(request) { return { ...request,
        authorization: { nonce: b64(crypto.randomBytes(32)) },
        signatureBase64: b64(crypto.randomBytes(64)) }; },
      async postProtectedCiphertextPut({ request }) {
        puts++;
        assert.equal(request.operation, "put");
        assert.equal(request.expectedObjectRevision, null);
        stored = Uint8Array.from(request.ciphertext);
        throw Error("ACK_LOST_AFTER_COMMITTED_PUT");
      },
      async postProtectedCiphertextBackupRead({ request, expectedObjectRevision,
        expectedEpoch, expectedRoot }) {
        gets++;
        assert.equal(request.operation, "get");
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
  const journal = browser.RootarkZk1RecoverablePendingJournal.openStore(pending);
  const input = Object.assign(realm("{}"), {
    ownerPublicKey: null, pinnedOwnerKeyHash: crypto.randomBytes(32),
    independentOwnerSpkiSha256: crypto.randomBytes(32),
    pinnedCurrentHead: Object.assign(realm("{}"),
      { revision: 1, epoch: 1, digest: crypto.randomBytes(32) }),
    signedDeviceGrant: { ...scope, device_id: "device-one" },
    ownerHistoryCheckpoint: null, devicePublicKey: null, devicePrivateKey: null,
    origin: "http://127.0.0.1/", fetchImpl: () => { throw Error("UNEXPECTED_FETCH"); },
    nowSeconds: 10, recoverySecret: secret, metadata,
    name: "encrypted.txt", mediaType: "text/plain", data: plaintext, journal,
  });
  return { browser, input, secret, plaintext, pending, realm,
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
  assert.equal(fixture.pending.writes, 1);
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
