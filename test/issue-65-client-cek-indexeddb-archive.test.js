"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const archive = require("../public/client/rootark-zk1-client-cek-archive");
const { webcrypto } = crypto;
const subtle = webcrypto.subtle;
const b64 = (data) => Buffer.from(data).toString("base64url");
const rnd = (n) => crypto.randomBytes(n);
const sha = (data) => crypto.createHash("sha256").update(data).digest();
const GRANT = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
  "authorization_key_id", "authorization_public_key", "manifest_revision", "manifest_digest",
  "current_epoch", "enrolled_epoch", "revoked_at_epoch"];

// Small transactional event simulator: all requests and completion callbacks
// are async; readwrite transactions are serialized as IndexedDB requires.
// Browser-specific persistence is separately exercised in Edge when available.
function indexedDBMock() {
  const data = new Map();
  let tail = Promise.resolve();
  let opened = false;
  function makeDB() {
    return {
      objectStoreNames: { contains: (name) => name === "sealed" },
      createObjectStore(name) { assert.equal(name, "sealed"); },
      close() {},
      transaction(name, mode) {
        assert.equal(name, "sealed");
        const previous = tail;
        let unlock = () => {};
        if (mode === "readwrite") tail = new Promise((done) => { unlock = done; });
        let pending = 0, stopped = false, completed = false;
        const tx = { oncomplete: null, onerror: null, onabort: null, abort() {
          if (stopped || completed) return;
          stopped = true; queueMicrotask(() => { unlock(); tx.onabort?.(); });
        } };
        function schedule(fn) {
          pending++;
          const request = { result: undefined, onsuccess: null };
          previous.then(() => queueMicrotask(() => {
            if (stopped) return;
            try {
              request.result = fn();
              request.onsuccess?.({ target: request });
            } catch (error) { tx.abort(); return; }
            queueMicrotask(() => {
              pending--;
              if (!pending && !stopped && !completed) {
                completed = true; unlock(); tx.oncomplete?.();
              }
            });
          }));
          return request;
        }
        tx.objectStore = () => ({
          get(key) { return schedule(() => data.get(key)); },
          put(value, key) {
            assert.equal(mode, "readwrite");
            return schedule(() => { data.set(key, value); return key; });
          },
        });
        return tx;
      },
    };
  }
  return {
    data,
    open(name, version) {
      assert.equal(name, "rootark-zk1-encrypted-cek-archive-v1");
      assert.equal(version, 1);
      const request = { result: makeDB(), onupgradeneeded: null,
        onsuccess: null, onerror: null, onblocked: null };
      queueMicrotask(() => {
        if (!opened) { opened = true; request.onupgradeneeded?.(); }
        request.onsuccess?.();
      });
      return request;
    },
  };
}

async function fixture({ backup = true } = {}) {
  const signing = crypto.generateKeyPairSync("ed25519");
  const ownerPublicKey = await subtle.importKey("spki",
    signing.publicKey.export({ type: "spki", format: "der" }),
    "Ed25519", true, ["verify"]);
  const ownerSigningKey = await subtle.importKey("pkcs8",
    signing.privateKey.export({ type: "pkcs8", format: "der" }),
    "Ed25519", false, ["sign"]);
  const scope = { account_id: b64(rnd(16)), compartment_id: b64(rnd(16)),
    keyring_id: b64(rnd(16)) };
  const head = { revision: 7, digest: rnd(32), epoch: 5 };
  const grant = { schema: "rootark-zk1-browser-owner-device-grant/v1", ...scope,
    device_id: "device-test", authorization_key_id: b64(rnd(16)),
    authorization_public_key: b64(rnd(32)), manifest_revision: head.revision,
    manifest_digest: b64(head.digest), current_epoch: head.epoch,
    enrolled_epoch: 1, revoked_at_epoch: null };
  const grantBytes = Buffer.concat([
    Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((key) => [key, grant[key]]))))]);
  grant.signature = b64(crypto.sign(null, grantBytes, signing.privateKey));
  const db = indexedDBMock();
  let pin = null;
  let pinLostAck = false;
  const pinProvider = {
    read: async () => pin,
    compareAndSwap: async (expected, next) => {
      if (pin !== expected) throw Error("PIN_RACE");
      pin = next;
      if (pinLostAck) { pinLostAck = false; throw Error("ACK_LOST"); }
      return { digest: next };
    },
  };
  const remote = new Map();
  let remoteLostAck = false;
  const providerSigner = crypto.generateKeyPairSync("ed25519");
  const providerId = b64(rnd(16));
  const providerSpki = providerSigner.publicKey.export({ type: "spki", format: "der" });
  const backupReceiptPublicKey = backup ? await subtle.importKey("spki", providerSpki,
    "Ed25519", true, ["verify"]) : null;
  const backupProvider = backup ? {
    async put({ key, ciphertext }) {
      assert.equal(b64(sha(ciphertext)), key);
      remote.set(key, Uint8Array.from(ciphertext));
      if (remoteLostAck) { remoteLostAck = false; throw Error("ACK_LOST"); }
      return { acknowledged: true };
    },
    async get({ key }) {
      const ciphertext = remote.get(key)?.slice();
      if (!ciphertext) return null;
      const signed = { schema: "rootark-zk1-client-cek-backup-receipt/v1",
        digest: key, byteLength: ciphertext.length, providerId };
      const message = Buffer.concat([
        Buffer.from("Root.ark/zk-1/cek-backup-provider-receipt/v1\0"),
        Buffer.from(JSON.stringify(signed))]);
      return { ciphertext, receipt: { ...signed,
        signature: b64(crypto.sign(null, message, providerSigner.privateKey)) } };
    },
  } : null;
  const secret = rnd(32);
  const config = {
    indexedDBImpl: db, recoverySecret: secret, ownerPublicKey, ownerSigningKey,
    independentOwnerSpkiSha256: sha(signing.publicKey.export({ type: "spki", format: "der" })),
    pinnedCurrentHead: head, signedDeviceGrant: grant,
    pinProvider, backupProvider, backupReceiptPublicKey,
    independentBackupReceiptSpkiSha256: backup ? sha(providerSpki) : null,
    assertLive: () => {},
  };
  const metadata = { ...scope, object_id: b64(rnd(16)), version_id: b64(rnd(16)),
    parent_version_id: null, epoch: 5, kind: "file" };
  function entry({ revision = 1, version = metadata.version_id, cek = rnd(32) } = {}) {
    const data = rnd(80);
    return { metadata: { ...metadata, version_id: version }, revision,
      ciphertext: data, cek, state: "file" };
  }
  function challenge(entries, nonce = b64(rnd(32))) {
    return { objectId: metadata.object_id, action: "rename", epoch: 5,
      nonce, entries: entries.map((item) => ({ revision: item.revision,
        versionId: item.metadata.version_id, ciphertextDigest: b64(sha(item.ciphertext)) })) };
  }
  return { db, config, grant, head, pinProvider, remote, backupProvider, signing,
    entry, challenge, getPin: () => pin, setPin: (value) => { pin = value; },
    lostAck() { pinLostAck = true; remoteLostAck = true; } };
}

test("IndexedDB signed AES-GCM CEK archive survives client restart, lost remote and pin ACK", async () => {
  const f = await fixture();
  const entry = f.entry();
  const challenge = f.challenge([entry]);
  f.lostAck();
  const store = await archive.openCekArchive(f.config);
  const saved = await store.archiveKeys({ challenge, entries: [entry] });
  assert.equal(saved.localIndexedDbCommitted, true);
  assert.equal(saved.remoteCiphertextReadbackVerified, true);
  assert.equal(saved.independentCloudDurabilityProven, false);
  assert.equal(saved.externallyPinnedDigest, f.getPin());
  const raw = [...f.db.data.values()][0];
  assert.equal(typeof raw, "string");
  assert.ok(!raw.includes(b64(entry.cek)));
  assert.ok(!raw.includes("filename"));
  assert.ok(!JSON.stringify([...f.remote.values()]).includes(b64(entry.cek)));
  let imported = await store.readArchivedCek({ objectId: entry.metadata.object_id,
    revision: entry.revision, versionId: entry.metadata.version_id, nonce: challenge.nonce });
  assert.equal(imported.extractable, false);
  const iv = rnd(12);
  const message = Buffer.from("recovered after restart");
  const seal = await subtle.encrypt({ name: "AES-GCM", iv },
    await subtle.importKey("raw", entry.cek, "AES-GCM", false, ["encrypt"]), message);
  assert.deepEqual(Buffer.from(await subtle.decrypt({ name: "AES-GCM", iv }, imported, seal)), message);
  store.close();
  await assert.rejects(store.readArchivedCek({ objectId: entry.metadata.object_id,
    revision: 1, versionId: entry.metadata.version_id, nonce: challenge.nonce }), /DENIED/);
  const reopened = await archive.openCekArchive(f.config);
  imported = await reopened.readArchivedCek({ objectId: entry.metadata.object_id,
    revision: 1, versionId: entry.metadata.version_id, nonce: challenge.nonce });
  assert.deepEqual(Buffer.from(await subtle.decrypt({ name: "AES-GCM", iv }, imported, seal)), message);
  reopened.close();
});

test("tampering, rollback, metadata replay, revocation and epoch mismatch fail closed", async () => {
  const f = await fixture();
  const one = f.entry();
  const challenge = f.challenge([one]);
  const store = await archive.openCekArchive(f.config);
  const commit = await store.archiveKeys({ challenge, entries: [one] });
  const old = [...f.db.data.values()][0];
  const key = [...f.db.data.keys()][0];
  const attempt = () => store.readArchivedCek({ objectId: one.metadata.object_id,
    revision: 1, versionId: one.metadata.version_id, nonce: challenge.nonce });
  for (const property of ["ciphertext", "signature", "head", "challenge"]) {
    const tampered = JSON.parse(old);
    if (property === "head") tampered.head.epoch++;
    else if (property === "challenge") tampered.challenge.nonce = b64(rnd(32));
    else tampered[property] = b64(rnd(property === "signature" ? 64 : 48));
    f.db.data.set(key, JSON.stringify(tampered));
    await assert.rejects(attempt(), /DENIED/);
  }
  f.db.data.set(key, old);
  f.setPin(b64(rnd(32)));
  await assert.rejects(attempt(), /DENIED/);
  f.setPin(commit.externallyPinnedDigest);
  await assert.rejects(store.readArchivedCek({ objectId: one.metadata.object_id,
    revision: 1, versionId: one.metadata.version_id, nonce: b64(rnd(32)) }), /DENIED/);
  store.close();
  await assert.rejects(archive.openCekArchive({ ...f.config,
    signedDeviceGrant: { ...f.grant, revoked_at_epoch: 5 } }), /DENIED/);
  await assert.rejects(archive.openCekArchive({ ...f.config,
    pinnedCurrentHead: { ...f.head, epoch: 6 } }), /DENIED/);
  await assert.rejects(archive.openCekArchive({ ...f.config,
    independentOwnerSpkiSha256: rnd(32) }), /DENIED/);
});

test("restore ciphertext-only remote backup after local DB loss, require external pin", async () => {
  const f = await fixture();
  const a = f.entry();
  const challenge = f.challenge([a]);
  const store = await archive.openCekArchive(f.config);
  const { externallyPinnedDigest } = await store.archiveKeys({ challenge, entries: [a] });
  store.close();
  f.db.data.clear();
  const recovery = await archive.openCekArchive({ ...f.config, ownerSigningKey: null });
  await assert.rejects(recovery.readArchivedCek({ objectId: a.metadata.object_id,
    revision: 1, versionId: a.metadata.version_id, nonce: challenge.nonce }), /DENIED/);
  const result = await recovery.restoreFromBackup({ expectedDigest: externallyPinnedDigest });
  assert.equal(result.localIndexedDbCommitted, true);
  assert.equal(result.remoteCiphertextReadbackVerified, true);
  assert.equal(result.independentCloudDurabilityProven, false);
  assert.equal((await recovery.readArchivedCek({ objectId: a.metadata.object_id,
    revision: 1, versionId: a.metadata.version_id, nonce: challenge.nonce })).extractable, false);
  await assert.rejects(recovery.archiveKeys({ challenge, entries: [a] }), /DENIED/);
  recovery.close();
  f.db.data.clear();
  const stale = await archive.openCekArchive(f.config);
  f.remote.set(externallyPinnedDigest, rnd(160));
  await assert.rejects(stale.restoreFromBackup({ expectedDigest: externallyPinnedDigest }), /DENIED/);
  f.setPin(b64(rnd(32)));
  await assert.rejects(stale.restoreFromBackup({ expectedDigest: externallyPinnedDigest }), /DENIED/);
  stale.close();
});

test("optimistic local CAS fences racing writers and pending external pin ACK is reconcilable", async () => {
  const f = await fixture({ backup: false });
  const store1 = await archive.openCekArchive(f.config);
  const store2 = await archive.openCekArchive(f.config);
  const first = f.entry();
  const second = f.entry({ revision: 2, version: b64(rnd(16)) });
  const attempted = await Promise.allSettled([
    store1.archiveKeys({ challenge: f.challenge([first]), entries: [first] }),
    store2.archiveKeys({ challenge: f.challenge([second]), entries: [second] }),
  ]);
  assert.equal(attempted.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(attempted.filter((r) => r.status === "rejected").length, 1);
  const winner = attempted.find((r) => r.status === "fulfilled").value;
  assert.equal(f.getPin(), winner.externallyPinnedDigest);
  const pending = await store1.inspectPendingArchive();
  assert.equal(pending.independentlyPinned, true);
  assert.equal(pending.authorizesKeyRelease, false);
  const reconciled = await store2.reconcileUncertainArchive({ expectedDigest: winner.externallyPinnedDigest });
  assert.equal(reconciled.localIndexedDbCommitted, true);
  store1.close(); store2.close();
});

test("nonextractable CryptoKeys never downgrade into unencrypted IndexedDB custody", async () => {
  const f = await fixture();
  const store = await archive.openCekArchive(f.config);
  const item = f.entry();
  item.cek = await subtle.importKey("raw", item.cek, "AES-GCM", false, ["decrypt"]);
  await assert.rejects(store.archiveKeys({ challenge: f.challenge([item]), entries: [item] }), /DENIED/);
  assert.equal(f.db.data.size, 0);
  store.close();
});

test("re-archiving the same historical CEK adds only authenticated nonce aliases", async () => {
  const f = await fixture();
  const store = await archive.openCekArchive(f.config);
  const item = f.entry();
  const first = f.challenge([item]);
  await store.archiveKeys({ challenge: first, entries: [item] });
  const second = f.challenge([item]);
  const committed = await store.archiveKeys({ challenge: second, entries: [item] });
  assert.equal(committed.localIndexedDbCommitted, true);
  for (const nonce of [first.nonce, second.nonce]) {
    const cek = await store.readArchivedCek({ objectId: item.metadata.object_id,
      revision: item.revision, versionId: item.metadata.version_id, nonce });
    assert.equal(cek.extractable, false);
  }
  await assert.rejects(store.archiveKeys({ challenge: f.challenge([{
    ...item, cek: rnd(32) }]), entries: [{ ...item, cek: rnd(32) }] }), /DENIED/);
  store.close();
});

test("signed remote receipt must match independently pinned provider key and exact GET bytes", async () => {
  const f = await fixture();
  const item = f.entry();
  const store = await archive.openCekArchive(f.config);
  const oldGet = f.backupProvider.get;
  f.backupProvider.get = async (input) => {
    const response = await oldGet(input);
    return { ...response, receipt: { ...response.receipt,
      signature: b64(rnd(64)) } };
  };
  await assert.rejects(store.archiveKeys({ challenge: f.challenge([item]),
    entries: [item] }), /DENIED/);
  assert.equal(f.db.data.size, 0);
  f.backupProvider.get = oldGet;
  store.close();
  await assert.rejects(archive.openCekArchive({ ...f.config,
    independentBackupReceiptSpkiSha256: rnd(32) }), /DENIED/);
});

test("externally pinned signed pending local write can reconcile uncertain pin ACK", async () => {
  const f = await fixture({ backup: false });
  const item = f.entry();
  const store = await archive.openCekArchive(f.config);
  f.pinProvider.compareAndSwap = async () => { throw Error("PIN_OFFLINE"); };
  const challenge = f.challenge([item]);
  await assert.rejects(store.archiveKeys({ challenge, entries: [item] }), /DENIED/);
  assert.equal(f.db.data.size, 1);
  await assert.rejects(store.readArchivedCek({ objectId: item.metadata.object_id,
    revision: 1, versionId: item.metadata.version_id, nonce: challenge.nonce }), /DENIED/);
  const pending = await store.inspectPendingArchive();
  assert.equal(pending.independentlyPinned, false);
  const pinProvider = f.pinProvider;
  pinProvider.compareAndSwap = async (expected, digest) => {
    assert.equal(expected, null); f.setPin(digest); throw Error("ACK_LOST");
  };
  const reconciled = await store.reconcileUncertainArchive({ expectedDigest: pending.digest });
  assert.equal(reconciled.externallyPinnedDigest, f.getPin());
  const key = await store.readArchivedCek({ objectId: item.metadata.object_id,
    revision: 1, versionId: item.metadata.version_id, nonce: challenge.nonce });
  assert.equal(key.extractable, false);
  store.close();
});

test("an expired synchronous session fence denies key access after opening", async () => {
  const f = await fixture();
  let active = true;
  const store = await archive.openCekArchive({ ...f.config,
    assertLive: () => active });
  const item = f.entry();
  const challenge = f.challenge([item]);
  await store.archiveKeys({ challenge, entries: [item] });
  active = false;
  await assert.rejects(store.readArchivedCek({ objectId: item.metadata.object_id,
    revision: 1, versionId: item.metadata.version_id, nonce: challenge.nonce }), /DENIED/);
  store.close();
});

test("two independent browser stores exchange tombstone and restored CEKs through signed backup", async () => {
  const f = await fixture();
  const browserA = await archive.openCekArchive(f.config);
  const initial = f.entry();
  const started = f.challenge([initial]);
  const first = await browserA.archiveKeys({ challenge: started, entries: [initial] });
  const grantB = { ...f.grant, device_id: "second-browser-device",
    authorization_key_id: b64(rnd(16)), authorization_public_key: b64(rnd(32)) };
  grantB.signature = b64(crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((key) => [key, grantB[key]])))),
  ]), f.signing.privateKey));
  const deviceB = { ...f.config, indexedDBImpl: indexedDBMock(),
    signedDeviceGrant: grantB };
  const browserB = await archive.openCekArchive(deviceB);
  const imported = await browserB.syncFromBackup({ expectedDigest: first.externallyPinnedDigest });
  assert.equal(imported.signedHistoryVerified, true);
  const historical = await browserB.readArchivedCek({ objectId: initial.metadata.object_id,
    revision: 1, versionId: initial.metadata.version_id, nonce: started.nonce });
  const next = f.entry({ revision: 2, version: b64(rnd(16)) });
  next.metadata.parent_version_id = initial.metadata.version_id;
  next.state = "trashed";
  const request = { ...f.challenge([initial, next]), ...Object.fromEntries(
    ["account_id", "compartment_id", "keyring_id"].map((k) => [k, initial.metadata[k]])),
    action: "trash" };
  const bridgeB = browserB.createLogicalTrashBridge();
  const signed = await bridgeB.archiveKeys({ challenge: request, entries: [
    { ...initial, cek: historical }, next,
  ] });
  assert.deepEqual(Object.keys(signed), ["signatureBase64"]);
  assert.equal(Buffer.from(signed.signatureBase64, "base64url").length, 64);
  await assert.rejects(browserA.readArchivedCek({ objectId: initial.metadata.object_id,
    revision: 1, versionId: initial.metadata.version_id, nonce: started.nonce }), /DENIED/);
  assert.equal((await browserA.syncFromBackup({ expectedDigest: f.getPin() })).signedHistoryVerified, true);
  const readA = await browserA.createLogicalTrashBridge().readArchivedCek({
    account_id: initial.metadata.account_id,
    compartment_id: initial.metadata.compartment_id,
    keyring_id: initial.metadata.keyring_id,
    objectId: next.metadata.object_id, revision: 2,
    versionId: next.metadata.version_id, nonce: request.nonce });
  assert.equal(readA.extractable, false);
  // Restore is a new version, not a physical deletion of the tombstone.
  const restored = f.entry({ revision: 3, version: b64(rnd(16)) });
  restored.metadata.parent_version_id = next.metadata.version_id;
  const restore = { ...f.challenge([next, restored]), ...Object.fromEntries(
    ["account_id", "compartment_id", "keyring_id"].map((k) => [k, next.metadata[k]])),
    action: "restore" };
  const signedRestore = await browserA.createLogicalTrashBridge().archiveKeys({
    challenge: restore, entries: [{ ...next, cek: readA }, restored] });
  assert.equal(Object.keys(signedRestore).length, 1);
  browserA.close(); browserB.close();
  const restartedB = await archive.openCekArchive({ ...deviceB,
    indexedDBImpl: indexedDBMock(), ownerSigningKey: null });
  await restartedB.restoreFromBackup({ expectedDigest: f.getPin() });
  assert.equal((await restartedB.readArchivedCek({ objectId: restored.metadata.object_id,
    revision: 3, versionId: restored.metadata.version_id, nonce: restore.nonce })).extractable, false);
  restartedB.close();
  // The archive contains no raw CEKs, protected names, or plaintext on the provider.
  for (const data of f.remote.values()) {
    const text = Buffer.from(data).toString("utf8");
    for (const raw of [initial.cek, next.cek, restored.cek])
      assert.ok(!text.includes(b64(raw)));
  }
});

test("renameOrMoveCommitted bridge writes and reads exact raw32 before remote PUT", async () => {
  const f = await fixture();
  const browser = await archive.openCekArchive(f.config);
  const entry = f.entry();
  const bridge = browser.createRenameArchiveBridge();
  const digest = sha(entry.ciphertext);
  const receiptId = await bridge.write({ metadata: entry.metadata,
    objectRevision: entry.revision, ciphertext: entry.ciphertext,
    ciphertextDigest: digest, cek: entry.cek });
  assert.equal(receiptId, f.getPin());
  const recovered = await bridge.read({ receiptId, metadata: entry.metadata,
    objectRevision: entry.revision, ciphertextDigest: digest });
  assert.deepEqual(Buffer.from(recovered), Buffer.from(entry.cek));
  recovered.fill(0);
  await assert.rejects(bridge.read({ receiptId, metadata: entry.metadata,
    objectRevision: entry.revision, ciphertextDigest: rnd(32) }), /DENIED/);
  await assert.rejects(bridge.write({ metadata: entry.metadata,
    objectRevision: 2, ciphertext: entry.ciphertext, ciphertextDigest: digest,
    cek: await subtle.importKey("raw", entry.cek, "AES-GCM", false, ["encrypt"]) }), /DENIED/);
  browser.close();
});

test("two distinct owner keys cross-sign rotation and preserve historical CEKs without key egress", async () => {
  const f = await fixture();
  const browserA = await archive.openCekArchive(f.config);
  const entry = f.entry();
  const firstChallenge = f.challenge([entry]);
  await browserA.archiveKeys({ challenge: firstChallenge, entries: [entry] });
  const oldDigest = f.getPin();
  browserA.close();
  const nextOwner = crypto.generateKeyPairSync("ed25519");
  const nextPublic = await subtle.importKey("spki", nextOwner.publicKey.export({
    format: "der", type: "spki" }), "Ed25519", true, ["verify"]);
  const nextPrivate = await subtle.importKey("pkcs8", nextOwner.privateKey.export({
    format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]);
  const nextHead = { revision: f.head.revision + 1, epoch: f.head.epoch + 1,
    digest: rnd(32) };
  const nextGrant = { ...f.grant, device_id: "new-owner-browser",
    authorization_key_id: b64(rnd(16)), authorization_public_key: b64(rnd(32)),
    manifest_revision: nextHead.revision,
    manifest_digest: b64(nextHead.digest), current_epoch: nextHead.epoch };
  nextGrant.signature = b64(crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((key) => [key, nextGrant[key]])))),
  ]), nextOwner.privateKey));
  const oldPin = sha(f.signing.publicKey.export({ format: "der", type: "spki" }));
  const newPin = sha(nextOwner.publicKey.export({ format: "der", type: "spki" }));
  const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((key) => [key, entry.metadata[key]]));
  const transition = { schema: "rootark-zk1-client-cek-owner-rotation/v1", scope,
    fromOwnerSpkiSha256: b64(oldPin), toOwnerSpkiSha256: b64(newPin),
    fromHead: { revision: f.head.revision, digest: b64(f.head.digest), epoch: f.head.epoch },
    toHead: { revision: nextHead.revision, digest: b64(nextHead.digest), epoch: nextHead.epoch },
    previousArchiveDigest: oldDigest, nonce: b64(rnd(32)) };
  const signatureMessage = Buffer.concat([Buffer.from("Root.ark/zk-1/cek-owner-rotation/v1\0"),
    Buffer.from(JSON.stringify(transition))]);
  const approved = { ...transition,
    fromSignature: b64(crypto.sign(null, signatureMessage, f.signing.privateKey)),
    toSignature: b64(crypto.sign(null, signatureMessage, nextOwner.privateKey)) };
  const rotatedConfig = { ...f.config, indexedDBImpl: indexedDBMock(),
    ownerPublicKey: nextPublic, ownerSigningKey: nextPrivate,
    pinnedCurrentHead: nextHead, signedDeviceGrant: nextGrant,
    independentOwnerSpkiSha256: newPin };
  const browserB = await archive.openCekArchive(rotatedConfig);
  for (const invalid of [
    { ...approved, fromSignature: b64(rnd(64)) },
    { ...approved, toSignature: b64(rnd(64)) },
    { ...approved, previousArchiveDigest: b64(rnd(32)) },
    { ...approved, fromHead: { ...approved.fromHead, epoch: nextHead.epoch } },
  ]) await assert.rejects(browserB.rotateFromPreviousOwner({ transition: invalid,
    previousOwnerPublicKey: f.config.ownerPublicKey,
    independentPreviousOwnerSpkiSha256: oldPin,
    previousRecoverySecret: f.config.recoverySecret }), /DENIED/);
  const rotated = await browserB.rotateFromPreviousOwner({ transition: approved,
    previousOwnerPublicKey: f.config.ownerPublicKey,
    independentPreviousOwnerSpkiSha256: oldPin,
    previousRecoverySecret: f.config.recoverySecret });
  assert.equal(rotated.signedOwnerRotationVerified, true);
  assert.equal(rotated.previousArchiveDigest, oldDigest);
  assert.equal((await browserB.readArchivedCek({ objectId: entry.metadata.object_id,
    revision: 1, versionId: entry.metadata.version_id, nonce: firstChallenge.nonce })).extractable, false);
  browserB.close();
  const migratedA = await archive.openCekArchive({ ...rotatedConfig,
    indexedDBImpl: f.db, ownerSigningKey: null });
  const adoption = await migratedA.adoptRotatedOwner({ transition: approved,
    previousOwnerPublicKey: f.config.ownerPublicKey,
    independentPreviousOwnerSpkiSha256: oldPin,
    previousRecoverySecret: f.config.recoverySecret,
    expectedDigest: rotated.independentlyPinnedDigest });
  assert.equal(adoption.crossSignedOwnerRotationVerified, true);
  assert.equal((await migratedA.readArchivedCek({ objectId: entry.metadata.object_id,
    revision: 1, versionId: entry.metadata.version_id, nonce: firstChallenge.nonce })).extractable, false);
  migratedA.close();
  const revived = await archive.openCekArchive({ ...rotatedConfig, ownerSigningKey: null });
  assert.equal((await revived.readArchivedCek({ objectId: entry.metadata.object_id,
    revision: 1, versionId: entry.metadata.version_id, nonce: firstChallenge.nonce })).extractable, false);
  revived.close();
  const newBrowser = await archive.openCekArchive({ ...rotatedConfig,
    indexedDBImpl: indexedDBMock(), ownerSigningKey: null });
  assert.equal((await newBrowser.adoptRotatedOwner({ transition: approved,
    previousOwnerPublicKey: f.config.ownerPublicKey,
    independentPreviousOwnerSpkiSha256: oldPin,
    previousRecoverySecret: f.config.recoverySecret,
    expectedDigest: rotated.independentlyPinnedDigest })).crossSignedOwnerRotationVerified, true);
  newBrowser.close();
  await assert.rejects(archive.openCekArchive({ ...f.config,
    signedDeviceGrant: { ...f.grant, revoked_at_epoch: f.head.epoch } }), /DENIED/);
});
