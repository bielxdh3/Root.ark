"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname,
  "../public/client/rootark-zk1-authenticated-workspace.js"), "utf8");
const encode = (value) => Buffer.from(value).toString("base64url");
const tickUntil = async (condition) => {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error("BROWSER_LOGOUT_TEST_TIMEOUT");
};

async function harness() {
  const listeners = new Map();
  const controls = new Map();
  const downloads = [];
  const trace = [];
  let onDownload = null;
  let restoreCount = 0;
  let finishRestore;
  let finishArchive;
  let finishBatch;
  let batchCalls = 0;
  let finishAccountCreate;
  let finishAccountRecover;
  let accountCreateCalls = 0;
  let accountRecoverCalls = 0;
  let selectedBlob = null;
  const historicalChallenges = new WeakMap();
  let nextHistoricChallenge = 0;
  const window = {
    RootarkApi: { get: async () => ({ enabled: true,
      securityVersion: 2, signedHistoryRequired: true }) },
    isSecureContext: true, crypto: crypto.webcrypto,
    RootarkZk1NormalBrowserTrustFloor: {
      provisionOffline: async () => ({}),
      assertCurrent: async ({ ownerPublicKey, independentOwnerSpkiSha256 }) => {
        trace.push("assertCurrent");
        const raw = Buffer.from(await crypto.webcrypto.subtle.exportKey("raw", ownerPublicKey));
        const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
        assert.deepEqual(Buffer.from(independentOwnerSpkiSha256),
          crypto.createHash("sha256").update(spki).digest(), "external owner SPKI pin");
        return {};
      } },
    RootarkZk1OwnerSignedCheckpoint: {
      verifyOwnerCheckpoint: async ({ checkpoint }) => {
        trace.push("history");
        return { sequence: checkpoint.sequence };
      } },
    RootarkZk1NormalBrowserContent: { uploadAndVerify: async () => ({}) },
    RootarkZk1LegacyMigrationWorkflow: { openMigrationJournal: async () => ({ close() {} }) },
    RootarkZk1FileContent: { importFileCek: (raw) => crypto.webcrypto.subtle.importKey(
      "raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]) },
    RootarkZk1LegacyBatchMigration: { runLegacyMigrationBatch: (input) => {
      trace.push("batch");
      batchCalls++;
      window.batchInput = input;
      return new Promise((resolve) => { finishBatch = resolve; });
    } },
    RootarkZk1AccountPortableRecovery: {
      createArchive: (input) => {
        accountCreateCalls++;
        window.accountCreateInput = input;
        return new Promise((resolve) => { finishAccountCreate = resolve; });
      },
      recoverArchive: (input) => {
        accountRecoverCalls++;
        window.accountRecoverInput = input;
        return new Promise((resolve) => { finishAccountRecover = resolve; });
      },
    },
    RootarkZk1V2DeviceApproval: { verifyImportedApproval: async () => ({}) },
    RootarkZk1V2BrowserPop: { respond: async () => ({}) },
    RootarkZk1V2CommittedApproval: {
      verifyCommittedApproval: async () => ({
        committedOwnerApprovalVerified: true, signedWitnessReceiptVerified: true,
        previousReceiptHashPinned: true, committedV2ManifestDigestMatched: true,
        authorizesProductionIo: false,
      }),
      assertForRestore: async () => true,
    },
    RootarkZk1KeyringPortableArchive: {
      createArchive: async () => ({}),
      issueHistoricalRecoveryChallenge: async (binding) => {
        trace.push("historic-issue-device-pop");
        const challenge = Object.freeze({ nonce: ++nextHistoricChallenge });
        historicalChallenges.set(challenge, { binding,
          message: Uint8Array.from(Buffer.from("historical-one-use-" + nextHistoricChallenge)) });
        window.lastChallenge = challenge;
        return challenge;
      },
      historicalRecoveryChallengeMessage: (challenge) => {
        if (!historicalChallenges.has(challenge)) throw Error("FORGED_DEVICE_POP_CHALLENGE");
        trace.push("historic-branded-challenge-message");
        return historicalChallenges.get(challenge).message.slice();
      },
      recoverArchive: (input) => {
        trace.push("recoverArchive");
        window.archiveRecoverInput = input;
        return new Promise((resolve) => { finishArchive = resolve; });
      },
    },
    RootarkZk1RecoverableWorkspace: {
      restoreOnNewDevice: () => {
        restoreCount++;
        return new Promise((resolve) => { finishRestore = resolve; });
      },
    },
    addEventListener(name, callback) { listeners.set(name, callback); },
  };
  const dialog = {
    open: false, events: {}, setAttribute() {},
    addEventListener(name, callback) { this.events[name] = callback; },
    showModal() { this.open = true; },
    close() { this.open = false; },
    querySelectorAll() { return []; },
    querySelector(selector) {
      if (selector === "form") return { reset() {
        for (const field of controls.values()) { field.files = []; field.value = ""; }
      } };
      const name = /data-zk1-field="([^"]+)"/.exec(selector)?.[1];
      if (!name) return null;
      if (!controls.has(name)) {
        const control = { files: [], checked: false, textContent: "", _value: "" };
        Object.defineProperty(control, "value", {
          get() { return this._value; },
          set(value) { this._value = value; if (value === "") this.files = []; },
        });
        controls.set(name, control);
      }
      return controls.get(name);
    },
  };
  const panel = { append(button) { window.button = button; } };
  const document = {
    cookie: "rootark_csrf=original-session",
    getElementById(id) {
      if (id === "protectedClientStatus") return { closest: () => panel };
      if (id === "zk1-workspace-open") return window.button || null;
      return null;
    },
    createElement(kind) {
      if (kind === "dialog") return dialog;
      if (kind === "script") return {};
      if (kind === "button") return {
        addEventListener(_event, callback) { this.click = callback; },
        remove() { window.button = null; },
      };
      if (kind === "a") return {
        click() {
          downloads.push({ name: this.download, dialogOpen: dialog.open, blob: selectedBlob });
          onDownload?.();
        },
        remove() {},
      };
      throw new Error("UNEXPECTED_ELEMENT_" + kind);
    },
    head: { append(script) { script.onload?.(); } },
    body: { append() {} },
  };
  const url = { createObjectURL: (blob) => { selectedBlob = blob; return "blob:fixture"; },
    revokeObjectURL() {} };
  vm.runInNewContext(source, {
    window, document, location: { origin: "https://localhost" },
    crypto: crypto.webcrypto, URL: url, Blob, Headers,
    TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, atob, btoa,
    setTimeout: (callback, delay) => delay === 60000 ? 0 : setTimeout(callback, delay),
  });
  listeners.get("rootark:workspace-rendered")();
  await tickUntil(() => Boolean(window.button));
  await window.button.click();
  assert.equal(dialog.open, true);

  const owner = crypto.generateKeyPairSync("ed25519");
  const device = crypto.generateKeyPairSync("ed25519");
  const ownerRaw = owner.publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const field = (name) => dialog.querySelector('[data-zk1-field="' + name + '"]');
  const file = (name, data) => {
    const bytes = Buffer.from(data);
    field(name).files = [{ size: bytes.length,
      arrayBuffer: async () => Uint8Array.from(bytes).buffer }];
  };
  const value = (name, data) => { field(name).value = String(data); };
  file("owner", ownerRaw);
  const grantWire = { revoked_at_epoch: null,
    account_id: encode(crypto.randomBytes(16)), compartment_id: encode(Buffer.from("scope")),
    keyring_id: encode(crypto.randomBytes(16)) };
  file("grant", JSON.stringify(grantWire));
  file("history", JSON.stringify({ sequence: 1, signer_key_id: encode(crypto.randomBytes(16)) }));
  file("device", device.publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  file("private", device.privateKey.export({ type: "pkcs8", format: "der" }));
  file("secret", crypto.randomBytes(32));
  file("bundle", JSON.stringify({ metadata: {} }));
  file("owner-root", "{}");
  file("archive-json", "{}");
  file("account-owner-private", owner.privateKey.export({ type: "pkcs8", format: "der" }));
  file("witness-key", crypto.randomBytes(32));
  // This test harness isolates logout behavior, not cryptographic validity.
  file("new-approval", JSON.stringify({
    schema: "rootark-zk1-v2-owner-browser-delivery/v1",
    request: {}, approval: {}, signedDeviceGrant: grantWire,
    committedReceipt: {}, previousReceipt: {}, signedV2Manifest: "signed-fixture",
  }));
  value("owner-hash", encode(crypto.createHash("sha256").update(ownerRaw).digest()));
  value("owner-spki", encode(crypto.createHash("sha256")
    .update(owner.publicKey.export({ type: "spki", format: "der" })).digest()));
  value("revision", 1);
  value("epoch", 1);
  value("digest", encode(crypto.randomBytes(32)));
  value("root", encode(crypto.randomBytes(32)));
  value("archive-sha", encode(crypto.randomBytes(32)));
  value("owner-signer", encode(crypto.randomBytes(16)));
  value("owner-device", "fixture-owner");
  value("witness-spki", encode(crypto.randomBytes(32)));
  value("witness-prior", encode(crypto.randomBytes(32)));
  file("archive-json", JSON.stringify({ ownerRevision: Number(field("revision").value),
    ownerDigest: field("digest").value, ownerEpoch: Number(field("epoch").value) }));
  field("archive-opt-in").checked = true;
  field("migration-batch-opt-in").checked = true;
  field("account-opt-in").checked = true;
  return {
    document, dialog, downloads, field, file, listeners, window,
    trace,
    setDownloadHook(callback) { onDownload = callback; },
    click(action) { dialog.events.click({
      target: { closest: () => ({ dataset: { zk1Action: action } }) },
    }); },
    async authorizeRestore() {
      this.click("import-approval");
      await tickUntil(() => field("status").textContent.includes("Prova V2/witness"));
      // The UI clears imported private-key files between ceremonies.
      file("private", device.privateKey.export({ type: "pkcs8", format: "der" }));
      file("secret", crypto.randomBytes(32));
      file("bundle", JSON.stringify({ metadata: {} }));
    },
    logout() { listeners.get("rootark:logout")(); },
    restoreCalls() { return restoreCount; },
    waitForRestore: () => tickUntil(() => Boolean(finishRestore)),
    resolveRestore(result) { finishRestore(result); },
    waitForArchive: async () => {
      try { await tickUntil(() => Boolean(finishArchive)); }
      catch (error) { throw new Error(error.message + ": " + field("status").textContent
        + "; trace=" + trace.join(",")); }
    },
    resolveArchive(result) { finishArchive(result); },
    batchCalls: () => batchCalls,
    waitForBatch: () => tickUntil(() => Boolean(finishBatch)),
    resolveBatch(result) { finishBatch(result); },
    accountCreateCalls: () => accountCreateCalls,
    accountRecoverCalls: () => accountRecoverCalls,
    waitForAccountCreate: () => tickUntil(() => Boolean(finishAccountCreate)),
    waitForAccountRecover: async () => {
      try { await tickUntil(() => Boolean(finishAccountRecover)); }
      catch (e) { throw Error(e.message + ": " + field("status").textContent + " trace=" + trace); }
    },
    resolveAccountCreate(result) { finishAccountCreate(result); },
    resolveAccountRecover(result) { finishAccountRecover(result); },
    denied: () => tickUntil(() => field("status").textContent.includes("Operação recusada")),
  };
}

test("logout while signed restore is awaiting plaintext denies download and wipes output", async () => {
  const page = await harness();
  await page.authorizeRestore();
  page.click("restore");
  await page.waitForRestore();
  page.logout();
  assert.equal(page.dialog.open, false);
  const data = Uint8Array.of(91, 92, 93);
  page.resolveRestore({ name: "private.txt", mediaType: "text/plain", data });
  await page.denied();
  assert.equal(page.downloads.length, 0);
  assert.deepEqual([...data], [0, 0, 0]);
});

test("restoration without a separately witnessed and branded new-device approval never starts protected GET", async () => {
  const page = await harness();
  page.click("restore");
  await page.denied();
  assert.equal(page.restoreCalls(), 0);
  assert.equal(page.downloads.length, 0);
});

test("session change in another tab blocks resumed plaintext download", async () => {
  const page = await harness();
  await page.authorizeRestore();
  page.click("restore");
  await page.waitForRestore();
  page.document.cookie = "rootark_csrf=second-user";
  const data = Uint8Array.of(11, 12);
  page.resolveRestore({ name: "private.txt", mediaType: "text/plain", data });
  await page.denied();
  assert.equal(page.downloads.length, 0);
  assert.deepEqual([...data], [0, 0]);
});

test("logout during first archive download prevents remaining releases and wipes all files", async () => {
  const page = await harness();
  page.click("archive-recover");
  await page.waitForArchive();
  page.setDownloadHook(() => page.logout());
  const first = Uint8Array.of(1, 2);
  const second = Uint8Array.of(3, 4);
  page.resolveArchive({
    files: [{ name: "one.txt", data: first }, { name: "two.txt", data: second }],
    signedManifestVerified: true, independentArchiveHashMatched: true,
    allOwnerSignedRootsVerified: true, activeSignedGrantAtPinnedHeadVerified: true,
  });
  await page.denied();
  assert.deepEqual(page.downloads.map((item) => item.name), ["one.txt"]);
  assert.deepEqual([...first], [0, 0]);
  assert.deepEqual([...second], [0, 0]);
});

test("logout while a selected owner key file is being read stops before restore", async () => {
  const page = await harness();
  const ownerFile = page.field("owner").files[0];
  let completeFile;
  ownerFile.arrayBuffer = () => new Promise((resolve) => { completeFile = resolve; });
  page.click("restore");
  await tickUntil(() => Boolean(completeFile));
  page.logout();
  completeFile(Uint8Array.of(...Array(32).fill(1)).buffer);
  await page.denied();
  assert.equal(page.restoreCalls(), 0);
  assert.equal(page.downloads.length, 0);
});

function configureBatch(page, count = 2) {
  const pin = { version: 1, storedAs: "legacy.txt", uploadedAt: "2026-01-01T00:00:00Z",
    size: 3, lastModified: "Thu, 01 Jan 2026 00:00:00 GMT",
    sha256: encode(crypto.randomBytes(32)), mediaType: "text/plain" };
  const entries = Array.from({ length: count }, (_item, index) => ({
    legacy: { name: "legacy-" + index + ".txt", folderId: "" },
    sourcePin: { ...pin, version: index + 1 }, cekFile: "cek-" + index + ".bin",
  }));
  const keyFile = (index) => ({ name: "cek-" + index + ".bin", size: 32,
    arrayBuffer: async () => Uint8Array.from(crypto.randomBytes(32)).buffer });
  page.field("migration-batch-ceks").files = entries.map((_item, index) => keyFile(index));
  page.file("migration-batch-descriptors", JSON.stringify({
    schema: "rootark-zk1-legacy-version-batch/v1", entries,
  }));
  page.file("migration-batch-secret", crypto.randomBytes(32));
  return entries;
}

function batchReport(count = 2, verified = count) {
  return { total: count, verified, canDeleteLegacy: false, authorizesCutover: false,
    results: Array.from({ length: count }, (_item, index) => ({
      objectId: encode(crypto.randomBytes(16)), versionId: encode(crypto.randomBytes(16)),
      legacyVersion: index + 1, phase: index < verified
        ? "awaiting-independent-owner-checkpoint" : "needs-manual-review",
      verifiedLocalReadback: index < verified, requiresOwnerCheckpoint: true,
      canDeleteLegacy: false, authorizesCutover: false,
    })) };
}

test("batch imports 2 distinct non-extractable CEKs and downloads partial report without cutover", async () => {
  const page = await harness();
  configureBatch(page);
  page.click("migration-batch");
  await page.waitForBatch();
  assert.equal(page.window.batchInput.entries.length, 2);
  assert.equal(page.window.batchInput.migrationSecret.length, 32);
  assert.equal(page.window.batchInput.entries[0].cek.extractable, false);
  assert.equal(page.window.batchInput.entries[1].cek.extractable, false);
  assert.notEqual(page.window.batchInput.entries[0].cek, page.window.batchInput.entries[1].cek);
  page.resolveBatch(batchReport(2, 1));
  await tickUntil(() => page.downloads.length === 1);
  await tickUntil(() => page.field("status").textContent.includes("Versões conferidas"));
  assert.equal(page.downloads[0].name, "rootark-legacy-version-batch-report.json");
  const report = JSON.parse(await page.downloads[0].blob.text());
  assert.equal(report.verified, 1);
  assert.equal(report.results[1].phase, "needs-manual-review");
  assert.equal(report.canDeleteLegacy, false);
  assert.equal(report.authorizesCutover, false);
  assert.equal(report.productionAuthorized, false);
  assert.equal(page.field("migration-batch-ceks").files.length, 0);
  assert.equal(page.field("migration-batch-secret").files.length, 0);
});

test("logout mid-batch suppresses all report downloads", async () => {
  const page = await harness();
  configureBatch(page);
  page.click("migration-batch");
  await page.waitForBatch();
  page.logout();
  page.resolveBatch(batchReport());
  await page.denied();
  assert.equal(page.downloads.length, 0);
});

test("session cookie swap mid-batch suppresses report downloads", async () => {
  const page = await harness();
  configureBatch(page);
  page.click("migration-batch");
  await page.waitForBatch();
  page.document.cookie = "rootark_csrf=second-session";
  page.resolveBatch(batchReport());
  await page.denied();
  assert.equal(page.downloads.length, 0);
});

test("missing user selected version metadata or CEK refuses before batch I/O", async () => {
  const page = await harness();
  const entries = configureBatch(page);
  delete entries[0].sourcePin.sha256;
  page.file("migration-batch-descriptors", JSON.stringify({
    schema: "rootark-zk1-legacy-version-batch/v1", entries,
  }));
  page.click("migration-batch");
  await page.denied();
  assert.equal(page.batchCalls(), 0);
  assert.equal(page.downloads.length, 0);
});

test("forged offline owner SPKI pin refuses before any batch operation", async () => {
  const page = await harness();
  configureBatch(page);
  page.field("owner-spki").value = encode(crypto.randomBytes(32));
  page.click("migration-batch");
  await page.denied();
  assert.equal(page.batchCalls(), 0);
  assert.equal(page.downloads.length, 0);
});

async function configureAccount(page, create = false) {
  const originalGrant = JSON.parse(Buffer.from(
    await page.field("grant").files[0].arrayBuffer()).toString());
  const accountId = originalGrant.account_id;
  const deviceRaw = Buffer.from(await page.field("device").files[0].arrayBuffer());
  const signer = encode(crypto.randomBytes(16));
  const descriptor = { schema: "rootark-zk1-account-workspace-selection/v1",
    accountId, keyrings: Array.from({ length: 2 }, (_unused, index) => ({
      scope: { account_id: accountId, compartment_id: encode(Buffer.from([index + 1])),
        keyring_id: encode(crypto.randomBytes(16)) },
      pinnedCurrentHead: { revision: index + 1,
        digest: encode(crypto.randomBytes(32)), epoch: index + 1 },
      signedDeviceGrant: { revoked_at_epoch: null, device_id: "owner-device",
        authorization_public_key: encode(deviceRaw) },
      ownerHistory: [{ sequence: 1, signer_key_id: signer }],
      signerKeyId: signer, deviceId: "owner-device",
      holderSecretFile: "holder-" + index + ".bin",
      files: create ? ["file-" + index + ".txt"] : [],
    })) };
  for (const ring of descriptor.keyrings) Object.assign(ring.signedDeviceGrant, ring.scope);
  const keyedFile = (name, bytes, type = "application/octet-stream") => ({
    name, type, size: bytes.length,
    arrayBuffer: async () => Uint8Array.from(bytes).buffer,
  });
  const secretData = [crypto.randomBytes(32), crypto.randomBytes(32)];
  page.field("account-holder-files").files = secretData.map((b, i) => keyedFile("holder-" + i + ".bin", b));
  page.field("account-local-files").files = create
    ? [keyedFile("file-0.txt", Buffer.from("local A"), "text/plain"),
      keyedFile("file-1.txt", Buffer.from("local B"), "text/plain")] : [];
  page.file("account-descriptors", JSON.stringify(descriptor));
  page.file("account-archive", JSON.stringify({ keyrings: descriptor.keyrings.map((item) => ({
    scope: item.scope, ownerRevision: item.pinnedCurrentHead.revision,
    ownerDigest: item.pinnedCurrentHead.digest, ownerEpoch: item.pinnedCurrentHead.epoch,
    archiveSha256: encode(crypto.randomBytes(32)),
  })).sort((a, b) => {
    const left = a.scope.compartment_id + ":" + a.scope.keyring_id;
    const right = b.scope.compartment_id + ":" + b.scope.keyring_id;
    return left < right ? -1 : left > right ? 1 : 0;
  }) }));
  page.field("account-sha").value = encode(crypto.randomBytes(32));
  return descriptor;
}

test("account create imports two separate holder secrets, signs selected files and wipes inputs", async () => {
  const page = await harness();
  await configureAccount(page, true);
  page.click("account-create");
  await page.waitForAccountCreate();
  const input = page.window.accountCreateInput;
  assert.equal(input.keyrings.length, 2);
  assert.equal(input.keyrings[0].files.length, 1);
  assert.equal(input.keyrings[1].files.length, 1);
  assert.notDeepEqual([...input.keyrings[0].recoverySecret], [...input.keyrings[1].recoverySecret]);
  assert.equal(input.ownerSigningKey.extractable, false);
  page.resolveAccountCreate({ archive: { accountId: input.accountId,
    keyrings: [{}, {}] }, archiveSha256: crypto.randomBytes(32),
  authorizesProductionRestore: false });
  await tickUntil(() => page.downloads.length === 2);
  assert.deepEqual(page.downloads.map((file) => file.name), [
    "rootark-account-archive.json", "rootark-account-archive.sha256.txt"]);
  await tickUntil(() => page.field("account-local-files").files.length === 0);
  for (const ring of input.keyrings) {
    assert.deepEqual([...ring.recoverySecret], Array(32).fill(0));
    assert.deepEqual([...ring.files[0].data], Array(ring.files[0].data.length).fill(0));
  }
});

test("account recovery releases all verified keyrings locally and wipes every plaintext", async () => {
  const page = await harness();
  await configureAccount(page);
  page.click("account-recover");
  await page.waitForAccountRecover();
  const input = page.window.accountRecoverInput;
  const first = Uint8Array.of(1, 2), second = Uint8Array.of(3, 4);
  page.resolveAccountRecover({ keyrings: [
    { scope: input.keyrings[0].scope, files: [{ name: "alpha.txt", data: first }] },
    { scope: input.keyrings[1].scope, files: [{ name: "beta.txt", data: second }] },
  ], allKeyringsVerified: true, aggregateSignatureVerified: true,
  aggregateIndependentPinMatched: true, authorizesProductionRestore: false });
  await tickUntil(() => page.downloads.length === 2);
  await tickUntil(() => page.field("account-holder-files").files.length === 0);
  assert.match(page.downloads[0].name, /keyring-.*alpha\.txt/);
  assert.match(page.downloads[1].name, /keyring-.*beta\.txt/);
  assert.deepEqual([...first], [0, 0]);
  assert.deepEqual([...second], [0, 0]);
});

test("account recovery aborts all downloads when second keyring has unsafe name", async () => {
  const page = await harness();
  await configureAccount(page);
  page.click("account-recover");
  await page.waitForAccountRecover();
  const input = page.window.accountRecoverInput;
  const first = Uint8Array.of(6), second = Uint8Array.of(7);
  page.resolveAccountRecover({ keyrings: [
    { scope: input.keyrings[0].scope, files: [{ name: "safe.txt", data: first }] },
    { scope: input.keyrings[1].scope, files: [{ name: "../escape.txt", data: second }] },
  ], allKeyringsVerified: true, aggregateSignatureVerified: true,
  aggregateIndependentPinMatched: true, authorizesProductionRestore: false });
  await page.denied();
  assert.equal(page.downloads.length, 0);
  assert.deepEqual([...first], [0]);
  assert.deepEqual([...second], [0]);
});

for (const mode of ["logout", "session-swap"]) test("account recovery " + mode
  + " during pending verification denies local release and wipes plaintext", async () => {
  const page = await harness();
  await configureAccount(page);
  page.click("account-recover");
  await page.waitForAccountRecover();
  if (mode === "logout") page.logout();
  else page.document.cookie = "rootark_csrf=another-user";
  const input = page.window.accountRecoverInput;
  const first = Uint8Array.of(1), second = Uint8Array.of(2);
  page.resolveAccountRecover({ keyrings: [
    { scope: input.keyrings[0].scope, files: [{ name: "one.txt", data: first }] },
    { scope: input.keyrings[1].scope, files: [{ name: "two.txt", data: second }] },
  ], allKeyringsVerified: true, aggregateSignatureVerified: true,
  aggregateIndependentPinMatched: true, authorizesProductionRestore: false });
  await page.denied();
  assert.equal(page.downloads.length, 0);
  assert.deepEqual([...first], [0]);
  assert.deepEqual([...second], [0]);
});

test("account missing pinned head or forged owner SPKI denies before archive module", async () => {
  const page = await harness();
  const manifest = await configureAccount(page);
  delete manifest.keyrings[1].pinnedCurrentHead.digest;
  page.file("account-descriptors", JSON.stringify(manifest));
  page.click("account-recover");
  await page.denied();
  assert.equal(page.accountRecoverCalls(), 0);
  const other = await harness();
  await configureAccount(other);
  other.field("owner-spki").value = encode(crypto.randomBytes(32));
  other.click("account-recover");
  await other.denied();
  assert.equal(other.accountRecoverCalls(), 0);
});

test("UI explicitly disclaims complete signed inventory for keyring and account selection", () => {
  assert.match(source, /não comprova inventário completo do keyring/);
  assert.match(source, /não comprova inventário completo da conta/);
  assert.doesNotMatch(source, /<legend>Arquivo completo de keyring/);
});

async function historicKeyring(page) {
  const grant = JSON.parse(Buffer.from(await page.field("grant").files[0].arrayBuffer()).toString());
  grant.device_id = "fixture-owner";
  grant.authorization_public_key = encode(Buffer.from(
    await page.field("device").files[0].arrayBuffer()));
  page.file("grant", JSON.stringify(grant));
  const signer = page.field("owner-signer").value;
  const scope = { account_id: grant.account_id, compartment_id: grant.compartment_id,
    keyring_id: grant.keyring_id };
  const first = { sequence: 1, signer_key_id: signer, device_id: "fixture-owner",
    revision: 1, manifest_digest: encode(crypto.randomBytes(32)) };
  const currentDigest = page.field("digest").value;
  const last = { sequence: 2, signer_key_id: signer, device_id: "fixture-owner",
    revision: 2, manifest_digest: currentDigest };
  page.field("revision").value = "2";
  page.field("epoch").value = "2";
  const chain = [first, last];
  page.file("history", JSON.stringify(chain));
  const roots = [{ object_id: encode(crypto.randomBytes(16)),
    ciphertext_root: encode(crypto.randomBytes(32)) }];
  const historic = { signedOwnerHistoryChain: chain,
    currentSignedDeviceGrant: grant, currentOwnerRootCheckpoints: roots };
  const selected = { schema: "rootark-zk1-keyring-history-endorsement/v1",
    scope, historicalRecovery: historic };
  page.file("archive-historical-proof", JSON.stringify(selected));
  page.file("archive-json", JSON.stringify({ ownerRevision: 1,
    ownerDigest: first.manifest_digest, ownerEpoch: 1 }));
  page.field("archive-historical-opt-in").checked = true;
  return { grant, chain, roots, selected };
}

test("historical keyring opts in with fully branded current chain and current grant", async () => {
  const page = await harness();
  const f = await historicKeyring(page);
  page.click("archive-recover");
  await page.waitForArchive();
  const input = page.window.archiveRecoverInput;
  assert.equal(typeof input.historicalRecovery.devicePoP.signature, "string");
  assert.equal(input.historicalRecovery.devicePoP.challenge, page.window.lastChallenge);
  assert.equal(page.trace.filter((step) => step === "historic-issue-device-pop").length, 1);
  assert.equal(page.trace.filter((step) => step === "history").length >= 4, true);
  assert.equal(page.trace.includes("assertCurrent"), true);
  assert.equal(page.downloads.length, 0);
  page.resolveArchive({ files: [{ name: "historical.txt", data: Uint8Array.of(7, 8) }],
    signedManifestVerified: true, independentArchiveHashMatched: true,
    allOwnerSignedRootsVerified: true, activeSignedGrantAtPinnedHeadVerified: true,
    historicalOwnerContinuityVerified: true, currentSignedGrantAtPinnedHeadVerified: true });
  await tickUntil(() => page.downloads.length === 1);
  assert.equal(page.downloads[0].name, "historical.txt");
});

test("historical keyring denies incorrect device private key and never calls recovery module", async () => {
  const page = await harness();
  await historicKeyring(page);
  const other = crypto.generateKeyPairSync("ed25519");
  page.file("private", other.privateKey.export({ type: "pkcs8", format: "der" }));
  page.click("archive-recover");
  await page.denied();
  assert.equal(page.trace.includes("recoverArchive"), false);
  assert.equal(page.downloads.length, 0);
});

test("historical keyring refuses user-supplied devicePoP in offline JSON", async () => {
  const page = await harness();
  const value = await historicKeyring(page);
  value.selected.historicalRecovery.devicePoP = { challenge: "fake", signature: "fake" };
  page.file("archive-historical-proof", JSON.stringify(value.selected));
  page.click("archive-recover");
  await page.denied();
  assert.equal(page.trace.includes("historic-issue-device-pop"), false);
  assert.equal(page.downloads.length, 0);
});

for (const mode of ["no-opt-in", "incomplete-chain", "missing-root", "revoked",
  "cross-owner", "wrong-head", "csrf", "logout"]) test("historical keyring refuses " + mode,
  async () => {
    const page = await harness();
    const f = await historicKeyring(page);
    if (mode === "no-opt-in") page.field("archive-historical-opt-in").checked = false;
    if (mode === "incomplete-chain") f.selected.historicalRecovery.signedOwnerHistoryChain = [f.chain[1]];
    if (mode === "missing-root") f.selected.historicalRecovery.currentOwnerRootCheckpoints = [];
    if (mode === "revoked") {
      f.selected.historicalRecovery.currentSignedDeviceGrant =
        { ...f.grant, revoked_at_epoch: 2 };
    }
    if (mode === "cross-owner") f.selected.scope.keyring_id = encode(crypto.randomBytes(16));
    if (mode === "wrong-head") f.selected.historicalRecovery.signedOwnerHistoryChain[1]
      = { ...f.chain[1], manifest_digest: encode(crypto.randomBytes(32)) };
    page.file("archive-historical-proof", JSON.stringify(f.selected));
    page.click("archive-recover");
    if (mode === "csrf" || mode === "logout") {
      await page.waitForArchive();
      if (mode === "csrf") page.document.cookie = "rootark_csrf=switched";
      else page.logout();
      const recovered = Uint8Array.of(5);
      page.resolveArchive({ files: [{ name: "safe.txt", data: recovered }],
        signedManifestVerified: true, independentArchiveHashMatched: true,
        allOwnerSignedRootsVerified: true, activeSignedGrantAtPinnedHeadVerified: true,
        historicalOwnerContinuityVerified: true, currentSignedGrantAtPinnedHeadVerified: true });
      await page.denied();
      assert.deepEqual([...recovered], [0]);
    } else await page.denied();
    assert.equal(page.downloads.length, 0);
  });

async function historicAccount(page) {
  const manifest = await configureAccount(page);
  const old = { ...manifest.keyrings[1].pinnedCurrentHead };
  const freshDigest = encode(crypto.randomBytes(32));
  const ring = manifest.keyrings[1];
  ring.pinnedCurrentHead.revision++;
  ring.pinnedCurrentHead.epoch++;
  ring.pinnedCurrentHead.digest = freshDigest;
  ring.ownerHistory[0].device_id = "owner-device";
  ring.ownerHistory[0].revision = old.revision;
  ring.ownerHistory[0].manifest_digest = old.digest;
  ring.ownerHistory.push({ ...ring.ownerHistory[0], sequence: 2,
    revision: ring.pinnedCurrentHead.revision, manifest_digest: freshDigest });
  ring.currentOwnerRootCheckpoints = [{ object_id: encode(crypto.randomBytes(16)),
    ciphertext_root: encode(crypto.randomBytes(32)) }];
  ring.devicePrivateFile = "historical-device-1.pk8";
  const privateDer = Buffer.from(await page.field("private").files[0].arrayBuffer());
  page.field("account-historical-device-privates").files = [{
    name: ring.devicePrivateFile, size: privateDer.byteLength,
    arrayBuffer: async () => Uint8Array.from(privateDer).buffer,
  }];
  page.file("account-descriptors", JSON.stringify(manifest));
  page.field("account-historical-opt-in").checked = true;
  return manifest;
}

test("account historical recovery passes per-keyring independent current authority, no silent fallback", async () => {
  const page = await harness();
  await historicAccount(page);
  page.click("account-recover");
  await page.waitForAccountRecover();
  const keys = page.window.accountRecoverInput.keyrings;
  assert.equal(keys.length, 2);
  assert.equal(Object.hasOwn(keys[0], "historicalRecovery"), false);
  assert.equal(Object.hasOwn(keys[1], "historicalRecovery"), true);
  assert.equal(keys[1].previousOwnerHistoryProof, null);
  assert.equal(keys[1].historicalRecovery.currentOwnerRootCheckpoints.length, 1);
  assert.equal(typeof keys[1].historicalRecovery.devicePoP.signature, "string");
  assert.equal(keys[1].historicalRecovery.devicePoP.challenge, page.window.lastChallenge);
  page.resolveAccountRecover({ keyrings: keys.map((value, i) => ({
    scope: value.scope, files: [{ name: "version-" + i + ".txt", data: Uint8Array.of(i + 1) }],
  })), allKeyringsVerified: true, aggregateSignatureVerified: true,
  aggregateIndependentPinMatched: true, authorizesProductionRestore: false });
  await tickUntil(() => page.downloads.length === 2);
});

test("account historical recovery denies wrong grant device private key before archive I/O", async () => {
  const page = await harness();
  await historicAccount(page);
  const other = crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "der" });
  page.field("account-historical-device-privates").files = [{ name: "historical-device-1.pk8",
    size: other.length, arrayBuffer: async () => Uint8Array.from(other).buffer }];
  page.click("account-recover");
  await page.denied();
  assert.equal(page.accountRecoverCalls(), 0);
  assert.equal(page.downloads.length, 0);
});

test("account historical recovery refuses missing selected current device private file", async () => {
  const page = await harness();
  await historicAccount(page);
  page.field("account-historical-device-privates").files = [];
  page.click("account-recover");
  await page.denied();
  assert.equal(page.accountRecoverCalls(), 0);
  assert.equal(page.downloads.length, 0);
});

for (const mode of ["no-opt-in", "missing-roots", "revoked", "cross-scope",
  "broken-history", "csrf", "logout"]) test("account historical recovery refuses " + mode,
  async () => {
    const page = await harness();
    const manifest = await historicAccount(page);
    const ring = manifest.keyrings[1];
    if (mode === "no-opt-in") page.field("account-historical-opt-in").checked = false;
    if (mode === "missing-roots") ring.currentOwnerRootCheckpoints = [];
    if (mode === "revoked") ring.signedDeviceGrant.revoked_at_epoch = 3;
    if (mode === "cross-scope") ring.signedDeviceGrant.keyring_id = encode(crypto.randomBytes(16));
    if (mode === "broken-history") ring.ownerHistory = [ring.ownerHistory[1]];
    page.file("account-descriptors", JSON.stringify(manifest));
    page.click("account-recover");
    if (mode === "csrf" || mode === "logout") {
      await page.waitForAccountRecover();
      if (mode === "csrf") page.document.cookie = "rootark_csrf=swapped";
      else page.logout();
      const input = page.window.accountRecoverInput.keyrings;
      const files = input.map((v) => ({ scope: v.scope,
        files: [{ name: "ok.txt", data: Uint8Array.of(1) }] }));
      page.resolveAccountRecover({ keyrings: files, allKeyringsVerified: true,
        aggregateSignatureVerified: true, aggregateIndependentPinMatched: true,
        authorizesProductionRestore: false });
      await page.denied();
      assert.equal(files.every((v) => v.files[0].data[0] === 0), true);
    } else await page.denied();
    assert.equal(page.downloads.length, 0);
  });
