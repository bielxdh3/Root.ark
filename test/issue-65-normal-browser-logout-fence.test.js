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
  let selectedBlob = null;
  const window = {
    RootarkApi: { get: async () => ({ enabled: true }) },
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
      verifyOwnerCheckpoint: async () => { trace.push("history"); return {}; } },
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
    RootarkZk1V2DeviceApproval: { verifyImportedApproval: async () => ({}) },
    RootarkZk1KeyringPortableArchive: {
      createArchive: async () => ({}),
      recoverArchive: () => {
        trace.push("recoverArchive");
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
  file("grant", JSON.stringify({ revoked_at_epoch: null,
    account_id: encode(crypto.randomBytes(16)), compartment_id: "scope",
    keyring_id: encode(crypto.randomBytes(16)) }));
  file("history", JSON.stringify({ sequence: 1, signer_key_id: encode(crypto.randomBytes(16)) }));
  file("device", device.publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  file("private", device.privateKey.export({ type: "pkcs8", format: "der" }));
  file("secret", crypto.randomBytes(32));
  file("bundle", JSON.stringify({ metadata: {} }));
  file("owner-root", "{}");
  file("archive-json", "{}");
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
  field("archive-opt-in").checked = true;
  field("migration-batch-opt-in").checked = true;
  return {
    document, dialog, downloads, field, file, listeners, window,
    trace,
    setDownloadHook(callback) { onDownload = callback; },
    click(action) { dialog.events.click({
      target: { closest: () => ({ dataset: { zk1Action: action } }) },
    }); },
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
    denied: () => tickUntil(() => field("status").textContent.includes("Operação recusada")),
  };
}

test("logout while signed restore is awaiting plaintext denies download and wipes output", async () => {
  const page = await harness();
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

test("session change in another tab blocks resumed plaintext download", async () => {
  const page = await harness();
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
