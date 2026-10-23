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
  const window = {
    RootarkApi: { get: async () => ({ enabled: true }) },
    isSecureContext: true, crypto: crypto.webcrypto,
    RootarkZk1NormalBrowserTrustFloor: {
      provisionOffline: async () => ({}),
      assertCurrent: async () => { trace.push("assertCurrent"); return {}; } },
    RootarkZk1OwnerSignedCheckpoint: {
      verifyOwnerCheckpoint: async () => { trace.push("history"); return {}; } },
    RootarkZk1NormalBrowserContent: { uploadAndVerify: async () => ({}) },
    RootarkZk1LegacyMigrationWorkflow: { openMigrationJournal: async () => ({}) },
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
      if (!controls.has(name))
        controls.set(name, { files: [], value: "", checked: false, textContent: "" });
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
          downloads.push({ name: this.download, dialogOpen: dialog.open });
          onDownload?.();
        },
        remove() {},
      };
      throw new Error("UNEXPECTED_ELEMENT_" + kind);
    },
    head: { append(script) { script.onload?.(); } },
    body: { append() {} },
  };
  const url = { createObjectURL: () => "blob:fixture",
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
  file("grant", JSON.stringify({ revoked_at_epoch: null }));
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
  return {
    document, dialog, downloads, field, file, listeners,
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
