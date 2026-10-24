"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const CODE = fs.readFileSync(path.join(__dirname,
  "../public/client/rootark-dev-vault-ui.js"), "utf8");
const KEY_ID = "A".repeat(43);

function makeNode(id) {
  return {
    id, value: "", textContent: "", type: "password", files: [], listeners: {},
    children: [],
    addEventListener(event, callback) { this.listeners[event] = callback; },
    replaceChildren() { this.children = []; },
    append(...children) { this.children.push(...children); },
    remove() {},
    click() { this.listeners.click?.(); },
  };
}
function harness({ objects = [], decryptFile, uploadCase = null, legacyCase = null } = {}) {
  const elements = new Map();
  let downloads = 0;
  let submitted = null;
  let legacyReads = 0;
  const legacySource = new Uint8Array([12, 34, 56]);
  const getNode = (id) => {
    if (!elements.has(id)) elements.set(id, makeNode(id));
    return elements.get(id);
  };
  const document = {
    body: makeNode("body"),
    getElementById: getNode,
    createElement: (tag) => makeNode(tag),
  };
  const pending = { openEmergencyPackage: async () => KEY_ID };
  const api = {
    get: async (url) => {
      if (url.endsWith("/session")) return { username: "alice", activeKeyId: null };
      if (url.endsWith("/objects")) return { objects };
      if (url.includes("/objects/")) {
        if (uploadCase && submitted) return { id: submitted.id, keyId: KEY_ID,
          revision: 1, envelope: submitted.envelope };
        return { id: objects[0].id, keyId: KEY_ID, envelope: {} };
      }
      throw new Error("Unexpected API read " + url);
    },
    post: async (_url, body) => {
      if (!uploadCase) throw new Error("No upload expected");
      submitted = body;
      return { id: body.id, revision: 1 };
    },
    delete: async () => { throw new Error("No delete expected"); },
  };
  const fileCrypto = {
    MAX_PLAINTEXT_BYTES: 4 * 1024 * 1024,
    keyCommitment: async () => KEY_ID,
    importRecoveryKey: async () => ({ type: "secret", extractable: false }),
    decryptFile: decryptFile || (async () => ({
      name: "synthetic.txt", mediaType: "text/plain", data: new Uint8Array([1]),
    })),
    encryptFile: async () => ({ format: "test", algorithm: "test", iv: "abc", ciphertext: "abc" }),
    verifyStoredCopy: async () => {
      if (uploadCase?.verificationFails) throw new Error("readback tampered");
      return true;
    },
    canSaveDeviceKey: () => true,
  };
  const sandbox = {
    window: {
      RootarkApi: api, RootarkDevVaultCrypto: fileCrypto,
      RootarkDevVaultMigration: {
        readLegacyPlaintext: async ({ name, folderId }) => {
          if (!legacyCase) throw new Error("Unexpected legacy copy");
          legacyReads += 1;
          assert.equal(name, "original.txt");
          assert.equal(folderId, "root");
          return { name, mediaType: "text/plain", data: legacySource };
        },
      },
      RootarkDevVaultEmergency: pending, crypto: crypto.webcrypto,
    },
    document, crypto: crypto.webcrypto,
    URL: { createObjectURL() { downloads += 1; return "blob:synthetic"; },
      revokeObjectURL() {} },
    Blob, setTimeout: () => 0, confirm: () => true, btoa, atob,
  };
  vm.createContext(sandbox);
  vm.runInContext(CODE.replace(
    "try { await operation(); } catch (error) { report(error); }",
    "try { await operation(); } catch (error) { window.__testError = String(error?.stack || error); report(error); }",
  ), sandbox);
  return { node: getNode, pending, api, fileCrypto,
    uploaded: () => submitted,
    lastError: () => sandbox.window.__testError,
    legacyReads: () => legacyReads,
    legacySource,
    downloads: () => downloads };
}
const settle = async () => {
  for (let i = 0; i < 20; i += 1) await Promise.resolve();
};

test("locking during emergency restore clears secrets and cannot re-unlock", async () => {
  const h = harness();
  await settle();
  let complete;
  h.pending.openEmergencyPackage = () => new Promise((resolve) => { complete = resolve; });
  h.node("emergency-password").value = "synthetic recovery password";
  h.node("emergency-recovery-key").value = "raw-secret";
  h.node("emergency-file").files = [{
    size: 120, text: async () => '{"format":"synthetic"}',
  }];
  h.node("emergency-import").click();
  await settle();
  assert.equal(typeof complete, "function", "emergency recovery must be in flight");
  h.node("lock").click();
  assert.equal(h.node("emergency-password").value, "");
  assert.equal(h.node("emergency-recovery-key").value, "");
  assert.equal(h.node("emergency-file").value, "");
  complete(KEY_ID);
  await settle();
  assert.match(h.node("status").textContent, /Chave apagada da sessão/);
  assert.doesNotMatch(h.node("status").textContent, /Chave restaurada/);
});

test("locking during a pending decrypt prevents any plaintext download", async () => {
  let finishDecrypt;
  const id = "Z".repeat(22);
  const h = harness({
    objects: [{ id, revision: 1 }],
    decryptFile: () => new Promise((resolve) => { finishDecrypt = resolve; }),
  });
  await settle();
  h.node("recovery").value = KEY_ID;
  h.node("import").click();
  await settle();
  assert.equal(h.node("recovery").value, "",
    "test harness must consume the raw recovery secret before attempting download");
  await new Promise((resolve) => setImmediate(resolve));
  const li = h.node("objects").children[0];
  const actions = li.children[1];
  const openButton = actions.children[0];
  openButton.click();
  await settle();
  assert.equal(typeof finishDecrypt, "function",
    "decrypt operation must be in flight; current status: " + h.node("status").textContent);
  h.node("lock").click();
  finishDecrypt({ name: "private.txt", mediaType: "text/plain", data: new Uint8Array([12]) });
  await settle();
  assert.equal(h.downloads(), 0, "no plaintext may leave the browser after explicit lock");
});

test("upload never reports migrated encrypted copy as confirmed until remote read-back verifies", async () => {
  const h = harness({ uploadCase: { verificationFails: true } });
  await settle();
  h.node("recovery").value = KEY_ID;
  h.node("import").click();
  await new Promise((resolve) => setImmediate(resolve));
  const picker = h.node("file");
  picker.value = "legacy.txt";
  picker.files = [{ size: 3, name: "legacy.txt", type: "text/plain",
    arrayBuffer: async () => Uint8Array.from([1, 2, 3]).buffer }];
  h.node("upload").click();
  await settle();
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(h.uploaded(), "the test must actually submit ciphertext before read-back");
  assert.match(h.node("status").textContent, /NÃO passou na verificação/);
  assert.equal(picker.value, "legacy.txt", "original selection must be retained on failed verification");
  assert.doesNotMatch(h.node("status").textContent, /Cópia cifrada confirmada/);
});

test("upload only confirms copy after separate read-back accepts the exact file", async () => {
  const h = harness({ uploadCase: { verificationFails: false } });
  await settle();
  h.node("recovery").value = KEY_ID;
  h.node("import").click();
  await new Promise((resolve) => setImmediate(resolve));
  h.node("file").value = "legacy.txt";
  h.node("file").files = [{ size: 3, name: "legacy.txt", type: "text/plain",
    arrayBuffer: async () => Uint8Array.from([1, 2, 3]).buffer }];
  h.node("upload").click();
  await settle();
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(h.uploaded());
  assert.equal(h.node("file").value, "");
  assert.match(h.node("status").textContent, /Cópia cifrada confirmada/);
});

test("explicit legacy copy uses the existing readable source but only sends encrypted envelope to the new API", async () => {
  const h = harness({ uploadCase: { verificationFails: false }, legacyCase: true });
  await settle();
  h.node("recovery").value = KEY_ID;
  h.node("import").click();
  await new Promise((resolve) => setImmediate(resolve));
  h.node("legacy-name").value = "original.txt";
  h.node("legacy-folder").value = "root";
  h.node("legacy-copy").click();
  await settle();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.legacyReads(), 1);
  assert.ok(h.uploaded(), "copy must upload an encrypted envelope");
  assert.deepEqual(Object.keys(h.uploaded()).sort(), ["account", "envelope", "id", "keyId"]);
  assert.match(h.node("status").textContent, /ORIGINAL continua intacto/,
    h.lastError());
  assert.deepEqual(h.legacySource, new Uint8Array([0, 0, 0]),
    "temporary plaintext bytes must be scrubbed after verified copy");
});
