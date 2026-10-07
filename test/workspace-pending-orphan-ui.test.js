"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

test("restore-orphan pending uploads show recovery state, block approval, and allow rejection", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-workspace.js"), "utf8");
  const pending = [
    { name: "ordinary.txt", folderId: "root", owner: "tester", size: 10 },
    { name: "restored.txt", folderId: "root", owner: "tester", size: 20, restoreOrphan: true, availability: "recovery_required" },
  ];
  let rendered = "";
  let liveToast = "";
  const listeners = new Map();
  const toasts = [];
  const root = { addEventListener(name, listener) { listeners.set(name, listener); }, contains: () => true };
  const context = {
    document: {
      forms: [],
      addEventListener() {},
      getElementById: (id) => id === "app-root" ? root : null,
    },
    Event: function Event() {},
    window: {
      addEventListener() {},
      dispatchEvent() {},
      location: { hash: "", protocol: "http:", host: "rootark.test" },
      RootarkApi: {
        query: (pathname) => pathname,
        get: async (pathname) => pathname === "/folders" ? [{ id: "root", name: "Arquivos", isRoot: true }] : pathname === "/list" ? [] : pathname === "/pending" ? pending : [],
        post: async (pathname) => pathname.startsWith("/approve/") ? { cloudSyncPending: true, cloudCleanupPending: true, trashCancellationPending: true } : ({}),
      },
      RootarkUI: {
        escape: (value) => String(value || ""),
        formatBytes: (value) => `${value} B`,
        formatDate: () => "",
        getSession: async () => ({ username: "tester", role: "admin", permissions: { listFiles: true, listPending: true, approve: true } }),
        mount: ({ content }) => { rendered = content; liveToast = ""; },
        dialog: async () => ({}),
        toast(message, tone) { toasts.push({ message, tone }); liveToast = message; },
        redirectToLogin() {},
      },
    },
  };

  vm.runInNewContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));

  assert.match(rendered, /<strong>restored\.txt<\/strong><span class="badge badge-warning">Recuperação necessária<\/span>/);
  assert.match(rendered, /Arquivo original indisponível\. Solicite um novo envio\./);
  assert.match(rendered, /<button type="button" class="button button-primary button-small" disabled>Aprovação indisponível<\/button>/);
  assert.match(rendered, /data-action="reject-file" data-name="restored\.txt"/);
  assert.match(rendered, /data-action="approve-file" data-name="ordinary\.txt"/);
  assert.doesNotMatch(rendered, /data-action="approve-file" data-name="restored\.txt"/);
  assert.doesNotMatch(rendered, /data-action="preview-pending" data-name="restored\.txt"/);

  const approveButton = { dataset: { action: "approve-file", name: "ordinary.txt", folder: "root" } };
  await listeners.get("click")({ target: { closest: () => approveButton } });
  assert.match(toasts.at(-1).message, /sincronização na nuvem/i);
  assert.match(toasts.at(-1).message, /limpeza do envio temporário/i);
  assert.match(toasts.at(-1).message, /cancelamento da exclusão remota anterior/i);
  assert.notEqual(toasts.at(-1).tone, "success", "pending background work must not look fully complete");
  assert.equal(liveToast, toasts.at(-1).message, "approval status remains in the live region after the file list rerenders");
});
