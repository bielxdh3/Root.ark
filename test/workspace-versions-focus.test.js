"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

test("closing the inline versions panel returns focus to its file action", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-workspace.js"), "utf8");
  const rootListeners = new Map();
  let activeElement = null;
  let versionButton;
  let closeButton;
  const makeButton = (action, name, folder) => ({
    isConnected: true,
    dataset: { action, name, folder },
    focus() { activeElement = this; },
  });
  const root = {
    addEventListener(name, listener) { rootListeners.set(name, listener); },
    contains(button) { return button.isConnected; },
    querySelectorAll(selector) { return selector === '[data-action="file-versions"]' && versionButton ? [versionButton] : []; },
  };
  const document = {
    get activeElement() { return activeElement; },
    set activeElement(value) { activeElement = value; },
    forms: [],
    addEventListener() {},
    getElementById(id) { return id === "app-root" ? root : null; },
    querySelector(selector) { return selector === ".versions-panel" ? { scrollIntoView() {} } : null; },
  };
  const context = {
    document,
    Event: function Event() {},
    window: {
      addEventListener() {},
      dispatchEvent() {},
      setTimeout,
      clearTimeout,
      location: { hash: "", protocol: "http:", host: "rootark.test" },
    },
  };
  context.window.RootarkApi = {
    query: (pathname) => pathname,
    get: async (pathname) => pathname === "/folders" ? [{ id: "root", name: "Arquivos", isRoot: true }] : pathname === "/list" ? [{ name: "example.txt", folderId: "root", size: 1 }] : pathname.startsWith("/versions/") ? { fileName: "example.txt", versions: [] } : [],
    post: async () => ({}),
  };
  context.window.RootarkUI = {
    escape: (value) => String(value || ""),
    formatBytes: () => "0 B",
    formatDate: () => "",
    getSession: async () => ({ username: "tester", role: "user", permissions: { listFiles: true } }),
    mount({ content }) {
      if (versionButton) versionButton.isConnected = false;
      if (closeButton) closeButton.isConnected = false;
      versionButton = content.includes('data-action="file-versions"') ? makeButton("file-versions", "example.txt", "root") : null;
      closeButton = content.includes('data-action="close-versions"') ? makeButton("close-versions", "", "") : null;
    },
    toast() {},
    redirectToLogin() {},
  };
  vm.runInNewContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));

  const click = async (button) => rootListeners.get("click")({ target: { closest: () => button } });
  await click(versionButton);
  await click(closeButton);
  assert.equal(activeElement, versionButton);
});
