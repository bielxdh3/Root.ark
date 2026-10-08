"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

test("realtime refresh waits for dirty values and resumes when all values return to their original values on blur", async (t) => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-workspace.js"), "utf8");
  const documentListeners = new Map();
  const windowListeners = new Map();
  const rootListeners = new Map();
  const body = { matches: () => false, isContentEditable: false };
  let activeElement = body;
  let socket;
  let foldersCalls = 0;
  let listCalls = 0;
  let remoteFolderExists = false;
  let renderedContent = "";

  const form = { id: "upload-form", tagName: "FORM" };
  const comment = {
    form,
    tagName: "INPUT",
    type: "text",
    name: "versionComment",
    defaultValue: "",
    value: "",
    matches: (selector) => selector === "input, select, textarea",
  };
  const checkbox = {
    form,
    tagName: "INPUT",
    type: "checkbox",
    name: "includeMetadata",
    defaultChecked: true,
    checked: true,
    matches: (selector) => selector === "input, select, textarea",
  };
  const dynamicallySelected = {
    form,
    tagName: "SELECT",
    type: "select-one",
    name: "encryptionLevel",
    value: "none",
    defaultValue: "",
    options: [{ value: "none", selected: true, defaultSelected: false }, { value: "account", selected: false, defaultSelected: false }],
    matches: (selector) => selector === "input, select, textarea",
  };
  form.elements = [comment, checkbox, dynamicallySelected];

  const root = {
    addEventListener(name, listener) { rootListeners.set(name, listener); },
    querySelectorAll(selector) {
      return selector === "input, select, textarea" ? form.elements : [];
    },
  };
  const document = {
    get activeElement() { return activeElement; },
    set activeElement(value) { activeElement = value; },
    get forms() { return [form]; },
    addEventListener(name, listener) { documentListeners.set(name, listener); },
    getElementById(id) { return id === "app-root" ? root : null; },
    querySelector() { return null; },
  };
  class FakeWebSocket {
    constructor() { this.listeners = new Map(); socket = this; }
    addEventListener(name, listener) { this.listeners.set(name, listener); }
    close() {}
  }
  const window = {
    location: { hash: "", protocol: "http:", host: "rootark.test" },
    WebSocket: FakeWebSocket,
    addEventListener(name, listener) { windowListeners.set(name, listener); },
    dispatchEvent(event) {
      const listener = windowListeners.get(event.type);
      if (listener) listener(event);
    },
    setTimeout,
    clearTimeout,
  };
  window.RootarkApi = {
    query: (route, values = {}) => `${route}?${new URLSearchParams(values).toString()}`,
    async get(route) {
      if (route === "/folders") {
        foldersCalls += 1;
        return [
          { id: "root", name: "Meu espaço", isRoot: true },
          ...(remoteFolderExists ? [{ id: "remote", name: "remote-folder" }] : []),
        ];
      }
      if (route.startsWith("/list")) { listCalls += 1; return []; }
      if (route.startsWith("/pending")) return [];
      throw new Error(`Unexpected GET route: ${route}`);
    },
    async post() { return {}; },
  };
  window.RootarkUI = {
    escape: (value) => String(value || ""),
    formatBytes: () => "0 B",
    formatDate: () => "",
    async getSession() { return { username: "tester", role: "user", permissions: { listFiles: true, upload: true } }; },
    mount({ content }) { renderedContent = content; },
    toast() {},
    redirectToLogin() {},
  };

  vm.runInNewContext(source, { document, window, Event: class Event { constructor(type) { this.type = type; } }, WebSocket: FakeWebSocket });
  t.after(() => {
    const pagehide = windowListeners.get("pagehide");
    if (pagehide) pagehide();
  });
  for (let attempt = 0; attempt < 10 && !socket; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.ok(socket, `the workspace connects its realtime socket after initial loading: ${root.innerHTML || "no rendered error"}; folders=${foldersCalls}; list=${listCalls}; rendered=${renderedContent.length}`);
  assert.equal(foldersCalls, 1);
  assert.equal(listCalls, 1);

  documentListeners.get("focusin")({ target: comment });
  comment.value = "unsaved text";
  checkbox.checked = false;
  dynamicallySelected.value = "account";
  documentListeners.get("input")({ target: comment });
  documentListeners.get("change")({ target: checkbox });
  documentListeners.get("change")({ target: dynamicallySelected });
  activeElement = comment;
  remoteFolderExists = true;
  socket.listeners.get("message")({ data: JSON.stringify({ event: "data:changed" }) });
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.equal(foldersCalls, 1, "a remote update stays deferred while the draft differs from its defaults");
  assert.equal(listCalls, 1, "the file list is not replaced while the form is dirty");
  assert.doesNotMatch(renderedContent, /remote-folder/, "the remote folder stays out of the rendered list while the draft differs");
  assert.equal(comment.value, "unsaved text", "unsaved text remains available to the user");

  activeElement = body;
  documentListeners.get("focusout")({ target: comment });
  await new Promise((resolve) => setTimeout(resolve, 400));
  assert.equal(foldersCalls, 1, "leaving a still-dirty form keeps the refresh deferred");
  assert.equal(comment.value, "unsaved text");

  comment.value = comment.defaultValue;
  documentListeners.get("input")({ target: comment });
  documentListeners.get("focusout")({ target: comment });
  await new Promise((resolve) => setTimeout(resolve, 400));
  assert.equal(foldersCalls, 1, "one reverted field does not clear another dirty value in the same form");
  assert.equal(checkbox.checked, false);
  dynamicallySelected.value = "none";
  documentListeners.get("change")({ target: dynamicallySelected });
  documentListeners.get("focusout")({ target: dynamicallySelected });
  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.equal(foldersCalls, 1, "a dynamically selected but unchanged option does not keep the form dirty");

  checkbox.checked = checkbox.defaultChecked;
  documentListeners.get("change")({ target: checkbox });
  documentListeners.get("focusout")({ target: checkbox });
  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.equal(foldersCalls, 2, "the pending refresh resumes when all controls return to their defaults");
  assert.equal(listCalls, 2);
  assert.match(renderedContent, /remote-folder/, "the remote folder appears after the deferred refresh");

});
