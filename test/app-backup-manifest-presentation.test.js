"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-management.js"), "utf8");

function element() {
  return {
    hidden: true, textContent: "", innerHTML: "", disabled: false, scrolls: 0,
    listeners: Object.create(null),
    addEventListener(type, handler) { this.listeners[type] = handler; },
    setAttribute() {},
    scrollIntoView() { this.scrolls += 1; },
  };
}

async function fixture() {
  const nodes = Object.fromEntries([
    "app-root", "page-content", "backups-body", "backup-warning",
    "manifest-panel", "manifest-content", "create-backup", "backup-feedback",
  ].map((id) => [id, element()]));
  const backups = [
    { id: "a", type: "manual", status: "success", sizeBytes: 1 },
    { id: "b", type: "manual", status: "success", sizeBytes: 2 },
  ];
  const requests = [];
  const document = {
    body: { dataset: { rootarkView: "backups" } },
    getElementById(id) {
      assert.ok(nodes[id], "unexpected UI element: " + id);
      return nodes[id];
    },
  };
  const window = {
    RootarkUI: {
      getSession: async () => ({ role: "admin" }),
      mount() {},
      escape: String,
      formatDate: () => "fixture",
      formatBytes: String,
    },
    RootarkApi: {
      get(url) {
        if (url === "/backups/latest-status") return Promise.resolve({ latest: null });
        if (url === "/backups") return Promise.resolve({ backups });
        assert.ok(url === "/backups/a/manifest" || url === "/backups/b/manifest", "unexpected mock request");
        return new Promise((resolve, reject) => requests.push({ url, resolve, reject }));
      },
    },
  };
  vm.runInNewContext(source, { window, document });
  await new Promise(setImmediate);
  const target = nodes["page-content"];
  assert.match(nodes["backups-body"].innerHTML, /data-backup-index="1"/);
  assert.equal(typeof target.listeners.click, "function");

  function click(action, index) {
    const button = { dataset: { action, backupIndex: String(index) } };
    return target.listeners.click({ target: { closest: () => button } });
  }
  function open(index) {
    const count = requests.length;
    const done = click("show-manifest", index);
    assert.equal(requests.length, count + 1);
    const request = requests[count];
    assert.equal(request.url, "/backups/" + backups[index].id + "/manifest");
    return { ...request, done };
  }
  return {
    open, close: () => click("close-manifest"),
    panel: nodes["manifest-panel"], content: nodes["manifest-content"],
  };
}

test("the most recently selected manifest wins when responses arrive in reverse order", async () => {
  const f = await fixture();
  const a = f.open(0);
  const b = f.open(1);
  assert.equal(f.panel.hidden, false);
  assert.equal(f.content.textContent, "Carregando manifesto…");
  b.resolve({ label: "B" });
  await b.done;
  const displayed = f.content.textContent;
  assert.equal(JSON.parse(displayed).label, "B");
  a.resolve({ label: "A" });
  await a.done;
  assert.equal(f.content.textContent, displayed);
  assert.equal(f.panel.scrolls, 2);
});

test("a late operational error does not replace the current manifest", async () => {
  const f = await fixture();
  const a = f.open(0);
  const b = f.open(1);
  b.resolve({ label: "B" });
  await b.done;
  a.reject(Object.assign(new Error("fixture failure"), { status: 500 }));
  await a.done;
  assert.equal(JSON.parse(f.content.textContent).label, "B");
});

test("closing a pending manifest clears its content and prevents late scrolling or rendering", async () => {
  const f = await fixture();
  const a = f.open(0);
  const scrolls = f.panel.scrolls;
  await f.close();
  assert.equal(f.panel.hidden, true);
  assert.equal(f.content.textContent, "");
  a.resolve({ label: "A" });
  await a.done;
  assert.equal(f.panel.hidden, true);
  assert.equal(f.content.textContent, "");
  assert.equal(f.panel.scrolls, scrolls);
});

test("a closed selection cannot replace a reopened manifest", async () => {
  const f = await fixture();
  const a = f.open(0);
  await f.close();
  const b = f.open(1);
  a.resolve({ label: "A" });
  await a.done;
  assert.equal(f.panel.hidden, false);
  assert.equal(f.content.textContent, "Carregando manifesto…");
  b.resolve({ label: "B" });
  await b.done;
  assert.equal(JSON.parse(f.content.textContent).label, "B");
});

test("the current operational error is shown and a subsequent selection can succeed", async () => {
  const f = await fixture();
  const a = f.open(0);
  a.reject(Object.assign(new Error("fixture failure"), { status: 500 }));
  await a.done;
  assert.equal(f.panel.hidden, false);
  assert.equal(f.content.textContent, "Não foi possível carregar o manifesto.");
  const retry = f.open(0);
  assert.equal(f.content.textContent, "Carregando manifesto…");
  retry.resolve({ label: "retry" });
  await retry.done;
  assert.equal(JSON.parse(f.content.textContent).label, "retry");
});
