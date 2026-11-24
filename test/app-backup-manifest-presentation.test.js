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

// Exercise the direct view initialization as well as the full application startup.
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

async function directViewFixture() {
  const clicks = [];
  const requests = [];
  const scrolls = [];
  const element = () => ({
    hidden: false,
    textContent: "",
    innerHTML: "",
    addEventListener() {},
    setAttribute() {},
  });
  const panel = element();
  panel.scrollIntoView = (options) => scrolls.push(options.block);
  const content = element();
  const body = element();
  const elements = new Map([
    ["backups-body", body],
    ["backup-warning", element()],
    ["manifest-panel", panel],
    ["manifest-content", content],
    ["create-backup", element()],
  ]);
  const target = {
    set innerHTML(markup) {
      assert.match(markup, /id="manifest-panel"[^>]*\bhidden\b/);
      assert.match(markup, /id="manifest-content"[^>]*role="status"/);
      panel.hidden = true;
    },
    addEventListener(type, listener) {
      assert.equal(type, "click");
      clicks.push(listener);
    },
  };
  const api = {
    async get(route) {
      if (route === "/backups/latest-status") return { latest: null };
      if (route === "/backups") return { backups: [
        { id: "A", status: "completed", type: "manual", sizeBytes: 1 },
        { id: "B", status: "completed", type: "manual", sizeBytes: 2 },
      ] };
      const match = /^\/backups\/(A|B)\/manifest$/.exec(route);
      assert.ok(match, "only synthetic manifest reads are expected");
      const request = deferred();
      requests.push({ id: match[1], ...request });
      return request.promise;
    },
  };
  const window = {
    RootarkApi: api,
    RootarkUI: {
      escape: (value) => String(value),
      formatDate: () => "data fictícia",
      formatBytes: (value) => String(value),
      toast() {},
    },
  };
  const document = {
    body: { dataset: { rootarkView: "backups" } },
    getElementById(id) {
      assert.ok(elements.has(id), "unexpected synthetic element: " + id);
      return elements.get(id);
    },
  };
  // Enter the already selected view directly; no application startup or real services.
  const entry = source.lastIndexOf("  start().catch(");
  assert.ok(entry >= 0, "expected application startup boundary");
  const initialize = vm.runInNewContext(source.slice(0, entry) +
    "  return initBackups(fixtureUser, fixtureTarget);\n})();",
    { window, document, fixtureUser: { role: "admin" }, fixtureTarget: target });
  await initialize;
  assert.equal(clicks.length, 1);
  assert.match(body.innerHTML, /data-action="show-manifest" data-backup-index="0"/);
  assert.match(body.innerHTML, /data-action="show-manifest" data-backup-index="1"/);
  function click(action, index) {
    const button = { dataset: { action, backupIndex: String(index) } };
    return clicks[0]({ target: { closest: () => button } });
  }
  return { panel, content, requests, scrolls, click };
}

const payload = (name) => ({ title: "Synthetic " + name });
const displayed = (name) => JSON.stringify(payload(name), null, 2);

test("latest selected manifest wins when A and B resolve in reverse order", async () => {
  const { panel, content, requests, click } = await directViewFixture();
  const a = click("show-manifest", 0);
  assert.equal(panel.hidden, false);
  assert.equal(content.textContent, "Carregando manifesto…");
  const b = click("show-manifest", 1);
  assert.deepEqual(requests.map(({ id }) => id), ["A", "B"]);
  requests[1].resolve(payload("B"));
  await b;
  assert.equal(content.textContent, displayed("B"));
  requests[0].resolve(payload("A"));
  await a;
  assert.equal(content.textContent, displayed("B"));
  assert.equal(panel.hidden, false);
});

test("late ordinary failure from A cannot replace the displayed B", async () => {
  const { panel, content, requests, click } = await directViewFixture();
  const a = click("show-manifest", 0);
  const b = click("show-manifest", 1);
  requests[1].resolve(payload("B"));
  await b;
  requests[0].reject(new Error("Falha fictícia"));
  await a;
  assert.equal(content.textContent, displayed("B"));
  assert.equal(panel.hidden, false);
});

for (const settle of ["resolve", "reject"]) {
  test("closing a pending manifest prevents late visual update: " + settle, async () => {
    const { panel, content, requests, scrolls, click } = await directViewFixture();
    const pending = click("show-manifest", 0);
    assert.equal(panel.hidden, false);
    assert.equal(content.textContent, "Carregando manifesto…");
    assert.equal(scrolls.length, 1, "scroll when the panel opens");
    await click("close-manifest");
    assert.equal(panel.hidden, true);
    assert.equal(content.textContent, "");
    const before = scrolls.length;
    requests[0][settle](settle === "resolve" ? payload("A") : new Error("Falha fictícia"));
    await pending;
    assert.equal(panel.hidden, true);
    assert.equal(content.textContent, "");
    assert.equal(scrolls.length, before, "no late scroll after closing");
    const reopened = click("show-manifest", 1);
    assert.equal(panel.hidden, false);
    assert.equal(content.textContent, "Carregando manifesto…");
    requests[1].resolve(payload("B"));
    await reopened;
    assert.equal(content.textContent, displayed("B"));
    assert.equal(panel.hidden, false);
  });
}

test("ordinary failure remains visible and reopening replaces it with loading and fresh content", async () => {
  const { panel, content, requests, click } = await directViewFixture();
  const a = click("show-manifest", 0);
  requests[0].reject(new Error("Falha fictícia"));
  await a;
  assert.equal(panel.hidden, false);
  assert.equal(content.textContent, "Falha fictícia");
  await click("close-manifest");
  const b = click("show-manifest", 1);
  assert.equal(panel.hidden, false);
  assert.equal(content.textContent, "Carregando manifesto…");
  requests[1].resolve(payload("B"));
  await b;
  assert.equal(content.textContent, displayed("B"));
});
