"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");
const express = require("express");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");

const CAPABILITY = "/zk-1/v1/workspace-capability";

async function browserWith(response) {
  const handlers = new Map();
  const buttons = [];
  let served = response;
  const panel = { append(button) { buttons.push(button); } };
  const status = { closest: (selector) => selector === ".protected-client-panel" ? panel : null };
  const document = {
    getElementById(id) {
      if (id === "protectedClientStatus") return status;
      if (id === "zk1-workspace-open") return buttons.find((button) => !button.removed) || null;
      return null;
    },
    createElement(name) {
      assert.equal(name, "button");
      return { name, removed: false,
        remove() { this.removed = true; },
        addEventListener(event, fn) { this[event] = fn; } };
    },
  };
  const window = {
    RootarkApi: { async get(url) {
      assert.equal(url, CAPABILITY);
      return served;
    } },
    addEventListener(name, callback) { handlers.set(name, callback); },
  };
  const source = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-authenticated-workspace.js"), "utf8");
  vm.runInNewContext(source, { window, document, TextDecoder }, { timeout: 1000 });
  handlers.get("rootark:workspace-rendered")();
  for (let i = 0; i < 5; ++i) await Promise.resolve();
  return { buttons, setResponse(value) { served = value; } };
}

test("V2 browser refuses V1/legacy or spoofed unsigned history capability", async () => {
  for (const reply of [
    { enabled: true }, // Previous ambiguous V1 server reply.
    { enabled: true, securityVersion: 1, signedHistoryRequired: false },
    { enabled: true, securityVersion: 2, signedHistoryRequired: false },
    { enabled: true, securityVersion: 1, signedHistoryRequired: true },
    { enabled: false, securityVersion: 2, signedHistoryRequired: true },
  ]) {
    const state = await browserWith(reply);
    assert.equal(state.buttons.length, 0,
      "A V1 or unproven mode MUST NOT display V2 encrypted workspace controls");
  }
  const state = await browserWith({ enabled: true,
    securityVersion: 2, signedHistoryRequired: true });
  assert.equal(state.buttons.length, 1,
    "genuine explicit owner-history V2 may offer development workspace");
  state.setResponse({ enabled: true, securityVersion: 1, signedHistoryRequired: false });
  await state.buttons[0].click();
  assert.equal(state.buttons[0].removed, true,
    "V2->V1 mode transition must be denied even after UI button is rendered");
});

test("authenticated capability explicitly separates intentional V1 from owner-rooted V2", async (t) => {
  for (const signedHistoryRequired of [false, true]) {
    const app = express();
    const store = { signedHistoryRequired, put() {}, get() {} };
    registerZk1ProtectedObjectRoutes({ app, store,
      authenticate: (req, _res, next) => { req.user = { username: "owner" }; next(); },
      requirePermission: () => (_req, _res, next) => next(),
      resolveTrustedScope: (user) => user?.username === "owner" ? { account_id: "pinned" } : null });
    const server = await new Promise((resolve) => {
      const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
    });
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const response = await fetch(`http://127.0.0.1:${server.address().port}${CAPABILITY}`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), { enabled: true,
      securityVersion: signedHistoryRequired ? 2 : 1, signedHistoryRequired });
  }
});
