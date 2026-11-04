"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const express = require("express");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");

test("standalone protected content routes bound anonymous requests across endpoints", async (t) => {
  const app = express();
  registerZk1ProtectedObjectRoutes({
    app,
    store: { put() {}, get() {}, signedHistoryRequired: false },
    authenticate: (_req, res) => res.status(401).json({ error: "UNAUTHORIZED" }),
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => null,
  });

  const server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const paths = [
    ["GET", "/zk-1/v1/workspace-capability"],
    ["POST", "/zk-1/v1/content/read"],
    ["POST", "/zk-1/v1/content/put"],
  ];
  for (let index = 0; index < 240; index++) {
    const [method, route] = paths[index % paths.length];
    const response = await fetch(base + route, { method });
    assert.equal(response.status, 401, `request ${index + 1} must reach authentication`);
    await response.arrayBuffer();
  }
  const denied = await fetch(base + "/zk-1/v1/content/read", { method: "POST" });
  assert.equal(denied.status, 429, "standalone routes must not rely on a global app limiter");
  assert.equal((await denied.json()).error, "ZK_CONTENT_RATE_LIMITED");
});
