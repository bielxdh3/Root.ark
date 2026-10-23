"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const express = require("express");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { registerZk1LocalSignedHistoryRoutes } =
  require("../src/routes/zk1LocalSignedHistoryRoutes");

const b64 = (value) => Buffer.from(value).toString("base64url");

test("opt-in signed zk-1 history API authenticates, isolates owners, verifies signed append, paginates and conflicts", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-http-"));
  const app = express();
  const authentication = (req, res, next) => {
    if (req.headers.authorization !== "Bearer example-test-token")
      return res.status(401).json({ error: "UNAUTHORIZED" });
    req.user = { username: req.headers["x-example-owner"] || "alice", permissions: {
      listFiles: true, upload: req.headers["x-example-writer"] !== "no",
    } };
    next();
  };
  const permissions = (p) => (req, res, next) => req.user.permissions[p]
    ? next() : res.status(403).json({ error: "FORBIDDEN" });
  const store = registerZk1LocalSignedHistoryRoutes({
    app, authenticate: authentication, requirePermission: permissions,
    dbPath: path.join(directory, "history.sqlite"),
    nowSeconds: () => 1100,
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const root = "http://127.0.0.1:" + server.address().port + "/zk-dev/v1/zk1-history";
  const call = async (suffix, method = "GET", data, headers = {}) => {
    const response = await fetch(root + suffix, {
      method, headers: { "content-type": "application/json",
        authorization: "Bearer example-test-token", "x-example-owner": "alice", ...headers },
      ...(data === undefined ? {} : { body: JSON.stringify(data) }),
    });
    return { status: response.status, json: await response.json(), response };
  };
  const state = await fixtures.createInitialState(2);
  const scope = {
    accountId: b64(state.scope.account_id),
    compartmentId: b64(state.scope.compartment_id),
    keyringId: b64(state.scope.keyring_id),
  };
  const query = new URLSearchParams(scope).toString();
  assert.equal((await call("/head?" + query, "GET", undefined,
    { authorization: "unauthorized" })).status, 401);
  const baseBytes = await z.encodeDeterministic(state.baseManifest);
  const baseBody = { account: "alice", manifestBase64: b64(baseBytes),
    expectedRevision: 0, expectedDigest: null };
  assert.equal((await call("", "POST", baseBody, { "x-example-writer": "no" })).status, 403);
  assert.equal((await call("", "POST", { ...baseBody, account: "bob" })).status, 409);
  assert.equal((await call("/head?" + query)).status, 404);
  const counterfeit = { ...state.baseManifest,
    actor_signature: Buffer.alloc(64, 0x7a) };
  const counterfeitResult = await call("", "POST", {
    ...baseBody, manifestBase64: b64(await z.encodeDeterministic(counterfeit)),
  });
  assert.equal(counterfeitResult.status, 422,
    "authenticated but unsigned/forged manifest must be refused before any SQLite append");
  const initial = await call("", "POST", baseBody);
  assert.equal(initial.status, 201, JSON.stringify(initial.json));
  assert.equal(initial.json.revision, 1);
  assert.equal(initial.json.authority, "LOCAL_ONLY_UNWITNESSED");
  assert.equal((await call("/head?" + query)).json.revision, 1);
  assert.equal((await call("/head?" + query, "GET", undefined,
    { "x-example-owner": "bob" })).status, 404);
  const page1 = await call("/entries/1?" + query);
  assert.equal(page1.status, 200);
  assert.equal(page1.json.manifestBase64, b64(baseBytes));
  const nextBody = { account: "alice", manifestBase64:
    b64(await z.encodeDeterministic(state.headManifest)),
    expectedRevision: 1, expectedDigest: initial.json.digest };
  const concurrent = await Promise.all([call("", "POST", nextBody), call("", "POST", nextBody)]);
  assert.deepEqual(concurrent.map((r) => r.status).sort(), [201, 409]);
  assert.equal((await call("/entries/2?" + query)).status, 200);
  assert.equal((await call("/entries/3?" + query)).status, 404);
  assert.equal((await call("/head?" + query)).json.revision, 2);
});
