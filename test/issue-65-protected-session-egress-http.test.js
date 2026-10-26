"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const express = require("express");
const jwt = require("jsonwebtoken");
const z = require("../src/crypto/rootark-zk-1");
const { createAuthenticate } = require("../src/middlewares/auth");
const { createRequirePermission } = require("../src/middlewares/permissions");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");
const { Zk1OpaqueCatalog } = require("../src/services/zk1OpaqueCatalog");

const encoded = (size) => crypto.randomBytes(size).toString("base64url");
const scope = { account_id: Buffer.alloc(16, 1),
  compartment_id: Buffer.alloc(16, 2), keyring_id: Buffer.alloc(16, 3) };

function signedWire(operation, catalogHeader) {
  return { authorization: {
    account_id: scope.account_id.toString("base64url"),
    compartment_id: scope.compartment_id.toString("base64url"),
    keyring_id: scope.keyring_id.toString("base64url"),
    device_id: "owner-device", operation, object_id: encoded(16),
    expected_object_revision: 1, manifest_revision: 1,
    manifest_digest: encoded(32), epoch: 1, nonce: encoded(32),
    issued_at: 1, expires_at: 60, ciphertext_digest: encoded(32),
  }, signatureBase64: encoded(64),
  ...(operation === "catalog-read" ? { pageIndex: 0 } : {}),
  ...(operation === "put" ? { ciphertextBase64: encoded(64) } : {}),
  ...(operation === "catalog-commit" ? { headerBase64: catalogHeader,
    headerSignatureBase64: encoded(64), pages: [] } : {}) };
}

test("HTTP ZK1 ciphertext and catalog read must fence account revocation before egress", async (t) => {
  const secret = crypto.randomBytes(32);
  const catalogHeader = Buffer.from(await z.encodeDeterministic({ fixture: true })).toString("base64url");
  const user = { username: "owner", role: "user", permissions: { listFiles: true },
    sessionVersion: 0, disabled: false };
  let entered;
  let release;
  const pause = () => {
    const started = new Promise((resolve) => { entered = resolve; });
    const allowed = new Promise((resolve) => { release = resolve; });
    return { started, allowed };
  };
  let gate = pause();
  const mutations = { put: 0, catalog: 0 };
  const waitForGate = async () => {
    await gate.started;
    const continueFromGate = release;
    return continueFromGate;
  };
  const store = {
    signedHistoryRequired: true,
    put() {}, get() {},
    async runWithAdmission(_request, operation, emit, guard) {
      entered();
      await gate.allowed;
      if (operation === "put") {
        guard?.();
        mutations.put++;
        return emit({ id: "opaque-object", revision: 1 });
      }
      assert.equal(operation, "get");
      return emit({ id: "opaque-object", revision: 1, epoch: 1,
        ciphertext: Buffer.from("fake-sealed-ciphertext") });
    },
  };
  const opaqueCatalog = Object.assign(Object.create(Zk1OpaqueCatalog.prototype), {
    store,
    async commit({ guard, emit }) {
      entered();
      await gate.allowed;
      guard?.();
      mutations.catalog++;
      return emit({ sequence: 1 });
    },
    async read({ emit }) {
      entered();
      await gate.allowed;
      return emit({ pageIndex: 0, metadataCiphertextBase64: encoded(32) });
    },
  });
  const app = express();
  let liveScope = scope;
  const authenticate = createAuthenticate({ jwt, jwtSecret: secret,
    loadUser: (name) => name === user.username ? user : null,
    normalizeUserPermissions: (current) => ({ ...current.permissions }) });
  registerZk1ProtectedObjectRoutes({ app, store, opaqueCatalog, authenticate,
    requirePermission: createRequirePermission(),
    resolveTrustedScope: (current) => current?.username === "owner" ? liveScope : null });
  const server = await new Promise((resolve) => {
    const value = app.listen(0, "127.0.0.1", () => resolve(value));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const cookie = () => `rootark_session=${jwt.sign({ username: "owner", sessionVersion: user.sessionVersion },
    secret, { algorithm: "HS256", expiresIn: "10m" })}; rootark_csrf=fixture-csrf`;
  const request = (route, rawCookie, csrf = "fixture-csrf") => fetch(base + route, {
    method: "POST", headers: { cookie: rawCookie, origin: base,
      "x-csrf-token": csrf, "content-type": "application/json" },
    body: JSON.stringify(signedWire(route.endsWith("catalog/read") ? "catalog-read"
      : route.endsWith("catalog/commit") ? "catalog-commit"
        : route.endsWith("content/put") ? "put" : "get", catalogHeader)),
  });
  const routes = ["/zk-1/v1/content/read", "/zk-1/v1/catalog/read"];

  for (const route of routes) {
    user.sessionVersion = 0;
    user.permissions.listFiles = true;
    user.disabled = false;
    const initialCookie = cookie();
    // CSRF rejection is enforced on initial HTTP middleware entry.
    const csrfDenied = await request(route, initialCookie, "wrong-csrf");
    assert.equal(csrfDenied.status, 403);

    gate = pause();
    const inflightLogout = request(route, initialCookie);
    const afterLogoutAdmission = await waitForGate();
    user.sessionVersion++;
    afterLogoutAdmission();
    const revoked = await inflightLogout;
    assert.equal(revoked.status, 401, `${route}: logout raced while witness was pending`);
    assert.equal(JSON.stringify(await revoked.json()).includes("ciphertextBase64"), false);
    assert.equal(revoked.headers.get("cache-control"), "no-store");

    gate = pause();
    const inflightPermission = request(route, cookie());
    const afterPermissionAdmission = await waitForGate();
    user.permissions.listFiles = false;
    afterPermissionAdmission();
    const denied = await inflightPermission;
    assert.equal(denied.status, 403, `${route}: permission revoked while witness was pending`);
    assert.equal(JSON.stringify(await denied.json()).includes("ciphertextBase64"), false);

    user.permissions.listFiles = true;
    gate = pause();
    const inflightDisabled = request(route, cookie());
    const afterDisabledAdmission = await waitForGate();
    user.disabled = true;
    afterDisabledAdmission();
    const disabled = await inflightDisabled;
    assert.equal(disabled.status, 401, `${route}: account disabled during witness read`);
    assert.equal(JSON.stringify(await disabled.json()).includes("ciphertextBase64"), false);

    user.disabled = false;
    gate = pause();
    const inflightScope = request(route, cookie());
    const afterScopeAdmission = await waitForGate();
    liveScope = { ...scope, keyring_id: Buffer.alloc(16, 9) };
    afterScopeAdmission();
    const scopeDenied = await inflightScope;
    assert.equal(scopeDenied.status, 403, `${route}: trusted owner scope changed`);
    assert.equal(JSON.stringify(await scopeDenied.json()).includes("ciphertextBase64"), false);

    liveScope = scope;
    gate = pause();
    const valid = request(route, cookie());
    const afterValidAdmission = await waitForGate();
    afterValidAdmission();
    const succeeded = await valid;
    assert.equal(succeeded.status, 200, `${route}: unchanged live session`);
    const body = await succeeded.json();
    if (route.endsWith("content/read")) assert.equal(body.ciphertextBase64,
      Buffer.from("fake-sealed-ciphertext").toString("base64url"));
    else assert.equal(body.pageIndex, 0);
  }

  for (const [route, effect] of [["/zk-1/v1/content/put", "put"],
    ["/zk-1/v1/catalog/commit", "catalog"]]) {
    user.sessionVersion = 0;
    user.disabled = false;
    user.permissions.upload = true;
    const snapshot = mutations[effect];
    const csrfDenied = await request(route, cookie(), "wrong-csrf");
    assert.equal(csrfDenied.status, 403, `${route}: CSRF denied at request entry`);
    assert.equal(mutations[effect], snapshot);

    gate = pause();
    const inflightLogout = request(route, cookie());
    const afterLogoutAdmission = await waitForGate();
    user.sessionVersion++;
    afterLogoutAdmission();
    const loggedOut = await inflightLogout;
    assert.equal(loggedOut.status, 401, `${route}: logout during awaited admission`);
    assert.equal(mutations[effect], snapshot, `${route}: forbidden persisted effect`);

    gate = pause();
    const inflightPermission = request(route, cookie());
    const afterPermissionAdmission = await waitForGate();
    user.permissions.upload = false;
    afterPermissionAdmission();
    const forbidden = await inflightPermission;
    assert.equal(forbidden.status, 403, `${route}: upload permission withdrawn`);
    assert.equal(mutations[effect], snapshot, `${route}: forbidden persisted effect`);

    user.permissions.upload = true;
    gate = pause();
    const inflightDisabled = request(route, cookie());
    const afterDisabledAdmission = await waitForGate();
    user.disabled = true;
    afterDisabledAdmission();
    const disabled = await inflightDisabled;
    assert.equal(disabled.status, 401, `${route}: account disabled before effect`);
    assert.equal(mutations[effect], snapshot, `${route}: forbidden persisted effect`);

    user.disabled = false;
    gate = pause();
    const live = request(route, cookie());
    const afterLiveAdmission = await waitForGate();
    afterLiveAdmission();
    const succeeded = await live;
    assert.equal(succeeded.status, 201);
    assert.equal(mutations[effect], snapshot + 1, `${route}: live session allowed effect`);
  }
});
