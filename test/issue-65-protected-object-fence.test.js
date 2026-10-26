"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } = require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");

test("opaque content plane enforces independently signed live head, device signature and durable replay fencing", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk-content-gate-");
  const instances = [];
  const servers = [];
  t.after(async () => {
    for (const server of servers) await new Promise((done) => server.close(done));
    for (const instance of instances) instance.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const state = await fixtures.createInitialState(2);
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const scope = state.scope;
  let manifest = state.headManifest;
  let offline = false;
  let pending = false;
  let clock = 1200;
  let crossExpiryDuringWitness = false;
  const witnessProvider = {
    async freshHead({ scope: requested, nonce }) {
      if (offline) throw new Error("network partition");
      if (crossExpiryDuringWitness) { clock += 2; crossExpiryDuringWitness = false; }
      assert.deepEqual(requested.account_id, scope.account_id);
      const head = {
        type: "rootark-recovery-witness-head/v1", witness_key_id: witnessKeyId,
        ...scope, current_revision: manifest.revision,
        current_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
        witness_sequence: manifest.revision, nonce, observed_at: clock,
        status: pending ? "pending" : "committed",
        pending_reservation_id: pending ? crypto.randomBytes(16) : null,
      };
      const signature = crypto.sign(null, Buffer.concat([HEAD_DOMAIN,
        Buffer.from(await z.encodeDeterministic(head))]), witness.privateKey);
      return Buffer.from(await z.encodeDeterministic({ ...head, signature }));
    },
  };
  const filename = path.join(dir, "objects.sqlite");
  const make = (trustedScope = scope, bootstrapNew = false) => {
    const instance = new Zk1ProtectedObjectStore(filename, {
      witnessProvider, witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
      manifestProvider: async () => z.encodeDeterministic(manifest),
      trustedScope, bootstrapNew,
      minimumHead: { revision: 1, digest: awaitDigest, witnessSequence: 1 },
      nowSeconds: () => clock,
    });
    instances.push(instance);
    return instance;
  };
  const awaitDigest = await v2.recoveryManifestDigestV2(state.baseManifest);
  assert.throws(() => make(null, true), /ZK_CONTENT_DENIED/);
  assert.throws(() => make(), /ZK_CONTENT_BOOTSTRAP_REQUIRED/,
    "a missing replay/floor database must never silently reset on restart");
  let store = make(scope, true);
  assert.throws(() => make(scope, true), /ZK_CONTENT_BOOTSTRAP_REQUIRED/,
    "exclusive bootstrap must reject an already-created protected store");
  const auth = (device = manifest.devices[0], operation = "put", objectId = crypto.randomBytes(16).toString("base64url"), expectedRevision = null) => ({
    ...scope, device_id: device.device_id, operation, object_id: objectId,
    expected_object_revision: expectedRevision, manifest_revision: manifest.revision,
    manifest_digest: null, epoch: manifest.current_epoch, nonce: crypto.randomBytes(32),
    issued_at: clock - 1, expires_at: clock + 30,
    ciphertext_digest: null,
  });
  const signed = async (authorization, ciphertext = null) => {
    const withDigest = { ...authorization, manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      ciphertext_digest: ciphertext === null ? null : crypto.createHash("sha256").update(ciphertext).digest() };
    const device = manifest.devices.find((d) => d.device_id === withDigest.device_id);
    const privateKey = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
    const signature = crypto.sign(null, await contentAuthorizationMessageV1(withDigest), privateKey);
    return { scope, authorization: withDigest, signature, ciphertext };
  };
  const id = crypto.randomBytes(16).toString("base64url");
  const ciphertext = crypto.randomBytes(512);
  const write = await signed(auth(manifest.devices[0], "put", id), ciphertext);
  assert.deepEqual(await store.put(write), { id, revision: 1 });
  await assert.rejects(store.put(write), /ZK_CONTENT_REPLAY/);

  const otherDevice = await signed(auth(manifest.devices[1], "get", id));
  const result = await store.get(otherDevice);
  assert.equal(result.revision, 1);
  assert.deepEqual(result.ciphertext, ciphertext);
  result.ciphertext.fill(0);
  const repeat = await signed(auth(manifest.devices[1], "get", id));
  assert.deepEqual((await store.get(repeat)).ciphertext, ciphertext);

  const forged = await signed(auth(manifest.devices[1], "get", id));
  forged.signature = crypto.sign(null, await contentAuthorizationMessageV1(forged.authorization),
    crypto.generateKeyPairSync("ed25519").privateKey);
  await assert.rejects(store.get(forged), /ZK_CONTENT_DENIED/);
  await assert.rejects(store.get({ ...repeat, scope: { ...scope, account_id: crypto.randomBytes(16) } }),
    /ZK_CONTENT_DENIED/);

  offline = true;
  await assert.rejects(store.get(await signed(auth(manifest.devices[0], "get", id))), /ZK_CONTENT_UNAVAILABLE/);
  offline = false;
  pending = true;
  await assert.rejects(store.get(await signed(auth(manifest.devices[0], "get", id))), /ZK_CONTENT_UNAVAILABLE/);
  pending = false;

  store.close();
  store = make();
  await assert.rejects(store.put(write), /ZK_CONTENT_REPLAY/);
  const freshWrite = await signed(auth(manifest.devices[0], "put", id, 1), crypto.randomBytes(100));
  assert.deepEqual(await store.put(freshWrite), { id, revision: 2 });
  await assert.rejects(store.put({ ...freshWrite, ciphertext: crypto.randomBytes(100) }),
    /ZK_CONTENT_DENIED|ZK_CONTENT_REPLAY/);

  // Reviewer P2 reproduction: expiration during independently signed witness
  // operation must be rechecked at the actual SQLite read/effect boundary.
  const expiring = await signed({ ...auth(manifest.devices[0], "get", id),
    issued_at: clock - 1, expires_at: clock });
  crossExpiryDuringWitness = true;
  await assert.rejects(store.get(expiring), /ZK_CONTENT_DENIED/);

  // Nonces from EXPIRED signed requests can be reclaimed only when the
  // durable trusted clock high-water makes time rollback fail closed.
  const soonExpired = await signed({ ...auth(manifest.devices[0], "get", id),
    issued_at: clock - 1, expires_at: clock + 1 });
  assert.equal((await store.get(soonExpired)).revision, 2);
  await assert.rejects(store.get(soonExpired), /ZK_CONTENT_REPLAY/);
  // Reviewer P2: a once-full nonce table must not permanently disable a
  // legitimately authorized user after every synthetic nonce has expired.
  const protectedScopeKey = store.db.prepare("SELECT scope FROM zk_content_head LIMIT 1").get().scope;
  store.db.prepare(`WITH RECURSIVE seq(n) AS
    (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<100005)
    INSERT INTO zk_content_nonce(scope,nonce,expires_at)
    SELECT ?,randomblob(32),? FROM seq`).run(protectedScopeKey, clock);
  assert.ok(store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_nonce").get().n > 100000);
  clock += 2;
  assert.equal((await store.get(await signed(auth(manifest.devices[0], "get", id)))).revision, 2);
  const oldRows = store.db.prepare("SELECT COUNT(*) AS total FROM zk_content_nonce WHERE expires_at < ?")
    .get(clock).total;
  assert.equal(oldRows, 0, "expired nonce tombstones must not occupy finite capacity forever");
  const highWater = clock;
  store.close();
  store = make();
  clock -= 4;
  await assert.rejects(store.get(await signed(auth(manifest.devices[0], "get", id))),
    /ZK_CONTENT_UNAVAILABLE/, "rollback of local time must never revive purged signed requests");
  clock = highWater;

  const app = express();
  app.use(express.json({ limit: "7mb" }));
  const authenticate = (req, res, next) => {
    if (req.get("x-test-auth") !== "authorized") return res.sendStatus(401);
    req.user = { username: "owner" };
    next();
  };
  registerZk1ProtectedObjectRoutes({ app, store, authenticate,
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: (user) => user.username === "owner" ? scope : null });
  const server = await new Promise((done) => {
    const srv = app.listen(0, "127.0.0.1", () => done(srv));
  });
  servers.push(server);
  const base = `http://127.0.0.1:${server.address().port}`;
  const b64 = (value) => Buffer.from(value).toString("base64url");
  const wire = (operation) => ({
    authorization: Object.fromEntries(Object.entries(operation.authorization)
      .map(([k, value]) => [k, Buffer.isBuffer(value) ? b64(value) : value])),
    signatureBase64: b64(operation.signature),
    ...(operation.ciphertext ? { ciphertextBase64: b64(operation.ciphertext) } : {}),
  });
  const send = async (route, object, authorized = true) => fetch(base + route, {
    method: "POST", headers: {
      "content-type": "application/json", ...(authorized ? { "x-test-auth": "authorized" } : {}),
    }, body: JSON.stringify(wire(object)),
  });
  const httpId = crypto.randomBytes(16).toString("base64url");
  const httpBytes = crypto.randomBytes(222);
  const httpWrite = await signed(auth(manifest.devices[0], "put", httpId), httpBytes);
  assert.equal((await send("/zk-1/v1/content/put", httpWrite, false)).status, 401);
  const created = await send("/zk-1/v1/content/put", httpWrite);
  assert.equal(created.status, 201);
  assert.deepEqual(await created.json(), { id: httpId, revision: 1 });
  assert.equal((await send("/zk-1/v1/content/put", httpWrite)).status, 409);
  const httpRead = await signed(auth(manifest.devices[1], "get", httpId));
  const fetched = await send("/zk-1/v1/content/read", httpRead);
  assert.equal(fetched.status, 200);
  const readResult = await fetched.json();
  assert.equal(readResult.revision, 1);
  assert.deepEqual(Buffer.from(readResult.ciphertextBase64, "base64url"), httpBytes);

  // Real crypto transition from v2 fixtures, not a fake device table edit.
  const previouslySigned = await signed(auth(manifest.devices[1], "get", id));
  const oldManifest = manifest;
  await fixtures.appendDeviceRevocation(state, "trusted-1");
  manifest = state.headManifest;
  await assert.rejects(store.get(previouslySigned), /ZK_CONTENT_UNAVAILABLE/);
  await assert.rejects(store.get(await signed(auth(manifest.devices[1], "get", id))),
    /ZK_CONTENT_DENIED/);
  assert.equal((await send("/zk-1/v1/content/read",
    await signed(auth(manifest.devices[1], "get", httpId)))).status, 403);
  const active = await signed(auth(manifest.devices[0], "get", id));
  assert.equal((await store.get(active)).revision, 2);

  store.close();
  store = make();
  manifest = oldManifest; // forged rollback of an otherwise correctly signed old head
  await assert.rejects(store.get(await signed(auth(manifest.devices[0], "get", id))),
    /ZK_CONTENT_UNAVAILABLE/);
  manifest = state.headManifest;

  // Only the trusted mapped scope may consume a watermark floor; do not
  // transplant a genesis floor into another compartment or account.
  const alien = { ...scope, compartment_id: Buffer.from("another-compartment") };
  await assert.rejects(store.get({ ...await signed(auth(manifest.devices[0], "get", id)),
    scope: alien }), /ZK_CONTENT_DENIED/);
});
