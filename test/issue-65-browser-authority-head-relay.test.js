"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const express = require("express");
const { shouldDeferZk1JsonParsing } = require("../src/middlewares/zk1DeferredJsonParsing");
const z = require("../src/crypto/rootark-zk-1");
const { registerZk1ProtectedObjectRoutes } =
  require("../src/routes/zk1ProtectedObjectRoutes");
const relayBrowser = require("../public/client/rootark-zk1-browser-authority-head-relay");

const b64 = (value) => Buffer.from(value).toString("base64url");
const SHA = (value) => crypto.createHash("sha256").update(value).digest();
const spki = (key) => key.export({ type: "spki", format: "der" });
const raw = (key) => spki(key).subarray(-32);
const OWNER_HEAD = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const CAS_HEAD = Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0");

test("global JSON deferral is restricted to exact opt-in development POST routes", () => {
  const names = ["/zk-1/v1/content/read", "/zk-1/v1/content/put",
    "/zk-1/v1/catalog/read", "/zk-1/v1/catalog/commit",
    "/zk-1/v1/catalog/authority/witness-head",
    "/zk-1/v1/catalog/authority/cas-head", "/zk-1/v1/multiprovider-restore/read"];
  for (const path of names) {
    const req = { method: "POST", path };
    assert.equal(shouldDeferZk1JsonParsing(req,
      { contentConfig: "test-config", environment: "test" }), true);
    assert.equal(shouldDeferZk1JsonParsing({ ...req, path: path.toUpperCase() + "/" },
      { contentConfig: "test-config", environment: "development" }), true,
    "match Express's case-insensitive optional-slash route aliases");
    for (const options of [{ contentConfig: "", environment: "test" },
      { contentConfig: "test-config", environment: "production" },
      { contentConfig: "test-config", environment: "staging" }]) {
      assert.equal(shouldDeferZk1JsonParsing(req, options), false);
    }
    assert.equal(shouldDeferZk1JsonParsing({ ...req, method: "PUT" },
      { contentConfig: "test-config", environment: "test" }), false);
    assert.equal(shouldDeferZk1JsonParsing({ ...req, path: path + "-evil" },
      { contentConfig: "test-config", environment: "test" }), false);
  }
  for (const path of ["/auth/login", "/upload", "/zk-1/v1/catalog/authority/other-head"])
    assert.equal(shouldDeferZk1JsonParsing({ path, method: "POST" },
      { contentConfig: "test-config", environment: "test" }), false);
});

test("browser authority relay UMD boots in Edge-like window without Node globals", () => {
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, Uint8Array,
    ArrayBuffer, URL, btoa, atob, WeakMap, WeakSet };
  context.globalThis = context;
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-browser-authority-head-relay.js"), "utf8"),
  context, { timeout: 1000 });
  assert.equal(typeof context.RootarkZk1BrowserAuthorityHeadRelay.createProbes, "function");
});

test("browser authority relay aborts stalled fetch and unending signed-proof body within its absolute deadline", async () => {
  const witness = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  let observedSignal;
  const setup = (fetchImpl) => relayBrowser.createProbes({
    origin: "https://example.test/", fetchImpl,
    assertLive: () => {}, csrfToken: () => "test-csrf",
    ownerWitnessKeyRaw: new Uint8Array(raw(witness.publicKey)),
    ownerWitnessSpkiSha256: new Uint8Array(SHA(spki(witness.publicKey))),
    ownerWitnessKeyId: new Uint8Array(crypto.randomBytes(16)),
    catalogAuthorityKeyRaw: new Uint8Array(raw(cas.publicKey)),
    catalogAuthoritySpkiSha256: new Uint8Array(SHA(spki(cas.publicKey))),
    requestTimeoutMs: 100,
  });
  const scope = { account_id: b64(crypto.randomBytes(16)),
    compartment_id: b64(crypto.randomBytes(16)), keyring_id: b64(crypto.randomBytes(16)) };

  const noHeaders = await setup((_url, options) => {
    observedSignal = options.signal;
    return new Promise(() => {});
  });
  await assert.rejects(noHeaders.catalogProbe({ scope, nonce: crypto.randomBytes(32) }),
    /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/);
  assert.equal(observedSignal.aborted, true, "fetch without headers is aborted");

  let streamAborted = false;
  const stalledBody = await setup((_url, options) => {
    observedSignal = options.signal;
    let source;
    const body = new ReadableStream({
      start(controller) {
        source = controller;
        controller.enqueue(new Uint8Array([123])); // Incomplete JSON, then silence.
      },
      cancel() { streamAborted = true; },
    });
    options.signal.addEventListener("abort", () => {
      streamAborted = true;
      try { source.error(new Error("aborted")); } catch (_) { /* reader closed */ }
    }, { once: true });
    return new Response(body, { status: 200,
      headers: { "content-type": "application/json" } });
  });
  await assert.rejects(stalledBody.ownerWitnessProbe({ scope, nonce: crypto.randomBytes(32) }),
    /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/);
  assert.equal(observedSignal.aborted, true, "stream read is aborted after deadline");
  assert.equal(streamAborted, true, "stalled response stream observes cancellation");

  const tooLarge = await setup(async () => new Response(new Uint8Array(16000), {
    status: 200, headers: { "content-type": "application/json" },
  }));
  await assert.rejects(tooLarge.catalogProbe({ scope, nonce: crypto.randomBytes(32) }),
    /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/);
});

test("authenticated fresh witness/CAS relay: browser-pinned SPKI, nonce, account isolation, logout and forged-key denial", async (t) => {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(16), keyring_id: crypto.randomBytes(16) };
  const otherScope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(16), keyring_id: crypto.randomBytes(16) };
  const scopeWire = Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)]));
  const witness = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const untrusted = crypto.generateKeyPairSync("ed25519");
  const keyId = crypto.randomBytes(16);
  const ownerDigest = crypto.randomBytes(32);
  let sessionActive = true, sessionVersion = 3, csrf = "csrf-current-3";
  let witnessCalls = 0, casCalls = 0;
  let revokeDuringWitness = false;
  let maliciousWitness = null;
  const now = () => Math.floor(Date.now() / 1000);
  function checkScope(received) {
    for (const key of Object.keys(scope)) {
      assert.deepEqual(Buffer.from(received[key]), scope[key]);
    }
  }
  const signed = async (fields, prefix, key) => {
    const proof = await z.encodeDeterministic(fields);
    return z.encodeDeterministic({ ...fields,
      signature: crypto.sign(null, Buffer.concat([prefix, Buffer.from(proof)]), key) });
  };
  const store = {
    signedHistoryRequired: true,
    witnessPinned: { keyId, publicKey: witness.publicKey },
    minimumHead: { revision: 1, witnessSequence: 1, digest: ownerDigest },
    nowSeconds: now,
    witnessProvider: {
      async freshHead({ scope: supplied, nonce }) {
        witnessCalls++;
        checkScope(supplied);
        assert.equal(nonce.length, 32);
        if (revokeDuringWitness) {
          sessionActive = false;
          sessionVersion++;
        }
        if (maliciousWitness === "oversize") return Buffer.alloc(8193);
        return signed({ type: "rootark-recovery-witness-head/v1", witness_key_id: keyId,
          ...(maliciousWitness === "scope" ? otherScope : scope),
          current_revision: 1, current_manifest_digest: ownerDigest,
          witness_sequence: 1,
          nonce: maliciousWitness === "nonce" ? crypto.randomBytes(32) : nonce,
          observed_at: now() - (maliciousWitness === "stale" ? 120 : 0),
          status: maliciousWitness === "pending" ? "pending" : "committed",
          pending_reservation_id: null }, OWNER_HEAD,
        maliciousWitness === "signature" ? untrusted.privateKey : witness.privateKey);
      },
    },
    put() {}, get() {},
  };
  const opaqueCatalog = { store, async commit() {}, async read() {},
    authority: { publicKey: cas.publicKey, async readHead({ scope: supplied, nonce }) {
      casCalls++;
      checkScope(supplied);
      assert.equal(nonce.length, 32);
      return signed({ type: "rootark-zk1-opaque-catalog-cas/v1",
        ...scope, sequence: 0, digest: Buffer.alloc(32),
        nonce, observed_at: now() }, CAS_HEAD, cas.privateKey);
    } },
  };
  const app = express();
  // Exercise the same opt-in global-parser selection that server.js uses.
  app.use((req, res, next) => shouldDeferZk1JsonParsing(req, {
    contentConfig: "opted-in-config", environment: "test",
  }) ? next() : express.json()(req, res, next));
  const authenticate = (req, res, next) => {
    const cookie = req.get("cookie") || "";
    if (!sessionActive || cookie !== "rootark_session=owner; rootark_csrf=" + csrf
      || req.get("x-csrf-token") !== csrf) return res.sendStatus(401);
    req.user = { username: "owner", sessionVersion };
    next();
  };
  registerZk1ProtectedObjectRoutes({
    app, store, opaqueCatalog, authenticate,
    requirePermission: (permission) => (req, res, next) => {
      if (!req.user || !["listFiles", "upload"].includes(permission)) return res.sendStatus(403);
      next();
    },
    resolveTrustedScope: (user) => user?.username === "owner" ? scope : null,
  });
  app.use((error, _req, res, _next) => res.status(error.status || 500).end());
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}/`;
  for (const route of ["catalog/authority/witness-head", "catalog/authority/cas-head",
    "CATALOG/AUTHORITY/WITNESS-HEAD/"]) {
    const endpoint = origin + "zk-1/v1/" + route;
    const unauthenticated = await fetch(endpoint, { method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce: b64(crypto.randomBytes(32)), padding: "a".repeat(120_000) }) });
    assert.equal(unauthenticated.status, 401,
      "reject oversized unauthenticated body before any JSON parsing");
    const authenticated = await fetch(endpoint, { method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": csrf,
        cookie: "rootark_session=owner; rootark_csrf=" + csrf },
      body: JSON.stringify({ nonce: b64(crypto.randomBytes(32)), padding: "a".repeat(600) }) });
    assert.equal(authenticated.status, 413,
      "route-local 512-byte parser must enforce limit after authorization");
  }
  assert.equal(witnessCalls, 0);
  assert.equal(casCalls, 0);
  let flipCsrfAfterResponse = false;
  const fetchImpl = async (url, options) => {
    assert.equal(options.method, "POST");
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.redirect, "error");
    assert.equal(options.cache, "no-store");
    assert.equal(options.mode, "same-origin");
    const response = await fetch(url, { ...options, headers: {
      ...options.headers, cookie: "rootark_session=owner; rootark_csrf=" + csrf,
    } });
    if (flipCsrfAfterResponse) csrf = "csrf-next-4";
    return response;
  };
  const options = { origin, fetchImpl,
    assertLive: () => { if (!sessionActive) throw Error("session closed"); },
    csrfToken: () => csrf,
    ownerWitnessKeyRaw: new Uint8Array(raw(witness.publicKey)),
    ownerWitnessSpkiSha256: new Uint8Array(SHA(spki(witness.publicKey))),
    ownerWitnessKeyId: new Uint8Array(keyId),
    catalogAuthorityKeyRaw: new Uint8Array(raw(cas.publicKey)),
    catalogAuthoritySpkiSha256: new Uint8Array(SHA(spki(cas.publicKey))) };
  const relay = await relayBrowser.createProbes(options);
  assert.deepEqual(Buffer.from(relay.ownerWitnessKeyId), keyId);
  const nonce1 = crypto.randomBytes(32), nonce2 = crypto.randomBytes(32);
  const proof1 = await relay.ownerWitnessProbe({ scope: scopeWire, nonce: nonce1 });
  const proof2 = await relay.catalogProbe({ scope: scopeWire, nonce: nonce2 });
  assert.equal(witnessCalls, 1);
  assert.equal(casCalls, 1);
  for (const [proof, nonce, prefix, trusted] of [
    [proof1, nonce1, OWNER_HEAD, witness.publicKey],
    [proof2, nonce2, CAS_HEAD, cas.publicKey],
  ]) {
    const statement = await z.decodeDeterministic(Buffer.from(proof));
    const { signature, ...unsigned } = statement;
    assert.deepEqual(Buffer.from(statement.nonce), nonce);
    checkScope(statement);
    assert.equal(crypto.verify(null, Buffer.concat([prefix,
      Buffer.from(await z.encodeDeterministic(unsigned))]), trusted, signature), true);
    assert.equal(crypto.verify(null, Buffer.concat([prefix,
      Buffer.from(await z.encodeDeterministic(unsigned))]), untrusted.publicKey, signature), false);
  }
  const beforeDuplicate = casCalls;
  await assert.rejects(relay.catalogProbe({ scope: scopeWire, nonce: nonce2 }),
    /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/,
    "browser may not submit a challenge twice, including after successful receipt");
  assert.equal(casCalls, beforeDuplicate, "duplicate fails before egress");
  const duplicatedHttp = await fetch(origin + "zk-1/v1/catalog/authority/witness-head", {
    method: "POST", headers: { "content-type": "application/json",
      "x-csrf-token": csrf, cookie: "rootark_session=owner; rootark_csrf=" + csrf },
    body: JSON.stringify({ nonce: b64(nonce1) }),
  });
  assert.equal(duplicatedHttp.status, 503, "server also refuses same signed challenge");
  assert.equal(witnessCalls, 1);
  // A compromised HTTP relay can forge JSON or replay a real receipt. Even
  // correctly signed but stale, wrong-scope, or wrong-nonce proofs must fail
  // IN THE BROWSER, before being passed to the catalog writer.
  for (const variant of ["replay", "scope", "nonce", "stale", "signature"]) {
    const malicious = await relayBrowser.createProbes({
      ...options, fetchImpl: async (_url, init) => {
        const challenge = Buffer.from(JSON.parse(init.body).nonce, "base64url");
        let proof = proof2;
        if (variant !== "replay") {
          const body = { type: "rootark-zk1-opaque-catalog-cas/v1",
            ...(variant === "scope" ? otherScope : scope),
            sequence: 0, digest: Buffer.alloc(32),
            nonce: variant === "nonce" ? crypto.randomBytes(32) : challenge,
            observed_at: now() - (variant === "stale" ? 120 : 0) };
          proof = await signed(body, CAS_HEAD,
            variant === "signature" ? untrusted.privateKey : cas.privateKey);
        }
        return new Response(JSON.stringify({ proofBase64: b64(proof) }),
          { status: 200, headers: { "content-type": "application/json" } });
      },
    });
    await assert.rejects(malicious.catalogProbe({ scope: scopeWire,
      nonce: crypto.randomBytes(32) }), /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/,
    "browser refuses " + variant + " independently of HTTP session success");
  }

  // A signed proof for a different scope cannot enter the browser writer;
  // the route cannot be retargeted by client-provided account metadata.
  const extra = await fetch(origin + "zk-1/v1/catalog/authority/cas-head", {
    method: "POST", headers: { "content-type": "application/json",
      "x-csrf-token": csrf, cookie: "rootark_session=owner; rootark_csrf=" + csrf },
    body: JSON.stringify({ nonce: b64(crypto.randomBytes(32)),
      scope: Object.fromEntries(Object.entries(otherScope).map(([k, v]) => [k, b64(v)])) }),
  });
  assert.equal(extra.status, 503);
  assert.equal(casCalls, 1, "malformed probe must fail before contacting external CAS");

  await assert.rejects(relayBrowser.createProbes({ ...options,
    catalogAuthoritySpkiSha256: new Uint8Array(SHA(spki(untrusted.publicKey))) }),
  /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/);
  await assert.rejects(relayBrowser.createProbes({ ...options,
    ownerWitnessKeyRaw: new Uint8Array(raw(untrusted.publicKey)) }),
  /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/);

  const serverOnlyKey = await relayBrowser.createProbes({ ...options,
    fetchImpl: async (url, init) => {
      const response = await fetchImpl(url, init);
      const forged = { ...await response.json(),
        authorityPublicKeyBase64: b64(raw(untrusted.publicKey)) };
      return new Response(JSON.stringify(forged), { status: response.status,
        headers: { "content-type": "application/json" } });
    },
  });
  await assert.rejects(serverOnlyKey.catalogProbe({
    scope: scopeWire, nonce: crypto.randomBytes(32) }),
  /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/);

  flipCsrfAfterResponse = true;
  await assert.rejects(relay.catalogProbe({
    scope: scopeWire, nonce: crypto.randomBytes(32) }),
  /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/);
  flipCsrfAfterResponse = false;
  revokeDuringWitness = true;
  await assert.rejects(relay.ownerWitnessProbe({
    scope: scopeWire, nonce: crypto.randomBytes(32) }),
  /ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED/,
  "logout during independently signed witness response denies HTTP egress");
  revokeDuringWitness = false;
  assert.equal(witnessCalls, 2);
  sessionVersion++;
  sessionActive = false;
  await assert.rejects(relay.ownerWitnessProbe({
    scope: scopeWire, nonce: crypto.randomBytes(32) }));
  assert.equal(witnessCalls, 2, "logout denies before contacting independent witness");
  assert.ok(casCalls >= 2);
  sessionActive = true;
  for (const fault of ["scope", "nonce", "stale", "signature", "pending", "oversize"]) {
    maliciousWitness = fault;
    const challenge = crypto.randomBytes(32);
    const remote = await fetch(origin + "zk-1/v1/catalog/authority/witness-head", {
      method: "POST", headers: { "content-type": "application/json",
        "x-csrf-token": csrf, cookie: "rootark_session=owner; rootark_csrf=" + csrf },
      body: JSON.stringify({ nonce: b64(challenge) }),
    });
    assert.equal(remote.status, 503,
      "the authenticated HTTP relay must itself reject the " + fault + " proof");
  }
  maliciousWitness = null;
});
