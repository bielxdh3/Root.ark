"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const express = require("express");
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

test("browser authority relay UMD boots in Edge-like window without Node globals", () => {
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, Uint8Array,
    ArrayBuffer, URL, btoa, atob, WeakMap, WeakSet };
  context.globalThis = context;
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-browser-authority-head-relay.js"), "utf8"),
  context, { timeout: 1000 });
  assert.equal(typeof context.RootarkZk1BrowserAuthorityHeadRelay.createProbes, "function");
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
    signedHistoryRequired: true, witnessProvider: {
      async freshHead({ scope: supplied, nonce }) {
        witnessCalls++;
        checkScope(supplied);
        assert.equal(nonce.length, 32);
        if (revokeDuringWitness) {
          sessionActive = false;
          sessionVersion++;
        }
        return signed({ type: "rootark-recovery-witness-head/v1", witness_key_id: keyId,
          ...scope, current_revision: 1, current_manifest_digest: ownerDigest,
          witness_sequence: 1, nonce, observed_at: now(),
          status: "committed", pending_reservation_id: null }, OWNER_HEAD, witness.privateKey);
      },
    },
    put() {}, get() {},
  };
  const opaqueCatalog = { store, async commit() {}, async read() {},
    authority: { async readHead({ scope: supplied, nonce }) {
      casCalls++;
      checkScope(supplied);
      assert.equal(nonce.length, 32);
      return signed({ type: "rootark-zk1-opaque-catalog-cas/v1",
        ...scope, sequence: 0, digest: Buffer.alloc(32),
        nonce, observed_at: now() }, CAS_HEAD, cas.privateKey);
    } },
  };
  const app = express();
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
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}/`;
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
});
