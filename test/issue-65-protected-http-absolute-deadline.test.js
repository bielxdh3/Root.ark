"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");

const source = fs.readFileSync(path.join(__dirname,
  "../public/client/rootark-zk1-protected-http-client.js"), "utf8");
const origin = "https://rootark.example";

async function signedClient() {
  const timers = new Set();
  const context = vm.createContext({
    crypto: crypto.webcrypto, TextEncoder, TextDecoder, URL, Uint8Array,
    ArrayBuffer, AbortController, ReadableStream, Headers, btoa, atob,
    location: { origin },
    RootarkZk1CiphertextDownloadIntegrity:
      require("../public/client/rootark-zk1-ciphertext-download-integrity"),
    RootarkZk1OwnerCiphertextRootCheckpoint:
      require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint"),
    setTimeout(callback, ms) {
      const timer = setTimeout(() => { timers.delete(timer); callback(); },
        Math.min(ms, 65));
      timers.add(timer);
      return timer;
    },
    clearTimeout(timer) { clearTimeout(timer); timers.delete(timer); },
  });
  vm.runInContext(source, context);
  const signer = crypto.generateKeyPairSync("ed25519");
  const privateKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    signer.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  context.signerKey = privateKey;
  context.fields = {
    operation: "put", objectId: crypto.randomBytes(16).toString("base64url"),
    expectedObjectRevision: null, manifestRevision: 1,
    manifestDigest: crypto.randomBytes(32), epoch: 1, nowSeconds: 1400,
    ciphertext: crypto.randomBytes(16), deviceId: "device-1",
    scope: { account_id: crypto.randomBytes(16).toString("base64url"),
      compartment_id: Buffer.from("scope").toString("base64url"),
      keyring_id: crypto.randomBytes(16).toString("base64url") },
  };
  const request = await vm.runInContext(`RootarkZk1ProtectedHttpClient
    .signProtectedContentOperation({ ...fields, scope: { ...fields.scope }, signerKey })`, context);
  return { api: context.RootarkZk1ProtectedHttpClient, request,
    clear() { for (const timer of timers) clearTimeout(timer); } };
}

function jsonResponse(body, status = 201) {
  return { status, headers: new Headers({ "content-type": "application/json" }),
    body: new ReadableStream({ start(controller) {
      controller.enqueue(new TextEncoder().encode(body));
      controller.close();
    } }),
  };
}

test("signed HTTP denies stalled headers even if fetch ignores AbortSignal", async () => {
  const fixture = await signedClient();
  let aborted = false;
  try {
    await assert.rejects(Promise.race([
      fixture.api.postProtectedCiphertextPut({ origin, request: fixture.request,
        fetchImpl: (_url, options) => {
          assert.equal(options.redirect, "error");
          options.signal.addEventListener("abort", () => { aborted = true; });
          return new Promise(() => {});
        } }),
      new Promise((_, reject) => setTimeout(() => reject(Error("MISSING_ABSOLUTE_DEADLINE")), 450)),
    ]), /ZK_BROWSER_CONTENT_UNAVAILABLE/);
    assert.equal(aborted, true);
  } finally { fixture.clear(); }
});

test("signed HTTP denies a partial JSON body without a terminal chunk", async () => {
  const fixture = await signedClient();
  let aborted = false;
  try {
    await assert.rejects(Promise.race([
      fixture.api.postProtectedCiphertextPut({ origin, request: fixture.request,
        fetchImpl: (_url, options) => {
          options.signal.addEventListener("abort", () => { aborted = true; });
          return Promise.resolve({ status: 201, headers: new Headers({
            "content-type": "application/json",
          }), body: new ReadableStream({ start(controller) {
            controller.enqueue(new TextEncoder().encode("{"));
          } }) });
        } }),
      new Promise((_, reject) => setTimeout(() => reject(Error("MISSING_BODY_DEADLINE")), 450)),
    ]), /ZK_BROWSER_CONTENT_UNAVAILABLE/);
    assert.equal(aborted, true);
  } finally { fixture.clear(); }
});

test("bounded signed HTTP retains valid same-origin JSON acknowledgements", async () => {
  const fixture = await signedClient();
  try {
    const actual = await fixture.api.postProtectedCiphertextPut({
      origin, request: fixture.request,
      fetchImpl: (_url, options) => {
        assert.equal(options.redirect, "error");
        assert.ok(options.signal instanceof AbortSignal);
        return Promise.resolve(jsonResponse(JSON.stringify({
          id: fixture.request.authorization.object_id, revision: 1,
        })));
      },
    });
    assert.equal(actual.revision, 1);
    assert.equal(actual.id, fixture.request.authorization.object_id);
  } finally { fixture.clear(); }
});
