"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const file = require("../public/client/rootark-zk1-file-content");
const chunks = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const browser = require("../public/client/rootark-zk1-protected-http-client");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } =
  require("../src/routes/zk1ProtectedObjectRoutes");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const randomId = () => crypto.randomBytes(16).toString("base64url");
const base64 = (bytes) => Buffer.from(bytes).toString("base64url");

test("browser UMD executes without Node require and refuses a cross-origin signed transfer", async () => {
  const origin = "https://rootark.example";
  const context = vm.createContext({ crypto: crypto.webcrypto, TextEncoder, TextDecoder,
    URL, btoa, atob, Uint8Array, ArrayBuffer, location: { origin },
    RootarkZk1CiphertextDownloadIntegrity: require("../public/client/rootark-zk1-ciphertext-download-integrity"),
  });
  const script = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-protected-http-client.js"), "utf8");
  vm.runInContext(script, context);
  assert.equal(typeof context.RootarkZk1ProtectedHttpClient.signProtectedContentOperation,
    "function", "plain browser build must export a live WebCrypto API without CommonJS");
  const pkcs8 = crypto.generateKeyPairSync("ed25519").privateKey
    .export({ format: "der", type: "pkcs8" });
  context.signer = await crypto.webcrypto.subtle.importKey("pkcs8", pkcs8,
    "Ed25519", false, ["sign"]);
  context.metadata = {
    account_id: randomId(), compartment_id: base64(Buffer.from("browser-demo")),
    keyring_id: randomId(),
  };
  context.objectId = randomId();
  context.manifest = crypto.randomBytes(32);
  await vm.runInContext(`(async () => {
    const input = {
      signerKey: signer, scope: { ...metadata },
      deviceId: "device-1", operation: "get", objectId,
      expectedObjectRevision: null, manifestRevision: 1,
      manifestDigest: manifest, epoch: 1, nowSeconds: 1400,
      ciphertext: null,
    };
    const signed = await RootarkZk1ProtectedHttpClient.signProtectedContentOperation(input);
    let calls = 0;
    try {
      await RootarkZk1ProtectedHttpClient.postProtectedCiphertextRead({
        origin: "https://foreign.example/", request: signed,
        fetchImpl: () => { calls++; throw Error("SHOULD_NOT_FETCH"); },
        expectedObjectRevision: 1, expectedRoot: new Uint8Array(32),
        cek: null, metadata: {},
      });
      throw Error("ACCEPTED_CROSS_ORIGIN");
    } catch (error) {
      if (error.message !== "ZK_BROWSER_CONTENT_UNAVAILABLE") throw error;
    }
    if (calls !== 0) throw Error("CROSS_ORIGIN_REQUEST_SENT");
  })()`, context);
});

test("browser WebCrypto Ed25519 canonical-CBOR signed encrypted HTTP PUT/GET obey server admission and verified ciphertext root", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-browser-protected-http-"));
  const state = await fixtures.createInitialState(2);
  const scope = state.scope;
  const scopeWire = Object.fromEntries(Object.entries(scope).map(([key, value]) => [key, base64(value)]));
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  let gateOpen = true;
  let signedHead = state.headManifest;
  let admissions = 0;
  let emittedBody = "";
  const manifestDigest = () => v2.recoveryManifestDigestV2(signedHead);
  const witnessProvider = {
    async freshHead({ nonce }) {
      const body = {
        type: "rootark-recovery-witness-head/v1", witness_key_id: witnessKeyId,
        ...scope, current_revision: signedHead.revision,
        current_manifest_digest: await manifestDigest(),
        witness_sequence: signedHead.revision, nonce, observed_at: 1400,
        status: gateOpen ? "committed" : "pending",
        pending_reservation_id: gateOpen ? null : crypto.randomBytes(16),
      };
      const signature = crypto.sign(null, Buffer.concat([
        HEAD_DOMAIN, Buffer.from(await z.encodeDeterministic(body)),
      ]), witnessKeys.privateKey);
      return z.encodeDeterministic({ ...body, signature });
    },
    async beginIoAdmission({ revision, digest }) {
      if (!gateOpen || revision !== signedHead.revision
        || !Buffer.from(digest).equals(Buffer.from(await manifestDigest()))) {
        throw new Error("NO_ACTIVE_WITNESS_ADMISSION");
      }
      ++admissions;
      return { admissionId: crypto.randomBytes(16), proceed: true };
    },
    async finishIoAdmission() { return { status: "completed" }; },
  };
  const store = new Zk1ProtectedObjectStore(path.join(dir, "content.sqlite"), {
    trustedScope: scope, witnessPinned: {
      keyId: witnessKeyId, publicKey: witnessKeys.publicKey,
    }, minimumHead: { revision: 1,
      witnessSequence: 1, digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    manifestProvider: () => z.encodeDeterministic(signedHead),
    witnessProvider, bootstrapNew: true, admissionRequired: true,
    nowSeconds: () => 1400,
  });
  const app = express();
  const authenticate = (req, res, next) => {
    if (req.get("x-fixture-session") !== "owner") return res.sendStatus(401);
    req.user = { username: "owner" }; next();
  };
  registerZk1ProtectedObjectRoutes({ app, store, authenticate,
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const sessionFetch = (url, options) => {
    emittedBody = String(options.body);
    return fetch(url, { ...options, headers: {
      ...options.headers, "x-fixture-session": "owner",
    } });
  };
  const device = signedHead.devices[0];
  const privateKey = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
  const webKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const parameters = { signerKey: webKey, scope: scopeWire,
    deviceId: device.device_id,
    manifestRevision: signedHead.revision, manifestDigest: await manifestDigest(),
    epoch: signedHead.current_epoch, nowSeconds: 1400 };
  const metadata = { ...scopeWire, object_id: randomId(),
    version_id: randomId(), parent_version_id: null,
    epoch: signedHead.current_epoch, kind: "file" };
  const cek = await file.generateFileCek();
  // This deliberately exceeds an 8 KiB JSON response to catch accidental
  // use of the small CBOR-signature bound for legitimate ciphertext downloads.
  const plaintext = Buffer.concat([Buffer.from("only browser decrypts: segredo local 2026"),
    crypto.randomBytes(80 * 1024)]);
  const encrypted = await file.encryptFile({ cek, metadata,
    name: "hidden-file.txt", mediaType: "text/plain", data: plaintext });
  const signedPut = await browser.signProtectedContentOperation({
    ...parameters, operation: "put", objectId: metadata.object_id,
    expectedObjectRevision: null, ciphertext: encrypted,
  });
  const serverFormat = Object.fromEntries(Object.entries(signedPut.authorization)
    .map(([name, value]) => [name,
      ["account_id", "compartment_id", "keyring_id", "manifest_digest", "nonce",
        "ciphertext_digest"].includes(name) && value !== null
        ? Buffer.from(value, "base64url") : value]));
  assert.equal(crypto.verify(null, await contentAuthorizationMessageV1(serverFormat),
    crypto.createPublicKey(privateKey),
    Buffer.from(signedPut.signatureBase64, "base64url")), true,
  "browser canonical CBOR must exactly match backend RFC8949 message");
  assert.equal((await browser.postProtectedCiphertextPut({
    origin, request: signedPut, fetchImpl: sessionFetch,
  })).revision, 1);
  assert.equal(emittedBody.includes("segredo local"), false);
  assert.equal(emittedBody.includes("hidden-file.txt"), false);
  assert.equal(admissions, 1, "browser route must pass live witness admission");
  await assert.rejects(browser.postProtectedCiphertextPut({
    origin, request: signedPut, fetchImpl: sessionFetch,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/, "identical signed nonce never replays");
  await assert.rejects(browser.postProtectedCiphertextPut({
    origin: "http://example.com/", request: signedPut,
    fetchImpl: () => { throw new Error("unexpected cross-origin network call"); },
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "insecure cross-origin HTTP must be rejected without a network call");

  const expected = chunks.createCiphertextRootBuilder(1);
  await expected.append(encrypted);
  const expectedRoot = await expected.finish();
  const signedGet = await browser.signProtectedContentOperation({
    ...parameters, operation: "get", objectId: metadata.object_id,
    expectedObjectRevision: null, ciphertext: null,
  });
  const opened = await browser.postProtectedCiphertextRead({
    origin, request: signedGet, fetchImpl: sessionFetch,
    expectedObjectRevision: 1, expectedRoot, cek, metadata,
  });
  assert.equal(opened.name, "hidden-file.txt");
  assert.deepEqual(Buffer.from(opened.data), plaintext);
  opened.data.fill(0);
  assert.equal(opened.authorizesRelease, false,
    "browser verifier cannot override independently required server admission");
  const corruptResponse = async (url, options) => {
    const received = await sessionFetch(url, options);
    const decoded = await received.json();
    decoded.ciphertextBase64 = base64(crypto.randomBytes(150));
    return new Response(JSON.stringify(decoded), { status: 200,
      headers: { "content-type": "application/json" } });
  };
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: null, ciphertext: null,
    }), fetchImpl: corruptResponse, expectedObjectRevision: 1,
    expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "even authenticated HTTP's ciphertext must match the independently pinned root");
  const rollbackResponse = async (url, options) => {
    const received = await sessionFetch(url, options);
    const decoded = await received.json();
    decoded.revision = 0;
    return new Response(JSON.stringify(decoded), { status: 200,
      headers: { "content-type": "application/json" } });
  };
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: null, ciphertext: null,
    }), fetchImpl: rollbackResponse, expectedObjectRevision: 1,
    expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "response revision rollback is rejected before ciphertext decryption");
  const mutating = { ...parameters, scope: { ...scopeWire },
    operation: "get", objectId: metadata.object_id,
    expectedObjectRevision: null, ciphertext: null,
    manifestDigest: Buffer.from(parameters.manifestDigest) };
  const duringSign = browser.signProtectedContentOperation(mutating);
  mutating.objectId = randomId();
  mutating.scope.account_id = randomId();
  mutating.manifestDigest.fill(0);
  const snapshotted = await duringSign;
  assert.equal(snapshotted.authorization.object_id, metadata.object_id);
  assert.equal(snapshotted.authorization.account_id, scopeWire.account_id);
  assert.equal(snapshotted.authorization.manifest_digest, base64(parameters.manifestDigest));
  assert.equal((await browser.postProtectedCiphertextRead({
    origin, request: snapshotted, fetchImpl: sessionFetch,
    expectedObjectRevision: 1, expectedRoot, cek, metadata,
  })).name, "hidden-file.txt", "form mutation during WebCrypto may not retarget a signed GET");
  const wrongRoot = crypto.randomBytes(32);
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: null, ciphertext: null,
    }), fetchImpl: sessionFetch, expectedObjectRevision: 1,
    expectedRoot: wrongRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/, "wrong independently supplied root denies before decrypt");

  const forgedKey = crypto.generateKeyPairSync("ed25519");
  const forged = await crypto.webcrypto.subtle.importKey("pkcs8",
    forgedKey.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, signerKey: forged, operation: "get",
      objectId: metadata.object_id, expectedObjectRevision: null, ciphertext: null,
    }), fetchImpl: sessionFetch, expectedObjectRevision: 1,
    expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/, "valid Ed25519 on untrusted device key denies");
  await fixtures.appendDeviceRevocation(state, device.device_id);
  signedHead = state.headManifest;
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, manifestRevision: signedHead.revision,
      manifestDigest: await manifestDigest(), epoch: signedHead.current_epoch,
      operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: null, ciphertext: null,
    }), fetchImpl: sessionFetch, expectedObjectRevision: 1,
    expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "an actual signed manifest revocation invalidates the formerly active device even with its key");
  gateOpen = false;
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: null, ciphertext: null,
    }), fetchImpl: sessionFetch, expectedObjectRevision: 1,
    expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/, "pending witness never releases ciphertext");
  assert.ok(admissions >= 3);
});
