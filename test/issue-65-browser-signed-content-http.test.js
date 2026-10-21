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
const reconciliation = require("../public/client/rootark-zk1-uncertain-put-reconciliation");
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
  vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-ciphertext-chunk-root.js"), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-uncertain-put-reconciliation.js"), "utf8"), context);
  assert.equal(typeof context.RootarkZk1ProtectedHttpClient.signProtectedContentOperation,
    "function", "plain browser build must export a live WebCrypto API without CommonJS");
  assert.equal(typeof context.RootarkZk1UncertainPutReconciliation.reconcileUncertainProtectedPut,
    "function", "uncertain PUT verifier must load in a plain browser without require");
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
  const storeFilename = path.join(dir, "content.sqlite");
  const storeConfig = {
    trustedScope: scope, witnessPinned: {
      keyId: witnessKeyId, publicKey: witnessKeys.publicKey,
    }, minimumHead: { revision: 1,
      witnessSequence: 1, digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    manifestProvider: () => z.encodeDeterministic(signedHead),
    witnessProvider, bootstrapNew: true, admissionRequired: true,
    nowSeconds: () => 1400,
  };
  let store = new Zk1ProtectedObjectStore(storeFilename, storeConfig);
  const liveStore = {
    put: (...args) => store.put(...args),
    get: (...args) => store.get(...args),
    runWithAdmission: (...args) => store.runWithAdmission(...args),
  };
  const app = express();
  const authenticate = (req, res, next) => {
    if (req.get("x-fixture-session") !== "owner") return res.sendStatus(401);
    req.user = { username: "owner" }; next();
  };
  registerZk1ProtectedObjectRoutes({ app, store: liveStore, authenticate,
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
  let allPutRequests = 0;
  const sessionFetch = (url, options) => {
    if (url.endsWith("/zk-1/v1/content/put") && options?.method === "POST") {
      allPutRequests++;
    }
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

  const secondMetadata = { ...metadata, version_id: randomId(),
    parent_version_id: metadata.version_id };
  const secondCek = await file.generateFileCek();
  const secondPlaintext = crypto.randomBytes(340);
  const secondCiphertext = await file.encryptFile({
    cek: secondCek, metadata: secondMetadata, name: "updated-hidden-file.txt",
    mediaType: "text/plain", data: secondPlaintext,
  });
  assert.equal((await browser.postProtectedCiphertextPut({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, operation: "put", objectId: metadata.object_id,
      expectedObjectRevision: 1, ciphertext: secondCiphertext,
    }), fetchImpl: sessionFetch,
  })).revision, 2);
  const historicalGet = await browser.signProtectedContentOperation({
    ...parameters, operation: "get", objectId: metadata.object_id,
    expectedObjectRevision: 1, expectedCiphertextDigest:
      crypto.createHash("sha256").update(encrypted).digest(), ciphertext: null,
  });
  const historicalServerFormat = Object.fromEntries(Object.entries(historicalGet.authorization)
    .map(([name, value]) => [name,
      ["account_id", "compartment_id", "keyring_id", "manifest_digest", "nonce",
        "ciphertext_digest"].includes(name) && value !== null
        ? Buffer.from(value, "base64url") : value]));
  assert.equal(crypto.verify(null, await contentAuthorizationMessageV1(historicalServerFormat),
    crypto.createPublicKey(privateKey),
    Buffer.from(historicalGet.signatureBase64, "base64url")), true,
  "new signed historical GET must use the existing canonical CBOR domain with revision and digest");
  const oldOpened = await browser.postProtectedCiphertextRead({
    origin, request: historicalGet, fetchImpl: async (url, options) => {
      const response = await sessionFetch(url, options);
      assert.equal(response.status, 200, "historical signed HTTP GET must pass backend admission");
      const actual = await response.clone().json();
      assert.equal(actual.id, metadata.object_id);
      assert.equal(actual.revision, 1);
      assert.equal(actual.epoch, metadata.epoch);
      assert.equal(crypto.createHash("sha256").update(Buffer.from(actual.ciphertextBase64, "base64url"))
        .digest("base64url"), historicalGet.authorization.ciphertext_digest,
      "historical HTTP ciphertext SHA must match the signed expected digest");
      const assertBuilder = chunks.createCiphertextRootBuilder(1);
      await assertBuilder.append(Buffer.from(actual.ciphertextBase64, "base64url"));
      assert.deepEqual(Buffer.from(await assertBuilder.finish()), Buffer.from(expectedRoot),
        "historical HTTP ciphertext root must equal independently held root");
      return response;
    },
    expectedObjectRevision: 1, expectedRoot, cek, metadata,
  });
  assert.deepEqual(Buffer.from(oldOpened.data), plaintext,
    "immutable version 1 remains available after signed overwrite with version 2");
  oldOpened.data.fill(0);
  const simultaneous = await Promise.all(Array.from({ length: 6 }, async () => {
    const signed = await browser.signProtectedContentOperation({
      ...parameters, operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: 1, expectedCiphertextDigest:
        crypto.createHash("sha256").update(encrypted).digest(), ciphertext: null,
    });
    return browser.postProtectedCiphertextRead({
      origin, request: signed, fetchImpl: sessionFetch,
      expectedObjectRevision: 1, expectedRoot, cek, metadata,
    });
  }));
  for (const openedCopy of simultaneous) {
    assert.deepEqual(Buffer.from(openedCopy.data), plaintext,
      "parallel authenticated HTTP readers cannot substitute the current ciphertext");
    openedCopy.data.fill(0);
  }
  const secondBuilder = chunks.createCiphertextRootBuilder(1);
  await secondBuilder.append(secondCiphertext);
  const secondRoot = await secondBuilder.finish();
  const newer = await browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: 2, expectedCiphertextDigest:
        crypto.createHash("sha256").update(secondCiphertext).digest(), ciphertext: null,
    }), fetchImpl: sessionFetch, expectedObjectRevision: 2,
    expectedRoot: secondRoot, cek: secondCek, metadata: secondMetadata,
  });
  assert.deepEqual(Buffer.from(newer.data), secondPlaintext);
  newer.data.fill(0);
  const thirdMetadata = { ...metadata, version_id: randomId(),
    parent_version_id: secondMetadata.version_id };
  const thirdCek = await file.generateFileCek();
  const thirdPlaintext = crypto.randomBytes(570);
  const thirdCiphertext = await file.encryptFile({
    cek: thirdCek, metadata: thirdMetadata, name: "uncertain-file.txt",
    mediaType: "application/octet-stream", data: thirdPlaintext,
  });
  const thirdRootBuilder = chunks.createCiphertextRootBuilder(1);
  await thirdRootBuilder.append(thirdCiphertext);
  const thirdRoot = await thirdRootBuilder.finish();
  const thirdPlaintextSha = crypto.createHash("sha256").update(thirdPlaintext).digest();
  const uncertainPut = await browser.signProtectedContentOperation({
    ...parameters, operation: "put", objectId: metadata.object_id,
    expectedObjectRevision: 2, ciphertext: thirdCiphertext,
  });
  let sentPut = 0;
  await assert.rejects(browser.postProtectedCiphertextPut({
    origin, request: uncertainPut, fetchImpl: async (url, options) => {
      const response = await sessionFetch(url, options);
      sentPut++;
      assert.equal(response.status, 200);
      throw new Error("connection lost after server committed, before client read ACK");
    },
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/);
  assert.equal(sentPut, 1);
  assert.equal(store.db.prepare("SELECT revision FROM zk_content_object WHERE id=?")
    .get(metadata.object_id).revision, 3);
  const putCountBeforeReconciliation = allPutRequests;
  const snapshot = Buffer.from(thirdCiphertext);
  const inputs = {
    origin, fetchImpl: sessionFetch, signer: { ...parameters },
    objectId: metadata.object_id, previousRevision: 2,
    ciphertext: Buffer.from(thirdCiphertext), expectedRoot: Buffer.from(thirdRoot),
    expectedPlaintextSha256: Buffer.from(thirdPlaintextSha),
    cek: thirdCek, metadata: { ...thirdMetadata },
  };
  for (const [field, size] of [
    ["ciphertext", 4 * 1024 * 1024 + 1],
    ["expectedRoot", 33],
    ["expectedPlaintextSha256", 33],
  ]) {
    const oversized = new Uint8Array(size);
    const buffer = oversized.buffer;
    const originalSlice = buffer.slice.bind(buffer);
    let cloneCalls = 0;
    buffer.slice = (...arguments_) => {
      cloneCalls++;
      return originalSlice(...arguments_);
    };
    await assert.rejects(reconciliation.reconcileUncertainProtectedPut({
      ...inputs, [field]: oversized,
    }), /ZK_UNCERTAIN_PUT_NOT_RECONCILED/);
    assert.equal(cloneCalls, 0,
      field + " must be rejected by byteLength BEFORE cloning or allocating an oversized buffer");
  }
  const oversizedArrayBuffer = new ArrayBuffer(33);
  const savedSlice = oversizedArrayBuffer.slice.bind(oversizedArrayBuffer);
  let arrayBufferCloneCalls = 0;
  oversizedArrayBuffer.slice = (...args) => {
    arrayBufferCloneCalls++;
    return savedSlice(...args);
  };
  await assert.rejects(reconciliation.reconcileUncertainProtectedPut({
    ...inputs, expectedRoot: oversizedArrayBuffer,
  }), /ZK_UNCERTAIN_PUT_NOT_RECONCILED/);
  assert.equal(arrayBufferCloneCalls, 0,
    "raw ArrayBuffer inputs must also reject before allocation");
  const uncertain = await reconciliation.reconcileUncertainProtectedPut(inputs);
  assert.equal(uncertain.objectId, metadata.object_id);
  assert.equal(uncertain.revision, 3);
  assert.equal(uncertain.clientReadbackVerified, true);
  assert.equal(uncertain.authorizesCutover, false);
  assert.equal(uncertain.independentDurableCommitProven, false);
  assert.equal(sentPut, 1, "reconciliation must never resend uncertain PUT");
  assert.equal(allPutRequests, putCountBeforeReconciliation,
    "all actual authenticated PUT HTTP calls are counted, not just the lost-ACK wrapper");
  assert.deepEqual(Buffer.from(thirdCiphertext), snapshot, "helper never destroys caller ciphertext");
  const mutableInputs = {
    ...inputs, signer: { ...inputs.signer, scope: { ...scopeWire },
      manifestDigest: Buffer.from(parameters.manifestDigest) },
    metadata: { ...thirdMetadata }, ciphertext: Buffer.from(thirdCiphertext),
    expectedRoot: Buffer.from(thirdRoot),
    expectedPlaintextSha256: Buffer.from(thirdPlaintextSha),
  };
  const whileSigning = reconciliation.reconcileUncertainProtectedPut(mutableInputs);
  mutableInputs.objectId = randomId();
  mutableInputs.metadata.object_id = randomId();
  mutableInputs.metadata.version_id = randomId();
  mutableInputs.signer.scope.keyring_id = randomId();
  mutableInputs.signer.manifestDigest.fill(0);
  mutableInputs.ciphertext.fill(0);
  mutableInputs.expectedRoot.fill(0);
  mutableInputs.expectedPlaintextSha256.fill(0);
  assert.equal((await whileSigning).clientReadbackVerified, true,
    "all signed identity, content, root and digest inputs must be snapshotted before first await");
  assert.equal(sentPut, 1, "a successful reconciliation never writes another PUT");
  assert.equal(allPutRequests, putCountBeforeReconciliation,
    "parallel or delayed reconciliation GET must not issue any HTTP PUT");
  // Reopen the durable backend while retaining the SAME Express route and
  // authenticated network boundary. A lost ACK cannot be treated as failure
  // to persist, and an old PUT nonce cannot become valid after restart.
  store.close();
  store = new Zk1ProtectedObjectStore(storeFilename, {
    ...storeConfig, bootstrapNew: false,
  });
  assert.equal(store.db.prepare("SELECT revision FROM zk_content_object WHERE id=?")
    .get(metadata.object_id).revision, 3);
  assert.equal((await reconciliation.reconcileUncertainProtectedPut(inputs))
    .clientReadbackVerified, true,
  "reconciliation must survive physical SQLite close/open with no synthetic rewrite");
  await assert.rejects(browser.postProtectedCiphertextPut({
    origin, request: uncertainPut, fetchImpl: sessionFetch,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "lost-ACK PUT nonce remains tombstoned after physical SQLite restart");
  assert.equal(allPutRequests, putCountBeforeReconciliation + 1,
    "only the explicit adversarial replay attempt increments PUT calls");
  await assert.rejects(reconciliation.reconcileUncertainProtectedPut({
    ...inputs, previousRevision: 3,
  }), /ZK_UNCERTAIN_PUT_NOT_RECONCILED/,
  "unsigned future version is not fabricated after lost ACK");
  await assert.rejects(reconciliation.reconcileUncertainProtectedPut({
    ...inputs, expectedPlaintextSha256: crypto.randomBytes(32),
  }), /ZK_UNCERTAIN_PUT_NOT_RECONCILED/,
  "a ciphertext correct under AEAD with incorrect user plaintext digest still denies");
  let tamperedFetchCalls = 0;
  await assert.rejects(reconciliation.reconcileUncertainProtectedPut({
    ...inputs, expectedRoot: crypto.randomBytes(32),
    fetchImpl: async () => { tamperedFetchCalls++; throw Error("unexpected network"); },
  }), /ZK_UNCERTAIN_PUT_NOT_RECONCILED/);
  assert.equal(tamperedFetchCalls, 0, "local root mismatch must reject before GET");
  await assert.rejects(reconciliation.reconcileUncertainProtectedPut({
    ...inputs, fetchImpl: async (url, options) => {
      const response = await sessionFetch(url, options);
      const forged = await response.json();
      forged.ciphertextBase64 = base64(crypto.randomBytes(190));
      return new Response(JSON.stringify(forged), { status: 200,
        headers: { "content-type": "application/json" } });
    },
  }), /ZK_UNCERTAIN_PUT_NOT_RECONCILED/,
  "a compromised protected HTTP readback cannot turn a lost ACK into false verification");
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: historicalGet, fetchImpl: sessionFetch,
    expectedObjectRevision: 1, expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/, "signed historical GET nonce cannot replay");
  const wrongHistoricalDigest = await browser.signProtectedContentOperation({
    ...parameters, operation: "get", objectId: metadata.object_id,
    expectedObjectRevision: 1, expectedCiphertextDigest:
      crypto.createHash("sha256").update(secondCiphertext).digest(),
    ciphertext: null,
  });
  const deniedHistoricResponse = await sessionFetch(origin + "/zk-1/v1/content/read", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(wrongHistoricalDigest),
  });
  assert.equal(deniedHistoricResponse.status, 409,
    "signed mismatched ciphertext digest must be rejected by SQLite before network egress");
  const historicWrongRevision = await browser.signProtectedContentOperation({
    ...parameters, operation: "get", objectId: metadata.object_id,
    expectedObjectRevision: 3, expectedCiphertextDigest:
      crypto.createHash("sha256").update(encrypted).digest(), ciphertext: null,
  });
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: historicWrongRevision, fetchImpl: sessionFetch,
    expectedObjectRevision: 3, expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "no history fallback may serve the latest revision when signed revision is missing");
  const mutableHistoricalDigest = crypto.createHash("sha256").update(encrypted).digest();
  const signedPending = browser.signProtectedContentOperation({
    ...parameters, operation: "get", objectId: metadata.object_id,
    expectedObjectRevision: 1, expectedCiphertextDigest: mutableHistoricalDigest,
    ciphertext: null,
  });
  mutableHistoricalDigest.fill(0);
  const immutableSignedGet = await signedPending;
  assert.equal(immutableSignedGet.authorization.ciphertext_digest,
    crypto.createHash("sha256").update(encrypted).digest("base64url"),
  "historiographically signed digest is a snapshot, not mutable caller memory");
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: immutableSignedGet, fetchImpl: sessionFetch,
    expectedObjectRevision: 2, expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "the read API must reject a different revision before sending signed HTTP operation");
  assert.equal((await browser.postProtectedCiphertextRead({
    origin, request: immutableSignedGet, fetchImpl: sessionFetch,
    expectedObjectRevision: 1, expectedRoot, cek, metadata,
  })).name, "hidden-file.txt");
  await assert.rejects(browser.signProtectedContentOperation({
    ...parameters, operation: "get", objectId: metadata.object_id,
    expectedObjectRevision: 1, ciphertext: null,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/, "historical GET requires a matching signed digest");

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
  gateOpen = false;
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: 1, expectedCiphertextDigest:
        crypto.createHash("sha256").update(encrypted).digest(), ciphertext: null,
    }), fetchImpl: sessionFetch, expectedObjectRevision: 1,
    expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "a pending witness forbids historical ciphertext GET even with valid signer and digest");
  gateOpen = true;
  await fixtures.appendDeviceRevocation(state, device.device_id);
  signedHead = state.headManifest;
  await assert.rejects(reconciliation.reconcileUncertainProtectedPut({
    ...inputs, signer: { ...parameters, manifestRevision: signedHead.revision,
      manifestDigest: await manifestDigest(), epoch: signedHead.current_epoch },
  }), /ZK_UNCERTAIN_PUT_NOT_RECONCILED/,
  "revoked signer cannot reconcile old ciphertext merely because bytes remain in SQLite");
  const otherDevice = signedHead.devices.find((item) =>
    item.device_id !== device.device_id && item.revoked_at_epoch === null);
  assert.ok(otherDevice, "new signed manifest retains a separately trusted active device");
  const otherPrivate = state.actors.get(Buffer.from(otherDevice.authorization_key_id).toString("hex"));
  const otherWebKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    otherPrivate.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const currentEpochParameters = {
    ...parameters, signerKey: otherWebKey, deviceId: otherDevice.device_id,
    manifestRevision: signedHead.revision,
    manifestDigest: await manifestDigest(), epoch: signedHead.current_epoch,
  };
  const olderEpochRead = await browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...currentEpochParameters, operation: "get",
      objectId: metadata.object_id, expectedObjectRevision: 1,
      expectedCiphertextDigest: crypto.createHash("sha256").update(encrypted).digest(),
      ciphertext: null,
    }), fetchImpl: sessionFetch, expectedObjectRevision: 1,
    expectedRoot, cek, metadata,
  });
  assert.deepEqual(Buffer.from(olderEpochRead.data), plaintext,
    "newly active current-epoch signer can access retained old-epoch ciphertext with its separately held old CEK");
  olderEpochRead.data.fill(0);
  assert.notEqual(signedHead.current_epoch, metadata.epoch,
    "test must prove real keyring epoch transition, not a same-epoch fixture");
  await assert.rejects(browser.postProtectedCiphertextRead({
    origin, request: await browser.signProtectedContentOperation({
      ...parameters, manifestRevision: signedHead.revision,
      manifestDigest: await manifestDigest(), epoch: signedHead.current_epoch,
      operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: 1, expectedCiphertextDigest:
        crypto.createHash("sha256").update(encrypted).digest(), ciphertext: null,
    }), fetchImpl: sessionFetch, expectedObjectRevision: 1,
    expectedRoot, cek, metadata,
  }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "signed revoked device cannot open archived old ciphertext under current live head");
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
