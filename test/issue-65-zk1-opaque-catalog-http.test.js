"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { spawn, execFileSync } = require("node:child_process");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixture = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } =
  require("../src/routes/zk1ProtectedObjectRoutes");
const { Zk1OpaqueCatalog, catalogOperationObjectId, catalogHeaderMessage,
  catalogHeadDigest, catalogPageDigest, catalogCasDomain } =
  require("../src/services/zk1OpaqueCatalog");
const { verifyZk1OpaqueCatalogPage, sealZk1CatalogMetadataV1,
  openZk1CatalogMetadataV1 } =
  require("../src/crypto/rootark-zk1-opaque-catalog-client-v1");

const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest();

test("ZK1 opaque catalog: two owner-enrolled device sessions enumerate signed versions and GET; no names, stale/forged/missing/replay/rollback rejected", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-opaque-catalog-"));
  const state = await fixture.createInitialState(2);
  let manifest = state.headManifest;
  let clock = 1100;
  const scope = state.scope;
  const w = crypto.generateKeyPairSync("ed25519");
  const authorityKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const signedHistory = async () => history.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes, now: clock,
  });
  let proof = await signedHistory();
  let admissions = 0;
  const witnessProvider = {
    async freshHead({ nonce }) {
      const base = { type: "rootark-recovery-witness-head/v1", witness_key_id: witnessKeyId,
        ...scope, current_revision: manifest.revision,
        current_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
        witness_sequence: manifest.revision, nonce, observed_at: clock,
        status: "committed", pending_reservation_id: null };
      return z.encodeDeterministic({ ...base, signature: crypto.sign(null,
        Buffer.concat([WITNESS_DOMAIN, Buffer.from(await z.encodeDeterministic(base))]),
        w.privateKey) });
    },
    async beginIoAdmission() {
      if (admissions) throw Error("active witness gate");
      admissions += 1;
      return { admissionId: crypto.randomBytes(16), proceed: true };
    },
    async finishIoAdmission() { admissions -= 1; },
  };
  const store = new Zk1ProtectedObjectStore(path.join(dir, "content.sqlite"), {
    bootstrapNew: true, witnessProvider, admissionRequired: true,
    witnessPinned: { keyId: witnessKeyId, publicKey: w.publicKey },
    trustedScope: scope, minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    signedHistoryRequired: true,
    signedHistoryGenesisDigest: await v2.recoveryManifestDigestV2(state.baseManifest),
    verifiedHistoryProvider: async () => proof,
    manifestProvider: async () => z.encodeDeterministic(manifest),
    nowSeconds: () => clock,
  });
  let sequence = 0;
  let currentDigest = Buffer.alloc(32);
  let failCAS = false;
  const signedCas = async (nonce) => {
    const statement = { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
      sequence, digest: Buffer.from(currentDigest), nonce: Buffer.from(nonce),
      observed_at: clock };
    return z.encodeDeterministic({ ...statement, signature: crypto.sign(null,
      Buffer.concat([catalogCasDomain, Buffer.from(await z.encodeDeterministic(statement))]),
      authorityKeys.privateKey) });
  };
  const authority = {
    publicKey: authorityKeys.publicKey,
    async readHead({ nonce }) { return signedCas(nonce); },
    async compareAndSwap({ expectedSequence, expectedDigest, nextSequence, nextDigest, nonce }) {
      if (failCAS || expectedSequence !== sequence || !expectedDigest.equals(currentDigest)
        || nextSequence !== sequence + 1) throw Error("CAS conflict");
      sequence = nextSequence;
      currentDigest = Buffer.from(nextDigest);
      return signedCas(nonce);
    },
  };
  const catalog = new Zk1OpaqueCatalog({ store, authority });
  const app = express();
  app.use(express.json({ limit: "7mb" }));
  const authenticate = (req, res, next) => {
    if (req.get("x-session") !== "authenticated") return res.sendStatus(401);
    req.user = { username: "owner" };
    next();
  };
  registerZk1ProtectedObjectRoutes({ app, store, opaqueCatalog: catalog,
    authenticate, requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: (user) => user.username === "owner" ? scope : null });
  app.use("/client", express.static(path.join(__dirname, "../public/client")));
  app.get("/edge-catalog-fixture", (_req, res) => res.type("html").send(
    "<!doctype html><html><body>"
    + "<script>window.RootarkZk1NormalBrowserTrustFloor={assertCurrent:async()=>{}};</script>"
    + '<script src="/client/rootark-zk1-protected-http-client.js"></script>'
    + '<script src="/client/rootark-zk1-browser-catalog.js"></script>'
    + "</body></html>"));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const send = async (url, body, authorized = true) => {
    const response = await fetch(origin + url, { method: "POST",
      headers: { "content-type": "application/json",
        ...(authorized ? { "x-session": "authenticated" } : {}) },
      body: JSON.stringify(body) });
    const raw = await response.text();
    let json;
    try { json = JSON.parse(raw); } catch (_) { json = { raw }; }
    return { status: response.status, json };
  };
  const device = (index) => manifest.devices[index];
  const privateKey = (index) => state.actors.get(
    Buffer.from(device(index).authorization_key_id).toString("hex"));
  const signed = async (index, operation, id, revision, ciphertextDigest) => {
    const auth = { ...scope, device_id: device(index).device_id,
      operation, object_id: id, expected_object_revision: revision,
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch), nonce: crypto.randomBytes(32),
      issued_at: clock, expires_at: clock + 30, ciphertext_digest: ciphertextDigest };
    return { authorization: auth, signature: crypto.sign(null,
      await contentAuthorizationMessageV1(auth), privateKey(index)) };
  };
  const wire = (request) => ({
    authorization: Object.fromEntries(Object.entries(request.authorization).map(([k, v]) =>
      ["account_id", "compartment_id", "keyring_id", "manifest_digest", "nonce",
        "ciphertext_digest"].includes(k) && v !== null ? [k, b64(v)] : [k, v])),
    signatureBase64: b64(request.signature),
  });
  const id = crypto.randomBytes(16).toString("base64url");
  const sealed = crypto.randomBytes(90);
  const filename = "financial/private/file.txt";
  const metadataKey = crypto.randomBytes(32);
  const encryptedName = await sealZk1CatalogMetadataV1({
    scope, objectId: id, revision: 1, epoch: Number(manifest.current_epoch),
    metadataKey, name: filename });
  const write = await signed(0, "put", id, null, digest(sealed));
  assert.equal((await send("/zk-1/v1/content/put", { ...wire(write),
    ciphertextBase64: b64(sealed) })).status, 201);
  const entries = [[{ object_id: id, revision: 1, epoch: Number(manifest.current_epoch),
    ciphertext_digest: digest(sealed), metadata_ciphertext: encryptedName }]];
  const build = async (index, usedEntries = entries, parent = currentDigest, seq = sequence + 1) => {
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence: seq, previous_digest: Buffer.from(parent),
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch),
      signer_device_id: device(index).device_id,
      total_count: usedEntries.flat().length,
      page_digests: await Promise.all(usedEntries.map(catalogPageDigest)), issued_at: clock };
    const signature = crypto.sign(null, await catalogHeaderMessage(header), privateKey(index));
    const headBytes = Buffer.from(await z.encodeDeterministic(header));
    const requestedDigest = catalogHeadDigest(headBytes, signature);
    const auth = await signed(index, "catalog-commit",
      catalogOperationObjectId(scope, "catalog-commit"),
      sequence === 0 ? null : sequence, requestedDigest);
    return { ...wire(auth), headerBase64: b64(headBytes),
      headerSignatureBase64: b64(signature), pages: usedEntries.map((page) =>
        page.map((e) => ({ objectId: e.object_id, revision: e.revision,
          epoch: e.epoch, ciphertextDigestBase64: b64(e.ciphertext_digest),
          metadataCiphertextBase64: b64(e.metadata_ciphertext) }))) };
  };
  const commit = await build(0);
  assert.equal((await send("/zk-1/v1/catalog/commit", commit, false)).status, 401);
  const created = await send("/zk-1/v1/catalog/commit", commit);
  assert.equal(created.status, 201, JSON.stringify(created.json));
  assert.equal(created.json.sequence, 1);
  assert.equal(admissions, 0);
  assert.equal((await send("/zk-1/v1/catalog/commit", commit)).status, 409,
    "same device nonce is persistently consumed");
  const requestRead = async (index, indexPage = 0, digestOverride = currentDigest) =>
    wire(await signed(index, "catalog-read", catalogOperationObjectId(scope, "catalog-read", indexPage),
      sequence, digestOverride));
  const firstRead = await requestRead(1);
  const read = await send("/zk-1/v1/catalog/read", { ...firstRead, pageIndex: 0 });
  assert.equal(read.status, 200, JSON.stringify(read.json));
  assert.equal(read.json.totalCount, 1);
  assert.equal(read.json.entries[0].objectId, id);
  assert.equal(read.json.entries[0].ciphertextDigestBase64, b64(digest(sealed)));
  // The actual browser UMD client signs fresh challenges through WebCrypto,
  // verifies signed owner/device grants and pinned CAS receipts, compares
  // local page checkpoints, opens AEAD metadata, and GETs ciphertext.
  function ephemeralIndexedDB() {
    const state = new Map();
    let initialized = false;
    return { open() {
      const request = {};
      const db = {
        objectStoreNames: { contains() { return initialized; } },
        createObjectStore() { initialized = true; },
        close() {},
        transaction(_name, mode) {
          const tx = {
            oncomplete: null, onabort: null, onerror: null,
            abort() { queueMicrotask(() => tx.onabort?.()); },
            objectStore() {
              return {
                get(key) {
                  const r = { result: undefined };
                  queueMicrotask(() => {
                    r.result = state.get(key);
                    r.onsuccess?.();
                    queueMicrotask(() => tx.oncomplete?.());
                  });
                  return r;
                },
                put(value, key) {
                  if (mode !== "readwrite") throw Error("read-only");
                  state.set(key, structuredClone(value));
                },
              };
            },
          };
          return tx;
        },
      };
      request.result = db;
      queueMicrotask(() => {
        if (!initialized) request.onupgradeneeded?.();
        queueMicrotask(() => request.onsuccess?.());
      });
      return request;
    } };
  }
  const browserScope = Object.fromEntries(Object.entries(scope).map(([k,v]) => [k, b64(v)]));
  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerPublicKey = await crypto.webcrypto.subtle.importKey("raw",
    owner.publicKey.export({ format: "der", type: "spki" }).subarray(-32),
    "Ed25519", true, ["verify"]);
  const GRANT = ["schema", "account_id", "compartment_id", "keyring_id",
    "device_id", "authorization_key_id", "authorization_public_key",
    "manifest_revision", "manifest_digest", "current_epoch",
    "enrolled_epoch", "revoked_at_epoch"];
  const ownerHead = { revision: Number(manifest.revision),
    digest: await v2.recoveryManifestDigestV2(manifest), epoch: Number(manifest.current_epoch) };
  const makeGrant = (idx) => {
    const target = device(idx);
    const claim = { schema: "rootark-zk1-browser-owner-device-grant/v1",
      ...browserScope, device_id: target.device_id,
      authorization_key_id: b64(target.authorization_key_id),
      authorization_public_key: b64(target.authorization_public_key),
      manifest_revision: ownerHead.revision, manifest_digest: b64(ownerHead.digest),
      current_epoch: ownerHead.epoch, enrolled_epoch: Number(target.enrolled_epoch),
      revoked_at_epoch: target.revoked_at_epoch };
    return { ...claim, signature: b64(crypto.sign(null, Buffer.concat([
      Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
      Buffer.from(JSON.stringify(Object.fromEntries(
        GRANT.map((field) => [field, claim[field]])))) ]), owner.privateKey)) };
  };
  const ownerPublicRaw = owner.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const ownerRawDigest = digest(ownerPublicRaw);
  const trust = (idx) => ({
    ownerPublicKey, pinnedOwnerKeyHash: ownerRawDigest,
    independentOwnerSpkiSha256: digest(owner.publicKey.export({ format: "der", type: "spki" })),
    pinnedCurrentHead: ownerHead, signedDeviceGrant: makeGrant(idx),
    ownerHistoryCheckpoint: { independentlySelectedSignedOwnerHistory: true },
    previousOwnerHistoryProof: null,
  });
  const browserContext = {
    crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob, URL,
    location: { origin },
    RootarkZk1NormalBrowserTrustFloor: {
      async assertCurrent({ signedDeviceGrant, pinnedCurrentHead }) {
        assert.equal(signedDeviceGrant.manifest_digest, b64(pinnedCurrentHead.digest));
      },
    },
    RootarkZk1ProtectedHttpClient: {
      signProtectedContentOperation(value) {
        const protectedHttp = require("../public/client/rootark-zk1-protected-http-client");
        // Realm boundary belongs only to the Node vm test harness. A real
        // browser creates both signed objects in the same JS realm.
        return protectedHttp.signProtectedContentOperation({
          ...value, scope: { ...value.scope },
          manifestDigest: new Uint8Array(value.manifestDigest),
          expectedCiphertextDigest: new Uint8Array(value.expectedCiphertextDigest),
        });
      },
    },
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-browser-catalog.js"), "utf8"), browserContext);
  const browser = browserContext.RootarkZk1BrowserCatalog;
  assert.equal(typeof browser?.openCatalog, "function");
  const authorityPublicRaw = authorityKeys.publicKey.export({
    format: "der", type: "spki" }).subarray(-32);
  const browserAuthority = await crypto.webcrypto.subtle.importKey("raw",
    authorityPublicRaw, "Ed25519", true, ["verify"]);
  const localDB = ephemeralIndexedDB();
  let activeSession = true;
  let csrfValue = "first";
  const fetchImpl = async (url, options) => {
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.method, "POST");
    return fetch(url, { ...options,
      headers: { ...options.headers, "x-session": activeSession ? "authenticated" : "",
        "x-csrf-token": csrfValue } });
  };
  const privateFor = async (idx) => crypto.webcrypto.subtle.importKey("pkcs8",
    privateKey(idx).export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const browserInput = (idx) => ({
    trust: trust(idx), signerGrant: makeGrant(0),
    catalogAuthorityKey: browserAuthority,
    independentAuthoritySpkiHash: digest(
      authorityKeys.publicKey.export({ format: "der", type: "spki" })),
    pinnedCatalogHead: { sequence: 1, digest: created.json.catalogDigest },
    origin: origin + "/", fetchImpl, indexedDBImpl: localDB,
    nowSeconds: clock,
    assertLive: () => {
      if (!activeSession || csrfValue !== "first") throw Error("session expired");
    },
  });
  const deviceOneSnapshot = await browser.openCatalog({
    ...browserInput(1), devicePrivateKey: await privateFor(1),
  });
  assert.equal(deviceOneSnapshot.totalCount, 1);
  assert.deepEqual(Array.from(deviceOneSnapshot.changedPageIndices), [0]);
  assert.equal(await browser.openCatalogName(deviceOneSnapshot, 0, metadataKey), filename);
  await assert.rejects(browser.openCatalogName(deviceOneSnapshot, 0,
    crypto.randomBytes(32)), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  assert.deepEqual(Buffer.from((await browser.getCatalogCiphertext(
    deviceOneSnapshot, 0)).ciphertextBase64, "base64url"), sealed);
  // Reopening with exactly the same independently pinned current head has no
  // changed page. A second authorized profile has its own independent floor.
  const repeatSnapshot = await browser.openCatalog({
    ...browserInput(1), devicePrivateKey: await privateFor(1),
  });
  assert.deepEqual(Array.from(repeatSnapshot.changedPageIndices), []);
  const deviceZeroSnapshot = await browser.openCatalog({
    ...browserInput(0), devicePrivateKey: await privateFor(0),
    indexedDBImpl: ephemeralIndexedDB(),
  });
  assert.equal(deviceZeroSnapshot.entries[0].objectId, id);
  if (process.env.ROOTARK_ZK1_EDGE_CATALOG === "1") {
    const edgeExe = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
    assert.equal(fs.existsSync(edgeExe), true, "Edge explicitly requested for this run");
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-catalog-edge-"));
    const edge = spawn(edgeExe, ["--headless=new", "--disable-gpu",
      "--no-first-run", "--disable-extensions", "--remote-debugging-port=0",
      "--user-data-dir=" + profile, "about:blank"], { stdio: "ignore", windowsHide: true });
    let socket;
    t.after(() => {
      socket?.close();
      try {
        execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
          { timeout: 10000, stdio: "ignore" });
      } catch (_) { edge.kill(); }
      try { fs.rmSync(profile, { recursive: true, force: true, maxRetries: 15, retryDelay: 150 }); }
      catch (_) { /* busy profile is a disposable test artifact */ }
    });
    const wait = async (fn) => {
      for (let i = 0; i < 250; i++) {
        const value = await fn();
        if (value) return value;
        await new Promise((resolve) => setTimeout(resolve, 75));
      }
      throw Error("EDGE_CATALOG_TIMEOUT");
    };
    const port = await wait(() => {
      const file = path.join(profile, "DevToolsActivePort");
      return fs.existsSync(file) ? Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]) : null;
    });
    const pages = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    socket = new WebSocket(pages.find((item) => item.type === "page").webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    let serial = 0;
    const pending = new Map();
    socket.addEventListener("message", ({ data }) => {
      const parsed = JSON.parse(data);
      if (!pending.has(parsed.id)) return;
      const item = pending.get(parsed.id);
      pending.delete(parsed.id);
      parsed.error ? item.reject(Error(parsed.error.message)) : item.resolve(parsed.result);
    });
    const sendCdp = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++serial;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
    await sendCdp("Runtime.enable");
    await sendCdp("Page.enable");
    const evalEdge = async (expression) => {
      const response = await sendCdp("Runtime.evaluate", {
        expression, awaitPromise: true, returnByValue: true });
      if (response.exceptionDetails) throw Error("EDGE_CATALOG_JS_ERROR "
        + response.exceptionDetails.text + " " + JSON.stringify(response.exceptionDetails.exception?.description));
      return response.result.value;
    };
    await sendCdp("Page.navigate", { url: origin + "/edge-catalog-fixture" });
    await wait(() => evalEdge("document.readyState==='complete' && !!window.RootarkZk1BrowserCatalog"));
    const edgeInput = {
      ownerRaw: b64(ownerPublicRaw), signerGrant: makeGrant(0),
      ownGrant: makeGrant(1), privateDer: b64(privateKey(1).export({
        format: "der", type: "pkcs8" })),
      casRaw: b64(authorityPublicRaw),
      casSpkiHash: b64(digest(authorityKeys.publicKey.export({ format: "der", type: "spki" }))),
      ownerSpkiHash: b64(digest(owner.publicKey.export({ format: "der", type: "spki" }))),
      headRevision: ownerHead.revision, headDigest: b64(ownerHead.digest),
      epoch: ownerHead.epoch, catalogDigest: created.json.catalogDigest,
      metadataKey: b64(metadataKey), now: clock,
    };
    const edgeResult = await evalEdge(`(async()=>{
      const d=${JSON.stringify(edgeInput)};
      const from64=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")
        .padEnd(Math.ceil(s.length/4)*4,"=")),c=>c.charCodeAt(0));
      const to64=x=>btoa(String.fromCharCode(...x)).replace(/\\+/g,"-")
        .replace(/\\//g,"_").replace(/=+$/g,"");
      const ownerPublicKey=await crypto.subtle.importKey("raw",from64(d.ownerRaw),"Ed25519",true,["verify"]);
      const casPublicKey=await crypto.subtle.importKey("raw",from64(d.casRaw),"Ed25519",true,["verify"]);
      const devicePrivateKey=await crypto.subtle.importKey("pkcs8",from64(d.privateDer),"Ed25519",false,["sign"]);
      window.__edgeCatalogActive=true;
      window.__edgeCatalog=await RootarkZk1BrowserCatalog.openCatalog({
        trust:{ownerPublicKey,independentOwnerSpkiSha256:from64(d.ownerSpkiHash),
          pinnedCurrentHead:{revision:d.headRevision,digest:from64(d.headDigest),epoch:d.epoch},
          signedDeviceGrant:d.ownGrant,ownerHistoryCheckpoint:{source:"independent"},previousOwnerHistoryProof:null},
        signerGrant:d.signerGrant,devicePrivateKey,catalogAuthorityKey:casPublicKey,
        independentAuthoritySpkiHash:from64(d.casSpkiHash),
        pinnedCatalogHead:{sequence:1,digest:d.catalogDigest},origin:location.origin+"/",
        fetchImpl:(url,options)=>fetch(url,{...options,headers:{...options.headers,
          "x-session":"authenticated","x-csrf-token":"edge-fixture"}}),
        assertLive:()=>{if(!window.__edgeCatalogActive)throw Error("logout")},
        indexedDBImpl:indexedDB,nowSeconds:()=>d.now});
      const name=await RootarkZk1BrowserCatalog.openCatalogName(
        window.__edgeCatalog,0,from64(d.metadataKey));
      const fetched=await RootarkZk1BrowserCatalog.getCatalogCiphertext(window.__edgeCatalog,0);
      window.__edgeCatalogActive=false;
      let refused=false;try{await RootarkZk1BrowserCatalog.getCatalogCiphertext(window.__edgeCatalog,0)}
      catch(e){refused=e.message==="ZK_BROWSER_CATALOG_UNVERIFIED"}
      return {count:window.__edgeCatalog.totalCount,name,sha:to64(new Uint8Array(
        await crypto.subtle.digest("SHA-256",from64(fetched.ciphertextBase64)))),refused};
    })()`);
    assert.deepEqual(edgeResult, { count: 1, name: filename, sha: b64(digest(sealed)),
      refused: true }, "real Edge must verify and GET with an independent active device");
  }
  await assert.rejects(browser.openCatalog({
    ...browserInput(1), devicePrivateKey: await privateFor(1),
    independentAuthoritySpkiHash: crypto.randomBytes(32),
  }), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  await assert.rejects(browser.openCatalog({
    ...browserInput(1), devicePrivateKey: await privateFor(1),
    signerGrant: { ...makeGrant(0), authorization_public_key: b64(crypto.randomBytes(32)) },
  }), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  csrfValue = "switched";
  await assert.rejects(browser.getCatalogCiphertext(deviceOneSnapshot, 0),
    /ZK_BROWSER_CATALOG_UNVERIFIED/);
  csrfValue = "first";
  activeSession = false;
  await assert.rejects(browser.getCatalogCiphertext(deviceOneSnapshot, 0),
    /ZK_BROWSER_CATALOG_UNVERIFIED/);
  activeSession = true;
  assert.ok(!JSON.stringify(read.json).includes(filename));
  const ownerNonce = crypto.randomBytes(32);
  const ownerWitnessRaw = await witnessProvider.freshHead({ scope, nonce: ownerNonce });
  const verify = async (response) => verifyZk1OpaqueCatalogPage({
    response, expectedScope: scope, verifiedOwnerHistory: proof,
    pinnedOwnerGenesisDigest: await v2.recoveryManifestDigestV2(state.baseManifest),
    ownerWitnessRaw, ownerWitnessNonce: ownerNonce,
    pinnedOwnerWitness: { keyId: witnessKeyId, publicKey: w.publicKey },
    minimumOwnerHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    catalogNonce: Buffer.from(firstRead.authorization.nonce, "base64url"),
    pinnedCatalogAuthorityKey: authorityKeys.publicKey,
    minimumCatalogHead: { sequence: 0, digest: Buffer.alloc(32) },
    nowSeconds: clock,
  });
  const trusted = await verify(read.json);
  assert.equal(trusted.entries[0].objectId, id);
  assert.deepEqual(trusted.entries[0].ciphertextDigest, digest(sealed));
  assert.equal(await openZk1CatalogMetadataV1({ scope, objectId: id,
    revision: 1, epoch: Number(manifest.current_epoch), metadataKey,
    ciphertext: trusted.entries[0].metadataCiphertext }), filename);
  await assert.rejects(openZk1CatalogMetadataV1({ scope, objectId: id,
    revision: 2, epoch: Number(manifest.current_epoch), metadataKey,
    ciphertext: trusted.entries[0].metadataCiphertext }), /ZK_CATALOG_UNVERIFIED/);
  await assert.rejects(verify({ ...read.json,
    totalCount: read.json.totalCount - 1 }), /ZK_CATALOG_UNVERIFIED/);
  await assert.rejects(verify({ ...read.json, entries: read.json.entries.map(
    (e) => ({ ...e, ciphertextDigestBase64: b64(crypto.randomBytes(32)) })) }),
  /ZK_CATALOG_UNVERIFIED/);
  await assert.rejects(verify({ ...read.json,
    authorityProofBase64: b64(crypto.randomBytes(128)) }), /ZK_CATALOG_UNVERIFIED/);
  // Second-device independently verifies the entire public catalog page
  // against signer, page digest, and separately signed CAS head.
  const signedHead = await z.decodeDeterministic(Buffer.from(read.json.headerBase64, "base64url"));
  assert.equal(crypto.verify(null, await catalogHeaderMessage(signedHead),
    crypto.createPublicKey({ key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(manifest.devices[0].authorization_public_key)]), format: "der", type: "spki" }),
    Buffer.from(read.json.headerSignatureBase64, "base64url")), true);
  assert.deepEqual(await catalogPageDigest(entries[0]), Buffer.from(signedHead.page_digests[0]));
  const witnessed = await z.decodeDeterministic(Buffer.from(read.json.authorityProofBase64, "base64url"));
  const { signature: authoritySig, ...statement } = witnessed;
  assert.equal(crypto.verify(null, Buffer.concat([catalogCasDomain,
    Buffer.from(await z.encodeDeterministic(statement))]),
  authorityKeys.publicKey, authoritySig), true);
  assert.equal(witnessed.sequence, read.json.sequence);
  const signedGet = await signed(1, "get", id, 1, digest(sealed));
  const fetched = await send("/zk-1/v1/content/read", wire(signedGet));
  assert.equal(fetched.status, 200);
  assert.deepEqual(Buffer.from(fetched.json.ciphertextBase64, "base64url"), sealed);
  assert.equal((await send("/zk-1/v1/catalog/read", { ...firstRead, pageIndex: 0 })).status, 409);
  const wrongPage = await requestRead(1, 1);
  assert.equal((await send("/zk-1/v1/catalog/read",
    { ...wrongPage, pageIndex: 0 })).status, 403,
  "a signed catalog page challenge cannot be redirected to a different page");
  const omitted = await build(0, []);
  assert.equal((await send("/zk-1/v1/catalog/commit", omitted)).status, 409);
  const forged = await build(0);
  forged.headerSignatureBase64 = b64(crypto.randomBytes(64));
  assert.equal((await send("/zk-1/v1/catalog/commit", forged)).status, 403);
  const wrongScope = await build(0);
  wrongScope.authorization.compartment_id = b64(Buffer.from("other-compartment"));
  assert.equal((await send("/zk-1/v1/catalog/commit", wrongScope)).status, 403);
  const corrupted = await build(0);
  corrupted.pages[0][0].ciphertextDigestBase64 = b64(crypto.randomBytes(32));
  assert.equal((await send("/zk-1/v1/catalog/commit", corrupted)).status, 403);
  const previousSequence = sequence;
  const rolledBack = await requestRead(1);
  sequence = 0; currentDigest = Buffer.alloc(32);
  assert.equal((await send("/zk-1/v1/catalog/read", { ...rolledBack, pageIndex: 0 })).status, 503);
  sequence = previousSequence; currentDigest = Buffer.from(created.json.catalogDigest, "base64url");
  const deniedMissingDigest = await requestRead(1, 0, crypto.randomBytes(32));
  assert.equal((await send("/zk-1/v1/catalog/read", { ...deniedMissingDigest, pageIndex: 0 })).status, 409);
  failCAS = true;
  const competing = await build(1);
  assert.equal((await send("/zk-1/v1/catalog/commit", competing)).status, 503);
  failCAS = false;
  const historicalSignerGrant = makeGrant(0);
  await fixture.appendDeviceRevocation(state, "trusted-0");
  manifest = state.headManifest;
  proof = await signedHistory();
  const afterRevocation = await requestRead(1);
  assert.equal((await send("/zk-1/v1/catalog/read",
    { ...afterRevocation, pageIndex: 0 })).status, 403,
  "a revoked catalog signer cannot silently remain trusted in the active epoch");
  await assert.rejects(browser.openCatalog({
    ...browserInput(1), signerGrant: historicalSignerGrant,
    devicePrivateKey: await privateFor(1),
    indexedDBImpl: ephemeralIndexedDB(),
  }), /ZK_BROWSER_CATALOG_UNVERIFIED/,
  "the browser cannot reuse an older owner grant when the current V2 witness revokes that signer");
  // Concurrent authorized devices can propose the same next revision, but
  // the external CAS admits only one; the surviving ACTIVE device can re-sign
  // the unchanged historical inventory after a revocation.
  const proposalA = await build(1);
  const proposalB = await build(1);
  const transitions = await Promise.all([
    send("/zk-1/v1/catalog/commit", proposalA),
    send("/zk-1/v1/catalog/commit", proposalB),
  ]);
  assert.equal(transitions.filter((v) => v.status === 201).length, 1);
  assert.equal(transitions.filter((v) => [409, 503].includes(v.status)).length, 1);
  assert.equal(sequence, 2);
  const resumed = await requestRead(1);
  assert.equal((await send("/zk-1/v1/catalog/read", { ...resumed,
    pageIndex: 0 })).status, 200);
});
