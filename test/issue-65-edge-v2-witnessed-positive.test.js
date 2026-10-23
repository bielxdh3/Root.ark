"use strict";

// Disposable integration fixture: REAL Edge UI, owner-offline V2 ceremony,
// independently signed commitment receipts, two separate pinned mTLS peers,
// strict server-side V2 history and an actual authenticated HTTP ciphertext GET.
// The mTLS peers model independently signed replies; they do not prove
// real-world custody or external physical durability.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { spawn, execFileSync } = require("node:child_process");
const express = require("express");
const jwt = require("jsonwebtoken");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const enrollment = require("../src/crypto/rootark-zk1-owner-offline-v2-enrollment");
const commitment = require("../src/crypto/rootark-zk1-offline-commitment-receipt");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const ownerRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const protectedHttp = require("../public/client/rootark-zk1-protected-http-client");
const committedApproval = require("../public/client/rootark-zk1-v2-committed-approval");
const { Zk1ProtectedObjectStore } = require("../src/services/zk1ProtectedObjectStore");
const { createZk1SignedHistoryCasProofProvider } =
  require("../src/services/zk1SignedHistoryCasProofProvider");
const { createZk1CasManifestHttpsClient } = require("../src/services/zk1CasManifestHttpsClient");
const { createZk1WitnessHttpsClient } = require("../src/services/zk1WitnessHttpsClient");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");
const { createAuthenticate } = require("../src/middlewares/auth");
const { createRequirePermission } = require("../src/middlewares/permissions");

const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const b64 = (value) => Buffer.from(value).toString("base64url");
const rawPublic = (key) => key.export({ type: "spki", format: "der" }).subarray(-32);
const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest();
const scopeNames = ["account_id", "compartment_id", "keyring_id"];
const time = () => Math.floor(Date.now() / 1000);
const wait = async (fn, label = "fixture", count = 250) => {
  for (let i = 0; i < count; i++) {
    const value = await fn();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 60));
  }
  throw Error("EDGE_V2_TIMEOUT_" + label);
};

function signedReceipt(fields, signer, scope) {
  const source = { schema: commitment.SCHEMA, status: "committed", ...scope,
    revision: null, digest: null, epoch: null, previous_revision: null,
    previous_digest: null, operation_id: null, pop_challenge_id: null,
    request_nonce: null, commit_nonce: null, sequence: null,
    previous_receipt_sha256: null, issued_at: null, expires_at: null,
    ...fields };
  const unsigned = Object.fromEntries(commitment.FIELDS.map((k) => [k, source[k]]));
  return { ...unsigned, signature: b64(crypto.sign(null,
    commitment.commitmentSigningBytes(unsigned), signer)) };
}
function receiptDigest(receipt) {
  const unsigned = Object.fromEntries(commitment.FIELDS.map((k) => [k, receipt[k]]));
  return digest(Buffer.concat([commitment.commitmentSigningBytes(unsigned),
    Buffer.from(receipt.signature, "base64url")]));
}

function certificates(dir) {
  generateNativeFixtureCertificates(dir, { caSubject: "V2 isolated positive fixture",
    servers: ["cas", "witness"], clients: ["casreader", "headreader"] });
  const read = (file) => fs.readFileSync(path.join(dir, file));
  return { ca: read("ca.pem"), cas: { key: read("cas.key"), cert: read("cas.pem"),
    clientKey: read("casreader.key"), clientCert: read("casreader.pem") },
  witness: { key: read("witness.key"), cert: read("witness.pem"),
    clientKey: read("headreader.key"), clientCert: read("headreader.pem") } };
}

async function createTlsAuthorities(t, dir, state, getHead, signer) {
  const certs = certificates(dir);
  const expected = Object.fromEntries(scopeNames.map((k) => [k, b64(state.scope[k])]));
  const entries = [state.baseManifest, ...await Promise.all(state.transitions.map(
    (entry) => z.decodeDeterministic(entry)))];
  let getCount = 0;
  let witnessCount = 0;
  const build = (identity, callback) => {
    const permittedClient = new crypto.X509Certificate(identity.clientCert).fingerprint256;
    return https.createServer({
    key: identity.key, cert: identity.cert, ca: certs.ca, requestCert: true,
    rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, (req, res) => {
    if (!req.socket.authorized
      || req.socket.getPeerCertificate()?.fingerprint256 !== permittedClient
      || req.method !== "POST") return res.writeHead(403).end();
    let payload = "";
    req.on("data", (part) => {
      payload += part;
      if (payload.length > 8192) req.destroy();
    });
    req.on("end", async () => {
      try {
        const input = JSON.parse(payload);
        if (JSON.stringify(input.scope) !== JSON.stringify(expected)) throw Error("scope");
        const reply = await callback(req.url, input);
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify(reply));
      } catch (_) { res.writeHead(403).end(); }
    });
  });
  };
  const cas = build(certs.cas, async (url, input) => {
    getCount++;
    const head = getHead();
    const packed = entries.map((item) => z.encodeDeterministic(item));
    const current = await Promise.all(packed);
    if (url === "/v1/manifest") return { manifestBase64: b64(current.at(-1)) };
    if (url !== "/v1/history" || !Number.isSafeInteger(input.startRevision)) throw Error("path");
    const start = input.startRevision;
    return { headRevision: head.revision,
      headDigest: b64(await v2.recoveryManifestDigestV2(head)), startRevision: start,
      nextRevision: null, entriesBase64: current.slice(start - 1).map(b64) };
  });
  const witness = build(certs.witness, async (url, input) => {
    witnessCount++;
    const head = getHead();
    if (url === "/v1/head") {
      const unsigned = { type: "rootark-recovery-witness-head/v1",
        witness_key_id: signer.id, ...state.scope,
        nonce: Buffer.from(input.nonce, "base64url"),
        current_revision: head.revision,
        current_manifest_digest: await v2.recoveryManifestDigestV2(head),
        witness_sequence: head.revision, observed_at: time(),
        status: "committed", pending_reservation_id: null };
      return { receiptBase64: b64(await z.encodeDeterministic({ ...unsigned,
        signature: crypto.sign(null, Buffer.concat([
          Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0"),
          Buffer.from(await z.encodeDeterministic(unsigned))]), signer.key.privateKey) })),
      authority: "WITNESS_ENGINE_ONLY" };
    }
    if (url === "/v1/admission/start") return { admissionId: b64(crypto.randomBytes(16)),
      proceed: true, authority: "WITNESS_IO_GATE_LOCAL_V1" };
    if (url === "/v1/admission/finish") return {
      status: "completed", authority: "WITNESS_IO_GATE_LOCAL_V1" };
    throw Error("path");
  });
  const connections = new Set();
  for (const server of [cas, witness]) server.on("connection", (socket) => {
    connections.add(socket);
    socket.on("close", () => connections.delete(socket));
  });
  for (const server of [cas, witness]) await new Promise((resolve) =>
    server.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    for (const socket of connections) socket.destroy();
    for (const server of [witness, cas]) {
      server.closeAllConnections();
      server.close();
      server.unref();
    }
  });
  const pin = (bytes) => new crypto.X509Certificate(bytes).fingerprint256;
  const casClient = createZk1CasManifestHttpsClient({
    endpoint: "https://localhost:" + cas.address().port + "/v1/manifest",
    ca: certs.ca, clientKey: certs.cas.clientKey, clientCert: certs.cas.clientCert,
    serverFingerprint256: pin(certs.cas.cert) });
  const witnessClient = createZk1WitnessHttpsClient({
    endpoint: "https://localhost:" + witness.address().port,
    ca: certs.ca, clientKey: certs.witness.clientKey, clientCert: certs.witness.clientCert,
    serverFingerprint256: pin(certs.witness.cert) });
  return { casClient, witnessClient, addManifest(manifest) { entries.push(manifest); },
    get requests() { return { cas: getCount, witness: witnessCount }; } };
}

async function launchEdge(t, origin, session) {
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-edge-v2-profile-"));
  const edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--no-first-run",
    "--disable-extensions", "--remote-debugging-port=0",
    "--user-data-dir=" + profileDir, "about:blank"],
  { stdio: "ignore", windowsHide: true });
  let socket;
  t.after(async () => {
    socket?.close();
    if (edge.pid) {
      try { execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
        { timeout: 10000, stdio: "ignore" }); } catch (_) { edge.kill(); }
    }
    for (let i = 0; i < 30; i++) {
      try { fs.rmSync(profileDir, { recursive: true, force: true }); break; }
      catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 120));
      }
    }
  });
  const port = await wait(() => {
    const file = path.join(profileDir, "DevToolsActivePort");
    return fs.existsSync(file) ? Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]) : null;
  }, "devtools");
  const pages = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
  socket = new WebSocket(pages.find((p) => p.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  let serial = 0;
  const pending = new Map();
  socket.addEventListener("message", ({ data }) => {
    const parsed = JSON.parse(data);
    if (!pending.has(parsed.id)) return;
    const { resolve, reject } = pending.get(parsed.id);
    pending.delete(parsed.id);
    parsed.error ? reject(Error(parsed.error.message)) : resolve(parsed.result);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++serial;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Network.setCookie", { name: "rootark_session", value: session,
    url: origin, httpOnly: true, sameSite: "Strict" });
  await send("Network.setCookie", { name: "rootark_csrf", value: "edge-v2-session",
    url: origin, sameSite: "Strict" });
  const evalJs = async (expression) => {
    const result = await send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw Error("EDGE_SCRIPT_EXCEPTION:"
      + result.exceptionDetails.text);
    return result.result?.value;
  };
  const navigate = async () => {
    await send("Page.navigate", { url: origin + "/workspace-v2-test" });
    await wait(() => evalJs("document.readyState==='complete'"), "page");
    await wait(() => evalJs("!!window.RootarkApi && !!document.getElementById('protectedClientStatus')"),
      "entry");
    assert.equal(await evalJs("(async()=>{const r=await fetch('/zk-1/v1/workspace-capability');"
      + "return JSON.stringify(await r.json())})()"),
    JSON.stringify({ enabled: true, securityVersion: 2, signedHistoryRequired: true }));
    await evalJs("window.dispatchEvent(new Event('rootark:workspace-rendered'))");
    await wait(() => evalJs("!!document.getElementById('zk1-workspace-open')"), "button");
    await evalJs("document.getElementById('zk1-workspace-open').click()");
    await wait(() => evalJs("!!document.querySelector('dialog[open]')"), "modal");
    await evalJs(`window.__captured=[]; window.__pendingBlob=[]; window.__blobs=new Map();
      const originalCreate=URL.createObjectURL.bind(URL);
      URL.createObjectURL=(blob)=>{const url=originalCreate(blob);window.__blobs.set(url,blob);return url};
      HTMLAnchorElement.prototype.click=function(){
        const name=this.download; const href=this.href;
        window.__pendingBlob.push(window.__blobs.get(href).arrayBuffer().then(bytes=>{
          let binary=''; for(const n of new Uint8Array(bytes)) binary+=String.fromCharCode(n);
          window.__captured.push({name,data:btoa(binary).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'')});
        }));
      }; window.__files=(values)=>{
        for(const [name,raw] of Object.entries(values)){
          const element=document.querySelector('[data-zk1-field="'+name+'"]');
          if(raw===null){element.value='';continue;}
          const data=Uint8Array.from(atob(raw.replace(/-/g,'+').replace(/_/g,'/')
            +'='.repeat((4-raw.length%4)%4)),c=>c.charCodeAt(0));
          const dt=new DataTransfer(); dt.items.add(new File([data],name+'.bin'));element.files=dt.files;
        }
      }; window.__values=(values)=>{
        for(const [name,val] of Object.entries(values))
          document.querySelector('[data-zk1-field="'+name+'"]').value=String(val);
      }; window.__action=(name)=>document.querySelector('[data-zk1-action="'+name+'"]').click();`);
  };
  return { send, evalJs, navigate, async inputs(files, values = {}) {
    await evalJs("window.__files(" + JSON.stringify(files) + ");window.__values("
      + JSON.stringify(values) + ")");
  }, async click(action) { await evalJs("window.__action(" + JSON.stringify(action) + ")"); },
  async statusIncludes(needle) {
    return wait(() => evalJs("document.querySelector('[data-zk1-field=status]')?.textContent.includes("
      + JSON.stringify(needle) + ")"), "status-" + needle);
  }, async downloads() {
    return evalJs("(async()=>{await Promise.all(window.__pendingBlob);return window.__captured})()");
  } };
}

test("REAL Edge owner-witnessed V2 PoP import survives fresh realm and restores only through signed-history strict mTLS-backed server", {
  timeout: 120000,
}, async (t) => {
  let stage = "initial";
  try {
  if (!fs.existsSync(EDGE)) return t.skip("Microsoft Edge unavailable");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-edge-v2-strict-"));
  const state = await fixtures.createInitialState(2);
  const former = state.headManifest;
  const owner = crypto.generateKeyPairSync("ed25519");
  const witnessKey = crypto.generateKeyPairSync("ed25519");
  const witnessId = crypto.randomBytes(16);
  const signer = { id: witnessId, key: witnessKey };
  const ownerRaw = rawPublic(owner.publicKey);
  const ownerSpki = digest(owner.publicKey.export({ type: "spki", format: "der" }));
  const witnessSpki = digest(witnessKey.publicKey.export({ type: "spki", format: "der" }));
  const scope = Object.fromEntries(scopeNames.map((k) => [k, b64(state.scope[k])]));
  const formerDigest = await v2.recoveryManifestDigestV2(former);
  const at = time();
  const priorReceipt = signedReceipt({ revision: former.revision,
    digest: b64(formerDigest), epoch: former.current_epoch, sequence: 30,
    issued_at: at - 2, expires_at: at + 300 }, witnessKey.privateKey, scope);
  const hpke = await z.hpkeSuite().kem.generateKeyPair();
  const hpkeRaw = Buffer.from(await z.hpkeSuite().kem.serializePrivateKey(hpke.privateKey));
  const hpkeDer = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), hpkeRaw]);
  const targetKeys = crypto.generateKeyPairSync("ed25519");
  const targetPrivateDer = targetKeys.privateKey.export({ type: "pkcs8", format: "der" });
  const request = { schema: "rootark-zk1-device-enrollment-request/v1",
    device_id: "actual-edge-new-device", authorization_key_id: b64(crypto.randomBytes(16)),
    authorization_public_key: b64(rawPublic(targetKeys.publicKey)),
    hpke_key_id: b64(crypto.randomBytes(16)),
    hpke_public_key: b64(await z.hpkeSuite().kem.serializePublicKey(hpke.publicKey)),
    challenge: b64(crypto.randomBytes(32)),
    approval: "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT" };
  const prepared = await enrollment.beginOwnerEnrollment({
    request, verifiedHistory: state.verifiedHistory,
    externalCurrentHead: { revision: former.revision, digest: b64(formerDigest),
      epoch: former.current_epoch }, trustedOwnerPublicKey: owner.publicKey,
    independentOwnerSpkiSha256: b64(ownerSpki),
    trustedCommitmentSignerPublicKey: witnessKey.publicKey,
    independentCommitmentSignerSpkiSha256: b64(witnessSpki),
    trustedPriorCommitment: priorReceipt, nowSeconds: at });

  let head = former;
  const peers = await createTlsAuthorities(t, dir, state, () => head, signer);
  const genesis = await v2.recoveryManifestDigestV2(state.baseManifest);
  const signedHistory = createZk1SignedHistoryCasProofProvider({
    casClient: peers.casClient, trustedScope: state.scope, trustedGenesisDigest: genesis,
    baseReceipt: state.baseReceipt, pinnedBaseWitness: state.pinnedWitness,
    packageEnvelopes: [], nowSeconds: time });
  const store = new Zk1ProtectedObjectStore(path.join(dir, "strict-v2.sqlite"), {
    bootstrapNew: true, trustedScope: state.scope, admissionRequired: true,
    minimumHead: { revision: 1, witnessSequence: 1, digest: genesis },
    witnessProvider: peers.witnessClient,
    witnessPinned: { keyId: witnessId, publicKey: witnessKey.publicKey },
    manifestProvider: (scope) => peers.casClient.getCommittedManifest({ scope }),
    signedHistoryRequired: true, signedHistoryGenesisDigest: genesis,
    verifiedHistoryProvider: signedHistory, nowSeconds: time });
  t.after(() => store.close());
  const secret = crypto.randomBytes(32).toString("hex");
  const token = jwt.sign({ username: "owner", sessionVersion: 0 }, secret, { expiresIn: "10m" });
  const app = express();
  let signedGets = 0;
  let signedPuts = 0;
  let accidentalSecretWire = false;
  const plaintext = Buffer.from("Actual Edge authenticated V2 owner-only local restored plaintext");
  const filename = "owner-private-edge-v2.txt";
  app.use((req, _res, next) => {
    if (req.path === "/zk-1/v1/content/read") signedGets++;
    if (req.path === "/zk-1/v1/content/put") signedPuts++;
    if (req.path.startsWith("/zk-1/v1/content/")) {
      let data = "";
      req.on("data", (part) => {
        data += part;
        if (data.includes(filename) || data.includes(plaintext.toString("utf8"))) {
          accidentalSecretWire = true;
        }
      });
    }
    next();
  });
  const authenticate = createAuthenticate({ jwt, jwtSecret: secret,
    loadUser: (name) => name === "owner" ? { username: name, sessionVersion: 0,
      permissions: { listFiles: true, upload: true } } : null,
    normalizeUserPermissions: (user) => user.permissions });
  registerZk1ProtectedObjectRoutes({ app, store, authenticate,
    requirePermission: createRequirePermission(),
    resolveTrustedScope: (user) => user?.username === "owner" ? state.scope : null });
  const allowed = new Set(["rootark-api", "rootark-zk1-authenticated-workspace",
    ...[ "rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
      "rootark-zk1-ciphertext-download-integrity", "rootark-zk1-owner-signed-checkpoint",
      "rootark-zk1-owner-ciphertext-root-checkpoint", "rootark-zk1-protected-http-client",
      "rootark-zk1-uncertain-put-reconciliation", "rootark-zk1-normal-browser-trust-floor",
      "rootark-zk1-normal-browser-content", "rootark-zk1-owner-inventory-trust-head",
      "rootark-zk1-portable-file-recovery", "rootark-zk1-browser-recovery-http",
      "rootark-zk1-recoverable-workspace", "rootark-dev-vault-migration",
      "rootark-zk1-legacy-transition-receipt",
      "rootark-zk1-legacy-migration-workflow", "rootark-zk1-legacy-batch-migration",
      "rootark-zk1-v2-device-approval", "rootark-zk1-v2-browser-pop",
      "rootark-zk1-v2-committed-approval", "rootark-zk1-browser-authoritative-backup",
      "rootark-zk1-keyring-portable-archive", "rootark-zk1-browser-versioned-archive",
      "rootark-zk1-account-portable-recovery" ]]);
  app.get("/client/:name", (req, res) => {
    const name = req.params.name.replace(/\.js$/, "");
    if (!allowed.has(name) || req.params.name !== name + ".js") return res.sendStatus(404);
    return res.type("application/javascript").sendFile(
      path.join(__dirname, "../public/client", name + ".js"), { dotfiles: "allow" });
  });
  app.get("/workspace-v2-test", authenticate, (_req, res) => res.type("html")
    .set("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'self'")
    .send('<!doctype html><html><head><script defer src="/client/rootark-api.js"></script>'
      + '<script defer src="/client/rootark-zk1-authenticated-workspace.js"></script>'
      + '</head><body><section class="protected-client-panel">'
      + '<p id="protectedClientStatus"></p></section></body></html>'));
  const server = await new Promise((resolve) => {
    const running = app.listen(0, "127.0.0.1", () => resolve(running));
  });
  t.after(() => {
    server.closeAllConnections();
    server.close();
    server.unref();
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  const fetchAuthenticated = (url, options) => fetch(url, {
    ...options, headers: { ...options.headers,
      cookie: "rootark_session=" + token + "; rootark_csrf=edge-v2-session",
      "X-CSRF-Token": "edge-v2-session" } });
  const metadata = { ...scope, object_id: b64(crypto.randomBytes(16)),
    version_id: b64(crypto.randomBytes(16)), parent_version_id: null,
    epoch: former.current_epoch, kind: "file" };
  const holderSecret = portable.generateRecoverySecret();
  const bundle = await portable.sealForUserHeldSecret({
    recoverySecret: holderSecret, metadata, objectRevision: 1,
    name: filename, mediaType: "text/plain", data: plaintext });
  const initialDevice = former.devices[0];
  const initialSigner = state.actors.get(
    Buffer.from(initialDevice.authorization_key_id).toString("hex"));
  const signerKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    initialSigner.export({ type: "pkcs8", format: "der" }),
    "Ed25519", false, ["sign"]);
  const operation = await protectedHttp.signProtectedContentOperation({
    signerKey, scope, deviceId: initialDevice.device_id, operation: "put",
    objectId: metadata.object_id, expectedObjectRevision: null,
    manifestRevision: former.revision, manifestDigest: formerDigest,
    epoch: former.current_epoch, nowSeconds: time(),
    ciphertext: Buffer.from(bundle.ciphertextBase64, "base64url") });
  stage = "seed-put";
  const put = await protectedHttp.postProtectedCiphertextPut({
    origin: origin + "/", request: operation, fetchImpl: fetchAuthenticated });
  assert.equal(put.revision, 1, "real authenticated strict V2 PUT seeds old ciphertext");
  assert.equal(signedPuts, 1);
  assert.equal(store.signedHistoryRequired, true);

  stage = "launch-edge";
  const edge = await launchEdge(t, origin, token);
  // Register filesystem removal AFTER all database, mTLS, HTTP and browser
  // cleanup hooks so Windows never races an open SQLite or TLS handle.
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  await edge.navigate();
  await edge.inputs({
    "new-request": b64(JSON.stringify(request)),
    "pop-challenge": b64(JSON.stringify(enrollment.exportBrowserChallenge(prepared))),
    private: b64(targetPrivateDer), "hpke-private": b64(hpkeDer) });
  await edge.click("answer-pop");
  await edge.statusIncludes("PoP X25519");
  const popOutput = (await edge.downloads()).find((entry) =>
    entry.name === "rootark-v2-device-pop-response.json");
  assert.ok(popOutput, "actual Edge workspace generated its HPKE + Ed25519 PoP");
  const signedPop = JSON.parse(Buffer.from(popOutput.data, "base64url").toString("utf8"));
  stage = "owner-stage";
  const actor = state.actors.get(Buffer.from(former.devices[0].authorization_key_id).toString("hex"));
  const candidate = await enrollment.stageBrowserPopResponse({
    prepared, response: signedPop, trustedActorPrivateKey: actor, nowSeconds: at + 3 });
  const currentDigest = await v2.recoveryManifestDigestV2(candidate.manifest);
  const current = { revision: candidate.manifest.revision,
    digest: b64(currentDigest), epoch: candidate.manifest.current_epoch };
  const committedReceipt = signedReceipt({
    ...current, previous_revision: former.revision, previous_digest: b64(formerDigest),
    operation_id: b64(candidate.manifest.operation.operation_id),
    pop_challenge_id: b64(candidate.manifest.operation.target_pop_proof.challenge_context.challenge_id),
    request_nonce: request.challenge, commit_nonce: prepared.commitmentNonce,
    sequence: priorReceipt.sequence + 1,
    previous_receipt_sha256: b64(receiptDigest(priorReceipt)),
    issued_at: at + 4, expires_at: at + 290,
  }, witnessKey.privateKey, scope);
  const issued = await enrollment.ownerApproveCommittedEnrollment({
    candidate, signedCommittedHead: committedReceipt,
    ownerPrivateKey: owner.privateKey, nowSeconds: at + 5 });
  // The trusted owner host publishes the signed V2 transition only AFTER its
  // independent witnessed operation is committed. CAS and witness remain separate mTLS peers.
  head = candidate.manifest;
  peers.addManifest(head);
  assert.equal((await signedHistory({ scope: state.scope })).revision, head.revision,
    "real mTLS CAS history verifies owner-rooted complete V2 chain");

  const subtle = crypto.webcrypto.subtle;
  const ownerSigner = await subtle.importKey("pkcs8",
    owner.privateKey.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const ownerKey = await subtle.importKey("raw", ownerRaw, "Ed25519", true, ["verify"]);
  const signerId = crypto.randomBytes(16);
  const ownerDeviceId = "owner-offline-v2-root";
  const ownerCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope, signerKey: ownerSigner, signerPublicKey: ownerKey,
    signerKeyId: signerId, deviceId: ownerDeviceId,
    revision: current.revision, manifestDigest: currentDigest,
    issuedAt: time(), previous: null });
  const rootCheckpoint = await ownerRoots.signOwnerCiphertextRootCheckpoint({
    scope, signerKey: ownerSigner, signerKeyId: signerId,
    deviceId: ownerDeviceId, manifestRevision: current.revision,
    manifestDigest: currentDigest, manifestEpoch: current.epoch,
    objectId: metadata.object_id, objectRevision: 1, ciphertextEpoch: metadata.epoch,
    ciphertextRoot: Buffer.from(bundle.ciphertextRoot, "base64url"), issuedAt: time() });
  const delivery = issued.browserDelivery;
  const preflight = await committedApproval.verifyCommittedApproval({
    request: delivery.request, approval: delivery.approval,
    signedDeviceGrant: delivery.signedDeviceGrant,
    ownerPublicKey: ownerKey,
    independentOwnerSpkiSha256: ownerSpki,
    pinnedOwnerKeyHash: digest(ownerRaw),
    pinnedCurrentHead: { revision: current.revision, digest: currentDigest, epoch: current.epoch },
    devicePublicKey: await subtle.importKey("raw", rawPublic(targetKeys.publicKey),
      "Ed25519", true, ["verify"]),
    devicePrivateKey: await subtle.importKey("pkcs8", targetPrivateDer,
      "Ed25519", false, ["sign"]),
    nowSeconds: time(),
    committedReceipt: delivery.committedReceipt, previousReceipt: delivery.previousReceipt,
    witnessPublicKey: await subtle.importKey("raw", rawPublic(witnessKey.publicKey),
      "Ed25519", true, ["verify"]),
    independentWitnessSpkiSha256: witnessSpki,
    independentlyPinnedPreviousReceiptSha256: receiptDigest(priorReceipt),
    signedV2Manifest: delivery.signedV2Manifest,
  });
  assert.equal(preflight.committedOwnerApprovalVerified, true,
    "Node verifies the exact independently signed delivery used in real Edge");
  const commonFiles = {
    owner: b64(ownerRaw), grant: b64(JSON.stringify(delivery.signedDeviceGrant)),
    history: b64(JSON.stringify(ownerCheckpoint)),
    device: request.authorization_public_key, private: b64(targetPrivateDer),
    "new-approval": b64(JSON.stringify(delivery)),
    "witness-key": b64(rawPublic(witnessKey.publicKey)),
    secret: b64(holderSecret), bundle: b64(JSON.stringify(bundle)),
    "owner-root": b64(JSON.stringify(rootCheckpoint)) };
  const commonValues = { "owner-hash": b64(digest(ownerRaw)),
    "owner-spki": b64(ownerSpki), revision: current.revision,
    digest: current.digest, epoch: current.epoch,
    "witness-spki": b64(witnessSpki),
    "witness-prior": b64(receiptDigest(priorReceipt)),
    root: bundle.ciphertextRoot, "owner-signer": b64(signerId),
    "owner-device": ownerDeviceId };
  const importValid = async () => {
    await edge.inputs(commonFiles, commonValues);
    await edge.click("provision");
    await wait(() => edge.evalJs("(()=>{const s=document.querySelector('[data-zk1-field=status]')?.textContent;"
      + "return s&&(s.includes('Âncora offline')||s.includes('Piso local verificado'))})()"),
    "offline-floor");
    // Every action wipes private keys and imported approval File inputs,
    // including the preceding offline-floor provisioning action.
    await edge.inputs({ private: b64(targetPrivateDer),
      "new-approval": b64(JSON.stringify(delivery)) });
    await edge.click("import-approval");
    await wait(() => edge.evalJs("(()=>{const s=document.querySelector('[data-zk1-field=status]')?.textContent;"
      + "return s&&(s.includes('Prova V2/witness')||s.includes('Operação recusada'))})()"),
    "witness-import");
    const message = await edge.evalJs(
      "document.querySelector('[data-zk1-field=status]')?.textContent");
    assert.match(message, /Prova V2\/witness/, "Edge import rejected V2 delivery: " + message);
  };
  stage = "edge-import-restore";
  await importValid();
  await edge.inputs({ private: b64(targetPrivateDer), secret: b64(holderSecret),
    bundle: b64(JSON.stringify(bundle)), "owner-root": b64(JSON.stringify(rootCheckpoint)) });
  await edge.click("restore");
  await edge.statusIncludes("Arquivo histórico recuperado");
  const resultFiles = await edge.downloads();
  const recovered = resultFiles.find((entry) => entry.name === filename);
  assert.ok(recovered, "Edge initiated a local-only download after real signed HTTP GET");
  assert.deepEqual(Buffer.from(recovered.data, "base64url"), plaintext);
  assert.ok(signedGets > 0, "authenticated V2 server actually received signed GET");
  assert.equal(accidentalSecretWire, false, "no filename or plaintext reached protected HTTP");

  // A page reload destroys all WeakMap brands. Genuine imported evidence must
  // be reverified in the fresh JS realm; a serialized 'verified:true' cannot substitute.
  const beforeReloadGets = signedGets;
  stage = "edge-reload";
  await edge.navigate();
  await importValid();
  await edge.inputs({ private: b64(targetPrivateDer), secret: b64(holderSecret),
    bundle: b64(JSON.stringify(bundle)), "owner-root": b64(JSON.stringify(rootCheckpoint)) });
  await edge.click("restore");
  await edge.statusIncludes("Arquivo histórico recuperado");
  assert.ok(signedGets > beforeReloadGets, "fresh Edge page rebrands valid V2 evidence");
  assert.ok((await edge.downloads()).some((entry) => entry.name === filename));

  const negatives = [
    ["foreign owner pin", { values: { "owner-spki": b64(crypto.randomBytes(32)) } }],
    ["foreign witness", { values: { "witness-spki": b64(crypto.randomBytes(32)) } }],
    ["forged witnessed digest", { files: {
      "new-approval": b64(JSON.stringify({ ...delivery,
        committedReceipt: { ...committedReceipt, digest: b64(crypto.randomBytes(32)) } })) } }],
    ["expired witnessed receipt", { files: {
      "new-approval": b64(JSON.stringify({ ...delivery,
        committedReceipt: signedReceipt({ ...committedReceipt,
          issued_at: time() - 60, expires_at: time() - 1 },
        witnessKey.privateKey, scope) })) } }],
    ["revoked grant", { files: {
      grant: b64(JSON.stringify({ ...delivery.signedDeviceGrant,
        revoked_at_epoch: current.epoch })),
      "new-approval": b64(JSON.stringify({ ...delivery,
        signedDeviceGrant: { ...delivery.signedDeviceGrant, revoked_at_epoch: current.epoch } })) } }],
  ];
  stage = "edge-negative";
  for (const [label, changes] of negatives) {
    const beforeGets = signedGets;
    const beforeDownloads = (await edge.downloads()).length;
    await edge.inputs(commonFiles, commonValues);
    if (changes.files || changes.values) await edge.inputs(changes.files || {},
      changes.values || {});
    await edge.click("import-approval");
    await edge.statusIncludes("Operação recusada");
    await edge.inputs({ private: b64(targetPrivateDer), secret: b64(holderSecret),
      bundle: b64(JSON.stringify(bundle)), "owner-root": b64(JSON.stringify(rootCheckpoint)) });
    await edge.click("restore");
    await edge.statusIncludes("Operação recusada");
    assert.equal(signedGets, beforeGets, label + " never reaches protected GET");
    assert.equal((await edge.downloads()).length, beforeDownloads,
      label + " never releases plaintext");
  }

  // Both cancellation races happen while a valid branded proof exists and
  // before the pending signed network read resolves.
  for (const mode of ["csrf-change", "logout"]) {
    stage = "edge-race-" + mode;
    await importValid();
    await edge.inputs({ private: b64(targetPrivateDer), secret: b64(holderSecret),
      bundle: b64(JSON.stringify(bundle)), "owner-root": b64(JSON.stringify(rootCheckpoint)) });
    const before = (await edge.downloads()).length;
    await edge.evalJs(`window.__realFetch=window.fetch;window.__gateRelease=null;
      window.fetch=(url,opts)=>{
        if(String(url).endsWith('/zk-1/v1/content/read'))
          return new Promise(resolve=>{window.__gateRelease=()=>resolve(window.__realFetch(url,opts))});
        return window.__realFetch(url,opts);
      };`);
    await edge.click("restore");
    await wait(() => edge.evalJs("typeof window.__gateRelease==='function'"), mode + "-held");
    if (mode === "logout") await edge.evalJs("window.dispatchEvent(new Event('rootark:logout'))");
    else await edge.evalJs("document.cookie='rootark_csrf=changed-v2-session;path=/'");
    await edge.evalJs("window.__gateRelease();window.fetch=window.__realFetch");
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal((await edge.downloads()).length, before, mode + " fences local output");
    if (mode === "csrf-change") await edge.evalJs(
      "document.cookie='rootark_csrf=edge-v2-session;path=/'");
  }
  holderSecret.fill(0);
  hpkeRaw.fill(0);
  assert.ok(peers.requests.cas > 0 && peers.requests.witness > 0,
    "actual independent pinned mTLS CAS and witness network traffic occurred");
  } catch (error) {
    console.error("EDGE_V2_STAGE", stage, String(error?.stack || error));
    throw error;
  }
});
