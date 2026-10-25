"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { spawn, execFileSync } = require("node:child_process");
const { DatabaseSync } = require("node:sqlite");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const history = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const ownerRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const persisted = require("../public/client/rootark-zk1-persisted-portable-chunk-recovery");
const nativeRoots = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const browser = require("../public/client/rootark-zk1-browser-recovery-http");

const b64 = (raw) => Buffer.from(raw).toString("base64url");
const rid = () => b64(crypto.randomBytes(16));
const fields = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch",
  "revoked_at_epoch"];

async function actor() {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = await crypto.webcrypto.subtle.importKey("spki",
    pair.publicKey.export({ type: "spki", format: "der" }), "Ed25519", true, ["verify"]);
  const privateKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    pair.privateKey.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  return { pair, publicKey, privateKey };
}

async function fixture(t) {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-client-ui-optin-"));
  const owner = await actor();
  const device = await actor();
  const scope = { account_id: rid(), compartment_id: b64(crypto.randomBytes(8)),
    keyring_id: rid() };
  const metadata = { ...scope, object_id: rid(), version_id: rid(),
    parent_version_id: null, epoch: 4, kind: "file" };
  const current = { revision: 7, digest: crypto.randomBytes(32), epoch: 4 };
  const ownerSpki = Buffer.from(await crypto.webcrypto.subtle.exportKey("spki", owner.publicKey));
  const independentOwnerSpkiSha256 = crypto.createHash("sha256").update(ownerSpki).digest();
  const pinnedOwnerKeyHash = crypto.createHash("sha256")
    .update(Buffer.from(await crypto.webcrypto.subtle.exportKey("raw", owner.publicKey))).digest();
  const deviceRaw = await crypto.webcrypto.subtle.exportKey("raw", device.publicKey);
  const grantBody = { schema: "rootark-zk1-browser-owner-device-grant/v1", ...scope,
    device_id: "client-device", authorization_key_id: rid(),
    authorization_public_key: b64(deviceRaw),
    manifest_revision: current.revision, manifest_digest: b64(current.digest),
    current_epoch: current.epoch, enrolled_epoch: 1, revoked_at_epoch: null };
  const signature = crypto.sign(null, Buffer.concat([Buffer.from(
    "Root.ark/zk-1/browser-owner-device-grant/v1\0"),
  Buffer.from(JSON.stringify(Object.fromEntries(fields.map((key) => [key, grantBody[key]]))))]),
  owner.pair.privateKey);
  const grant = { ...grantBody, signature: b64(signature) };
  const signerKeyId = crypto.randomBytes(16);
  const checkpoint = await history.signOwnerCheckpoint({
    scope, signerKey: owner.privateKey, signerPublicKey: owner.publicKey,
    signerKeyId, deviceId: "offline-owner", revision: current.revision,
    manifestDigest: current.digest, issuedAt: 1420, previous: null });
  const secret = portable.generateRecoverySecret();
  const plaintext = Buffer.from("Owner-only cleartext never written to disk, transport or server");
  const bundle = await portable.sealForUserHeldSecret({ recoverySecret: secret,
    metadata, name: "private.txt", mediaType: "text/plain", data: plaintext });
  const signedRoot = await ownerRoots.signOwnerCiphertextRootCheckpoint({
    scope, signerKey: owner.privateKey, signerKeyId, deviceId: "offline-owner",
    manifestRevision: current.revision, manifestDigest: current.digest,
    manifestEpoch: current.epoch, objectId: metadata.object_id,
    objectRevision: 1, ciphertextEpoch: metadata.epoch,
    ciphertextRoot: Buffer.from(bundle.ciphertextRoot, "base64url"), issuedAt: 1421 });
  const ciphertext = Buffer.from(bundle.ciphertextBase64, "base64url");
  const chunks = [ciphertext.subarray(0, 65), ciphertext.subarray(65)];
  const independentlyPinnedSourceChunkRoot = Buffer.from(
    await nativeRoots.computeCiphertextRoot(chunks));
  assert.notDeepEqual(independentlyPinnedSourceChunkRoot,
    Buffer.from(bundle.ciphertextRoot, "base64url"),
    "owner-pinned native two-chunk root cannot be substituted with the portable root");
  const inventory = await persisted.createSignedPersistedPortableChunkInventory({
    bundle, ownerSigningKey: owner.privateKey, ownerPublicKey: owner.publicKey,
    independentOwnerSpkiSha256, ownerHead: current,
    chunks, assertLive: () => undefined });
  const file = path.join(folder, "chunks.sqlite");
  let db = new DatabaseSync(file);
  db.exec("CREATE TABLE chunks (n INTEGER PRIMARY KEY, data BLOB NOT NULL)");
  for (let i = 0; i < chunks.length; i++) {
    db.prepare("INSERT INTO chunks VALUES (?, ?)").run(i, Buffer.from(chunks[i]));
  }
  db.close();
  db = new DatabaseSync(file);
  t.after(() => { if (db.isOpen) db.close();
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 }); });
  let reads = 0;
  let alive = true;
  const input = { ownerPublicKey: owner.publicKey,
    pinnedOwnerKeyHash, independentOwnerSpkiSha256, pinnedCurrentHead: current,
    signedDeviceGrant: grant, devicePublicKey: device.publicKey,
    devicePrivateKey: device.privateKey,
    ownerHistoryCheckpoint: checkpoint, previousOwnerHistoryProof: null,
    ownerSignerKeyId: b64(signerKeyId), ownerDeviceId: "offline-owner",
    ownerRootCheckpoint: signedRoot, recoverySecret: secret, bundle,
    expectedMetadata: metadata,
    independentlyPinnedCiphertextRoot: Buffer.from(bundle.ciphertextRoot, "base64url"),
    independentlyPinnedSourceChunkRoot,
    signedInventory: inventory,
    readChunk: async ({ index }) => {
      reads++;
      return db.prepare("SELECT data FROM chunks WHERE n=?").get(index)?.data;
    },
    assertLive: () => { if (!alive) throw new Error("page revoked"); },
  };
  return { input, plaintext, chunks, secret, db, current, owner, device,
    get reads() { return reads; }, setAlive(value) { alive = value; } };
}

test("explicit opt-in browser coordinator releases local AES-GCM plaintext only after Ed25519, head, root and all SQLite chunks", async (t) => {
  const f = await fixture(t);
  const opened = await browser.recoverFromOwnerSignedPersistedChunks(f.input);
  assert.deepEqual(Buffer.from(opened.data), f.plaintext);
  assert.equal(opened.ownerSignedHistoricalRootVerified, true);
  assert.equal(opened.localPersistedChunksVerified, true);
  assert.equal(opened.authorizesProductionRestore, false);
  assert.equal(opened.independentRemoteDurabilityProven, false);
  assert.equal(f.reads, f.chunks.length);
  opened.data.fill(0);
  f.secret.fill(0);
});

test("independent trust absent refuses before ANY SQLite chunk access, even with a valid bundle and signed inventory", async (t) => {
  const f = await fixture(t);
  for (const modified of [
    { independentOwnerSpkiSha256: null },
    { pinnedOwnerKeyHash: null },
    { pinnedCurrentHead: null },
    { independentlyPinnedCiphertextRoot: null },
    { independentlyPinnedSourceChunkRoot: null },
    { ownerHistoryCheckpoint: null },
    { ownerRootCheckpoint: null },
  ]) await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks({ ...f.input,
    ...modified }), /ZK_BROWSER_RECOVERY_EXTERNAL_TRUST_REQUIRED/);
  assert.equal(f.reads, 0);
  f.secret.fill(0);
});

test("two-chunk source root must be independently pinned; forged bundle root cannot replace native root", async (t) => {
  const f = await fixture(t);
  assert.equal(f.input.independentlyPinnedSourceChunkRoot.length, 32);
  const expected = /ZK_BROWSER_RECOVERY_HTTP_DENIED/;
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks({
    ...f.input, independentlyPinnedSourceChunkRoot: f.input.independentlyPinnedCiphertextRoot,
  }), expected, "signed portable ciphertext root is not the external native chunk root");
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks({
    ...f.input, independentlyPinnedSourceChunkRoot: crypto.randomBytes(32),
  }), expected, "wrong externally supplied native root cannot authorize plaintext");
  assert.equal(f.reads, f.chunks.length * 2);
  f.secret.fill(0);
});

test("replayed head, unrelated owner signature, current device revocation, wrong-key and absent chunk deny", async (t) => {
  const f = await fixture(t);
  const denied = /ZK_BROWSER_RECOVERY_HTTP_DENIED/;
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks({ ...f.input,
    pinnedCurrentHead: { ...f.current, revision: f.current.revision + 1 } }), denied);
  const attacker = await actor();
  const forged = await persisted.createSignedPersistedPortableChunkInventory({
    bundle: f.input.bundle, ownerSigningKey: attacker.privateKey,
    ownerPublicKey: attacker.publicKey,
    independentOwnerSpkiSha256: crypto.createHash("sha256").update(
      Buffer.from(await crypto.webcrypto.subtle.exportKey("spki", attacker.publicKey))).digest(),
    ownerHead: f.current, chunks: f.chunks, assertLive: () => undefined });
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks({ ...f.input,
    signedInventory: forged }), denied);
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks({ ...f.input,
    signedDeviceGrant: { ...f.input.signedDeviceGrant, revoked_at_epoch: f.current.epoch } }), denied);
  assert.equal(f.reads, 0, "fork and revocation cannot initiate ciphertext read");
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks({ ...f.input,
    recoverySecret: crypto.randomBytes(32) }), denied);
  f.db.prepare("DELETE FROM chunks WHERE n=1").run();
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks(f.input), denied);
  f.db.prepare("INSERT INTO chunks VALUES (?, ?)").run(1, Buffer.from(f.chunks[1]));
  f.setAlive(false);
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks(f.input), denied);
  f.setAlive(true);
  const opened = await browser.recoverFromOwnerSignedPersistedChunks(f.input);
  opened.data.fill(0);
  f.secret.fill(0);
});

test("late synchronous liveness rejection after the final awaited floor check never releases plaintext", async (t) => {
  const f = await fixture(t);
  let checks = 0;
  await assert.rejects(browser.recoverFromOwnerSignedPersistedChunks({ ...f.input,
    assertLive: () => { checks++; return checks >= 7 ? false : undefined; },
  }), /ZK_BROWSER_RECOVERY_HTTP_DENIED/);
  assert.equal(checks, 7,
    "revocation at final synchronous egress fence must be sampled and rejected");
  f.secret.fill(0);
});

test("experimental page explicitly loads the browser chunk API and keeps protected GET as default", () => {
  const html = fs.readFileSync(path.join(__dirname, "../dev-ui/zk1-protected-file-lab.html"), "utf8");
  const ui = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-portable-recovery-lab-ui.js"), "utf8");
  assert.match(html, /rootark-zk1-persisted-portable-chunk-recovery\.js/);
  assert.match(html, /id="portable-offline-opt-in"/);
  assert.match(html, /id="portable-chunk-inventory"/);
  assert.match(html, /id="portable-chunks"[^>]*multiple/);
  assert.match(html, /id="portable-source-chunk-root"/);
  assert.match(ui, /if \(offline\) \{/);
  assert.match(ui, /recoverFromOwnerSignedPersistedChunks/);
  assert.match(ui, /recoverFromOwnerSignedProtectedGet/);
  assert.match(ui, /ZK_BROWSER_RECOVERY_EXTERNAL_TRUST_REQUIRED/);
  assert.match(ui, /independentlyPinnedSourceChunkRoot/);
});

test("real Edge opt-in UI refuses missing external pins and recovers signed local chunks without HTTP GET", {
  timeout: 85_000,
}, async (t) => {
  const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Edge Windows unavailable");
    return;
  }
  const f = await fixture(t);
  const htmlFile = path.join(__dirname, "../dev-ui/zk1-protected-file-lab.html");
  const html = fs.readFileSync(htmlFile, "utf8");
  const allowed = new Set([...html.matchAll(/<script defer src="\/client\/([\w-]+)\.js"/g)]
    .map((item) => item[1]));
  assert.ok(allowed.has("rootark-zk1-persisted-portable-chunk-recovery"));
  const rawOwner = await crypto.webcrypto.subtle.exportKey("raw", f.owner.publicKey);
  const rawDevice = await crypto.webcrypto.subtle.exportKey("raw", f.device.publicKey);
  const values = {
    ownerKey: b64(rawOwner), deviceKey: b64(rawDevice),
    devicePrivate: b64(f.device.pair.privateKey.export({ type: "pkcs8", format: "der" })),
    ownerHash: b64(f.input.pinnedOwnerKeyHash),
    ownerSpki: b64(f.input.independentOwnerSpkiSha256),
    ownerHead: { revision: f.current.revision, digest: b64(f.current.digest),
      epoch: f.current.epoch },
    grant: f.input.signedDeviceGrant,
    ownerHistory: f.input.ownerHistoryCheckpoint,
    ownerRoot: f.input.ownerRootCheckpoint,
    bundle: f.input.bundle, inventory: f.input.signedInventory,
    secret: b64(f.secret), root: b64(f.input.independentlyPinnedCiphertextRoot),
    sourceRoot: b64(f.input.independentlyPinnedSourceChunkRoot),
    chunks: f.chunks.map(b64),
  };
  // Test-only disposable localhost fixture: no production HTTP routes, no
  // server-owned pins, and only exact dev-lab script paths are served.
  const probe = `window.addEventListener("load", async () => {
    const output=document.createElement("output");output.id="edge-local-result";document.body.append(output);
    const v=${JSON.stringify(values)};
    const decode=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
    function file(id,bytes,name){const dt=new DataTransfer();dt.items.add(new File([bytes],name));document.getElementById(id).files=dt.files;}
    function chunks(){const dt=new DataTransfer();v.chunks.forEach((chunk,i)=>dt.items.add(new File([decode(chunk)],"chunk-"+i+".bin")));document.getElementById("portable-chunks").files=dt.files;}
    const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
    const status=()=>document.getElementById("status").textContent;
    let downloads=0;const originalClick=HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click=function(){if(this.hasAttribute("download"))downloads++;return originalClick.call(this);};
    let lastError="";const original=window.RootarkZk1BrowserRecoveryHttp;
    window.RootarkZk1BrowserRecoveryHttp=Object.freeze({...original,
      recoverFromOwnerSignedPersistedChunks:async(input)=>{try{return await original.recoverFromOwnerSignedPersistedChunks(input);}catch(error){lastError=error.message;throw error;}}});
    function prepare(){
      file("owner-key",decode(v.ownerKey),"owner.raw");file("device-public",decode(v.deviceKey),"device.raw");
      file("device-private",decode(v.devicePrivate),"device.der");
      file("device-grant",new TextEncoder().encode(JSON.stringify(v.grant)),"device.json");
      file("owner-history",new TextEncoder().encode(JSON.stringify(v.ownerHistory)),"history.json");
      file("portable-owner-root",new TextEncoder().encode(JSON.stringify(v.ownerRoot)),"root.json");
      file("portable-secret",decode(v.secret),"secret.bin");
      file("portable-bundle",new TextEncoder().encode(JSON.stringify(v.bundle)),"bundle.json");
      file("portable-chunk-inventory",new TextEncoder().encode(JSON.stringify(v.inventory)),"inventory.json");
      chunks();
      document.getElementById("owner-hash").value=v.ownerHash;
      document.getElementById("owner-spki-hash").value=v.ownerSpki;
      document.getElementById("head-revision").value=v.ownerHead.revision;
      document.getElementById("head-digest").value=v.ownerHead.digest;
      document.getElementById("head-epoch").value=v.ownerHead.epoch;
      document.getElementById("portable-root").value=v.root;
      document.getElementById("portable-source-chunk-root").value=v.sourceRoot;
      document.getElementById("portable-offline-opt-in").checked=true;
    }
    try {
      document.getElementById("portable-offline-opt-in").checked=true;
      document.getElementById("portable-restore").click();
      await pause(120);
      if(!status().includes("faltam pins externos")||downloads!==0)throw Error("MISSING_PIN_NOT_CLOSED:"+status());
      prepare();
      const ownerKey=await crypto.subtle.importKey("raw",decode(v.ownerKey),"Ed25519",true,["verify"]);
      await window.RootarkZk1NormalBrowserTrustFloor.provisionOffline({
        ownerPublicKey:ownerKey,independentOwnerSpkiSha256:decode(v.ownerSpki),
        pinnedCurrentHead:{revision:v.ownerHead.revision,digest:decode(v.ownerHead.digest),epoch:v.ownerHead.epoch},
        signedDeviceGrant:v.grant,ownerHistoryCheckpoint:v.ownerHistory,previousOwnerHistoryProof:null});
      document.getElementById("portable-source-chunk-root").value="";
      document.getElementById("portable-restore").click();await pause(130);
      if(!status().includes("faltam pins externos")||downloads!==0)
        throw Error("MISSING_NATIVE_PIN_NOT_CLOSED:"+status()+":"+downloads);
      // A rejected restore deliberately clears local File inputs, so a
      // second attempt must explicitly reselect those offline files.
      prepare();
      document.getElementById("portable-restore").click();
      for(let i=0;i<100;i++){await pause(70);if(status().includes("Recuperação local concluída")||lastError)break;}
      if(!status().includes("Recuperação local concluída")||downloads!==1)
        throw Error("LOCAL_RECOVER_FAILED:"+status()+":"+lastError+":"+downloads);
      prepare();document.getElementById("head-revision").value=String(v.ownerHead.revision+1);
      document.getElementById("portable-restore").click();await pause(350);
      if(downloads!==1||status().includes("Recuperação local concluída"))throw Error("ROLLBACK_EXPORTED:"+status());
      output.textContent="EDGE_LOCAL_PASS";
    }catch(error){output.textContent="EDGE_LOCAL_FAIL:"+error.message;}
  });`;
  const server = http.createServer((request, response) => {
    if (request.url === "/zk1-protected-file-lab.html") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'self'; script-src 'self'; connect-src 'self'" });
      response.end(html.replace("</body>", '<script defer src="/__probe.js"></script></body>'));
    } else if (request.url === "/__probe.js") {
      response.writeHead(200, { "content-type": "application/javascript" });
      response.end(probe);
    } else if (/^\/client\/[a-z0-9-]+\.js$/.test(request.url || "")) {
      const name = request.url.slice("/client/".length, -3);
      if (!allowed.has(name)) { response.writeHead(404); response.end(); return; }
      const file = path.join(__dirname, "../public/client", name + ".js");
      response.writeHead(200, { "content-type": "application/javascript" });
      response.end(fs.readFileSync(file));
    } else { response.writeHead(404); response.end(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-offline-chunks-"));
  const profile = path.join(directory, "edge-profile");
  let edge, socket;
  try {
    edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--no-first-run",
      "--disable-extensions", "--remote-debugging-port=0",
      "--user-data-dir=" + profile, "about:blank"], { stdio: "ignore", windowsHide: true });
    const waitFor = async (read, ms = 23000) => {
      const deadline = Date.now() + ms;
      while (Date.now() < deadline) {
        const value = await read();
        if (value) return value;
        await new Promise((resolve) => setTimeout(resolve, 90));
      }
      throw Error("EDGE_LOCAL_TIMEOUT");
    };
    const port = await waitFor(() => {
      const file = path.join(profile, "DevToolsActivePort");
      if (!fs.existsSync(file)) return null;
      const n = Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]);
      return Number.isSafeInteger(n) && n > 0 ? n : null;
    });
    const tabs = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const tab = tabs.find((item) => item.type === "page");
    assert.ok(tab?.webSocketDebuggerUrl);
    socket = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    const pending = new Map();
    let next = 0;
    socket.addEventListener("message", ({ data }) => {
      const message = JSON.parse(data);
      const item = pending.get(message.id);
      if (!item) return;
      pending.delete(message.id);
      if (message.error) item.reject(new Error(message.error.message));
      else item.resolve(message.result);
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++next;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Page.navigate", { url: `http://127.0.0.1:${server.address().port}/zk1-protected-file-lab.html` });
    const result = await waitFor(async () => {
      const info = await send("Runtime.evaluate", {
        expression: "document.getElementById('edge-local-result')?.textContent || null",
        returnByValue: true,
      });
      const value = info.result?.value;
      return typeof value === "string" && /^EDGE_LOCAL_(PASS|FAIL)/.test(value) ? value : null;
    }, 26000);
    assert.equal(result, "EDGE_LOCAL_PASS");
  } finally {
    socket?.close();
    if (edge?.pid) {
      try { execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
        { stdio: "ignore", timeout: 10000 }); }
      catch (_) { edge.kill(); }
    }
    server.closeAllConnections();
    server.close();
    server.unref();
    let removed = false;
    for (let i = 0; i < 15; i++) {
      try { fs.rmSync(directory, { recursive: true, force: true }); removed = true; break; }
      catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 180));
      }
    }
    if (!removed) process.stderr.write("EDGE_LOCAL_PROFILE_CLEANUP_PENDING\n");
  }
});
