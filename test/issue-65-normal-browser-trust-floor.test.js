"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const floor = require("../public/client/rootark-zk1-normal-browser-trust-floor");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");

const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const ROOT = path.resolve(__dirname, "..");
const DOMAIN = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const GRANT = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch",
  "enrolled_epoch", "revoked_at_epoch"];
const b64 = (v) => Buffer.from(v).toString("base64url");
const negative = /ZK_NORMAL_BROWSER_LOCAL_FLOOR_UNVERIFIED/;

function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const spki = owner.publicKey.export({ type: "spki", format: "der" });
  const scope = { account_id: b64(crypto.randomBytes(16)),
    compartment_id: b64(crypto.randomBytes(10)), keyring_id: b64(crypto.randomBytes(16)) };
  const device = crypto.generateKeyPairSync("ed25519");
  const deviceRaw = device.publicKey.export({ type: "spki", format: "der" }).subarray(12);
  const hash = b64(crypto.createHash("sha256").update(spki).digest());
  function make(revision, epoch, digest = b64(crypto.randomBytes(32))) {
    const content = { schema: "rootark-zk1-browser-owner-device-grant/v1",
      ...scope, device_id: "owner-device", authorization_key_id: b64(crypto.randomBytes(16)),
      authorization_public_key: b64(deviceRaw), manifest_revision: revision,
      manifest_digest: digest, current_epoch: epoch, enrolled_epoch: 1,
      revoked_at_epoch: null };
    const message = Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((n) => [n, content[n]]))));
    const signature = crypto.sign(null, Buffer.concat([DOMAIN, message]), owner.privateKey);
    return { revision, epoch, digest, grant: { ...content, signature: b64(signature) } };
  }
  return { owner, spki, raw: spki.subarray(12), scope, hash,
    candidates: [make(5, 3), make(4, 2), make(5, 3), make(6, 2),
      make(6, 4), make(6, 4), make(7, 5)] };
}
function trustInput(nodePublicKey, hash, candidate, history = null) {
  return { ownerPublicKey: nodePublicKey,
    independentOwnerSpkiSha256: Buffer.from(hash, "base64url"),
    pinnedCurrentHead: { revision: candidate.revision,
      digest: Buffer.from(candidate.digest, "base64url"), epoch: candidate.epoch },
    signedDeviceGrant: candidate.grant, ownerHistoryCheckpoint: history };
}

test("Node24 synthetic owner grant, DER SPKI pin and signed history never bootstrap from forged input", async () => {
  const f = fixture();
  const subtle = crypto.webcrypto.subtle;
  const key = await subtle.importKey("spki", f.spki, "Ed25519", true, ["verify"]);
  const grant = f.candidates[0];
  const anchor = trustInput(key, f.hash, grant);
  const verified = await floor.verifyExternalAnchor(anchor);
  assert.equal(verified.candidate.revision, 5);
  assert.equal(verified.candidate.epoch, 3);
  assert.equal(verified.candidate.ownerSpkiSha256, f.hash);
  await assert.rejects(floor.verifyExternalAnchor({
    ...anchor, independentOwnerSpkiSha256: crypto.randomBytes(32) }), negative);
  await assert.rejects(floor.verifyExternalAnchor({
    ...anchor, signedDeviceGrant: { ...grant.grant, manifest_revision: 6 } }), negative);
  await assert.rejects(floor.verifyExternalAnchor({
    ...anchor, signedDeviceGrant: { ...grant.grant,
      signature: b64(crypto.randomBytes(64)) } }), negative);
  const ownerPrivate = await subtle.importKey("pkcs8",
    f.owner.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const history = await ownerHistory.signOwnerCheckpoint({
    scope: f.scope, signerKey: ownerPrivate, signerPublicKey: key,
    signerKeyId: crypto.randomBytes(16), deviceId: "owner-device",
    revision: grant.revision, manifestDigest: Buffer.from(grant.digest, "base64url"),
    issuedAt: 100, previous: null,
  });
  assert.equal((await floor.verifyExternalAnchor(
    trustInput(key, f.hash, grant, history))).candidate.revision, 5);
  await assert.rejects(floor.verifyExternalAnchor(
    trustInput(key, f.hash, f.candidates[4], history)), negative);
  // A signed grant can be valid yet must not silently create an absent floor.
  await assert.rejects(floor.assertCurrent(anchor), negative);
});

async function waitFor(callback, max = 15000) {
  const until = Date.now() + max;
  while (Date.now() < until) {
    const result = await callback();
    if (result) return result;
    await new Promise((r) => setTimeout(r, 90));
  }
  throw new Error("Edge CDP did not become ready");
}
async function connect(ws) {
  const socket = new WebSocket(ws);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  const waiting = new Map();
  let id = 0;
  socket.addEventListener("message", ({ data }) => {
    const message = JSON.parse(data);
    if (!waiting.has(message.id)) return;
    const { resolve, reject } = waiting.get(message.id);
    waiting.delete(message.id);
    if (message.error) reject(new Error(message.error.message));
    else resolve(message.result);
  });
  return { socket, send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const next = ++id;
      waiting.set(next, { resolve, reject });
      socket.send(JSON.stringify({ id: next, method, params }));
    });
  } };
}
async function evaluate(client, expression) {
  const result = await client.send("Runtime.evaluate", {
    expression, awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) throw new Error(
    result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  return result.result?.value;
}

test("real Edge IndexedDB serializes two tabs, denies rollback/forks/epoch regressions and corrupt records", {
  timeout: 75000,
}, async (t) => {
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Edge Windows unavailable"); return;
  }
  const f = fixture();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-normal-floor-edge-"));
  const profile = path.join(tmp, "profile");
  const scripts = [ "rootark-zk1-owner-signed-checkpoint.js",
    "rootark-zk1-normal-browser-trust-floor.js" ];
  const server = http.createServer((req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Security-Policy",
      "default-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'");
    if (req.url === "/") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end("<!doctype html><meta charset='utf-8'>" +
        scripts.map((name) => '<script defer src="/client/' + name + '"></script>').join(""));
    } else if (scripts.some((name) => req.url === "/client/" + name)) {
      res.setHeader("Content-Type", "application/javascript");
      fs.createReadStream(path.join(ROOT, "public/client", req.url.split("/").pop())).pipe(res);
    } else { res.statusCode = 404; res.end(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = "http://127.0.0.1:" + server.address().port;
  const edge = spawn(EDGE, [ "--headless=new", "--disable-gpu",
    "--no-first-run", "--disable-extensions", "--remote-debugging-port=0",
    "--user-data-dir=" + profile, "about:blank" ],
  { stdio: "ignore", windowsHide: true });
  const clients = [];
  try {
    const port = await waitFor(() => {
      const active = path.join(profile, "DevToolsActivePort");
      if (!fs.existsSync(active)) return null;
      const number = Number(fs.readFileSync(active, "utf8").split(/\r?\n/)[0]);
      return Number.isSafeInteger(number) && number > 0 ? number : null;
    });
    const list = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    const tab1 = list.find((item) => item.type === "page");
    const created = await fetch("http://127.0.0.1:" + port
      + "/json/new?" + encodeURIComponent(origin + "/"), { method: "PUT" });
    assert.equal(created.status, 200);
    const tab2 = await created.json();
    for (const tab of [tab1, tab2]) {
      const client = await connect(tab.webSocketDebuggerUrl);
      clients.push(client);
      await client.send("Page.enable");
      await client.send("Runtime.enable");
      await client.send("Page.navigate", { url: origin + "/" });
      await waitFor(async () => await evaluate(client,
        "Boolean(window.RootarkZk1NormalBrowserTrustFloor)"));
      const prepare = `(async()=>{const test=${JSON.stringify({
        ownerRaw: b64(f.raw), spkiHash: f.hash, candidates: f.candidates,
      })};const decode=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const key=await crypto.subtle.importKey("raw",decode(test.ownerRaw),"Ed25519",true,["verify"]);
window.__floorArg=n=>({ownerPublicKey:key,independentOwnerSpkiSha256:decode(test.spkiHash),
  pinnedCurrentHead:{revision:test.candidates[n].revision,digest:decode(test.candidates[n].digest),epoch:test.candidates[n].epoch},
  signedDeviceGrant:test.candidates[n].grant,ownerHistoryCheckpoint:null});
window.__run=async(method,n)=>{try{await window.RootarkZk1NormalBrowserTrustFloor[method](window.__floorArg(n));return "ALLOW";}
catch(e){return e.message==="ZK_NORMAL_BROWSER_LOCAL_FLOOR_UNVERIFIED"?"DENY":"ERROR:"+e.message;}};
return "READY"})()`;
      assert.equal(await evaluate(client, prepare), "READY");
    }
    const [a, b] = clients;
    assert.equal(await evaluate(a, "__run('assertCurrent',0)"), "DENY",
      "signed grant cannot silently create local floor");
    assert.equal(await evaluate(a, "__run('provisionOffline',0)"), "ALLOW");
    assert.equal(await evaluate(b, "__run('assertCurrent',0)"), "ALLOW");
    for (const index of [1, 2, 3]) {
      assert.equal(await evaluate(a, `__run('provisionOffline',${index})`), "DENY",
        "revision rollback, same-revision fork, epoch rollback");
    }
    // Two actual browser tabs race two separately signed revision-6 forks.
    const races = await Promise.all([
      evaluate(a, "__run('provisionOffline',4)"),
      evaluate(b, "__run('provisionOffline',5)"),
    ]);
    assert.deepEqual([...races].sort(), ["ALLOW", "DENY"],
      "only one same-revision digest may win the IndexedDB transaction");
    const expected = races[0] === "ALLOW" ? 4 : 5;
    assert.equal(await evaluate(a, `__run('assertCurrent',${expected})`), "ALLOW");
    assert.equal(await evaluate(b, "__run('assertCurrent',0)"), "DENY",
      "other tab refuses old signed checkpoint after advance");
    assert.equal(await evaluate(b, "__run('provisionOffline',6)"), "ALLOW");
    assert.equal(await evaluate(a, `__run('provisionOffline',${expected})`), "DENY",
      "late stale tab cannot erase later floor");
    const corrupted = `(async()=>{const input=window.__floorArg(6);
const scope=input.signedDeviceGrant;
const id=JSON.stringify([scope.account_id,scope.compartment_id,scope.keyring_id]);
const db=await new Promise((resolve,reject)=>{const r=indexedDB.open("rootark-zk1-normal-browser-owner-floor-v1",1);
 r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)});
await new Promise((resolve,reject)=>{const tx=db.transaction("owners","readwrite");
tx.objectStore("owners").put({schema:"rootark-zk1-normal-browser-owner-floor/v1",
ownerSpkiSha256:"corrupt",revision:999,digest:"corrupt",epoch:NaN},id);
tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error)});
db.close();return "CORRUPTED"})()`;
    assert.equal(await evaluate(b, corrupted), "CORRUPTED");
    assert.equal(await evaluate(a, "__run('assertCurrent',6)"), "DENY");
    assert.equal(await evaluate(b, "__run('provisionOffline',6)"), "DENY",
      "corrupt floor cannot be repaired by clearing/reinitializing implicitly");
  } finally {
    for (const client of clients) client.socket.close();
    if (edge.pid) {
      try { execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
        { stdio: "ignore", timeout: 10000 }); } catch (_) { edge.kill(); }
    }
    await new Promise((resolve) => server.close(resolve));
    for (let i = 0; i < 15; ++i) {
      try { fs.rmSync(tmp, { recursive: true, force: true }); break; }
      catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((r) => setTimeout(r, 180));
      }
    }
  }
});
