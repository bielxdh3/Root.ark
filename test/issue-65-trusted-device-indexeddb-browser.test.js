"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const test = require("node:test");
const WebSocket = require("ws");

const ROOT = path.resolve(__dirname, "..");
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const SCRIPTS = new Map([
  ["/client/rootark-dev-vault-crypto.js",
    path.join(ROOT, "public/client/rootark-dev-vault-crypto.js")],
  ["/client/rootark-dev-vault-trusted-device.js",
    path.join(ROOT, "public/client/rootark-dev-vault-trusted-device.js")],
  ["/client/rootark-dev-vault-ui.js",
    path.join(ROOT, "public/client/rootark-dev-vault-ui.js")],
  ["/client/rootark-zk1-owner-signed-checkpoint.js",
    path.join(ROOT, "public/client/rootark-zk1-owner-signed-checkpoint.js")],
  ["/client/rootark-zk1-owner-checkpoint-indexeddb.js",
    path.join(ROOT, "public/client/rootark-zk1-owner-checkpoint-indexeddb.js")],
]);
const BROWSER_PROBE = [
  '(async () => {',
  ' const recovery = window.RootarkDevVaultTrustedDevice;',
  ' const vault = window.RootarkDevVaultCrypto;',
  ' if (!recovery || !vault || !window.indexedDB) throw Error("browser feature missing");',
  ' const original = await vault.generateRecoveryKey();',
  ' const keyId = await vault.keyCommitment(original.recoveryKey, "alice");',
  ' const enrolled = await recovery.enrollTrustedDevice({ username:"alice", recoveryKey:original.recoveryKey, keyId });',
  ' const pending = await recovery.createRecoveryRequest({username:"alice"});',
  ' const db = await new Promise((resolve,reject) => {',
  '  const open = indexedDB.open("rootark-trusted-device-fixture-v1",1);',
  '  open.onupgradeneeded = () => { open.result.createObjectStore("trusted"); open.result.createObjectStore("pending"); };',
  '  open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error);',
  ' });',
  ' await new Promise((resolve,reject) => {',
  '  const tx = db.transaction(["trusted","pending"],"readwrite");',
  '  tx.objectStore("trusted").put(enrolled,"alice");',
  '  tx.objectStore("pending").put(pending,"alice");',
  '  tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);',
  ' });',
  ' db.close();',
  ' const fresh = await new Promise((resolve,reject) => {',
  '  const open = indexedDB.open("rootark-trusted-device-fixture-v1",1);',
  '  open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error);',
  ' });',
  ' const read = (store) => new Promise((resolve,reject) => {',
  '  const tx = fresh.transaction(store,"readonly"); const get = tx.objectStore(store).get("alice");',
  '  get.onsuccess = () => resolve(get.result); get.onerror = () => reject(get.error);',
  ' });',
  ' const saved = await read("trusted"); const waiting = await read("pending");',
  ' fresh.close();',
  ' if (saved.wrappingKey.extractable || waiting.privateKey.extractable)',
  '  throw Error("exportable key after IndexedDB restore");',
  ' const answer = await recovery.approveRecoveryRequest({',
  '  username:"alice", record:saved, request:waiting.request });',
  ' const restored = await recovery.completeRecoveryRequest({',
  '  username:"alice", privateKey:waiting.privateKey, request:waiting.request, answer });',
  ' if (restored.recoveryKey !== original.recoveryKey || restored.keyId !== keyId)',
  '  throw Error("incorrect recovery key after IndexedDB roundtrip");',
  ' return "BROWSER_TRUSTED_DEVICE_INDEXEDDB_PASS";',
  '})()',
].join("\n");
const NORMAL_SESSION_UI_PROBE = `(async () => {
  const el = id => document.getElementById(id);
  const until = async check => {
    for (let i=0;i<250;i++) {
      const value=await check(); if (value) return value;
      await new Promise(resolve=>setTimeout(resolve,20));
    }
    throw Error("UI_ACTION_TIMEOUT: "+el("status").textContent);
  };
  await until(()=>el("account")?.textContent.includes("alice"));
  await until(()=>el("status")?.textContent.includes("Cofre acessível"));
  window.confirm=()=>true;
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open("rootark-opaque-dev-vault-key-v1",2);
    req.onsuccess=()=>resolve(req.result); req.onerror=()=>reject(req.error);
  });
  const read=store=>new Promise((resolve,reject)=>{
    const tx=db.transaction(store,"readonly");
    const req=tx.objectStore(store).get("alice");
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
  const write=(store,record)=>new Promise((resolve,reject)=>{
    const tx=db.transaction(store,"readwrite");
    tx.objectStore(store).put(record,"alice");
    tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error);
  });
  const original=await RootarkDevVaultCrypto.generateRecoveryKey();
  const keyId=await RootarkDevVaultCrypto.keyCommitment(original.recoveryKey,"alice");
  el("recovery").value=original.recoveryKey;
  el("import").click();
  await until(()=>el("status").textContent.includes("Chave importada"));
  el("save-device").click();
  await until(async()=>Boolean(await read("keys")));
  el("emergency-recovery-key").value=original.recoveryKey;
  el("device-enroll").click();
  await until(async()=>Boolean(await read("trusted")));
  el("device-request").click();
  const first=await until(()=>read("pending"));
  const oldCode=el("device-request-code").textContent;
  if (!first.privateKey || oldCode.length!==22) throw Error("FIRST_REQUEST_MISSING");
  el("device-request").click();
  await until(()=>el("status").textContent.includes("Existe uma solicitação pendente"));
  if ((await read("pending")).request.requestId!==first.request.requestId)
    throw Error("ACTIVE_REQUEST_REPLACED_WITHOUT_CANCEL");
  const expiredAt=Date.now()-1000;
  const stale={...first,request:{...first.request,
    createdAt:expiredAt-15*60*1000,expiresAt:expiredAt}};
  await write("pending",stale);
  el("device-request").click();
  const second=await until(async()=>{
    const current=await read("pending");
    return current?.request.requestId!==first.request.requestId && current;
  });
  if (!second.privateKey || second.privateKey.extractable!==false
    || el("device-request-code").textContent===oldCode)
    throw Error("EXPIRED_REQUEST_NOT_REPLACED");
  if ((await read("keys"))?.keyId!==keyId
    || (await read("trusted"))?.keyId!==keyId)
    throw Error("EXPIRY_RENEWAL_REMOVED_TRUSTED_KEYS");
  // A second tab changes the pending request after this tab has read it,
  // during the human confirmation. The first tab must not delete it.
  const race=await RootarkDevVaultTrustedDevice.createRecoveryRequest({username:"alice"});
  window.confirm=()=>{
    const tx=db.transaction("pending","readwrite");
    tx.objectStore("pending").put(race,"alice");
    return true;
  };
  el("device-cancel").click();
  await until(async()=> (await read("pending"))?.request.requestId===race.request.requestId);
  await new Promise(resolve=>setTimeout(resolve,100));
  if ((await read("pending"))?.request.requestId!==race.request.requestId)
    throw Error("CONCURRENT_REPLACEMENT_DELETED");
  window.confirm=()=>true;
  el("device-cancel").click();
  await until(async()=>!(await read("pending")));
  if ((await read("keys"))?.keyId!==keyId
    || (await read("trusted"))?.keyId!==keyId
    || el("device-request-code").textContent!=="Nenhuma solicitação pendente")
    throw Error("CANCEL_DAMAGED_KEYS_OR_UI");
  // IndexedDB preserves NaN numbers. A corrupt pending timestamp must still
  // be cancellable without using the destructive Forget all local keys action.
  const malformedRequest=await RootarkDevVaultTrustedDevice.createRecoveryRequest({username:"alice"});
  const malformed={...malformedRequest,request:{...malformedRequest.request,
    createdAt:Number.NaN,expiresAt:Number.NaN}};
  await write("pending",malformed);
  const restoredMalformed=await read("pending");
  if (!Number.isNaN(restoredMalformed?.request.createdAt)
    || !Number.isNaN(restoredMalformed?.request.expiresAt))
    throw Error("INDEXEDDB_DID_NOT_PRESERVE_NAN");
  // Even a malformed expected request cannot cancel a different new request
  // inserted while the user is confirming the operation.
  const replacement=await RootarkDevVaultTrustedDevice.createRecoveryRequest({username:"alice"});
  window.confirm=()=>{
    const tx=db.transaction("pending","readwrite");
    tx.objectStore("pending").put(replacement,"alice");
    return true;
  };
  el("device-cancel").click();
  await until(async()=> (await read("pending"))?.request.requestId===replacement.request.requestId);
  await new Promise(resolve=>setTimeout(resolve,100));
  if ((await read("pending"))?.request.requestId!==replacement.request.requestId)
    throw Error("MALFORMED_CANCEL_DELETED_NEW_REQUEST");
  await write("pending",malformed);
  window.confirm=()=>true;
  el("device-cancel").click();
  await until(async()=>!(await read("pending")));
  if ((await read("keys"))?.keyId!==keyId
    || (await read("trusted"))?.keyId!==keyId)
    throw Error("MALFORMED_CANCEL_DELETED_TRUSTED_KEYS");
  el("device-request").click();
  const third=await until(()=>read("pending"));
  window.__testAccount="bob";
  el("device-cancel").click();
  await until(()=>el("account").textContent.includes("mudou"));
  if ((await read("pending"))?.request.requestId!==third.request.requestId)
    throw Error("CHANGED_ACCOUNT_REMOVED_OTHER_ACCOUNT_REQUEST");
  db.close();
  return "NORMAL_SESSION_DEVICE_PENDING_UI_PASS";
})()`;
const OWNER_CHECKPOINT_PROBE = `(async () => {
  const cryptoClient = RootarkZk1OwnerSignedCheckpoint;
  const idb = RootarkZk1OwnerCheckpointIndexedDb;
  if (!cryptoClient || !idb) throw Error("CHECKPOINT_SCRIPT_MISSING");
  const enc = bytes => btoa(String.fromCharCode(...bytes))
    .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"");
  const scope = {
    account_id: enc(crypto.getRandomValues(new Uint8Array(16))),
    compartment_id: enc(new TextEncoder().encode("fixture-independent-owner")),
    keyring_id: enc(crypto.getRandomValues(new Uint8Array(16))),
  };
  const keys = await crypto.subtle.generateKey({ name:"Ed25519" }, false, ["sign","verify"]);
  if (keys.privateKey.extractable) throw Error("EXTRACTABLE_OWNER_PRIVATE_KEY");
  const keyId = crypto.getRandomValues(new Uint8Array(16));
  const common = {scope, signerKey:keys.privateKey, signerPublicKey:keys.publicKey,
    signerKeyId:keyId, deviceId:"edge-owner", issuedAt:1001};
  const persistent = {scope, deviceId:common.deviceId,
    signerKeyId:keyId, signerPublicKey:keys.publicKey};
  const name = "rootark-zk1-owner-checkpoints-v1";
  let store = await idb.openOwnerCheckpointStore({databaseName:name});
  const firstWire = await cryptoClient.signOwnerCheckpoint({
    ...common, revision:1,
    manifestDigest:crypto.getRandomValues(new Uint8Array(32)), previous:null,
  });
  const first = await store.bootstrapOwnerCheckpoint({ ...persistent, checkpoint:firstWire });
  if (!first.storedLocally || first.authorizesProtectedIo) throw Error("WRONG_LOCAL_BOOTSTRAP");
  store.close();
  store = await idb.openOwnerCheckpointStore({databaseName:name});
  const afterRestart = await store.loadOwnerCheckpoint({
    ...persistent, expectedExternalDigest:first.checkpointDigest,
  });
  if (afterRestart.checkpointDigest !== first.checkpointDigest
    || afterRestart.verifiedCheckpoint.sequence !== 1) throw Error("RESTART_LOST_CHECKPOINT");
  // Typed-array view variants have the same bytes but different JS object
  // shapes; owner key IDs must be snapshotted as bytes, not array elements.
  const keyIdView = new DataView(keyId.buffer.slice(
    keyId.byteOffset, keyId.byteOffset + keyId.byteLength));
  const loadedThroughView = await store.loadOwnerCheckpoint({
    ...persistent, signerKeyId:keyIdView, expectedExternalDigest:first.checkpointDigest,
  });
  if (loadedThroughView?.checkpointDigest !== first.checkpointDigest)
    throw Error("IDB_DATAVIEW_KEY_ID_REJECTED");
  const secondWire = await cryptoClient.signOwnerCheckpoint({
    ...common, revision:2, issuedAt:1002,
    manifestDigest:crypto.getRandomValues(new Uint8Array(32)),
    previous:afterRestart.verifiedCheckpoint,
  });
  await store.appendOwnerCheckpoint({ ...persistent, checkpoint:secondWire,
    expectedHeadDigest:afterRestart.checkpointDigest });
  const second = await store.loadOwnerCheckpoint({...persistent});
  const candidateA = await cryptoClient.signOwnerCheckpoint({
    ...common, revision:3, issuedAt:1003,
    manifestDigest:crypto.getRandomValues(new Uint8Array(32)),
    previous:second.verifiedCheckpoint,
  });
  const candidateB = await cryptoClient.signOwnerCheckpoint({
    ...common, revision:3, issuedAt:1003,
    manifestDigest:crypto.getRandomValues(new Uint8Array(32)),
    previous:second.verifiedCheckpoint,
  });
  const outcomes = await Promise.allSettled([
    store.appendOwnerCheckpoint({...persistent,
      checkpoint:candidateA, expectedHeadDigest:second.checkpointDigest}),
    store.appendOwnerCheckpoint({...persistent,
      checkpoint:candidateB, expectedHeadDigest:second.checkpointDigest}),
  ]);
  if (outcomes.filter(x=>x.status==="fulfilled").length !== 1
    || outcomes.filter(x=>x.status==="rejected").length !== 1)
    throw Error("CHECKPOINT_CONCURRENT_CAS_NOT_SERIALIZED");
  const committed = await store.loadOwnerCheckpoint({...persistent});
  if (committed.verifiedCheckpoint.sequence !== 3) throw Error("CHECKPOINT_LOST_CONCURRENT_COMMIT");
  const tamperDb = await new Promise((resolve,reject)=>{
    const request=indexedDB.open(name,1);
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error);
  });
  const key = JSON.stringify([scope.account_id,scope.compartment_id,
    scope.keyring_id,common.deviceId,enc(keyId)]);
  const rawRecord = await new Promise((resolve,reject)=>{
    const tx=tamperDb.transaction("owner_checkpoints","readonly");
    const request=tx.objectStore("owner_checkpoints").get(key);
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error);
  });
  if (!rawRecord || rawRecord.records.length !== 3)
    throw Error("TEST_OWNER_CHECKPOINT_LEDGER_NOT_CREATED");
  const putTamper = value => new Promise((resolve,reject)=>{
    const tx=tamperDb.transaction("owner_checkpoints","readwrite");
    tx.objectStore("owner_checkpoints").put(value,key);
    tx.oncomplete=resolve;
    tx.onerror=()=>reject(tx.error);
    tx.onabort=()=>reject(tx.error);
  });
  const corrupted=structuredClone(rawRecord);
  corrupted.records[0].signature=enc(crypto.getRandomValues(new Uint8Array(64)));
  await putTamper(corrupted);
  let corruptDenied=false;
  try { await store.loadOwnerCheckpoint({
    ...persistent,expectedExternalDigest:committed.checkpointDigest,
  }); } catch(e) {
    corruptDenied=e.message==="ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED";
  }
  if (!corruptDenied) throw Error("CHECKPOINT_INVALID_SIGNATURE_WAS_ACCEPTED");
  await putTamper({schema:rawRecord.schema,records:[rawRecord.records[0]],
    headDigest:first.checkpointDigest});
  let rollbackDenied=false;
  try { await store.loadOwnerCheckpoint({
    ...persistent,expectedExternalDigest:committed.checkpointDigest,
  }); } catch(e) {
    rollbackDenied=e.message==="ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED";
  }
  if (!rollbackDenied) throw Error("CHECKPOINT_COHERENT_ROLLBACK_WAS_ACCEPTED");
  await putTamper(rawRecord);
  tamperDb.close();
  const recovered=await store.loadOwnerCheckpoint({
    ...persistent,expectedExternalDigest:committed.checkpointDigest,
  });
  if (recovered.verifiedCheckpoint.sequence !== 3)
    throw Error("CHECKPOINT_RESTORED_ORIGINAL_NOT_VERIFIABLE");
  store.close();
  // Malicious/silent deletion of the ENTIRE test-owned IndexedDB cannot be
  // mistaken for a fresh owner identity when the caller retains its floor.
  await new Promise((resolve,reject)=>{
    const req=indexedDB.deleteDatabase(name);
    req.onsuccess=resolve; req.onerror=()=>reject(req.error);
    req.onblocked=()=>reject(Error("CHECKPOINT_DB_DELETE_BLOCKED"));
  });
  store = await idb.openOwnerCheckpointStore({databaseName:name});
  let refused = false;
  try { await store.loadOwnerCheckpoint({
    ...persistent, expectedExternalDigest:committed.checkpointDigest,
  }); } catch (error) {
    refused = error.message === "ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED";
  }
  store.close();
  if (!refused) throw Error("MISSING_LOCAL_HIGH_WATER_ACCEPTED");
  return "BROWSER_OWNER_CHECKPOINT_INDEXEDDB_PASS";
})()`;

async function waitFor(condition, timeoutMs = 15000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const ready = await condition();
    if (ready) return ready;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Browser debugging session did not become ready");
}

async function connectDevTools(socketUrl) {
  const socket = new WebSocket(socketUrl);
  await new Promise((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("error", reject);
  });
  const inflight = new Map();
  let sequence = 0;
  socket.on("message", (data) => {
    const reply = JSON.parse(data.toString());
    if (!reply.id || !inflight.has(reply.id)) return;
    const { resolve, reject } = inflight.get(reply.id);
    inflight.delete(reply.id);
    if (reply.error) reject(new Error(reply.error.message));
    else resolve(reply.result);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    inflight.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }), (error) => {
      if (error && inflight.has(id)) {
        inflight.delete(id);
        reject(error);
      }
    });
  });
  return { socket, send };
}

test("real Edge IndexedDB restores nonextractable trusted-device keys for independent recovery", {
  timeout: 60000,
}, async (t) => {
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Microsoft Edge headless only runs on Windows");
    return;
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-idb-"));
  const profile = path.join(tmp, "profile");
  const server = http.createServer((req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'");
    if (req.url === "/") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end('<!doctype html><meta charset="utf-8"><script defer src="/client/rootark-dev-vault-crypto.js"></script><script defer src="/client/rootark-dev-vault-trusted-device.js"></script><script defer src="/client/rootark-zk1-owner-signed-checkpoint.js"></script><script defer src="/client/rootark-zk1-owner-checkpoint-indexeddb.js"></script>');
    } else if (req.url === "/ui") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      fs.createReadStream(path.join(ROOT,"public/zk-dev-vault.html")).pipe(res);
    } else if (req.url === "/client/rootark-api.js") {
      res.setHeader("Content-Type", "application/javascript");
      res.end('window.__testAccount="alice";window.RootarkApi={get:async url=>url.endsWith("/session")?{username:window.__testAccount,activeKeyId:null}:{objects:[]}};');
    } else if (SCRIPTS.has(req.url)) {
      res.setHeader("Content-Type", "application/javascript");
      fs.createReadStream(SCRIPTS.get(req.url)).pipe(res);
    } else { res.statusCode = 404; res.end(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = "http://127.0.0.1:" + server.address().port;
  const edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--no-first-run",
    "--disable-extensions", "--no-default-browser-check",
    "--remote-debugging-port=0", "--user-data-dir=" + profile,
    "about:blank"], { stdio: "ignore", windowsHide: true });
  let client;
  try {
    const activePort = path.join(profile, "DevToolsActivePort");
    const port = await waitFor(() => {
      if (!fs.existsSync(activePort)) return null;
      const value = Number(fs.readFileSync(activePort, "utf8").split(/\r?\n/)[0]);
      return Number.isSafeInteger(value) && value > 0 ? value : null;
    });
    const targets = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    const page = targets.find((item) => item.type === "page");
    assert.ok(page?.webSocketDebuggerUrl, "isolated Edge tab must be accessible");
    client = await connectDevTools(page.webSocketDebuggerUrl);
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    await client.send("Page.navigate", { url: origin + "/" });
    await waitFor(async () => {
      const r = await client.send("Runtime.evaluate", {
        expression: "Boolean(window.RootarkDevVaultTrustedDevice && window.RootarkDevVaultCrypto)",
        returnByValue: true,
      });
      return r.result?.value === true;
    }, 15000);
    const response = await client.send("Runtime.evaluate", {
      expression: BROWSER_PROBE,
      awaitPromise: true,
      returnByValue: true,
    });
    assert.equal(response.exceptionDetails, undefined,
      response.exceptionDetails?.text || "Device recovery crashed in browser");
    assert.equal(response.result?.value, "BROWSER_TRUSTED_DEVICE_INDEXEDDB_PASS");
    const checkpoint = await client.send("Runtime.evaluate", {
      expression: OWNER_CHECKPOINT_PROBE, awaitPromise: true, returnByValue: true,
    });
    assert.equal(checkpoint.exceptionDetails, undefined,
      checkpoint.exceptionDetails?.text || "Owner checkpoint IndexedDB crashed in browser");
    assert.equal(checkpoint.result?.value, "BROWSER_OWNER_CHECKPOINT_INDEXEDDB_PASS");
    await client.send("Page.navigate", { url: origin + "/ui" });
    await waitFor(async () => {
      const result = await client.send("Runtime.evaluate", {
        expression: "Boolean(window.RootarkDevVaultTrustedDevice && document.getElementById('device-cancel') && window.RootarkApi)",
        returnByValue: true,
      });
      return result.result?.value === true;
    });
    const ui = await client.send("Runtime.evaluate", {
      expression: NORMAL_SESSION_UI_PROBE, awaitPromise: true, returnByValue: true,
    });
    assert.equal(ui.exceptionDetails, undefined,
      JSON.stringify(ui.exceptionDetails || ui.result));
    assert.equal(ui.result?.value, "NORMAL_SESSION_DEVICE_PENDING_UI_PASS");
  } finally {
    client?.socket.close();
    // Only the unique test-owned browser process/tree is terminated.
    if (edge.pid) {
      try { execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
        { stdio: "ignore", timeout: 10000 }); } catch (_) { edge.kill(); }
    }
    await new Promise((resolve) => server.close(resolve));
    if (edge.exitCode === null && edge.signalCode === null) {
      await Promise.race([
        new Promise((resolve) => edge.once("exit", resolve)),
        new Promise((resolve) => setTimeout(resolve, 1500)),
      ]);
    }
    // The test-owned Edge profile may briefly retain Win32 file handles
    // after taskkill exits. Do not mask an actual browser test failure with
    // a transient cleanup EPERM.
    let removed = false;
    for (let attempt = 0; attempt < 18; attempt += 1) {
      try {
        fs.rmSync(tmp, { recursive: true, force: true });
        removed = true;
        break;
      } catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
    }
    if (!removed) process.stderr.write("DEV_DEVICE_TEST_PROFILE_CLEANUP_PENDING\n");
  }
});
