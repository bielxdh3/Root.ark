"use strict";

// Optional real Edge IndexedDB smoke test (Node 24, Windows, no npm packages).
// Run explicitly: node test/support/issue-65-cek-edge-manual.js
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const { spawn } = require("node:child_process");
const assert = require("node:assert/strict");
const source = fs.readFileSync(path.join(__dirname,
  "../../public/client/rootark-zk1-client-cek-archive.js"));
const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function run() {
  if (!fs.existsSync(edge)) throw Error("EDGE_UNAVAILABLE");
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cek-edge-"));
  const server = http.createServer((request, response) => {
    if (request.url === "/archive.js") {
      response.writeHead(200, { "Content-Type": "text/javascript" });
      response.end(source);
    } else {
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end("<!doctype html><script src='/archive.js'></script><title>CEK Edge</title>");
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const child = spawn(edge, ["--headless=new", "--disable-gpu", "--no-first-run",
    "--no-default-browser-check", "--disable-extensions", "--remote-debugging-port=0",
    `--user-data-dir=${profile}`, `http://127.0.0.1:${port}/`],
  { stdio: "ignore", windowsHide: true });
  let socket;
  try {
    const file = path.join(profile, "DevToolsActivePort");
    let debuggingPort = 0;
    for (let i = 0; i < 80; i++) {
      if (fs.existsSync(file)) {
        debuggingPort = Number(fs.readFileSync(file, "utf8").split("\n")[0]);
        break;
      }
      if (child.exitCode !== null) throw Error("EDGE_START_FAILED");
      await sleep(100);
    }
    if (!debuggingPort) throw Error("EDGE_DEBUG_PORT_TIMEOUT");
    let tab;
    for (let i = 0; i < 40; i++) {
      const pages = await (await fetch(`http://127.0.0.1:${debuggingPort}/json/list`)).json();
      tab = pages.find((item) => item.type === "page" && item.url.includes(`:${port}/`));
      if (tab) break;
      await sleep(100);
    }
    if (!tab) throw Error("EDGE_TEST_TAB_MISSING");
    socket = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.onopen = resolve;
      socket.onerror = reject;
    });
    let counter = 0;
    const pending = new Map();
    socket.onmessage = (event) => {
      const reply = JSON.parse(event.data);
      if (pending.has(reply.id)) {
        const { resolve, reject } = pending.get(reply.id);
        pending.delete(reply.id);
        if (reply.error) reject(Error(JSON.stringify(reply.error)));
        else resolve(reply.result);
      }
    };
    function cdp(method, params = {}) {
      const id = ++counter;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        socket.send(JSON.stringify({ id, method, params }));
      });
    }
    async function evaluate(expression) {
      const reply = await cdp("Runtime.evaluate", {
        expression, awaitPromise: true, returnByValue: true });
      if (reply.exceptionDetails) throw Error(JSON.stringify(reply.exceptionDetails));
      return reply.result.value;
    }
    let browserReady = null;
    for (let attempt = 0; attempt < 50; attempt++) {
      browserReady = await evaluate("({href:location.href,ready:document.readyState,secure:isSecureContext,subtle:!!crypto.subtle,loaded:!!globalThis.RootarkZk1ClientCekArchive})");
      if (browserReady.secure && browserReady.subtle && browserReady.loaded) break;
      await sleep(100);
    }
    if (!browserReady.secure || !browserReady.subtle || !browserReady.loaded)
      throw Error(`EDGE_TEST_ORIGIN_UNREADY ${JSON.stringify(browserReady)}`);
    const before = await evaluate(`(async () => {
      const crypto = globalThis.crypto, subtle = crypto.subtle;
      const b64 = (v) => btoa(String.fromCharCode(...v)).replace(/\\+/g,'-')
        .replace(/\\//g,'_').replace(/=+$/g,'');
      const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
      const owner = await subtle.generateKey('Ed25519', true, ['sign','verify']);
      const scope = { account_id:b64(rand(16)), compartment_id:b64(rand(16)),
        keyring_id:b64(rand(16)) };
      const head = { revision:3, digest:rand(32), epoch:2 };
      const grant = { schema:'rootark-zk1-browser-owner-device-grant/v1', ...scope,
        device_id:'edge-device', authorization_key_id:b64(rand(16)),
        authorization_public_key:b64(rand(32)), manifest_revision:head.revision,
        manifest_digest:b64(head.digest), current_epoch:head.epoch,
        enrolled_epoch:1, revoked_at_epoch:null };
      const fields = ['schema','account_id','compartment_id','keyring_id','device_id',
        'authorization_key_id','authorization_public_key','manifest_revision',
        'manifest_digest','current_epoch','enrolled_epoch','revoked_at_epoch'];
      const prefix = new TextEncoder().encode('Root.ark/zk-1/browser-owner-device-grant/v1\\0');
      const body = new TextEncoder().encode(JSON.stringify(Object.fromEntries(fields.map(k => [k,grant[k]]))));
      const msg = new Uint8Array(prefix.length + body.length);
      msg.set(prefix); msg.set(body,prefix.length);
      grant.signature = b64(new Uint8Array(await subtle.sign('Ed25519', owner.privateKey, msg)));
      const pub = new Uint8Array(await subtle.exportKey('spki',owner.publicKey));
      const pin = new Uint8Array(await subtle.digest('SHA-256',pub));
      const secret = rand(32), cek=rand(32), ciphertext=rand(60), nonce=b64(rand(32));
      const metadata = { ...scope, object_id:b64(rand(16)), version_id:b64(rand(16)),
        parent_version_id:null, epoch:2, kind:'file' };
      const dg = b64(new Uint8Array(await subtle.digest('SHA-256',ciphertext)));
      const challenge = { objectId:metadata.object_id, action:'rename', epoch:2, nonce,
        entries:[{ revision:1, versionId:metadata.version_id, ciphertextDigest:dg }] };
      const iv=rand(12), text=new TextEncoder().encode('EDGE_REAL_IDB');
      const cekKey=await subtle.importKey('raw',cek,'AES-GCM',false,['encrypt']);
      const sample=new Uint8Array(await subtle.encrypt({name:'AES-GCM',iv},cekKey,text));
      const state={ secret:b64(secret), publicKey:b64(pub),
        pin:b64(pin), head:{ ...head,digest:b64(head.digest) }, grant,
        metadata, challenge, iv:b64(iv), sample:b64(sample) };
      sessionStorage.setItem('fixture',JSON.stringify(state));
      const dbpin={read:async()=>sessionStorage.getItem('pin'),
        compareAndSwap:async(old,next)=>{
          if(sessionStorage.getItem('pin')!==old)throw Error('CAS');
          sessionStorage.setItem('pin',next);
        }};
      const archive=await RootarkZk1ClientCekArchive.openCekArchive({
        indexedDBImpl:indexedDB, recoverySecret:secret,
        ownerPublicKey:owner.publicKey, ownerSigningKey:owner.privateKey,
        independentOwnerSpkiSha256:pin, pinnedCurrentHead:head,
        signedDeviceGrant:grant, pinProvider:dbpin, backupProvider:null,
        backupReceiptPublicKey:null, independentBackupReceiptSpkiSha256:null,
        assertLive:()=>{} });
      const result=await archive.archiveKeys({challenge,entries:[{
        metadata,revision:1,ciphertext,cek,state:'file'}]});
      archive.close();
      return result.localIndexedDbCommitted && !!result.externallyPinnedDigest;
    })()`);
    assert.equal(before, true, "Edge IndexedDB must commit");
    await cdp("Page.enable");
    await cdp("Page.reload", { ignoreCache: true });
    let after;
    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        after = await evaluate(`(async () => {
          if (!globalThis.RootarkZk1ClientCekArchive) throw Error('PAGE_NOT_LOADED');
          const state=JSON.parse(sessionStorage.getItem('fixture'));
          const raw=(value)=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')
            .padEnd(Math.ceil(value.length/4)*4,'=')),c=>c.charCodeAt(0));
          const subtle=crypto.subtle;
          const pub=await subtle.importKey('spki',raw(state.publicKey),'Ed25519',true,['verify']);
          const archive=await RootarkZk1ClientCekArchive.openCekArchive({
            indexedDBImpl:indexedDB, recoverySecret:raw(state.secret),
            ownerPublicKey:pub,ownerSigningKey:null,independentOwnerSpkiSha256:raw(state.pin),
            pinnedCurrentHead:{...state.head,digest:raw(state.head.digest)},
            signedDeviceGrant:state.grant,
            pinProvider:{read:async()=>sessionStorage.getItem('pin'),
              compareAndSwap:async()=>{throw Error('read only')}},
            backupProvider:null,backupReceiptPublicKey:null,
            independentBackupReceiptSpkiSha256:null,assertLive:()=>{} });
          const key=await archive.readArchivedCek({objectId:state.metadata.object_id,
            revision:1,versionId:state.metadata.version_id,nonce:state.challenge.nonce});
          const bytes=new Uint8Array(await subtle.decrypt({name:'AES-GCM',iv:raw(state.iv)},
            key,raw(state.sample)));
          archive.close();
          return new TextDecoder().decode(bytes);
        })()`);
        break;
      } catch (error) {
        if (!String(error).includes("PAGE_NOT_LOADED")) throw error;
        await sleep(100);
      }
    }
    assert.equal(after, "EDGE_REAL_IDB", "Edge must recover after actual page reload");
    process.stdout.write("EDGE_REAL_INDEXEDDB_RESTART_PASS\n");
  } finally {
    socket?.close();
    child.kill();
    await new Promise((resolve) => server.close(resolve));
    // Browser may still hold handles to profile files. The isolated profile is
    // created in the system temp directory and never touches a user profile.
  }
}
run().catch((error) => { process.stderr.write(`${error.stack}\n`); process.exitCode = 1; });
