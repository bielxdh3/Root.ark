"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const http = require("node:http");

const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const modules = ["rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
  "rootark-zk1-portable-file-recovery", "rootark-zk1-recoverable-pending-journal"];
const scripts = modules.map((name) => `<script src="/client/${name}.js"></script>`).join("");
const encode = (value) => Buffer.from(value).toString("base64url");

test("real Edge encrypted strict IndexedDB pending bundle survives browser reload and rejects wrong secret", {
  timeout: 60_000,
}, async (t) => {
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Windows Edge unavailable"); return;
  }
  const server = http.createServer((req, res) => {
    if (req.url === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'self'; script-src 'self'; connect-src 'self'" });
      res.end(`<!DOCTYPE html><title>Private journal test</title>${scripts}`);
      return;
    }
    const match = modules.find((name) => req.url === `/client/${name}.js`);
    if (!match) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
    res.end(fs.readFileSync(path.join(__dirname, "../public/client", match + ".js")));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-pending-"));
  const profile = path.join(folder, "profile");
  let edge, socket;
  try {
    edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--no-first-run",
      "--disable-extensions", "--remote-debugging-port=0",
      "--user-data-dir=" + profile, "about:blank"],
    { stdio: "ignore", windowsHide: true });
    const wait = async (fn) => {
      for (let i = 0; i < 220; i++) {
        const result = await fn(); if (result) return result;
        await new Promise((resolve) => setTimeout(resolve, 80));
      }
      throw Error("EDGE_PENDING_TIMEOUT");
    };
    const port = await wait(() => {
      const file = path.join(profile, "DevToolsActivePort");
      if (!fs.existsSync(file)) return null;
      return Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]) || null;
    });
    const tabs = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const page = tabs.find((tab) => tab.type === "page");
    assert.ok(page?.webSocketDebuggerUrl);
    socket = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    const pending = new Map();
    let sequence = 0;
    socket.addEventListener("message", ({ data }) => {
      const value = JSON.parse(data);
      if (!pending.has(value.id)) return;
      const { resolve, reject } = pending.get(value.id);
      pending.delete(value.id);
      if (value.error) reject(Error(value.error.message));
      else resolve(value.result);
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++sequence;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
    const evalJs = async (expression) => {
      const response = await send("Runtime.evaluate", {
        expression, awaitPromise: true, returnByValue: true });
      if (response.exceptionDetails) throw Error(response.exceptionDetails.text + ": "
        + response.exceptionDetails.exception?.description);
      return response.result?.value;
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Page.navigate", { url: `http://127.0.0.1:${server.address().port}/` });
    await wait(() => evalJs("document.readyState==='complete' && !!window.RootarkZk1RecoverablePendingJournal"));
    const first = await evalJs(`(async()=>{
      const rand=(n)=>crypto.getRandomValues(new Uint8Array(n));
      const to64=(b)=>btoa(String.fromCharCode(...b)).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');
      const secret=rand(32), owner=rand(32), headDigest=rand(32);
      const meta={account_id:to64(rand(16)),compartment_id:to64(rand(5)),
        keyring_id:to64(rand(16)),object_id:to64(rand(16)),version_id:to64(rand(16)),
        parent_version_id:null,epoch:1,kind:'file'};
      const bundle=await RootarkZk1PortableFileRecovery.sealForUserHeldSecret({
        recoverySecret:secret,metadata:meta,name:'edge-local-only.txt',
        mediaType:'text/plain',data:new TextEncoder().encode('edge pending encrypted secret')});
      const db=RootarkZk1RecoverablePendingJournal.openStore(indexedDB);
      const saved=await db.prepare({recoverySecret:secret,bundle,
        ownerSpkiSha256:owner,pinnedCurrentHead:{revision:2,digest:headDigest,epoch:1},
        ownerHistorySequence:1,operationId:to64(rand(32)),operationSignature:to64(rand(64))});
      if(!saved.strictTransactionCompleted||!saved.encryptedJournalReadbackVerified)
        throw Error('STRICT_PRE_PUT_DENIED');
      const ids=await db.listPendingIds();
      if(ids.length!==1||ids[0]!==meta.object_id)throw Error('JOURNAL_NOT_LISTED');
      return {id:meta.object_id,secret:to64(secret),root:bundle.ciphertextRoot};
    })()`);
    assert.match(first.id, /^[A-Za-z0-9_-]{22}$/);
    assert.match(first.root, /^[A-Za-z0-9_-]{43}$/);
    const wrong = encode(Buffer.alloc(32, 111));
    await send("Page.reload", { ignoreCache: true });
    await wait(() => evalJs("document.readyState==='complete' && !!window.RootarkZk1RecoverablePendingJournal"));
    const reopened = await evalJs(`(async()=>{
      const from64=(s)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
      const journal=RootarkZk1RecoverablePendingJournal.openStore(indexedDB);
      const id=${JSON.stringify(first.id)},holder=from64(${JSON.stringify(first.secret)});
      if(!(await journal.listPendingIds()).includes(id))throw Error('RESTART_INTENT_LOST');
      let wrongBlocked=false;
      try{await journal.load({objectId:id,recoverySecret:from64(${JSON.stringify(wrong)})});}
      catch(_){wrongBlocked=true;}
      if(!wrongBlocked)throw Error('WRONG_SECRET_ACCEPTED');
      const loaded=await journal.load({objectId:id,recoverySecret:holder});
      const opened=await RootarkZk1PortableFileRecovery.openWithIndependentRoot({
        recoverySecret:holder,bundle:loaded.bundle,
        expectedMetadata:loaded.bundle.metadata,
        independentlyPinnedCiphertextRoot:from64(loaded.bundle.ciphertextRoot)});
      const plain=new TextDecoder().decode(opened.data);opened.data.fill(0);holder.fill(0);
      return {plain,root:loaded.bundle.ciphertextRoot,verified:loaded.encryptedJournalReadbackVerified};
    })()`);
    assert.deepEqual(reopened, { plain: "edge pending encrypted secret",
      root: first.root, verified: true });
  } finally {
    socket?.close();
    if (edge?.pid) {
      try { execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
        { stdio: "ignore", timeout: 10000 }); }
      catch (_) { edge.kill(); }
    }
    await new Promise((resolve) => server.close(resolve));
    for (let i = 0; i < 16; i++) {
      try { fs.rmSync(folder, { recursive: true, force: true }); break; }
      catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 150));
      }
    }
  }
});
