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
      res.end('<!doctype html><meta charset="utf-8"><script defer src="/client/rootark-dev-vault-crypto.js"></script><script defer src="/client/rootark-dev-vault-trusted-device.js"></script>');
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
