"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const test = require("node:test");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

function request(port, file, { method = "GET", body = null, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const outgoing = http.request({ host: "127.0.0.1", port, path: file, method,
      headers: { authorization: "Bearer junction-acl-test-token", ...headers } }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode,
        body: Buffer.concat(chunks).toString("utf8") }));
    });
    outgoing.once("error", reject);
    outgoing.end(body);
  });
}

test("Windows local WebDAV refuses unsafe descendant DACL before starting or recovering", {
  skip: process.platform !== "win32", timeout: 20_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-unsafe-start-");
  const unsafe = path.join(root, "mutable");
  fs.mkdirSync(unsafe);
  execFileSync("icacls.exe", [unsafe, "/grant", "*S-1-5-32-545:(OI)(CI)M"],
    { stdio: "ignore", windowsHide: true });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await assert.rejects(bridge.start(), /Windows chunk staging ACL validation failed|Untrusted principal/);
  assert.equal(bridge.server.listening, false);
});

test("Windows local WebDAV must refuse untrusted mutable ancestors before a junction can read outside root", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-unsafe-parent-");
  const ancestor = path.join(root, "safe");
  const parked = path.join(root, "parked");
  const foreign = createPrivateAuthorityFixture("rootark-bridge-foreign-");
  fs.mkdirSync(ancestor, { recursive: true });
  const inside = "AUTHORIZED_INSIDE_CONTENT";
  const outside = "OUTSIDE_ROOT_CONFIDENTIAL_TEST";
  const target = path.join(ancestor, "sample.txt");
  fs.writeFileSync(target, inside);
  fs.writeFileSync(path.join(foreign, "sample.txt"), outside);
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  const nativeLstat = fs.lstatSync;
  let attemptedSwap = false;
  let targetChecks = 0;
  t.after(async () => {
    fs.lstatSync = nativeLstat;
    await bridge.stop();
    if (fs.existsSync(parked)) {
      if (fs.existsSync(ancestor)) fs.unlinkSync(ancestor);
      fs.renameSync(parked, ancestor);
    }
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    fs.rmSync(foreign, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  // Grant an untrusted local SID Modify AFTER successful secure startup.
  // Startup verification alone must not authorize later filesystem access.
  execFileSync("icacls.exe", [ancestor, "/grant", "*S-1-5-32-545:(OI)(CI)M"],
    { stdio: "ignore", windowsHide: true });
  fs.lstatSync = function (filename, ...args) {
    if (filename !== target) return nativeLstat.call(fs, filename, ...args);
    targetChecks += 1;
    if (targetChecks === 1) {
      fs.renameSync(ancestor, parked);
      fs.symlinkSync(foreign, ancestor, "junction");
      attemptedSwap = true;
    }
    const stat = nativeLstat.call(fs, filename, ...args);
    if (targetChecks === 2) {
      fs.unlinkSync(ancestor);
      fs.renameSync(parked, ancestor);
    }
    return stat;
  };
  const response = await request(bridge.address().port, "/safe/sample.txt");
  fs.lstatSync = nativeLstat;
  assert.equal(response.status, 503,
    `Untrusted writable ancestor must be rejected, not served: ${response.body}`);
  assert.equal(response.body.includes(outside), false);
  assert.equal(fs.readFileSync(target, "utf8"), inside);
  assert.equal(fs.readFileSync(path.join(foreign, "sample.txt"), "utf8"), outside);
  assert.equal(attemptedSwap, false,
    "The ACL must reject an unsafe tree before filesystem leaf access");
  // A GET-only guard would leave the same mutable ancestor available to
  // MOVE/PUT/DELETE and could redirect writes or deletions outside the root.
  for (const method of ["PUT", "DELETE", "MOVE"]) {
    const denied = await request(bridge.address().port, "/safe/sample.txt", {
      method, body: method === "PUT" ? "must not write" : null,
      headers: method === "MOVE" ? {
        destination: `http://127.0.0.1:${bridge.address().port}/moved.txt`,
      } : {},
    });
    assert.equal(denied.status, 503, `${method} must reject untrusted local directory rights`);
  }
  assert.equal(fs.readFileSync(target, "utf8"), inside);
  assert.equal(fs.readFileSync(path.join(foreign, "sample.txt"), "utf8"), outside);
});

test("Windows local WebDAV permits GET from a verified owner-only directory tree", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-trusted-get-");
  const trusted = path.join(root, "safe");
  fs.mkdirSync(trusted);
  const content = "TRUSTED_OPAQUE_CONTENT_" + crypto.randomBytes(5).toString("hex");
  fs.writeFileSync(path.join(trusted, "sample.ct"), content);
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  const response = await request(bridge.address().port, "/safe/sample.ct");
  assert.equal(response.status, 200);
  assert.equal(response.body, content);
});

test("Windows WebDAV MOVE independently refuses an untrusted destination parent", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-move-acl-");
  const sourceDir = path.join(root, "safe");
  const destinationDir = path.join(root, "destination");
  fs.mkdirSync(sourceDir);
  fs.mkdirSync(destinationDir);
  const source = path.join(sourceDir, "opaque.ct");
  const destination = path.join(destinationDir, "opaque.ct");
  fs.writeFileSync(source, "KEEP_SOURCE_BYTES");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  execFileSync("icacls.exe", [destinationDir, "/grant", "*S-1-5-32-545:(OI)(CI)M"],
    { stdio: "ignore", windowsHide: true });
  const denied = await request(bridge.address().port, "/safe/opaque.ct", {
    method: "MOVE",
    headers: { destination: `http://127.0.0.1:${bridge.address().port}/destination/opaque.ct` },
  });
  assert.equal(denied.status, 503);
  assert.equal(fs.readFileSync(source, "utf8"), "KEEP_SOURCE_BYTES");
  assert.equal(fs.existsSync(destination), false);
});

test("Windows local WebDAV concurrent ACL checks leave the Node event loop responsive", {
  skip: process.platform !== "win32", timeout: 45_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-async-load-");
  const content = "PRIVATE_BOUNDED_WEB_DAV_BYTES";
  fs.writeFileSync(path.join(root, "file.ct"), content);
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  let beats = 0;
  let worstLag = 0;
  let previous = Date.now();
  const interval = setInterval(() => {
    const now = Date.now();
    worstLag = Math.max(worstLag, now - previous);
    previous = now;
    beats += 1;
  }, 20);
  let responses;
  const started = Date.now();
  try {
    responses = await Promise.all(Array.from({ length: 12 }, () =>
      request(bridge.address().port, "/file.ct")));
  } finally {
    clearInterval(interval);
  }
  const elapsed = Date.now() - started;
  t.diagnostic(`12 authenticated GETs: ${elapsed}ms ACL-checked HTTP, including verifier startup`);
  for (const result of responses) {
    assert.equal(result.status, 200);
    assert.equal(result.body, content);
  }
  assert.ok(beats >= 12, `event loop must advance during 12 ACL checks: ${beats} ticks`);
  assert.ok(worstLag < 275,
    `ACL checks must not block the event loop for a PowerShell startup: ${worstLag}ms`);
  assert.ok(elapsed < 1500,
    `12 request-time native ACL checks must reuse a compiled verifier: ${elapsed}ms`);
});

test("Windows bridge ACL admission is bounded and excess requests fail closed", {
  skip: process.platform !== "win32", timeout: 55_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-async-cap-");
  fs.writeFileSync(path.join(root, "file.ct"), "PRIVATE_BOUNDED_CONTENT");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  const responses = await Promise.all([
    ...Array.from({ length: 30 }, () => request(bridge.address().port, "/file.ct")),
    request(bridge.address().port, "/file.ct", { headers: { authorization: "" } }),
  ]);
  const allowed = responses.slice(0, 30).filter((item) => item.status === 200);
  const denied = responses.slice(0, 30).filter((item) => item.status === 503);
  assert.ok(allowed.length > 0, "trusted requests retain a working GET path");
  assert.ok(denied.length > 0, "excess concurrent ACL checks must reject, not queue without bound");
  assert.equal(allowed.length + denied.length, 30, "no unexpected status or unverified success");
  assert.ok(allowed.every((item) => item.body === "PRIVATE_BOUNDED_CONTENT"));
  assert.ok(denied.every((item) => item.body === "Untrusted bridge storage"));
  assert.equal(responses[30].status, 401, "unauthenticated requests cannot exhaust ACL subprocesses");
});

test("Windows native ACL verifier stop rejects every queued check and never reuses prior trust", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-worker-stop-");
  fs.writeFileSync(path.join(root, "file.ct"), "PRIVATE_WORKER_STOP_CONTENT");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  const queued = Array.from({ length: 12 }, () => bridge.windowsAclVerifier.verify(root));
  bridge.windowsAclVerifier.stop();
  const settled = await Promise.allSettled(queued);
  assert.ok(settled.every((result) => result.status === "rejected"),
    "terminated worker must not authorize pending checks");
  const denied = await request(bridge.address().port, "/file.ct");
  assert.equal(denied.status, 503);
  assert.equal(denied.body, "Untrusted bridge storage");
});

test("Windows local WebDAV refuses post-start untrusted leaf ACLs for reads and mutations", {
  skip: process.platform !== "win32", timeout: 35_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-leaf-drift-");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  const port = bridge.address().port;
  const grantUnsafeLeaf = (name, content) => {
    const filename = path.join(root, name);
    fs.writeFileSync(filename, content);
    // A trusted operator may import an ACL-bearing file after startup;
    // an untrusted user can then alter its bytes without parent write access.
    execFileSync("icacls.exe", [filename, "/grant", "*S-1-5-32-545:M"],
      { stdio: "ignore", windowsHide: true });
    return filename;
  };
  for (const method of ["GET", "PUT", "DELETE", "MOVE"]) {
    const name = `unsafe-${method.toLowerCase()}.ct`;
    const content = `ORIGINAL_${method}_BYTES`;
    const file = grantUnsafeLeaf(name, content);
    const denied = await request(port, `/${name}`, {
      method, body: method === "PUT" ? "UNTRUSTED_REPLACEMENT" : null,
      headers: method === "MOVE" ? { destination: `http://127.0.0.1:${port}/moved.ct` } : {},
    });
    assert.equal(denied.status, 503, `${method} must deny an unsafe existing file ACL`);
    assert.equal(denied.body, "Untrusted bridge storage");
    assert.equal(fs.readFileSync(file, "utf8"), content);
  }
  const safeSource = path.join(root, "safe-source.ct");
  fs.writeFileSync(safeSource, "SAFE_SOURCE_BYTES");
  const unsafeDestination = grantUnsafeLeaf("unsafe-destination.ct", "KEEP_DESTINATION_BYTES");
  const deniedDestination = await request(port, "/safe-source.ct", {
    method: "MOVE", headers: { destination: `http://127.0.0.1:${port}/unsafe-destination.ct` },
  });
  assert.equal(deniedDestination.status, 503, "MOVE must check an existing destination file ACL");
  assert.equal(fs.readFileSync(safeSource, "utf8"), "SAFE_SOURCE_BYTES");
  assert.equal(fs.readFileSync(unsafeDestination, "utf8"), "KEEP_DESTINATION_BYTES");
});

test("Windows local WebDAV keeps owner-only GET PUT MOVE DELETE working", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-leaf-positive-");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  const port = bridge.address().port;
  const source = path.join(root, "trusted.ct");
  fs.writeFileSync(source, "TRUSTED_START");
  assert.equal((await request(port, "/trusted.ct")).body, "TRUSTED_START");
  assert.equal((await request(port, "/trusted.ct", { method: "PUT", body: "TRUSTED_REPLACEMENT" })).status, 204);
  assert.equal((await request(port, "/trusted.ct")).body, "TRUSTED_REPLACEMENT");
  assert.equal((await request(port, "/trusted.ct", {
    method: "MOVE", headers: { destination: `http://127.0.0.1:${port}/moved.ct` },
  })).status, 201);
  assert.equal((await request(port, "/moved.ct")).body, "TRUSTED_REPLACEMENT");
  assert.equal((await request(port, "/moved.ct", { method: "DELETE" })).status, 204);
  assert.equal(fs.existsSync(path.join(root, "moved.ct")), false);
});

test("Windows bridge repeated start cannot orphan its live native ACL worker", {
  skip: process.platform !== "win32", timeout: 35_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-repeat-start-");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  let firstVerifier;
  t.after(async () => {
    // Retain the original reference so even a failing regression test cannot
    // leave a live native PowerShell child behind in the test runner.
    firstVerifier?.stop();
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await bridge.start();
  assert.equal(bridge.server.listenerCount("error"), 0,
    "successful listen must not retain a one-shot failure listener");
  firstVerifier = bridge.windowsAclVerifier;
  await firstVerifier.verify(root);
  await assert.rejects(bridge.start(), /already starting or listening/);
  assert.equal(bridge.windowsAclVerifier, firstVerifier,
    "a rejected second start must not replace the live native child");
  assert.equal(bridge.server.listenerCount("error"), 0,
    "duplicate-start denial must not add stale error listeners");
  const positive = await request(bridge.address().port, "/missing.ct");
  assert.equal(positive.status, 404, "the original listener must remain usable");
  await bridge.stop();
  await assert.rejects(firstVerifier.verify(root), /Windows bridge ACL validation failed/);
  await bridge.start();
  const restarted = bridge.windowsAclVerifier;
  assert.notEqual(restarted, firstVerifier,
    "a clean stop may start again only with a fresh ACL worker");
  await restarted.verify(root);
  await bridge.stop();
  await assert.rejects(restarted.verify(root), /Windows bridge ACL validation failed/);
});

test("Windows bridge concurrent starts admit exactly one native verifier", {
  skip: process.platform !== "win32", timeout: 35_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-concurrent-start-");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const first = bridge.start();
  const second = bridge.start();
  const results = await Promise.allSettled([first, second]);
  assert.equal(results.filter((item) => item.status === "fulfilled").length, 1);
  assert.equal(results.filter((item) => item.status === "rejected"
    && /already starting or listening/.test(item.reason?.message)).length, 1);
  assert.equal(bridge.server.listenerCount("error"), 0);
  const verifier = bridge.windowsAclVerifier;
  await verifier.verify(root);
  await bridge.stop();
  await assert.rejects(verifier.verify(root), /Windows bridge ACL validation failed/);
});

test("Windows bridge stop during startup prevents a late listener and ACL child", {
  skip: process.platform !== "win32", timeout: 35_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-stop-during-start-");
  let signalRecovery;
  const enteredRecovery = new Promise((resolve) => { signalRecovery = resolve; });
  let releaseRecovery;
  const recoverBarrier = new Promise((resolve) => { releaseRecovery = resolve; });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0,
    journal: { async recover() { signalRecovery(); await recoverBarrier; return []; } } });
  t.after(async () => {
    releaseRecovery();
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const starting = bridge.start();
  await enteredRecovery;
  const stopping = bridge.stop();
  releaseRecovery();
  await assert.rejects(starting, /start cancelled by stop/);
  await stopping;
  assert.equal(bridge.server.listening, false,
    "stop must not let a still-running startup reopen the HTTP listener");
  assert.equal(bridge.windowsAclVerifier, null);
  assert.equal(bridge.server.listenerCount("error"), 0);
});

test("Windows bridge stop completes while journal recovery never settles", {
  skip: process.platform !== "win32", timeout: 15_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-stalled-recovery-");
  let announceRecovery;
  const recovering = new Promise((resolve) => { announceRecovery = resolve; });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0,
    journal: { recover() { announceRecovery(); return new Promise(() => {}); } } });
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  // The deliberately unresolved startup is never allowed to listen. The
  // orphaned promise owns no native process or timer after this test.
  void bridge.start().catch(() => {});
  await recovering;
  let deadline;
  const result = await Promise.race([
    bridge.stop().then(() => "stopped"),
    new Promise((resolve) => { deadline = setTimeout(() => resolve("timed-out"), 1000); }),
  ]);
  clearTimeout(deadline);
  assert.equal(result, "stopped", "shutdown cannot wait on unbounded journal recovery");
  assert.equal(bridge.server.listening, false);
  assert.equal(bridge.windowsAclVerifier, null);
});

test("Windows bridge recovery awaiting its own stop cannot deadlock startup", {
  skip: process.platform !== "win32", timeout: 15_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-recursive-stop-");
  let announceRecovery;
  const recovering = new Promise((resolve) => { announceRecovery = resolve; });
  let bridge;
  bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0,
    journal: { async recover() { announceRecovery(); await bridge.stop(); return []; } } });
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const starting = bridge.start();
  await recovering;
  let deadline;
  const result = await Promise.race([
    starting.then(() => "started", (error) =>
      /start cancelled by stop/.test(error.message) ? "cancelled" : "wrong rejection"),
    new Promise((resolve) => { deadline = setTimeout(() => resolve("timed-out"), 1000); }),
  ]);
  clearTimeout(deadline);
  assert.equal(result, "cancelled", "journal recovery must be able to await stop without deadlock");
  assert.equal(bridge.server.listening, false);
  assert.equal(bridge.windowsAclVerifier, null);
});

test("Windows bridge stop waits for an issued but unacknowledged listen", {
  skip: process.platform !== "win32", timeout: 20_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-pending-listen-");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: 0 });
  const listen = bridge.server.listen.bind(bridge.server);
  let announceBind;
  const bound = new Promise((resolve) => { announceBind = resolve; });
  let releaseCallback;
  const callbackGate = new Promise((resolve) => { releaseCallback = resolve; });
  bridge.server.listen = (port, host, callback) => listen(port, host, () => {
    announceBind();
    void callbackGate.then(callback);
  });
  t.after(async () => {
    releaseCallback();
    await bridge.stop();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const starting = bridge.start();
  await bound;
  assert.equal(bridge.server.listening, true);
  const stopping = bridge.stop();
  let deadline;
  const result = await Promise.race([
    stopping.then(() => "stopped"),
    new Promise((resolve) => { deadline = setTimeout(() => resolve("pending"), 80); }),
  ]);
  clearTimeout(deadline);
  assert.equal(result, "pending", "stop cannot return while issued listen has no callback");
  releaseCallback();
  await assert.rejects(starting, /start cancelled by stop/);
  await stopping;
  assert.equal(bridge.server.listening, false);
  assert.equal(bridge.windowsAclVerifier, null);
  assert.equal(bridge.server.listenerCount("error"), 0);
});

test("Windows bridge failed listen releases the native ACL verifier before retry", {
  skip: process.platform !== "win32", timeout: 35_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-listen-fail-");
  const occupied = http.createServer();
  await new Promise((resolve) => occupied.listen(0, "127.0.0.1", resolve));
  const bridge = new LocalSyncWebDavBridge({ rootDir: root,
    token: "junction-acl-test-token", port: occupied.address().port });
  t.after(async () => {
    await bridge.stop();
    if (occupied.listening) await new Promise((resolve) => occupied.close(resolve));
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await assert.rejects(bridge.start(), /EADDRINUSE/);
  assert.equal(bridge.windowsAclVerifier, null,
    "a failed bind must release and discard its newly created ACL verifier");
  assert.equal(bridge.server.listenerCount("error"), 0,
    "failed listen cannot retain stale error listeners");
  await new Promise((resolve) => occupied.close(resolve));
  await bridge.start();
  assert.equal(bridge.server.listenerCount("error"), 0);
  const verifier = bridge.windowsAclVerifier;
  await verifier.verify(root);
  await bridge.stop();
  await assert.rejects(verifier.verify(root), /Windows bridge ACL validation failed/);
});
