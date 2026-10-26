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
