"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");

const LINUX = process.platform === "linux";
const TOKEN = crypto.randomBytes(32).toString("hex");
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-posix-webdav-"));
  const root = path.join(dir, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return { dir, root };
}
function request(port, relative, method = "GET", body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, method, path: relative,
      headers: { authorization: "Bearer " + TOKEN, ...headers }, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end(body);
  });
}
async function bridgeFor(t, root) {
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, port: 0, token: TOKEN });
  await bridge.start();
  t.after(() => bridge.stop());
  return bridge;
}

test("POSIX owner-only bridge supports bearer GET HEAD PUT and MOVE through sticky /tmp", {
  skip: !LINUX,
}, async (t) => {
  const { root } = fixture(t);
  fs.mkdirSync(path.join(root, "nested"), { mode: 0o700 });
  fs.writeFileSync(path.join(root, "nested", "safe.txt"), "SAFE");
  const bridge = await bridgeFor(t, root);
  const port = bridge.address().port;
  assert.deepEqual(await request(port, "/nested/safe.txt"), { status: 200, body: "SAFE" });
  assert.deepEqual(await request(port, "/nested/safe.txt", "HEAD"), { status: 200, body: "" });
  assert.equal((await request(port, "/nested/new.txt", "PUT", "PUT_OK")).status, 201);
  assert.equal((await request(port, "/nested/new.txt")).body, "PUT_OK");
  assert.equal((await request(port, "/nested/new.txt", "MOVE", null,
    { destination: "http://127.0.0.1/nested/moved.txt" })).status, 201);
  assert.equal((await request(port, "/nested/moved.txt")).body, "PUT_OK");
  assert.equal((await request(port, "/created", "MKCOL")).status, 201);
  assert.equal((await request(port, "/created/child.txt", "PUT", "NESTED")).status, 201);
  assert.equal((await request(port, "/created/child.txt")).body, "NESTED");
});

test("POSIX writable root, ancestor and nested directory fail closed", { skip: !LINUX }, async (t) => {
  const { dir, root } = fixture(t);
  const nested = path.join(root, "nested");
  fs.mkdirSync(nested, { mode: 0o700 });
  fs.writeFileSync(path.join(nested, "safe.txt"), "SAFE");
  // A sticky root-owned /tmp is safe for a trusted-owned child, but a normal
  // group/world-writable ancestor cannot protect that child against rename.
  fs.chmodSync(dir, 0o777);
  await assert.rejects(new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN }).start(),
    /Untrusted writable POSIX bridge ancestor/);
  fs.chmodSync(dir, 0o700);
  fs.chmodSync(root, 0o777);
  await assert.rejects(new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN }).start(),
    /Untrusted writable POSIX bridge ancestor/);
  fs.chmodSync(root, 0o700);
  const bridge = await bridgeFor(t, root);
  const port = bridge.address().port;
  fs.chmodSync(nested, 0o770);
  assert.equal((await request(port, "/nested/safe.txt")).status, 503);
  fs.chmodSync(nested, 0o707);
  assert.equal((await request(port, "/nested/safe.txt", "HEAD")).status, 503);
  fs.chmodSync(nested, 0o700);
  if (process.getuid?.() === 0) {
    fs.chownSync(nested, 65534, 65534);
    assert.equal((await request(port, "/nested/safe.txt")).status, 503,
      "different POSIX owner denied even with private mode");
    fs.chownSync(nested, 0, 0);
  }
  fs.chmodSync(root, 0o770);
  assert.equal((await request(port, "/nested/safe.txt")).status, 503);
  fs.chmodSync(root, 0o700);
  fs.chmodSync(root, 0o777);
  for (const [method, name] of [["GET", "/nested/safe.txt"],
    ["HEAD", "/nested/safe.txt"], ["PUT", "/nested/write.txt"]]) {
    const response = await request(port, name, method, method === "PUT" ? "NEW" : null);
    assert.equal(response.status, 503, method);
    assert.doesNotMatch(response.body, /SAFE|NEW/);
  }
  const move = await request(port, "/nested/safe.txt", "MOVE", null,
    { destination: "http://127.0.0.1/nested/new.txt" });
  assert.equal(move.status, 503);
  assert.equal(fs.readFileSync(path.join(nested, "safe.txt"), "utf8"), "SAFE");
});

test("POSIX separate UID symlink swap before native leaf open cannot leak outside secret", {
  skip: !LINUX || process.getuid?.() !== 0,
}, async (t) => {
  const { dir, root } = fixture(t);
  const nested = path.join(root, "nested");
  const parked = path.join(root, "parked");
  const foreign = path.join(dir, "foreign");
  fs.mkdirSync(nested, { mode: 0o755 });
  fs.mkdirSync(foreign, { mode: 0o711 });
  const leaf = path.join(nested, "payload.txt");
  const secret = path.join(foreign, "payload.txt");
  fs.writeFileSync(leaf, "INSIDE");
  fs.writeFileSync(secret, "OUTSIDE_SECRET", { mode: 0o600 });
  fs.chmodSync(secret, 0o600);
  const attackerScript = path.join(dir, "attacker.cjs");
  fs.writeFileSync(attackerScript, [
    'const fs=require("node:fs");',
    'const [dir,nested,parked,foreign,secret,mode]=process.argv.slice(2);',
    'if(mode==="probe") {',
    ' fs.accessSync(dir,fs.constants.W_OK|fs.constants.X_OK);',
    ' try {fs.readFileSync(secret); process.exit(7);} catch(e){if(e.code!=="EACCES") throw e;}',
    '} else if(mode==="swap") {fs.renameSync(nested,parked);fs.symlinkSync(foreign,nested,"dir");}',
    'else if(mode==="restore") {fs.unlinkSync(nested);fs.renameSync(parked,nested);}',
  ].join("\n"), { mode: 0o644 });
  // This fixture must be accessible to the other UID only AFTER startup.
  const attacker = (mode) => execFileSync("/usr/sbin/runuser",
    ["-u", "nobody", "--", process.execPath, attackerScript,
      root, nested, parked, foreign, secret, mode], { timeout: 10000 });
  const bridge = await bridgeFor(t, root);
  const port = bridge.address().port;
  assert.equal((await request(port, "/nested/payload.txt")).body, "INSIDE");
  fs.chmodSync(dir, 0o755);
  fs.chmodSync(root, 0o777);
  attacker("probe");
  let swapped = false;
  let swapAttempted = false;
  let openReached = false;
  const originalOpen = fs.openSync;
  const originalLstat = fs.lstatSync;
  // The malicious UID can replace the ancestor before the leaf's native open
  // would occur. Schedule a real swap during the POSIX ancestry admission.
  fs.lstatSync = function (name, ...args) {
    if (!swapAttempted && name === root) {
      attacker("swap");
      swapAttempted = true;
      swapped = true;
    }
    return originalLstat.call(fs, name, ...args);
  };
  fs.openSync = function (name, ...args) {
    if (name === leaf) {
      openReached = true;
      attacker("swap");
      swapped = true;
      try { return originalOpen.call(fs, name, ...args); }
      finally { attacker("restore"); swapped = false; }
    }
    return originalOpen.call(fs, name, ...args);
  };
  let reply;
  try { reply = await request(port, "/nested/payload.txt"); }
  finally {
    fs.lstatSync = originalLstat;
    fs.openSync = originalOpen;
    if (swapped) { attacker("restore"); swapped = false; }
  }
  assert.equal(reply.status, 503);
  assert.doesNotMatch(reply.body, /OUTSIDE_SECRET/);
  assert.equal(swapAttempted, true, "other UID performed an actual directory exchange");
  assert.equal(openReached, false, "untrusted ancestor refused before fd open");
  assert.equal(fs.readFileSync(secret, "utf8"), "OUTSIDE_SECRET");
  fs.chmodSync(root, 0o700);
  assert.equal((await request(port, "/nested/payload.txt")).body, "INSIDE");
});

test("POSIX pinned GET uses the opened inode despite a trusted after-open directory swap", {
  skip: !LINUX,
}, async (t) => {
  const { dir, root } = fixture(t);
  const nested = path.join(root, "nested");
  const parked = path.join(root, "parked");
  const foreign = path.join(dir, "foreign");
  fs.mkdirSync(nested, { mode: 0o700 });
  fs.mkdirSync(foreign, { mode: 0o700 });
  const leaf = path.join(nested, "sample.txt");
  fs.writeFileSync(leaf, "SAFE_OPENED_INODE");
  fs.writeFileSync(path.join(foreign, "sample.txt"), "OUTSIDE_SENTINEL");
  const bridge = await bridgeFor(t, root);
  const originalOpen = fs.openSync;
  let swapped = false;
  fs.openSync = function (name, ...args) {
    const fd = originalOpen.call(fs, name, ...args);
    if (name === leaf) {
      fs.renameSync(nested, parked);
      fs.symlinkSync(foreign, nested, "dir");
      fs.unlinkSync(nested);
      fs.renameSync(parked, nested);
      swapped = true;
    }
    return fd;
  };
  let result;
  try { result = await request(bridge.address().port, "/nested/sample.txt"); }
  finally { fs.openSync = originalOpen; }
  assert.equal(swapped, true);
  assert.deepEqual(result, { status: 200, body: "SAFE_OPENED_INODE" });
});

test("POSIX recovery refuses a writable descendant before staged backup rollback", {
  skip: !LINUX,
}, async (t) => {
  const { root } = fixture(t);
  const nested = path.join(root, "nested");
  const trash = path.join(root, ".rootark-trash");
  fs.mkdirSync(nested, { mode: 0o777 });
  fs.chmodSync(nested, 0o777);
  fs.mkdirSync(trash, { mode: 0o700 });
  fs.writeFileSync(path.join(trash, "backup.txt"), "PREVIOUS_BYTES");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, port: 0, token: TOKEN,
    journal: { recover: async () => [{ kind: "put", operationId: "recover-1",
      source: "/nested/file.txt", destination: "/nested/file.txt",
      trash: ".rootark-trash/backup.txt", phase: "staged", existed: true }] } });
  await assert.rejects(bridge.start(), /Untrusted writable POSIX bridge ancestor/);
  assert.equal(fs.readFileSync(path.join(trash, "backup.txt"), "utf8"), "PREVIOUS_BYTES");
  assert.equal(fs.existsSync(path.join(nested, "file.txt")), false);
  assert.equal(bridge.server.listening, false);
});
