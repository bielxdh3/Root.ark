"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { execFileSync, spawnSync } = require("node:child_process");
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

test("POSIX MKCOL stays 0700 under umask 000 and denies real foreign UID writes", {
  skip: !LINUX,
}, async (t) => {
  const { dir, root } = fixture(t);
  // Allow the lower UID to traverse every ordinary ancestor, but never to
  // modify one. /tmp itself is root-owned sticky, as in production.
  fs.chmodSync(dir, 0o755);
  fs.chmodSync(root, 0o755);
  const bridge = await bridgeFor(t, root);
  const port = bridge.address().port;
  const previousUmask = process.umask(0);
  let response;
  try { response = await request(port, "/private", "MKCOL"); }
  finally { process.umask(previousUmask); }
  assert.equal(response.status, 201);
  const created = path.join(root, "private");
  const createdStat = fs.lstatSync(created);
  assert.equal(createdStat.mode & 0o777, 0o700,
    "MKCOL cannot inherit world-write from umask 000");
  assert.equal(createdStat.uid, process.getuid());
  assert.equal((await request(port, "/private", "MKCOL", null,
    { authorization: "" })).status, 401);
  if (process.getuid() === 0) {
    const nobody = (...args) => spawnSync("/usr/sbin/runuser",
      ["-u", "nobody", "--", ...args], { encoding: "utf8", timeout: 10000 });
    for (const ancestor of [dir, root]) {
      assert.equal(nobody("test", "-x", ancestor).status, 0,
        "foreign UID must be able to traverse the fixture ancestor");
      assert.notEqual(nobody("test", "-w", ancestor).status, 0,
        "foreign UID must not be able to mutate an ancestor");
    }
    assert.notEqual(nobody("mkdir", path.join(created, "foreign-dir")).status, 0);
    assert.notEqual(nobody(process.execPath, "-e",
      "require('node:fs').writeFileSync(process.argv[1], 'foreign')",
      path.join(created, "foreign-file")).status, 0);
    assert.equal(fs.existsSync(path.join(created, "foreign-file")), false);
  }
  assert.equal((await request(port, "/private/owner.txt", "PUT", "OWNER")).status, 201);
  assert.deepEqual(await request(port, "/private/owner.txt"), { status: 200, body: "OWNER" });
  assert.equal((await request(port, "/private/owner.txt", "HEAD")).status, 200);
  assert.equal((await request(port, "/private", "PROPFIND", null, { depth: "1" })).status, 207);
  assert.equal((await request(port, "/private/owner.txt", "MOVE", null,
    { destination: "http://127.0.0.1/private/moved.txt" })).status, 201);
  assert.equal((await request(port, "/private/moved.txt")).body, "OWNER");
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

test("POSIX startup must not create root beneath other-UID symlink ancestor", {
  skip: !LINUX || process.getuid?.() !== 0,
}, async (t) => {
  const { dir } = fixture(t);
  const writable = path.join(dir, "writable");
  const outside = path.join(dir, "private-outside");
  const pivot = path.join(writable, "pivot");
  const foreignRoot = path.join(outside, "unauthorized-created-root");
  fs.mkdirSync(writable, { mode: 0o777 });
  fs.chmodSync(writable, 0o777);
  fs.mkdirSync(outside, { mode: 0o700 });
  fs.chmodSync(dir, 0o755);
  execFileSync("/usr/sbin/runuser", ["-u", "nobody", "--", process.execPath,
    "-e", 'require("node:fs").symlinkSync(process.argv[1],process.argv[2],"dir")',
    outside, pivot]);
  assert.equal(fs.lstatSync(pivot).uid, 65534);
  const bridge = new LocalSyncWebDavBridge({ rootDir: path.join(pivot, "unauthorized-created-root"),
    token: TOKEN });
  await assert.rejects(bridge.start(), /Untrusted|EACCES|Path outside|Symlink/);
  assert.equal(fs.existsSync(foreignRoot), false,
    "startup must not create a directory through a foreign-UID symlink");
  assert.equal(bridge.server.listening, false);
});

test("POSIX startup must not create trash under other-UID symlink or outside bridge root", {
  skip: !LINUX || process.getuid?.() !== 0,
}, async (t) => {
  const { dir, root } = fixture(t);
  const writable = path.join(root, "writable");
  const outside = path.join(dir, "private-outside");
  const pivot = path.join(writable, "pivot");
  fs.mkdirSync(writable, { mode: 0o777 });
  fs.chmodSync(writable, 0o777);
  fs.mkdirSync(outside, { mode: 0o700 });
  fs.chmodSync(root, 0o755);
  fs.chmodSync(dir, 0o755);
  execFileSync("/usr/sbin/runuser", ["-u", "nobody", "--", process.execPath,
    "-e", 'require("node:fs").symlinkSync(process.argv[1],process.argv[2],"dir")',
    outside, pivot]);
  const trashDir = path.join(pivot, "unauthorized-created-trash");
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, trashDir, token: TOKEN });
  await assert.rejects(bridge.start(), /Untrusted|Symlink/);
  assert.equal(fs.existsSync(path.join(outside, "unauthorized-created-trash")), false,
    "startup must not create trash through a foreign-UID symlink");
  const otherTrash = path.join(outside, "outside-configured-trash");
  const external = new LocalSyncWebDavBridge({ rootDir: root, trashDir: otherTrash, token: TOKEN });
  await assert.rejects(external.start(), /outside|Untrusted|Path outside|below bridge root/);
  assert.equal(fs.existsSync(otherTrash), false,
    "startup must not create a configured trash directory outside the root");
});

test("POSIX startup creates private nested root and trash through trusted parents", {
  skip: !LINUX,
}, async (t) => {
  const { dir } = fixture(t);
  const root = path.join(dir, "new", "deep", "bridge");
  const trashDir = path.join(root, ".rootark-trash", "new", "deep");
  assert.equal(fs.existsSync(root), false);
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, trashDir, token: TOKEN });
  await bridge.start();
  t.after(() => bridge.stop());
  assert.equal(fs.statSync(root).mode & 0o077, 0);
  assert.equal(fs.statSync(path.join(dir, "new")).mode & 0o077, 0);
  assert.equal(fs.statSync(trashDir).mode & 0o077, 0);
  const port = bridge.address().port;
  assert.equal((await request(port, "/newfile.txt", "PUT", "NEW_CONTENT")).status, 201);
  assert.deepEqual(await request(port, "/newfile.txt"), { status: 200, body: "NEW_CONTENT" });
  assert.deepEqual(await request(port, "/newfile.txt", "HEAD"), { status: 200, body: "" });
  assert.equal((await request(port, "/newfile.txt", "MOVE", null,
    { destination: "http://127.0.0.1/moved.txt" })).status, 201);
  assert.equal((await request(port, "/moved.txt")).body, "NEW_CONTENT");
});

test("POSIX startup can create a new owner-only root directly below sticky /tmp", {
  skip: !LINUX,
}, async (t) => {
  const root = path.join(os.tmpdir(), `rootark-posix-new-sticky-${crypto.randomUUID()}`);
  assert.equal(fs.existsSync(root), false);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN });
  await bridge.start();
  t.after(() => bridge.stop());
  assert.equal(fs.statSync(root).mode & 0o077, 0);
  assert.equal(fs.statSync(path.join(root, ".rootark-trash")).mode & 0o077, 0);
  assert.equal((await request(bridge.address().port, "/created.txt", "PUT", "OK")).status, 201);
  assert.equal((await request(bridge.address().port, "/created.txt")).body, "OK");
});
