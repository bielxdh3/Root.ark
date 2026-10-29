"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { once } = require("node:events");
const test = require("node:test");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

test("local WebDAV GET/HEAD preserves empty and nonempty HTTP framing", async (t) => {
  const root = createPrivateAuthorityFixture("zk65-w106-empty-get-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  fs.writeFileSync(path.join(root, "empty.ct"), "", { flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(root, "normal.ct"), "VERIFIED", { flag: "wx", mode: 0o600 });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "w106-empty", port: 0 });
  await bridge.start();
  t.after(async () => bridge.stop());
  for (const [name, method, expected] of [
    ["empty.ct", "GET", ""], ["empty.ct", "HEAD", ""],
    ["normal.ct", "GET", "VERIFIED"], ["normal.ct", "HEAD", ""],
  ]) {
    const result = await new Promise((resolve, reject) => {
      const request = http.request({ hostname: "127.0.0.1", port: bridge.address().port,
        path: `/${name}`, method, headers: { authorization: "Bearer w106-empty" } }, (res) => {
        const parts = [];
        res.on("data", (part) => parts.push(part));
        res.on("end", () => resolve({ status: res.statusCode,
          length: res.headers["content-length"], body: Buffer.concat(parts).toString("utf8") }));
      });
      request.on("error", reject);
      request.end();
    });
    assert.equal(result.status, 200);
    assert.equal(result.length, String(name === "empty.ct" ? 0 : 8));
    assert.equal(result.body, expected);
  }
});

test("local WebDAV closes a keep-alive HTTP response if the pinned FD is truncated", async (t) => {
  const root = createPrivateAuthorityFixture("zk65-w106-short-get-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const source = path.join(root, "short.ct");
  fs.writeFileSync(source, "12345678", { flag: "wx", mode: 0o600 });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "w106-short", port: 0 });
  await bridge.start();
  t.after(async () => bridge.stop());
  const native = fs.createReadStream;
  let attacked = false;
  fs.createReadStream = function (name, options) {
    if (name === null && options?.fd !== undefined && !attacked) {
      attacked = true;
      // Deterministic equivalent of an already-open foreign writer FD: the
      // owner check and HTTP Content-Length have completed before this hook.
      fs.truncateSync(source, 0);
    }
    return native.call(fs, name, options);
  };
  t.after(() => { fs.createReadStream = native; });
  const outcome = await new Promise((resolve) => {
    const request = http.get({ hostname: "127.0.0.1", port: bridge.address().port,
      path: "/short.ct", agent: false, headers: { authorization: "Bearer w106-short",
        connection: "keep-alive" } }, (res) => {
      res.resume();
      res.on("aborted", () => resolve("aborted"));
      res.on("error", () => resolve("aborted"));
      res.on("end", () => resolve("complete"));
    });
    request.on("error", () => resolve("aborted"));
    request.setTimeout(1500, () => { request.destroy(); resolve("hung"); });
  });
  assert.equal(attacked, true);
  assert.equal(outcome, "aborted",
    "short source reads must tear down HTTP/1.1 keep-alive, not misframe the next response");
});

test("local WebDAV GET cannot stream foreign-UID inode growth beyond its HTTP Content-Length", async (t) => {
  if (process.platform !== "linux" || process.getuid?.() !== 0) {
    t.skip("requires native Linux root and runuser -u nobody");
    return;
  }
  if (spawnSync("runuser", ["--version"], { encoding: "utf8" }).status !== 0) {
    t.skip("runuser unavailable");
    return;
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w106-http-framing-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.chmodSync(root, 0o755);
  const source = path.join(root, "ciphertext.ct");
  const signal = path.join(root, "signal");
  const ack = path.join(root, "ack");
  fs.writeFileSync(source, "AAAA", { flag: "wx", mode: 0o666 });
  fs.chmodSync(source, 0o666);
  for (const control of [signal, ack]) {
    fs.writeFileSync(control, "", { flag: "wx", mode: 0o666 });
    fs.chmodSync(control, 0o666);
  }

  const attacker = spawn("runuser", ["-u", "nobody", "--", process.execPath, "-e", `
    const fs = require("node:fs");
    const [source, signal, ack] = process.argv.slice(1);
    const fd = fs.openSync(source, "r+");
    process.stdout.write("ready\\n");
    const interval = setInterval(() => {
      if (fs.readFileSync(signal, "utf8") !== "grow") return;
      fs.writeSync(fd, Buffer.from("BBBB-FOREIGN-UID-EXTRA"), 0, 22, 4);
      fs.fsyncSync(fd);
      fs.writeFileSync(ack, "done");
      clearInterval(interval);
      fs.closeSync(fd);
    }, 5);
  `, source, signal, ack], { stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => attacker.kill());
  let timeout;
  const ready = await Promise.race([
    once(attacker.stdout, "data").then(([buf]) => String(buf).trim()),
    new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error("foreign UID did not open FD")), 5000);
    }),
  ]).finally(() => clearTimeout(timeout));
  assert.equal(ready, "ready");
  fs.chmodSync(source, 0o644);

  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "w106-framing", port: 0 });
  await bridge.start();
  t.after(async () => bridge.stop());
  const native = fs.createReadStream;
  let triggered = false;
  fs.createReadStream = function (name, options) {
    if (name === null && options?.fd !== undefined && !triggered) {
      triggered = true;
      fs.writeFileSync(signal, "grow");
      const wait = spawnSync("/bin/sh", ["-c",
        `i=0; while [ ! -s "${ack}" ] && [ "$i" -lt 500 ]; do i=$((i+1)); sleep 0.01; done; [ -s "${ack}" ]`,
      ], { encoding: "utf8", timeout: 10000 });
      assert.equal(wait.status, 0, "real nobody UID did not grow retained FD");
    }
    return native.call(fs, name, options);
  };
  t.after(() => { fs.createReadStream = native; });
  const response = await new Promise((resolve, reject) => {
    const socket = net.connect(bridge.address().port, "127.0.0.1");
    const chunks = [];
    socket.on("connect", () => socket.write("GET /ciphertext.ct HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer w106-framing\r\nConnection: close\r\n\r\n"));
    socket.on("data", (part) => chunks.push(part));
    socket.on("error", reject);
    socket.on("end", () => resolve(Buffer.concat(chunks)));
    socket.setTimeout(7000, () => socket.destroy(new Error("GET timed out")));
  });
  const split = response.indexOf("\r\n\r\n");
  assert.ok(split > 0, "server must emit actual HTTP response");
  const headers = response.subarray(0, split).toString("latin1");
  assert.match(headers, /^HTTP\/1\.1 200/m);
  assert.match(headers, /content-length:\s*4\r?\n/i);
  assert.equal(triggered, true, "race must be scheduled after status/length authorization");
  assert.equal(fs.readFileSync(source, "utf8"), "AAAABBBB-FOREIGN-UID-EXTRA");
  assert.deepEqual(response.subarray(split + 4), Buffer.from("AAAA"),
    "body cannot exceed pinned Content-Length despite real foreign UID retained-FD append");

  // A zero-byte file has no valid inclusive end offset; its GET still needs
  // to emit a correctly framed empty response and close the verified FD.
  fs.writeFileSync(path.join(root, "empty.ct"), "", { flag: "wx", mode: 0o600 });
  const empty = await new Promise((resolve, reject) => {
    const request = http.get({ hostname: "127.0.0.1", port: bridge.address().port,
      path: "/empty.ct", headers: { authorization: "Bearer w106-framing" } }, (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("end", () => resolve({ status: res.statusCode,
        length: res.headers["content-length"], body: Buffer.concat(parts) }));
    });
    request.on("error", reject);
  });
  assert.equal(empty.status, 200);
  assert.equal(empty.length, "0");
  assert.equal(empty.body.length, 0);
});
