"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");

function runInit(folder, serverUrl, configPath, { preload = false, preseedTarget = "" } = {}) {
  const args = [];
  if (preload) {
    args.push("-e", String.raw`
      const fs = require("node:fs");
      const planned = process.env.ROOTARK_TEST_PRESEEDED_PATH + ".tmp-" + process.pid;
      if (process.env.ROOTARK_TEST_PRESEEDED_TARGET)
        fs.symlinkSync(process.env.ROOTARK_TEST_PRESEEDED_TARGET, planned, "file");
      else fs.writeFileSync(planned, "PRESERVE_EXISTING_TEMP");
      process.umask(0o022);
      process.argv = [process.execPath, process.env.ROOTARK_TEST_SYNC_CLI,
        ...JSON.parse(process.env.ROOTARK_TEST_SYNC_ARGS)];
      require(process.env.ROOTARK_TEST_SYNC_CLI);
    `);
  } else args.push(cli);
  const commands = ["init", "--server", serverUrl, "--username", "fixture-user",
    "--password", "fixture-password", "--folder", path.join(folder, "files"),
    "--folder-id", "root", "--config", configPath];
  if (!preload) args.push(...commands);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: folder, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, ROOTARK_TEST_SYNC_CLI: cli,
        ROOTARK_TEST_SYNC_ARGS: JSON.stringify(commands),
        ROOTARK_TEST_PRESEEDED_PATH: configPath,
        ROOTARK_TEST_PRESEEDED_TARGET: preseedTarget },
    });
    const timer = setTimeout(() => child.kill(), 10000);
    let output = "";
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => { output += chunk.toString("utf8"); });
    }
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code) => { clearTimeout(timer); resolve({ code, output }); });
  });
}

test("legacy sync rejects remote cleartext HTTP before sending a password", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-sync-url-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const result = await runInit(dir, "http://192.0.2.42:10443", path.join(dir, "config.json"));
  assert.notEqual(result.code, 0);
  assert.match(result.output, /SYNC_UNTRUSTED_SERVER_URL/);
});

test("legacy init keeps bearer config private and preserves a preseeded predictable temp", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-sync-private-");
  const configPath = path.join(dir, "config.json");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ token: "fixture-token", permissions: {} }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  const result = await runInit(dir, url, configPath, { preload: true });
  assert.equal(result.code, 0, result.output);
  assert.equal(JSON.parse(await fsp.readFile(configPath, "utf8")).token, "fixture-token");
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(configPath).mode & 0o077, 0,
      "bearer config must be private even under an ordinary 0022 umask");
  }
  const names = await fsp.readdir(dir);
  const planted = names.find((name) => name.startsWith("config.json.tmp-") );
  assert.ok(planted, "the old predictable temp fixture was installed");
  assert.equal(await fsp.readFile(path.join(dir, planted), "utf8"), "PRESERVE_EXISTING_TEMP");
  const second = await runInit(dir, url, configPath);
  assert.equal(second.code, 0, second.output);
  assert.equal(JSON.parse(await fsp.readFile(configPath, "utf8")).token, "fixture-token");
});

test("legacy init does not follow a preseeded predictable temp symlink", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX temp symlink fixture");
  const dir = createPrivateAuthorityFixture("rootark-sync-temp-link-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const outside = path.join(dir, "outside-sentinel");
  const configPath = path.join(dir, "config.json");
  await fsp.writeFile(outside, "PRESERVE_OUTSIDE");
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" }).end('{"token":"fixture-token"}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const result = await runInit(dir, `http://127.0.0.1:${server.address().port}`,
    configPath, { preload: true, preseedTarget: outside });
  assert.equal(result.code, 0, result.output);
  assert.equal(await fsp.readFile(outside, "utf8"), "PRESERVE_OUTSIDE");
  const files = await fsp.readdir(dir);
  const alias = files.find((name) => name.startsWith("config.json.tmp-"));
  assert.ok(alias);
  assert.equal((await fsp.lstat(path.join(dir, alias))).isSymbolicLink(), true);
});

test("legacy login never forwards a password across an HTTP redirect", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-sync-redirect-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  let redirectedRequests = 0;
  const attacker = http.createServer((req, res) => {
    redirectedRequests++;
    req.resume();
    res.writeHead(200, { "content-type": "application/json" }).end('{"token":"untrusted"}');
  });
  await new Promise((resolve) => attacker.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => attacker.close(resolve)));
  const origin = http.createServer((req, res) => {
    req.resume();
    res.writeHead(307, { location: `http://127.0.0.1:${attacker.address().port}/receiver` }).end();
  });
  await new Promise((resolve) => origin.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => origin.close(resolve)));
  const result = await runInit(dir, `http://127.0.0.1:${origin.address().port}`,
    path.join(dir, "config.json"));
  assert.notEqual(result.code, 0);
  assert.equal(redirectedRequests, 0);
});

test("legacy init refuses a symlinked config or an aliased parent", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-sync-link-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" }).end('{"token":"fixture-token"}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  const outside = path.join(dir, "outside");
  await fsp.mkdir(outside);
  const sentinel = path.join(outside, "keep.json");
  await fsp.writeFile(sentinel, "PRESERVE_OUTSIDE");
  const alias = path.join(dir, "config.json");
  try { await fsp.symlink(sentinel, alias, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("symlinks unavailable");
    throw error;
  }
  const leaf = await runInit(dir, url, alias);
  assert.notEqual(leaf.code, 0, "symlink config must never be replaced");
  assert.equal((await fsp.lstat(alias)).isSymbolicLink(), true);
  assert.equal(await fsp.readFile(sentinel, "utf8"), "PRESERVE_OUTSIDE");
  const parentAlias = path.join(dir, "parent-alias");
  await fsp.symlink(outside, parentAlias, process.platform === "win32" ? "junction" : "dir");
  const child = await runInit(dir, url, path.join(parentAlias, "new.json"));
  assert.notEqual(child.code, 0, "symlink parent must never receive a config");
  assert.equal(fs.existsSync(path.join(outside, "new.json")), false);
});

test("legacy init preserves pre-existing hard-linked credentials", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-sync-hardlink-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const original = path.join(dir, "original.json");
  const alias = path.join(dir, "config.json");
  await fsp.writeFile(original, "PRESERVE_LINKED_FILE", { mode: 0o600 });
  await fsp.link(original, alias);
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" }).end('{"token":"fixture-token"}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const result = await runInit(dir, `http://127.0.0.1:${server.address().port}`, alias);
  assert.notEqual(result.code, 0, "linked files must not be replaced");
  assert.equal(await fsp.readFile(original, "utf8"), "PRESERVE_LINKED_FILE");
  assert.equal(await fsp.readFile(alias, "utf8"), "PRESERVE_LINKED_FILE");
  assert.equal(fs.statSync(alias).nlink, 2);
});

test("legacy init rejects a group-writable config parent", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX ownership and mode fixture");
  const dir = createPrivateAuthorityFixture("rootark-sync-unsafe-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const parent = path.join(dir, "writable");
  await fsp.mkdir(parent, { mode: 0o777 });
  await fsp.chmod(parent, 0o777);
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" }).end('{"token":"fixture-token"}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const result = await runInit(dir, `http://127.0.0.1:${server.address().port}`,
    path.join(parent, "config.json"));
  assert.notEqual(result.code, 0);
  assert.match(result.output, /UNTRUSTED_SQLITE_PATH|Unsafe|unsafe/);
  assert.equal(fs.existsSync(path.join(parent, "config.json")), false);
});
