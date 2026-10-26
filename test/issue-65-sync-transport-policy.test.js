"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { normalizeTrustedSyncServerUrl } =
  require("../sync-client/rootark-sync-transport-policy");

test("sync transport pins HTTPS, with HTTP allowed only for explicit loopback endpoints", () => {
  for (const [input, expected] of [
    ["https://vault.example.org/", "https://vault.example.org"],
    ["https://vault.example.org/base/", "https://vault.example.org/base"],
    ["https://VAULT.example.org:443/base", "https://vault.example.org/base"],
    ["http://localhost:3000/", "http://localhost:3000"],
    ["http://127.0.0.1:3000", "http://127.0.0.1:3000"],
    ["http://[::1]:3000/", "http://[::1]:3000"],
  ]) {
    assert.equal(normalizeTrustedSyncServerUrl(input), expected, input);
  }
});

test("sync transport denies insecure remote HTTP and authority confusion before any credentials or ciphertext", () => {
  for (const input of [
    "http://example.org", "http://127.0.0.2:3000", "http://localhost.attacker.example",
    "http://[::2]:3000", "http://127.0.0.1.attacker.example",
    "ftp://vault.example.org", "file:///etc/passwd", "data:text/plain,hello",
    "https://alice:password@vault.example.org", "https://vault.example.org@attacker.example",
    "https://vault.example.org/?token=x", "https://vault.example.org/#redirect",
    "https://vault.example.org\\@attacker.example", " https://vault.example.org",
    "https://vault.example.org\n", "", "localhost:3000",
  ]) {
    assert.throws(() => normalizeTrustedSyncServerUrl(input),
      { code: "SYNC_UNTRUSTED_SERVER_URL" }, JSON.stringify(input));
  }
  for (const input of [null, undefined, {}, 23, []]) {
    assert.throws(() => normalizeTrustedSyncServerUrl(input),
      { code: "SYNC_UNTRUSTED_SERVER_URL" });
  }
});

test("legacy Sync CLI denies remote HTTP before login, directory creation or writing config", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-sync-policy-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const config = path.join(root, "not-created.json");
  const folder = path.join(root, "not-created-data");
  const run = spawnSync(process.execPath, [
    path.resolve(__dirname, "../sync-client/rootark-sync.js"), "init",
    "--server", "http://public-example.invalid", "--username", "alice",
    "--password", "not-a-real-secret", "--folder", folder, "--config", config,
  ], { timeout: 6000, encoding: "utf8", windowsHide: true });
  assert.equal(run.status, 1, String(run.error || run.stderr));
  assert.match(run.stderr, /SYNC_UNTRUSTED_SERVER_URL/);
  assert.equal(fs.existsSync(config), false);
  assert.equal(fs.existsSync(folder), false);
});
