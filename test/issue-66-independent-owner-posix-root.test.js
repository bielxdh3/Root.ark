"use strict";

// Opt-in physical ownership probe, NOT a production RootSession authority.
// The root-owned fixture is created separately by the privileged test setup.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawn, spawnSync } = require("node:child_process");

const enabled = process.platform === "linux" && process.env.ROOTARK_ISSUE66_OWNER_PROBE === "1";
const source = path.resolve(__dirname, "../experiments/issue66-owner-rooted-read/owner_rooted_read.c");
const expected = "ROOTARK_OWNER_V1 fs=EXT4 parent=ROOT_STICKY root=ROOT_OWNED marker=READ_ONLY fd=PINNED\n";

test("#66 root-owned ext4 parent rejects concurrent same-UID substitution while native child reads exact root", {
  skip: !enabled, timeout: 60000,
}, async (t) => {
  assert.match(process.version, /^v22\./);
  assert.match(os.release(), /wsl|microsoft/i);
  assert.notEqual(process.getuid(), 0, "adversarial reader must not have root authority");
  const leaf = process.env.ROOTARK_ISSUE66_OWNER_LEAF || "";
  assert.match(leaf, /^rootark-issue66-owner-[0-9a-f]{16}$/);
  const parent = "/var/tmp";
  const parentStats = fs.statSync(parent);
  assert.equal(parentStats.uid, 0);
  assert.equal(parentStats.mode & 0o1777, 0o1777);
  assert.equal(fs.statfsSync(parent).type, 0xef53, "test must run on real ext4");
  const owned = path.join(parent, leaf);
  const unicodeMarker = path.join(owned, "café-中-😀.txt");
  const rootStats = fs.lstatSync(owned);
  assert.equal(rootStats.uid, 0);
  assert.ok(rootStats.isDirectory() && !rootStats.isSymbolicLink());
  assert.equal(rootStats.mode & 0o777, 0o555);
  const markerStats = fs.lstatSync(unicodeMarker);
  assert.equal(markerStats.uid, 0);
  assert.ok(markerStats.isFile() && !markerStats.isSymbolicLink());
  assert.equal(markerStats.mode & 0o777, 0o444);

  const home = os.homedir();
  assert.equal(fs.statfsSync(home).type, 0xef53);
  const build = fs.mkdtempSync(path.join(home, ".rootark-issue66-owner-build-"));
  assert.equal(fs.statSync(build).mode & 0o777, 0o700);
  const binary = path.join(build, "owner-read");
  const compile = spawnSync("/usr/bin/gcc", ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", source, "-o", binary], {
    cwd: build, env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", TMPDIR: build },
    encoding: "utf8", timeout: 30000, maxBuffer: 4096,
  });
  assert.equal(compile.status, 0, `owner test helper did not build: ${compile.stderr}`);
  const run = () => spawnSync(binary, [leaf], {
    cwd: build, env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    encoding: "utf8", timeout: 15000, maxBuffer: 4096,
  });
  const forged = spawnSync(binary, ["../etc/passwd"], {
    cwd: build, env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    encoding: "utf8", timeout: 15000, maxBuffer: 4096,
  });
  assert.equal(forged.status, 41, "path-shaped authority arguments must be rejected");
  assert.equal(forged.stdout, "");
  assert.equal(forged.stderr, "ROOTARK_OWNER_REJECTED\n");
  const first = run();
  assert.equal(first.status, 0, "first native root-owned read failed");
  assert.equal(first.stdout, expected);
  assert.equal(first.stderr, "");

  // The other unprivileged process has the SAME UID as this consumer. Root
  // ownership + sticky root-owned /var/tmp parent excludes it as a writer.
  // No test invokes an arbitrary delete or changes global permissions.
  const replacement = path.join(parent, `${leaf}-replace`);
  assert.throws(() => fs.renameSync(owned, replacement), (error) =>
    ["EPERM", "EACCES"].includes(error.code), "same-UID rename must be denied");
  assert.throws(() => fs.writeFileSync(unicodeMarker, "FORGED", { flag: "r+" }), (error) =>
    ["EPERM", "EACCES"].includes(error.code), "same-UID write must be denied");

  // Independent Node processes run as the SAME unprivileged UID and attempt
  // replacement + in-place mutation WHILE a fresh native process repeatedly
  // opens/read-verifies the root-owned fixture. Attackers never delete data.
  const attackerCode = [
    "'use strict';",
    "const fs = require('node:fs');",
    "if (process.getuid() === 0) process.exit(91);",
    "const [dir, renamed, file] = process.argv.slice(1);",
    "process.stdout.write('READY' + String.fromCharCode(10));",
    "process.stdin.once('end', () => process.exit(94));",
    "process.stdin.once('data', () => {",
    "  for (let i = 0; i < 400; i++) {",
    "    for (const attack of [",
    "      () => fs.renameSync(dir, renamed),",
    "      () => fs.writeFileSync(file, 'FORGED', {flag: 'r+'}),",
    "    ]) {",
    "      try { attack(); process.exit(92); }",
    "      catch (error) { if (!['EPERM','EACCES'].includes(error.code)) process.exit(93); }",
    "    }",
    "  }",
    "  process.stdout.write('DENIED' + String.fromCharCode(10));",
    "  process.exit(0);",
    "});",
  ].join("\n");
  const attackers = Array.from({ length: 2 }, () => {
    const child = spawn(process.execPath, ["-e", attackerCode, owned, replacement, unicodeMarker], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    });
    let out = "", err = "";
    const ready = new Promise((resolve, reject) => {
      child.once("error", reject);
      child.stdout.once("data", (chunk) => {
        out += String(chunk);
        if (!out.startsWith("READY\n")) reject(new Error("attacker handshake invalid"));
        else resolve();
      });
    });
    child.stdout.on("data", (chunk) => { out += String(chunk); });
    child.stderr.on("data", (chunk) => { err += String(chunk); });
    const done = new Promise((resolve) => child.once("close", (code) => resolve({ code, out, err })));
    return { child, ready, done };
  });
  t.after(() => { for (const attacker of attackers) attacker.child.stdin.end(); });
  await Promise.all(attackers.map((attacker) => attacker.ready));
  for (const attacker of attackers) attacker.child.stdin.write("GO\n");
  for (let i = 0; i < 8; i++) {
    const overlapping = run();
    assert.equal(overlapping.status, 0, "native open/read must survive active same-UID adversaries");
    assert.equal(overlapping.stdout, expected);
    assert.equal(overlapping.stderr, "");
  }
  for (const result of await Promise.all(attackers.map((attacker) => attacker.done))) {
    assert.equal(result.code, 0, `same-UID attacker failed unexpectedly: ${result.err}`);
    assert.ok(result.out.includes("DENIED\n"));
  }
  const second = run(); // a new native process, no inherited root fd
  assert.equal(second.status, 0, "cold-open native verification failed");
  assert.equal(second.stdout, expected);
  assert.equal(second.stderr, "");
  const after = fs.lstatSync(owned);
  assert.equal(after.dev, rootStats.dev);
  assert.equal(after.ino, rootStats.ino);
  assert.equal(fs.readFileSync(unicodeMarker, "utf8"), "TRUSTED_ROOT_CANARY_V1\n");
  t.diagnostic("Owned fixture and unprivileged build directory deliberately retained; no cleanup performed");
});
