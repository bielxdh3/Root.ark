"use strict";

// Issue 66 PR300: opt-in Windows NTFS LAB ONLY, no sync-client import except
// for the unchanged RootSession denial. Synthetic throwaway test fixtures.
// A Node test key signs original-A IDs collected in a separate enrollment
// executable run. The lab verifies the signature before invoking the native
// checked walk. Neither the key nor its local custody authorizes production.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { createInterface } = require("node:readline");

const windows = process.platform === "win32";
const base = path.resolve(__dirname, "..");
const source = path.join(base, "issue66-w21-inbound-held-publish-lab", "win-held-publisher.cs");
const issuer = path.join(__dirname, "enrollment-issuer.lab.cjs");
const compiler = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe";
let executable;
const fixtures = [];

function command(program, args, timeout = 25000) {
  return spawnSync(program, args, { windowsHide: true, encoding: "utf8", timeout,
    maxBuffer: 16384 });
}
function scratch() {
  const folder = fs.mkdtempSync(path.join(process.env.LOCALAPPDATA,
    "rootark66-w31-ancestor-"));
  const original = path.join(folder, "owner");
  const root = path.join(original, "deep");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "source"), "ENROLLED_ORIGINAL_A_BYTES");
  fixtures.push(folder); // retain named fixtures, do not recursively clean swapped paths
  return { folder, original, root };
}
function enroll(fixture, mode = "movable") {
  const result = command(process.execPath, [issuer, executable, mode, fixture.root]);
  assert.equal(result.status, 0, `${result.stderr} ${result.stdout}`);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.record.root, fixture.root);
  return receipt;
}
function checked(receipt) {
  const message = Buffer.from(JSON.stringify(receipt.record));
  assert.ok(crypto.verify(null, message,
    crypto.createPublicKey(receipt.publicKey), Buffer.from(receipt.signature, "base64")),
    "test-only independent signing receipt was not valid");
  assert.match(receipt.record.ids, /^[A-Za-z0-9+/=,]+$/);
  return receipt.record;
}
const attackerCode = String.raw`
const fs = require('node:fs');
const path = require('node:path');
const folder = process.argv[1];
const mode = process.argv[2];
const original = path.join(folder, 'owner');
const parked = path.join(folder, 'owner.parked');
const source = path.join(original, 'deep', 'source');
const sourceParked = path.join(original, 'deep', 'source.parked');
try {
  if (mode === 'source' || mode === 'veto-source') fs.renameSync(source, sourceParked);
  else fs.renameSync(original, parked);
} catch (error) {
  if (['veto', 'veto-source'].includes(mode) && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) {
    process.stdout.write('SHARE_VETO|' + process.pid + '\n');
    process.exit(0);
  }
  throw error;
}
if (mode === 'veto' || mode === 'veto-source') throw new Error('ABA_WINDOW_OPENED_UNEXPECTEDLY');
if (mode !== 'source') fs.mkdirSync(path.join(original, 'deep'), { recursive: true });
fs.writeFileSync(source, 'FOREIGN_SAME_SID_B_BYTES');
const fd = fs.openSync(source, 'r+');
try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
const sid = require('node:child_process').execFileSync(
  path.join(process.env.WINDIR, 'System32', 'whoami.exe'), ['/user'],
  { encoding: 'utf8' }).match(/S-1-(?:\d+-)+\d+/)[0];
process.stdout.write('SWAPPED|' + process.pid + '|' + sid + '\n');
`;
function attacker(fixture, mode = "swap") {
  const result = command(process.execPath, ["-e", attackerCode, fixture.folder, mode]);
  assert.equal(result.status, 0, `independent attacker failed: ${result.stderr || result.stdout}`);
  assert.match(result.stdout, mode.startsWith("veto")
    ? /^SHARE_VETO\|\d+\r?\n$/ : /^SWAPPED\|\d+\|S-1-(?:\d+-)+\d+\r?\n$/);
  assert.notEqual(Number(result.stdout.trim().split("|")[1]), process.pid,
    "attack must originate in a second OS PID");
  return { ...result, sid: result.stdout.trim().split("|")[2] };
}
async function publish(receipt, mode, afterPinned) {
  const record = checked(receipt);
  const processHandle = spawn(executable, ["publish", mode, record.root, record.ids],
    { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  const lines = [];
  const errors = [];
  const output = createInterface({ input: processHandle.stdout });
  let dispatch;
  const pinned = new Promise((resolve, reject) => { dispatch = { resolve, reject }; });
  output.on("line", (line) => {
    lines.push(line);
    if (line.startsWith("PINNED|")) dispatch.resolve(line);
    if (line.startsWith("REJECTED|") || line.startsWith("ERROR|")) dispatch.resolve(null);
  });
  output.once("close", () => dispatch.resolve(null));
  processHandle.stderr.on("data", (chunk) => errors.push(chunk.toString()));
  const exit = new Promise((resolve, reject) => {
    processHandle.once("error", reject);
    processHandle.once("exit", (code) => resolve(code));
  });
  const deadline = setTimeout(() => processHandle.kill(), 25000);
  try {
    const signal = await pinned;
    if (signal && afterPinned) await afterPinned(signal);
    if (signal) processHandle.stdin.end("COMMIT\n");
    else processHandle.stdin.end();
    return { code: await exit, lines, stderr: errors.join("") };
  } finally {
    clearTimeout(deadline);
    output.close();
    if (processHandle.exitCode === null) processHandle.kill();
  }
}

test("W31 test-signed FileId original-A checked by held native NtCreateFile chain",
  { skip: !windows, timeout: 100000 }, async (t) => {
    assert.equal(Number(process.versions.node.split(".")[0]), 22, "Windows Node22 required");
    assert.ok(fs.existsSync(compiler), "fixed Framework64 csc.exe required");
    assert.ok(process.env.LOCALAPPDATA, "LocalAppData required for physical NTFS fixtures");
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rootark66-w31-build-"));
    t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
    executable = path.join(temp, "w31-held-ancestors.exe");
    const compiled = command(compiler, ["/nologo", "/platform:x64", "/target:exe",
      `/out:${executable}`, source]);
    assert.equal(compiled.status, 0, `${compiled.stdout} ${compiled.stderr}`);

    await t.test("legitimate enrollment signs A and native publication remains on A", async () => {
      const fixture = scratch();
      const receipt = enroll(fixture);
      const result = await publish(receipt, "movable");
      assert.equal(result.code, 0, JSON.stringify(result));
      assert.ok(result.lines.some((line) => line.startsWith("PUBLISHED|HELD_SOURCE|NO_REPLACE|")));
      assert.equal(fs.readFileSync(path.join(fixture.root, "published"), "utf8"),
        "ENROLLED_ORIGINAL_A_BYTES");
      assert.equal(fs.statSync(path.join(fixture.root, "published"), { bigint: true }).ino,
        fs.statSync(path.join(fixture.root, "source"), { bigint: true }).ino);
    });

    await t.test("signed A refuses B planted by a second same-SID PID BEFORE native acquisition", async () => {
      const fixture = scratch();
      const receipt = enroll(fixture);
      const attack = attacker(fixture);
      const sid = command(path.join(process.env.WINDIR, "System32", "whoami.exe"), ["/user"])
        .stdout.match(/S-1-(?:\d+-)+\d+/)[0];
      assert.equal(attack.sid, sid, "pre-pin attacker must be same-SID");
      const result = await publish(receipt, "movable");
      assert.equal(result.code, 21, JSON.stringify(result));
      assert.ok(result.lines.includes("REJECTED|ENROLLED_ORIGINAL_MISMATCH"));
      assert.equal(fs.existsSync(path.join(fixture.original, "deep", "published")), false);
      assert.equal(fs.readFileSync(path.join(fixture.original, "deep", "source"), "utf8"),
        "FOREIGN_SAME_SID_B_BYTES");
    });

    await t.test("a post-pin same-SID source A-to-B rebind is rejected before COMMIT", async () => {
      const fixture = scratch();
      const receipt = enroll(fixture);
      const result = await publish(receipt, "movable", (signal) => {
        const attack = attacker(fixture, "source");
        assert.equal(attack.sid, signal.split("|")[1], "post-pin writer must be same SID");
      });
      assert.equal(result.code, 22, JSON.stringify(result));
      assert.ok(result.lines.includes("REJECTED|ORIGINAL_ANCESTRY_REBOUND"));
      assert.equal(fs.existsSync(path.join(fixture.original, "deep", "published")), false);
      assert.equal(fs.readFileSync(path.join(fixture.root, "source"), "utf8"),
        "FOREIGN_SAME_SID_B_BYTES");
    });

    await t.test("no-replace on retained parent preserves an occupied foreign target", async () => {
      const fixture = scratch();
      const receipt = enroll(fixture);
      fs.writeFileSync(path.join(fixture.root, "published"), "FOREIGN_COLLISION_CONTENT");
      const result = await publish(receipt, "movable");
      assert.equal(result.code, 23, JSON.stringify(result));
      assert.ok(result.lines.includes("REJECTED|NO_REPLACE_C0000035"));
      assert.equal(fs.readFileSync(path.join(fixture.root, "published"), "utf8"),
        "FOREIGN_COLLISION_CONTENT");
    });

    await t.test("strict held directory handles veto attempted same-SID A-B-A rename", async () => {
      const fixture = scratch();
      const receipt = enroll(fixture, "locked");
      const result = await publish(receipt, "locked", () => attacker(fixture, "veto"));
      assert.equal(result.code, 0, JSON.stringify(result));
      assert.ok(result.lines.some((line) => line.startsWith("PUBLISHED|HELD_SOURCE|NO_REPLACE|")));
      assert.equal(fs.readFileSync(path.join(fixture.root, "published"), "utf8"),
        "ENROLLED_ORIGINAL_A_BYTES");
    });

    await t.test("strict held original-source HANDLE also blocks same-SID file A-B-A", async () => {
      const fixture = scratch();
      const receipt = enroll(fixture, "locked");
      const result = await publish(receipt, "locked", () => attacker(fixture, "veto-source"));
      assert.equal(result.code, 0, JSON.stringify(result));
      assert.ok(result.lines.some((line) => line.startsWith("PUBLISHED|HELD_SOURCE|NO_REPLACE|")));
      assert.equal(fs.existsSync(path.join(fixture.root, "source.parked")), false);
      assert.equal(fs.readFileSync(path.join(fixture.root, "published"), "utf8"),
        "ENROLLED_ORIGINAL_A_BYTES");
    });

    await t.test("mutation of test-signed FileId receipt fails before invoking native code", () => {
      const fixture = scratch();
      const receipt = enroll(fixture);
      receipt.record.ids += "A";
      assert.throws(() => checked(receipt), /test-only independent signing receipt was not valid/);
      assert.equal(fs.existsSync(path.join(fixture.root, "published")), false);
    });
  });
