"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const KINDS = ["versions", "backups", "trash", "links", "derived", "retention"];
const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const childScript = `
  const path = require("node:path");
  process.env.TMPDIR = process.argv[3];
  const { runLocalFixtureCiphertextMigration } =
    require(path.join(process.argv[1], "src/services/zk1LocalFixtureMigrationJournal.js"));
  try {
    const report = runLocalFixtureCiphertextMigration(JSON.parse(process.argv[2]));
    process.stdout.write(report.state === "committed" ? "COMMITTED" : "UNEXPECTED_STATE");
  } catch (error) {
    process.stdout.write(error.code === "LOCAL_FIXTURE_MIGRATION_REFUSED" ? "DENIED" : "UNEXPECTED_ERROR");
  }
`;

function fixture(parent, principal = null) {
  const root = path.join(parent, "rootark-zk-local-fixture-" + crypto.randomBytes(8).toString("hex"));
  fs.mkdirSync(root, { mode: 0o700 });
  const directories = [root, ...["source", "target", "journal", "references",
    ...KINDS.map((kind) => path.join("references", kind))].map((name) => path.join(root, name))];
  // root occurs twice in this list, harmless and kept explicit for the owner transfer.
  for (const dir of directories.slice(1)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const bytes = Buffer.from("disposable ciphertext fixture", "utf8");
  const files = [
    [path.join(root, ".rootark-disposable-fixture"), Buffer.from("rootark-zk-local-fixture-v1\n")],
    [path.join(root, "source", "object1.ct"), bytes],
  ];
  const references = {};
  for (const kind of KINDS) {
    const id = kind + "1";
    const value = Buffer.from("disposable reference " + kind);
    references[kind] = [{ id, digest: digest(value) }];
    files.push([path.join(root, "references", kind, id + ".ct"), value]);
  }
  for (const [name, value] of files) fs.writeFileSync(name, value, { mode: 0o600 });
  if (principal) {
    for (const dir of directories) fs.chownSync(dir, principal.uid, principal.gid);
    for (const [name] of files) fs.chownSync(name, principal.uid, principal.gid);
  }
  return {
    root,
    plan: {
      fixtureDir: root, fixtureMode: "rootark-zk-local-fixture-only/v1",
      operationId: "operation1", objectId: "object1", sourceDigest: digest(bytes),
      sourceProvenance: { role: "source", provider: "fixture-source", identity: "source-1" },
      targetProvenance: { role: "target", provider: "fixture-target", identity: "target-1" },
      references,
    },
  };
}

function run(f, parent, principal) {
  const params = [process.execPath, "-e", childScript, path.resolve(__dirname, ".."),
    JSON.stringify(f.plan), parent];
  const command = principal ? "/usr/sbin/runuser" : process.execPath;
  const args = principal ? ["-u", principal, "--", ...params] : params.slice(1);
  const child = spawnSync(command, args, { encoding: "utf8", timeout: 20000,
    env: { ...process.env, TMPDIR: parent } });
  assert.equal(child.status, 0, "disposable migration subprocess must exit normally");
  return child.stdout;
}

test("POSIX fixture rejects untrusted writable TMPDIR ancestor before journal/stage side effects", {
  skip: process.platform !== "linux",
}, (t) => {
  const originalTemp = fs.realpathSync.native(os.tmpdir());
  const parent = fs.mkdtempSync(path.join(originalTemp, "zk65-hostile-tmpdir-"));
  t.after(() => fs.rmSync(parent, { force: true, recursive: true }));
  // A world-writable parent allows a distinct UID to rename a 0700 child.
  fs.chmodSync(parent, 0o777);
  let daemon = null;
  let adversary = null;
  if (process.getuid() === 0) {
    const ids = (name) => ({
      uid: Number(spawnSync("id", ["-u", name], { encoding: "utf8" }).stdout.trim()),
      gid: Number(spawnSync("id", ["-g", name], { encoding: "utf8" }).stdout.trim()),
    });
    daemon = ids("daemon");
    adversary = ids("nobody");
    fs.chownSync(parent, adversary.uid, adversary.gid);
  }
  const f = fixture(parent, daemon);
  if (daemon) {
    const parked = path.join(parent, "moved-by-lower-uid");
    const move = spawnSync("/usr/sbin/runuser",
      ["-u", "nobody", "--", "mv", f.root, parked],
      { encoding: "utf8", timeout: 10000 });
    assert.equal(move.status, 0, "different unprivileged UID can rename a 0700 fixture via its writable parent");
    fs.renameSync(parked, f.root);
  }
  assert.equal(run(f, parent, daemon ? "daemon" : null), "DENIED");
  assert.deepEqual(fs.readdirSync(path.join(f.root, "journal")), []);
  assert.deepEqual(fs.readdirSync(path.join(f.root, "target")), []);
  assert.deepEqual(fs.readFileSync(path.join(f.root, "source", "object1.ct")),
    Buffer.from("disposable ciphertext fixture"));
});

test("POSIX fixture still accepts default root-owned sticky /tmp with private 0700 child", {
  skip: process.platform !== "linux",
}, (t) => {
  const temporary = fs.realpathSync.native(os.tmpdir());
  const stat = fs.statSync(temporary);
  if ((stat.mode & 0o1000) === 0 || stat.uid !== 0) {
    t.skip("this temp root is not the root-owned sticky /tmp case");
    return;
  }
  const f = fixture(temporary);
  t.after(() => fs.rmSync(f.root, { force: true, recursive: true }));
  assert.equal(run(f, temporary, null), "COMMITTED");
});
