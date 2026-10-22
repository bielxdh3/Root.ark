"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  runLocalFixtureCiphertextMigration,
  verifyLocalFixtureCiphertextMigration,
  rollbackLocalFixtureCiphertextMigration,
} = require("../src/services/zk1LocalFixtureMigrationJournal");

const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const bytes = Buffer.from("synthetic encrypted ciphertext, never plaintext/user material\x00", "utf8");

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-local-fixture-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const sub of ["source", "target", "journal", "references/versions", "references/backups", "references/trash"])
    fs.mkdirSync(path.join(dir, sub), { recursive: true });
  fs.writeFileSync(path.join(dir, ".rootark-disposable-fixture"), "rootark-zk-local-fixture-v1\n");
  fs.writeFileSync(path.join(dir, "source", "object1.ct"), bytes);
  const references = {};
  for (const [kind, id] of [["versions", "version1"], ["backups", "backup1"], ["trash", "trash1"]]) {
    const snapshot = Buffer.from(`${kind}-distinct-encrypted-reference`);
    fs.writeFileSync(path.join(dir, "references", kind, `${id}.ct`), snapshot);
    references[kind] = [{ id, digest: digest(snapshot) }];
  }
  const plan = {
    fixtureDir: dir,
    fixtureMode: "rootark-zk-local-fixture-only/v1",
    operationId: "operation1",
    objectId: "object1",
    sourceDigest: digest(bytes),
    sourceProvenance: { role: "source", provider: "fixture-source", identity: "source-1" },
    targetProvenance: { role: "target", provider: "fixture-target", identity: "target-1" },
    references,
  };
  return { dir, plan, source: path.join(dir, "source", "object1.ct"),
    target: path.join(dir, "target", "object1.ct"), journal: path.join(dir, "journal", "operation1.json") };
}

test("opt-in disposable migration verifies independent ciphertext copy while preserving original and opaque report", (t) => {
  const f = fixture(t);
  const first = runLocalFixtureCiphertextMigration(f.plan);
  assert.equal(first.state, "committed");
  assert.equal(first.canMigrate, false);
  assert.equal(first.localVerified, true);
  assert.equal(first.rollbackScope, "local-fixture-only");
  assert.deepEqual(fs.readFileSync(f.source), bytes);
  assert.deepEqual(fs.readFileSync(f.target), bytes);
  assert.equal(verifyLocalFixtureCiphertextMigration(f.plan).localVerified, true);
  assert.equal(runLocalFixtureCiphertextMigration(f.plan).state, "committed");
  assert.equal(JSON.stringify(first).includes(f.dir), false);
  assert.equal(rollbackLocalFixtureCiphertextMigration(f.plan).state, "rolled-back");
  assert.equal(fs.existsSync(f.target), false);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
  assert.equal(rollbackLocalFixtureCiphertextMigration(f.plan).state, "rolled-back");
  assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
});

for (const checkpoint of ["journal-created", "staging-synced", "target-published", "target-verified", "commit-recorded"]) {
  test(`durable crash replay after ${checkpoint} finishes with identical bytes`, (t) => {
    const f = fixture(t);
    assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan,
      onCheckpoint(phase) { if (phase === checkpoint) throw new Error("simulated interrupted process"); },
    }), /simulated interrupted process/);
    assert.deepEqual(fs.readFileSync(f.source), bytes);
    assert.equal(runLocalFixtureCiphertextMigration(f.plan).state, "committed");
    assert.deepEqual(fs.readFileSync(f.target), bytes);
    assert.equal(rollbackLocalFixtureCiphertextMigration(f.plan).state, "rolled-back");
    assert.deepEqual(fs.readFileSync(f.source), bytes);
  });
}

for (const checkpoint of ["rollback-intent-recorded", "target-unlinked"]) {
  test(`rollback resumes crash after ${checkpoint}`, (t) => {
    const f = fixture(t);
    runLocalFixtureCiphertextMigration(f.plan);
    assert.throws(() => rollbackLocalFixtureCiphertextMigration({ ...f.plan,
      onCheckpoint(phase) { if (phase === checkpoint) throw new Error("simulated interruption"); },
    }), /simulated interruption/);
    assert.equal(rollbackLocalFixtureCiphertextMigration(f.plan).state, "rolled-back");
    assert.deepEqual(fs.readFileSync(f.source), bytes);
    assert.equal(fs.existsSync(f.target), false);
  });
}

test("missing or stale versions/backups/trash and missing source block before journal creation", (t) => {
  for (const kind of ["versions", "backups", "trash"]) {
    const f = fixture(t);
    fs.rmSync(path.join(f.dir, "references", kind, `${f.plan.references[kind][0].id}.ct`));
    assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
    assert.equal(fs.existsSync(f.target), false);
    assert.equal(fs.existsSync(f.journal), false);
    const stale = fixture(t);
    fs.writeFileSync(path.join(stale.dir, "references", kind,
      `${stale.plan.references[kind][0].id}.ct`), "stale provider copy");
    assert.throws(() => runLocalFixtureCiphertextMigration(stale.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
    assert.equal(fs.existsSync(stale.journal), false);
  }
  const f = fixture(t);
  fs.rmSync(f.source);
  assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
});

test("undeclared ciphertext versions, backups or trash cannot be silently omitted from local inventory", (t) => {
  for (const kind of ["versions", "backups", "trash"]) {
    const f = fixture(t);
    const extra = path.join(f.dir, "references", kind, "unlisted.ct");
    fs.writeFileSync(extra, Buffer.from("independent synthetic unlisted ciphertext"));
    assert.throws(() => runLocalFixtureCiphertextMigration(f.plan),
      /LOCAL_FIXTURE_MIGRATION_REFUSED/,
      "an omitted " + kind + " entry must deny even when declared references are valid");
    assert.equal(fs.existsSync(f.target), false);
    assert.equal(fs.existsSync(f.journal), false);
    fs.rmSync(extra);
    assert.equal(runLocalFixtureCiphertextMigration(f.plan).state, "committed");
    fs.writeFileSync(extra, Buffer.from("unexpected new synthetic reference"));
    assert.throws(() => verifyLocalFixtureCiphertextMigration(f.plan),
      /LOCAL_FIXTURE_MIGRATION_REFUSED/,
      "post-commit discovery of unlisted " + kind + " must invalidate localVerified");
    assert.throws(() => rollbackLocalFixtureCiphertextMigration(f.plan),
      /LOCAL_FIXTURE_MIGRATION_REFUSED/,
      "unlisted " + kind + " must not be silently skipped during rollback");
    assert.equal(fs.existsSync(f.target), true,
      "a blocked rollback must not destroy the validated target copy");
  }
});

test("adulterated destination, source or journal blocks replay and rollback without destroying evidence", (t) => {
  const f = fixture(t);
  runLocalFixtureCiphertextMigration(f.plan);
  fs.writeFileSync(f.target, "malicious ciphertext substitution");
  assert.throws(() => verifyLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.throws(() => rollbackLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.equal(fs.existsSync(f.target), true);
  fs.writeFileSync(f.target, bytes);
  fs.writeFileSync(f.source, "source changed since plan");
  assert.throws(() => rollbackLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.equal(fs.existsSync(f.target), true);
  fs.writeFileSync(f.source, bytes);
  const journal = JSON.parse(fs.readFileSync(f.journal, "utf8"));
  journal.phase = "rolled-back";
  fs.writeFileSync(f.journal, JSON.stringify(journal));
  assert.throws(() => rollbackLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.equal(fs.existsSync(f.target), true);
});

test("replay with changed scope, provenance or digest fails closed and preserves committed bytes", (t) => {
  const f = fixture(t);
  runLocalFixtureCiphertextMigration(f.plan);
  const changes = [
    { sourceDigest: "0".repeat(64) },
    { targetProvenance: { role: "target", provider: "fixture-target", identity: "other" } },
    { objectId: "object2" },
    { references: { ...f.plan.references, trash: [{ id: "trash1", digest: "0".repeat(64) }] } },
  ];
  for (const change of changes) assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan, ...change }),
    /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.deepEqual(fs.readFileSync(f.target), bytes);
});

test("changing object ID through a getter cannot redirect an already validated migration", (t) => {
  const f = fixture(t);
  const secondSource = path.join(f.dir, "source", "foreignobject.ct");
  const secondTarget = path.join(f.dir, "target", "foreignobject.ct");
  fs.writeFileSync(secondSource, bytes);
  let reads = 0;
  const hostile = { ...f.plan };
  Object.defineProperty(hostile, "objectId", {
    enumerable: true,
    get() { return ++reads === 1 ? "object1" : "foreignobject"; },
  });
  assert.throws(() => runLocalFixtureCiphertextMigration(hostile),
    /LOCAL_FIXTURE_MIGRATION_REFUSED/,
    "validated object1 must not be retargeted to a second source and destination");
  assert.equal(fs.existsSync(secondTarget), false);
  assert.equal(fs.existsSync(f.target), false);
  assert.equal(fs.existsSync(f.journal), false);
  assert.deepEqual(fs.readFileSync(secondSource), bytes);
});

test("accessor-based provenance and reference digest cannot change after validation", (t) => {
  const f = fixture(t);
  const sourceProvenance = { ...f.plan.sourceProvenance };
  Object.defineProperty(sourceProvenance, "identity", {
    enumerable: true,
    get() { return "target-1"; },
  });
  assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan, sourceProvenance }),
    /LOCAL_FIXTURE_MIGRATION_REFUSED/);

  const reference = { ...f.plan.references.versions[0] };
  const referenceDigest = reference.digest;
  let digestReads = 0;
  Object.defineProperty(reference, "digest", {
    enumerable: true,
    get() { return ++digestReads === 1 ? referenceDigest : "0".repeat(64); },
  });
  const references = { ...f.plan.references, versions: [reference] };
  assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan, references }),
    /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.equal(fs.existsSync(f.target), false);
  assert.equal(fs.existsSync(f.journal), false);
});

test("rejects traversal, symlinks, hardlinks, reused target and non-disposable paths", (t) => {
  const f = fixture(t);
  for (const objectId of ["../object1", "..", "bad/name", "bad\\name", ".stage"])
    assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan, objectId }), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan, fixtureDir: os.tmpdir() }),
    /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  fs.writeFileSync(f.target, bytes);
  assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  fs.rmSync(f.target);
  const alias = path.join(f.dir, "source", "other.ct");
  fs.linkSync(f.source, alias);
  assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  fs.rmSync(alias);
  const link = path.join(f.dir, "references", "versions", "version1.ct");
  fs.rmSync(link);
  try { fs.symlinkSync(f.source, link, "file"); } catch (error) {
    if (["EPERM", "EACCES"].includes(error.code)) return;
    throw error;
  }
  assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
});

test("real child-process termination at publish and rollback intent replays durably", (t) => {
  const f = fixture(t);
  function stopAt(method, checkpoint) {
    const script = `const api = require('./src/services/zk1LocalFixtureMigrationJournal');
      const plan = JSON.parse(process.env.ROOTARK_SYNTHETIC_PLAN);
      api[${JSON.stringify(method)}]({ ...plan,
        onCheckpoint(phase) { if (phase === ${JSON.stringify(checkpoint)}) process.exit(71); }
      });`;
    return spawnSync(process.execPath, ["-e", script], {
      cwd: path.resolve(__dirname, ".."),
      env: { ...process.env, ROOTARK_SYNTHETIC_PLAN: JSON.stringify(f.plan) },
      windowsHide: true, encoding: "utf8",
    });
  }
  const first = stopAt("runLocalFixtureCiphertextMigration", "target-published");
  assert.equal(first.status, 71, first.stderr);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
  assert.equal(runLocalFixtureCiphertextMigration(f.plan).state, "committed");
  const second = stopAt("rollbackLocalFixtureCiphertextMigration", "rollback-intent-recorded");
  assert.equal(second.status, 71, second.stderr);
  assert.equal(rollbackLocalFixtureCiphertextMigration(f.plan).state, "rolled-back");
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});

test("process death between exclusive initial journal link and temp unlink recovers only owned inode", (t) => {
  const f = fixture(t);
  const script = `const fs = require("node:fs");
    const originalLink = fs.linkSync;
    fs.linkSync = (...args) => { originalLink(...args); process.exit(71); };
    const api = require("./src/services/zk1LocalFixtureMigrationJournal");
    api.runLocalFixtureCiphertextMigration(JSON.parse(process.env.ROOTARK_SYNTHETIC_PLAN));`;
  const child = spawnSync(process.execPath, ["-e", script], {
    cwd: path.resolve(__dirname, ".."),
    env: { ...process.env, ROOTARK_SYNTHETIC_PLAN: JSON.stringify(f.plan) },
    windowsHide: true, encoding: "utf8",
  });
  assert.equal(child.status, 71, child.stderr);
  const files = fs.readdirSync(path.join(f.dir, "journal"));
  const orphan = files.find((name) => /^\.operation1\.json\.[a-f0-9]{24}\.tmp$/.test(name));
  assert.ok(orphan, "interruption leaves one temporary hard link to the published journal");
  assert.equal(fs.statSync(f.journal).nlink, 2);
  assert.equal(fs.statSync(path.join(f.dir, "journal", orphan)).ino, fs.statSync(f.journal).ino);
  assert.equal(runLocalFixtureCiphertextMigration(f.plan).state, "committed");
  assert.equal(fs.statSync(f.journal).nlink, 1);
  assert.equal(fs.existsSync(path.join(f.dir, "journal", orphan)), false);
  assert.deepEqual(fs.readFileSync(f.target), bytes);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});

test("unexpected hardlink to initial journal fails closed rather than removing foreign evidence", (t) => {
  const f = fixture(t);
  runLocalFixtureCiphertextMigration(f.plan);
  const unexpected = path.join(f.dir, "journal", "untrusted-hardlink");
  fs.linkSync(f.journal, unexpected);
  assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.equal(fs.existsSync(unexpected), true);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
  assert.deepEqual(fs.readFileSync(f.target), bytes);
});

test("repeated crashes before and after initial journal link ignore unrelated pre-link orphan", (t) => {
  const f = fixture(t);
  function crash(afterLink, code) {
    const script = `const fs = require("node:fs");
      const link = fs.linkSync;
      fs.linkSync = (...args) => { if (${afterLink}) link(...args); process.exit(${code}); };
      const api = require("./src/services/zk1LocalFixtureMigrationJournal");
      api.runLocalFixtureCiphertextMigration(JSON.parse(process.env.ROOTARK_SYNTHETIC_PLAN));`;
    const child = spawnSync(process.execPath, ["-e", script], {
      cwd: path.resolve(__dirname, ".."),
      env: { ...process.env, ROOTARK_SYNTHETIC_PLAN: JSON.stringify(f.plan) },
      windowsHide: true, encoding: "utf8",
    });
    assert.equal(child.status, code, child.stderr);
  }
  crash(false, 72);
  const dir = path.join(f.dir, "journal");
  const old = fs.readdirSync(dir);
  assert.equal(old.length, 1, "first failed publication left an inert pre-link temp");
  assert.equal(fs.existsSync(f.journal), false);
  crash(true, 71);
  const current = fs.readdirSync(dir);
  assert.equal(current.length, 3, "published journal, its own temp link and an unrelated prior orphan");
  assert.equal(fs.statSync(f.journal).nlink, 2);
  assert.equal(runLocalFixtureCiphertextMigration(f.plan).state, "committed");
  assert.equal(fs.statSync(f.journal).nlink, 1);
  assert.equal(fs.existsSync(path.join(dir, old[0])), true,
    "recovery must not delete the unrelated orphan or other evidence");
  assert.deepEqual(fs.readFileSync(f.target), bytes);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});

test("orphan and replacement symlinks and unexpected stage after commit block without deleting data", (t) => {
  const f = fixture(t);
  try { fs.symlinkSync(f.source, f.target, "file"); }
  catch (error) { if (["EPERM", "EACCES"].includes(error.code)) return; throw error; }
  assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.equal(fs.existsSync(f.journal), false);
  fs.unlinkSync(f.target);
  runLocalFixtureCiphertextMigration(f.plan);
  fs.writeFileSync(path.join(f.dir, "target", ".operation1.stage"), bytes);
  assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.throws(() => verifyLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});

test("switching a validated target directory to a junction cannot publish outside the fixture", (t) => {
  const f = fixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-fixture-journal-outside-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan,
    onCheckpoint(phase) {
      if (phase !== "journal-created") return;
      fs.renameSync(path.join(f.dir, "target"), path.join(f.dir, "target-original"));
      fs.symlinkSync(outside, path.join(f.dir, "target"), process.platform === "win32" ? "junction" : "dir");
    },
  }), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.equal(fs.existsSync(path.join(outside, "object1.ct")), false);
  assert.equal(fs.existsSync(path.join(outside, ".operation1.stage")), false);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});

test("switching target to an external junction during rollback cannot delete its copy", (t) => {
  const f = fixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-fixture-rollback-outside-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  runLocalFixtureCiphertextMigration(f.plan);
  const foreign = path.join(outside, "object1.ct");
  fs.writeFileSync(foreign, bytes);
  assert.throws(() => rollbackLocalFixtureCiphertextMigration({ ...f.plan,
    onCheckpoint(phase) {
      if (phase !== "rollback-intent-recorded") return;
      fs.renameSync(path.join(f.dir, "target"), path.join(f.dir, "target-original"));
      fs.symlinkSync(outside, path.join(f.dir, "target"), process.platform === "win32" ? "junction" : "dir");
    },
  }), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.deepEqual(fs.readFileSync(foreign), bytes);
  assert.deepEqual(fs.readFileSync(path.join(f.dir, "target-original", "object1.ct")), bytes);
});

test("exclusive target publication keeps a racing EEXIST collision without overwriting", (t) => {
  const f = fixture(t);
  const originalLink = fs.linkSync;
  let collision = false;
  fs.linkSync = (from, to) => {
    if (to === f.target) {
      collision = true;
      fs.writeFileSync(f.target, "synthetic foreign target");
    }
    return originalLink(from, to);
  };
  try {
    assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /EEXIST/);
  } finally { fs.linkSync = originalLink; }
  assert.equal(collision, true);
  assert.equal(fs.readFileSync(f.target, "utf8"), "synthetic foreign target");
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});

test("journal update refuses a replaced destination instead of overwriting it", (t) => {
  const f = fixture(t);
  const original = `${f.journal}.original`;
  assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan,
    onCheckpoint(phase) {
      if (phase !== "target-verified") return;
      fs.renameSync(f.journal, original);
      fs.writeFileSync(f.journal, "synthetic foreign journal");
    },
  }), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.equal(fs.readFileSync(f.journal, "utf8"), "synthetic foreign journal");
  assert.equal(fs.existsSync(original), true);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});

test("journal temp replacement after publication is preserved as foreign evidence", (t) => {
  const f = fixture(t);
  const originalLink = fs.linkSync;
  let replacedTemp;
  fs.linkSync = (from, to) => {
    originalLink(from, to);
    if (to === f.journal) {
      fs.unlinkSync(from);
      fs.writeFileSync(from, "synthetic foreign temp");
      replacedTemp = from;
    }
  };
  try {
    assert.throws(() => runLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  } finally { fs.linkSync = originalLink; }
  assert.ok(replacedTemp);
  assert.equal(fs.readFileSync(replacedTemp, "utf8"), "synthetic foreign temp");
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});

test("truncated staged ciphertext cannot be recorded as committed or rolled back destructively", (t) => {
  const f = fixture(t);
  assert.throws(() => runLocalFixtureCiphertextMigration({ ...f.plan,
    onCheckpoint(phase) {
      if (phase === "staging-synced") fs.truncateSync(path.join(f.dir, "target", ".operation1.stage"), 3);
    },
  }), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.throws(() => verifyLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.throws(() => rollbackLocalFixtureCiphertextMigration(f.plan), /LOCAL_FIXTURE_MIGRATION_REFUSED/);
  assert.deepEqual(fs.readFileSync(f.source), bytes);
});
