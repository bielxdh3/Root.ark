"use strict";

// Cross-process regression: a writer admitted before the durable whole-restore
// marker can commit after an unfenced evidence/pre-image read. The restore
// barrier MUST drain that writer before collecting the authoritative preimage.
// This file is intentionally test-only; W2 owns all production implementation.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const Database = require("better-sqlite3");
const { setTimeout: delay } = require("node:timers/promises");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const strictAudit = require("../services/strictAuditSnapshot");

const writerScript = String.raw`
"use strict";
const Database = require("better-sqlite3");
const fs = require("node:fs");
const [journalPath, coordinatorPath, kind] = process.argv.slice(1);
let db;
function failed(error) {
  try { if (db?.inTransaction) db.exec("ROLLBACK"); } catch {}
  try { db?.close(); } catch {}
  process.send?.({ type: "error", code: String(error?.code || "UNEXPECTED").slice(0, 48) });
  process.exitCode = 1;
}
try {
  db = new Database(journalPath, { timeout: 0, fileMustExist: true });
  db.exec("BEGIN IMMEDIATE");
  // This is the last coordinator check already inside the write transaction:
  // the fixture MUST be admitted before restoration publishes its marker.
  if (fs.existsSync(coordinatorPath)) throw Error("COORDINATOR_ALREADY_PRESENT");
  const event = JSON.stringify({ id: "pre-marker-delayed", eventType: "auth.login.failed" });
  if (kind === "sidecar") {
    db.prepare("INSERT INTO pending_audit (id,event) VALUES (?,?)").run("pre-marker-delayed", event);
  } else if (kind === "main") {
    db.prepare("INSERT INTO audit_logs (id) VALUES (?)").run("pre-marker-delayed");
  } else throw Error("INVALID_CHILD_KIND");
  process.send({ type: "held" });
  process.on("message", (message) => {
    if (message?.type !== "commit") return;
    try {
      if (!fs.existsSync(coordinatorPath)) throw Error("COORDINATOR_NOT_DURABLE");
      db.exec("COMMIT");
      db.close();
      process.send({ type: "committed" }, () => process.exit(0));
    } catch (error) { failed(error); }
  });
} catch (error) { failed(error); }
`;

function privateFixture() {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(),
      `rootark-audit-restore-barrier-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-restore-barrier-"));
  if (process.platform === "win32") {
    assert.equal(fs.existsSync(root), false);
    ensureWindowsChunkUploadRoot(root);
  }
  const primaryPath = path.join(root, "rootark.sqlite");
  const coordinator = path.join(root, ".rootark-restore-coordinator.json");
  const primary = new Database(primaryPath);
  primary.pragma("journal_mode = WAL");
  primary.pragma("synchronous = FULL");
  primary.exec("CREATE TABLE audit_logs (id TEXT PRIMARY KEY);"
    + "CREATE TABLE rootark_strict_sync_audit_mode "
    + "(id INTEGER PRIMARY KEY CHECK(id=1), mode TEXT NOT NULL CHECK(mode='append_only'));"
    + "INSERT INTO rootark_strict_sync_audit_mode VALUES (1,'append_only')");
  const sidecarPath = strictAudit.journalPath(primaryPath);
  const parent = path.dirname(sidecarPath);
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(parent);
  else fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const sidecar = new Database(sidecarPath);
  sidecar.pragma("journal_mode = WAL");
  sidecar.pragma("synchronous = FULL");
  sidecar.exec("CREATE TABLE pending_audit (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL);"
    + "CREATE TABLE archived_audit (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL)");
  sidecar.close();
  return { root, primaryPath, coordinator, sidecarPath, primary };
}

function childMessages(child) {
  const ready = [];
  const waiting = [];
  const deliver = (message) => {
    const waiter = waiting.shift();
    if (waiter) waiter(message);
    else ready.push(message);
  };
  child.on("message", deliver);
  child.on("error", (error) => deliver({ type: "error", code: error.code }));
  child.on("exit", (code, signal) => deliver({ type: "exit", code, signal }));
  return async function expect(type) {
    const message = ready.length ? ready.shift()
      : await new Promise((resolve) => {
        const timeout = setTimeout(() => resolve({ type: "timeout" }), 12_000);
        timeout.unref();
        waiting.push((value) => { clearTimeout(timeout); resolve(value); });
      });
    assert.equal(message?.type, type,
      `expected child IPC ${type}, received ${JSON.stringify(message)}`);
  };
}

for (const kind of ["sidecar", "main"]) test(
  `durable restore gate drains a pre-marker ${kind} cross-process write before evidence/preimage`, {
    timeout: 45_000,
  }, async (t) => {
  assert.equal(typeof strictAudit.drainAuditWriters, "function",
    "RED on published #235: the restore drain must exist before this safety gate can pass");
  const fixture = privateFixture();
  const heldPath = kind === "main" ? fixture.primaryPath : fixture.sidecarPath;
  const table = kind === "main" ? "audit_logs" : "pending_audit";
  const query = `SELECT COUNT(*) AS n FROM ${table} WHERE id='pre-marker-delayed'`;
  const child = spawn(process.execPath,
    ["-e", writerScript, heldPath, fixture.coordinator, kind],
    { cwd: fixture.root, stdio: ["ignore", "ignore", "ignore", "ipc"],
      windowsHide: true });
  const expect = childMessages(child);
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
      await Promise.race([once(child, "exit").catch(() => {}), delay(1000)]);
    }
    fixture.primary.close();
    fs.rmSync(fixture.root, { recursive: true, force: true, maxRetries: 5 });
  });
  await expect("held"); // SQLite write lock and row held in a different process.

  // Simulate the already durable restore coordinator (same name the runtime
  // checks); a write authorized before it existed remains able to commit.
  fs.writeFileSync(fixture.coordinator,
    JSON.stringify({ version: 1, phase: "preparing" }), { flag: "wx" });
  // On Windows fsync of a read-only handle fails EPERM. Use a writable handle
  // to make the deliberately created marker durable before starting the race.
  const markerFd = fs.openSync(fixture.coordinator, "r+");
  try { fs.fsyncSync(markerFd); } finally { fs.closeSync(markerFd); }

  // Counterexample: an evidence read followed by a WAL-consistent pre-image
  // before the pre-marker writer commits observes an empty sidecar. This is
  // precisely what restore must never mistake for complete live evidence.
  const unfencedReader = new Database(heldPath,
    { readonly: true, fileMustExist: true });
  try {
    assert.equal(unfencedReader.prepare(query).get().n, 0,
      "the held write is invisible to the restore snapshot");
    const prematurePreimage = path.join(fixture.root, `premature-${kind}.sqlite`);
    await unfencedReader.backup(prematurePreimage);
    const before = new Database(prematurePreimage, { readonly: true });
    try {
      assert.equal(before.prepare(query).get().n, 0,
        "unguarded preimage misses the pre-marker audit");
    } finally { before.close(); }
  } finally { unfencedReader.close(); }

  let drained = false;
  const draining = strictAudit.drainAuditWriters(fixture.primaryPath).then(() => {
    drained = true;
  });
  await delay(150);
  assert.equal(drained, false,
    "restore must not pass the fence while a pre-marker sidecar transaction is open");
  child.send({ type: "commit" });
  await expect("committed");
  await draining;
  assert.equal(drained, true);
  const current = new Database(heldPath, { readonly: true });
  try {
    assert.equal(current.prepare(query).get().n, 1);
    const safePreimage = path.join(fixture.root, `after-barrier-${kind}.sqlite`);
    await current.backup(safePreimage);
    const saved = new Database(safePreimage, { readonly: true });
    try {
      assert.equal(saved.prepare(query).get().n, 1,
      "post-barrier preimage contains every committed pre-marker audit");
    } finally { saved.close(); }
  } finally { current.close(); }
});
