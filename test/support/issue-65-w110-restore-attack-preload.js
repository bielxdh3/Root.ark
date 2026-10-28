"use strict";

// A deterministic timing hook around the REAL restore and real fs operations.
// No code in the verifier, provider adapter or cleanup path is mocked.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const originalMkdtemp = fs.mkdtempSync;
const originalRm = fs.rmSync;
let stage = null;
let victimSentinel = null;
let swapped = false;
let cleanupObserved = false;
const observation = { stageCreated: false, swapped: false,
  cleanupObserved: false, victimDeleted: false };
globalThis.__w110RestoreAttack = observation;

fs.mkdtempSync = function (prefix, ...args) {
  if (String(prefix).includes("zk1-cloud-recovery-")) {
    process.stdout.write(`W110_RESTORE_STAGE_MKDTEMP_ATTEMPT=${String(prefix).includes("zk65-w110-unsafe-")}\n`);
  }
  // Keep the unrelated signed SQLite authority on the legitimate trusted
  // root-owned sticky /tmp. Only restore staging inherits the hostile TMPDIR.
  if (String(prefix).includes("/zk65-full-restore-")) {
    return originalMkdtemp.call(fs, path.join("/tmp", path.basename(String(prefix))), ...args);
  }
  let result;
  try { result = originalMkdtemp.call(fs, prefix, ...args); }
  catch (error) {
    if (String(prefix).includes("zk1-cloud-recovery-")) process.stdout.write(`W110_MKDTEMP_ERROR=${error.code}\n`);
    throw error;
  }
  if (stage || !String(prefix).endsWith("/zk1-cloud-recovery-")) return result;
  observation.stageCreated = true;
  process.stdout.write("W110_STAGE_CREATED\n");
  const parent = path.dirname(result);
  const expected = os.tmpdir();
  const stat = fs.statSync(parent);
  const postCreateDrift = process.env.W110_ATTACK_DRIFT === "1";
  const expectedMode = postCreateDrift ? 0o700 : 0o777;
  if (parent !== expected || !path.basename(parent).startsWith("zk65-w110-unsafe-")
    || (stat.mode & 0o1777) !== expectedMode || typeof process.getuid !== "function"
    || process.getuid() !== 0) {
    process.stdout.write(`W110_ENV_MISMATCH_PARENT=${parent === expected} MODE=${(stat.mode & 0o1777).toString(8)} UID=${process.getuid()}\n`);
    throw Error("W110_PROBE_ENVIRONMENT_INVALID");
  }
  stage = result;
  const victim = path.join(parent, `w110-private-victim-${process.pid}`);
  fs.mkdirSync(victim, { mode: 0o700 });
  victimSentinel = path.join(victim, "protected-synthetic-sentinel");
  fs.writeFileSync(victimSentinel, "W110_SYNTHETIC_SENTINEL\n", { mode: 0o600 });
  process.stdout.write("W110_PRIVATE_VICTIM_CREATED\n");
  if (postCreateDrift) fs.chmodSync(parent, 0o777);
  const deniedRead = spawnSync("/usr/sbin/runuser", ["-u", "nobody", "--", "/usr/bin/test", "-r", victimSentinel], { timeout: 5000 });
  if (deniedRead.status === 0) throw Error("W110_OTHER_UID_CAN_ALREADY_READ_VICTIM");
  const mover = spawnSync("/usr/sbin/runuser", ["-u", "nobody", "--", process.execPath,
    path.join(__dirname, "issue-65-w110-foreign-uid-mover.js"), stage, victim],
  { timeout: 5000, encoding: "utf8", env: { ...process.env, NODE_OPTIONS: "" } });
  process.stdout.write(`W110_MOVER_EXIT=${mover.status} SIGNAL=${mover.signal || "NONE"} STDERR_BYTES=${mover.stderr?.length || 0}\n`);
  if (mover.status !== 0 || mover.stdout.trim() !== "FOREIGN_UID_RENAMED")
    throw Error(`W110_FOREIGN_UID_RENAME_FAILED_${mover.status}`);
  victimSentinel = path.join(stage, "protected-synthetic-sentinel");
  swapped = fs.existsSync(victimSentinel);
  observation.swapped = swapped;
  process.stdout.write(`W110_FOREIGN_UID_SWAP=${swapped}\n`);
  return result;
};

fs.rmSync = function (filename, ...args) {
  const target = filename === stage && swapped && !cleanupObserved;
  const before = target && fs.existsSync(victimSentinel);
  const result = originalRm.call(fs, filename, ...args);
  if (target) {
    cleanupObserved = true;
    const after = fs.existsSync(victimSentinel);
    observation.cleanupObserved = true;
    observation.victimDeleted = Boolean(before && !after);
    process.stdout.write(`W110_REAL_RESTORE_CLEANUP_VICTIM_BEFORE=${before} AFTER=${after}\n`);
  }
  return result;
};

process.on("exit", () => {
  process.stdout.write(`W110_RESULT_SWAP=${swapped} CLEANUP=${cleanupObserved}\n`);
});
