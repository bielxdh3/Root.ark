"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { isDependencyOrNetworkUnavailable } = require("./release-gate-environment");

const root = path.resolve(__dirname, "..");
const results = [];

function record(name, status, details) {
  results.push({ name, status, details });
  console.log(`${status}: ${name}${details ? ` — ${details}` : ""}`);
}

function command(name, executable, args, { blockedOnMissing = false, shell = false } = {}) {
  const result = spawnSync(executable, args, { cwd: root, encoding: "utf8", windowsHide: true, shell });
  const output = `${result.stdout || ""}\n${result.stderr || ""}\n${result.error?.message || ""}`.trim();
  if (result.status === 0) {
    record(name, "PASS", "exit 0");
    return true;
  }
  if (blockedOnMissing && (result.error?.code === "ENOENT" || isDependencyOrNetworkUnavailable(output))) {
    record(name, "BLOCKED", "dependency or network environment unavailable");
    return false;
  }
  record(name, "FAIL", `exit ${result.status ?? "unknown"}`);
  return false;
}

function checkLock() {
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const lock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
    const rootPackage = lock.packages[""];
    const brace = lock.packages["node_modules/brace-expansion"];
    assert.equal(lock.lockfileVersion, 3);
    assert.deepEqual(Object.keys(rootPackage.dependencies).sort(), Object.keys(manifest.dependencies).sort());
    assert.deepEqual(rootPackage.dependencies, manifest.dependencies);
    assert.equal(brace.version, "5.0.12");
    assert.equal(brace.resolved, "https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.12.tgz");
    assert.equal(brace.integrity, "sha512-YovQ3rzhaLMIrDjNDMkNS01tea93qhEhG5xy8f6+R0l+dw3Ki+5sCoIoI942iuLZTHWogWktgwVDhU09iNEimQ==");
    record("dependency lock/provenance", "PASS", `${Object.keys(lock.packages).length - 1} transitive package records; manifest parity preserved`);
  } catch (error) {
    record("dependency lock/provenance", "FAIL", error.message);
  }
}

function checkSecrets() {
  const files = spawnSync("git", ["ls-files", "-co", "--exclude-standard"], { cwd: root, encoding: "utf8" }).stdout
    .split(/\r?\n/).filter(Boolean);
  const patterns = [
    /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
    /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
    /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  ];
  const matches = [];
  for (const relative of files) {
    const absolute = path.join(root, relative);
    if (!fs.existsSync(absolute) || fs.statSync(absolute).size > 2 * 1024 * 1024) continue;
    const text = fs.readFileSync(absolute, "utf8");
    if (patterns.some((pattern) => pattern.test(text))) matches.push(relative.replace(/\\/g, "/"));
  }
  if (matches.length) record("secret-material pattern scan", "FAIL", `${matches.length} file(s) matched`);
  else record("secret-material pattern scan", "PASS", `${files.length} repository files scanned; no material pattern matches`);
}

function checkCiphertextOnlyEvidence() {
  try {
    const crypto = require("node:crypto");
    const { createOperation } = require(path.join(root, "sync-client/rootark-sync-protocol"));
    const resilience = require(path.join(root, "src/services/deploymentResilience"));
    const recordValue = createOperation({
      operation: "create", objectId: "gate-object", fileId: "gate-file", versionId: "gate-version",
      operationId: "gate-operation", revision: { counter: 1, deviceId: "gate-device" },
      keyEpoch: "gate-epoch", compartmentId: "gate-compartment", deviceId: "gate-device",
      metadata: { path: "release-gate.txt" },
      plaintext: "disposable release-gate fixture", fileKey: crypto.randomBytes(32),
    });
    assert.equal(resilience.attestCiphertextOnlyRecords([recordValue]).ok, true);
    assert.throws(() => resilience.attestCiphertextOnlyRecords([{ ...recordValue, plaintext: "leaked" }]));
    assert.throws(() => resilience.attestCiphertextOnlyRecords([{ ...recordValue, fileKey: "leaked" }]));
    record("ciphertext-only release evidence", "PASS", "positive attestation and plaintext/key rejection passed");
  } catch (error) {
    record("ciphertext-only release evidence", "FAIL", error.message);
  }
}

checkLock();
command("syntax gate", process.execPath, ["scripts/validate-syntax.js"]);
command("runtime artifact gate", process.execPath, ["scripts/validate-runtime-artifacts.js"]);
command("diff gate", "git", ["diff", "--check", "HEAD"]);
checkSecrets();
checkCiphertextOnlyEvidence();

for (const [name, files] of [
  ["Phase 9 crypto vectors", ["test/rootark-zk-1.test.js"]],
  ["Phase 10 auth/TOTP", ["test/totp-policy.test.js", "test/auth-totp-routes.test.js"]],
  ["Phase 12 sync/WebDAV", ["test/phase12-sync.test.js"]],
  ["Phase 13 client/groups", ["test/phase13-client-ux.test.js"]],
  ["Phase 16 bidirectional sync engine", ["test/phase16-sync-engine.test.js"]],
  ["Phase 16 opaque group sharing", ["test/phase16-group-sharing.test.js"]],
  ["Phase 16 final correction boundary", ["test/phase16-final-corrections.test.js"]],
  ["Realtime transport boundary", ["test/realtime-transport-boundaries.test.js"]],
  ["Upload security boundary", ["test/upload-security.test.js"]],
  ["Cloud inventory containment", ["test/cloud-storage.test.js"]],
  ["Phase 14 readiness/attestation", ["test/phase14-deployment-resilience.test.js"]],
  ["Phase 14 backup/restore evidence", ["test/backup-restore-security.test.js"]],
]) command(name, process.execPath, ["--test", ...files], { blockedOnMissing: true });

command("final-head canonical npm test", process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", "npm.cmd test"], { blockedOnMissing: true });

command("high-severity dependency audit", process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", "npm.cmd audit --package-lock-only --audit-level=high"], { blockedOnMissing: true });
const status = spawnSync("git", ["status", "--porcelain=v1"], { cwd: root, encoding: "utf8" }).stdout.trim();
if (status) record("clean worktree gate", "BLOCKED", "local changes remain; run after the required coherent commit");
else record("clean worktree gate", "PASS", "no tracked or untracked changes");

const passed = results.filter((result) => result.status === "PASS").length;
const blocked = results.filter((result) => result.status === "BLOCKED").length;
const failed = results.filter((result) => result.status === "FAIL").length;
console.log(`Release gate summary: ${passed} passed, ${blocked} blocked, ${failed} failed.`);
if (failed) process.exitCode = 1;
else if (blocked) process.exitCode = 2;
