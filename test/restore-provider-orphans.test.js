const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");

const servicePath = path.resolve(__dirname, "../services/restoreProviderOrphans.js");

function startChild(script, cwd, env) {
  const child = spawn(process.execPath, ["-e", script], { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  const result = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`child exited ${code}: ${stderr || stdout}`)));
  });
  return { child, result };
}

async function waitForFile(filePath, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(filePath) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 5));
  return fs.existsSync(filePath);
}

test("restore provider orphan identities follow host path case rules for areas, folders, and names", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const policy = require(${JSON.stringify(servicePath)});
      const windows = process.platform === "win32";
      const normalized = policy.normalizeObjects([
        { area: "uploads", folderId: "RootFolder", name: "Case-Orphan.TXT" },
        { area: "uploads", folderId: "rootfolder", name: "case-orphan.txt" },
      ]);
      assert.equal(normalized.length, windows ? 1 : 2);
      policy.write([{ area: "uploads", folderId: "RootFolder", name: "Case-Orphan.TXT" }]);
      assert.equal(policy.isSuppressed("rootfolder", "case-orphan.txt", "uploads"), windows);
      assert.equal(policy.isSuppressed("RootFolder", "Case-Orphan.TXT", "temp"), false, "area remains part of the identity");
      if (windows) {
        assert.equal(policy.clear("rootfolder", "case-orphan.txt", "uploads"), true);
        assert.equal(policy.read().length, 0, "clear uses the same case-insensitive path identity");
      } else {
        assert.equal(policy.clear("rootfolder", "case-orphan.txt", "uploads"), false);
        assert.equal(policy.read().length, 1, "Linux keeps path identity case-sensitive");
      }
      process.stdout.write(JSON.stringify({ ok: true, platform: process.platform, normalized: normalized.length }));
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("separate processes clearing different restore orphans do not lose either update", async (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-race-"));
  t.after(() => fs.rmSync(runtime, { recursive: true, force: true }));
  const policyPath = path.join(runtime, "data", ".rootark-restore-provider-orphans.json");
  const gateDirectory = path.join(runtime, "gates");
  fs.mkdirSync(gateDirectory, { recursive: true });
  const readyA = path.join(gateDirectory, "a-read");
  const readyB = path.join(gateDirectory, "b-read");
  const releaseA = path.join(gateDirectory, "a-release");
  const releaseB = path.join(gateDirectory, "b-release");
  const script = `
    const fs = require("node:fs");
    const path = require("node:path");
    const policy = require(${JSON.stringify(servicePath)});
    const policyPath = path.resolve(${JSON.stringify(policyPath)});
    const id = process.env.CHILD_ID;
    const originalReadFileSync = fs.readFileSync;
    let gated = false;
    fs.readFileSync = function (target, ...args) {
      const value = originalReadFileSync.call(this, target, ...args);
      if (!gated && path.resolve(String(target)) === policyPath) {
        gated = true;
        fs.writeFileSync(process.env.READY_FILE, "ready");
        const deadline = Date.now() + 10000;
        while (!fs.existsSync(process.env.RELEASE_FILE) && Date.now() < deadline) {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
        }
        if (!fs.existsSync(process.env.RELEASE_FILE)) throw new Error("test gate timed out");
      }
      return value;
    };
    const fileName = id === "a" ? "first.txt" : "second.txt";
    if (!policy.clear("folder", fileName)) throw new Error("expected suppression entry to be cleared");
  `;
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify({ version: 1, objects: [
    { area: "uploads", folderId: "folder", name: "first.txt" },
    { area: "uploads", folderId: "folder", name: "second.txt" },
  ] })}\n`);
  const first = startChild(script, runtime, { CHILD_ID: "a", READY_FILE: readyA, RELEASE_FILE: releaseA });
  let second;
  try {
    assert.equal(await waitForFile(readyA), true, "first process reached the policy read");
    second = startChild(script, runtime, { CHILD_ID: "b", READY_FILE: readyB, RELEASE_FILE: releaseB });

    if (!fs.existsSync(path.join(runtime, "data", ".backup-metadata.lock"))) {
      assert.equal(await waitForFile(readyB), true, "unserialized second process reaches the same policy snapshot");
      // Without serialization both processes read the same snapshot. Commit B first and
      // A last to prove that A's stale replacement loses B's distinct clear.
      fs.writeFileSync(releaseB, "release");
      await second.result;
      fs.writeFileSync(releaseA, "release");
    } else {
      // A serialized implementation keeps B outside the read-modify-write section.
      fs.writeFileSync(releaseA, "release");
      await first.result;
      assert.equal(await waitForFile(readyB), true, "second process reads only after the first commit");
      fs.writeFileSync(releaseB, "release");
    }
    await Promise.all([first.result, second.result]);
    assert.deepEqual(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects, [], "both independent removals must persist");
  } finally {
    fs.writeFileSync(releaseA, "release");
    fs.writeFileSync(releaseB, "release");
    for (const processRef of [first.child, second?.child]) {
      if (processRef && processRef.exitCode === null) processRef.kill();
    }
  }
});
