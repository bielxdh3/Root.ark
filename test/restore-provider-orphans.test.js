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

test("restore provider state is read through an open descriptor rather than a checked path", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-state-race-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const policy = require(${JSON.stringify(servicePath)});
      fs.mkdirSync(path.dirname(policy.STATE_PATH), { recursive: true });
      const originalState = JSON.stringify({ version: 1, initializedAt: "before" });
      fs.writeFileSync(policy.STATE_PATH, originalState);
      fs.writeFileSync(policy.POLICY_PATH, JSON.stringify({ version: 1, objects: [] }));
      const originalReadFileSync = fs.readFileSync;
      let pathRead = false;
      let descriptorRead = false;
      fs.readFileSync = function (target, ...args) {
        if (typeof target === "string" && path.resolve(target) === path.resolve(policy.STATE_PATH)) {
          pathRead = true;
          fs.writeFileSync(policy.STATE_PATH, "invalid replacement state");
          try { return originalReadFileSync.call(fs, target, ...args); }
          finally { fs.writeFileSync(policy.STATE_PATH, originalState); }
        }
        if (typeof target === "number") descriptorRead = true;
        return originalReadFileSync.call(fs, target, ...args);
      };
      assert.doesNotThrow(() => policy.initialize());
      assert.equal(pathRead, false, "control state must not be read through a separately checked path");
      assert.equal(descriptorRead, true, "control state must be read from a descriptor that can be checked");
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

async function waitForFile(filePath, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(filePath) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 5));
  return fs.existsSync(filePath);
}

test("restore provider policy retries transient Windows sharing violations", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-rename-retry-"));
  try {
    const script = [
      'const assert = require("node:assert/strict");',
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'Object.defineProperty(process, "platform", { value: "win32" });',
      'const policy = require(' + JSON.stringify(servicePath) + ');',
      'const originalRenameSync = fs.renameSync;',
      'let failures = 0;',
      'fs.renameSync = function (source, destination) {',
      '  if (path.resolve(destination) === path.resolve(policy.POLICY_PATH) && failures === 0) {',
      '    failures += 1;',
      '    const error = new Error("sharing violation");',
      '    error.code = "EPERM";',
      '    throw error;',
      '  }',
      '  return originalRenameSync.call(this, source, destination);',
      '};',
      '(async () => {',
      '  await policy.write([{ area: "uploads", folderId: "root", name: "retry.txt" }]);',
      '  assert.equal(failures, 1);',
      '  assert.deepEqual(policy.read(), [{ area: "uploads", folderId: "root", name: "retry.txt" }]);',
      '})().catch((error) => { console.error(error); process.exitCode = 1; });',
    ].join("\n");
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("missing restore provider suppression policy fails closed in-process and after restart", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-missing-policy-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const policy = require(${JSON.stringify(servicePath)});
      (async () => {
        await policy.write([{ area: "uploads", folderId: "root", name: "stale-provider-object.txt" }]);
        fs.unlinkSync(policy.POLICY_PATH);
        assert.throws(() => policy.isSuppressed("root", "stale-provider-object.txt"), /policy.*missing|missing.*policy/i,
          "a missing policy cannot turn previously suppressed provider objects into visible files");
        process.stdout.write("running-process-blocked");
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(result.stdout, "running-process-blocked");

    const restartScript = `
      const policy = require(${JSON.stringify(servicePath)});
      try { policy.initialize(); }
      catch (error) {
        if (/policy.*missing|missing.*policy/i.test(error.message)) process.exit(0);
        console.error(error);
        process.exit(2);
      }
      console.error("restart accepted a missing policy");
      process.exit(1);
    `;
    const restarted = spawnSync(process.execPath, ["-e", restartScript], { cwd: runtime, encoding: "utf8" });
    assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("unknown restore inventory keeps disabled local storage available while guarding enabled providers", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-local-guard-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const policy = require(${JSON.stringify(servicePath)});
      const { createCloudStorage } = require(${JSON.stringify(path.resolve(__dirname, "../services/cloudStorage.js"))});
      (async () => {
        policy.initialize();
        await policy.markInventoryUnknown("123e4567-e89b-42d3-a456-426614174000");
        const local = policy.guardProvider(createCloudStorage({ provider: "local" }));
        assert.equal(local.enabled(), false);
        assert.deepEqual(await local.list("root"), []);
        assert.equal(await local.upload(path.join(process.cwd(), "missing-upload.txt"), "root", "local.txt"), null);
        const cloud = policy.guardProvider(createCloudStorage({ provider: "s3", s3: { bucket: "fixture" } }));
        await assert.rejects(cloud.list("root"), { code: "PROVIDER_INVENTORY_UNKNOWN" });
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("provider suppression initialization creates a fail-closed marker and preserves legacy policy", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-initialize-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const policy = require(${JSON.stringify(servicePath)});
      assert.throws(() => policy.initialize({ requirePolicy: true }), /missing after cloud restore/i,
        "a pending cloud restore cannot start without its committed policy");
      assert.deepEqual(policy.initialize(), [], "a new runtime starts with an explicit empty policy");
      assert.equal(fs.existsSync(policy.POLICY_PATH), true);
      assert.equal(fs.existsSync(policy.STATE_PATH), true);
      fs.writeFileSync(policy.POLICY_PATH, JSON.stringify({ version: 1, objects: [{ area: "uploads", folderId: "root", name: "legacy-orphan.txt" }] }));
      fs.unlinkSync(policy.STATE_PATH);
      assert.deepEqual(policy.initialize(), [{ area: "uploads", folderId: "root", name: "legacy-orphan.txt" }],
        "a legacy policy is upgraded without discarding its suppressions");
      assert.equal(fs.existsSync(policy.STATE_PATH), true);
      assert.equal(policy.isSuppressed("root", "legacy-orphan.txt"), true);
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("restore provider orphan identities preserve provider object case on every host", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const policy = require(${JSON.stringify(servicePath)});
      const normalized = policy.normalizeObjects([
        { area: "uploads", folderId: "RootFolder", name: "Case-Orphan.TXT" },
        { area: "uploads", folderId: "rootfolder", name: "case-orphan.txt" },
      ]);
      assert.equal(normalized.length, 2);
      (async () => {
        await policy.write([{ area: "uploads", folderId: "RootFolder", name: "Case-Orphan.TXT" }]);
        assert.equal(policy.isSuppressed("rootfolder", "case-orphan.txt", "uploads"), process.platform === "win32");
        assert.equal(policy.isSuppressed("RootFolder", "Case-Orphan.TXT", "temp"), false, "area remains part of the identity");
        assert.equal(await policy.clear("rootfolder", "case-orphan.txt", "uploads"), false);
        assert.equal(policy.read().length, 1, "clearing a case-distinct provider key cannot remove another object");
        assert.equal(await policy.clear("RootFolder", "Case-Orphan.TXT", "uploads", { inventory: async () => [
          { area: "uploads", folderId: "RootFolder", name: "Case-Orphan.TXT" },
        ] }), true);
        assert.equal(policy.read().length, 0);
        process.stdout.write(JSON.stringify({ ok: true, platform: process.platform, normalized: normalized.length }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("suppression checks reuse one policy snapshot and observe another process update", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-snapshot-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const { spawnSync } = require("node:child_process");
      const policy = require(${JSON.stringify(servicePath)});
      const policyPath = policy.POLICY_PATH;
      const statePath = policy.STATE_PATH;
      (async () => {
        await policy.write([{ area: "uploads", folderId: "folder", name: "before.txt" }]);
        const snapshot = policy.createSnapshot();
        const originalOpenSync = fs.openSync;
        const originalStatSync = fs.statSync;
        const originalLstatSync = fs.lstatSync;
        let reads = 0;
        let markerReads = 0;
        fs.openSync = function (target, ...args) {
          if (typeof target === "string" && require("node:path").resolve(target) === policyPath) reads += 1;
          if (typeof target === "string" && require("node:path").resolve(target) === statePath) markerReads += 1;
          return originalOpenSync.call(this, target, ...args);
        };
        fs.statSync = function (target, ...args) {
          if (typeof target === "string" && [policyPath, statePath].includes(require("node:path").resolve(target))) markerReads += 1;
          return originalStatSync.call(this, target, ...args);
        };
        fs.lstatSync = function (target, ...args) {
          if (typeof target === "string" && [policyPath, statePath].includes(require("node:path").resolve(target))) markerReads += 1;
          return originalLstatSync.call(this, target, ...args);
        };
        for (let index = 0; index < 100; index++) {
          assert.equal(policy.isSuppressed("folder", "missing-" + index + ".txt", "uploads", snapshot), false);
        }
        assert.equal(reads, 0, "bulk checks should reuse their captured policy snapshot");
        assert.equal(markerReads, 0, "bulk checks should not reread the marker or stat control files per entry");
        const updateScript = "const policy = require(" + JSON.stringify(${JSON.stringify(servicePath)}) + "); policy.write([{ area: 'uploads', folderId: 'folder', name: 'after.txt' }]).catch((error) => { console.error(error); process.exitCode = 1; });";
        const updated = spawnSync(process.execPath, ["-e", updateScript], { cwd: process.cwd(), encoding: "utf8" });
        assert.equal(updated.status, 0, updated.stderr || updated.stdout);
        assert.equal(policy.isSuppressed("folder", "before.txt"), false, "a replaced policy must invalidate the old snapshot");
        assert.equal(policy.isSuppressed("folder", "after.txt"), true, "the replacement policy must be observed");
        assert.equal(reads, 1, "one replacement policy parse should refresh the snapshot");
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("Windows provider aliases with different case remain independently suppressible and clearable", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-case-alias-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      Object.defineProperty(process, "platform", { value: "win32" });
      const policy = require(${JSON.stringify(servicePath)});
      (async () => {
        await policy.write([
          { area: "uploads", folderId: "folder", name: "Alias.txt" },
          { area: "uploads", folderId: "folder", name: "alias.txt" },
        ]);
        assert.equal(policy.read().length, 2, "provider aliases differing by case are separate objects");
        assert.equal(policy.isSuppressed("folder", "Alias.txt"), true);
        assert.equal(policy.isSuppressed("folder", "alias.txt"), true);
        assert.equal(await policy.clear("folder", "Alias.txt", "uploads", { inventory: async () => [
          { area: "uploads", folderId: "folder", name: "Alias.txt" },
        ] }), true);
        assert.deepEqual(policy.read(), [{ area: "uploads", folderId: "folder", name: "alias.txt" }], "exact clear retains the unselected case-distinct provider object");
        assert.equal(policy.isSuppressed("folder", "Alias.txt"), true, "both local spellings remain fail-closed while the Windows alias is suppressed");
        assert.equal(policy.isSuppressed("folder", "alias.txt"), true, "clearing the selected alias must retain the unselected alias");
        assert.equal(await policy.clear("folder", "alias.txt", "uploads", { inventory: async () => [
          { area: "uploads", folderId: "folder", name: "alias.txt" },
        ] }), true);
        assert.equal(policy.isSuppressed("folder", "Alias.txt"), false);
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("Windows case-fold aliases keep restored objects suppressed until inventory is unambiguous", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-case-fold-access-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      Object.defineProperty(process, "platform", { value: "win32" });
      const policy = require(${JSON.stringify(servicePath)});
      (async () => {
        await policy.write([{ area: "uploads", folderId: "root", name: "Case-Orphan.TXT" }]);
        assert.equal(policy.isSuppressed("root", "case-orphan.txt"), true, "Windows local path aliases cannot expose suppressed provider bytes");
        const aliases = [
          { area: "uploads", folderId: "root", name: "Case-Orphan.TXT" },
          { area: "uploads", folderId: "root", name: "case-orphan.txt" },
        ];
        assert.throws(() => policy.assertUnambiguousProviderInventory(aliases), /case-colliding.*restore is blocked/i);
        await assert.rejects(policy.clear("root", "Case-Orphan.TXT", "uploads", { inventory: async () => aliases }), { code: "configuration" });
        assert.equal(policy.isSuppressed("root", "Case-Orphan.TXT"), true, "an alias conflict keeps the selected file suppressed");
        assert.equal(policy.isSuppressed("root", "case-orphan.txt"), true, "an alias conflict keeps the remote alias suppressed");
        assert.equal(await policy.clear("root", "Case-Orphan.TXT", "uploads", { inventory: async () => [aliases[0]] }), true);
        assert.equal(policy.isSuppressed("root", "Case-Orphan.TXT"), false, "an unambiguous provider inventory permits unhide");
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
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
    const originalOpenSync = fs.openSync;
    const originalCloseSync = fs.closeSync;
    const policyDescriptors = new Set();
    let gated = false;
    fs.openSync = function (target, ...args) {
      const descriptor = originalOpenSync.call(this, target, ...args);
      if (typeof target === "string" && path.resolve(target) === policyPath) policyDescriptors.add(descriptor);
      return descriptor;
    };
    fs.closeSync = function (descriptor, ...args) {
      const result = originalCloseSync.call(this, descriptor, ...args);
      if (!gated && policyDescriptors.delete(descriptor)) {
        gated = true;
        fs.writeFileSync(process.env.READY_FILE, "ready");
        const deadline = Date.now() + 10000;
        while (!fs.existsSync(process.env.RELEASE_FILE) && Date.now() < deadline) {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
        }
        if (!fs.existsSync(process.env.RELEASE_FILE)) throw new Error("test gate timed out");
      }
      policyDescriptors.delete(descriptor);
      return result;
    };
    const fileName = id === "a" ? "first.txt" : "second.txt";
    (async () => {
      if (!await policy.clear("folder", fileName, "uploads", { inventory: async () => [{ area: "uploads", folderId: "folder", name: fileName }] })) throw new Error("expected suppression entry to be cleared");
    })().catch((error) => { console.error(error); process.exitCode = 1; });
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

test("waiting for the provider-orphan policy lock lets the event loop release it", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-yield-"));
  try {
    const backupRepositoryPath = path.resolve(__dirname, "../repositories/backupRepository.js");
    const script = `
      const assert = require("node:assert/strict");
      const policy = require(${JSON.stringify(servicePath)});
      const backupRepository = require(${JSON.stringify(backupRepositoryPath)});
      (async () => {
        const holder = backupRepository.acquireJsonMutationLock("test-policy-holder");
        let releasedByTimer = false;
        setTimeout(() => { releasedByTimer = true; holder.release(); }, 30);
        await policy.write([{ area: "uploads", folderId: "folder", name: "timer.txt" }]);
        assert.equal(releasedByTimer, true, "policy acquisition must yield so the timer can release the held lock");
        assert.equal(policy.isSuppressed("folder", "timer.txt"), true);
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8", timeout: 1500 });
    assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("suppress restores a cleared orphan identity idempotently under the policy lock", async () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-provider-orphans-suppress-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const policy = require(${JSON.stringify(servicePath)});
      (async () => {
        await policy.write([]);
        await policy.suppress("folder", "replacement.txt", "temp");
        await policy.suppress("folder", "replacement.txt", "temp");
        assert.equal(policy.isSuppressed("folder", "replacement.txt", "temp"), true);
        assert.deepEqual(policy.read(), [{ area: "temp", folderId: "folder", name: "replacement.txt" }]);
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});
