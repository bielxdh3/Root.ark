const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const servicePath = path.resolve(__dirname, "../services/restoreProviderOrphans.js");

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
