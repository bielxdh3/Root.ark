"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const { once } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const test = require("node:test");

// Native Linux attack fixture: genuine OTHER UID retains a writable FD after
// chmod 0644. The legacy stream is explicitly NOT an integrity guarantee;
// the opted-in bounded copy MUST send only pre-verified detached bytes.
const resilience = require.resolve("../src/services/deploymentResilience");
require.cache[resilience] = { id: resilience, filename: resilience,
  loaded: true, exports: { normalizeProviderError: (error) => error } };
const { createCloudStorage } = require("../services/cloudStorage");
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

test("real other-UID retained-FD A-B-A corrupts legacy stream but not authenticated bounded Drive copy", async (t) => {
  if (process.platform !== "linux" || typeof process.getuid !== "function"
    || process.getuid() !== 0) {
    return t.skip("requires native Linux root and runuser -u nobody");
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-verified-other-uid-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.chmodSync(directory, 0o755);
  const source = path.join(directory, "ciphertext.ct");
  const original = Buffer.from("AAAA-verified-ciphertext");
  const injected = Buffer.from("BBBB-tampered-ciphertext");
  assert.equal(original.length, injected.length);
  fs.writeFileSync(source, original, { flag: "wx", mode: 0o666 });
  fs.chmodSync(source, 0o666);
  const inode = fs.statSync(source).ino;
  const child = spawn("runuser", ["-u", "nobody", "--", process.execPath, "-e", `
    const fs = require("node:fs");
    const fd = fs.openSync(process.argv[1], "r+");
    process.stdout.write("ready\\n");
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (input) => {
      for (const name of input.trim().split(/\\s+/)) {
        const data = name === "mutate" ? "BBBB-tampered-ciphertext" : "AAAA-verified-ciphertext";
        fs.writeSync(fd, Buffer.from(data), 0, data.length, 0);
        fs.fsyncSync(fd);
        process.stdout.write(name + "\\n");
      }
    });
  `, source], { stdio: ["pipe", "pipe", "pipe"] });
  t.after(() => { child.kill(); });
  const lines = readline.createInterface({ input: child.stdout });
  let timeout;
  const ready = await Promise.race([
    once(lines, "line").then(([line]) => line),
    new Promise((_, reject) => {
      timeout = setTimeout(() => reject(Error("unprivileged writer startup timed out")), 6000);
    }),
  ]).finally(() => clearTimeout(timeout));
  assert.equal(ready, "ready");
  fs.chmodSync(source, 0o644);
  const command = async (name) => {
    const response = once(lines, "line");
    child.stdin.write(name + "\n");
    assert.equal((await response)[0], name);
  };
  const remote = [];
  const driver = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "root" },
    createGoogleDriveClient: async () => ({ files: {
      list: async () => ({ data: { files: [] } }),
      get: async () => { throw Object.assign(new Error("missing"), { status: 404 }); },
      create: async ({ media, requestBody }) => {
        await command("mutate"); // legacy reads live FD; bounded SDK sees captured bytes
        remote.push(Buffer.concat(await Array.fromAsync(media.body)));
        await command("restore");
        return { data: { id: requestBody.id || "legacy" } };
      },
    } }) });

  const legacy = await driver.upload(source, "folder", "ciphertext.ct");
  assert.equal(legacy.id, "legacy");
  assert.deepEqual(remote[0], injected, "historical legacy streaming remains mutable and NOT verified");
  assert.deepEqual(fs.readFileSync(source), original);

  const verified = await driver.upload(source, "folder", "ciphertext.ct", "uploads", {
    providerFileId: "pinned", zk1BoundedBytes: original.length,
    zk1ExpectedSha256: sha(original),
  });
  assert.equal(verified.id, "pinned");
  assert.deepEqual(remote[1], original, "SDK only gets authenticated detached ciphertext");
  assert.deepEqual(fs.readFileSync(source), original);
  assert.equal(fs.statSync(source).ino, inode, "same inode was retained throughout");

  await command("mutate");
  await assert.rejects(driver.upload(source, "folder", "ciphertext.ct", "uploads", {
    providerFileId: "pinned", zk1BoundedBytes: original.length,
    zk1ExpectedSha256: sha(original),
  }), { code: "configuration" });
  assert.equal(remote.length, 2, "independent digest mismatch denies BEFORE a provider write");
  await command("restore");
  assert.deepEqual(fs.readFileSync(source), original);
});
