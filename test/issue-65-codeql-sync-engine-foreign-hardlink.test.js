"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");

test("ZK sync v2 refuses hardlink aliases of files outside its selected root before outbound upload", async (t) => {
  const fixture = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-v2-foreign-hardlink-"));
  t.after(() => fs.rm(fixture, { recursive: true, force: true }));
  const root = path.join(fixture, "selected");
  const secret = path.join(fixture, "outside-secret.txt");
  const alias = path.join(root, "inside-alias.txt");
  await fs.mkdir(root);
  await fs.writeFile(secret, "FOREIGN_SOURCE_MUST_NOT_BE_SYNCHRONIZED");
  await fs.link(secret, alias);
  assert.equal((await fs.lstat(alias)).nlink, 2, "the test must use a real filesystem hardlink");

  const outgoing = [];
  const engine = await new SyncEngine({
    rootDir: root,
    adapter: {
      async push(operation) { outgoing.push(operation); return { status: 201 }; },
      async list() { return []; },
    },
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => crypto.createHash("sha256").update("fixture-only-key").digest(),
  }).open();

  await assert.rejects(engine.syncOnce(), (error) => error.code === "unsafe_path",
    "an external source alias must refuse a scan before any ciphertext could leave the host");
  assert.equal(outgoing.length, 0, "external file contents must not be exported to remote storage");
});
