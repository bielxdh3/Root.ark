"use strict";

// Adversarial real-HTTP cases; UNRUN until exclusive Node22 gate opens.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "webdav-rollback-exact-inode-ownership-test";
const FOREIGN = "FOREIGN_REPLACEMENT_MUST_SURVIVE";

async function setup(t) {
  const dir = createPrivateAuthorityFixture("webdav-rollback-race-");
  const root = path.join(dir, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN, port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  return { root, bridge };
}

async function request(bridge, method, pathName, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: bridge.address().port,
      method, path: pathName,
      headers: { authorization: `Bearer ${TOKEN}`, ...headers },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode,
        body: Buffer.concat(chunks).toString() }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

test("MOVE rollback may not move a foreign directory or restore over its replacement", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await setup(t);
  const source = path.join(root, "source.txt");
  const destination = path.join(root, "destination.txt");
  const parked = path.join(root, "parked-original-move.txt");
  fs.writeFileSync(source, "MOVED_SOURCE", { mode: 0o600 });
  fs.writeFileSync(destination, "ORIGINAL_DESTINATION", { mode: 0o600 });
  let attacked = false;
  bridge.updateJournal = async (_id, patch) => {
    if (patch.phase !== "source-moved") return;
    attacked = true;
    fs.renameSync(destination, parked);
    fs.mkdirSync(destination, { mode: 0o700 });
    fs.writeFileSync(path.join(destination, "foreign.txt"), FOREIGN);
    throw new Error("injected post-MOVE journal interruption");
  };
  const response = await request(bridge, "MOVE", "/source.txt",
    { destination: "http://127.0.0.1/destination.txt" });
  assert.equal(attacked, true);
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(path.join(destination, "foreign.txt"), "utf8"), FOREIGN);
  assert.equal(fs.readFileSync(parked, "utf8"), "MOVED_SOURCE");
  assert.equal(fs.existsSync(source), false,
    "indeterminate rollback must not claim it restored source");
  const backups = fs.readdirSync(path.join(root, ".rootark-trash"))
    .filter((name) => name.startsWith(".rootark-move-"));
  assert.equal(backups.length, 1);
  assert.equal(fs.readFileSync(path.join(root, ".rootark-trash", backups[0]), "utf8"),
    "ORIGINAL_DESTINATION", "original overwritten item must survive in trash");
});

test("DELETE rollback cannot overwrite another actor's new file at original target", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await setup(t);
  const source = path.join(root, "source.txt");
  fs.writeFileSync(source, "ORIGINAL_DELETE", { mode: 0o600 });
  let attacked = false;
  bridge.updateJournal = async (_id, patch) => {
    if (patch.phase !== "source-moved") return;
    attacked = true;
    fs.writeFileSync(source, FOREIGN, { flag: "wx", mode: 0o600 });
    throw new Error("injected post-DELETE journal interruption");
  };
  const response = await request(bridge, "DELETE", "/source.txt");
  assert.equal(attacked, true);
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(source, "utf8"), FOREIGN);
  const trashed = fs.readdirSync(path.join(root, ".rootark-trash"));
  assert.equal(trashed.length, 1);
  assert.equal(fs.readFileSync(path.join(root, ".rootark-trash", trashed[0]), "utf8"),
    "ORIGINAL_DELETE");
});

test("ordinary failed MOVE and DELETE restore exact original files", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await setup(t);
  const source = path.join(root, "from.txt");
  const destination = path.join(root, "to.txt");
  fs.writeFileSync(source, "ORIGINAL_SOURCE");
  fs.writeFileSync(destination, "ORIGINAL_DESTINATION");
  bridge.updateJournal = async (_id, patch) => {
    if (patch.phase === "source-moved") throw new Error("injected durable journal error");
  };
  assert.equal((await request(bridge, "MOVE", "/from.txt",
    { destination: "http://127.0.0.1/to.txt" })).status, 500);
  assert.equal(fs.readFileSync(source, "utf8"), "ORIGINAL_SOURCE");
  assert.equal(fs.readFileSync(destination, "utf8"), "ORIGINAL_DESTINATION");
  assert.equal((await request(bridge, "DELETE", "/from.txt")).status, 500);
  assert.equal(fs.readFileSync(source, "utf8"), "ORIGINAL_SOURCE");
});
