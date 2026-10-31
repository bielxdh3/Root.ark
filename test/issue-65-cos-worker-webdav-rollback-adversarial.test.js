"use strict";

// Genuine loopback HTTP mutation tests. Leave TEST_UNRUN until the exclusive
// Node22 gate opens (zero competing Node processes, >=4096 MiB RAM, owner).
// Every attack occurs after the real WebDAV rename and before its journal ACK.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-worker-215-local-webdav-race-only";
const FOREIGN = "FOREIGN_ACTOR_BYTES_NOT_OWNED_BY_WEBDAV";
const ORIGINAL = "ORIGINAL_DURABLE_BYTES";
const INSTALLED = "NEW_INSTALLED_HTTP_BYTES";

async function fixture(t) {
  const parent = createPrivateAuthorityFixture("cos-w215-webdav-rollback-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN, port: 0 });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  return { root, bridge };
}

function request(bridge, method, pathname, { headers = {}, data } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1", port: bridge.address().port, method, path: pathname,
      headers: { authorization: `Bearer ${TOKEN}`, ...headers },
    }, (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode, body: Buffer.concat(parts).toString("utf8"),
      }));
    });
    req.on("error", reject);
    req.end(data);
  });
}

function attackAfterInstall(bridge, attack) {
  let count = 0;
  bridge.updateJournal = async (_operationId, patch) => {
    if (patch.phase !== "source-moved") return;
    count++;
    assert.equal(count, 1, "attack must occur once after actual HTTP rename");
    attack();
    throw new Error("controlled durable journal ACK failure after attack");
  };
  return () => assert.equal(count, 1, "HTTP route must reach the real mutation");
}

function writeForeign(filename) {
  fs.writeFileSync(filename, FOREIGN, { flag: "wx", mode: 0o600 });
}

function exactTrash(root, prefix) {
  const dir = path.join(root, ".rootark-trash");
  const names = fs.readdirSync(dir).filter((name) => name.startsWith(prefix));
  assert.equal(names.length, 1, "exactly one durable original backup expected");
  return path.join(dir, names[0]);
}

test("HTTP PUT overwrite: foreign replacement FILE is not unlinked or overwritten by rollback", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await fixture(t);
  const target = path.join(root, "overwrite.txt");
  const parked = path.join(root, "parked-installed.txt");
  fs.writeFileSync(target, ORIGINAL, { mode: 0o600 });
  const attacked = attackAfterInstall(bridge, () => {
    fs.renameSync(target, parked);
    writeForeign(target);
  });
  const response = await request(bridge, "PUT", "/overwrite.txt", { data: INSTALLED });
  attacked();
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(target, "utf8"), FOREIGN);
  assert.equal(fs.readFileSync(parked, "utf8"), INSTALLED);
  assert.equal(fs.readFileSync(exactTrash(root, ".rootark-put-"), "utf8"), ORIGINAL,
    "original destination must remain recoverable when a foreign file takes its name");
});

test("HTTP PUT create: foreign replacement DIRECTORY survives failed post-install rollback", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await fixture(t);
  const target = path.join(root, "new-item.txt");
  const parked = path.join(root, "parked-new-upload.txt");
  const attacked = attackAfterInstall(bridge, () => {
    fs.renameSync(target, parked);
    fs.mkdirSync(target, { mode: 0o700 });
    writeForeign(path.join(target, "child.txt"));
  });
  const response = await request(bridge, "PUT", "/new-item.txt", { data: INSTALLED });
  attacked();
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(path.join(target, "child.txt"), "utf8"), FOREIGN);
  assert.equal(fs.readFileSync(parked, "utf8"), INSTALLED);
  assert.deepEqual(fs.readdirSync(path.join(root, ".rootark-trash")), [],
    "new PUT must not manufacture an unrelated backup");
});

test("HTTP MOVE overwrite: foreign source reoccupation never gets replaced by rollback", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await fixture(t);
  const source = path.join(root, "source.txt");
  const destination = path.join(root, "destination.txt");
  fs.writeFileSync(source, INSTALLED, { mode: 0o600 });
  fs.writeFileSync(destination, ORIGINAL, { mode: 0o600 });
  const attacked = attackAfterInstall(bridge, () => writeForeign(source));
  const response = await request(bridge, "MOVE", "/source.txt", {
    headers: { destination: "http://127.0.0.1/destination.txt" },
  });
  attacked();
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(source, "utf8"), FOREIGN);
  assert.equal(fs.readFileSync(destination, "utf8"), INSTALLED,
    "rollback cannot move the installed inode over a foreign source");
  assert.equal(fs.readFileSync(exactTrash(root, ".rootark-move-"), "utf8"), ORIGINAL);
});

test("HTTP MOVE overwrite: foreign destination FILE is preserved alongside staged original", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await fixture(t);
  const source = path.join(root, "source.txt");
  const destination = path.join(root, "destination.txt");
  const parked = path.join(root, "parked-move-source.txt");
  fs.writeFileSync(source, INSTALLED, { mode: 0o600 });
  fs.writeFileSync(destination, ORIGINAL, { mode: 0o600 });
  const attacked = attackAfterInstall(bridge, () => {
    fs.renameSync(destination, parked);
    writeForeign(destination);
  });
  const response = await request(bridge, "MOVE", "/source.txt", {
    headers: { destination: "http://127.0.0.1/destination.txt" },
  });
  attacked();
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(destination, "utf8"), FOREIGN);
  assert.equal(fs.readFileSync(parked, "utf8"), INSTALLED);
  assert.equal(fs.existsSync(source), false,
    "indeterminate operation must not falsely claim source was restored");
  assert.equal(fs.readFileSync(exactTrash(root, ".rootark-move-"), "utf8"), ORIGINAL);
});

test("HTTP MOVE overwrite: replaced trash backup cannot be used to restore destination", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await fixture(t);
  const source = path.join(root, "source.txt");
  const destination = path.join(root, "destination.txt");
  const parkedOriginal = path.join(root, "parked-original-destination.txt");
  fs.writeFileSync(source, INSTALLED, { mode: 0o600 });
  fs.writeFileSync(destination, ORIGINAL, { mode: 0o600 });
  let hostileBackup;
  const attacked = attackAfterInstall(bridge, () => {
    hostileBackup = exactTrash(root, ".rootark-move-");
    fs.renameSync(hostileBackup, parkedOriginal);
    writeForeign(hostileBackup);
  });
  const response = await request(bridge, "MOVE", "/source.txt", {
    headers: { destination: "http://127.0.0.1/destination.txt" },
  });
  attacked();
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(source, "utf8"), INSTALLED,
    "source can be returned while rejecting a foreign staged backup");
  assert.equal(fs.existsSync(destination), false,
    "a replaced backup must not be installed at destination");
  assert.equal(fs.readFileSync(hostileBackup, "utf8"), FOREIGN);
  assert.equal(fs.readFileSync(parkedOriginal, "utf8"), ORIGINAL);
});

test("HTTP DELETE: foreign occupied-target DIRECTORY survives, original remains in trash", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await fixture(t);
  const target = path.join(root, "deleted.txt");
  fs.writeFileSync(target, ORIGINAL, { mode: 0o600 });
  const attacked = attackAfterInstall(bridge, () => {
    fs.mkdirSync(target, { mode: 0o700 });
    writeForeign(path.join(target, "foreign-child.txt"));
  });
  const response = await request(bridge, "DELETE", "/deleted.txt");
  attacked();
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(path.join(target, "foreign-child.txt"), "utf8"), FOREIGN);
  const trash = fs.readdirSync(path.join(root, ".rootark-trash"));
  assert.equal(trash.length, 1);
  assert.equal(fs.readFileSync(path.join(root, ".rootark-trash", trash[0]), "utf8"), ORIGINAL);
});

test("HTTP DELETE: swapped trash inode is never restored as the deleted original", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await fixture(t);
  const target = path.join(root, "deleted.txt");
  const parkedOriginal = path.join(root, "parked-deleted-original.txt");
  fs.writeFileSync(target, ORIGINAL, { mode: 0o600 });
  let hostileTrash;
  const attacked = attackAfterInstall(bridge, () => {
    const names = fs.readdirSync(path.join(root, ".rootark-trash"));
    assert.equal(names.length, 1, "DELETE must first move the original to trash");
    hostileTrash = path.join(root, ".rootark-trash", names[0]);
    fs.renameSync(hostileTrash, parkedOriginal);
    writeForeign(hostileTrash);
  });
  const response = await request(bridge, "DELETE", "/deleted.txt");
  attacked();
  assert.equal(response.status, 500);
  assert.equal(fs.existsSync(target), false);
  assert.equal(fs.readFileSync(hostileTrash, "utf8"), FOREIGN);
  assert.equal(fs.readFileSync(parkedOriginal, "utf8"), ORIGINAL);
});
