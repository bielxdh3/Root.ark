"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const test = require("node:test");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const TOKEN = "disposable-put-temp-ownership-fixture";
const SENTINEL = "PREEXISTING_FOREIGN_TEMP_MUST_SURVIVE";

async function setup(t, onOperation) {
  const dir = createPrivateAuthorityFixture("rootark-put-temp-safe-");
  const root = path.join(dir, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN,
    port: 0, onOperation });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  return { root, bridge };
}

function put(port, name, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method: "PUT", path: `/${name}`,
      headers: { authorization: `Bearer ${TOKEN}` } }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode,
        body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.once("error", reject);
    req.end(body);
  });
}

test("PUT collision never truncates or deletes a preexisting random-name temporary", {
  timeout: 120000,
}, async (t) => {
  const originalRandomUUID = crypto.randomUUID;
  const collisionId = "dd07e8f4-f08f-48d0-9c45-6dd2173c9d3a";
  let sentinelPath;
  t.after(() => { crypto.randomUUID = originalRandomUUID; });
  const { root, bridge } = await setup(t, () => {
    sentinelPath = path.join(root, `.rootark-put-${process.pid}-${collisionId}`);
    fs.writeFileSync(sentinelPath, SENTINEL, { flag: "wx", mode: 0o600 });
    crypto.randomUUID = () => {
      crypto.randomUUID = originalRandomUUID;
      return collisionId;
    };
  });
  const response = await put(bridge.address().port, "target.txt", "NEW_UPLOAD_BYTES");
  assert.equal(response.status, 405, "EEXIST must fail closed, never overwrite sentinels");
  assert.equal(fs.readFileSync(sentinelPath, "utf8"), SENTINEL);
  assert.equal(fs.existsSync(path.join(root, "target.txt")), false);
});

test("PUT rollback never unlinks a different inode substituted at its temporary name", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await setup(t);
  const destination = path.join(root, "existing.txt");
  fs.writeFileSync(destination, "ORIGINAL_DESTINATION");
  const nativeLink = fsp.link;
  let sentinelPath;
  t.after(() => { fsp.link = nativeLink; });
  fsp.link = async (from, to) => {
    if (!sentinelPath && to === destination && path.basename(from).startsWith(".rootark-put-")) {
      sentinelPath = from;
      fs.renameSync(from, `${from}.owned`);
      fs.writeFileSync(from, SENTINEL, { flag: "wx", mode: 0o600 });
      throw Object.assign(new Error("injected exclusive publication failure"), { code: "EACCES" });
    }
    return nativeLink(from, to);
  };
  const response = await put(bridge.address().port, "existing.txt", "NEW_UPLOAD_BYTES");
  assert.equal(response.status, 500);
  assert.ok(sentinelPath, "adversarial swap must occur before failed exclusive publication");
  assert.equal(fs.readFileSync(sentinelPath, "utf8"), SENTINEL);
  assert.equal(fs.readFileSync(destination, "utf8"), "ORIGINAL_DESTINATION");
});

test("post-install rollback preserves foreign replacement DIRECTORY and original trash backup", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await setup(t);
  const destination = path.join(root, "existing.txt");
  const ownedInstalled = path.join(root, "installed-new-content-owned.txt");
  fs.writeFileSync(destination, "ORIGINAL_DESTINATION");
  let swapped = false;
  bridge.updateJournal = async (_operationId, patch) => {
    if (patch.phase !== "source-moved") return;
    assert.equal(swapped, false, "journal injection fires only once");
    swapped = true;
    // This happens AFTER successful exclusive publish, BEFORE its
    // durable journal ACK. The new target is an unrelated directory. A broad
    // fs.rm(target,{recursive:true}) would silently destroy its contents.
    fs.renameSync(destination, ownedInstalled);
    fs.mkdirSync(destination, { mode: 0o700 });
    fs.writeFileSync(path.join(destination, "foreign.txt"), SENTINEL);
    throw new Error("injected post-install journal failure");
  };
  const response = await put(bridge.address().port, "existing.txt", "NEW_UPLOAD_BYTES");
  assert.equal(swapped, true, "a real installed file was replaced in the rollback window");
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(path.join(destination, "foreign.txt"), "utf8"), SENTINEL,
    "rollback must not recursively delete a substituted foreign directory");
  assert.equal(fs.readFileSync(ownedInstalled, "utf8"), "NEW_UPLOAD_BYTES");
  const backups = fs.readdirSync(path.join(root, ".rootark-trash"))
    .filter((name) => name.startsWith(".rootark-put-"));
  assert.equal(backups.length, 1,
    "a failed unsafe rollback must preserve the ORIGINAL target in the durable trash");
  assert.equal(fs.readFileSync(path.join(root, ".rootark-trash", backups[0]), "utf8"),
    "ORIGINAL_DESTINATION");
});

test("post-install journal failure without replacement restores the original exact target", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge } = await setup(t);
  const destination = path.join(root, "existing.txt");
  fs.writeFileSync(destination, "ORIGINAL_DESTINATION");
  let failed = false;
  bridge.updateJournal = async (_operationId, patch) => {
    if (patch.phase === "source-moved") {
      failed = true;
      throw new Error("injected post-install journal failure");
    }
  };
  const response = await put(bridge.address().port, "existing.txt", "NEW_UPLOAD_BYTES");
  assert.equal(failed, true);
  assert.equal(response.status, 500);
  assert.equal(fs.readFileSync(destination, "utf8"), "ORIGINAL_DESTINATION",
    "verified installed inode may be unlinked, permitting safe backup restoration");
  assert.deepEqual(fs.readdirSync(path.join(root, ".rootark-trash")), [],
    "successful rollback must not leave a stale backup in trash");
});
