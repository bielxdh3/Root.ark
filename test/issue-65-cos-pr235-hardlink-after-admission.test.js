"use strict";

// TEST_UNRUN pending exclusive Node22 gate. Real HTTP, filesystem hardlinks,
// and native lstat: this deliberately races the await between admission and
// physical mutation. No fs monkeypatch or fabricated inode witness.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-external-hardlink-race";
const ORIGINAL = "SINGLE_ADMITTED_ORIGINAL_INODE";

function request(bridge, method, target, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1", port: bridge.address().port, path: target, method,
      headers: { authorization: "Bearer " + TOKEN, ...headers },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.setTimeout(30000, () => req.destroy(Error("hardlink race HTTP timed out")));
    req.on("error", reject);
    req.end(data);
  });
}

for (const kind of ["PUT", "MOVE", "DELETE"]) {
  test("HTTP " + kind + " rejects a fresh foreign hardlink added during durable admission", {
    timeout: 90000,
  }, async (t) => {
    const parent = createPrivateAuthorityFixture("cos-pr235-race-links-");
    const root = path.join(parent, "root");
    fs.mkdirSync(root, { mode: 0o700 });
    const source = path.join(root, "original.txt");
    const alias = path.join(root, "independent-link.txt");
    const destination = path.join(root, "destination.txt");
    fs.writeFileSync(source, ORIGINAL, { mode: 0o600 });
    const original = fs.lstatSync(source, { bigint: true });
    assert.equal(original.nlink, 1n, "fixture starts with a genuine single-link original");

    let admissions = 0;
    const bridge = new LocalSyncWebDavBridge({
      rootDir: root, port: 0, token: TOKEN,
      onOperation: async (event) => {
        assert.equal(event.kind, kind.toLowerCase());
        admissions += 1;
        await fsp.link(source, alias);
        const after = await fsp.lstat(source, { bigint: true });
        assert.equal(after.ino, original.ino);
        assert.equal(after.nlink, 2n);
      },
    });
    t.after(async () => {
      await bridge.stop();
      await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
    });
    await bridge.start();
    let reply;
    if (kind === "PUT") {
      reply = await request(bridge, "PUT", "/original.txt", "NOT_ADMITTED_REPLACEMENT");
    } else if (kind === "MOVE") {
      reply = await request(bridge, "MOVE", "/original.txt", undefined, {
        destination: "http://127.0.0.1:" + bridge.address().port + "/destination.txt",
        overwrite: "F",
      });
    } else {
      reply = await request(bridge, "DELETE", "/original.txt");
    }
    assert.equal(admissions, 1, "the race must happen inside real admission");
    assert.equal(reply.status, 500, "hardlink substitution must be refused, never marked successful");
    assert.equal(await fsp.readFile(source, "utf8"), ORIGINAL);
    assert.equal(await fsp.readFile(alias, "utf8"), ORIGINAL);
    const sourceAfter = await fsp.lstat(source, { bigint: true });
    const aliasAfter = await fsp.lstat(alias, { bigint: true });
    assert.equal(sourceAfter.ino, original.ino);
    assert.equal(aliasAfter.ino, original.ino);
    assert.equal(sourceAfter.nlink, 2n);
    assert.equal(aliasAfter.nlink, 2n);
    assert.equal(fs.existsSync(destination), false);
    assert.deepEqual(await fsp.readdir(path.join(root, ".rootark-trash")), [],
      "failure must not stage or discard an unrelated hardlink");
  });
}
