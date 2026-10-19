"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const keyring = require("../src/crypto/rootark-zk-keyring");

test("v1 keyring keeps its rootKey and exported manifest shape unchanged", async () => {
  const ring = await keyring.createAccountKeyring();
  const manifest = keyring.exportManifest(ring);

  assert.ok(Buffer.isBuffer(ring.rootKey));
  assert.equal(ring.rootKey.length, 32);
  assert.equal(manifest.version, 1);
  assert.deepEqual(Object.keys(manifest).sort(), [
    "account_id", "current_epoch", "devices", "epochs", "mac", "suite", "type", "version", "wraps",
  ]);
  assert.equal(JSON.stringify(manifest).includes(ring.rootKey.toString("base64url")), false);
});
