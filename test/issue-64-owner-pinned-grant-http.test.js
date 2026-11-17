"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { fixture, verify } = require("../scripts/issue-64-owner-pinned-grant-fixture");

test("Node HTTP fixture emits genuine signed grant/head and rejects changed fields", async () => {
  execFileSync(process.execPath, ["scripts/issue-64-owner-pinned-grant-fixture.js"], {
    cwd: path.join(__dirname, ".."), stdio: "pipe",
  });
  const f = fixture();
  const crypto = require("node:crypto");
  const pub = crypto.createPublicKey({ key: Buffer.from(f.anchor.ownerPublicSpki, "base64url"),
    format: "der", type: "spki" });
  assert.equal(verify(pub, "cek-read", f.grant), true);
  assert.equal(verify(pub, "owner-head", f.head), true);
  assert.equal(verify(pub, "owner-head", f.revoked), true);
  assert.equal(verify(pub, "cek-read", f.revokedGrant), true);
  assert.equal(verify(pub, "cek-read", { ...f.grant, keyEpoch: "epoch-3" }), false);
  const source = fs.readFileSync(path.join(__dirname,
    "../android/core/src/main/kotlin/dev/rootark/core/sync/OwnerPinnedOfflineAdmission.kt"), "utf8");
  assert.match(source, /Signature\.getInstance\("Ed25519"\)/);
  assert.match(source, /revokedDeviceIds/);
  assert.match(source, /OwnerOfflineFloorStore/);
  const importer = fs.readFileSync(path.join(__dirname,
    "../android/app/src/main/java/dev/rootark/android/OwnerPinnedOfflineImport.kt"), "utf8");
  const hardware = fs.readFileSync(path.join(__dirname,
    "../android/app/src/main/java/dev/rootark/android/OwnerOfflineHardwareFloor.kt"), "utf8");
  assert.match(importer, /StrictRfc8259Json\.validate/);
  assert.match(importer, /withAuthorizedCek/);
  assert.match(hardware, /AndroidKeyStore/);
  assert.match(hardware, /isInsideSecureHardware/);
  assert.match(hardware, /setUserAuthenticationRequired\(true\)/);
  const saved = JSON.parse(fs.readFileSync(path.join(__dirname,
    "../android/core/src/test/resources/owner-pinned-grant.json"), "utf8"));
  assert.ok(!Object.hasOwn(saved, "cek") && !Object.hasOwn(saved, "ownerPrivateKey"));
  assert.equal(saved.head.schema, "rootark-android-owner-head/v1");
});
