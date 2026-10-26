"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { Zk1WitnessCasAnchorFloor } =
  require("../src/services/zk1WitnessCasAnchorFloor");

function newFloor(filename) {
  const witness = crypto.generateKeyPairSync("ed25519");
  const status = crypto.generateKeyPairSync("ed25519");
  return new Zk1WitnessCasAnchorFloor(filename, {
    bootstrapNew: true,
    witnessKeyId: crypto.randomBytes(16),
    witnessPrivateKey: witness.privateKey,
    statusKeyId: crypto.randomBytes(16),
    statusPublicKey: status.publicKey,
  });
}

test("Windows witness floor refuses an untrusted principal's Modify right before bootstrap", (t) => {
  if (process.platform !== "win32") return t.skip("Physical NTFS DACL required");
  const dir = createPrivateAuthorityFixture("rootark-w29-floor-acl-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const db = path.join(dir, "floor.sqlite");
  const icacls = spawnSync("C:\\Windows\\System32\\icacls.exe",
    [dir, "/grant", "*S-1-5-32-545:(OI)(CI)(M)"], { encoding: "utf8", windowsHide: true });
  assert.equal(icacls.status, 0, "test must install an actual untrusted Users DACL ACE");

  let floor;
  let error;
  try { floor = newFloor(db); }
  catch (caught) { error = caught; }
  finally { floor?.close(); }
  assert.equal(error?.code, "WITNESS_CAS_FLOOR_DENIED");
  assert.equal(fs.existsSync(db), false,
    "unauthorized storage authority must fail before SQLite creates files");
});

test("Windows witness floor still bootstraps under a private operator DACL", (t) => {
  if (process.platform !== "win32") return t.skip("Physical NTFS DACL required");
  const dir = createPrivateAuthorityFixture("rootark-w29-floor-positive-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const db = path.join(dir, "floor.sqlite");
  const floor = newFloor(db);
  try { assert.equal(floor.head().sequence, 0); }
  finally { floor.close(); }
});
