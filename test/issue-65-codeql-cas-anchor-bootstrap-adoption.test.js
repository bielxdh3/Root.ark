"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");

function hash(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

test("CAS anchor bootstrap may not adopt a preexisting signed foreign anchor via single-link rename", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cas-anchor-bootstrap-"));
  if (process.platform !== "win32") fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const signedOld = path.join(root, "signed-old-anchor.log");
  const target = path.join(root, "fresh-bootstrap-anchor.log");
  const identity = { statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey };
  const created = new Zk1CasTerminalAnchor(signedOld, { ...identity, bootstrapNew: true });
  const reservation = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("unrelated-authority"), keyring_id: crypto.randomBytes(16),
    reservation_id: crypto.randomBytes(16) };
  const ticket = crypto.randomBytes(64);
  const manifest = crypto.randomBytes(80);
  created.prepare(reservation, ticket, "committed", manifest);
  await created.append(reservation, ticket, "committed", manifest, crypto.randomBytes(64));
  assert.equal(created.sequence, 1, "foreign anchor is a genuine signed, nonempty terminal history");
  const originalHash = hash(signedOld);

  fs.renameSync(signedOld, target);
  assert.equal(fs.statSync(target).nlink, 1);
  assert.throws(() => new Zk1CasTerminalAnchor(target, {
    ...identity, bootstrapNew: true,
  }), /CAS_ANCHOR_INVALID/,
  "an explicit NEW anchor may not silently adopt an existing signed journal or rollback snapshot");
  assert.equal(hash(target), originalHash, "rejected foreign journal must remain unchanged");
  const legitimateRestart = new Zk1CasTerminalAnchor(target, { ...identity, bootstrapNew: false });
  assert.equal(legitimateRestart.sequence, 1);
});
