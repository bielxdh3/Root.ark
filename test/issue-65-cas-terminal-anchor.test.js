"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");

test("two CAS handles cannot append a duplicate sequence or permanently corrupt continuity on restart", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cas-anchor-lock-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const file = path.join(dir, "anchor.log");
  const statusPrivateKey = crypto.generateKeyPairSync("ed25519").privateKey;
  const statusKeyId = crypto.randomBytes(16);
  const first = new Zk1CasTerminalAnchor(file, {
    statusPrivateKey, statusKeyId, bootstrapNew: true,
  });
  const second = new Zk1CasTerminalAnchor(file, {
    statusPrivateKey, statusKeyId, bootstrapNew: false,
  });
  const scope = {
    account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16),
  };
  const q1 = { ...scope, reservation_id: crypto.randomBytes(16) };
  const q2 = { ...scope, reservation_id: crypto.randomBytes(16) };
  const firstSeal = crypto.randomBytes(64);
  const secondSeal = crypto.randomBytes(64);
  const receipt1 = crypto.randomBytes(100);
  const receipt2 = crypto.randomBytes(100);
  const manifest1 = crypto.randomBytes(200);
  first.prepare(q1, receipt1, "committed", manifest1);
  await first.append(q1, receipt1, "committed", manifest1, firstSeal);
  second.prepare(q2, receipt2, "not-committed-final", null);
  await second.append(q2, receipt2, "not-committed-final", null, secondSeal);
  const reopened = new Zk1CasTerminalAnchor(file, {
    statusPrivateKey, statusKeyId, bootstrapNew: false,
  });
  assert.equal(reopened.sequence, 2);
  assert.ok(reopened.get(q1.reservation_id));
  assert.ok(reopened.get(q2.reservation_id));
  assert.ok(first.get(q2.reservation_id), "stale reader refreshes from signed disk journal");
  assert.equal(first.sequence, 2, "a stale first handle must refresh its durable head");
});

test("incomplete staging file from a crashed intent writer is not an authoritative intent", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cas-intent-stage-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const pathname = path.join(dir, "anchor.log");
  const statusPrivateKey = crypto.generateKeyPairSync("ed25519").privateKey;
  const statusKeyId = crypto.randomBytes(16);
  const first = new Zk1CasTerminalAnchor(pathname, {
    bootstrapNew: true, statusPrivateKey, statusKeyId,
  });
  const query = {
    account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16), reservation_id: crypto.randomBytes(16),
  };
  const staged = first.intentPath(query) + ".stage-crashed-writer";
  fs.writeFileSync(staged, "{uncommitted", { mode: 0o600 });
  const receipt = crypto.randomBytes(100);
  const manifest = crypto.randomBytes(100);
  assert.equal(first.getIntent(query), null);
  assert.equal(first.prepare(query, receipt, "committed", manifest), true);
  assert.ok(first.getIntent(query), "only a complete signed intent becomes authoritative");
  const restarted = new Zk1CasTerminalAnchor(pathname, {
    bootstrapNew: false, statusPrivateKey, statusKeyId,
  });
  assert.equal(restarted.assertIntent(query, receipt, "committed", manifest), true);
});
