"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { fork } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { Zk1ProtectedCiphertextSharing } =
  require("../src/services/zk1ProtectedCiphertextSharing");

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk-share-egress-cross-store-"));
  const filename = path.join(directory, "authority.sqlite");
  const a = new Database(filename);
  const b = new Database(filename);
  for (const db of [a, b]) db.pragma("journal_mode = WAL");
  t.after(() => {
    for (const db of [a, b]) if (db.open) db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const store = (db) => ({
    db, signedHistoryRequired: true, admissionRequired: true,
    nowSeconds: () => 1400,
    runWithAdmission() { throw new Error("not used by synthetic tracker fixture"); },
  });
  const owner = new Zk1ProtectedCiphertextSharing(store(a));
  const recipient = new Zk1ProtectedCiphertextSharing(store(b));
  const scope = {
    account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(8),
    keyring_id: crypto.randomBytes(16),
  };
  const grantId = crypto.randomBytes(32).toString("base64url");
  const scopeId = [scope.account_id, scope.compartment_id, scope.keyring_id]
    .map((part) => part.toString("hex")).join(":");
  a.prepare("INSERT INTO zk_content_share (grant_id,scope,statement,signature,owner_username,recipient_username,expires_at,revoked) VALUES (?,?,?,?,?,?,?,0)")
    .run(grantId, scopeId, Buffer.from("synthetic-only"),
      Buffer.alloc(64), "owner", "recipient", 2000);
  return { a, b, owner, recipient, scope, grantId, scopeId, filename };
}

if (process.argv[2] === "--egress-child") {
  // This process shares the actual SQLite file, but not its DB handle,
  // JavaScript heap, activeEgress WeakMap, or request lifecycle.
  const db = new Database(process.env.W48_DB);
  const store = {
    db, signedHistoryRequired: true, admissionRequired: true,
    nowSeconds: () => 1400,
    runWithAdmission() { throw new Error("synthetic tracker only"); },
  };
  const sharing = new Zk1ProtectedCiphertextSharing(store);
  const scope = Object.fromEntries(Object.entries(JSON.parse(process.env.W48_SCOPE))
    .map(([name, hex]) => [name, Buffer.from(hex, "hex")]));
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  process.once("message", (message) => { if (message === "release") release(); });
  const sent = sharing.emitTracked(scope, process.env.W48_GRANT, () => held, {});
  process.send("started");
  sent.then(() => { db.close(); process.exit(0); })
    .catch((error) => { console.error(error.message); process.exit(1); });
} else {

test("two independent SQLite handles: revoke ACK waits for remote in-flight egress", async (t) => {
  const f = fixture(t);
  let release;
  const pendingBytes = new Promise((resolve) => { release = resolve; });
  const sending = f.owner.emitTracked(f.scope, f.grantId, () => pendingBytes, {});
  let acknowledged = false;
  const revoking = f.recipient.revokeAndDrain(f.scope, f.grantId, "owner")
    .then((result) => { acknowledged = true; return result; });
  try {
    await pause(80);
    assert.equal(f.a.prepare("SELECT revoked FROM zk_content_share WHERE grant_id=?")
      .get(f.grantId).revoked, 1, "tombstone commits during in-flight egress");
    assert.equal(acknowledged, false, "revoke cannot ACK before remote egress has settled");
    assert.equal(f.b.prepare("SELECT count(*) AS pending FROM zk_content_share_egress WHERE grant_id=?")
      .get(f.grantId).pending, 1, "durable row belongs to the active response");
  } finally {
    release();
  }
  await sending;
  assert.deepEqual(await revoking, { revoked: true });
  assert.equal(f.a.prepare("SELECT count(*) AS pending FROM zk_content_share_egress WHERE grant_id=?")
    .get(f.grantId).pending, 0);
});

test("durable tombstone rejects new egress through another independent store", async (t) => {
  const f = fixture(t);
  f.owner.revoke(f.scope, f.grantId, "owner");
  let emitted = false;
  assert.throws(() => f.recipient.emitTracked(f.scope, f.grantId, () => {
    emitted = true;
  }, {}), { code: "ZK_SHARE_UNAVAILABLE" });
  assert.equal(emitted, false);
});

test("orphaned durable egress row denies revoke ACK without TTL reclamation", { timeout: 16000 },
  async (t) => {
    const f = fixture(t);
    f.a.prepare("INSERT INTO zk_content_share_egress (lease_id,grant_id,scope) VALUES(?,?,?)")
      .run(crypto.randomBytes(24).toString("hex"), f.grantId, f.scopeId);
    await assert.rejects(
      f.recipient.revokeAndDrain(f.scope, f.grantId, "owner"),
      { code: "ZK_SHARE_UNAVAILABLE" },
    );
    assert.equal(f.a.prepare("SELECT revoked FROM zk_content_share WHERE grant_id=?")
      .get(f.grantId).revoked, 1);
    assert.equal(f.a.prepare("SELECT count(*) AS pending FROM zk_content_share_egress WHERE grant_id=?")
      .get(f.grantId).pending, 1, "crash/orphan row must remain until independently reconciled");
  });

test("two independent Node processes: durable revoke waits for remote egress release",
  { timeout: 12000 }, async (t) => {
    const f = fixture(t);
    const child = fork(__filename, ["--egress-child"], {
      execArgv: [],
      stdio: ["ignore", "ignore", "pipe", "ipc"],
      env: {
        ...process.env, W48_DB: f.filename, W48_GRANT: f.grantId,
        W48_SCOPE: JSON.stringify(Object.fromEntries(Object.entries(f.scope)
          .map(([name, buf]) => [name, buf.toString("hex")]))),
      },
    });
    let stderr = "";
    child.stderr.on("data", (part) => { stderr += part.toString().slice(-500); });
    t.after(() => { if (!child.killed && child.exitCode === null) child.kill(); });
    const exited = new Promise((resolve, reject) => {
      child.once("exit", (code) => code === 0 ? resolve() : reject(new Error(stderr)));
      child.once("error", reject);
    });
    const ready = await Promise.race([
      new Promise((resolve) => child.once("message", resolve)),
      new Promise((_, reject) => {
        const timer = setTimeout(() => reject(new Error("child egress did not start")), 5000);
        timer.unref();
      }),
    ]);
    assert.equal(ready, "started");
    let acknowledged = false;
    const revoking = f.recipient.revokeAndDrain(f.scope, f.grantId, "owner")
      .then((result) => { acknowledged = true; return result; });
    await pause(150);
    assert.equal(f.a.prepare("SELECT revoked FROM zk_content_share WHERE grant_id=?")
      .get(f.grantId).revoked, 1);
    assert.equal(f.a.prepare("SELECT count(*) AS pending FROM zk_content_share_egress WHERE grant_id=?")
      .get(f.grantId).pending, 1);
    assert.equal(acknowledged, false, "an unrelated process cannot be bypassed by local WeakMap");
    child.send("release");
    assert.deepEqual(await revoking, { revoked: true });
    await exited;
  });
}
