"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const { fork } = require("node:child_process");
const { Pool } = require("pg");
const { Zk1ExperimentalPgApprovalReplayLedger: Ledger,
  verifyDisposableReplayWriterPool: verifyPool } =
  require("../src/services/zk1ExperimentalPgApprovalReplayLedger");

const writerUrl = process.env.ROOTARK_ZK1_REPLAY_WRITER_PG_URL;
const adminUrl = process.env.ROOTARK_ZK1_REPLAY_ADMIN_PG_URL;
const enabled = Boolean(writerUrl && adminUrl);
const rand = (n) => crypto.randomBytes(n);
const scopeKey = (s) => `${s.account_id.toString("hex")}:${s.compartment_id.length.toString(16)}:${s.compartment_id.toString("hex")}`;
function fixture() {
  return { scope: { account_id: rand(16), compartment_id: rand(7), keyring_id: rand(16) },
    nonce: rand(32), rawSignedApproval: rand(300), deviceKeyId: rand(16),
    manifestRevision: 12, manifestDigest: rand(32), witnessSequence: 18,
    expiresAt: Math.floor(Date.now() / 1000) + 100 };
}
function context(t) {
  const admin = new Pool({ connectionString: adminUrl, max: 3, connectionTimeoutMillis: 3000 });
  const writer = new Pool({ connectionString: writerUrl, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), writer.end()]));
  return { admin, writer, ledger: new Ledger({ pool: writer }) };
}

test("restricted SQL role atomically consumes only one nonce, retaining tombstone across pool restart", {
  skip: !enabled && "needs exact disposable PostgreSQL writer and admin URLs",
}, async (t) => {
  const c = context(t);
  assert.deepEqual(await verifyPool(c.writer), { verified: true, labOnly: true });
  await assert.rejects(verifyPool(c.admin), /ZK_APPROVAL_REPLAY_LAB_DENIED/,
    "superuser login is not a replay writer");
  const f = fixture();
  assert.deepEqual(await c.ledger.consumeCandidate(f), {
    replayRecordCommitted: true, cryptographicApprovalVerified: false,
    liveAuthorityVerified: false, authorizesRelease: false, protectedIoAdmission: false });
  await assert.rejects(c.ledger.consumeCandidate(f), /ZK_APPROVAL_REPLAY_LAB_DENIED/);
  await assert.rejects(c.ledger.consumeCandidate({ ...f, rawSignedApproval: rand(300) }),
    /ZK_APPROVAL_REPLAY_LAB_DENIED/, "changed signature cannot reuse consumed nonce");
  await assert.rejects(c.ledger.consumeCandidate({ ...f, scope: {
    ...f.scope, keyring_id: rand(16) } }), /ZK_APPROVAL_REPLAY_LAB_DENIED/,
  "scope-key rotation must not revive a nonce in the same compartment");
  const freshPool = new Pool({ connectionString: writerUrl, max: 1 });
  t.after(async () => freshPool.end());
  await assert.rejects(new Ledger({ pool: freshPool }).consumeCandidate(f),
    /ZK_APPROVAL_REPLAY_LAB_DENIED/, "new process pool cannot forget durable tombstone");
  const count = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_approval_replay_lab.consumed
    WHERE scope_key=$1 AND nonce=$2`, [scopeKey(f.scope), f.nonce]);
  assert.equal(count.rows[0].n, 1);
});

test("independent PostgreSQL connections race the same approval; exactly one durable winner", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const c = context(t);
  const other = new Pool({ connectionString: writerUrl, max: 2 });
  t.after(async () => other.end());
  const f = fixture();
  const result = await Promise.allSettled(Array.from({ length: 12 }, (_, i) =>
    (i % 2 ? new Ledger({ pool: other }) : c.ledger).consumeCandidate(f)));
  assert.equal(result.filter((x) => x.status === "fulfilled").length, 1);
  assert.equal(result.filter((x) => x.status === "rejected"
    && /ZK_APPROVAL_REPLAY_LAB_DENIED/.test(x.reason?.message)).length, 11);
  const row = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_approval_replay_lab.consumed
    WHERE scope_key=$1 AND nonce=$2`, [scopeKey(f.scope), f.nonce]);
  assert.equal(row.rows[0].n, 1);
});

test("two independently spawned OS processes race one nonce and a restarted child cannot replay", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const c = context(t);
  const f = fixture();
  const encoded = (bytes) => Buffer.from(bytes).toString("base64url");
  const message = { kind: "consume", url: writerUrl,
    scope: [encoded(f.scope.account_id), encoded(f.scope.compartment_id),
      encoded(f.scope.keyring_id)], nonce: encoded(f.nonce),
    approval: encoded(f.rawSignedApproval), deviceKeyId: encoded(f.deviceKeyId),
    manifestDigest: encoded(f.manifestDigest),
    manifestRevision: f.manifestRevision, witnessSequence: f.witnessSequence,
    expiresAt: f.expiresAt };
  const children = new Set();
  t.after(() => { for (const child of children) try { child.kill("SIGKILL"); } catch (_) {} });
  const attempt = async () => {
    const child = fork(path.join(__dirname, "support", "issue-65-approval-replay-worker.js"),
      [], { cwd: path.resolve(__dirname, ".."),
        env: { PATH: process.env.PATH || "", SystemRoot: process.env.SystemRoot || "",
          TEMP: process.env.TEMP || "", TMP: process.env.TMP || "" },
        stdio: ["ignore", "ignore", "ignore", "ipc"], windowsHide: true });
    children.add(child);
    try {
      const result = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(Error("fixture child IPC timeout")), 5000);
        child.once("error", (error) => { clearTimeout(timer); reject(error); });
        child.once("exit", () => { clearTimeout(timer); reject(Error("fixture child exited without IPC proof")); });
        child.once("message", (reply) => { clearTimeout(timer); resolve(reply); });
        child.send(message);
      });
      assert.ok(["inserted", "denied"].includes(result?.status));
      return result.status;
    } finally {
      child.kill("SIGKILL");
      children.delete(child);
    }
  };
  const statuses = await Promise.all([attempt(), attempt()]);
  assert.deepEqual(statuses.sort(), ["denied", "inserted"]);
  assert.equal(await attempt(), "denied", "a newly spawned process cannot replay committed nonce");
  const count = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_approval_replay_lab.consumed
    WHERE scope_key=$1 AND nonce=$2`, [scopeKey(f.scope), f.nonce]);
  assert.equal(count.rows[0].n, 1);
});

test("PostgreSQL clock rejects expired/far-future candidate without burning nonce", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const c = context(t);
  const f = fixture();
  for (const expiresAt of [Math.floor(Date.now() / 1000) - 20,
    Math.floor(Date.now() / 1000) + 1000]) {
    await assert.rejects(c.ledger.consumeCandidate({ ...f, expiresAt }),
      /ZK_APPROVAL_REPLAY_LAB_DENIED/);
  }
  const row = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_approval_replay_lab.consumed
    WHERE scope_key=$1 AND nonce=$2`, [scopeKey(f.scope), f.nonce]);
  assert.equal(row.rows[0].n, 0);
  assert.equal((await c.ledger.consumeCandidate(f)).replayRecordCommitted, true);
});

test("writer SQL login cannot SELECT, UPDATE, DELETE, TRUNCATE or forge a gate role", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const c = context(t);
  const f = fixture();
  await c.ledger.consumeCandidate(f);
  for (const sql of [
    "SELECT * FROM zk1_approval_replay_lab.consumed",
    "UPDATE zk1_approval_replay_lab.consumed SET expires_at=1",
    "DELETE FROM zk1_approval_replay_lab.consumed",
    "TRUNCATE zk1_approval_replay_lab.consumed",
    "SET ROLE zk1_gate_runtime", "SET ROLE zk1_stop_runtime",
  ]) await assert.rejects(c.writer.query(sql), /permission|denied|42501|role/i);
  await assert.rejects(c.ledger.consumeCandidate(f), /ZK_APPROVAL_REPLAY_LAB_DENIED/);
});

test("writer preflight rejects hidden per-column SELECT/UPDATE privileges", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const c = context(t);
  for (const grant of ["SELECT(nonce)", "UPDATE(expires_at)"]) {
    const username = "zkreplayfixture_" + rand(6).toString("hex");
    const password = rand(24).toString("hex");
    const url = new URL(writerUrl);
    url.username = username;
    url.password = password;
    const probe = new Pool({ connectionString: url.toString(), max: 1 });
    try {
      await c.admin.query("CREATE ROLE " + username + " LOGIN PASSWORD '" + password + "'");
      await c.admin.query("GRANT zk1_approval_replay_writer TO " + username);
      await c.admin.query("GRANT " + grant + " ON zk1_approval_replay_lab.consumed TO " + username);
      const capabilities = await probe.query(`SELECT
        pg_catalog.has_table_privilege(current_user,
          'zk1_approval_replay_lab.consumed','SELECT') AS table_select,
        pg_catalog.has_table_privilege(current_user,
          'zk1_approval_replay_lab.consumed','UPDATE') AS table_update`);
      assert.equal(capabilities.rows[0].table_select, false);
      assert.equal(capabilities.rows[0].table_update, false);
      await assert.rejects(verifyPool(probe), /ZK_APPROVAL_REPLAY_LAB_DENIED/,
        "hidden column privilege " + grant + " must be rejected despite false table ACL");
    } finally {
      await probe.end();
      await c.admin.query("DROP OWNED BY " + username);
      await c.admin.query("DROP ROLE IF EXISTS " + username);
    }
  }
});

test("no privileged connection substitution after preflight may create a replay tombstone", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const c = context(t);
  let count = 0;
  const mixed = { connect: () => ++count % 2 ? c.writer.connect() : c.admin.connect() };
  const ledger = new Ledger({ pool: mixed });
  const first = fixture();
  assert.equal((await ledger.consumeCandidate(first)).replayRecordCommitted, true,
    "the first restricted connection is allowed; no second connection substitution occurs");
  assert.equal(count, 1, "verification and INSERT must lease exactly one physical SQL connection");
  const f = fixture();
  await assert.rejects(ledger.consumeCandidate(f),
    /ZK_APPROVAL_REPLAY_LAB_DENIED/,
    "the next unverified privileged backend must be rejected BEFORE INSERT");
  const rows = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_approval_replay_lab.consumed
    WHERE scope_key=$1 AND nonce=$2`, [scopeKey(f.scope), f.nonce]);
  assert.equal(rows.rows[0].n, 0, "no actor may substitute a connection after role verification");
});

test("an inherited open transaction cannot produce a false durable replay receipt", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const c = context(t);
  const stalePool = new Pool({ connectionString: writerUrl, max: 1,
    connectionTimeoutMillis: 3000 });
  t.after(async () => stalePool.end());
  const staleClient = await stalePool.connect();
  await staleClient.query("BEGIN");
  staleClient.release(); // Deliberately misbehaving caller leaves a pooled txn open.
  const f = fixture();
  await assert.rejects(new Ledger({ pool: stalePool }).consumeCandidate(f),
    /ZK_APPROVAL_REPLAY_LAB_DENIED/,
    "pre-existing external BEGIN must be refused, not treated as a committed INSERT");
  const row = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_approval_replay_lab.consumed
    WHERE scope_key=$1 AND nonce=$2`, [scopeKey(f.scope), f.nonce]);
  assert.equal(row.rows[0].n, 0);
});

test("connection shutdown before SQL COMMIT rolls back reservation; lost ACK after COMMIT is never replayed", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const c = context(t);
  const f = fixture();
  const txn = await c.writer.connect();
  txn.on("error", () => { /* disposable intentionally severed PG client */ });
  let released = false;
  t.after(() => { if (!released) txn.release(true); });
  await txn.query("BEGIN");
  await txn.query(`INSERT INTO zk1_approval_replay_lab.consumed
    (scope_key,nonce,keyring_id,approval_digest,device_key_id,manifest_digest,
      manifest_revision,witness_sequence,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
  [scopeKey(f.scope), f.nonce, f.scope.keyring_id, rand(32), f.deviceKeyId,
    f.manifestDigest, f.manifestRevision, f.witnessSequence, f.expiresAt]);
  // Releasing with an error destroys the physical socket. PostgreSQL aborts
  // the uncommitted transaction when that session disconnects.
  txn.release(true);
  released = true;
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal((await c.ledger.consumeCandidate(f)).replayRecordCommitted, true,
    "connection loss before COMMIT must not burn the challenge");
  await assert.rejects(c.ledger.consumeCandidate(f), /ZK_APPROVAL_REPLAY_LAB_DENIED/,
    "committed ledger row forbids exact retry even if prior ACK was lost");
});

test("malformed input and failed SQL authority never claim authorization", async () => {
  const f = fixture();
  const disconnected = new Ledger({ pool: { async connect() { throw new Error("disconnected"); } } });
  await assert.rejects(disconnected.consumeCandidate(f), /ZK_APPROVAL_REPLAY_LAB_DENIED/);
  for (const bad of [
    { nonce: rand(31) }, { scope: { ...f.scope, compartment_id: Buffer.alloc(0) } },
    { rawSignedApproval: "attacker" }, { manifestRevision: 0 },
    { injectedSql: "DROP TABLE" },
  ]) await assert.rejects(disconnected.consumeCandidate({ ...f, ...bad }),
    /ZK_APPROVAL_REPLAY_LAB_DENIED/);
});
