"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { fork, spawnSync } = require("node:child_process");
const test = require("node:test");
const repo = require("../repositories/usersRepository");
const { getDb, closeDb } = require("../db");
const { runMigrations } = require("../db/migrations");
const { replayDigest, authorizationDigest, secretDigest } = require("../src/services/syncResumeAccountProof");

if (process.argv[2] === "init-failure") {
  let attempts = 0;
  let closes = 0;
  class UnavailableDurabilityDb {
    constructor() { attempts += 1; }
    pragma(statement) {
      if (statement === "synchronous = FULL") throw new Error("durability unavailable");
      return null;
    }
    close() { closes += 1; }
  }
  const Module = require("node:module");
  const originalLoad = Module._load;
  Module._load = function (name, parent, isMain) {
    if (name === "better-sqlite3") return UnavailableDurabilityDb;
    return originalLoad.call(this, name, parent, isMain);
  };
  delete require.cache[require.resolve("../db")];
  const { getDb: open } = require("../db");
  assert.throws(() => open(), /durability unavailable/);
  assert.throws(() => open(), /durability unavailable/);
  assert.equal(attempts, 2, "an unconfigured connection must never be cached");
  assert.equal(closes, 2, "a failed connection must be closed");
} else if (process.argv[2] === "claim") {
  process.send({ ready: true });
  process.once("message", ({ claim, abrupt }) => {
    let outcome;
    try { outcome = repo.commitSyncResumeProof(claim); }
    catch (error) { outcome = `error:${error.code || "sqlite"}`; }
    const synchronous = getDb().pragma("synchronous", { simple: true });
    if (abrupt && outcome === "committed") process.exit(71);
    closeDb();
    process.send({ outcome, synchronous }, () => process.exit(0));
  });
} else {
  test("issue 65: SQLite 2FA recovery spend is FULL-durable, interprocess single-use and atomic on grant failure", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w13-sqlite-probe-"));
    process.env.DATABASE_URL = path.join(root, "accounts.sqlite");
    try {
      runMigrations({ backup: false });
      const db = getDb();
      assert.equal(String(db.pragma("journal_mode", { simple: true })).toLowerCase(), "wal");
      assert.equal(db.pragma("synchronous", { simple: true }), 2);
      const failedInit = spawnSync(process.execPath, [__filename, "init-failure"], {
        encoding: "utf8", env: { ...process.env, DATABASE_URL: path.join(root, "init-failure.sqlite") },
      });
      assert.equal(failedInit.status, 0, failedInit.stderr);
      repo.saveUsers([{ username: "alice", password: "hash", sessionVersion: 2,
        role: "user", permissions: { upload: true }, totpEnabled: true,
        totpSecret: { sealed: "public-fixture" }, totpRecoveryHashes: ["verifier-one", "verifier-two"] }]);
      const current = repo.loadUsers()[0];
      const after = structuredClone(current);
      after.totpRecoveryHashes.shift();
      const build = (deviceId, proof, expectedReplayDigest) => ({
        username: current.username, passwordHash: current.password,
        sessionVersion: current.sessionVersion, secretDigest: secretDigest(current),
        authorizationDigest: authorizationDigest(current), deviceId,
        pauseFence: "nonce-first", codeMac: deviceId === "device-a" ? "a".repeat(64) : "b".repeat(64),
        proof, expectedReplayDigest,
      });
      const claimA = build("device-a", { type: "recovery", hash: "verifier-one" }, replayDigest(after));
      const claimB = build("device-b", { type: "recovery", hash: "verifier-one" }, replayDigest(after));
      const launch = (claim, abrupt = false) => new Promise((resolve, reject) => {
        const child = fork(__filename, ["claim"], { env: process.env, stdio: ["ignore", "ignore", "pipe", "ipc"] });
        const status = { ready: false, child, resolve, reject };
        child.on("error", reject);
        child.on("message", (msg) => {
          if (msg.ready) { status.ready = true; status.notify?.(); }
          if (msg.outcome) {
            if (msg.synchronous !== 2) reject(new Error("Recovery worker used non-durable WAL configuration"));
            else resolve(msg.outcome);
          }
        });
        child.on("exit", (code) => {
          if (abrupt && code === 71) resolve("abrupt-after-commit");
          else if (code && code !== 0) reject(new Error(`child exit ${code}`));
        });
        status.send = () => child.send({ claim, abrupt });
        children.push(status);
      });
      const children = [];
      const results = [launch(claimA), launch(claimB)];
      await Promise.all(children.map((child) => child.ready
        ? Promise.resolve() : new Promise((resolve) => { child.notify = resolve; })));
      children.forEach((child) => child.send());
      const outcomes = await Promise.all(results);
      assert.deepEqual(outcomes.slice().sort(), ["committed", "conflict"].sort());
      const winner = outcomes[0] === "committed" ? claimA : claimB;
      const loser = outcomes[0] === "committed" ? claimB : claimA;
      const run = async (claim, abrupt = false) => {
        const pending = launch(claim, abrupt);
        const child = children.at(-1);
        if (!child.ready) await new Promise((resolve) => { child.notify = resolve; });
        child.send();
        return pending;
      };
      assert.equal(await run(winner), "already", "same exact retry after restart");
      assert.equal(await run(loser), "conflict", "second device may not borrow spent factor");
      assert.deepEqual(repo.loadUsers()[0].totpRecoveryHashes, ["verifier-two"]);
      const fresh = repo.loadUsers()[0];
      const consumed = structuredClone(fresh);
      consumed.totpRecoveryHashes.shift();
      const next = { ...build("device-a", { type: "recovery", hash: "verifier-two" }, replayDigest(consumed)),
        secretDigest: secretDigest(fresh), authorizationDigest: authorizationDigest(fresh),
        passwordHash: fresh.password, sessionVersion: fresh.sessionVersion,
        pauseFence: "nonce-second" };
      db.exec("CREATE TRIGGER fail_grant BEFORE INSERT ON sync_resume_factor_spend_grant BEGIN SELECT RAISE(ABORT, 'simulated insert failure'); END");
      const denied = await run(next);
      assert.match(denied, /^error:/);
      assert.deepEqual(repo.loadUsers()[0].totpRecoveryHashes, ["verifier-two"], "SQLite rollback preserves recovery verifier on failed spend grant");
      db.exec("DROP TRIGGER fail_grant");
      assert.equal(await run(next, true), "abrupt-after-commit", "worker exits without closing DB after committing factor");
      assert.deepEqual(repo.loadUsers()[0].totpRecoveryHashes, []);
      assert.equal(await run(next), "already", "committed factor survives worker crash and only exact intent may retry");
    } finally { closeDb(); fs.rmSync(root, { recursive: true, force: true }); }
  });
}
