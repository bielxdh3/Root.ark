"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sync-resume-cas-"));
process.env.DATABASE_URL = path.join(directory, "users.sqlite");

const { closeDb } = require("../db");
const { runMigrations } = require("../db/migrations");
const usersRepository = require("../repositories/usersRepository");
const { authorizationDigest, replayDigest, secretDigest } = require("../src/services/syncResumeAccountProof");

test("SQLite recovery commit is selective, atomic and rejects admin revocation or replay-state drift", (t) => {
  t.after(() => { closeDb(); fs.rmSync(directory, { recursive: true, force: true }); });
  runMigrations({ backup: false });
  const alice = {
    username: "alice", password: "hash-original", sessionVersion: 3, role: "admin",
    permissions: { upload: true }, disabled: false, totpEnabled: true,
    totpSecret: { data: "encrypted-secret" }, totpRecoveryHashes: ["recovery-A", "recovery-B"],
    totpLastUsedStep: null,
  };
  const bob = { username: "bob", password: "other-password", role: "user",
    permissions: { listFiles: true }, sessionVersion: 7, disabled: false };
  usersRepository.saveUsers([alice, bob]);
  const original = usersRepository.loadUsers().find((item) => item.username === "alice");
  const afterProof = structuredClone(original);
  afterProof.totpRecoveryHashes.splice(0, 1);
  const claim = { username: "alice", passwordHash: original.password,
    sessionVersion: original.sessionVersion, secretDigest: secretDigest(original),
    authorizationDigest: authorizationDigest(original),
    deviceId: "device-a", pauseFence: "pause-first", codeMac: "a".repeat(64),
    proof: { type: "recovery", hash: "recovery-A" },
    expectedReplayDigest: replayDigest(afterProof) };

  const revoked = { ...original, disabled: true, sessionVersion: 4,
    role: "user", permissions: { upload: false } };
  usersRepository.saveUsers([revoked, bob]);
  assert.equal(usersRepository.commitSyncResumeProof(claim), "conflict");
  const stillRevoked = usersRepository.loadUsers().find((item) => item.username === "alice");
  assert.equal(stillRevoked.disabled, true);
  assert.equal(stillRevoked.sessionVersion, 4);
  assert.equal(stillRevoked.role, "user");
  assert.deepEqual(stillRevoked.totpRecoveryHashes, original.totpRecoveryHashes);
  assert.equal(usersRepository.loadUsers().find((item) => item.username === "bob").sessionVersion, 7);

  const reinstated = { ...stillRevoked, disabled: false };
  usersRepository.saveUsers([reinstated, bob]);
  assert.equal(usersRepository.commitSyncResumeProof(claim), "conflict",
    "stale sessionVersion cannot authorize a reinstated user");
  const current = usersRepository.loadUsers().find((item) => item.username === "alice");
  const consumed = structuredClone(current);
  consumed.totpRecoveryHashes.shift();
  const updatedClaim = { ...claim, sessionVersion: current.sessionVersion,
    authorizationDigest: authorizationDigest(current),
    expectedReplayDigest: replayDigest(consumed) };
  assert.equal(usersRepository.commitSyncResumeProof(updatedClaim), "committed");
  assert.equal(usersRepository.commitSyncResumeProof(updatedClaim), "already",
    "the same persisted staged intent may finish after a sync-storage failure");
  assert.equal(usersRepository.commitSyncResumeProof({ ...updatedClaim, deviceId: "device-b" }), "conflict",
    "a second device may not reuse another paused device's spent factor");
  assert.equal(usersRepository.commitSyncResumeProof({ ...updatedClaim, pauseFence: "pause-fork" }), "conflict",
    "a forked pause marker may not borrow the same consumed factor");
  assert.equal(usersRepository.commitSyncResumeProof({ ...updatedClaim, codeMac: "b".repeat(64) }), "conflict",
    "a different signed resume intent cannot claim the committed factor");
  const committed = usersRepository.loadUsers().find((item) => item.username === "alice");
  assert.deepEqual(committed.totpRecoveryHashes, ["recovery-B"]);
  assert.equal(committed.role, "user");
  assert.deepEqual(committed.permissions, { upload: false });
  assert.equal(usersRepository.loadUsers().find((item) => item.username === "bob").sessionVersion, 7);
});
