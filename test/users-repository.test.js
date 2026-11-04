const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-user-generation-"));
process.env.DATABASE_URL = path.join(directory, "rootark.sqlite");

const { closeDb } = require("../db");
const { runMigrations } = require("../db/migrations");
const usersRepository = require("../repositories/usersRepository");
const { encryptSecret, generateSecret } = require("../src/services/totp");

test("SQLite increments a deleted username generation on every recreation", (t) => {
  t.after(() => {
    closeDb();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  runMigrations({ backup: false });

  const agent = {
    username: "agent",
    password: "disposable",
    role: "user",
    permissions: {},
    sessionVersion: 0,
    totpEnabled: true,
    totpSecret: encryptSecret(generateSecret(), Buffer.alloc(32, 4), "Root.ark/TOTP/agent"),
    totpPendingSecret: null,
    totpRecoveryHashes: ["scrypt-v1$disposable"],
    totpLastUsedStep: 123,
    totpEnrolledAt: "2026-08-16T00:00:00.000Z",
  };
  usersRepository.saveUsers([agent]);
  const loaded = usersRepository.loadUsers()[0];
  assert.equal(loaded.totpEnabled, true);
  assert.deepEqual(loaded.totpSecret, agent.totpSecret);
  assert.deepEqual(loaded.totpRecoveryHashes, agent.totpRecoveryHashes);
  assert.equal(loaded.totpLastUsedStep, 123);
  assert.equal(loaded.totpEnrolledAt, agent.totpEnrolledAt);
  usersRepository.saveUsers([], { expectedDeletedUsers: [loaded] });
  usersRepository.saveUsers([agent], { allowRecreateUsernames: [agent.username] });
  assert.equal(usersRepository.loadUsers()[0].sessionVersion, 1);

  usersRepository.saveUsers([], { expectedDeletedUsers: usersRepository.loadUsers() });
  usersRepository.saveUsers([agent], { allowRecreateUsernames: [agent.username] });
  assert.equal(usersRepository.loadUsers()[0].sessionVersion, 2);
});
