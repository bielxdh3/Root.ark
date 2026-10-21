"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { OpaqueDevVaultStore } = require("../src/services/zkOpaqueDevVault");

const validId = () => crypto.randomBytes(16).toString("base64url");
const KEY_ID = crypto.randomBytes(32).toString("base64url");
const create = (store, owner, input) => store.create(owner, { ...input, keyId: KEY_ID });
const replace = (store, owner, input) => store.replace(owner, { ...input, keyId: KEY_ID });
function sampleEnvelope(ciphertext = crypto.randomBytes(64).toString("base64url")) {
  return { format: "rootark-dev-file-v1", algorithm: "AES-256-GCM",
    iv: crypto.randomBytes(12).toString("base64url"), ciphertext };
}

test("stores opaque ciphertext durably without server-visible file metadata or decryption keys", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-vault-"));
  const filename = path.join(dir, "vault.sqlite");
  const aliceId = validId();
  const envelope = sampleEnvelope();
  const store = new OpaqueDevVaultStore(filename);
  const created = create(store, "alice", { id: aliceId, envelope });
  assert.equal(created.revision, 1);
  assert.deepEqual(store.list("alice"), [{ id: aliceId, revision: 1 }]);
  assert.equal(store.get("bob", aliceId), null);
  assert.deepEqual(store.list("bob"), []);
  assert.deepEqual(store.get("alice", aliceId).envelope, envelope);
  assert.equal(store.get("alice", aliceId).owner, undefined);
  const persisted = new OpaqueDevVaultStore(filename);
  t.after(() => { persisted.close(); store.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  assert.deepEqual(persisted.get("alice", aliceId).envelope, envelope);
  const onDisk = fs.readFileSync(filename);
  assert.equal(onDisk.includes(Buffer.from("secret-file-name.pdf")), false);
  assert.equal(onDisk.includes(Buffer.from("secret-password")), false);
});

test("cross-user isolation, replay conflicts, stale revision and persistent tombstone", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-vault-"));
  const dbPath = path.join(dir, "store.sqlite");
  const store = new OpaqueDevVaultStore(dbPath);
  t.after(() => { resumed?.close(); store.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  let resumed;
  const id = validId();
  const a = sampleEnvelope();
  const b = sampleEnvelope();
  assert.equal(create(store, "alice", { id, envelope: a }).revision, 1);
  assert.throws(() => create(store, "alice", { id, envelope: a }), (e) => e.code === "VAULT_CONFLICT");
  assert.equal(create(store, "bob", { id, envelope: b }).revision, 1);
  assert.throws(() => replace(store, "alice", { id, expectedRevision: 2, envelope: b }),
    (e) => e.code === "VAULT_CONFLICT");
  assert.equal(replace(store, "alice", { id, expectedRevision: 1, envelope: b }).revision, 2);
  assert.throws(() => store.remove("alice", { id, expectedRevision: 1 }), (e) => e.code === "VAULT_CONFLICT");
  assert.equal(store.remove("alice", { id, expectedRevision: 2 }).revision, 3);
  assert.equal(store.get("alice", id), null);
  assert.deepEqual(store.list("alice"), []);
  assert.deepEqual(store.get("bob", id).envelope, b);
  assert.throws(() => create(store, "alice", { id, envelope: a }), (e) => e.code === "VAULT_CONFLICT");
  resumed = new OpaqueDevVaultStore(dbPath);
  assert.throws(() => create(resumed, "alice", { id, envelope: a }), (e) => e.code === "VAULT_CONFLICT");
});

test("rejects plaintext, filenames, key material, noncanonical ciphertext and extra fields", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-vault-"));
  const store = new OpaqueDevVaultStore(path.join(dir, "vault.sqlite"));
  t.after(() => { store.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const id = validId();
  const envelope = sampleEnvelope();
  for (const input of [
    { id, envelope, filename: "secret-file-name.pdf" },
    { id, envelope, plaintext: "SECRET" },
    { id, envelope, key: "hidden" },
    { id, envelope: { ...envelope, originalName: "sensitive" } },
    { id, envelope: { ...envelope, iv: "aaaaaaaaaaaa+" } },
    { id, envelope: { ...envelope, ciphertext: "Aa" } },
    { id, envelope: { ...envelope, algorithm: "AES-128-GCM" } },
    { id, envelope: { ...envelope, ciphertext: "" } },
    { id: "../../private", envelope },
  ]) {
    assert.throws(() => create(store, "alice", input), (e) => e.code === "VAULT_INVALID");
  }
});

test("per-account and global ciphertext quotas fail closed without losing prior records", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-vault-"));
  const initial = sampleEnvelope(crypto.randomBytes(32).toString("base64url"));
  const normalSize = Buffer.byteLength(JSON.stringify(initial));
  const db = new OpaqueDevVaultStore(path.join(dir, "vault.sqlite"), {
    maxOwnerBytes: normalSize, maxTotalBytes: normalSize * 2,
  });
  t.after(() => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const alice = validId(), bob = validId();
  assert.equal(create(db, "alice", { id: alice, envelope: initial }).revision, 1);
  assert.throws(() => create(db, "alice", { id: validId(), envelope: initial }),
    (e) => e.code === "VAULT_LIMIT");
  assert.throws(() => replace(db, "alice", {
    id: alice, expectedRevision: 1, envelope: sampleEnvelope(crypto.randomBytes(60).toString("base64url")),
  }), (e) => e.code === "VAULT_LIMIT");
  assert.equal(db.get("alice", alice).revision, 1);
  assert.equal(create(db, "bob", { id: bob, envelope: initial }).revision, 1);
  assert.throws(() => create(db, "carol", { id: validId(), envelope: initial }),
    (e) => e.code === "VAULT_LIMIT");
  db.remove("alice", { id: alice, expectedRevision: 1 });
  assert.equal(create(db, "carol", { id: validId(), envelope: initial }).revision, 1);
});

test("active-object quota is released after deletion but old object IDs cannot be replayed", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-vault-"));
  const db = new OpaqueDevVaultStore(path.join(dir, "vault.sqlite"), {
    maxObjectsPerOwner: 2,
  });
  t.after(() => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const objects = [validId(), validId(), validId()];
  const encrypted = sampleEnvelope();
  create(db, "alice", { id: objects[0], envelope: encrypted });
  create(db, "alice", { id: objects[1], envelope: encrypted });
  assert.throws(() => create(db, "alice", { id: objects[2], envelope: encrypted }),
    (error) => error.code === "VAULT_LIMIT");
  db.remove("alice", { id: objects[0], expectedRevision: 1 });
  assert.equal(create(db, "alice", { id: objects[2], envelope: encrypted }).revision, 1);
  assert.throws(() => create(db, "alice", { id: objects[0], envelope: encrypted }),
    (error) => error.code === "VAULT_CONFLICT");
  assert.equal(db.list("alice").length, 2);
});

test("retained tombstones have explicit per-user and global upper bounds", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-vault-"));
  const store = new OpaqueDevVaultStore(path.join(dir, "vault.sqlite"), {
    maxObjectsPerOwner: 2, maxLifetimeIdsPerOwner: 3, maxGlobalIds: 4,
  });
  t.after(() => { store.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const envelope = sampleEnvelope();
  const oldIds = [];
  for (let i = 0; i < 3; i += 1) {
    const id = validId();
    oldIds.push(id);
    create(store, "alice", { id, envelope });
    store.remove("alice", { id, expectedRevision: 1 });
  }
  assert.equal(store.list("alice").length, 0);
  assert.throws(() => create(store, "alice", { id: validId(), envelope }),
    (e) => e.code === "VAULT_LIMIT");
  assert.throws(() => create(store, "alice", { id: oldIds[0], envelope }),
    (e) => e.code === "VAULT_CONFLICT");
  const bobId = validId();
  create(store, "bob", { id: bobId, envelope });
  store.remove("bob", { id: bobId, expectedRevision: 1 });
  assert.throws(() => create(store, "carol", { id: validId(), envelope }),
    (e) => e.code === "VAULT_LIMIT");
});

test("one active vault key commitment is enforced across files, revisions and concurrent writers", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-vault-"));
  const store = new OpaqueDevVaultStore(path.join(dir, "vault.sqlite"));
  t.after(() => { store.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const first = validId(), second = validId();
  const envelope = sampleEnvelope();
  const differentKeyId = crypto.randomBytes(32).toString("base64url");
  assert.equal(store.activeKeyId("alice"), null);
  assert.equal(create(store, "alice", { id: first, envelope }).revision, 1);
  assert.equal(store.activeKeyId("alice"), KEY_ID);
  assert.throws(() => store.create("alice", { id: second, envelope, keyId: differentKeyId }),
    (error) => error.code === "VAULT_KEY_MISMATCH");
  assert.throws(() => store.replace("alice", {
    id: first, envelope, expectedRevision: 1, keyId: differentKeyId,
  }), (error) => error.code === "VAULT_KEY_MISMATCH");
  assert.equal(store.list("alice").length, 1);
  store.remove("alice", { id: first, expectedRevision: 1 });
  assert.equal(store.activeKeyId("alice"), null);
  assert.equal(store.create("alice", { id: second, envelope, keyId: differentKeyId }).revision, 1);
  assert.equal(store.activeKeyId("alice"), differentKeyId);
  assert.throws(() => store.create("alice", { id: validId(), envelope, keyId: KEY_ID }),
    (error) => error.code === "VAULT_KEY_MISMATCH");
});
