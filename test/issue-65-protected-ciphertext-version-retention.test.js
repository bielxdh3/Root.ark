"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");

const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const rand = (n) => crypto.randomBytes(n);

test("protected local PUT archives ciphertext revisions atomically and never replaces earlier opaque bytes", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-version-ledger-"));
  const filename = path.join(dir, "content.sqlite");
  const state = await fixtures.createInitialState(2);
  const scope = state.scope;
  const manifest = state.headManifest;
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = rand(16);
  const digest = await v2.recoveryManifestDigestV2(manifest);
  const instances = [];
  t.after(() => {
    for (const instance of instances) if (instance.db.open) instance.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const make = (bootstrapNew) => {
    const store = new Zk1ProtectedObjectStore(filename, {
      trustedScope: scope, minimumHead: { revision: 1,
        digest: awaitDigest, witnessSequence: 1 },
      bootstrapNew,
      witnessProvider: { async freshHead({ nonce }) {
        const head = { type: "rootark-recovery-witness-head/v1",
          witness_key_id: witnessKeyId, ...scope,
          current_revision: manifest.revision, current_manifest_digest: digest,
          witness_sequence: manifest.revision, nonce, observed_at: 1200,
          status: "committed", pending_reservation_id: null };
        const signature = crypto.sign(null, Buffer.concat([
          DOMAIN, Buffer.from(await z.encodeDeterministic(head)),
        ]), witness.privateKey);
        return z.encodeDeterministic({ ...head, signature });
      } },
      witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
      manifestProvider: () => z.encodeDeterministic(manifest),
      nowSeconds: () => 1200,
    });
    instances.push(store);
    return store;
  };
  const awaitDigest = await v2.recoveryManifestDigestV2(state.baseManifest);
  let store = make(true);
  const device = manifest.devices[0];
  const privateKey = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
  const objectId = rand(16).toString("base64url");
  const signed = async (data, expectedRevision) => {
    const operation = { ...scope, device_id: device.device_id, operation: "put",
      object_id: objectId, expected_object_revision: expectedRevision,
      manifest_revision: manifest.revision, manifest_digest: digest,
      epoch: manifest.current_epoch, nonce: rand(32), issued_at: 1199,
      expires_at: 1230, ciphertext_digest: crypto.createHash("sha256").update(data).digest() };
    return { scope, authorization: operation, ciphertext: data,
      signature: crypto.sign(null, await contentAuthorizationMessageV1(operation), privateKey) };
  };
  const firstBytes = rand(300);
  const secondBytes = rand(301);
  const first = await signed(firstBytes, null);
  assert.equal((await store.put(first)).revision, 1);
  const second = await signed(secondBytes, 1);
  assert.equal((await store.put(second)).revision, 2);
  const revisions = () => store.db.prepare(
    "SELECT revision,epoch,ciphertext,ciphertext_digest,provenance FROM zk_content_version WHERE id=? ORDER BY revision")
    .all(objectId);
  assert.equal(revisions().length, 2,
    "both committed ciphertext versions must persist, not just latest overwritten bytes");
  assert.deepEqual(revisions().map((row) => row.revision), [1, 2]);
  assert.deepEqual(revisions().map((row) => row.ciphertext), [firstBytes, secondBytes]);
  for (const row of revisions()) {
    assert.deepEqual(row.ciphertext_digest,
      crypto.createHash("sha256").update(row.ciphertext).digest());
    assert.equal(row.provenance, "transactional");
  }
  const failed = await signed(rand(100), 1);
  await assert.rejects(store.put(failed), /ZK_CONTENT_CONFLICT/);
  assert.equal(revisions().length, 2, "failed overwrite cannot create phantom immutable revisions");
  assert.throws(() => store.db.prepare("UPDATE zk_content_version SET ciphertext=? WHERE id=?")
    .run(rand(20), objectId), /ZK_CONTENT_VERSION_IMMUTABLE/);
  assert.throws(() => store.db.prepare("DELETE FROM zk_content_version WHERE id=?")
    .run(objectId), /ZK_CONTENT_VERSION_IMMUTABLE/);
  const currentScope = store.db.prepare("SELECT scope FROM zk_content_object WHERE id=?")
    .get(objectId).scope;
  const replaced = rand(300);
  assert.throws(() => store.db.prepare(
    "INSERT OR REPLACE INTO zk_content_version "
      + "(scope,id,revision,epoch,ciphertext,ciphertext_digest,provenance) "
      + "VALUES(?,?,?,?,?,?,'transactional')")
    .run(currentScope, objectId, 1, manifest.current_epoch,
      replaced, crypto.createHash("sha256").update(replaced).digest()),
  /ZK_CONTENT_VERSION_IMMUTABLE/,
  "SQLite REPLACE must not silently bypass immutable history via its implicit DELETE");
  store.close();
  store = make(false);
  assert.deepEqual(revisions().map((row) => row.ciphertext), [firstBytes, secondBytes],
    "restart must preserve all opaque revisions byte-for-byte");
  await assert.rejects(store.put(second), /ZK_CONTENT_REPLAY/);
  assert.equal(revisions().length, 2);
  const third = await signed(rand(320), 2);
  store.db.exec("CREATE TRIGGER zk_content_version_fixture_abort "
    + "BEFORE INSERT ON zk_content_version "
    + "BEGIN SELECT RAISE(ABORT,'VERSION_FIXTURE_ABORT'); END");
  await assert.rejects(store.put(third), /VERSION_FIXTURE_ABORT/,
    "a history write failure must reject the entire protected PUT");
  assert.equal(store.db.prepare("SELECT revision FROM zk_content_object WHERE id=?")
    .get(objectId).revision, 2, "no partially advanced latest ciphertext revision");
  assert.equal(revisions().length, 2, "no phantom archive row");
  store.db.exec("DROP TRIGGER zk_content_version_fixture_abort");
  assert.equal((await store.put(third)).revision, 3,
    "failed transaction must not consume nonce or poison a safe exact retry");
  assert.equal(revisions().length, 3);
  // Intentional corruption of this disposable fixture, not customer data.
  // An attacker with direct file access can drop SQLite triggers; the next
  // startup must detect a corrupted historical digest and refuse future I/O.
  store.db.exec("DROP TRIGGER zk_content_version_no_update");
  store.db.prepare("UPDATE zk_content_version SET ciphertext=? WHERE id=? AND revision=1")
    .run(rand(300), objectId);
  store.close();
  assert.throws(() => make(false), /ZK_CONTENT_VERSION_HISTORY_CORRUPT/,
    "restart must never accept a forged/altered prior version");
  const fixture = new Database(filename);
  fixture.exec("DROP TABLE zk_content_version");
  fixture.close();
  const bytesBefore = fs.readFileSync(filename);
  assert.throws(() => make(false), /ZK_CONTENT_VERSION_HISTORY_REQUIRED/,
    "older/incomplete history requires an explicit reviewed migration, not invented prior rows");
  assert.deepEqual(fs.readFileSync(filename), bytesBefore,
    "unknown or missing version archive must not be repaired by writing to the original database");
});
