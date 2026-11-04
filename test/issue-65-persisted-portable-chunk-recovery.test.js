"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { DatabaseSync } = require("node:sqlite");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const roots = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { createSignedPersistedPortableChunkInventory, recoverPersistedPortableChunks } =
  require("../public/client/rootark-zk1-persisted-portable-chunk-recovery");

const fields = ["format", "scope", "ownerRevision", "ownerDigest", "ownerEpoch",
  "objectRevision", "chunkSha256", "chunkLengths", "ciphertextSha256", "ciphertextRoot"];
const domain = Buffer.from("Root.ark/zk-1/persisted-portable-chunk-inventory/v1\0");
const b64 = (raw) => Buffer.from(raw).toString("base64url");
const id = () => b64(crypto.randomBytes(16));

async function fixture(t, { twoChunks = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-persisted-portable-"));
  const databaseFile = path.join(dir, "opaque.sqlite");
  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerPublicKey = await crypto.webcrypto.subtle.importKey("spki",
    owner.publicKey.export({ type: "spki", format: "der" }), "Ed25519", true, ["verify"]);
  const ownerSigningKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    owner.privateKey.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const independentOwnerSpkiSha256 = crypto.createHash("sha256").update(
    owner.publicKey.export({ type: "spki", format: "der" })).digest();
  const meta = { account_id: id(), compartment_id: b64(crypto.randomBytes(5)),
    keyring_id: id(), object_id: id(), version_id: id(), parent_version_id: null,
    epoch: 4, kind: "file" };
  const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((field) => [field, meta[field]]));
  const expectedOwnerHead = { revision: 7, digest: crypto.randomBytes(32), epoch: 4 };
  const recoverySecret = portable.generateRecoverySecret();
  const plaintext = Buffer.from("secret owner content only client may decrypt after persisted restart");
  const bundle = await portable.sealForUserHeldSecret({ recoverySecret,
    metadata: meta, name: "secret.txt", mediaType: "text/plain", data: plaintext });
  const ciphertext = Buffer.from(bundle.ciphertextBase64, "base64url");
  const chunks = twoChunks
    ? [ciphertext.subarray(0, 42), ciphertext.subarray(42)]
    : [ciphertext.subarray(0, 42), ciphertext.subarray(42, 151),
      ciphertext.subarray(151)];
  assert.ok(chunks.every((chunk) => chunk.length > 0));
  const sourceChunkRoot = Buffer.from(await roots.computeCiphertextRoot(chunks));
  function signInventory(head = expectedOwnerHead, data = chunks, signingKey = owner.privateKey) {
    const record = { format: "rootark-zk1-persisted-portable-chunk-inventory/v1", scope,
      ownerRevision: head.revision, ownerDigest: b64(head.digest), ownerEpoch: head.epoch,
      objectRevision: bundle.objectRevision,
      chunkSha256: data.map((part) => b64(crypto.createHash("sha256").update(part).digest())),
      chunkLengths: data.map((part) => part.length),
      ciphertextSha256: bundle.ciphertextSha256, ciphertextRoot: bundle.ciphertextRoot };
    return { ...record, signature: b64(crypto.sign(null, Buffer.concat([domain,
      Buffer.from(JSON.stringify(Object.fromEntries(fields.map((name) => [name, record[name]]))))]),
    signingKey)) };
  }
  const inventory = await createSignedPersistedPortableChunkInventory({
    bundle, ownerSigningKey, ownerPublicKey, independentOwnerSpkiSha256,
    ownerHead: expectedOwnerHead, chunks, assertLive: () => undefined,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(inventory)), signInventory());
  let db = new DatabaseSync(databaseFile);
  db.exec("CREATE TABLE archive (id INTEGER PRIMARY KEY, payload TEXT NOT NULL, inventory TEXT NOT NULL)");
  db.exec("CREATE TABLE chunk (ordinal INTEGER PRIMARY KEY, opaque BLOB NOT NULL)");
  db.prepare("INSERT INTO archive VALUES (1, ?, ?)").run(JSON.stringify(bundle), JSON.stringify(inventory));
  const insert = db.prepare("INSERT INTO chunk VALUES (?, ?)");
  chunks.forEach((part, index) => insert.run(index, Buffer.from(part)));
  db.close();
  t.after(() => {
    if (db.isOpen) db.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  // All material is recovered from the SQLite file after a genuine close/open.
  function restart() { db = new DatabaseSync(databaseFile); }
  function close() { db.close(); }
  const recover = async (overrides = {}) => {
    const stored = db.prepare("SELECT payload, inventory FROM archive WHERE id=1").get();
    return recoverPersistedPortableChunks({ bundle: JSON.parse(stored.payload),
      signedInventory: JSON.parse(stored.inventory), expectedOwnerHead,
      ownerPublicKey, independentOwnerSpkiSha256,
      expectedMetadata: meta, independentlyPinnedCiphertextRoot:
        Buffer.from(bundle.ciphertextRoot, "base64url"), recoverySecret,
      independentlyPinnedSourceChunkRoot: sourceChunkRoot,
      readChunk: async ({ index }) => db.prepare("SELECT opaque FROM chunk WHERE ordinal=?")
        .get(index)?.opaque, assertLive: () => undefined, ...overrides });
  };
  return { db: () => db, databaseFile, restart, close, recover, signInventory, plaintext,
    inventory, expectedOwnerHead, recoverySecret, owner, ownerPublicKey,
    ownerSigningKey, independentOwnerSpkiSha256, meta,
    chunks, bundle, sourceChunkRoot };
}

test("real two-chunk source root is independently required alongside portable single-chunk wrapping root", async (t) => {
  const f = await fixture(t, { twoChunks: true });
  f.restart();
  assert.deepEqual(f.sourceChunkRoot, computeZk1CiphertextRoot(f.chunks),
    "the source pin must use the exact native provider/owner checkpoint root transcript");
  assert.notDeepEqual(f.sourceChunkRoot,
    Buffer.from(f.bundle.ciphertextRoot, "base64url"),
    "the native owner-rooted two-chunk transcript is distinct from portable wrapping context");
  const restored = await f.recover();
  assert.deepEqual(Buffer.from(restored.data), f.plaintext);
  assert.equal(restored.sourceChunkRootVerifiedAgainstIndependentPin, true);
  restored.data.fill(0);
  await assert.rejects(f.recover({ independentlyPinnedSourceChunkRoot:
    Buffer.from(f.bundle.ciphertextRoot, "base64url") }),
  /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/,
  "a bundle's own portable root must not be accepted as the independently pinned native root");
  await assert.rejects(f.recover({ independentlyPinnedSourceChunkRoot: undefined }),
    /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/,
  "source authority cannot be silently omitted");
  f.recoverySecret.fill(0);
});

test("persisted SQLite ciphertext chunks restore only after signed inventory and real AES-GCM checks", async (t) => {
  const f = await fixture(t);
  f.restart();
  const result = await f.recover();
  assert.deepEqual(Buffer.from(result.data), f.plaintext);
  assert.equal(result.persistedChunkInventoryVerified, true);
  assert.equal(result.ownerSignatureVerified, true);
  assert.equal(result.authorizesProductionRestore, false);
  assert.equal(result.independentRemoteDurabilityProven, false);
  result.data.fill(0);
  f.recoverySecret.fill(0);
});

test("persisted restart refuses missing/corrupt chunks, signed old head, forked key and wrong recovery secret", async (t) => {
  const f = await fixture(t);
  f.restart();
  const denied = /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/;
  await assert.rejects(f.recover({ recoverySecret: crypto.randomBytes(32) }), denied);
  await assert.rejects(f.recover({ expectedOwnerHead: { ...f.expectedOwnerHead,
    revision: f.expectedOwnerHead.revision + 1 } }), denied);
  await assert.rejects(f.recover({ independentOwnerSpkiSha256: crypto.randomBytes(32) }), denied);
  await assert.rejects(f.recover({ expectedMetadata: { ...f.meta, epoch: 5 } }), denied);
  const forged = f.signInventory(f.expectedOwnerHead, f.chunks,
    crypto.generateKeyPairSync("ed25519").privateKey);
  await assert.rejects(f.recover({ signedInventory: forged }), denied);
  f.db().prepare("DELETE FROM chunk WHERE ordinal=1").run();
  await assert.rejects(f.recover(), denied, "missing persisted chunk must not fall back to bundle data");
  f.db().prepare("INSERT INTO chunk VALUES (?, ?)").run(1, Buffer.from(f.chunks[1]));
  f.db().prepare("UPDATE chunk SET opaque=? WHERE ordinal=2").run(crypto.randomBytes(f.chunks[2].length));
  await assert.rejects(f.recover(), denied, "same-length replacement must fail before decrypt");
  f.db().prepare("UPDATE chunk SET opaque=? WHERE ordinal=2").run(Buffer.from(f.chunks[2]));
  const live = await f.recover();
  assert.deepEqual(Buffer.from(live.data), f.plaintext);
  live.data.fill(0);
  f.recoverySecret.fill(0);
});

test("persisted SQLite rollback and owner-key fork cannot cross an independently retained newer head", async (t) => {
  const f = await fixture(t);
  const newerHead = { revision: f.expectedOwnerHead.revision + 1,
    digest: crypto.randomBytes(32), epoch: f.expectedOwnerHead.epoch };
  // Capture an actual older SQLite snapshot after closing its connection.
  const olderFile = fs.readFileSync(f.databaseFile);
  f.restart();
  const latestInventory = f.signInventory(newerHead);
  f.db().prepare("UPDATE archive SET inventory=? WHERE id=1")
    .run(JSON.stringify(latestInventory));
  await assert.rejects(f.recover(), /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/,
    "an independently retained old owner head cannot approve newer inventory");
  const latest = await f.recover({ expectedOwnerHead: newerHead });
  assert.deepEqual(Buffer.from(latest.data), f.plaintext);
  latest.data.fill(0);
  f.close();

  // A storage administrator restores an old, correctly signed complete DB.
  // The independent latest head remains outside that DB and blocks release.
  fs.writeFileSync(f.databaseFile, olderFile);
  f.restart();
  await assert.rejects(f.recover({ expectedOwnerHead: newerHead }),
    /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/);
  const attacker = crypto.generateKeyPairSync("ed25519");
  f.db().prepare("UPDATE archive SET inventory=? WHERE id=1")
    .run(JSON.stringify(f.signInventory(newerHead, f.chunks, attacker.privateKey)));
  await assert.rejects(f.recover({ expectedOwnerHead: newerHead }),
    /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/,
    "valid signature by an unrelated owner cannot fork retained trust");
  f.recoverySecret.fill(0);
});

test("local authority revocation while persisted chunks stream prevents plaintext release", async (t) => {
  const f = await fixture(t);
  f.restart();
  let active = true;
  let reads = 0;
  await assert.rejects(f.recover({
    readChunk: async ({ index }) => {
      const data = f.db().prepare("SELECT opaque FROM chunk WHERE ordinal=?").get(index)?.opaque;
      reads++;
      if (reads === 2) active = false;
      return data;
    },
    assertLive: () => active ? undefined : false,
  }), /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/);
  assert.equal(reads, 2, "revocation must interrupt later chunk retrieval");
  f.recoverySecret.fill(0);
});

test("backup signer refuses mismatched persisted ciphertext and mismatched owner credential", async (t) => {
  const f = await fixture(t);
  f.restart();
  const basic = { bundle: f.bundle, ownerSigningKey: f.ownerSigningKey,
    ownerPublicKey: f.ownerPublicKey,
    independentOwnerSpkiSha256: f.independentOwnerSpkiSha256,
    ownerHead: f.expectedOwnerHead, chunks: f.chunks,
    assertLive: () => undefined };
  await assert.rejects(createSignedPersistedPortableChunkInventory({ ...basic,
    chunks: [f.chunks[0], crypto.randomBytes(f.chunks[1].length), f.chunks[2]] }),
  /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/);
  await assert.rejects(createSignedPersistedPortableChunkInventory({ ...basic,
    independentOwnerSpkiSha256: crypto.randomBytes(32) }),
  /ZK_PERSISTED_PORTABLE_RECOVERY_DENIED/);
  assert.deepEqual(Buffer.from((await f.recover()).data).toString("utf8"),
    f.plaintext.toString("utf8"));
  f.recoverySecret.fill(0);
});

test("browser client recovery binding loads without Node APIs", () => {
  const ctx = vm.createContext({ crypto: crypto.webcrypto, TextEncoder, TextDecoder,
    atob, btoa, Uint8Array, ArrayBuffer,
    RootarkZk1PortableFileRecovery: portable,
    RootarkZk1CiphertextRoot: require("../public/client/rootark-zk1-ciphertext-chunk-root") });
  vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-persisted-portable-chunk-recovery.js"), "utf8"), ctx);
  assert.equal(typeof ctx.RootarkZk1PersistedPortableChunkRecovery
    .recoverPersistedPortableChunks, "function");
  assert.equal(typeof ctx.RootarkZk1PersistedPortableChunkRecovery
    .createSignedPersistedPortableChunkInventory, "function");
});
