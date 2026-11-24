"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const express = require("express");

const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const zk = require("../src/crypto/rootark-zk-1");
const { SyncEngine, normalizeExcludedPaths } = require("../sync-client/rootark-sync-engine");
const { safeJsonStringify } = require("../sync-client/rootark-sync-journal");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { trustedAtomicBatchWitnessOptions } = require("../sync-client/rootark-sync-v2");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { runMigrations } = require("../db/migrations");
const { closeDb } = require("../db");
const usersRepository = require("../repositories/usersRepository");
const { DOMAIN: OWNER_PROVISION_DOMAIN } =
  require("../sync-client/rootark-sync-atomic-owner-provision");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

// Read recovery witnesses through an independently opened regular-file handle.
// A pathname observed during recovery may be rebound before the test reaches
// its assertions; the byte oracle must authenticate the descriptor it reads.
async function readHeldRegularFile(filename, expectedIdentity = null) {
  const handle = await fsp.open(filename, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const before = await handle.stat({ bigint: true });
    assert.equal(before.isFile() && !before.isSymbolicLink(), true);
    if (expectedIdentity) {
      assert.equal(before.dev, expectedIdentity.dev);
      assert.equal(before.ino, expectedIdentity.ino);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(after.size, before.size);
    return bytes;
  } finally { await handle.close(); }
}

test("#262 P2: bounded CBOR snapshot admits the supported 16,384-wrap history shape", async () => {
  const keyRef = Buffer.alloc(32, 1);
  const wrapId = Buffer.alloc(16, 2);
  const enc = Buffer.alloc(32, 3);
  const ciphertext = Buffer.alloc(48, 4);
  const wraps = new Array(16_384);
  for (let index = 0; index < wraps.length; index += 1) {
    wraps[index] = {
      device_id: `device-${String(index % 256).padStart(3, "0")}`,
      epoch: (index % 64) + 1,
      key_ref: keyRef,
      wrap_id: wrapId,
      enc,
      ciphertext,
    };
  }
  const serialized = await zk.encodeDeterministic({ wraps });
  assert.ok(serialized.byteLength < 8 * 1024 * 1024);
});

test("#262 P2: v2 envelope opener classifies absent input before map validation", async () => {
  await assert.rejects(zk.openAuthorizationEnvelopeV2(null),
    { code: "INVALID_AUTHORIZATION_INPUT" });
  await assert.rejects(zk.openAuthorizationEnvelopeV2(undefined),
    { code: "INVALID_AUTHORIZATION_INPUT" });
});

test("#262 P2: excluded path traversal has a stable unsafe_path classification", () => {
  assert.throws(() => normalizeExcludedPaths(["../escape"]), { code: "unsafe_path" });
});

const RESTORE_WITNESS_DOMAIN = "rootark-sync-historical-restore-physical-witness-v1\0";
const RESTORE_CURRENT_DOMAIN = "rootark-sync-historical-restore-physical-current-v1\0";
const nativeFetch = globalThis.fetch.bind(globalThis);

test("#262 P1: journal snapshot refuses Proxy traps before serializing durable signed state", () => {
  let invoked = 0;
  const proxy = new Proxy({ operationId: "histrestore-fake" }, {
    ownKeys() { invoked += 1; throw new Error("untrusted ownKeys executed"); },
    getOwnPropertyDescriptor() { invoked += 1; throw new Error("untrusted descriptor executed"); },
  });
  assert.throws(() => safeJsonStringify({ pending: [proxy] }), /proxy values are not trusted/);
  assert.equal(invoked, 0);
});

test("#262 P1: a signed authorization cannot retain a revoked device across asynchronous CBOR", async (t) => {
  const f = await fixture(t);
  const expected = { username: "alice",
    trustedDevicePublicKeys: { "device-a": f.publicKeySpki }, revokedDeviceIds: [] };
  const inFlight = verifyAuthorizationProof(f.original.authorization, f.original, expected);
  expected.revokedDeviceIds.push("device-a");
  await assert.rejects(inFlight, (error) => error.code === "authorization_device_revoked");

  const otherPolicy = { username: "alice",
    trustedDevicePublicKeys: { "device-a": f.publicKeySpki }, revokedDeviceIds: [] };
  const another = verifyAuthorizationProof(f.original.authorization, f.original, otherPolicy);
  otherPolicy.trustedDevicePublicKeys["device-a"] = "replaced-untrusted-key";
  await assert.rejects(another, (error) => error.code === "authorization_device_untrusted");
});

test("#262 P2: a real signed grant expiring during asynchronous CBOR is rejected", async (t) => {
  const f = await fixture(t);
  // Isolate the pre-require clock and CBOR await in a child process. The
  // signature, encrypted operation, device pin and CBOR implementation remain
  // genuine; only the trusted clock advances at a deterministic await point.
  const script = `
    const assert = require("node:assert/strict");
    const zk = require(process.argv[1]);
    const originalEncode = zk.encodeDeterministic;
    const payload = JSON.parse(Buffer.from(process.argv[3], "base64url").toString("utf8"));
    const expiry = payload.proof.expiresAt;
    let clock = expiry - 1;
    let advanceAtAwait = false;
    Date.now = () => clock;
    zk.encodeDeterministic = async (...args) => {
      const bytes = await originalEncode(...args);
      if (advanceAtAwait) clock = expiry + 1;
      return bytes;
    };
    const { verifyAuthorizationProof } = require(process.argv[2]);
    (async () => {
      assert.equal(await verifyAuthorizationProof(payload.proof, payload.operation, payload.expected), true);
      clock = expiry - 1;
      advanceAtAwait = true;
      await assert.rejects(
        verifyAuthorizationProof(payload.proof, payload.operation, payload.expected),
        (error) => error.code === "authorization_expired",
      );
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `;
  const payload = Buffer.from(JSON.stringify({
    proof: f.original.authorization, operation: f.original, expected: f.trusted,
  })).toString("base64url");
  const result = spawnSync(process.execPath, ["-e", script,
    require.resolve("../src/crypto/rootark-zk-1"),
    require.resolve("../sync-client/rootark-sync-authorization"), payload], {
    encoding: "utf8", windowsHide: true, timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
});

test("#67 P1: exported Sync v2 witness helper cannot bypass the disabled external-admission gate", () => {
  let proxyTrapCalls = 0;
  const untrustedOptions = new Proxy({}, {
    get() { proxyTrapCalls += 1; throw new Error("untrusted witness getter executed"); },
    ownKeys() { proxyTrapCalls += 1; throw new Error("untrusted witness ownKeys executed"); },
  });
  assert.throws(() => trustedAtomicBatchWitnessOptions(untrustedOptions, true),
    /disabled pending full provider-chain hardening/);
  assert.deepEqual(trustedAtomicBatchWitnessOptions(untrustedOptions, false), {});
  assert.equal(proxyTrapCalls, 0, "the exported helper must fail closed without touching proxy traps");
  assert.throws(() => trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: {} }, false),
    /requires independently pinned readback and external CAS floor/,
    "pair-only mode must not silently accept a caller-supplied witness");
});

function configureStrictSqliteAuthority(t) {
  const directory = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, "rootark-issue-67-authority-" + crypto.randomBytes(8).toString("hex"))
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue-67-authority-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(directory);
  const prior = {
    DATABASE_URL: process.env.DATABASE_URL,
    DB_ENABLED: process.env.DB_ENABLED,
    DB_WRITE_LEGACY_JSON: process.env.DB_WRITE_LEGACY_JSON,
  };
  process.env.DATABASE_URL = path.join(directory, "accounts.sqlite");
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  runMigrations({ backup: false });
  usersRepository.saveUsers([{
    username: "alice",
    role: "user",
    password: "fixture",
    sessionVersion: 0,
    permissions: { upload: true, delete: true },
  }]);
  t.after(() => {
    closeDb();
    for (const [name, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
}

const issue67ZkBytes = (value, length = 8) => Buffer.alloc(length, value);
function issue67ZkManifestV1() {
  return {
    type: "rootark-authorization-manifest-v1", suite: zk.SUITE_ID, envelope_version: 1,
    compartment_id: issue67ZkBytes(1), epoch: 7, purpose: "content",
    sender_key_id: issue67ZkBytes(2), recipient_key_id: issue67ZkBytes(3),
    object_id: issue67ZkBytes(4), version_id: issue67ZkBytes(5), key_ref: issue67ZkBytes(6),
    expiry: 9223372036854775807n, replay_id: issue67ZkBytes(7),
    idempotency_key: issue67ZkBytes(8), wrap_id: issue67ZkBytes(9, 16),
    hpke_enc: issue67ZkBytes(10, 32), hpke_info_digest: issue67ZkBytes(11, 32),
    wrapped_key_digest: issue67ZkBytes(12, 32), ciphertext_digest: issue67ZkBytes(13, 32),
  };
}

test("#262 P2: v1 signed authorization accepts its original numeric epoch scope", async () => {
  const signed = issue67ZkManifestV1();
  const signer = crypto.generateKeyPairSync("ed25519");
  const signature = await zk.signAuthorization(signed, signer.privateKey);
  assert.equal(await zk.verifyAuthorization(signed, signature, signer.publicKey,
    { epoch: 7 }), true,
  "v1 source epoch 7 and expected numeric epoch 7 must have matching semantics");
  await assert.rejects(zk.verifyAuthorization(signed, signature, signer.publicKey,
    { epoch: 8 }), (error) => error.code === "SCOPE_MISMATCH");
});

function issue67ZkStaticCoreV2() {
  return {
    type: "rootark-authorization-manifest-v2", suite: zk.SUITE_ID, envelope_version: 2,
    compartment_id: issue67ZkBytes(1), epoch: 7, purpose: "content",
    sender_key_id: issue67ZkBytes(2), recipient_key_id: issue67ZkBytes(3),
    object_id: issue67ZkBytes(4), version_id: issue67ZkBytes(5), key_ref: issue67ZkBytes(6),
    expiry: 1000n, replay_id: issue67ZkBytes(7), idempotency_key: issue67ZkBytes(8),
    wrap_id: issue67ZkBytes(9, 16),
  };
}

// Test-only simulated custody: separate signing keys verify an on-disk file
// reopened on every challenge. This is NOT an independently deployed operator.
// A dedicated production-store test below additionally uses SyncObjectStore.
function simulatedRestorePhysicalAuthority(root) {
  const witness = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const owner = crypto.generateKeyPairSync("ed25519");
  const spki = (pair) => pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const signing = (pair, domain, statement) => ({ statement,
    signature: crypto.sign(null, Buffer.from(domain + protocol.canonicalJson(statement)),
      pair.privateKey).toString("base64url") });
  const scope = "alice:historical-restore";
  const identity = { accountId: crypto.randomUUID(), storeId: crypto.randomUUID(),
    username: "alice", compartmentId: "private" };
  const provisioning = signing(owner, OWNER_PROVISION_DOMAIN, {
    type: "atomic-owner-provisioning", version: 1, scope, ...identity,
    witnessSpki: spki(witness), casSpki: spki(cas), sequence: 1,
  });
  const digest = crypto.createHash("sha256")
    .update(OWNER_PROVISION_DOMAIN + protocol.canonicalJson(provisioning)).digest("hex");
  const statePath = path.join(root, "witness-store-current.json");
  let sequence = 0;
  const reopen = async () => JSON.parse(await fsp.readFile(statePath, "utf8"));
  let currentPhysicalRead = reopen;
  const physicalStoreCommitted = async (operation) => {
    const state = { operation, commitId: crypto.randomBytes(24).toString("base64url"),
      fencingEpoch: ++sequence };
    state.storeHeadSha256 = crypto.createHash("sha256")
      .update(protocol.canonicalJson(operation)).digest("hex");
    const temporary = `${statePath}.tmp-${crypto.randomUUID()}`;
    const handle = await fsp.open(temporary, "wx", 0o600);
    try { await handle.writeFile(protocol.canonicalJson(state)); await handle.sync(); }
    finally { await handle.close(); }
    await fsp.rename(temporary, statePath);
    if (process.platform !== "win32") {
      const directory = await fsp.open(root, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0));
      try { await directory.sync(); } finally { await directory.close(); }
    }
  };
  const options = {
    atomicBatchWitnessScope: scope,
    atomicBatchOwnerIdentity: identity,
    atomicBatchOwnerProvisionerPublicKey: spki(owner),
    atomicBatchOwnerProvisioning: provisioning,
    atomicBatchOwnerProvisionDigest: digest,
    atomicBatchWitnessPublicKey: spki(witness),
    atomicBatchCasFloorPublicKey: spki(cas),
    async atomicBatchWitnessReadback({ nonce, operationIds, envelopeDigests }) {
      const disk = await currentPhysicalRead();
      assert.deepEqual(operationIds, [disk.operation.operationId]);
      assert.deepEqual(envelopeDigests, [crypto.createHash("sha256")
        .update(protocol.canonicalJson(disk.operation)).digest("hex")]);
      return signing(witness, RESTORE_WITNESS_DOMAIN, {
        version: 2, scope, ...identity, nonce, operationIds, envelopeDigests,
        commitId: disk.commitId, storeHeadSha256: disk.storeHeadSha256,
        fencingEpoch: disk.fencingEpoch, physicalDurable: true,
      });
    },
    async atomicBatchCasFloorReadback({ nonce, commitId, storeHeadSha256, fencingEpoch }) {
      const disk = await currentPhysicalRead();
      assert.equal(disk.commitId, commitId);
      assert.equal(disk.storeHeadSha256, storeHeadSha256);
      assert.equal(disk.fencingEpoch, fencingEpoch);
      assert.equal(crypto.createHash("sha256")
        .update(protocol.canonicalJson(disk.operation)).digest("hex"), storeHeadSha256);
      return signing(cas, RESTORE_CURRENT_DOMAIN, {
        version: 2, scope, accountId: identity.accountId, storeId: identity.storeId,
        nonce, commitId, storeHeadSha256, fencingEpoch, sequence: disk.fencingEpoch,
        current: true,
      });
    },
  };
  return { physicalStoreCommitted, options,
    // Test-only: bind both signing callbacks to a fresh reopening of the real
    // SyncObjectStore disk image. No new trust source is exposed in production.
    useReopenedPhysicalSource(reader) { currentPhysicalRead = reader; },
  };
}

async function restoreRecoveredBytesOnlyIfVacant(target, bytes) {
  // This helper is deliberately test-only. Recovery must never overwrite a
  // path another writer creates after the earlier existence assertion.
  const file = await fsp.open(target, "wx", 0o600);
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
}

test("#67: restore CLI rejects an incomplete request before reading private credentials", () => {
  const command = spawnSync(process.execPath, [path.join(__dirname, "../sync-client/rootark-sync-v2.js"),
    "restore", "--config", "missing-private-config", "--object-id", "file-1"], { encoding: "utf8", windowsHide: true });
  assert.equal(command.status, 1);
  assert.match(command.stderr, /version-id/i);
  assert.doesNotMatch(command.stdout + command.stderr, /ROOTARK_SYNC_FILE_KEY|token|privateKey/);
});

async function fixture(t) {
  const root = createPrivateAuthorityFixture("rootark-67-restore-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const local = path.join(root, "client");
  await fsp.mkdir(local);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeySpki = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const privateFileKey = crypto.randomBytes(32);
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKeySpki }, revokedDeviceIds: [] };
  const sign = async (input, authorizationOptions = {}) => {
    const operation = protocol.createOperation({
      objectId: "file-1", fileId: "file-1", deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", fileKey: privateFileKey, ...input,
    });
    return { ...operation, authorization: await createAuthorizationProof(operation, {
      username: "alice", privateKey, publicKey: publicKeySpki, ...authorizationOptions,
    }) };
  };
  const original = await sign({ operation: "create", versionId: "first", operationId: "first-op",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("original authenticated bytes") });
  const deleted = await sign({ operation: "delete", versionId: "deleted", operationId: "delete-op",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: original.revision,
    metadata: { path: "document.txt" } });
  let current = deleted;
  const versions = [original, deleted];
  let pushes = 0;
  const physical = simulatedRestorePhysicalAuthority(root);
  const adapter = {
    history: async () => ({ protocolVersion: 2, versions: versions.map((record) => structuredClone(record)) }),
    list: async () => structuredClone(current),
    push: async (operation) => {
      pushes += 1;
      protocol.validateFreshSignedOperation(operation);
      assert.equal(await verifyAuthorizationProof(operation.authorization, operation, trusted), true);
      if (protocol.compareRevisions(operation.baseRevision, current.revision) !== 0) {
        const err = new Error("Stale revision");
        err.status = 409;
        throw err;
      }
      current = structuredClone(operation);
      versions.push(current);
      await physical.physicalStoreCommitted(current);
      return structuredClone(current);
    },
  };
  const engine = await new SyncEngine({
    rootDir: local, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => privateFileKey, requireAuthorization: true,
    authorize: () => true, authorizeOutgoing: () => !trusted.revokedDeviceIds.includes("device-a"),
    verifyIncoming: (record) => verifyAuthorizationProof(record.authorization, record, trusted),
    authorizationFactory: (operation) => createAuthorizationProof(operation, {
      username: "alice", privateKey, publicKey: publicKeySpki,
    }),
    ...physical.options,
  }).open();
  return { root, local, engine, original, deleted, versions, trusted, adapter, sign, privateKey, publicKey,
    privateFileKey, publicKeySpki,
    setCurrent: (value) => { current = value; },
    physical, pushes: () => pushes, current: () => current };
}

test("#262 P2: generic strict admission cannot replace its adapter through a callback accessor", async (t) => {
  const f = await fixture(t);
  const rootDir = path.join(f.root, "generic-adapter-identity");
  const adapter = { push: async () => ({ status: 200 }), list: async () => [] };
  const replacement = { push: async () => ({ status: 200 }), list: async () => [] };
  let engine;
  let callbackCalls = 0;
  let adapterReads = 0;
  let mutationBlocked = false;
  engine = new SyncEngine({
    rootDir, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    requireAuthorization: true, authorize: () => true,
    verifyIncoming: async () => {
      callbackCalls += 1;
      try {
        Object.defineProperty(engine, "adapter", {
          configurable: true,
          enumerable: true,
          get() {
            adapterReads += 1;
            return adapterReads <= 3 ? adapter : replacement;
          },
        });
      } catch { mutationBlocked = true; }
      return true;
    },
  });
  await engine.open();

  await engine.verifyIncomingOperation(f.original);

  assert.equal(callbackCalls, 1);
  assert.equal(mutationBlocked, true,
    "the adapter reference must be pinned even without owner-provision authority");
  const descriptor = Object.getOwnPropertyDescriptor(engine, "adapter");
  assert.equal(descriptor.configurable, false);
  assert.equal(descriptor.writable, false);
  assert.equal(descriptor.value, adapter);
  assert.equal(engine.adapter, adapter);
  assert.equal(adapterReads, 0, "a callback-installed accessor must never run");
});

test("#67 P1: SyncEngine owner provisioning rejects proxies, accessors and poisoned crypto intrinsics before verification", async (t) => {
  const f = await fixture(t);
  const makeOptions = (overrides = {}) => ({
    rootDir: path.join(f.root, "owner-provision-guard"), adapter: f.adapter,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => f.privateFileKey, authorize: () => true,
    authorizeOutgoing: () => true, requireAuthorization: true,
    verifyIncoming: (record) => verifyAuthorizationProof(record.authorization, record, f.trusted),
    authorizationFactory: (operation) => createAuthorizationProof(operation, {
      username: "alice", privateKey: f.privateKey, publicKey: f.publicKeySpki,
    }),
    ...f.physical.options,
    ...overrides,
  });

  let proxyTrapCalls = 0;
  const proxyProvisioning = new Proxy(f.physical.options.atomicBatchOwnerProvisioning, {
    ownKeys(target) { proxyTrapCalls += 1; return Reflect.ownKeys(target); },
  });
  assert.throws(() => new SyncEngine(makeOptions({ atomicBatchOwnerProvisioning: proxyProvisioning })),
    (error) => error.code === "authorization_required");
  assert.equal(proxyTrapCalls, 0, "owner provisioning Proxy traps must not execute");

  let getterCalls = 0;
  const accessorProvisioning = { ...f.physical.options.atomicBatchOwnerProvisioning };
  Object.defineProperty(accessorProvisioning, "signature", {
    configurable: true, enumerable: true,
    get() { getterCalls += 1; return f.physical.options.atomicBatchOwnerProvisioning.signature; },
  });
  assert.throws(() => new SyncEngine(makeOptions({ atomicBatchOwnerProvisioning: accessorProvisioning })),
    (error) => error.code === "authorization_required");
  assert.equal(getterCalls, 0, "owner provisioning accessors must not execute");

  const adversarialOwnerKey = {};
  Object.defineProperty(adversarialOwnerKey, "key", {
    enumerable: true,
    get() { getterCalls += 1; crypto.verify = () => true; return f.publicKeySpki; },
  });
  assert.throws(() => new SyncEngine(makeOptions({
    atomicBatchOwnerProvisionerPublicKey: adversarialOwnerKey,
  })), (error) => error.code === "authorization_required");
  assert.equal(getterCalls, 0, "untrusted owner key getters cannot poison the provisioning verifier");

  const adversarialDigest = {
    [Symbol.toPrimitive]() {
      getterCalls += 1;
      return f.physical.options.atomicBatchOwnerProvisionDigest;
    },
  };
  assert.throws(() => new SyncEngine(makeOptions({
    atomicBatchOwnerProvisionDigest: adversarialDigest,
  })), (error) => error.code === "authorization_required");
  assert.equal(getterCalls, 0, "untrusted digest conversion cannot run inside owner signature verification");

  const originalVerify = crypto.verify;
  try {
    crypto.verify = () => true;
    assert.throws(() => new SyncEngine(makeOptions()),
      (error) => error.code === "authorization_required");
  } finally {
    crypto.verify = originalVerify;
  }
});

test("#262 P2: bounded canonical JSON preserves shared DAGs, rejects cycles and blocks exponential aliases", async (t) => {
  const leaf = { value: 1 };
  const shared = { a: leaf, b: leaf };
  assert.equal(protocol.canonicalJson({ first: shared, second: shared }),
    '{"first":{"a":{"value":1},"b":{"value":1}},"second":{"a":{"value":1},"b":{"value":1}}}');
  const reserved = JSON.parse('{"__proto__":{"polluted":true},"constructor":{"value":1}}');
  assert.equal(protocol.canonicalJson(reserved),
    '{"__proto__":{"polluted":true},"constructor":{"value":1}}');
  assert.equal(Object.prototype.polluted, undefined,
    "canonical JSON reserved keys must never mutate the ambient prototype");

  const originalSort = Array.prototype.sort;
  try {
    Array.prototype.sort = () => { throw new Error("poisoned array sort"); };
    assert.equal(protocol.canonicalJson({ z: 3, a: 1, m: 2 }),
      '{"a":1,"m":2,"z":3}', "canonical sorting must use the pre-callback native method");
  } finally { Array.prototype.sort = originalSort; }

  for (const escaped of ['"\\\b\t\n\f\r\u0000\u001f', '\uD800', '\uDC00', '\uD83D\uDE80', 'á\u2028é']) {
    assert.equal(protocol.canonicalJson({ text: escaped }), JSON.stringify({ text: escaped }),
      "the preflight byte count must allow the exact JSON escape representation");
  }
  // This safely printable string is far below 64 MiB as transmitted JSON.
  // The old blanket 6-bytes-per-code-unit estimate falsely rejected it.
  const longAscii = "A".repeat(11 * 1024 * 1024);
  const longJson = protocol.canonicalJson({ payload: longAscii });
  assert.equal(Buffer.byteLength(longJson, "utf8"), longAscii.length + '{"payload":""}'.length);

  const cycle = { name: "cycle" };
  cycle.self = cycle;
  assert.throws(() => protocol.canonicalJson(cycle), /Cyclic JSON graph/);

  // Only 26 objects exist, but an unchecked 25-level binary alias expands
  // into hundreds of megabytes. Budget arithmetic must reject before clone.
  let amplifier = { value: "x" };
  for (let index = 0; index < 25; index += 1) amplifier = { a: amplifier, b: amplifier };
  assert.throws(() => protocol.canonicalJson(amplifier),
    (error) => error.code === "payload_too_large");

  const f = await fixture(t);
  const makeEngine = (ownerProvisioning) => new SyncEngine({
    rootDir: path.join(f.root, "bounded-owner-input"), adapter: f.adapter,
    requireAuthorization: true, ...f.physical.options,
    atomicBatchOwnerProvisioning: ownerProvisioning,
  });
  // The owner JSON guard must accept small aliases; only the later invalid
  // certificate schema/signature can reject this deliberately unsigned input.
  assert.throws(() => makeEngine({ statement: shared, signature: shared }),
    (error) => error.code === "authorization_required"
      && /not independently authenticated/.test(error.message));
  assert.throws(() => makeEngine(amplifier), (error) => error.code === "authorization_required");
  assert.throws(() => makeEngine(cycle), (error) => error.code === "authorization_required");
  assert.throws(() => makeEngine(JSON.stringify({ oversized: "x".repeat(65 * 1024) })),
    (error) => error.code === "authorization_required");

  let tooDeep = { value: "x" };
  for (let index = 0; index < 70; index += 1) tooDeep = { child: tooDeep };
  assert.throws(() => protocol.canonicalJson(tooDeep),
    (error) => error.code === "payload_too_large");
  assert.throws(() => makeEngine(tooDeep), (error) => error.code === "authorization_required");

  // A memoized subtree first seen through a shallow path must still fail
  // when another alias reaches it at a greater absolute depth.
  let sharedDepth = { value: "x" };
  for (let index = 0; index < 21; index += 1) sharedDepth = { child: sharedDepth };
  const shallowJson = protocol.canonicalJson({ short: sharedDepth }, true);
  assert.equal(typeof shallowJson, "string", "depth-24 short path must serialize before cache reuse");
  assert.equal((shallowJson.match(/"child":/g) || []).length, 21);
  const equalDepthJson = protocol.canonicalJson({ first: sharedDepth, second: sharedDepth }, true);
  assert.equal((equalDepthJson.match(/"child":/g) || []).length, 42,
    "reusing the cached subtree at the same depth must remain valid");
  const compactNumbers = { values: Array.from({ length: 800 }, (_, index) => index) };
  assert.equal(protocol.canonicalJson(compactNumbers, true), JSON.stringify(compactNumbers),
    "bounded owner JSON must accept compact numeric arrays without inflated byte estimates");
  const ownerBoundaryOverhead = '{"payload":""}'.length;
  const ownerBoundary = { payload: "A".repeat(64 * 1024 - ownerBoundaryOverhead) };
  assert.equal(Buffer.byteLength(protocol.canonicalJson(ownerBoundary, true), "utf8"), 64 * 1024,
    "exactly 64 KiB of owner JSON must be accepted without surplus comma accounting");
  ownerBoundary.payload += "A";
  assert.throws(() => protocol.canonicalJson(ownerBoundary, true),
    (error) => error.code === "payload_too_large", "64 KiB plus one byte must fail closed");
  // The budget preflight visits own keys in insertion order. `short` must
  // populate the memo; only `long.wrapper` reaches the cached subtree at
  // depth 3, moving its value leaf to depth 25 (over the depth-24 limit).
  const aliased = { short: sharedDepth, long: { wrapper: sharedDepth } };
  assert.deepEqual(Object.keys(aliased), ["short", "long"]);
  assert.strictEqual(aliased.short, aliased.long.wrapper);
  assert.throws(() => protocol.canonicalJson(aliased, true),
    (error) => error.code === "payload_too_large");
});

test("#262 P2: CBOR snapshot bounds expanded aliases before cloning and preserves small DAGs", async () => {
  const leaf = { value: 1 };
  const shared = { first: leaf, second: leaf };
  const flattened = { first: { value: 1 }, second: { value: 1 } };
  assert.deepEqual(await zk.encodeDeterministic(shared), await zk.encodeDeterministic(flattened),
    "small acyclic aliases must encode identically to expanded data");

  let amplifier = { value: 1 };
  for (let index = 0; index < 25; index += 1) amplifier = { a: amplifier, b: amplifier };
  await assert.rejects(zk.encodeDeterministic(amplifier),
    (error) => error.code === "CBOR_VALUE_TOO_LARGE",
    "an aliased binary DAG must hit the expansion budget before consuming exponential memory");

  const cycle = { value: 1 };
  cycle.self = cycle;
  await assert.rejects(zk.encodeDeterministic(cycle),
    (error) => error.code === "UNSUPPORTED_CBOR_VALUE",
    "CBOR cycles must remain rejected rather than mistaken for legitimate aliases");

  let deep = { value: 1 };
  for (let index = 0; index < 70; index += 1) deep = { child: deep };
  await assert.rejects(zk.encodeDeterministic(deep),
    (error) => error.code === "CBOR_VALUE_TOO_LARGE",
    "the CBOR snapshot must reject excessive depth before encoder recursion");

  // TypedArray.byteLength and .length can be shadowed by own properties.
  // The snapshot must use internal-slot length and copy bytes without
  // invoking a caller-provided iterator or accepting the spoofed budget.
  const tamperedBytes = new Uint8Array([7, 9, 11, 13]);
  Object.defineProperty(tamperedBytes, "byteLength", { value: 0 });
  Object.defineProperty(tamperedBytes, "length", { value: 0 });
  Object.defineProperty(tamperedBytes, Symbol.iterator, {
    get() { throw new Error("untrusted typed-array iterator was invoked"); },
  });
  assert.deepEqual(await zk.encodeDeterministic({ bytes: tamperedBytes }),
    await zk.encodeDeterministic({ bytes: new Uint8Array([7, 9, 11, 13]) }),
    "shadowed TypedArray properties must not change CBOR bytes");

  // The snapshot owns a captured iterator method, but the returned Array
  // Iterator still resolves `next` through its mutable prototype. Poison it
  // after snapshot creation, during the awaited cborg() promise; the synchronous
  // encoder must temporarily restore the captured intrinsic for its walk.
  const expectedArrayEncoding = await zk.encodeDeterministic([1, 2]);
  assert.notDeepEqual(expectedArrayEncoding, await zk.encodeDeterministic([]),
    "positive control must distinguish the real two-item encoding from an empty array");
  const arrayIteratorPrototype = Object.getPrototypeOf(Array.prototype.values.call([]));
  const originalArrayIteratorNext = Object.getOwnPropertyDescriptor(arrayIteratorPrototype, "next");
  let poisonedArrayIteratorNextCalls = 0;
  const poisonedArrayIteratorNext = () => {
    poisonedArrayIteratorNextCalls += 1;
    return { done: true, value: undefined };
  };
  try {
    const pendingArrayEncoding = zk.encodeDeterministic([1, 2]);
    Object.defineProperty(arrayIteratorPrototype, "next", {
      ...originalArrayIteratorNext,
      value: poisonedArrayIteratorNext,
    });
    const poisonedArrayIteratorNextDescriptor = Object.getOwnPropertyDescriptor(
      arrayIteratorPrototype, "next");
    const positiveControlResult = Array.prototype.values.call([9]).next();
    assert.equal(positiveControlResult.done, true,
      "positive control proves the iterator-prototype poison is active");
    assert.equal(positiveControlResult.value, undefined);
    assert.equal(poisonedArrayIteratorNextCalls, 1);
    assert.deepEqual(await pendingArrayEncoding, expectedArrayEncoding,
      "the awaited encoder must not let mutable ArrayIteratorPrototype.next replace validated array items");
    assert.equal(poisonedArrayIteratorNextCalls, 1,
      "only the positive control may invoke the poisoned iterator next");
    assert.deepEqual(Object.getOwnPropertyDescriptor(arrayIteratorPrototype, "next"),
      poisonedArrayIteratorNextDescriptor,
      "CBOR must restore the exact caller-visible poisoned descriptor after its synchronous walk");
  } finally {
    Object.defineProperty(arrayIteratorPrototype, "next", originalArrayIteratorNext);
  }

  const oversizedBytes = new Uint8Array(64 * 1024 * 1024 + 1);
  Object.defineProperty(oversizedBytes, "byteLength", { value: 0 });
  await assert.rejects(zk.encodeDeterministic({ bytes: oversizedBytes }),
    (error) => error.code === "CBOR_VALUE_TOO_LARGE",
    "the real typed-array byte count must reject an oversized clone before allocating a second copy");
});

test("#67: restoring a deleted historical ciphertext creates a fresh signed revision and real local bytes", async (t) => {
  const f = await fixture(t);
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.restored, true);
  assert.equal(result.pushed, true);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.deepEqual(await fsp.readdir(path.join(f.local, ".rootark-trash")), [],
    "successful restore must remove its private materialization temporary");
  assert.equal(f.pushes(), 1);
  assert.equal(f.versions.length, 3);
  assert.equal(f.versions[0].versionId, "first");
  assert.equal(f.versions[1].versionId, "deleted");
  const restored = f.current();
  assert.notEqual(restored.operationId, f.original.operationId);
  assert.notEqual(restored.versionId, f.original.versionId);
  assert.equal(restored.operation, "update");
  assert.equal(restored.baseRevision.counter, 2);
  assert.equal(restored.revision.counter, 3);
  assert.equal(await verifyAuthorizationProof(restored.authorization, restored, f.trusted), true);
  assert.equal(protocol.decryptPayload(restored, f.engine.fileKeyResolver(restored)).toString(), "original authenticated bytes");
});

for (const echo of [false, true]) {
  test(`#67 P1: HTTP 200 ${echo ? "exact signed echo" : "empty ACK"} without physical CURRENT never consumes a historical restore`, async (t) => {
    const f = await fixture(t);
    let acceptedSigned = null;
    f.adapter.push = async (operation) => {
      assert.equal(await verifyAuthorizationProof(operation.authorization, operation, f.trusted), true);
      assert.match(operation.operationId, /^histrestore-/);
      acceptedSigned = structuredClone(operation);
      return echo ? structuredClone(operation) : { status: 200 };
    };
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_remote_admission_unproven",
      "HTTP and a valid client signature must not impersonate independently durable CURRENT");
    assert.ok(acceptedSigned, "the malicious server received an actual Ed25519 signed restore");
    const [pending] = await f.engine.journal.recover();
    assert.equal(pending.operationId, acceptedSigned.operationId,
      "the exact signed outbox must remain after a forged remote ACK");
    assert.equal((await f.engine.journal.recover()).length, 1);
    assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
      "original authenticated bytes", "local materialization must survive unproven ACK");
    assert.equal(f.versions.length, 2, "the server must not create a physical historical version");
  });
}

test("#67 P1: 409 with server-controlled exact signed restore echo cannot clear the outbox", async (t) => {
  const f = await fixture(t);
  let signedRequest = null;
  f.adapter.push = async (operation) => {
    signedRequest = structuredClone(operation);
    assert.equal(await verifyAuthorizationProof(operation.authorization, operation, f.trusted), true);
    throw Object.assign(new Error("server claims the restore already exists"),
      { code: "sync_conflict", status: 409, current: structuredClone(operation) });
  };
  const pendingRestore = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(pendingRestore.restored, true);
  assert.equal(pendingRestore.pushed, false);
  assert.equal(pendingRestore.pending, true, "a forged 409 cannot certify physical CURRENT");
  const [pending] = await f.engine.journal.recover();
  assert.equal(pending.operationId, signedRequest.operationId);
  assert.equal(f.versions.length, 2, "a server-controlled conflict cannot fabricate a physical commit");
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
    "original authenticated bytes");
});

test("#262 P1: ordinary markSeen cannot discharge a pending signed historical restore", async (t) => {
  const f = await fixture(t);
  const signed = await f.sign({ operation: "update",
    operationId: `histrestore-${crypto.randomUUID()}`, versionId: "unadmitted-restore",
    revision: { counter: 3, deviceId: "device-a" }, baseRevision: f.deleted.revision,
    metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("signed but not physically admitted") });
  await f.engine.journal.enqueue(signed);
  await assert.rejects(f.engine.journal.markSeen(signed.operationId),
    /independently verified markSeenExact/,
    "even a direct ordinary journal ACK must preserve the original signed restore");
  const [pending] = await f.engine.journal.recover();
  assert.equal(pending.operationId, signed.operationId);
  assert.equal(f.engine.journal.hasSeen(signed.operationId), false);
});

test("#262 P2: independent physical restore ACK promotes the durable observation", async (t) => {
  const f = await fixture(t);
  const outcome = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(outcome.pushed, true);
  const digest = f.engine.journal.durableSignedReceiptDigest(outcome.operationId);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(f.engine.journal.state.admitted[outcome.operationId], digest,
    "independently verified acknowledgement must promote the exact signed receipt");
  assert.equal(Object.hasOwn(f.engine.journal.state.observed, outcome.operationId), false,
    "the pre-observation must not consume a slot after physical admission");
  assert.deepEqual(await f.engine.journal.recover(), []);
});

test("#262 P1: excluded signed restore LIST echo cannot consume pending physical admission", async (t) => {
  const f = await fixture(t);
  let echoed;
  f.adapter.push = async (operation) => {
    echoed = structuredClone(operation);
    throw Object.assign(new Error("unproven server-side CAS conflict"),
      { code: "sync_conflict", status: 409, current: structuredClone(operation) });
  };
  const queued = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(queued.pending, true);
  assert.ok(echoed?.operationId.startsWith("histrestore-"));
  f.engine.excludedPaths = ["document.txt"];
  f.adapter.list = async () => [structuredClone(echoed)];
  const summary = { pulled: 0, applied: 0, offline: false, conflicts: [] };
  await f.engine.pullRemote(summary);
  assert.equal(summary.pulled, 0);
  assert.equal(f.engine.journal.hasSeen(echoed.operationId), false);
  const [pending] = await f.engine.journal.recover();
  assert.equal(pending.operationId, echoed.operationId,
    "LIST cannot erase the signed outbox or its restore materialization record");
  assert.equal(f.engine.journal.hasMaterializedRestore(pending), true);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
    "original authenticated bytes");
});

for (const status of [200, 409]) {
  test(`#262 P1: old committed histrestore B cannot launder queued restore A after HTTP ${status}`, async (t) => {
    const f = await fixture(t);
    const oldCurrent = await f.sign({ operation: "update", versionId: "old-restore-B",
      operationId: "histrestore-old-current-B",
      revision: { counter: 3, deviceId: "device-a" }, baseRevision: f.deleted.revision,
      metadata: { path: "document.txt", name: "document.txt" },
      plaintext: Buffer.from("previous committed restore B") });
    await f.physical.physicalStoreCommitted(oldCurrent);
    let journalBeforeAck;
    f.adapter.push = async (operation) => {
      assert.equal(await verifyAuthorizationProof(operation.authorization, operation, f.trusted), true);
      assert.equal(Object.isFrozen(operation), true,
        "transport must receive a detached immutable signed envelope");
      assert.equal(Object.isFrozen(operation.metadata), true,
        "nested signed fields must also be immutable");
      assert.equal(Object.isFrozen(operation.authorization), true,
        "the authorization proof must be part of the immutable envelope");
      const authorizationSignature = operation.authorization.signature;
      assert.notEqual(authorizationSignature, oldCurrent.authorization.signature,
        "the older committed envelope must carry a distinct authorization");
      try { operation.authorization.signature = oldCurrent.authorization.signature; }
      catch { /* frozen authorization is expected */ }
      assert.equal(operation.authorization.signature, authorizationSignature,
        "transport must not be able to rewrite the signed authorization");
      journalBeforeAck = await fsp.readFile(f.engine.journal.filePath);
      // A hostile transport attempts to replace queued A with the older,
      // already committed B. A frozen request must make this ineffective.
      try { Object.assign(operation, oldCurrent); } catch { /* fail closed */ }
      if (status === 409) {
        throw Object.assign(new Error("Remote reports its older committed restore B"),
          { status: 409, code: "sync_conflict", current: structuredClone(oldCurrent) });
      }
      return { status: 200 };
    };

    if (status === 200) {
      await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
        (error) => error.code === "restore_remote_admission_unproven",
        "a false success without physical CURRENT must reject");
    } else {
      const pendingRestore = await f.engine.restoreHistoricalVersion("file-1", "first");
      assert.equal(pendingRestore.restored, true);
      assert.equal(pendingRestore.pushed, false);
      assert.equal(pendingRestore.pending, true, "only a witness of exact A may ACK queued A");
    }
    assert.ok(journalBeforeAck, "capture the durable journal after A was staged");
    assert.deepEqual(await fsp.readFile(f.engine.journal.filePath), journalBeforeAck,
      "a stale physical CURRENT must not cause any durable ACK mutation");
    const [pending] = await f.engine.journal.recover();
    assert.ok(pending.operationId.startsWith("histrestore-"));
    assert.notEqual(pending.operationId, oldCurrent.operationId,
      "the original queued A identity must not be replaced by committed B");
    const digest = crypto.createHash("sha256")
      .update(protocol.canonicalJson(pending)).digest("hex");
    assert.equal(f.engine.journal.hasPendingEnvelope(pending.operationId, digest), true);
    assert.equal(f.engine.journal.durableSignedReceiptDigest(pending.operationId), digest);
    assert.equal(f.engine.journal.hasSeen(pending.operationId), false);
    assert.equal(f.engine.journal.hasSeen(oldCurrent.operationId), false);
    assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
      "original authenticated bytes");
  });
}

test("#262 P1: witness callback cannot replace the pinned Ed25519 verifier", async (t) => {
  const f = await fixture(t);
  const originalWitness = f.physical.options.atomicBatchWitnessReadback;
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  const originalVerify = crypto.verify;
  let casReads = 0;
  let journalBeforeAck;
  const originalPush = f.adapter.push.bind(f.adapter);
  f.adapter.push = async (operation) => {
    journalBeforeAck = await fsp.readFile(f.engine.journal.filePath);
    return originalPush(operation);
  };
  const engine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchWitnessReadback: async (challenge) => {
      const signed = await originalWitness(challenge);
      // Keep digest and Buffer decoding intact so this test reaches the actual
      // signature decision on both parent and candidate. A dynamic verifier
      // would accept the deliberately invalid signature below.
      crypto.verify = () => true;
      return { ...signed, signature: "A".repeat(86) };
    },
    atomicBatchCasFloorReadback: async (challenge) => {
      casReads += 1;
      return originalCas(challenge);
    },
  }).open();

  try {
    await assert.rejects(engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_remote_admission_unproven");
  } finally { crypto.verify = originalVerify; }

  assert.equal(casReads, 0,
    "invalid witness signature must be rejected before the independent CAS read");
  assert.ok(journalBeforeAck);
  assert.deepEqual(await fsp.readFile(engine.journal.filePath), journalBeforeAck,
    "forged physical evidence must not mutate the durable outbox");
  const [pending] = await engine.journal.recover();
  assert.ok(pending.operationId.startsWith("histrestore-"));
  assert.equal(engine.journal.hasSeen(pending.operationId), false);
});

test("#262 P1: retry guard survives a failed transport poisoning crypto and Buffer intrinsics", async (t) => {
  const f = await fixture(t);
  const originalPush = f.adapter.push.bind(f.adapter);
  const originalWitness = f.physical.options.atomicBatchWitnessReadback;
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  const original = {
    createHash: crypto.createHash,
    timingSafeEqual: crypto.timingSafeEqual,
    randomBytes: crypto.randomBytes,
    randomUUID: crypto.randomUUID,
    hashUpdate: crypto.Hash.prototype.update,
    hashDigest: crypto.Hash.prototype.digest,
    bufferFrom: Buffer.from,
    bufferAlloc: Buffer.alloc,
    bufferByteLength: Buffer.byteLength,
    bufferIsBuffer: Buffer.isBuffer,
    bufferConcat: Buffer.concat,
    bufferToString: Buffer.prototype.toString,
    jsonStringify: JSON.stringify,
  };
  const restoreIntrinsics = () => {
    crypto.createHash = original.createHash;
    crypto.timingSafeEqual = original.timingSafeEqual;
    crypto.randomBytes = original.randomBytes;
    crypto.randomUUID = original.randomUUID;
    crypto.Hash.prototype.update = original.hashUpdate;
    crypto.Hash.prototype.digest = original.hashDigest;
    Buffer.from = original.bufferFrom;
    Buffer.alloc = original.bufferAlloc;
    Buffer.byteLength = original.bufferByteLength;
    Buffer.isBuffer = original.bufferIsBuffer;
    Buffer.concat = original.bufferConcat;
    Buffer.prototype.toString = original.bufferToString;
    // The engine's synchronous POST fence intentionally exposes a getter-
    // only serializer; a transport must not replace it during serialization.
    if (!Object.getOwnPropertyDescriptor(JSON, "stringify").get) {
      JSON.stringify = original.jsonStringify;
    }
  };
  let attempts = 0;
  f.adapter.push = async (operation) => {
    attempts += 1;
    if (attempts === 1) {
      crypto.createHash = () => { throw new Error("poisoned createHash"); };
      crypto.timingSafeEqual = () => { throw new Error("poisoned timingSafeEqual"); };
      crypto.randomBytes = () => { throw new Error("poisoned randomBytes"); };
      crypto.randomUUID = () => { throw new Error("poisoned randomUUID"); };
      crypto.Hash.prototype.update = () => { throw new Error("poisoned Hash.update"); };
      crypto.Hash.prototype.digest = () => { throw new Error("poisoned Hash.digest"); };
      Buffer.from = () => { throw new Error("poisoned Buffer.from"); };
      Buffer.alloc = () => { throw new Error("poisoned Buffer.alloc"); };
      Buffer.byteLength = () => { throw new Error("poisoned Buffer.byteLength"); };
      Buffer.isBuffer = () => { throw new Error("poisoned Buffer.isBuffer"); };
      Buffer.concat = () => { throw new Error("poisoned Buffer.concat"); };
      Buffer.prototype.toString = () => { throw new Error("poisoned Buffer.toString"); };
      throw Object.assign(new Error("transport lost the first ACK"), { code: "offline" });
    }
    restoreIntrinsics();
    return originalPush(operation);
  };

  const engine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchWitnessReadback: async (challenge) => {
      const signed = await originalWitness(challenge);
      JSON.stringify = () => { throw new Error("poisoned JSON.stringify after witness readback"); };
      return signed;
    },
    atomicBatchCasFloorReadback: async (challenge) => {
      JSON.stringify = original.jsonStringify;
      const signed = await originalCas(challenge);
      JSON.stringify = () => { throw new Error("poisoned JSON.stringify after CAS readback"); };
      return signed;
    },
  }).open();

  try {
    const restored = await engine.restoreHistoricalVersion("file-1", "first");
    assert.equal(attempts, 2, "the signed restore must safely retry after the transport callback poisons globals");
    assert.equal(restored.pushed, true);
    assert.equal(f.pushes(), 1, "only the second, successful physical commit reaches the adapter");
    assert.deepEqual(await engine.journal.recover(), []);
    assert.equal(engine.journal.hasSeen(restored.operationId), true);
  } finally { restoreIntrinsics(); }
});

test("#262 P1: valid physical witness/CAS and exact ACK survive crypto/Buffer poisoning after transport success", async (t) => {
  const f = await fixture(t);
  const originalWitness = f.physical.options.atomicBatchWitnessReadback;
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  const originalPush = f.adapter.push.bind(f.adapter);
  const originals = {
    createHash: crypto.createHash,
    verify: crypto.verify,
    randomBytes: crypto.randomBytes,
    timingSafeEqual: crypto.timingSafeEqual,
    hashUpdate: crypto.Hash.prototype.update,
    hashDigest: crypto.Hash.prototype.digest,
    bufferFrom: Buffer.from,
    bufferIsBuffer: Buffer.isBuffer,
    bufferConcat: Buffer.concat,
    bufferToString: Buffer.prototype.toString,
  };
  const restore = () => {
    crypto.createHash = originals.createHash;
    crypto.verify = originals.verify;
    crypto.randomBytes = originals.randomBytes;
    crypto.timingSafeEqual = originals.timingSafeEqual;
    crypto.Hash.prototype.update = originals.hashUpdate;
    crypto.Hash.prototype.digest = originals.hashDigest;
    Buffer.from = originals.bufferFrom;
    Buffer.isBuffer = originals.bufferIsBuffer;
    Buffer.concat = originals.bufferConcat;
    Buffer.prototype.toString = originals.bufferToString;
  };
  const poison = () => {
    crypto.createHash = () => { throw new Error("poisoned createHash after transport"); };
    crypto.verify = () => { throw new Error("poisoned verify after transport"); };
    crypto.randomBytes = () => { throw new Error("poisoned randomBytes after transport"); };
    crypto.timingSafeEqual = () => { throw new Error("poisoned timingSafeEqual after transport"); };
    crypto.Hash.prototype.update = () => { throw new Error("poisoned Hash.update after transport"); };
    crypto.Hash.prototype.digest = () => { throw new Error("poisoned Hash.digest after transport"); };
    Buffer.from = () => { throw new Error("poisoned Buffer.from after transport"); };
    Buffer.isBuffer = () => false;
    Buffer.concat = () => { throw new Error("poisoned Buffer.concat after transport"); };
    Buffer.prototype.toString = () => { throw new Error("poisoned Buffer.toString after transport"); };
  };
  f.adapter.push = async (operation) => {
    const result = await originalPush(operation);
    poison();
    return result;
  };
  const engine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchWitnessReadback: async (challenge) => {
      restore();
      try {
        const signed = await originalWitness(challenge);
        poison();
        return signed;
      } catch (error) { poison(); throw error; }
    },
    atomicBatchCasFloorReadback: async (challenge) => {
      restore();
      try {
        const signed = await originalCas(challenge);
        poison();
        return signed;
      } catch (error) { poison(); throw error; }
    },
  }).open();

  let restored;
  try { restored = await engine.restoreHistoricalVersion("file-1", "first"); }
  finally { restore(); }
  assert.equal(restored.pushed, true);
  assert.equal(f.pushes(), 1);
  assert.deepEqual(await engine.journal.recover(), []);
  assert.equal(engine.journal.hasSeen(restored.operationId), true);
});

test("#262 P1: AES-GCM and MOVE HMAC remain bound to native cipher/HMAC methods after readback poisoning", async (t) => {
  const f = await fixture(t);
  const expectedPlaintext = protocol.decryptPayload(f.original, f.privateFileKey);
  const invalidTag = Buffer.alloc(16, 0x5a).toString("base64url");
  const moveContent = Buffer.from("authenticated MOVE payload");
  const macOffset = Buffer.byteLength("ROOTARK-SYNC-MOVE\0v1\0", "utf8") + 8;
  const originals = {
    cipherSetAAD: crypto.Cipheriv.prototype.setAAD,
    cipherUpdate: crypto.Cipheriv.prototype.update,
    cipherFinal: crypto.Cipheriv.prototype.final,
    cipherGetAuthTag: crypto.Cipheriv.prototype.getAuthTag,
    decipherSetAAD: crypto.Decipheriv.prototype.setAAD,
    decipherSetAuthTag: crypto.Decipheriv.prototype.setAuthTag,
    decipherUpdate: crypto.Decipheriv.prototype.update,
    decipherFinal: crypto.Decipheriv.prototype.final,
    hmacUpdate: crypto.Hmac.prototype.update,
    hmacDigest: crypto.Hmac.prototype.digest,
  };
  const restore = () => {
    crypto.Cipheriv.prototype.setAAD = originals.cipherSetAAD;
    crypto.Cipheriv.prototype.update = originals.cipherUpdate;
    crypto.Cipheriv.prototype.final = originals.cipherFinal;
    crypto.Cipheriv.prototype.getAuthTag = originals.cipherGetAuthTag;
    crypto.Decipheriv.prototype.setAAD = originals.decipherSetAAD;
    crypto.Decipheriv.prototype.setAuthTag = originals.decipherSetAuthTag;
    crypto.Decipheriv.prototype.update = originals.decipherUpdate;
    crypto.Decipheriv.prototype.final = originals.decipherFinal;
    crypto.Hmac.prototype.update = originals.hmacUpdate;
    crypto.Hmac.prototype.digest = originals.hmacDigest;
  };
  const poison = () => {
    crypto.Cipheriv.prototype.setAAD = function () { return this; };
    crypto.Cipheriv.prototype.update = function () { return Buffer.alloc(0); };
    crypto.Cipheriv.prototype.final = function () { return Buffer.alloc(0); };
    crypto.Cipheriv.prototype.getAuthTag = function () { return Buffer.alloc(16, 0x5a); };
    crypto.Decipheriv.prototype.setAAD = function () { return this; };
    crypto.Decipheriv.prototype.setAuthTag = function () { return this; };
    crypto.Decipheriv.prototype.update = function () { return Buffer.alloc(0); };
    crypto.Decipheriv.prototype.final = function () { return Buffer.alloc(0); };
    crypto.Hmac.prototype.update = function () { return this; };
    crypto.Hmac.prototype.digest = function () { return Buffer.alloc(32, 0x5a); };
  };
  try {
    poison();
    assert.deepEqual(protocol.decryptPayload(f.original, f.privateFileKey), expectedPlaintext);
    assert.throws(() => protocol.decryptPayload({ ...f.original, tag: invalidTag }, f.privateFileKey));

    const encrypted = protocol.createOperation({
      operation: "create", operationId: "intrinsic-fence-create", objectId: "intrinsic-fence-object",
      fileId: "intrinsic-fence-file", versionId: "intrinsic-fence-version",
      revision: { counter: 1, deviceId: "device-a" }, keyEpoch: "epoch-1",
      compartmentId: "private", deviceId: "device-a",
      metadata: { path: "intrinsic-fence.txt", name: "intrinsic-fence.txt" },
      plaintext: Buffer.from("fresh authenticated ciphertext"), fileKey: f.privateFileKey,
    });
    assert.equal(protocol.decryptPayload(encrypted, f.privateFileKey).toString("utf8"),
      "fresh authenticated ciphertext");

    const encodedMove = protocol.encodeMovePayload(moveContent, f.privateFileKey);
    assert.deepEqual(protocol.decodeMovePayload(encodedMove, f.privateFileKey), moveContent);
    const forgedMove = Buffer.from(encodedMove);
    for (let index = 0; index < 32; index += 1) forgedMove[macOffset + index] = 0x5a;
    assert.equal(protocol.decodeMovePayload(forgedMove, f.privateFileKey), null,
      "a forged MAC matching the poisoned Hmac.digest must not pass native verification");
  } finally { restore(); }
});

test("#262 P1: canonical JSON arrays ignore a stateful Array.prototype.toJSON hook", () => {
  const previous = Object.getOwnPropertyDescriptor(Array.prototype, "toJSON");
  let calls = 0;
  let getterReads = 0;
  Object.defineProperty(Array.prototype, "toJSON", {
    configurable: true, writable: true,
    value() { calls += 1; return calls === 1 ? this : ["laundered-envelope-B"]; },
  });
  try {
    const canonical = protocol.canonicalJson({
      operationIds: ["restore-A"], envelopeDigests: ["a".repeat(64)],
    });
    assert.equal(canonical,
      `{"envelopeDigests":["${"a".repeat(64)}"],"operationIds":["restore-A"]}`);
    assert.equal(calls, 0, "canonicalization must not consult the mutable Array.prototype hook");
    const accessorEnvelope = {};
    Object.defineProperty(accessorEnvelope, "operationIds", {
      enumerable: true, get() { getterReads += 1; return ["restore-A"]; },
    });
    assert.throws(() => protocol.canonicalJson(accessorEnvelope), /accessor|Invalid JSON value/);
    assert.equal(getterReads, 0, "canonicalization must reject accessors without invoking them");
  } finally {
    if (previous) Object.defineProperty(Array.prototype, "toJSON", previous);
    else delete Array.prototype.toJSON;
  }
});

test("#262 P1: stored-operation validation rejects getter-backed signed metadata without invoking it", async (t) => {
  const f = await fixture(t);
  const operation = await f.sign({ operation: "create", operationId: "getter-envelope-op",
    versionId: "getter-envelope-version", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: Buffer.from("getter") });
  let getterReads = 0;
  const hostile = {};
  const fields = Object.keys(operation);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (field === "metadata") continue;
    Object.defineProperty(hostile, field, {
      configurable: true, enumerable: true, writable: true, value: operation[field],
    });
  }
  Object.defineProperty(hostile, "metadata", {
    configurable: true, enumerable: true,
    get() { getterReads += 1; return operation.metadata; },
  });
  assert.throws(() => protocol.validateStoredOperation(hostile), /accessor|Invalid JSON value/);
  assert.equal(getterReads, 0, "validation must inspect data descriptors rather than evaluate untrusted getters");
});

test("#262 P1: exact restore ACK records seen by indexed assignment when Array.prototype.push is poisoned", async (t) => {
  const f = await fixture(t);
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  const originalPush = Array.prototype.push;
  const originalSplice = Array.prototype.splice;
  const engine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchCasFloorReadback: async (challenge) => {
      const signed = await originalCas(challenge);
      Array.prototype.push = function (...items) {
        if (items.length === 1 && typeof items[0] === "string"
          && items[0].startsWith("histrestore-")) return this.length;
        return Reflect.apply(originalPush, this, items);
      };
      Array.prototype.splice = function (start, deleteCount, ...items) {
        if (this[start] && typeof this[start] === "object"
          && typeof this[start].operationId === "string"
          && this[start].operationId.startsWith("histrestore-")) return [];
        return Reflect.apply(originalSplice, this, [start, deleteCount, ...items]);
      };
      return signed;
    },
  }).open();
  let restored;
  try { restored = await engine.restoreHistoricalVersion("file-1", "first"); }
  finally {
    Array.prototype.push = originalPush;
    Array.prototype.splice = originalSplice;
  }
  assert.equal(restored.pushed, true);
  assert.deepEqual(await engine.journal.recover(), []);
  assert.equal(engine.journal.hasSeen(restored.operationId), true);
  assert.ok(engine.journal.durableSignedReceiptDigest(restored.operationId));
});

test("#262 P1: journal ACK preserves prior seen IDs when Array.prototype iterator is poisoned after CAS readback", async (t) => {
  const f = await fixture(t);
  const priorSeenId = "prior-seen-operation";
  await f.engine.journal.markSeen(priorSeenId);
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  const originalIterator = Array.prototype[Symbol.iterator];
  const engine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchCasFloorReadback: async (challenge) => {
      const signed = await originalCas(challenge);
      Array.prototype[Symbol.iterator] = function* poisonedArrayIterator() { return; };
      return signed;
    },
  }).open();
  let restored;
  try { restored = await engine.restoreHistoricalVersion("file-1", "first"); }
  finally { Array.prototype[Symbol.iterator] = originalIterator; }
  assert.equal(restored.pushed, true);
  assert.equal(engine.journal.hasSeen(priorSeenId), true,
    "a poisoned iterator must not silently erase pre-existing durable seen IDs");
  assert.equal(engine.journal.hasSeen(restored.operationId), true);
  assert.deepEqual(await engine.journal.recover(), []);
});

test("#262 P1: historical restore durably enqueues its signed envelope after history callback poisons Array.prototype.push", async (t) => {
  const f = await fixture(t);
  const originalHistory = f.adapter.history.bind(f.adapter);
  const originalPush = Array.prototype.push;
  f.adapter.history = async (objectId) => {
    const result = await originalHistory(objectId);
    Array.prototype.push = function (...items) {
      if (items.length === 1 && items[0] && typeof items[0] === "object"
        && typeof items[0].operationId === "string"
        && items[0].operationId.startsWith("histrestore-")) return this.length;
      return Reflect.apply(originalPush, this, items);
    };
    return result;
  };
  let restored;
  try { restored = await f.engine.restoreHistoricalVersion("file-1", "first"); }
  finally { Array.prototype.push = originalPush; }
  assert.equal(restored.pushed, true);
  assert.deepEqual(await f.engine.journal.recover(), []);
  assert.equal(f.engine.journal.hasSeen(restored.operationId), true);
  assert.ok(f.engine.journal.durableSignedReceiptDigest(restored.operationId));
});

test("#262 P1: journal commit serialization ignores inherited Object.prototype.toJSON after CAS readback", async (t) => {
  const f = await fixture(t);
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  const previousArray = Object.getOwnPropertyDescriptor(Array.prototype, "toJSON");
  const engine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchCasFloorReadback: async (challenge) => {
      const signed = await originalCas(challenge);
      Object.defineProperty(Object.prototype, "toJSON", {
        configurable: true, writable: true,
        value() {
          if (this && this.version === 1 && Array.isArray(this.pending) && Array.isArray(this.seen)) {
            return { version: 1, pending: [], seen: [], admitted: {}, observed: {},
              committedSigned: {}, atomicSignedGroups: {}, materializedRestore: {}, restoreStaging: {} };
          }
          return this;
        },
      });
      Object.defineProperty(Array.prototype, "toJSON", {
        configurable: true, writable: true,
        value() { return []; },
      });
      return signed;
    },
  }).open();
  let restored;
  try { restored = await engine.restoreHistoricalVersion("file-1", "first"); }
  finally {
    if (previous) Object.defineProperty(Object.prototype, "toJSON", previous);
    else delete Object.prototype.toJSON;
    if (previousArray) Object.defineProperty(Array.prototype, "toJSON", previousArray);
    else delete Array.prototype.toJSON;
  }
  assert.equal(restored.pushed, true);
  assert.deepEqual(await engine.journal.recover(), []);
  assert.equal(engine.journal.hasSeen(restored.operationId), true);
  assert.ok(engine.journal.durableSignedReceiptDigest(restored.operationId));
});

test("#262 P1: signed proof verification cannot reuse proof A bytes for a differently bound proof B", async (t) => {
  const f = await fixture(t);
  const first = await f.sign({ operation: "create", operationId: "proof-reuse-op",
    versionId: "version-A", revision: { counter: 7, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: Buffer.from("proof A") });
  const second = await f.sign({ operation: "create", operationId: "proof-reuse-op",
    versionId: "version-B", revision: { counter: 8, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: Buffer.from("proof B") });
  const { signature: _firstSignature, ...firstUnsigned } = first.authorization;
  const { signature: _secondSignature, ...secondUnsigned } = second.authorization;
  assert.ok(_firstSignature && _secondSignature);
  const cachedFirstCbor = await zk.encodeDeterministic(firstUnsigned);
  const secondCbor = await zk.encodeDeterministic(secondUnsigned);
  assert.equal(secondCbor.length, cachedFirstCbor.length,
    "the substitution hook must target the actual encoded proof B bytes");
  const forgedSecond = { ...second.authorization, signature: first.authorization.signature };
  const originalBufferFrom = Buffer.from;
  Buffer.from = function (value, ...args) {
    if (typeof value === "object" && value !== null
      && value instanceof Uint8Array && value.length === cachedFirstCbor.length) {
      return Reflect.apply(originalBufferFrom, Buffer, [cachedFirstCbor]);
    }
    return Reflect.apply(originalBufferFrom, Buffer, [value, ...args]);
  };
  try {
    await assert.rejects(verifyAuthorizationProof(forgedSecond, second, f.trusted),
      (error) => error.code === "authorization_signature",
      "signature A must not authorize proof B when a callback poisons Buffer.from");
  } finally { Buffer.from = originalBufferFrom; }
});

test("#262 P1: authorization envelope binding ignores inherited Object/Array toJSON hooks", async (t) => {
  const f = await fixture(t);
  const operation = await f.sign({ operation: "create", operationId: "tojson-proof-op",
    versionId: "tojson-version", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: Buffer.from("toJSON") });
  const previousObject = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  const previousArray = Object.getOwnPropertyDescriptor(Array.prototype, "toJSON");
  Object.defineProperty(Object.prototype, "toJSON", {
    configurable: true, writable: true,
    value() { throw new Error("poisoned inherited Object.prototype.toJSON"); },
  });
  Object.defineProperty(Array.prototype, "toJSON", {
    configurable: true, writable: true,
    value() { throw new Error("poisoned inherited Array.prototype.toJSON"); },
  });
  try {
    assert.equal(await verifyAuthorizationProof(operation.authorization, operation, f.trusted), true);
  } finally {
    if (previousObject) Object.defineProperty(Object.prototype, "toJSON", previousObject);
    else delete Object.prototype.toJSON;
    if (previousArray) Object.defineProperty(Array.prototype, "toJSON", previousArray);
    else delete Array.prototype.toJSON;
  }
});

test("#262 P1: revoked-device authorization cannot be bypassed by poisoning Array.prototype.includes", async (t) => {
  const f = await fixture(t);
  const operation = await f.sign({ operation: "create", operationId: "revoked-device-proof",
    versionId: "revoked-version", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: Buffer.from("revoked") });
  const revokedDeviceIds = ["device-a"];
  const expected = { ...f.trusted, revokedDeviceIds };
  const originalIncludes = Array.prototype.includes;
  Array.prototype.includes = function (value, ...args) {
    if (this === revokedDeviceIds && value === "device-a") return false;
    return Reflect.apply(originalIncludes, this, [value, ...args]);
  };
  try {
    await assert.rejects(verifyAuthorizationProof(operation.authorization, operation, expected),
      (error) => error.code === "authorization_device_revoked",
      "the native revocation check must reject even when the shared includes method is poisoned");
  } finally { Array.prototype.includes = originalIncludes; }
});

test("#262 P1: remote pull cannot overwrite an existing same-ID admission when Object.hasOwn/includes are poisoned", async (t) => {
  const f = await fixture(t);
  const first = await f.sign({ operation: "create", operationId: "shared-admission-id",
    versionId: "admission-A", revision: { counter: 7, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: Buffer.from("admission A") });
  const second = await f.sign({ operation: "create", operationId: "shared-admission-id",
    versionId: "admission-B", revision: { counter: 8, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: Buffer.from("admission B") });
  const digest = (operation) => crypto.createHash("sha256")
    .update(protocol.canonicalJson(operation)).digest("hex");
  const firstDigest = digest(first);
  const secondDigest = digest(second);
  await f.engine.journal.observeAdmission(first.operationId, firstDigest);
  const originalHasOwn = Object.hasOwn;
  const originalIncludes = Array.prototype.includes;
  const seen = f.engine.journal.state.seen;
  f.adapter.list = async () => {
    Object.hasOwn = (object, key) => {
      if (object && (typeof object === "object" || typeof object === "function")
        && key === first.operationId && object[key] === firstDigest) return false;
      return originalHasOwn(object, key);
    };
    Array.prototype.includes = function (value, ...args) {
      if (this === seen && value === first.operationId) return false;
      return Reflect.apply(originalIncludes, this, [value, ...args]);
    };
    return { objects: [second] };
  };
  try {
    await assert.rejects(f.engine.pullRemote({ pulled: 0, offline: false }),
      (error) => error.code === "remote_authorization_rejected");
  } finally {
    Object.hasOwn = originalHasOwn;
    Array.prototype.includes = originalIncludes;
  }
  assert.equal(f.engine.journal.hasLocalAdmission(first.operationId, firstDigest), true);
  assert.equal(f.engine.journal.hasLocalAdmission(second.operationId, secondDigest), false);
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false,
    "conflicting signed B must not be applied over the previously admitted A");
});

test("#262 P1: replayed physical witness nonce cannot ACK a pending restore after a lost CAS readback", async (t) => {
  const f = await fixture(t);
  const originalWitness = f.physical.options.atomicBatchWitnessReadback;
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  let firstNonce = null;
  let firstReceipt = null;
  const firstEngine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchWitnessReadback: async (challenge) => {
      firstNonce = challenge.nonce;
      firstReceipt = await originalWitness(challenge);
      return firstReceipt;
    },
    atomicBatchCasFloorReadback: async () => {
      throw Object.assign(new Error("temporary independent CAS readback outage"),
        { code: "offline" });
    },
  }).open();
  await assert.rejects(firstEngine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_remote_admission_unproven");
  assert.equal(firstReceipt?.statement?.nonce, firstNonce);
  const [originalPending] = await firstEngine.journal.recover();
  assert.ok(originalPending.operationId.startsWith("histrestore-"));
  assert.equal(firstEngine.journal.hasSeen(originalPending.operationId), false);

  let casReads = 0;
  const retryEngine = await new SyncEngine({
    rootDir: f.local, journal: firstEngine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchWitnessReadback: async () => firstReceipt,
    atomicBatchCasFloorReadback: async (challenge) => {
      casReads += 1;
      return originalCas(challenge);
    },
  }).open();
  const originalRandomBytes = crypto.randomBytes;
  const replayNonceBytes = Buffer.from(firstNonce, "base64url");
  const journalBeforeRetry = await fsp.readFile(retryEngine.journal.filePath);
  try {
    // A mutable global RNG would repeat the prior challenge and make the
    // cached, validly signed receipt replayable. The engine must use its pin.
    crypto.randomBytes = () => Buffer.from(replayNonceBytes);
    const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
    await retryEngine.pushPending(summary);
    assert.equal(summary.offline, true, "replayed witness is still an uncertain remote outcome");
    assert.equal(summary.pushed, 0, "no replayed witness may ACK the pending restore");
  } finally { crypto.randomBytes = originalRandomBytes; }

  assert.deepEqual(await fsp.readFile(retryEngine.journal.filePath), journalBeforeRetry,
    "replayed witness must not mutate the durable pending outbox");
  assert.equal(casReads, 0, "a replayed witness must fail before the CURRENT CAS read");
  const [stillPending] = await retryEngine.journal.recover();
  assert.equal(stillPending.operationId, originalPending.operationId);
  assert.equal(retryEngine.journal.hasSeen(originalPending.operationId), false);
});

test("#67 P1: absent independent owner-witness-CAS authority rejects restore before staging", async (t) => {
  const f = await fixture(t);
  const engine = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
  }).open();
  await assert.rejects(engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_remote_admission_unproven");
  assert.equal(f.pushes(), 0, "missing physical authority must not send signed restore");
  assert.deepEqual(await engine.journal.recover(), [], "no unserviceable outbox entry is created");
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false);
});

test("#67 P1: signed physical witness alone cannot ACK without genuine CAS CURRENT", async (t) => {
  const f = await fixture(t);
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  const engine = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
    atomicBatchCasFloorReadback: async (challenge) => {
      const signed = await originalCas(challenge);
      // Even a correctly signed *previous* physical witness cannot confer
      // CURRENT when the independent floor is substituted after signing.
      return { ...signed, statement: { ...signed.statement, current: false } };
    },
  }).open();
  await assert.rejects(engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_remote_admission_unproven");
  assert.equal(f.pushes(), 1, "server has actually committed once");
  assert.equal(f.versions.length, 3, "remote operation exists but cannot fabricate CURRENT");
  assert.equal((await engine.journal.recover()).length, 1,
    "local signed outbox must survive a substituted CAS floor");
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
    "original authenticated bytes");
});

test("#67: invalid historical signature, unknown version and revoked signer fail before any new write", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "missing"), /version|history/i);
  f.versions[0] = { ...f.original, ciphertext: f.original.ciphertext + "AA" };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"));
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false);
  f.versions[0] = f.original;
  f.trusted.revokedDeviceIds.push("device-a");
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"));
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false);
});

test("#67: historical MOVE restores authenticated file bytes, not the encrypted move framing", async (t) => {
  const f = await fixture(t);
  const moved = await f.sign({ operation: "move", operationId: "move-op", versionId: "move-version",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: f.original.revision,
    metadata: { path: "moved.txt", sourcePath: "document.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("historical move content"), f.privateFileKey),
  });
  const deleted = await f.sign({ operation: "delete", operationId: "delete-move-op", versionId: "delete-move-version",
    revision: { counter: 3, deviceId: "device-a" }, baseRevision: moved.revision,
    metadata: { path: "moved.txt" } });
  f.versions.splice(1, 1, moved, deleted);
  f.setCurrent(deleted);
  const outcome = await f.engine.restoreHistoricalVersion("file-1", moved.versionId);
  assert.equal(outcome.pushed, true);
  assert.equal(await fsp.readFile(path.join(f.local, "moved.txt"), "utf8"), "historical move content");
  assert.equal(f.current().revision.counter, 4);
});

test("#67 P2: stale tracked source cannot restore after an authenticated remote MOVE", async (t) => {
  const f = await fixture(t);
  const source = path.join(f.local, "document.txt");
  const destination = path.join(f.local, "moved.txt");
  const originalBytes = Buffer.from("original authenticated bytes");
  await fsp.writeFile(source, originalBytes);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(originalBytes).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const moved = await f.sign({ operation: "move", operationId: "trusted-move-op",
    versionId: "trusted-move-version", revision: { counter: 2, deviceId: "device-a" },
    baseRevision: f.original.revision,
    metadata: { path: "moved.txt", sourcePath: "document.txt" },
    plaintext: protocol.encodeMovePayload(originalBytes, f.privateFileKey),
  });
  assert.equal(await verifyAuthorizationProof(moved.authorization, moved, f.trusted), true);
  f.versions.splice(1, 1, moved);
  f.setCurrent(moved);

  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict",
    "restore must not duplicate a signed identity at stale and current paths");
  assert.deepEqual(await fsp.readFile(source), originalBytes);
  assert.equal(fs.existsSync(destination), false);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);

  // The fixture's historical `list(objectId)` returns a single record;
  // the ordinary sync pull uses `list()` and expects a record collection.
  const historyList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? historyList(objectId) : [await historyList()];
  const synced = await f.engine.syncOnce();
  assert.equal(synced.offline, false);
  assert.equal(fs.existsSync(source), false, "verified MOVE reconciles the old name");
  assert.deepEqual(await fsp.readFile(destination), originalBytes);
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.pushed, true, "normal restore succeeds after reconciling the signed MOVE");
  assert.equal(f.current().revision.counter, 3);
  assert.equal(fs.existsSync(source), false);
  assert.deepEqual(await fsp.readFile(destination), originalBytes);
});

test("#67 P2: a signed fileId rotation cannot hide the old tracked objectId during MOVE restore", async (t) => {
  const f = await fixture(t);
  const source = path.join(f.local, "document.txt");
  const destination = path.join(f.local, "moved.txt");
  const originalBytes = Buffer.from("original authenticated bytes");
  await fsp.writeFile(source, originalBytes);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(originalBytes).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const rotated = await f.sign({ operation: "update", fileId: "rotated-file-id",
    operationId: "signed-id-rotation", versionId: "rotated-version",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: f.original.revision,
    metadata: { path: "document.txt" }, plaintext: originalBytes,
  });
  const moved = await f.sign({ operation: "move", fileId: "rotated-file-id",
    operationId: "signed-rotated-move", versionId: "moved-rotated-version",
    revision: { counter: 3, deviceId: "device-a" }, baseRevision: rotated.revision,
    metadata: { path: "moved.txt", sourcePath: "document.txt" },
    plaintext: protocol.encodeMovePayload(originalBytes, f.privateFileKey),
  });
  assert.equal(await verifyAuthorizationProof(rotated.authorization, rotated, f.trusted), true);
  assert.equal(await verifyAuthorizationProof(moved.authorization, moved, f.trusted), true);
  f.versions.splice(1, 1, rotated, moved);
  f.setCurrent(moved);

  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", rotated.versionId),
    (error) => error.code === "restore_local_conflict",
    "the old tracked object cannot be hidden by a newly signed fileId");
  assert.deepEqual(await fsp.readFile(source), originalBytes);
  assert.equal(fs.existsSync(destination), false);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67: restore never overwrites untracked local data or accepts a cross-object current head", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  await fsp.writeFile(target, "independent local data");
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /untracked|overwrite/i);
  assert.equal(await fsp.readFile(target, "utf8"), "independent local data");
  assert.equal(f.pushes(), 0);
  await fsp.unlink(target);
  f.setCurrent({ ...f.deleted, objectId: "foreign-file" });
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"));
  assert.equal(f.pushes(), 0);
});

test("#67: restore rejects unsent edits to a tracked local file before enqueuing or pushing", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const lastSynced = Buffer.from("last synchronized content");
  await fsp.writeFile(target, lastSynced);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(lastSynced).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const unsent = Buffer.from("UNSENT LOCAL MODIFICATION");
  await fsp.writeFile(target, unsent);
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.deepEqual(await fsp.readFile(target), unsent);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
  assert.equal(fs.existsSync(path.join(f.local, ".rootark-trash")), false);
});

test("#67: a clean tracked file can be restored and its former bytes remain recoverable in trash", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const clean = Buffer.from("clean synchronized newer content");
  await fsp.writeFile(target, clean);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "newer",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(clean).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.pushed, true);
  assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
  const trash = path.join(f.local, ".rootark-trash");
  const files = await fsp.readdir(trash);
  assert.equal(files.length, 1);
  assert.deepEqual(await fsp.readFile(path.join(trash, files[0])), clean);
});

test("#67: a local write while the signed restore enters its durable outbox cannot be overwritten or pushed", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const clean = Buffer.from("last synchronized content");
  await fsp.writeFile(target, clean);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(clean).digest("hex"),
  };
  await f.engine.persistSnapshot();

  const enqueue = f.engine.journal.enqueue.bind(f.engine.journal);
  const unsent = Buffer.from("UNSENT LOCAL MODIFICATION DURING ENQUEUE");
  f.engine.journal.enqueue = async (operation) => {
    const result = await enqueue(operation);
    await fsp.writeFile(target, unsent);
    return result;
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.deepEqual(await fsp.readFile(target), unsent);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0,
    "rejected restore must not remain eligible for retry/push after restart");
});

test("#67: staging detects an edit after final hash read and restores changed bytes to their path", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const clean = Buffer.from("clean snapshot");
  await fsp.writeFile(target, clean);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(clean).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const stage = f.engine.stageExisting.bind(f.engine);
  const edit = Buffer.from("NEW EDIT BETWEEN CHECK AND STAGING");
  f.engine.stageExisting = async (requested) => {
    await fsp.writeFile(target, edit);
    return stage(requested);
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.deepEqual(await fsp.readFile(target), edit);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67: staged content hash rejects same-size edits with restored mtime and stable inode", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const clean = Buffer.from("clean synchronized bytes");
  const altered = Buffer.from("dirty synchronized bytes");
  assert.equal(clean.length, altered.length);
  const timestamp = new Date("2023-11-14T00:00:00.000Z");
  await fsp.writeFile(target, clean);
  await fsp.utimes(target, timestamp, timestamp);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(clean).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const stage = f.engine.stageExisting.bind(f.engine);
  f.engine.stageExisting = async (requested) => {
    await fsp.writeFile(target, altered);
    await fsp.utimes(target, timestamp, timestamp);
    return stage(requested);
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.deepEqual(await fsp.readFile(target), altered);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67: a restart cannot dispatch a signed restore whose file was not materialized", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const old = Buffer.from("previous clean on-disk bytes");
  await fsp.writeFile(target, old);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(old).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("simulated process halt after moving original to trash");
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /simulated process halt/);
  // The later O_EXCL claim proves target absence atomically; do not authorize
  // a later open from an earlier path-existence observation.
  assert.equal((await f.engine.journal.recover()).length, 1);
  f.adapter.list = async (id) => id ? structuredClone(f.current()) : [structuredClone(f.current())];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
  }).open();
  await assert.rejects(reopened.syncOnce(), (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0, "an unmaterialized local restore must never be pushed after restart");
  assert.equal((await reopened.journal.recover()).length, 1);
  const trash = await fsp.readdir(path.join(f.local, ".rootark-trash"));
  assert.equal(trash.length, 1);
  assert.deepEqual(await fsp.readFile(path.join(f.local, ".rootark-trash", trash[0])), old);
  // Explicit recovery is possible without a new signature: materialize the
  // exact authenticated pending bytes, then let the existing CAS path resume.
  const recoveredBytes = protocol.decryptPayload(f.original, f.privateFileKey);
  try {
    // Simulate a writer atomically claiming the missing path. Exclusive
    // creation is the absence check; never check-then-write a shared pathname.
    const competingBytes = Buffer.from("rival local edit before explicit recovery");
    const competing = await fsp.open(target, fs.constants.O_WRONLY
      | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try { await competing.writeFile(competingBytes); }
    finally { await competing.close(); }
    await assert.rejects(() => restoreRecoveredBytesOnlyIfVacant(target, recoveredBytes),
      (error) => error.code === "EEXIST");
    assert.deepEqual(await readHeldRegularFile(target), competingBytes);
    await fsp.unlink(target);
    await restoreRecoveredBytesOnlyIfVacant(target, recoveredBytes);
  } finally {
    recoveredBytes.fill(0);
  }
  const resumed = await reopened.syncOnce();
  assert.equal(resumed.pushed, 1);
  assert.equal(f.pushes(), 1);
  assert.equal((await reopened.journal.recover()).length, 0);
});

test("#67 P2: offline materialized restore survives later local edit and pushes before the edit", async (t) => {
  const f = await fixture(t);
  const actualPush = f.adapter.push;
  let offline = true;
  f.adapter.push = async (operation) => {
    if (offline) throw Object.assign(new Error("disposable offline"), { code: "offline" });
    return actualPush(operation);
  };
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.restored, true);
  assert.equal(result.pushed, false);
  assert.equal(result.pending, true);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 1);
  const target = path.join(f.local, "document.txt");
  assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
  const materialized = f.engine.snapshot.files["document.txt"];
  assert.equal(materialized.versionId, result.versionId);
  assert.equal(materialized.hash,
    crypto.createHash("sha256").update("original authenticated bytes").digest("hex"));

  // This is a legitimate LOCAL edit to a restore already durably written to
  // the filesystem and sync snapshot. The restore's signed parent must commit
  // before the edit is assigned a subsequent CAS revision.
  const edited = Buffer.from("locally edited after successful materialization");
  await fsp.writeFile(target, edited);
  offline = false;
  const historyList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? historyList(objectId) : [await historyList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
  }).open();
  const committedRestore = await reopened.syncOnce();
  assert.equal(committedRestore.pushed, 1,
    "durably materialized restore must not strand the entire outbox on later user edits");
  assert.equal(f.pushes(), 1);
  assert.equal((await reopened.journal.recover()).length, 0);
  assert.deepEqual(await fsp.readFile(target), edited, "signed restore ACK cannot erase local edits");
  assert.equal(f.current().versionId, result.versionId);
  const after = await reopened.syncOnce();
  assert.equal(after.pushed, 1, "later local edit is independently signed after restore CAS");
  assert.equal(f.pushes(), 2);
  assert.deepEqual(protocol.decryptPayload(f.current(), f.privateFileKey), edited);
  assert.deepEqual(await fsp.readFile(target), edited);
});

test("#67 P2: forged persisted snapshot alone cannot authorize a never-materialized restore", async (t) => {
  const f = await fixture(t);
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("disposable crash before restoring target bytes");
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    /disposable crash before restoring target bytes/);
  const queued = await f.engine.journal.recover();
  assert.equal(queued.length, 1);
  const signed = queued[0];
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  const payload = protocol.decryptPayload(signed, f.privateFileKey);
  try {
    // Simulate a local attacker altering the untrusted snapshot JSON without
    // changing the signed journal or materializing the file's actual bytes.
    f.engine.snapshot.files["document.txt"] = {
      objectId: signed.objectId, fileId: signed.fileId, versionId: signed.versionId,
      revision: signed.revision, hash: crypto.createHash("sha256").update(payload).digest("hex"),
      deleted: false, directory: false,
    };
    await f.engine.persistSnapshot();
  } finally { payload.fill(0); }
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false);
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const resumed = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
  }).open();
  await assert.rejects(resumed.syncOnce(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0);
  assert.equal((await resumed.journal.recover()).length, 1);
});

test("#67 P2: deletion after durable offline restore remains a later signed delete", async (t) => {
  const f = await fixture(t);
  const actualPush = f.adapter.push;
  let offline = true;
  f.adapter.push = async (operation) => {
    if (offline) throw Object.assign(new Error("disposable offline"), { code: "offline" });
    return actualPush(operation);
  };
  const pending = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(pending.pending, true);
  const target = path.join(f.local, "document.txt");
  assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
  await fsp.unlink(target);
  offline = false;
  const historyList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? historyList(objectId) : [await historyList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
  }).open();
  const restored = await reopened.syncOnce();
  assert.equal(restored.pushed, 1);
  assert.equal(f.current().versionId, pending.versionId);
  assert.equal(fs.existsSync(target), false, "remote restore ACK cannot re-create the deleted local file");
  const deletion = await reopened.syncOnce();
  assert.equal(deletion.pushed, 1);
  assert.equal(f.current().operation, "delete");
  assert.equal(f.current().tombstone, true);
  assert.equal(fs.existsSync(target), false);
  assert.deepEqual(await reopened.journal.recover(), []);
});

function isHistoricalRestoreStageTempPath(name) {
  return /^(restore-materialize-[a-f0-9]{64}|document\.txt)\.tmp-/.test(path.basename(String(name)));
}

function resolveHistoricalRestoreStagePath(localDir, stagingName) {
  return String(stagingName).startsWith("restore-materialize-")
    ? path.join(localDir, ".rootark-trash", stagingName)
    : path.join(localDir, stagingName);
}

test("#67 P2: failing physical file fsync cannot certify a restore as materialized", async (t) => {
  const f = await fixture(t);
  const originalOpen = fsp.open;
  let injected = 0;
  fsp.open = async (name, ...rest) => {
    const handle = await originalOpen(name, ...rest);
    if (isHistoricalRestoreStageTempPath(name)) {
      Object.defineProperty(handle, "sync", {
        value: async () => {
          injected += 1;
          throw Object.assign(new Error("disposable file fsync refused"), { code: "EIO" });
        }, configurable: true,
      });
    }
    return handle;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "EIO");
  } finally { fsp.open = originalOpen; }
  assert.equal(injected, 1, "the fsync injection must hit the REAL plaintext file handle");
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false,
    "failure before link must not create a supposed restored file");
  const pending = await f.engine.journal.recover();
  assert.equal(pending.length, 1, "the signed outbox cannot be silently cleared");
  assert.equal(f.engine.journal.hasMaterializedRestore(pending[0]), false,
    "the journal must not witness bytes that were never physically flushed");
  assert.equal(f.engine.snapshot.files["document.txt"], undefined);
});

test("#67 P2: a recovered restore without witness cannot push if retry file fsync fails", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("disposable halt before durable materialization");
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    /disposable halt before durable materialization/);
  const [signed] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  assert.equal(f.engine.journal.hasMaterializedRestore(signed), false);
  const bytes = protocol.decryptPayload(signed, f.privateFileKey);
  try { await restoreRecoveredBytesOnlyIfVacant(target, bytes); }
  finally { bytes.fill(0); }
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
  }).open();
  const originalOpen = fsp.open;
  let injected = 0;
  fsp.open = async (name, flags, ...rest) => {
    const handle = await originalOpen(name, flags, ...rest);
    if (name === target && typeof flags === "number" && (flags & fs.constants.O_RDWR)) {
      Object.defineProperty(handle, "sync", { value: async () => {
        injected += 1;
        throw Object.assign(new Error("disposable recovered file fsync EIO"), { code: "EIO" });
      }, configurable: true });
    }
    return handle;
  };
  try {
    await assert.rejects(reopened.syncOnce(), (error) => error.code === "restore_local_materialization_missing");
  } finally { fsp.open = originalOpen; }
  assert.equal(injected, 1, "retry must fsync the exact recovered file descriptor");
  assert.equal(f.pushes(), 0, "failed retry fsync must never authorize remote POST");
  assert.equal((await reopened.journal.recover()).length, 1);
  assert.equal(reopened.journal.hasMaterializedRestore(signed), false);
  assert.deepEqual(await fsp.readFile(target), Buffer.from("original authenticated bytes"));
  const resumed = await reopened.syncOnce();
  assert.equal(resumed.pushed, 1, "a fresh successful physical sync permits a safe retry");
  assert.equal(f.pushes(), 1);
});

test("#67 P2: failed POSIX directory fsync after link cannot authorize push on retry", {
  skip: process.platform === "win32" ? "directory FileHandle.sync is not available on Windows" : false,
}, async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalOpen = fsp.open;
  const originalLink = fsp.link;
  let linked = false;
  let injectionsRemaining = 2;
  fsp.link = async (source, destination) => {
    const result = await originalLink(source, destination);
    if (destination === target && isHistoricalRestoreStageTempPath(source)) linked = true;
    return result;
  };
  fsp.open = async (name, flags, ...rest) => {
    const handle = await originalOpen(name, flags, ...rest);
    if (linked && name === f.local
      && typeof flags === "number"
      && (flags & (fs.constants.O_DIRECTORY || 0)) !== 0
      && (flags & (fs.constants.O_NOFOLLOW || 0)) !== 0
      && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === fs.constants.O_RDONLY
      && injectionsRemaining > 0) {
      Object.defineProperty(handle, "sync", { value: async () => {
        injectionsRemaining -= 1;
        throw Object.assign(new Error("disposable directory durability EIO"), { code: "EIO" });
      }, configurable: true });
    }
    return handle;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "EIO");
    assert.equal(injectionsRemaining, 1, "first EIO must strike directory sync after physical link");
    assert.equal((await readHeldRegularFile(target)).toString("utf8"),
      "original authenticated bytes");
    const [signed] = await f.engine.journal.recover();
    assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
    assert.equal(f.engine.journal.hasMaterializedRestore(signed), false);
    assert.equal(f.pushes(), 0);
    const originalList = f.adapter.list;
    f.adapter.list = async (objectId) => objectId
      ? originalList(objectId) : [await originalList(objectId)];
    const reopened = await new SyncEngine({
      rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
      keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
      fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
      authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
      verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
    }).open();
    await assert.rejects(reopened.syncOnce(),
      (error) => error.code === "restore_local_materialization_missing",
      "the real POSIX retry must fail closed when directory fsync fails");
    assert.equal(injectionsRemaining, 0, "second EIO must strike missing-witness retry directory fsync");
    assert.equal(f.pushes(), 0, "the server must not receive the restore after either fsync EIO");
    assert.equal((await reopened.journal.recover()).length, 1);
    assert.equal(reopened.journal.hasMaterializedRestore(signed), false);
    const result = await reopened.syncOnce();
    assert.equal(result.pushed, 1, "physical fsync on the real retry permits subsequent admission");
    assert.equal(f.pushes(), 1);
    assert.equal((await reopened.journal.recover()).length, 0);
  } finally { fsp.open = originalOpen; fsp.link = originalLink; }
});

test("#67 P2: restart recovers an exactly bound crash hardlink or fails closed on changed identity", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalUnlink = fsp.unlink;
  const originalRemove = fsp.rm;
  let interruptedCleanup = 0;
  let suppressedCleanup = 0;
  fsp.unlink = async (name, ...args) => {
    if (isHistoricalRestoreStageTempPath(name)) {
      interruptedCleanup += 1;
      throw new Error("disposable hard crash after linked staging identity was committed");
    }
    return originalUnlink(name, ...args);
  };
  fsp.rm = async (name, ...args) => {
    if (isHistoricalRestoreStageTempPath(name)) {
      suppressedCleanup += 1;
      return;
    }
    return originalRemove(name, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_materialization_missing",
      "a cleanup mock that reports success without removing the linked temp must fail closed");
  } finally { fsp.unlink = originalUnlink; fsp.rm = originalRemove; }
  assert.equal(interruptedCleanup, 1, "real target link and exact bound identity precede failed unlink");
  assert.equal(suppressedCleanup, 1, "simulated kill must bypass only the stage unlink cleanup");
  const [pending] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(pending.authorization, pending, f.trusted), true);
  assert.equal(f.engine.journal.hasMaterializedRestore(pending), false);
  const staging = f.engine.journal.restoreStagingInfo(pending);
  assert.ok(staging, "crash recovery needs a durable exact staged inode/name bound to signed envelope");
  const orphan = resolveHistoricalRestoreStagePath(f.local, staging.name);
  assert.equal(fs.existsSync(orphan), true, "the original producer-created temporary hardlink remains");
  assert.equal((await fsp.lstat(target)).nlink, 2);
  assert.equal((await fsp.lstat(orphan)).ino, (await fsp.lstat(target)).ino);
  const current = await fsp.lstat(target, { bigint: true });
  const idMatches = current.ino.toString() === staging.ino
    && current.dev.toString() === staging.dev;
  // Win32 filesystem index exposure can change across link creation. If it
  // does, a pre-crash journal identity MUST NOT authorize guessed cleanup.
  // This is safe manual-recovery NO-GO, not a falsely claimed auto-repair.
  if (!idMatches) {
    assert.equal(process.platform, "win32", "POSIX inode identity must remain stable");
  }
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
  }).open();
  if (!idMatches) {
    await assert.rejects(reopened.syncOnce(),
      (error) => error.code === "restore_local_materialization_missing");
    assert.equal(f.pushes(), 0);
    assert.equal(fs.existsSync(orphan), true, "mismatched staged identity cannot be deleted");
    assert.equal((await reopened.journal.recover()).length, 1);
    assert.equal((await readHeldRegularFile(target)).toString("utf8"),
      "original authenticated bytes");
    return;
  }
  const result = await reopened.syncOnce();
  assert.equal(result.pushed, 1, "a verified original restore may safely resume after cleanup");
  assert.equal(f.pushes(), 1);
  assert.equal(fs.existsSync(orphan), false, "remove only the authenticated temporary second hardlink");
  assert.equal((await fsp.lstat(target)).nlink, 1);
  assert.equal((await readHeldRegularFile(target, current)).toString("utf8"),
    "original authenticated bytes");
  assert.deepEqual(await reopened.journal.recover(), []);
});

test("#262 P2: unresolved restore staging pathname cannot become a scanned CREATE", async (t) => {
  const f = await fixture(t);
  const payload = Buffer.from("orphaned restore staging bytes");
  const operation = await f.sign({
    operation: "update", operationId: `histrestore-${crypto.randomUUID()}`,
    versionId: "orphaned-stage", baseRevision: f.deleted.revision,
    revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt", size: payload.length },
    plaintext: payload,
  });
  await f.engine.journal.enqueue(operation);
  const name = `document.txt.tmp-${process.pid}-${crypto.randomUUID()}`;
  await f.engine.journal.recordRestoreStagingIntent(operation, name);
  const staged = path.join(f.local, name);
  await fsp.writeFile(staged, payload, { flag: "wx", mode: 0o600 });
  const stats = await fsp.lstat(staged, { bigint: true });
  // A signed staging intent points to a different inode; the target is gone.
  // ENOENT from recovery must not turn this recorded temp into a local CREATE.
  await f.engine.journal.bindRestoreStagingIdentity(operation, name, {
    dev: stats.dev.toString(), ino: (stats.ino + 1n).toString(),
  });

  await assert.rejects(f.engine.reconcileLocal(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.deepEqual(await readHeldRegularFile(staged, stats), payload);
  assert.equal((await f.engine.journal.recover()).length, 1,
    "the signed outbox and staging provenance remain for explicit recovery");
  assert.equal(f.engine.snapshot.files[name], undefined,
    "unresolved restore staging must never enter the ordinary CREATE snapshot");
});

test("#262 P2: direct pushPending preserves residual staging provenance before offline POST", async (t) => {
  const f = await fixture(t);
  const payload = Buffer.from("signed bytes also present in an independent target");
  const operation = await f.sign({
    operation: "update", operationId: `histrestore-${crypto.randomUUID()}`,
    versionId: "direct-push-residual-stage", baseRevision: f.deleted.revision,
    revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt", size: payload.length },
    plaintext: payload,
  });
  const target = path.join(f.local, "document.txt");
  const name = `document.txt.tmp-${process.pid}-${crypto.randomUUID()}`;
  const staged = path.join(f.local, name);
  await f.engine.journal.enqueue(operation);
  await f.engine.journal.recordRestoreStagingIntent(operation, name);
  await fsp.writeFile(staged, payload, { flag: "wx", mode: 0o600 });
  const pinned = await fsp.lstat(staged, { bigint: true });
  await f.engine.journal.bindRestoreStagingIdentity(operation, name, {
    dev: pinned.dev.toString(), ino: pinned.ino.toString(),
  });
  await fsp.writeFile(target, payload, { flag: "wx", mode: 0o600 });
  const independent = await fsp.lstat(target, { bigint: true });
  assert.equal(pinned.nlink, 1n, "the recorded temp was never linked into the target");
  assert.equal(independent.nlink, 1n, "matching target bytes are an independent file");
  assert.notEqual(`${pinned.dev}:${pinned.ino}`, `${independent.dev}:${independent.ino}`);
  assert.equal(await f.engine.hashPendingPayload(operation),
    crypto.createHash("sha256").update(payload).digest("hex"),
    "the signed payload itself is valid and matches the standalone target");
  assert.deepEqual(await readHeldRegularFile(target, independent), payload);

  const originalPush = f.adapter.push;
  const originalWitness = f.engine.journal.recordRestoreMaterialization;
  let postAttempts = 0;
  let witnessAttempts = 0;
  f.adapter.push = async () => {
    postAttempts += 1;
    throw Object.assign(new Error("offline adapter POST"), { code: "offline" });
  };
  f.engine.journal.recordRestoreMaterialization = async (...args) => {
    witnessAttempts += 1;
    return originalWitness.apply(f.engine.journal, args);
  };
  const summary = { pushed: 0, conflicts: [], offline: false };
  try {
    await assert.rejects(f.engine.pushPending(summary),
      (error) => error.code === "restore_local_materialization_missing",
      "public pushPending must guard the exact recorded staging name without reconcileLocal");
  } finally {
    f.adapter.push = originalPush;
    f.engine.journal.recordRestoreMaterialization = originalWitness;
  }
  assert.equal(postAttempts, 0, "the offline adapter must receive no POST attempt");
  assert.equal(witnessAttempts, 0, "staging provenance must not be cleared by a witness commit");
  assert.equal(summary.pushed, 0);
  assert.equal(summary.offline, false);
  assert.equal(f.pushes(), 0);
  const [pending] = await f.engine.journal.recover();
  assert.equal(pending.operationId, operation.operationId);
  assert.equal(f.engine.journal.hasMaterializedRestore(pending), false);
  assert.equal(f.engine.journal.restoreStagingInfo(pending).name, name);
  assert.deepEqual(await readHeldRegularFile(staged, pinned), payload, "recorded staging plaintext remains for recovery");
  await assert.rejects(f.engine.reconcileLocal(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal((await f.engine.journal.recover()).length, 1);
  assert.equal(f.engine.snapshot.files[name], undefined,
    "a later reconcile must fail before recording the staged temp as CREATE");
});

test("#262 P2: recovered restore records snapshot and materialization witness before retry push", async (t) => {
  const f = await fixture(t);
  const recordMaterialization = f.engine.journal.recordRestoreMaterialization.bind(f.engine.journal);
  let interruptOnce = true;
  f.engine.journal.recordRestoreMaterialization = async (operation) => {
    if (interruptOnce) {
      interruptOnce = false;
      throw new Error("simulated crash before durable restore materialization witness");
    }
    return recordMaterialization(operation);
  };

  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    /simulated crash before durable restore materialization witness/);
  f.engine.journal.recordRestoreMaterialization = recordMaterialization;
  const [pending] = await f.engine.journal.recover();
  assert.ok(pending);
  assert.equal(f.engine.journal.hasMaterializedRestore(pending), false);
  assert.equal(f.engine.snapshot.files["document.txt"].versionId, pending.versionId);

  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const actualPush = f.adapter.push.bind(f.adapter);
  let checkedBeforePush = false;
  f.adapter.push = async (operation) => {
    assert.equal(f.engine.journal.hasMaterializedRestore(operation), true,
      "recovery must durably record materialization before the remote POST");
    const persisted = JSON.parse(await fsp.readFile(f.engine.snapshotPath, "utf8"));
    assert.equal(persisted.files["document.txt"].versionId, operation.versionId,
      "the exact restore snapshot must be persisted before the journal witness");
    checkedBeforePush = true;
    return actualPush(operation);
  };

  const resumed = await f.engine.syncOnce();
  assert.equal(checkedBeforePush, true);
  assert.equal(resumed.pushed, 1);
  assert.equal(f.pushes(), 1);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#262 P2: recovery witness commit cannot bless a replaced transport method", async (t) => {
  const f = await fixture(t);
  const originalCommit = f.engine.journal.recordRestoreMaterialization.bind(f.engine.journal);
  let interruptOnce = true;
  f.engine.journal.recordRestoreMaterialization = async (operation) => {
    if (interruptOnce) {
      interruptOnce = false;
      throw new Error("simulated interruption before witness");
    }
    return originalCommit(operation);
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    /simulated interruption before witness/);
  const oldPush = f.adapter.push;
  let substitutedPushCalls = 0;
  f.engine.journal.recordRestoreMaterialization = async (operation) => {
    await originalCommit(operation);
    f.adapter.push = async (...args) => {
      substitutedPushCalls += 1;
      return oldPush(...args);
    };
  };
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];

  await assert.rejects(f.engine.syncOnce(),
    (error) => error.code === "restore_remote_admission_unproven",
    "the original method identity must be checked before a remote POST");
  assert.equal(substitutedPushCalls, 0);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 1,
    "the signed operation remains durably pending for explicit retry");
});
test("#262 P2: failed restore staging cleanup preserves signed provenance", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const competing = Buffer.from("competing file created before restore link");
  const originalLink = fsp.link;
  const originalRm = fsp.rm;
  let temporary = null;
  let cleanupAttempted = false;
  fsp.link = async (source, destination) => {
    if (destination === target && isHistoricalRestoreStageTempPath(source)) {
      temporary = source;
      await fsp.writeFile(target, competing, { flag: "wx" });
    }
    return originalLink(source, destination);
  };
  fsp.rm = async (name, ...args) => {
    if (temporary && name === temporary) {
      cleanupAttempted = true;
      throw Object.assign(new Error("disposable restore-temp cleanup denial"), { code: "EPERM" });
    }
    return originalRm(name, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "EPERM");
  } finally {
    fsp.link = originalLink;
    fsp.rm = originalRm;
  }

  assert.equal(cleanupAttempted, true);
  assert.ok(temporary);
  assert.equal(fs.existsSync(temporary), true,
    "failed cleanup must not be swallowed while plaintext staging remains");
  assert.deepEqual(await fsp.readFile(target), competing,
    "the competing local target must remain untouched");
  const [pending] = await f.engine.journal.recover();
  assert.ok(pending);
  assert.ok(f.engine.journal.restoreStagingInfo(pending),
    "cleanup failure must preserve the exact durable staging identity");
  await assert.rejects(f.engine.reconcileLocal(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.deepEqual(await fsp.readFile(target), competing);
});

test("#67 P2: foreign hardlink cannot be misidentified as restore temp and deleted", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("disposable stop before materialization");
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /disposable stop/);
  const [pending] = await f.engine.journal.recover();
  const bytes = protocol.decryptPayload(pending, f.privateFileKey);
  try { await restoreRecoveredBytesOnlyIfVacant(target, bytes); }
  finally { bytes.fill(0); }
  // A user can legitimately create a hardlink whose name merely resembles
  // the engine's staging suffix. It has NO durable journal staging intent.
  // Matching the suffix, inode and payload hash must not suffice to unlink it.
  const foreignName = `${target}.tmp-${process.pid}-${crypto.randomUUID()}`;
  await fsp.link(target, foreignName);
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const countBefore = f.pushes();
  await assert.rejects(f.engine.syncOnce(),
    (error) => error.code === "restore_local_materialization_missing"
      || error.code === "unsafe_path",
    "either the durable staging-recovery fence or the strict hardlink file-identity fence must fail closed");
  assert.equal(f.pushes(), countBefore);
  assert.equal((await fsp.lstat(target)).nlink, 2);
  assert.equal(fs.existsSync(foreignName), true, "never remove an arbitrary user hardlink");
  assert.equal((await f.engine.journal.recover()).length, 1);
});

test("#67 P2: pre-link crash cannot silently upload the durable staging temp", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  const originalRemove = fsp.rm;
  let skippedCleanup = 0;
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("disposable crash before hardlink to target");
  };
  fsp.rm = async (name, ...args) => {
    if (isHistoricalRestoreStageTempPath(name)) {
      skippedCleanup += 1;
      return;
    }
    return originalRemove(name, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_materialization_missing",
      "the staged file must not survive a falsely successful cleanup unnoticed");
  } finally { fsp.rm = originalRemove; }
  assert.equal(skippedCleanup, 1, "injected process kill must preserve producer's exact staging temp");
  const [signed] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  const intent = f.engine.journal.restoreStagingInfo(signed);
  assert.ok(intent, "signed outbox must preserve its physically pinned staging intent");
  const staged = resolveHistoricalRestoreStagePath(f.local, intent.name);
  assert.equal((await fsp.lstat(staged, { bigint: true })).ino.toString(), intent.ino);
  assert.equal(fs.existsSync(target), false);
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
  }).open();
  await assert.rejects(reopened.syncOnce(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0, "a staged but never linked file must not create remote content");
  assert.equal(fs.existsSync(staged), true, "manual recovery must still have the original bytes");
  assert.equal((await reopened.journal.recover()).length, 1);
});

test("#67 P2: crash after staging name intent but before inode bind cannot upload orphan", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalBind = f.engine.journal.bindRestoreStagingIdentity.bind(f.engine.journal);
  const originalRemove = fsp.rm;
  let injected = 0;
  f.engine.journal.bindRestoreStagingIdentity = async () => {
    injected += 1;
    throw new Error("disposable kill after file data fsync before inode intent bind");
  };
  fsp.rm = async (name, ...args) => {
    if (isHistoricalRestoreStageTempPath(name)) return;
    return originalRemove(name, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_materialization_missing",
      "even an unbound staging intent must fail closed if cleanup leaves the temp");
  } finally {
    fsp.rm = originalRemove;
    f.engine.journal.bindRestoreStagingIdentity = originalBind;
  }
  assert.equal(injected, 1);
  const [signed] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  const intent = f.engine.journal.restoreStagingInfo(signed);
  assert.ok(intent && intent.name && intent.dev === null && intent.ino === null);
  const staged = resolveHistoricalRestoreStagePath(f.local, intent.name);
  assert.equal((await fsp.lstat(staged)).nlink, 1);
  assert.equal(fs.existsSync(target), false);
  const originalList = f.adapter.list;
  f.adapter.list = async (id) => id ? originalList(id) : [await originalList(id)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory, ...f.physical.options,
  }).open();
  await assert.rejects(reopened.syncOnce(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(staged), true, "cannot discard or upload the unbound exact-stage bytes");
  assert.equal((await reopened.journal.recover()).length, 1);
});

test("#67 P2: O_EXCL staging collision cannot delete another user's file", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalOpen = fsp.open;
  const foreign = Buffer.from("FOREIGN_STAGING_COLLISION_MUST_SURVIVE");
  let collided = null;
  fsp.open = async (name, flags, ...args) => {
    if (!collided && typeof name === "string" && isHistoricalRestoreStageTempPath(name)
      && typeof flags === "number" && (flags & fs.constants.O_EXCL)) {
      collided = name;
      await fsp.writeFile(name, foreign, { flag: "wx" });
    }
    return originalOpen(name, flags, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "EEXIST");
  } finally { fsp.open = originalOpen; }
  assert.ok(collided, "the collision must occur after durable signed name intent");
  assert.deepEqual(await fsp.readFile(collided), foreign,
    "finally must never delete the foreign file when exclusive creation failed");
  assert.equal(f.pushes(), 0);
  const [pending] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(pending.authorization, pending, f.trusted), true);
  assert.equal(f.engine.journal.hasMaterializedRestore(pending), false);
});

test("#67 P2: staging bytes changed immediately before signed hardlink cannot gain witness", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalLink = fsp.link;
  const foreign = Buffer.from("FOREIGN_EDIT_REPLACES_AUTHENTICATED_STAGED_BYTES");
  let edited = 0;
  fsp.link = async (source, destination) => {
    if (destination === target && isHistoricalRestoreStageTempPath(source)) {
      edited += 1;
      // Genuine on-disk edit through the same pathname after the outbox
      // bound its name/inode but immediately before the filesystem link.
      await fsp.writeFile(source, foreign);
    }
    return originalLink(source, destination);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_materialization_missing");
  } finally { fsp.link = originalLink; }
  assert.equal(edited, 1, "the adversarial edit must strike the real hardlink path");
  assert.equal(f.pushes(), 0, "mutated bytes must not be presented as signed materialization");
  const [signed] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  assert.equal(f.engine.journal.hasMaterializedRestore(signed), false);
  assert.equal(f.engine.snapshot.files["document.txt"], undefined);
  assert.deepEqual(await fsp.readFile(target), foreign,
    "a conflicting local file must remain for manual recovery, not be silently removed");
});

test("#67 P2: witnessed offline restore never removes a user's matching-suffix hardlink", async (t) => {
  const f = await fixture(t);
  const actualPush = f.adapter.push;
  f.adapter.push = async () => {
    throw Object.assign(new Error("disposable offline"), { code: "offline" });
  };
  try {
    const result = await f.engine.restoreHistoricalVersion("file-1", "first");
    assert.equal(result.pending, true);
    const [signed] = await f.engine.journal.recover();
    assert.equal(f.engine.journal.hasMaterializedRestore(signed), true);
    assert.equal(f.engine.journal.restoreStagingInfo(signed), null);
    const target = path.join(f.local, "document.txt");
    const userLink = `${target}.tmp-${process.pid}-${crypto.randomUUID()}`;
    await fsp.link(target, userLink);
    await assert.rejects(f.engine.syncOnce(),
      (error) => error.code === "unsafe_path" || error.code === "restore_local_materialization_missing");
    assert.equal(fs.existsSync(userLink), true,
      "a valid local restore witness must NEVER authorize cleanup of a later user alias");
    assert.equal((await fsp.lstat(userLink)).nlink, 2);
    assert.equal((await f.engine.journal.recover()).length, 1);
    assert.equal(f.pushes(), 0);
  } finally { f.adapter.push = actualPush; }
});

test("#67: hardlink permission failure preserves local bytes and blocks remote restore", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const old = Buffer.from("newer synchronized local bytes");
  await fsp.writeFile(target, old);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(old).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const originalLink = fsp.link;
  fsp.link = async (source, destination) => {
    if (destination === target && source.includes(".tmp-")) {
      throw Object.assign(new Error("simulated hardlink permission denial"), { code: "EACCES" });
    }
    return originalLink(source, destination);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /hardlink permission denial/);
  } finally { fsp.link = originalLink; }
  assert.deepEqual(await fsp.readFile(target), old);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 1);
  await assert.rejects(f.engine.syncOnce(), (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0);
});

test("#67: failed restore temp cleanup cannot dispatch or become an ordinary CREATE", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalUnlink = fsp.unlink;
  const originalRm = fsp.rm;
  let injected = 0;
  const failCleanup = async (file) => {
    if (isHistoricalRestoreStageTempPath(file)) {
      injected += 1;
      throw Object.assign(new Error("simulated restore temporary cleanup failure"), { code: "EPERM" });
    }
    return false;
  };
  fsp.unlink = async (file, ...rest) => {
    await failCleanup(file);
    return originalUnlink(file, ...rest);
  };
  fsp.rm = async (file, options) => {
    await failCleanup(file);
    return originalRm(file, options);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "EPERM");
  } finally {
    fsp.unlink = originalUnlink;
    fsp.rm = originalRm;
  }
  assert.ok(injected >= 1, "the actual restore-temp cleanup must be exercised");
  assert.equal(f.pushes(), 0, "cleanup failure must stop the first remote POST");
  assert.equal((await f.engine.journal.recover()).length, 1,
    "the exact signed outbox must remain pending");
  const signedPending = (await f.engine.journal.recover())[0];
  const privatePrefix = `restore-materialize-${crypto.createHash("sha256")
    .update(signedPending.operationId).digest("hex")}.tmp-`;
  assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
  const trash = await fsp.readdir(path.join(f.local, ".rootark-trash"));
  assert.equal(trash.filter((name) => name.startsWith(privatePrefix)).length, 1,
    "preserved plaintext temp must be confined to excluded local trash");
  if (process.platform === "win32") {
    // NTFS permits a case-only rename of the same physical file. A pending
    // signed restore must not treat the renamed residue as a missing temp.
    const physicalName = trash.find((name) => name.startsWith(privatePrefix));
    const renamed = physicalName.replace(/^restore-materialize-/, "RESTORE-MATERIALIZE-")
      .replace(".tmp-", ".TMP-");
    const trashDir = path.join(f.local, ".rootark-trash");
    await fsp.rename(path.join(trashDir, physicalName), path.join(trashDir, renamed));
    assert.ok((await fsp.readdir(trashDir)).includes(renamed),
      "test must physically reproduce mixed-case private residue on Windows");
  }
  // The private temp still hardlinks the destination (nlink=2), so the
  // existing inode-bound scanner must reject the destination fail-closed.
  // Its private alias must never be promoted as an ordinary CREATE.
  await assert.rejects(f.engine.scanFiles(), (error) => error.code === "unsafe_path");
  assert.deepEqual((await fsp.readdir(f.local)).filter((name) => name.includes(".tmp-")), []);
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  await assert.rejects(reopened.reconcileLocal(),
    (error) => error.code === "restore_local_materialization_missing");
  await assert.rejects(reopened.pushPending({ pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false }),
    (error) => error.code === "restore_local_materialization_missing");
  const afterRestart = await reopened.journal.recover();
  assert.equal(afterRestart.length, 1, "restart must not enqueue the private temp as CREATE");
  assert.match(afterRestart[0].operationId, /^histrestore-/);
  assert.equal(f.pushes(), 0);
});

test("#67: interrupted restore temp write remains outside scan after restart", async (t) => {
  const f = await fixture(t);
  const originalOpen = fsp.open;
  const originalRm = fsp.rm;
  let interrupted = 0;
  fsp.open = async (file, ...rest) => {
    const handle = await originalOpen(file, ...rest);
    if (isHistoricalRestoreStageTempPath(file)) {
      const originalWrite = handle.writeFile.bind(handle);
      Object.defineProperty(handle, "writeFile", {
        value: async (data, options) => {
          await originalWrite(data, options);
          interrupted += 1;
          throw new Error("simulated abrupt stop after temp write");
        },
        configurable: true,
      });
    }
    return handle;
  };
  fsp.rm = async (file, options) => {
    if (interrupted > 0 && isHistoricalRestoreStageTempPath(file)) return;
    return originalRm(file, options);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_materialization_missing");
  } finally {
    fsp.open = originalOpen;
    fsp.rm = originalRm;
  }
  assert.equal(interrupted, 1, "must interrupt actual plaintext temp materialization");
  assert.equal(f.pushes(), 0);
  const [signedPending] = await f.engine.journal.recover();
  assert.match(signedPending.operationId, /^histrestore-/);
  assert.deepEqual((await fsp.readdir(f.local)).filter((name) => name.includes(".tmp-")), []);
  const trash = await fsp.readdir(path.join(f.local, ".rootark-trash"));
  const privatePrefix = `restore-materialize-${crypto.createHash("sha256")
    .update(signedPending.operationId).digest("hex")}.tmp-`;
  assert.equal(trash.filter((name) => name.startsWith(privatePrefix)).length, 1);
  assert.deepEqual(Object.keys(await f.engine.scanFiles()), [],
    "orphaned temp must not be visible to local reconciliation");
  await assert.rejects(f.engine.reconcileLocal(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal((await f.engine.journal.recover()).length, 1,
    "only the original signed restore may remain after recovery");
  assert.equal(f.pushes(), 0);
});

test("#67: legacy root-level restore temp cannot become a CREATE or bypass direct pushPending", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalLink = fsp.link;
  fsp.link = async (source, destination) => {
    if (destination === target && source.includes(".tmp-")) {
      throw Object.assign(new Error("simulated pre-link crash"), { code: "EACCES" });
    }
    return originalLink(source, destination);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /pre-link crash/);
  } finally { fsp.link = originalLink; }
  const pending = await f.engine.journal.recover();
  assert.equal(pending.length, 1);
  const bytes = protocol.decryptPayload(f.original, f.privateFileKey);
  await fsp.writeFile(target, bytes);
  const legacyTemp = `${target}.tmp-4242-${crypto.randomUUID()}`;
  await fsp.writeFile(legacyTemp, bytes);
  assert.deepEqual(await fsp.readFile(legacyTemp), bytes);
  await assert.rejects(f.engine.pushPending({ pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false }),
    (error) => error.code === "restore_local_materialization_missing");
  await assert.rejects(f.engine.reconcileLocal(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0);
  assert.deepEqual((await f.engine.journal.recover()).map((item) => item.operationId),
    [pending[0].operationId], "no unsanctioned CREATE may be enqueued");
  assert.deepEqual(await fsp.readFile(legacyTemp), bytes, "original residue preserved for investigation");
});

test("#67: preexisting legacy temp must fail before signing or enqueueing a new restore", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const other = `${target}.tmp-4242-${crypto.randomUUID()}`;
  await fsp.writeFile(other, "preexisting independent bytes");
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0, "never dispatch a restore whose temp evidence is unresolved");
  assert.deepEqual(await f.engine.journal.recover(), [],
    "preflight must not create a newly stranded signed outbox");
  assert.equal(fs.existsSync(target), false, "preflight must not materialize the destination");
  assert.equal(await fsp.readFile(other, "utf8"), "preexisting independent bytes");
});

test("#67: unrelated legitimate tmp-shaped file remains visible and cannot block a restore", async (t) => {
  const f = await fixture(t);
  const unrelated = `notes.txt.tmp-999-${crypto.randomUUID()}`;
  const unrelatedPath = path.join(f.local, unrelated);
  await fsp.writeFile(unrelatedPath, "owner-authored temporary name");
  const trashDir = path.join(f.local, ".rootark-trash");
  await fsp.mkdir(trashDir, { recursive: true });
  const unrelatedResidue = path.join(trashDir,
    `restore-materialize-${"0".repeat(64)}.tmp-999-${crypto.randomUUID()}`);
  await fsp.writeFile(unrelatedResidue, "unrelated restore incident evidence");
  const initial = await f.engine.scanFiles();
  assert.equal(initial[unrelated]?.directory, false,
    "the scanner must not blanket-ignore user files by a .tmp naming pattern");
  const restored = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(restored.pushed, true);
  assert.equal(f.pushes(), 1);
  assert.equal(await fsp.readFile(unrelatedPath, "utf8"), "owner-authored temporary name");
  assert.equal(await fsp.readFile(unrelatedResidue, "utf8"),
    "unrelated restore incident evidence", "another incident's private evidence is preserved");
});

test("#67: an untracked file created after enqueue is never replaced by restore", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const enqueue = f.engine.journal.enqueue.bind(f.engine.journal);
  f.engine.journal.enqueue = async (operation) => {
    const result = await enqueue(operation);
    await fsp.writeFile(target, "NEW UNTRACKED FILE");
    return result;
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.equal(await fsp.readFile(target, "utf8"), "NEW UNTRACKED FILE");
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

for (const mode of ["normal", "lost-ack-409", "lost-ack-expired", "lost-ack-503"]) {
const lostAck = mode !== "normal";
const poisonOnAck = mode === "lost-ack-409";
test(`#67 P1: real atomic device registry ${mode} historical restore only after physical CURRENT`, async (t) => {
  const f = await fixture(t);
  // The atomic registry requires its own protected storage directory rather
  // than sharing the disposable local client/witness fixture root.
  const registryRoot = path.join(f.root, "physical-registry");
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(registryRoot);
  else fs.mkdirSync(registryRoot, { mode: 0o700 });
  const storagePath = path.join(registryRoot, "physical-store.json");
  const store = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  await store.enrollDevice({ username: "alice", deviceId: "device-a",
    publicKey: f.publicKeySpki, expectedEpoch: 0 });
  assert.equal((await store.put("alice", f.original)).kind, "stored");
  assert.equal((await store.put("alice", f.deleted)).kind, "stored");
  f.adapter.history = async (id) => ({ protocolVersion: 2, versions: store.history("alice", id) });
  f.adapter.list = async (id) => store.list("alice", id)[0];
  // Read CURRENT from the actual reopened, durable atomic registry. Signing
  // keys live separately in the test authority; neither signer receives the
  // server's HTTP response as evidence of physical persistence.
  f.physical.useReopenedPhysicalSource(async () => {
    const bytes = await fsp.readFile(storagePath);
    const reopened = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
    const [operation] = reopened.list("alice", "file-1");
    const physicalHead = crypto.createHash("sha256").update(bytes).digest("hex");
    const contentHead = crypto.createHash("sha256")
      .update(protocol.canonicalJson(operation)).digest("hex");
    return { operation, storeHeadSha256: contentHead,
      commitId: Buffer.from(physicalHead, "hex").toString("base64url"),
      fencingEpoch: reopened.atomicRegistryEpoch() };
  });
  const originalWitness = f.physical.options.atomicBatchWitnessReadback;
  const originalCas = f.physical.options.atomicBatchCasFloorReadback;
  const originalDateNow = Date.now;
  let clockValue = originalDateNow();
  const nativeTestCreateHash = crypto.createHash.bind(crypto);
  const nativeTestHashUpdate = crypto.Hash.prototype.update;
  const nativeTestHashDigest = crypto.Hash.prototype.digest;
  const nativeTestReflectApply = Reflect.apply;
  const requestDigest = (operation) => {
    const hash = nativeTestCreateHash("sha256");
    nativeTestReflectApply(nativeTestHashUpdate, hash, [protocol.canonicalJson(operation)]);
    return nativeTestReflectApply(nativeTestHashDigest, hash, ["hex"]);
  };
  const originals = {
    createHash: crypto.createHash, verify: crypto.verify, randomBytes: crypto.randomBytes,
    timingSafeEqual: crypto.timingSafeEqual, hashUpdate: crypto.Hash.prototype.update,
    hashDigest: crypto.Hash.prototype.digest, bufferFrom: Buffer.from,
    bufferIsBuffer: Buffer.isBuffer, bufferConcat: Buffer.concat,
    bufferToString: Buffer.prototype.toString,
  };
  const restoreIntrinsics = () => {
    crypto.createHash = originals.createHash;
    crypto.verify = originals.verify;
    crypto.randomBytes = originals.randomBytes;
    crypto.timingSafeEqual = originals.timingSafeEqual;
    crypto.Hash.prototype.update = originals.hashUpdate;
    crypto.Hash.prototype.digest = originals.hashDigest;
    Buffer.from = originals.bufferFrom;
    Buffer.isBuffer = originals.bufferIsBuffer;
    Buffer.concat = originals.bufferConcat;
    Buffer.prototype.toString = originals.bufferToString;
  };
  const poisonIntrinsics = () => {
    crypto.createHash = () => { throw new Error("poisoned createHash during lost-ACK recovery"); };
    crypto.verify = () => { throw new Error("poisoned verify during lost-ACK recovery"); };
    crypto.randomBytes = () => { throw new Error("poisoned randomBytes during lost-ACK recovery"); };
    crypto.timingSafeEqual = () => { throw new Error("poisoned timingSafeEqual during lost-ACK recovery"); };
    crypto.Hash.prototype.update = () => { throw new Error("poisoned Hash.update during lost-ACK recovery"); };
    crypto.Hash.prototype.digest = () => { throw new Error("poisoned Hash.digest during lost-ACK recovery"); };
    Buffer.from = () => { throw new Error("poisoned Buffer.from during lost-ACK recovery"); };
    Buffer.isBuffer = () => false;
    Buffer.concat = () => { throw new Error("poisoned Buffer.concat during lost-ACK recovery"); };
    Buffer.prototype.toString = () => { throw new Error("poisoned Buffer.toString during lost-ACK recovery"); };
  };
  let attempts = 0;
  const requests = [];
  f.adapter.push = async (operation) => {
    attempts++;
    requests.push({ operationId: operation.operationId,
      digest: requestDigest(operation) });
    if (attempts > 1 && mode === "lost-ack-409") {
      // This in-process adapter also hosts the real durable server. Restore
      // its native primitives before the physical replay, then re-poison the
      // untrusted client side; otherwise the server's ACL validator itself
      // inherits the injected Buffer/crypto functions.
      if (poisonOnAck) restoreIntrinsics();
      try {
        const replay = await store.put("alice", operation);
        assert.equal(replay.kind, "replay",
          "the real store's seen-operation replay is what the HTTP route maps to 409");
      } finally {
        if (poisonOnAck) poisonIntrinsics();
      }
      throw Object.assign(new Error("Already applied signed CAS revision"),
        { status: 409, code: "sync_conflict" });
    }
    const admitted = await store.put("alice", operation);
    assert.equal(admitted.kind, "stored");
    if (poisonOnAck) {
      poisonIntrinsics();
      throw Object.assign(new Error("HTTP ACK lost after fsynced store commit"),
        { code: "offline" });
    }
    if (mode === "lost-ack-expired") {
      clockValue = originalDateNow() + 24 * 60 * 60 * 1000;
      throw Object.assign(new Error("HTTP ACK lost before the signed grant expired"), { code: "offline" });
    }
    if (mode === "lost-ack-503") {
      throw Object.assign(new Error("HTTP 503 after the durable store commit"),
        { status: 503, code: "sync_remote_uncertain" });
    }
    return admitted.record;
  };
  const before = await fsp.readFile(storagePath, "utf8");
  const engine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    clock: () => clockValue,
    ...f.physical.options,
    atomicBatchWitnessReadback: async (challenge) => {
      if (poisonOnAck) restoreIntrinsics();
      try {
        const signed = await originalWitness(challenge);
        if (poisonOnAck) poisonIntrinsics();
        return signed;
      } catch (error) { if (poisonOnAck) poisonIntrinsics(); throw error; }
    },
    atomicBatchCasFloorReadback: async (challenge) => {
      if (poisonOnAck) restoreIntrinsics();
      try {
        const signed = await originalCas(challenge);
        if (poisonOnAck) poisonIntrinsics();
        return signed;
      } catch (error) { if (poisonOnAck) poisonIntrinsics(); throw error; }
    },
  }).open();
  let restored;
  try { restored = await engine.restoreHistoricalVersion("file-1", "first"); }
  finally { restoreIntrinsics(); }
  assert.equal(restored.pushed, true);
  assert.equal((await engine.journal.recover()).length, 0,
    "only verified physical CURRENT can consume the exact signed pending restore");
  assert.equal(attempts, mode === "lost-ack-409" ? 2 : 1);
  if (mode === "lost-ack-409") {
    assert.deepEqual(requests[1], requests[0],
      "lost-ACK retry must resend the identical operationId and canonical signed-envelope digest");
  } else if (lostAck) {
    assert.equal(requests.length, 1,
      "expired authorization and 503 readback must not cause an unproven second PUT");
  }
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal(store.history("alice", "file-1").length, 3);
  const durable = JSON.parse(await fsp.readFile(storagePath, "utf8"));
  assert.equal(durable.users.alice.objects["file-1"].operationId, restored.operationId);
  assert.equal(JSON.parse(before).users.alice.versions["file-1"].length, 2);
  const reopened = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  assert.equal(reopened.list("alice", "file-1")[0].versionId, restored.versionId);
});
}
test("#67 P2: restore succeeds across signed fileId rotation create(oldId) -> update(newId) -> delete(newId)", async (t) => {
  const f = await fixture(t);
  const oldId = "old-file-id";
  const newId = "rotated-file-id";
  const originalBytes = Buffer.from("original authenticated bytes");
  const updatedBytes = Buffer.from("updated authenticated bytes");
  const created = await f.sign({ operation: "create", fileId: oldId, versionId: "v1-created", operationId: "op1",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "document.txt", name: "document.txt" },
    plaintext: originalBytes });
  const updated = await f.sign({ operation: "update", fileId: newId, versionId: "v2-updated", operationId: "op2",
    baseRevision: created.revision, revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: updatedBytes });
  const deleted = await f.sign({ operation: "delete", fileId: newId, versionId: "v3-deleted", operationId: "op3",
    baseRevision: updated.revision, revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "document.txt" } });
  f.versions.splice(0, f.versions.length, created, updated, deleted);
  f.setCurrent(deleted);
  const restored = await f.engine.restoreHistoricalVersion("file-1", "v1-created");
  assert.equal(restored.pushed, true);
  assert.equal(restored.sourceVersionId, "v1-created");
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal(f.current().fileId, newId, "restored revision inherits current rotated fileId");
});

test("#67 P1: file-key resolver cannot replace historical signed A with another signed B", async (t) => {
  const f = await fixture(t);
  const alternate = await f.sign({ operation: "create", versionId: "alternate-B", operationId: "alternate-B-op",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("substituted historical B") });
  const originalResolver = f.engine.fileKeyResolver;
  let resolverSnapshot = null;
  let mutationBlocked = false;
  f.engine.fileKeyResolver = async (operation) => {
    if (operation.operationId === f.original.operationId) {
      resolverSnapshot = {
        operationId: operation.operationId,
        frozen: Object.isFrozen(operation),
        nullPrototype: Object.getPrototypeOf(operation) === null,
      };
      try { Object.assign(operation, alternate); }
      catch { mutationBlocked = true; }
    }
    return originalResolver(operation);
  };

  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.restored, true);
  assert.deepEqual(resolverSnapshot, {
    operationId: f.original.operationId, frozen: true, nullPrototype: true,
  });
  assert.equal(mutationBlocked, true);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal(protocol.decryptPayload(f.current(), f.privateFileKey).toString(), "original authenticated bytes");
});

test("#67 P1: keyFor revalidates the captured key epoch after the resolver await", async (t) => {
  const f = await fixture(t);
  f.engine.fileKeyResolver = async () => {
    f.engine.keyEpoch = "epoch-2";
    return f.privateFileKey;
  };
  await assert.rejects(f.engine.keyFor(f.original),
    (error) => error.code === "sync_key_epoch_mismatch"
      || error.code === "historical_restore_callback_changed");
  assert.equal(f.pushes(), 0);
});

test("#67 P1: authorize callback cannot replace the captured file-key resolver", async (t) => {
  const f = await fixture(t);
  const originalAuthorize = f.engine.authorize;
  const originalResolver = f.engine.fileKeyResolver;
  f.engine.authorize = async (operation) => {
    const result = await originalAuthorize(operation);
    f.engine.fileKeyResolver = async () => Buffer.alloc(32, 0x77);
    return result;
  };
  await assert.rejects(f.engine.keyFor(f.original),
    (error) => error.code === "historical_restore_callback_changed");
  f.engine.fileKeyResolver = originalResolver;
  assert.equal(f.pushes(), 0);
});

test("#67 P1: protocol and authorization validation ignore poisoned String, RegExp, Number and Date intrinsics", async (t) => {
  const f = await fixture(t);
  const originalNumberIsSafeInteger = Number.isSafeInteger;
  const originalRegExpTest = Object.getOwnPropertyDescriptor(RegExp.prototype, "test");
  const originalLocaleCompare = Object.getOwnPropertyDescriptor(String.prototype, "localeCompare");
  const originalSplit = Object.getOwnPropertyDescriptor(String.prototype, "split");
  const originalDateNow = Date.now;
  const nativeStringIncludes = String.prototype.includes;
  const nativeReflectApply = Reflect.apply;
  let badRevisionError;
  let badIdError;
  let badPathError;
  let revisionOrder;
  try {
    Number.isSafeInteger = () => true;
    Object.defineProperty(RegExp.prototype, "test", {
      ...originalRegExpTest,
      value() { return true; },
    });
    Object.defineProperty(String.prototype, "localeCompare", {
      ...originalLocaleCompare,
      value() { throw new Error("poisoned localeCompare"); },
    });
    Object.defineProperty(String.prototype, "split", {
      ...originalSplit,
      value(separator, limit) {
        if (separator === "/" || separator === path.sep) throw new Error("poisoned path split");
        return nativeReflectApply(originalSplit.value, this, limit === undefined ? [separator] : [separator, limit]);
      },
    });

    const malformedRevision = structuredClone(f.original);
    malformedRevision.revision.counter = 1.5;
    malformedRevision.authorization.revision.counter = 1.5;
    try { protocol.validateStoredOperation(malformedRevision); }
    catch (error) { badRevisionError = error; }

    const malformedId = structuredClone(f.original);
    malformedId.operationId = "invalid operation id";
    malformedId.authorization.operationId = "invalid operation id";
    try { protocol.validateStoredOperation(malformedId); }
    catch (error) { badIdError = error; }

    try { badPathError = protocol.safeRelativePath("nested/document.txt", "path"); }
    catch (error) { badPathError = error; }
    revisionOrder = protocol.compareRevisions(
      { counter: 1, deviceId: "device-a" },
      { counter: 1, deviceId: "device-b" },
    );
  } finally {
    Number.isSafeInteger = originalNumberIsSafeInteger;
    Object.defineProperty(RegExp.prototype, "test", originalRegExpTest);
    Object.defineProperty(String.prototype, "localeCompare", originalLocaleCompare);
    Object.defineProperty(String.prototype, "split", originalSplit);
  }

  assert.ok(badRevisionError, "a fractional signed revision must remain invalid when Number.isSafeInteger is poisoned");
  assert.ok(badIdError, "an invalid operation ID must remain invalid when RegExp.prototype.test is poisoned");
  assert.equal(badPathError, "nested/document.txt", "portable path validation must not call mutable String.prototype.split");
  assert.equal(revisionOrder, -1, "revision tie-breaking must use the captured comparison primitive");

  // Allow enough time for Ed25519/CBOR setup even on loaded Windows runners.
  // Wait for the actual trusted clock boundary, not a fragile 40/75ms race.
  const expiresAt = originalDateNow() + 3000;
  const expiring = await f.sign({
    operation: "update", versionId: "expiring-proof", operationId: "expiring-proof-op",
    baseRevision: f.deleted.revision, revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("expired authorization proof"),
  }, { expiresAt });
  while (originalDateNow() <= expiresAt) {
    await new Promise((resolve) => setTimeout(resolve,
      Math.min(100, Math.max(1, expiresAt - originalDateNow() + 1))));
  }
  let expiryError;
  try {
    Date.now = () => 0;
    await verifyAuthorizationProof(expiring.authorization, expiring, f.trusted);
  } catch (error) { expiryError = error; }
  finally { Date.now = originalDateNow; }
  assert.equal(expiryError?.code, "authorization_expired",
    "a poisoned wall clock must not make an expired signed grant fresh");
});

test("#67 P1: historical restore survives String, RegExp, Number, BigInt and Object.entries poisoning after history readback", async (t) => {
  const f = await fixture(t);
  const descriptors = {
    numberSafeInteger: Object.getOwnPropertyDescriptor(Number, "isSafeInteger"),
    regexpTest: Object.getOwnPropertyDescriptor(RegExp.prototype, "test"),
    regexpExec: Object.getOwnPropertyDescriptor(RegExp.prototype, "exec"),
    stringSplit: Object.getOwnPropertyDescriptor(String.prototype, "split"),
    stringStartsWith: Object.getOwnPropertyDescriptor(String.prototype, "startsWith"),
    stringSlice: Object.getOwnPropertyDescriptor(String.prototype, "slice"),
    stringLocaleCompare: Object.getOwnPropertyDescriptor(String.prototype, "localeCompare"),
    bigintToString: Object.getOwnPropertyDescriptor(BigInt.prototype, "toString"),
    objectEntries: Object.getOwnPropertyDescriptor(Object, "entries"),
  };
  const nativeStringIncludes = String.prototype.includes;
  const nativeReflectApply = Reflect.apply;
  const restore = () => {
    Object.defineProperty(Number, "isSafeInteger", descriptors.numberSafeInteger);
    Object.defineProperty(RegExp.prototype, "test", descriptors.regexpTest);
    Object.defineProperty(RegExp.prototype, "exec", descriptors.regexpExec);
    Object.defineProperty(String.prototype, "split", descriptors.stringSplit);
    Object.defineProperty(String.prototype, "startsWith", descriptors.stringStartsWith);
    Object.defineProperty(String.prototype, "slice", descriptors.stringSlice);
    Object.defineProperty(String.prototype, "localeCompare", descriptors.stringLocaleCompare);
    Object.defineProperty(BigInt.prototype, "toString", descriptors.bigintToString);
    Object.defineProperty(Object, "entries", descriptors.objectEntries);
  };
  const poison = () => {
    Object.defineProperty(Number, "isSafeInteger", {
      ...descriptors.numberSafeInteger,
      value(value) {
        if (value === 1 || value === 2 || value === 3) throw new Error("poisoned Number.isSafeInteger");
        return nativeReflectApply(descriptors.numberSafeInteger.value, Number, [value]);
      },
    });
    Object.defineProperty(RegExp.prototype, "test", {
      ...descriptors.regexpTest,
      value(value) {
        if (nativeReflectApply(nativeStringIncludes, this.source, ["A-Za-z0-9"]) ||
            nativeReflectApply(nativeStringIncludes, this.source, ["0-9a-f"])) {
          throw new Error("poisoned RegExp.prototype.test");
        }
        return nativeReflectApply(descriptors.regexpTest.value, this, [value]);
      },
    });
    Object.defineProperty(RegExp.prototype, "exec", {
      ...descriptors.regexpExec,
      value(value) {
        if (nativeReflectApply(nativeStringIncludes, this.source, ["A-Za-z0-9"]) ||
            nativeReflectApply(nativeStringIncludes, this.source, ["0-9a-f"])) {
          throw new Error("poisoned RegExp.prototype.exec");
        }
        return nativeReflectApply(descriptors.regexpExec.value, this, [value]);
      },
    });
    Object.defineProperty(String.prototype, "split", {
      ...descriptors.stringSplit,
      value(separator, limit) {
        if (separator === "/" || separator === path.sep) throw new Error("poisoned String.prototype.split");
        return nativeReflectApply(descriptors.stringSplit.value, this,
          limit === undefined ? [separator] : [separator, limit]);
      },
    });
    Object.defineProperty(String.prototype, "startsWith", {
      ...descriptors.stringStartsWith,
      value(prefix, ...args) {
        if (prefix === "histrestore-" || prefix === ".rootark-restore-") {
          throw new Error("poisoned String.prototype.startsWith");
        }
        return nativeReflectApply(descriptors.stringStartsWith.value, this, [prefix, ...args]);
      },
    });
    Object.defineProperty(String.prototype, "slice", {
      ...descriptors.stringSlice,
      value(start, end) {
        if (nativeReflectApply(nativeStringIncludes, this, [".rootark-restore-"]) ||
            nativeReflectApply(nativeStringIncludes, this, ["histrestore-"])) {
          throw new Error("poisoned String.prototype.slice");
        }
        return nativeReflectApply(descriptors.stringSlice.value, this,
          end === undefined ? [start] : [start, end]);
      },
    });
    Object.defineProperty(String.prototype, "localeCompare", {
      ...descriptors.stringLocaleCompare,
      value() { throw new Error("poisoned String.prototype.localeCompare"); },
    });
    Object.defineProperty(BigInt.prototype, "toString", {
      ...descriptors.bigintToString,
      value() { throw new Error("poisoned BigInt.prototype.toString"); },
    });
    Object.defineProperty(Object, "entries", {
      ...descriptors.objectEntries,
      value() { throw new Error("poisoned Object.entries"); },
    });
  };

  const originalHistory = f.adapter.history;
  f.adapter.history = async (...args) => {
    const result = await originalHistory(...args);
    poison();
    return result;
  };
  let restored;
  try { restored = await f.engine.restoreHistoricalVersion("file-1", "first"); }
  finally { restore(); }
  assert.equal(restored.restored, true);
  assert.equal(f.pushes(), 1);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67 P1: authorization factory cannot substitute the newly signed historical restore envelope", async (t) => {
  const f = await fixture(t);
  const alternate = await f.sign({ operation: "update", versionId: "forged-B", operationId: "histrestore-forged-B",
    baseRevision: f.deleted.revision, revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("substituted signed B") });
  const originalFactory = f.engine.authorizationFactory;
  let factorySnapshot = null;
  let mutationBlocked = false;
  f.engine.authorizationFactory = async (operation) => {
    if (operation.operationId.startsWith("histrestore-")) {
      factorySnapshot = {
        operationId: operation.operationId,
        frozen: Object.isFrozen(operation),
        nullPrototype: Object.getPrototypeOf(operation) === null,
      };
      try { Object.assign(operation, alternate); }
      catch { mutationBlocked = true; }
      factorySnapshot.operationIdAfterAttempt = operation.operationId;
    }
    return originalFactory(operation);
  };

  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.restored, true);
  assert.ok(factorySnapshot);
  assert.equal(factorySnapshot.frozen, true);
  assert.equal(factorySnapshot.nullPrototype, true);
  assert.equal(factorySnapshot.operationIdAfterAttempt, factorySnapshot.operationId);
  assert.notEqual(result.operationId, alternate.operationId);
  assert.equal(mutationBlocked, true);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal(protocol.decryptPayload(f.current(), f.privateFileKey).toString(), "original authenticated bytes");
});

test("#67 P1: opaque HTTP adapter POST serializes the frozen A envelope despite JSON hooks", async (t) => {
  const f = await fixture(t);
  const alternate = await f.sign({ operation: "update", versionId: "wire-forged-B", operationId: "histrestore-wire-B",
    baseRevision: f.deleted.revision, revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("wire substitution B") });
  const originalStringifyDescriptor = Object.getOwnPropertyDescriptor(JSON, "stringify");
  const originalStringify = JSON.stringify;
  const originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  const postedBodies = [];
  let poisoned = false;
  const opaqueAdapter = createOpaqueSyncAdapter({
    fetchImpl: async (_url, options) => {
      postedBodies.push(options.body);
      return { ok: true, status: 200, json: async () => ({}) };
    },
  });
  f.adapter.push = opaqueAdapter.push;
  f.adapter.validate = opaqueAdapter.validate;
  f.adapter.normalize = opaqueAdapter.normalize;
  f.engine.authorizeOutgoing = (operation) => {
    if (!poisoned && operation.operationId.startsWith("histrestore-")) {
      poisoned = true;
      Object.defineProperty(Object.prototype, "toJSON", {
        configurable: true,
        enumerable: false,
        writable: true,
        value(key) {
          if (key === "" && typeof this?.operationId === "string"
            && this.operationId.startsWith("histrestore-")) return alternate;
          return this;
        },
      });
      Object.defineProperty(JSON, "stringify", {
        ...originalStringifyDescriptor,
        value(value, replacer, space) {
          if (value && typeof value.operationId === "string"
            && value.operationId.startsWith("histrestore-")) return originalStringify(alternate);
          return originalStringify(value, replacer, space);
        },
      });
    }
    return true;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_remote_admission_unproven");
    const [pending] = await f.engine.journal.recover();
    assert.equal(poisoned, true);
    assert.equal(postedBodies.length, 1);
    assert.equal(postedBodies[0], protocol.canonicalJson(pending),
      "the exact frozen signed envelope must be the serialized POST body");
    assert.notEqual(postedBodies[0], protocol.canonicalJson(alternate));
    assert.notEqual(pending.operationId, alternate.operationId);
  } finally {
    Object.defineProperty(JSON, "stringify", originalStringifyDescriptor);
    if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, "toJSON", originalToJSONDescriptor);
    else delete Object.prototype.toJSON;
  }
});

test("#262 P1: serializer fence rejects signed B after previously serializing pending A", async (t) => {
  const f = await fixture(t);
  const alternate = await f.sign({ operation: "update", versionId: "wire-B",
    operationId: "histrestore-wire-second-B", baseRevision: f.deleted.revision,
    revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("unexpected signed B") });
  let firstBody;
  let transmitted = false;
  f.adapter.push = (original) => {
    firstBody = JSON.stringify(original);
    JSON.stringify(alternate); // Must reject before any malicious B transmission.
    transmitted = true;
    return Promise.resolve({ status: 200 });
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_remote_admission_unproven");
  const [pending] = await f.engine.journal.recover();
  assert.equal(firstBody, protocol.canonicalJson(pending));
  assert.equal(transmitted, false);
  assert.notEqual(pending.operationId, alternate.operationId);
  assert.equal(f.engine.journal.hasSeen(pending.operationId), false);
});

test("#262 P1: proxy transport ACK cannot trigger traps or consume queued signed restore", async (t) => {
  const f = await fixture(t);
  let descriptorTraps = 0;
  f.adapter.push = () => new Proxy({ status: 200 }, {
    getOwnPropertyDescriptor() {
      descriptorTraps += 1;
      throw new Error("untrusted transport response descriptor trap ran");
    },
  });
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_remote_admission_unproven");
  assert.equal(descriptorTraps, 0);
  const [pending] = await f.engine.journal.recover();
  assert.ok(pending.operationId.startsWith("histrestore-"));
  assert.equal(f.engine.journal.hasSeen(pending.operationId), false);
});

test("#67 P1: ZK maps reject stateful accessors and CBOR encoding snapshots before await", async () => {
  const manifest = issue67ZkManifestV1();
  let getterCalls = 0;
  Object.defineProperty(manifest, "compartment_id", {
    configurable: true,
    enumerable: true,
    get() { getterCalls += 1; return issue67ZkBytes(1); },
  });
  await assert.rejects(zk.buildManifestMap(manifest), (error) => error.code === "AMBIGUOUS_MAP");
  assert.equal(getterCalls, 0, "normalization must inspect the descriptor without invoking the getter");

  const graph = { nested: { counter: 1 }, items: [1, 2] };
  const encoding = zk.encodeDeterministic(graph);
  graph.nested.counter = 2;
  graph.items[0] = 9;
  const decoded = await zk.decodeDeterministic(await encoding);
  assert.equal(decoded.nested.counter, 1);
  assert.equal(decoded.items[0], 1);

  const stateful = {};
  let statefulReads = 0;
  Object.defineProperty(stateful, "value", {
    configurable: true,
    enumerable: true,
    get() { statefulReads += 1; return statefulReads; },
  });
  await assert.rejects(zk.encodeDeterministic(stateful), (error) => error.code === "UNSUPPORTED_CBOR_VALUE");
  assert.equal(statefulReads, 0);
});

test("#67 P1: ZK v2 scope singleton gate is independent of mutable hasOwn and Array.some", async () => {
  const recipient = await zk.hpkeSuite().kem.generateKeyPair();
  const signing = crypto.generateKeyPairSync("ed25519");
  const sealed = await zk.sealAuthorizationEnvelopeV2({
    static_core: issue67ZkStaticCoreV2(),
    recipientPublicKey: recipient.publicKey,
    signingKey: signing.privateKey,
    plaintext: issue67ZkBytes(31, 32),
    wrapped_key: issue67ZkBytes(32, 60),
    ciphertext: issue67ZkBytes(33, 48),
  });
  const originalHasOwn = Object.getOwnPropertyDescriptor(Object, "hasOwn");
  const originalSome = Object.getOwnPropertyDescriptor(Array.prototype, "some");
  for (const mode of ["hasOwn", "some", "both"]) {
    try {
      if (mode === "hasOwn" || mode === "both") {
        Object.defineProperty(Object, "hasOwn", {
          ...originalHasOwn,
          value(value, key) {
            if (value && typeof value === "object"
              && originalHasOwn.value(value, "now") && originalHasOwn.value(value, "claimReplay")) return true;
            return originalHasOwn.value(value, key);
          },
        });
      }
      if (mode === "some" || mode === "both") {
        Object.defineProperty(Array.prototype, "some", {
          ...originalSome,
          value(callback, thisArg) {
            if (this.length === 9 && this[0] === "sender_key_id" && this[1] === "recipient_key_id") return false;
            return Reflect.apply(originalSome.value, this, [callback, thisArg]);
          },
        });
      }
      let error;
      try {
        await zk.verifyAuthorization(sealed.manifest, sealed.signature, signing.publicKey,
          { now: 900, claimReplay: async () => true });
      } catch (caught) { error = caught; }
      assert.equal(error?.code, "EXPECTED_SCOPE_REQUIRED", `missing V2 scope must fail closed under ${mode} poisoning`);
    } finally {
      Object.defineProperty(Object, "hasOwn", originalHasOwn);
      Object.defineProperty(Array.prototype, "some", originalSome);
    }
  }
});

test("#67 P1: captured crypto, Buffer, Hash, HMAC, Cipher, Decipher and nonce primitives survive poisoning", async () => {
  const manifest = issue67ZkManifestV1();
  const { hpke_info_digest: _hpke, wrapped_key_digest: _wrapped, ciphertext_digest: _ciphertext, ...core } = manifest;
  const signing = crypto.generateKeyPairSync("ed25519");
  const key = issue67ZkBytes(41, 32);
  const hkdfSalt = issue67ZkBytes(2, 16);
  const nonce = issue67ZkBytes(42, 12);
  const aad = Buffer.from("intrinsic-pinning-aad");
  const plaintext = Buffer.from("intrinsic-pinning-plaintext");
  const wrapInput = {
    suite: zk.SUITE_ID, compartment_id: issue67ZkBytes(1), epoch: 7, purpose: "content",
    object_id: issue67ZkBytes(4), version_id: issue67ZkBytes(5), key_ref: issue67ZkBytes(6),
    recipient_key_id: issue67ZkBytes(3), wrap_id: issue67ZkBytes(9, 16),
    cer: issue67ZkBytes(15, 32), aad: Buffer.from("wrap-intrinsic-aad"),
    plaintext: issue67ZkBytes(12, 32),
  };
  const operationInput = {
    operation: "create", objectId: "file-1", fileId: "file-1", deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private", operationId: "intrinsic-op",
    versionId: "intrinsic-version", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "intrinsic.txt", name: "intrinsic.txt" }, plaintext, fileKey: key,
  };
  const hashProbe = crypto.createHash("sha256");
  const hmacProbe = crypto.createHmac("sha256", key);
  const cipherProbe = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const decipherProbe = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  const slots = [
    [crypto, "createHash"], [crypto, "createHmac"], [crypto, "sign"], [crypto, "verify"],
    [crypto, "hkdfSync"], [crypto, "randomBytes"], [crypto, "createCipheriv"],
    [crypto, "createDecipheriv"], [crypto, "timingSafeEqual"],
    [Buffer, "from"], [Buffer, "alloc"], [Buffer, "concat"], [Buffer, "isBuffer"],
    [Buffer.prototype, "subarray"], [Buffer.prototype, "fill"], [Buffer.prototype, "toString"],
    [Object.getPrototypeOf(hashProbe), "update"], [Object.getPrototypeOf(hashProbe), "digest"],
    [Object.getPrototypeOf(hmacProbe), "update"], [Object.getPrototypeOf(hmacProbe), "digest"],
    [Object.getPrototypeOf(cipherProbe), "setAAD"], [Object.getPrototypeOf(cipherProbe), "update"],
    [Object.getPrototypeOf(cipherProbe), "final"], [Object.getPrototypeOf(cipherProbe), "getAuthTag"],
    [Object.getPrototypeOf(decipherProbe), "setAAD"], [Object.getPrototypeOf(decipherProbe), "setAuthTag"],
    [Object.getPrototypeOf(decipherProbe), "update"], [Object.getPrototypeOf(decipherProbe), "final"],
  ];
  const descriptors = slots.map(([target, keyName]) => Object.getOwnPropertyDescriptor(target, keyName));
  const poison = () => { throw new Error("poisoned native primitive"); };
  const secret = Buffer.alloc(4, 7);
  let signature;
  let verified;
  let coreDigest;
  let derived;
  let sealed;
  let opened;
  let wrapped;
  let unwrapped;
  let wrapId;
  let recoverySalt;
  let movePayload;
  let decodedMove;
  let operation;
  let decrypted;
  try {
    for (const [target, keyName] of slots) {
      Object.defineProperty(target, keyName, {
        configurable: true,
        enumerable: false,
        writable: true,
        value: poison,
      });
    }
    signature = await zk.signAuthorization(manifest, signing.privateKey);
    verified = await zk.verifyAuthorization(manifest, signature, signing.publicKey);
    coreDigest = await zk.buildManifestCoreDigest(core);
    derived = zk.hkdfSha256({ ikm: key, salt: hkdfSalt, info: aad, length: 32 });
    sealed = zk.aesGcmSeal({ key, nonce, aad, plaintext });
    opened = zk.aesGcmOpen({ key, nonce, aad, ...sealed });
    wrapped = await zk.wrapKey(wrapInput);
    unwrapped = await zk.unwrapKey({ ...wrapInput, wrapped });
    wrapId = zk.newWrapId();
    recoverySalt = zk.newRecoverySalt();
    movePayload = protocol.encodeMovePayload(plaintext, key);
    decodedMove = protocol.decodeMovePayload(movePayload, key);
    operation = protocol.createOperation(operationInput);
    decrypted = protocol.decryptPayload(operation, key);
    zk.clearSecret(secret);
  } finally {
    for (let index = slots.length - 1; index >= 0; index -= 1) {
      const [target, keyName] = slots[index];
      if (descriptors[index]) Object.defineProperty(target, keyName, descriptors[index]);
      else delete target[keyName];
    }
  }
  assert.equal(verified, true);
  assert.equal(signature.length, 64);
  assert.equal(coreDigest.length, 32);
  assert.equal(derived.length, 32);
  assert.deepEqual(opened, plaintext);
  assert.equal(wrapped.length, 60);
  assert.deepEqual(unwrapped, wrapInput.plaintext);
  assert.equal(wrapId.length, 16);
  assert.equal(recoverySalt.length, 16);
  assert.deepEqual(decodedMove, plaintext);
  assert.deepEqual(decrypted, plaintext);
  assert.equal(secret.every((byte) => byte === 0), true);
});

test("#67 P1: lost ACK retry uses the real HTTP route's 409 and the identical signed POST body", async (t) => {
  configureStrictSqliteAuthority(t);
  const f = await fixture(t);
  const registryRoot = path.join(f.root, "physical-registry");
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(registryRoot);
  else fs.mkdirSync(registryRoot, { mode: 0o700 });
  const storagePath = path.join(registryRoot, "physical-store.json");
  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const routes = registerSyncRoutes({
    app,
    storagePath,
    atomicDeviceRegistry: true,
    requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => {
      req.user = {
        username: "alice", role: "user", sessionVersion: 0,
        permissions: { upload: true, delete: true },
      };
      next();
    },
    requirePermission: (permission) => (req, res, next) => {
      if (req.user?.permissions?.[permission] === true) return next();
      return res.status(403).json({ error: "forbidden" });
    },
  });
  await routes.ready;
  const server = await new Promise((resolve, reject) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
    listening.once("error", reject);
  });
  t.after(async () => {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  });

  const store = routes.store;
  await store.enrollDevice({ username: "alice", deviceId: "device-a",
    publicKey: f.publicKeySpki, expectedEpoch: 0 });
  assert.equal((await store.put("alice", f.original)).kind, "stored");
  assert.equal((await store.put("alice", f.deleted)).kind, "stored");
  f.adapter.history = async (id) => ({ protocolVersion: 2, versions: store.history("alice", id) });
  f.adapter.list = async (id) => store.list("alice", id)[0];
  f.physical.useReopenedPhysicalSource(async () => {
    const bytes = await fsp.readFile(storagePath);
    const readbackCopy = path.join(registryRoot, `physical-readback-${crypto.randomUUID()}.json`);
    await fsp.writeFile(readbackCopy, bytes, { flag: "wx", mode: 0o600 });
    try {
      // Reopen the exact byte snapshot that was hashed. Reading the live file
      // again after opening a second store could mix two concurrent commits.
      const reopened = await new SyncObjectStore(readbackCopy, { atomicDeviceRegistry: true }).open();
      const [operation] = reopened.list("alice", "file-1");
      const physicalHead = crypto.createHash("sha256").update(bytes).digest("hex");
      const contentHead = crypto.createHash("sha256")
        .update(protocol.canonicalJson(operation)).digest("hex");
      return {
        operation,
        storeHeadSha256: contentHead,
        commitId: Buffer.from(physicalHead, "hex").toString("base64url"),
        fencingEpoch: reopened.atomicRegistryEpoch(),
      };
    } finally { await fsp.rm(readbackCopy, { force: true }); }
  });

  const nativeCreateHash = crypto.createHash.bind(crypto);
  const nativeHashUpdate = crypto.Hash.prototype.update;
  const nativeHashDigest = crypto.Hash.prototype.digest;
  const nativeReflectApply = Reflect.apply;
  const requestDigest = (operation) => {
    const hash = nativeCreateHash("sha256");
    nativeReflectApply(nativeHashUpdate, hash, [protocol.canonicalJson(operation)]);
    return nativeReflectApply(nativeHashDigest, hash, ["hex"]);
  };
  let attempts = 0;
  const requests = [];
  const fetchImpl = async (url, options) => {
    // The independently signed POST is serialized before the network call.
    // The live server shares this test process; primitive attacks are tested
    // separately so they cannot corrupt the trusted physical readback here.
    attempts += 1;
    const parsed = JSON.parse(options.body);
    const entry = {
      body: options.body,
      operationId: parsed.operationId,
      digest: requestDigest(parsed),
      status: null,
    };
    requests.push(entry);
    const response = await nativeFetch(url, options);
    entry.status = response.status;
    if (attempts === 1) {
      await response.arrayBuffer();
      throw new TypeError("fetch failed", {
        cause: Object.assign(new Error("socket closed after the real route committed the signed operation"), {
          code: "UND_ERR_SOCKET",
        }),
      });
    }
    entry.error = (await response.clone().json()).error;
    return response;
  };
  const opaqueAdapter = createOpaqueSyncAdapter({
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    fetchImpl,
  });
  f.adapter.push = opaqueAdapter.push;
  f.adapter.validate = opaqueAdapter.validate;
  f.adapter.normalize = opaqueAdapter.normalize;

  const engine = await new SyncEngine({
    rootDir: f.local, journal: f.engine.journal, adapter: f.adapter,
    deviceId: f.engine.deviceId, keyEpoch: f.engine.keyEpoch,
    compartmentId: f.engine.compartmentId, fileKeyResolver: f.engine.fileKeyResolver,
    requireAuthorization: true, authorize: f.engine.authorize,
    authorizeOutgoing: f.engine.authorizeOutgoing, verifyIncoming: f.engine.verifyIncoming,
    authorizationFactory: f.engine.authorizationFactory,
    ...f.physical.options,
  }).open();
  const restored = await engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(restored.restored, true);
  assert.equal(restored.pushed, true);
  assert.equal(attempts, 2);
  assert.equal(requests[0].status, 201, "the first real POST must commit before its ACK is discarded");
  assert.equal(requests[1].status, 409, "the real sync route must translate the store replay into HTTP 409");
  assert.equal(requests[1].error, "Replay rejected", "409 must be the persisted seen-operation replay, not a stale-revision conflict");
  assert.equal(requests[1].body, requests[0].body, "retry must send the byte-identical frozen envelope");
  assert.equal(requests[1].operationId, requests[0].operationId);
  assert.equal(requests[1].digest, requests[0].digest);
  assert.equal(requests[0].body, protocol.canonicalJson(JSON.parse(requests[0].body)));
  assert.equal((await engine.journal.recover()).length, 0);
  const durable = JSON.parse(await fsp.readFile(storagePath, "utf8"));
  assert.equal(durable.users.alice.seen[restored.operationId], true,
    "the original operationId must remain durably recorded as seen after the lost ACK");
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal(store.history("alice", "file-1").length, 3);
  const reopened = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  assert.equal(reopened.list("alice", "file-1")[0].operationId, restored.operationId);
});

test("#262 P1: ordinary markSeen cannot discharge a pending signed historical restore", async (t) => {
  const f = await fixture(t);
  const signed = await f.sign({ operation: "update",
    operationId: `histrestore-${crypto.randomUUID()}`, versionId: "unadmitted-restore",
    revision: { counter: 3, deviceId: "device-a" }, baseRevision: f.deleted.revision,
    metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("signed but not physically admitted") });
  await f.engine.journal.enqueue(signed);
  await assert.rejects(f.engine.journal.markSeen(signed.operationId),
    /independently verified markSeenExact/,
    "even a direct ordinary journal ACK must preserve the original signed restore");
  const [pending] = await f.engine.journal.recover();
  assert.equal(pending.operationId, signed.operationId);
  assert.equal(f.engine.journal.hasSeen(signed.operationId), false);
});

test("#262 P2: independent physical restore ACK promotes the durable observation", async (t) => {
  const f = await fixture(t);
  const outcome = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(outcome.pushed, true);
  const digest = f.engine.journal.durableSignedReceiptDigest(outcome.operationId);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(f.engine.journal.state.admitted[outcome.operationId], digest,
    "independently verified acknowledgement must promote the exact signed receipt");
  assert.equal(Object.hasOwn(f.engine.journal.state.observed, outcome.operationId), false,
    "the pre-observation must not consume a slot after physical admission");
  assert.deepEqual(await f.engine.journal.recover(), []);
});

test("#271 P2: physical historical restore ACK is atomic with 10,000 occupied observation slots", async (t) => {
  const f = await fixture(t);
  const otherDigest = "a".repeat(64);
  // Reach the actual durable capacity boundary, rather than mocking a
  // capacity error. These unrelated observations must remain untouched.
  await f.engine.journal.commit((next) => {
    for (let index = 0; index < 10_000; index += 1) {
      next.observed[`capacity-${String(index).padStart(5, "0")}`] = otherDigest;
    }
  });
  assert.equal(Object.keys(f.engine.journal.state.observed).length, 10_000);

  const outcome = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(outcome.pushed, true,
    "signed physical witness + CURRENT CAS must not require a free pre-observation slot");
  const digest = f.engine.journal.durableSignedReceiptDigest(outcome.operationId);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(f.engine.journal.state.admitted[outcome.operationId], digest);
  assert.equal(f.engine.journal.hasSeen(outcome.operationId), true);
  assert.equal(Object.hasOwn(f.engine.journal.state.observed, outcome.operationId), false);
  assert.equal(Object.keys(f.engine.journal.state.observed).length, 10_000,
    "physical admission must not evict unrelated pending observations");
  assert.equal(f.engine.journal.state.observed["capacity-00000"], otherDigest);
  assert.equal(f.engine.journal.state.observed["capacity-09999"], otherDigest);
  assert.deepEqual(await f.engine.journal.recover(), [],
    "exact signed restore must leave pending state only with a durable ACK");
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
    "original authenticated bytes");
});

test("#262 P1: excluded signed restore LIST echo cannot consume pending physical admission", async (t) => {
  const f = await fixture(t);
  let echoed;
  f.adapter.push = async (operation) => {
    echoed = structuredClone(operation);
    throw Object.assign(new Error("unproven server-side CAS conflict"),
      { code: "sync_conflict", status: 409, current: structuredClone(operation) });
  };
  const queued = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(queued.pending, true);
  assert.ok(echoed?.operationId.startsWith("histrestore-"));
  f.engine.excludedPaths = ["document.txt"];
  f.adapter.list = async () => [structuredClone(echoed)];
  const summary = { pulled: 0, applied: 0, offline: false, conflicts: [] };
  await f.engine.pullRemote(summary);
  assert.equal(summary.pulled, 0);
  assert.equal(f.engine.journal.hasSeen(echoed.operationId), false);
  const [pending] = await f.engine.journal.recover();
  assert.equal(pending.operationId, echoed.operationId,
    "LIST cannot erase the signed outbox or its restore materialization record");
  assert.equal(f.engine.journal.hasMaterializedRestore(pending), true);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
    "original authenticated bytes");
});

test("#262 P2: committed restore recovers after key epoch rotation without old file key", async (t) => {
  const f = await fixture(t);
  let committedOp = null;
  let witnessOffline = true;
  const origPush = f.adapter.push;
  const statePath = path.join(f.root, "witness-store-current.json");
  f.adapter.push = async (operation) => {
    if (!committedOp) {
      committedOp = await origPush(operation);
      throw Object.assign(new Error("ACK lost after remote commit"), { code: "ECONNRESET" });
    }
    throw Object.assign(new Error("Replay conflict after rotation"), { status: 409, code: "sync_conflict" });
  };
  f.physical.useReopenedPhysicalSource(async () => {
    if (witnessOffline) throw Object.assign(new Error("witness offline"), { code: "ECONNRESET" });
    return JSON.parse(await fsp.readFile(statePath, "utf8"));
  });
  f.adapter.list = async () => [structuredClone(f.current())];
  const queued = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(queued.restored, true);
  assert.equal(queued.pushed, false);
  assert.equal(queued.pending, true);
  const [pendingOp] = await f.engine.journal.recover();
  assert.ok(pendingOp?.operationId.startsWith("histrestore-"));
  assert.ok(committedOp);
  witnessOffline = false;

  const epoch2Key = crypto.randomBytes(32);
  const rotatedEngine = await new SyncEngine({
    rootDir: f.local,
    adapter: f.adapter,
    deviceId: "device-a",
    keyEpoch: "epoch-2",
    compartmentId: "private",
    fileKeyResolver: (op) => (op.keyEpoch === "epoch-2" ? epoch2Key : null),
    requireAuthorization: true,
    authorize: () => true,
    authorizeOutgoing: () => true,
    verifyIncoming: (record) => verifyAuthorizationProof(record.authorization, record, f.trusted),
    authorizationFactory: (operation) => createAuthorizationProof(operation, {
      username: "alice", privateKey: f.privateKey, publicKey: f.publicKeySpki,
    }),
    ...f.physical.options,
  }).open();

  const summary = await rotatedEngine.syncOnce();
  assert.equal(summary.offline, false);
  assert.equal(summary.pushed, 1);
  assert.deepEqual(await rotatedEngine.journal.recover(), []);
  assert.equal(rotatedEngine.journal.hasSeen(pendingOp.operationId), true);
  assert.equal(rotatedEngine.journal.durableSignedReceiptDigest(pendingOp.operationId) !== null, true);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
});

test("#262 P2: genuine 409 restore conflict recovers verified remote winner instead of stalling offline", async (t) => {
  for (const mode of ["inline-current", "list-fallback"]) {
    await t.test(mode, async (st) => {
      const f = await fixture(st);
      let offline = true;
      f.adapter.push = async (operation) => {
        if (offline) throw Object.assign(new Error("offline during restore"), { code: "ECONNRESET" });
        const err = new Error("Stale baseRevision conflict");
        err.status = 409;
        err.code = "sync_conflict";
        if (mode === "inline-current") err.current = structuredClone(f.current());
        throw err;
      };
      const queued = await f.engine.restoreHistoricalVersion("file-1", "first");
      assert.equal(queued.pending, true);
      const [pendingOp] = await f.engine.journal.recover();
      assert.ok(pendingOp?.operationId.startsWith("histrestore-"));

      const { privateKey: keyB, publicKey: pubB } = crypto.generateKeyPairSync("ed25519");
      const pubBSpki = pubB.export({ type: "spki", format: "der" }).toString("base64url");
      f.trusted.trustedDevicePublicKeys["device-b"] = pubBSpki;
      const remoteWin = protocol.createOperation({
        objectId: "file-1", fileId: "file-1", deviceId: "device-b", keyEpoch: "epoch-1",
        compartmentId: "private", fileKey: f.privateFileKey,
        operation: "update", versionId: "remote-v3", operationId: `remote-win-${crypto.randomUUID()}`,
        revision: { counter: 3, deviceId: "device-b" }, baseRevision: f.deleted.revision,
        metadata: { path: "document.txt", name: "document.txt" },
        plaintext: Buffer.from("device-b winner"),
      });
      remoteWin.authorization = await createAuthorizationProof(remoteWin, {
        username: "alice", privateKey: keyB, publicKey: pubBSpki,
      });
      f.setCurrent(remoteWin);
      f.versions.push(remoteWin);
      await f.physical.physicalStoreCommitted(remoteWin);
      f.adapter.list = async () => [structuredClone(f.current())];
      offline = false;

      const summary = await f.engine.syncOnce();
      assert.equal(summary.offline, false, "genuine 409 conflict must not stall syncOnce offline");
      assert.equal(summary.conflicts.length, 1);
      assert.equal(summary.conflicts[0].operationId, pendingOp.operationId);
      assert.deepEqual(await f.engine.journal.recover(), [], "rejected restore must not remain pending");
      assert.equal(f.engine.journal.state.admitted[pendingOp.operationId], undefined,
        "rejected restore must never be fabricated as admitted");
      assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "device-b winner");
      assert.equal(await fsp.readFile(path.join(f.local, ".rootark-conflicts", `${pendingOp.operationId}.conflict`), "utf8"),
        "original authenticated bytes");
    });
  }
});
