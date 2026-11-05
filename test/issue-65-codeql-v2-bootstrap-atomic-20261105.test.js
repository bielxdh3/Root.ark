"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { Zk1OpaqueCheckpointV2Client } =
  require("../src/services/zk1OpaqueCheckpointV2Client");
const { OpaqueCheckpointV2Authority, createOpaqueCheckpointV2HttpsClient } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { Zk1OpaqueCatalogCheckpointV2Stage } =
  require("../src/services/zk1OpaqueCatalogCheckpointV2Stage");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");

function scenarios() {
  const [cas, floor, checkpoint, owner, catalog, witness, oldCas, oldFloor] =
    Array.from({ length: 8 }, () => crypto.generateKeyPairSync("ed25519"));
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("v2-atomic-bootstrap"), keyring_id: crypto.randomBytes(16) };
  const transport = { endpoint: "https://127.0.0.1:53431/", ca: "fixture-ca",
    clientKey: "fixture-key", clientCert: "fixture-cert",
    serverFingerprint256: "ab:".repeat(31) + "ab" };
  const oldFloorClient = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    ...transport, floorPublicKey: oldFloor.publicKey,
    casSignerPublicKey: oldCas.publicKey, trustedScope: scope });
  const oldCasClient = { publicKey: oldCas.publicKey,
    async readHead() { throw Error("unused"); } };
  const casClient = createOpaqueCheckpointV2HttpsClient({
    ...transport, authorityPublicKey: cas.publicKey,
    casPublicKey: cas.publicKey, floorPublicKey: floor.publicKey, scope });
  const floorClient = createOpaqueCheckpointV2HttpsClient({
    ...transport, authorityPublicKey: floor.publicKey,
    casPublicKey: cas.publicKey, floorPublicKey: floor.publicKey, scope });
  const trust = { pinnedWitness: { publicKey: witness.publicKey },
    minimumHead: {}, freshWitnessHead: async () => { throw Error("unused"); } };
  const baseDigest = crypto.randomBytes(32), baseCheckpoint = crypto.randomBytes(32);
  return [
    { name: "checkpoint V2 local client", construct: (filename) =>
      new Zk1OpaqueCheckpointV2Client({
        journalPath: filename, bootstrapNew: true, trustedScope: scope,
        expectedV1Digest: baseDigest, expectedV1Checkpoint: baseCheckpoint,
        casClient, floorClient, v1CasClient: oldCasClient,
        v1FloorClient: oldFloorClient, checkpointPublicKey: checkpoint.publicKey,
        ownerPublicKey: owner.publicKey, catalogPublicKey: catalog.publicKey,
        ownerTrust: trust }) },
    { name: "checkpoint V2 remote CAS authority", construct: (filename) =>
      new OpaqueCheckpointV2Authority(filename, {
        role: "CAS", bootstrapNew: true, scope,
        signingPrivateKey: cas.privateKey, casSignerPublicKey: cas.publicKey,
        floorSignerPublicKey: floor.publicKey,
        checkpointPublicKey: checkpoint.publicKey, ownerPublicKey: owner.publicKey,
        ownerTrust: { ...trust, genesisDigest: crypto.randomBytes(32) },
        baseDigest, baseCheckpoint }) },
    { name: "checkpoint V2 local stage", construct: (filename) =>
      new Zk1OpaqueCatalogCheckpointV2Stage(filename, {
        bootstrapNew: true, trustedScope: scope,
        ownerPublicKey: owner.publicKey, checkpointPublicKey: checkpoint.publicKey,
        casClient: oldCasClient, floorClient: oldFloorClient,
        resolveCatalogSigner: async () => catalog.publicKey }) },
  ];
}

test("V2 bootstrap authorizes creation with O_EXCL despite an unreliable existence probe", (t) => {
  const root = createPrivateAuthorityFixture("zk65-codeql-v2-atomic-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  for (const [index, scenario] of scenarios().entries()) {
    const filename = path.join(root, `new-${index}.sqlite`);
    const exists = fs.existsSync;
    let queried = 0;
    let authority;
    try {
      fs.existsSync = function unreliableExists(name, ...args) {
        if (name === filename) { queried++; return true; }
        return exists.call(this, name, ...args);
      };
      authority = scenario.construct(filename);
    } finally {
      fs.existsSync = exists;
      authority?.close();
    }
    assert.equal(queried, 0,
      `${scenario.name}: filename existence probe is not creation authority`);
    assert.ok(fs.statSync(filename).size > 0,
      `${scenario.name}: atomic bootstrap must still initialize valid SQLite`);
  }
});

test("V2 O_EXCL bootstraps refuse occupied target without overwriting it", (t) => {
  const root = createPrivateAuthorityFixture("zk65-codeql-v2-collision-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  for (const [index, scenario] of scenarios().entries()) {
    const filename = path.join(root, `occupied-${index}.sqlite`);
    const sentinel = Buffer.from("foreign sqlite fixture must remain untouched");
    fs.writeFileSync(filename, sentinel, { flag: "wx", mode: 0o600 });
    const before = fs.statSync(filename, { bigint: true });
    assert.throws(() => scenario.construct(filename),
      `${scenario.name}: occupied path must never be adopted or overwritten`);
    const after = fs.statSync(filename, { bigint: true });
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.deepEqual(fs.readFileSync(filename), sentinel);
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      assert.equal(fs.existsSync(filename + suffix), false,
        `${scenario.name}: no SQLite sidecar may be created for a foreign path`);
    }
  }
});

test("V2 bootstrap refuses a private same-owner inode replaced after O_EXCL close", (t) => {
  const root = createPrivateAuthorityFixture("zk65-codeql-v2-swap-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  for (const [index, scenario] of scenarios().entries()) {
    const filename = path.join(root, `swapped-${index}.sqlite`);
    const replacement = path.join(root, `replacement-${index}.sqlite`);
    const original = path.join(root, `original-${index}.sqlite`);
    fs.writeFileSync(replacement, Buffer.alloc(0), { flag: "wx", mode: 0o600 });
    const open = fs.openSync, close = fs.closeSync;
    let createdFd = null, swapped = false;
    try {
      fs.openSync = function trackedOpen(name, flags, ...args) {
        const fd = open.call(this, name, flags, ...args);
        if (name === filename && typeof flags === "number"
          && (flags & fs.constants.O_CREAT) && (flags & fs.constants.O_EXCL)) {
          createdFd = fd;
        }
        return fd;
      };
      fs.closeSync = function swapAfterClose(fd) {
        close.call(this, fd);
        if (fd === createdFd && !swapped) {
          swapped = true;
          fs.renameSync(filename, original);
          fs.renameSync(replacement, filename);
        }
      };
      assert.throws(() => scenario.construct(filename),
        `${scenario.name}: swapped SQLite inode must be rejected before WAL/schema write`);
    } finally {
      fs.openSync = open;
      fs.closeSync = close;
    }
    assert.equal(swapped, true, `${scenario.name}: actual exclusive FD must be tested`);
    assert.equal(fs.statSync(filename).size, 0,
      `${scenario.name}: substituted inode must receive no SQLite writes`);
    assert.equal(fs.statSync(original).size, 0,
      `${scenario.name}: originally created inode must remain untouched`);
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      assert.equal(fs.existsSync(filename + suffix), false,
        `${scenario.name}: refused swapped authority must have no sidecars`);
    }
  }
});
