"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto").webcrypto;
const rename = require("../public/client/rootark-zk1-client-rename-move");

const id = Buffer.alloc(16, 3).toString("base64url");
const scope = { account_id: id, compartment_id: id, keyring_id: id };

function uploadFixture() {
  const effects = { signedReads: 0, intentWrites: 0, puts: 0 };
  const writer = {
    async readAll() {
      effects.signedReads++;
      if (effects.signedReads > 1) throw Error("stop after filename preflight");
      return { head: { sequence: 0, digest: new Uint8Array(32) }, rows: [] };
    },
    async prepareIntent() { effects.intentWrites++; throw Error("unexpected intent"); },
  };
  const context = vm.createContext({
    crypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, WeakMap,
    btoa, atob, objectId: id,
    RootarkZk1BrowserOpaqueCatalogCommit: { createClient: () => writer },
    RootarkZk1ProtectedHttpClient: {
      signProtectedContentOperation: async () => { effects.puts++; throw Error("unexpected PUT"); },
    },
    RootarkZk1CiphertextRoot: { computeCiphertextRoot: async () => new Uint8Array(32) },
    RootarkZk1FileContent: {},
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-opaque-device-delta-sync.js"), "utf8"), context);
  const commit = vm.runInContext(`async (name) => {
    const client = RootarkZk1OpaqueDeviceDeltaSync.createClient({
      authority: { signedDeviceGrant: {}, pinnedOwnerHead: {
        epoch: 1, digest: new Uint8Array(32) }, signerGrants: [],
        csrfToken: () => "csrf", isSessionCurrent: () => true },
      assertLive: () => true,
    });
    const previous = await client.readCurrent();
    return client.commitVersion({ previous, objectId, expectedRevision: null,
      revision: 1, epoch: 1, ciphertext: new Uint8Array(32), name,
      metadataKey: null });
  }`, context);
  return { commit, effects };
}

test("composed upload rejects overlong UTF-8 before signed reads, intent and PUT", async () => {
  for (const name of ["é".repeat(111), "a".repeat(221), "bad\u0000name"]) {
    const { commit, effects } = uploadFixture();
    await assert.rejects(commit(name), /ZK_OPAQUE_DELTA_SYNC_DENIED/);
    assert.deepEqual(effects, { signedReads: 1, intentWrites: 0, puts: 0 },
      "only the initial signed snapshot read is allowed");
  }
});

test("composed upload admits exactly 220 UTF-8 bytes to signed authority preflight", async () => {
  for (const name of ["a".repeat(220), "é".repeat(110)]) {
    assert.equal(Buffer.byteLength(name, "utf8"), 220);
    const { commit, effects } = uploadFixture();
    await assert.rejects(commit(name), /ZK_OPAQUE_DELTA_SYNC_DENIED/);
    assert.deepEqual(effects, { signedReads: 2, intentWrites: 0, puts: 0 },
      "valid name must pass metadata prevalidation and reach fresh signed read");
  }
});

function renameFixture(destinationName, composed) {
  const effects = { liveChecks: 0, intentWrites: 0, puts: 0, archiveWrites: 0 };
  const sourceMetadata = { ...scope, object_id: id, version_id: id,
    parent_version_id: null, epoch: 1, kind: "file" };
  const input = {
    catalog: { entries: [{ objectId: id, epoch: 1, revision: 1,
      ciphertextDigestBase64: Buffer.alloc(32).toString("base64url") }] },
    sourceIndex: 0, sourceMetadata, sourceCek: null,
    destinationName, destinationParentFolderId: null,
    ownerPublicKey: null, pinnedOwnerKeyHash: new Uint8Array(32),
    independentOwnerSpkiSha256: new Uint8Array(32),
    pinnedCurrentHead: { revision: 1, epoch: 1, digest: new Uint8Array(32) },
    signedDeviceGrant: { ...scope }, ownerHistoryCheckpoint: null,
    previousOwnerHistoryProof: null, devicePublicKey: null, devicePrivateKey: null,
    origin: "https://example.invalid", nowSeconds: () => 100,
    assertLive: () => { effects.liveChecks++; },
    fetchImpl: async () => { effects.puts++; throw Error("unexpected HTTP request"); },
  };
  if (composed) {
    input.catalogWriter = {
      readAll: async () => { throw Error("unexpected catalog read"); },
      prepareIntent: async () => { effects.intentWrites++; throw Error("unexpected intent"); },
      commit: async () => { throw Error("unexpected catalog commit"); },
      confirmPendingIntent: async () => { throw Error("unexpected intent confirmation"); },
    };
    input.metadataKey = { type: "secret", extractable: false,
      algorithm: { name: "AES-GCM", length: 256 }, usages: ["encrypt"] };
    input.cekArchive = {
      write: async () => { effects.archiveWrites++; throw Error("unexpected archive write"); },
      read: async () => { throw Error("unexpected archive read"); },
    };
  }
  return { input, effects };
}

for (const composed of [false, true]) {
  const operation = composed ? "renameOrMoveCommitted" : "renameOrMove";
  test(`${operation} rejects overlong UTF-8 and ASCII names without effects`, async () => {
    for (const name of ["é".repeat(111), "a".repeat(221), "a".repeat(255)]) {
      const { input, effects } = renameFixture(name, composed);
      await assert.rejects(rename[operation](input), /ZK_CLIENT_RENAME_MOVE_DENIED/);
      assert.deepEqual(effects, { liveChecks: 0, intentWrites: 0,
        puts: 0, archiveWrites: 0 },
      "invalid filename must fail before trust checks, signed intent, archive and PUT");
    }
  });

  test(`${operation} accepts the exact 220-byte name preflight boundary`, async () => {
    for (const name of ["a".repeat(220), "é".repeat(110)]) {
      assert.equal(Buffer.byteLength(name, "utf8"), 220);
      const { input, effects } = renameFixture(name, composed);
      // The fixture deliberately lacks an owner's public key; after name
      // admission it must reach the independent cryptographic grant check.
      await assert.rejects(rename[operation](input), /ZK_CLIENT_RENAME_MOVE_DENIED/);
      assert.ok(effects.liveChecks > 0,
        "valid boundary name must advance to cryptographic verification");
      assert.equal(effects.intentWrites, 0);
      assert.equal(effects.puts, 0);
      assert.equal(effects.archiveWrites, 0);
    }
  });
}
