"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const {
  createAuthenticatedOpaqueCatalogArchiveV2: create,
  verifyAuthenticatedOpaqueCatalogArchiveV2: verify,
} = require("../src/crypto/rootark-zk1-opaque-catalog-checkpoint-v2");

const HEAD = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");

async function signedGenesis(scope, signer) {
  const header = Buffer.from(await z.encodeDeterministic({
    type: "rootark-zk1-opaque-catalog/v1", ...scope,
    sequence: 1, previous_digest: Buffer.alloc(32),
    manifest_revision: 1, manifest_digest: crypto.randomBytes(32),
    epoch: 1, signer_device_id: "historical-device", total_count: 0,
    page_digests: [], issued_at: 1792740000,
  }));
  return { sequence: 1, header,
    signature: crypto.sign(null, Buffer.concat([HEAD, header]), signer),
    page_bodies: [] };
}

function fixtures() {
  return { scope: { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("rootark-v2"), keyring_id: crypto.randomBytes(16) },
  device: crypto.generateKeyPairSync("ed25519"),
  checkpoint: crypto.generateKeyPairSync("ed25519") };
}

test("checkpoint authoring seals the sequence validated before an asynchronous signer lookup", async () => {
  const { scope, device, checkpoint } = fixtures();
  const record = await signedGenesis(scope, device.privateKey);
  const inputs = { scope, records: [record], previousSequence: 0,
    previousDigest: Buffer.alloc(32), previousCheckpointDigest: Buffer.alloc(32) };
  const archive = await create({ ...inputs,
    resolveCatalogSigner: async () => {
      record.sequence = 999;
      await Promise.resolve();
      return device.publicKey;
    }, checkpointPrivateKey: checkpoint.privateKey, issuedAt: 1792740001 });
  assert.equal(archive.records.length, 1);
  assert.equal(archive.records[0].sequence, 1);
  const verified = await verify({ ...inputs, records: archive.records,
    ...archive, resolveCatalogSigner: async () => device.publicKey,
    pinnedCheckpointPublicKey: checkpoint.publicKey });
  assert.equal(verified.finalSequence, 1);
});

test("checkpoint uses the bounded record collection captured before an asynchronous lookup", async () => {
  const { scope, device, checkpoint } = fixtures();
  const record = await signedGenesis(scope, device.privateKey);
  const records = [record];
  const archive = await create({ scope, records, previousSequence: 0,
    previousDigest: Buffer.alloc(32), previousCheckpointDigest: Buffer.alloc(32),
    resolveCatalogSigner: async () => {
      records.push({ ...record });
      await Promise.resolve();
      return device.publicKey;
    }, checkpointPrivateKey: checkpoint.privateKey, issuedAt: 1792740001 });
  assert.equal(archive.records.length, 1);
  const verified = await verify({ scope, records: archive.records, previousSequence: 0,
    previousDigest: Buffer.alloc(32), previousCheckpointDigest: Buffer.alloc(32),
    resolveCatalogSigner: async () => device.publicKey,
    pinnedCheckpointPublicKey: checkpoint.publicKey, ...archive });
  assert.equal(verified.finalSequence, 1);
});
