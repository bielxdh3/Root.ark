"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { sealZk1CatalogMetadataV1, openZk1CatalogMetadataV1 } =
  require("../src/crypto/rootark-zk1-opaque-catalog-client-v1");
const { catalogPageDigest, catalogHeaderMessage, catalogHeadDigest } =
  require("../src/services/zk1OpaqueCatalog");

test("portable ZK1 catalog cryptography isolates names and binds AEAD to exact version/scope", async () => {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("a"), keyring_id: crypto.randomBytes(16) };
  const objectId = crypto.randomBytes(16).toString("base64url");
  const metadataKey = crypto.randomBytes(32);
  const name = "private/path/documentação-2026.pdf";
  const input = { scope, objectId, revision: 3, epoch: 2, metadataKey, name };
  const sealed = await sealZk1CatalogMetadataV1(input);
  assert.equal(sealed.length, 284);
  assert.ok(!sealed.includes(Buffer.from(name)));
  assert.equal(await openZk1CatalogMetadataV1({
    ...input, ciphertext: sealed }), name);
  for (const modified of [
    { ...input, revision: 2 }, { ...input, epoch: 1 },
    { ...input, objectId: crypto.randomBytes(16).toString("base64url") },
    { ...input, scope: { ...scope, keyring_id: crypto.randomBytes(16) } },
    { ...input, metadataKey: crypto.randomBytes(32) },
  ]) await assert.rejects(openZk1CatalogMetadataV1({
    ...modified, ciphertext: sealed }), /ZK_CATALOG_UNVERIFIED/);
  const corrupted = Buffer.from(sealed);
  corrupted[100] ^= 1;
  await assert.rejects(openZk1CatalogMetadataV1({
    ...input, ciphertext: corrupted }), /ZK_CATALOG_UNVERIFIED/);
  const page = [{ object_id: objectId, revision: 3, epoch: 2,
    ciphertext_digest: crypto.randomBytes(32), metadata_ciphertext: sealed }];
  const pageDigest = await catalogPageDigest(page);
  assert.equal(pageDigest.length, 32);
  const changed = [{ ...page[0], metadata_ciphertext: corrupted }];
  assert.notDeepEqual(await catalogPageDigest(changed), pageDigest);
  const signer = crypto.generateKeyPairSync("ed25519");
  const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
    sequence: 1, previous_digest: Buffer.alloc(32),
    manifest_revision: 1, manifest_digest: crypto.randomBytes(32),
    epoch: 2, signer_device_id: "device", total_count: 1,
    page_digests: [pageDigest], issued_at: 1000 };
  const message = await catalogHeaderMessage(header);
  const signature = crypto.sign(null, message, signer.privateKey);
  assert.equal(crypto.verify(null, message, signer.publicKey, signature), true);
  const z = require("../src/crypto/rootark-zk-1");
  const digest = catalogHeadDigest(Buffer.from(await z.encodeDeterministic(header)), signature);
  assert.equal(digest.length, 32);
  assert.notDeepEqual(catalogHeadDigest(Buffer.from(await z.encodeDeterministic({
    ...header, total_count: 0 })), signature), digest);
});
