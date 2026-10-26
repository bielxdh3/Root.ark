"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const {
  createAuthenticatedOpaqueCatalogArchiveV2: create,
  verifyAuthenticatedOpaqueCatalogArchiveV2: verify,
  createOpaqueCatalogInclusionProofV2: makeProof,
  verifyAuthenticatedOpaqueCatalogInclusionV2: verifyProof,
  MAX_ARCHIVE_RECORDS,
} = require("../src/crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const HEAD = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const PAGE = Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0");
const CHECKPOINT_SIGN = Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-sign/v2\0");
const DIGEST = Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-digest/v2\0");
const sha = (...parts) => {
  const h = crypto.createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
};
const altered = (input) => {
  const out = Buffer.from(input);
  out[Math.floor(out.length / 2)] ^= 1;
  return out;
};
const rejects = (action) => assert.rejects(action,
  { code: "ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED" });

test("opt-in checkpoint v2: absolute 127->128->129, signed Merkle history, inclusion and canonical bytes", async () => {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("opaque-v2"),
    keyring_id: crypto.randomBytes(16) };
  const checkpointSigner = crypto.generateKeyPairSync("ed25519");
  const deviceSigner = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const resolveCatalogSigner = async () => deviceSigner.publicKey;
  const prefix = { sequence: 126, digest: crypto.randomBytes(32),
    checkpoint: crypto.randomBytes(32) };

  async function header(sequence, previous, withPage = false) {
    const item = { object_id: crypto.randomBytes(16).toString("base64url"),
      revision: 1, epoch: 1, ciphertext_digest: crypto.randomBytes(32),
      metadata_ciphertext: crypto.randomBytes(284) };
    const page = withPage
      ? [Buffer.from(await z.encodeDeterministic([item]))] : [];
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence, previous_digest: previous,
      manifest_revision: 3, manifest_digest: crypto.randomBytes(32),
      epoch: 2, signer_device_id: "authorized-device",
      total_count: withPage ? 1 : 0,
      page_digests: page.map((part) => sha(PAGE, part)),
      issued_at: 1792740000 };
    const raw = Buffer.from(await z.encodeDeterministic(header));
    const signature = crypto.sign(null, Buffer.concat([HEAD, raw]),
      deviceSigner.privateKey);
    return { record: { sequence, header: raw, signature, page_bodies: page },
      digest: sha(HEAD, raw, signature) };
  }
  const first = await header(127, prefix.digest, true);
  const second = await header(128, first.digest);
  const records = [first.record, second.record];
  const inputs = { scope, records, previousSequence: 126,
    previousDigest: prefix.digest, previousCheckpointDigest: prefix.checkpoint,
    resolveCatalogSigner };
  const archive = await create({ ...inputs,
    checkpointPrivateKey: checkpointSigner.privateKey, issuedAt: 1792740001 });
  const verified = await verify({ ...inputs, ...archive,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey,
    expectedFinalSequence: 128, expectedFinalDigest: second.digest });
  assert.equal(verified.previousSequence, 126);
  assert.equal(verified.finalSequence, 128);
  assert.deepEqual(verified.finalDigest, second.digest);
  assert.deepEqual(archive.checkpointDigest,
    sha(DIGEST, archive.checkpointBytes, archive.checkpointSignature));

  const firstProof = await makeProof({ records: archive.records, index: 0 });
  const secondProof = await makeProof({ records: archive.records, index: 1 });
  const request = { checkpointBytes: archive.checkpointBytes,
    checkpointSignature: archive.checkpointSignature,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey,
    scope, expectedPreviousSequence: 126, expectedPreviousDigest: prefix.digest,
    expectedPreviousCheckpointDigest: prefix.checkpoint, resolveCatalogSigner };
  for (const [record, proof, sequence] of [
    [archive.records[0], firstProof, 127], [archive.records[1], secondProof, 128]]) {
    const result = await verifyProof({ ...request, record, proof });
    assert.equal(result.sequence, sequence);
    assert.deepEqual(result.archiveRoot, verified.archiveRoot);
  }

  // Data-level 128->129 continuation is cryptographically representable here.
  // Production CAS/floor/browser v1 MUST continue refusing 129.
  const third = await header(129, second.digest);
  const nextInputs = { scope, records: [third.record], previousSequence: 128,
    previousDigest: second.digest, previousCheckpointDigest: archive.checkpointDigest,
    resolveCatalogSigner };
  const next = await create({ ...nextInputs,
    checkpointPrivateKey: checkpointSigner.privateKey, issuedAt: 1792740002 });
  const verifiedNext = await verify({ ...nextInputs, ...next,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey,
    expectedFinalSequence: 129, expectedFinalDigest: third.digest });
  assert.equal(verifiedNext.finalSequence, 129);
  assert.deepEqual((await verifyProof({
    checkpointBytes: next.checkpointBytes,
    checkpointSignature: next.checkpointSignature,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey, scope,
    record: third.record, proof: await makeProof({ records: next.records, index: 0 }),
    expectedPreviousSequence: 128, expectedPreviousDigest: second.digest,
    expectedPreviousCheckpointDigest: archive.checkpointDigest,
    resolveCatalogSigner,
  })).digest, third.digest);

  // Odd-size Merkle trees duplicate the final leaf at the lowest level;
  // callers cannot substitute a different sibling even if the other levels
  // are unchanged. The full verifier still checks every predecessor link.
  const oddInputs = { ...inputs, records: [first.record, second.record, third.record] };
  const odd = await create({ ...oddInputs,
    checkpointPrivateKey: checkpointSigner.privateKey, issuedAt: 1792740003 });
  assert.equal((await verify({ ...oddInputs, ...odd,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey })).finalSequence, 129);
  const oddProof = await makeProof({ records: odd.records, index: 2 });
  assert.equal(oddProof.siblings.length, 2);
  assert.equal((await verifyProof({ ...request, checkpointBytes: odd.checkpointBytes,
    checkpointSignature: odd.checkpointSignature,
    record: third.record, proof: oddProof })).sequence, 129);
  await rejects(verifyProof({ ...request, checkpointBytes: odd.checkpointBytes,
    checkpointSignature: odd.checkpointSignature, record: third.record,
    proof: { ...oddProof, siblings: [crypto.randomBytes(32), oddProof.siblings[1]] } }));

  const incorrectlyLinked = await header(129, crypto.randomBytes(32));
  await rejects(create({ ...oddInputs,
    records: [first.record, second.record, incorrectlyLinked.record],
    checkpointPrivateKey: checkpointSigner.privateKey, issuedAt: 1792740003 }));

  // Full-chain corruption, sequence gaps, duplicates, swapped history and
  // altered signatures/page bytes fail before a checkpoint can be issued.
  for (const replacements of [
    [second.record],
    [second.record, first.record],
    [first.record, first.record],
    [{ ...first.record, sequence: 126 }, second.record],
    [{ ...first.record, header: altered(first.record.header) }, second.record],
    [{ ...first.record, signature: altered(first.record.signature) }, second.record],
    [{ ...first.record, page_bodies: [altered(first.record.page_bodies[0])] },
      second.record],
    [{ ...first.record, unsigned: true }, second.record],
  ]) {
    await rejects(create({ ...inputs, records: replacements,
      checkpointPrivateKey: checkpointSigner.privateKey, issuedAt: 1792740001 }));
    await rejects(verify({ ...inputs, ...archive, records: replacements,
      pinnedCheckpointPublicKey: checkpointSigner.publicKey }));
  }
  await rejects(verify({ ...inputs, ...archive,
    pinnedCheckpointPublicKey: attacker.publicKey }));
  await rejects(verify({ ...inputs, ...archive,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey,
    previousSequence: 0, previousDigest: Buffer.alloc(32),
    previousCheckpointDigest: Buffer.alloc(32) }));
  await rejects(verify({ ...inputs, ...archive,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey,
    previousCheckpointDigest: crypto.randomBytes(32) }));
  await rejects(verify({ ...inputs, ...archive,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey,
    expectedFinalSequence: 127 }));
  await rejects(verify({ ...inputs, ...archive,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey,
    expectedFinalDigest: crypto.randomBytes(32) }));
  await rejects(verify({ ...inputs, ...archive,
    pinnedCheckpointPublicKey: checkpointSigner.publicKey,
    resolveCatalogSigner: async () => attacker.publicKey }));

  const badProof = { ...firstProof,
    siblings: [altered(firstProof.siblings[0])] };
  await rejects(verifyProof({ ...request, record: records[0], proof: badProof }));
  await rejects(verifyProof({ ...request, record: records[0],
    proof: { ...firstProof, index: 1 } }));
  await rejects(verifyProof({ ...request, record: records[0],
    proof: { ...firstProof, siblings: [] } }));
  await rejects(verifyProof({ ...request, record: records[0],
    proof: { ...firstProof, count: 3 } }));
  await rejects(verifyProof({ ...request, record: records[0],
    proof: { ...firstProof, duplicate: true } }));
  await rejects(verifyProof({ ...request, record:
    { ...records[0], page_bodies: [altered(records[0].page_bodies[0])] },
    proof: firstProof }));

  // Even an otherwise valid v2-domain signature cannot bless a v1/downgraded
  // checkpoint envelope or lie about the committed Merkle archive root.
  const checkpoint = await z.decodeDeterministic(archive.checkpointBytes);
  for (const rewritten of [
    { ...checkpoint, type: "rootark-zk1-opaque-catalog-checkpoint/v1" },
    { ...checkpoint, archive_root: crypto.randomBytes(32) },
    { ...checkpoint, final_sequence: 129 },
    { ...checkpoint, previous_sequence: 0 },
  ]) {
    const raw = Buffer.from(await z.encodeDeterministic(rewritten));
    const signature = crypto.sign(null, Buffer.concat([CHECKPOINT_SIGN, raw]),
      checkpointSigner.privateKey);
    await rejects(verify({ ...inputs, ...archive,
      checkpointBytes: raw, checkpointSignature: signature,
      pinnedCheckpointPublicKey: checkpointSigner.publicKey }));
    await rejects(verifyProof({ ...request, checkpointBytes: raw,
      checkpointSignature: signature, record: records[0], proof: firstProof }));
  }
  await rejects(verify({ ...inputs, ...archive,
    checkpointSignature: crypto.sign(null,
      Buffer.concat([Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-sign/v1\0"),
        archive.checkpointBytes]), checkpointSigner.privateKey),
    pinnedCheckpointPublicKey: checkpointSigner.publicKey }));
  await rejects(verify({ ...inputs, ...archive,
    checkpointSignature: crypto.sign(null,
      Buffer.concat([HEAD, archive.checkpointBytes]), checkpointSigner.privateKey),
    pinnedCheckpointPublicKey: checkpointSigner.publicKey }));
  // Noncanonical CBOR cannot be misinterpreted as a v2 signed checkpoint.
  await rejects(verify({ ...inputs, ...archive,
    checkpointBytes: Buffer.concat([archive.checkpointBytes, Buffer.from([0])]),
    pinnedCheckpointPublicKey: checkpointSigner.publicKey }));

  await rejects(create({ ...inputs, records: Array(MAX_ARCHIVE_RECORDS + 1)
    .fill(first.record), checkpointPrivateKey: checkpointSigner.privateKey,
    issuedAt: 1792740001 }));
  await rejects(makeProof({ records: [first.record], index: 1 }));
  await rejects(create({ ...inputs, records: [{ ...first.record,
    header: Buffer.alloc(16385) }], checkpointPrivateKey: checkpointSigner.privateKey,
    issuedAt: 1792740001 }));
  // A genesis archive must use precisely sequence 1 and zero predecessor.
  await rejects(create({ ...inputs, previousSequence: 0,
    previousDigest: Buffer.alloc(32), previousCheckpointDigest: Buffer.alloc(32),
    checkpointPrivateKey: checkpointSigner.privateKey, issuedAt: 1792740001 }));
});

test("checkpoint v2 rejects a valid signed archive that exceeds the finite aggregate byte budget", async () => {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("bounded"), keyring_id: crypto.randomBytes(16) };
  const device = crypto.generateKeyPairSync("ed25519");
  const checkpoint = crypto.generateKeyPairSync("ed25519");
  const pages = [];
  for (let page = 0; page < 128; page++) {
    const entries = [];
    for (let offset = 0; offset < 32; offset++) {
      const id = Buffer.alloc(16);
      id.writeUInt32BE(page * 32 + offset, 12);
      entries.push({ object_id: id.toString("base64url"), revision: 1, epoch: 1,
        ciphertext_digest: Buffer.alloc(32, 1),
        metadata_ciphertext: Buffer.alloc(284, 2) });
    }
    const raw = Buffer.from(await z.encodeDeterministic(entries));
    assert.ok(raw.length <= 16384);
    pages.push(raw);
  }
  const pageDigests = pages.map((body) => sha(PAGE, body));
  const records = [];
  let predecessor = Buffer.alloc(32);
  for (let sequence = 1; sequence <= 6; sequence++) {
    const header = Buffer.from(await z.encodeDeterministic({
      type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence, previous_digest: predecessor,
      manifest_revision: 1, manifest_digest: Buffer.alloc(32, 7),
      epoch: 1, signer_device_id: "full-catalog",
      total_count: 4096, page_digests: pageDigests, issued_at: 1792740004,
    }));
    const signature = crypto.sign(null, Buffer.concat([HEAD, header]),
      device.privateKey);
    records.push({ sequence, header, signature, page_bodies: pages });
    predecessor = sha(HEAD, header, signature);
  }
  const totalBytes = records.reduce((sum, item) => sum + item.header.length
    + item.signature.length + item.page_bodies.reduce((n, body) => n + body.length, 0), 0);
  assert.ok(totalBytes > 8 * 1024 * 1024);
  await rejects(create({ scope, records, previousSequence: 0,
    previousDigest: Buffer.alloc(32), previousCheckpointDigest: Buffer.alloc(32),
    resolveCatalogSigner: async () => device.publicKey,
    checkpointPrivateKey: checkpoint.privateKey, issuedAt: 1792740004 }));
});
