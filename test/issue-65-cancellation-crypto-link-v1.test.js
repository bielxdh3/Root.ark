"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const { inspectCancellationCryptoLinkV1 } = require("../src/crypto/rootark-zk-cancellation-crypto-link-v1");

function fixture() {
  const statusKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const statusPinned = { keyId: Buffer.alloc(16, 0x01), publicKey: statusKeys.publicKey };
  const witnessPinned = { keyId: Buffer.alloc(16, 0x02), publicKey: witnessKeys.publicKey };
  const scope = { account_id: Buffer.alloc(16, 0x03),
    compartment_id: Buffer.from("synthetic"), keyring_id: Buffer.alloc(16, 0x04) };
  const query = { ...scope, reservation_id: Buffer.alloc(16, 0x05),
    operation_id: Buffer.alloc(16, 0x06), request_digest: Buffer.alloc(32, 0x07),
    package_envelope_digest: null, expected_revision: 1,
    expected_manifest_digest: Buffer.alloc(32, 0x08),
    proposed_revision: 2, proposed_manifest_digest: Buffer.alloc(32, 0x09) };
  const nonce = Buffer.alloc(32, 0x0a);
  const status = { type: "rootark-recovery-cas-status/v1",
    status_authority_key_id: statusPinned.keyId, ...query,
    observed_revision: 1, observed_manifest_digest: query.expected_manifest_digest,
    terminal_status: "not-committed-final", observed_at: 1760000350, nonce };
  function cancellation(digest) {
    return { type: "rootark-recovery-witness-cancel/v1", witness_key_id: witnessPinned.keyId,
      ...scope, reservation_id: query.reservation_id, operation_id: query.operation_id,
      status_authority_proof_digest: digest, resolved_at: 1760000360, status: "cancelled" };
  }
  async function sign(value, label, key) {
    return z.encodeDeterministic({
      ...value,
      signature: crypto.sign(null, Buffer.concat([
        Buffer.from("Root.ark/zk-1/recovery-" + label + "/v1\0", "ascii"),
        await z.encodeDeterministic(value),
      ]), key),
    });
  }
  const signStatus = (value = status) => sign(value, "cas-status", statusKeys.privateKey);
  const signCancellation = (value) => sign(value, "witness-cancel", witnessKeys.privateKey);
  return { statusPinned, witnessPinned, query, nonce, status, cancellation,
    signStatus, signCancellation };
}

test("signed terminal no-commit proof cryptographically links to exact signed witness cancellation", async () => {
  const f = fixture();
  const rawStatus = await f.signStatus();
  const digest = crypto.createHash("sha256").update(rawStatus).digest();
  const rawCancellation = await f.signCancellation(f.cancellation(digest));
  const result = await inspectCancellationCryptoLinkV1({
    rawStatus, statusPinned: f.statusPinned, query: f.query, nonce: f.nonce,
    rawCancellation, witnessPinned: f.witnessPinned,
  });
  assert.equal(result.linkVerified, true);
  assert.equal(result.authorizesRecovery, false, "crypto binding cannot replace durable fence or fresh witness head");
  assert.equal(Object.isFrozen(result), true);
});

test("even validly signed committed terminal proof may not be used to cancel reservation", async () => {
  const f = fixture();
  const committed = { ...f.status, terminal_status: "committed",
    observed_revision: 2, observed_manifest_digest: f.query.proposed_manifest_digest };
  const rawStatus = await f.signStatus(committed);
  const digest = crypto.createHash("sha256").update(rawStatus).digest();
  await assert.rejects(inspectCancellationCryptoLinkV1({
    rawStatus, statusPinned: f.statusPinned, query: f.query, nonce: f.nonce,
    rawCancellation: await f.signCancellation(f.cancellation(digest)),
    witnessPinned: f.witnessPinned,
  }));
});

test("tampered proof, stale nonce, wrong tuple, wrong digest or missing linked authority fails closed", async () => {
  const f = fixture();
  const rawStatus = await f.signStatus();
  const digest = crypto.createHash("sha256").update(rawStatus).digest();
  const rawCancellation = await f.signCancellation(f.cancellation(digest));
  const args = { rawStatus, statusPinned: f.statusPinned, query: f.query, nonce: f.nonce,
    rawCancellation, witnessPinned: f.witnessPinned };
  for (const changed of [
    { nonce: Buffer.alloc(32, 0xee) },
    { statusPinned: undefined },
    { witnessPinned: undefined },
    { query: { ...f.query, account_id: Buffer.alloc(16, 0xee) } },
    { rawStatus: Buffer.concat([rawStatus, Buffer.from([0])]) },
    { rawCancellation: await f.signCancellation(f.cancellation(Buffer.alloc(32, 0xff))) },
    { rawCancellation: await f.signCancellation({ ...f.cancellation(digest),
      operation_id: Buffer.alloc(16, 0xee) }) },
  ]) {
    await assert.rejects(inspectCancellationCryptoLinkV1({ ...args, ...changed }));
  }
});

test("asynchronous mutation cannot switch the hashed signed proof after CAS signature verification", async () => {
  const f = fixture();
  const proofA = await f.signStatus();
  const nonceB = Buffer.alloc(32, 0x7b);
  const proofB = await f.signStatus({ ...f.status, nonce: nonceB });
  assert.equal(proofA.byteLength, proofB.byteLength, "different nonces preserve canonical wire length");
  const digestB = crypto.createHash("sha256").update(proofB).digest();
  const cancellationForB = await f.signCancellation(f.cancellation(digestB));
  const mutable = Buffer.from(proofA);
  const verification = inspectCancellationCryptoLinkV1({
    rawStatus: mutable,
    statusPinned: f.statusPinned,
    query: f.query,
    nonce: f.nonce,
    rawCancellation: cancellationForB,
    witnessPinned: f.witnessPinned,
  });
  queueMicrotask(() => mutable.set(proofB));
  await assert.rejects(verification,
    (error) => error.code === "CANCELLATION_CRYPTO_LINK_INVALID",
    "must bind the digest to the exact verified byte snapshot, not a later caller mutation");
});

test("caller mutation cannot change the original nonce or operation query during asynchronous verification", async () => {
  const f = fixture();
  const rawStatus = await f.signStatus();
  const digest = crypto.createHash("sha256").update(rawStatus).digest();
  const rawCancellation = await f.signCancellation(f.cancellation(digest));
  const base = { rawStatus, statusPinned: f.statusPinned, rawCancellation,
    witnessPinned: f.witnessPinned };
  const mutableNonce = Buffer.alloc(32, 0xfe); // Not the signed challenge.
  const nonceRun = inspectCancellationCryptoLinkV1({
    ...base, query: f.query, nonce: mutableNonce,
  });
  queueMicrotask(() => mutableNonce.set(f.nonce));
  await assert.rejects(nonceRun, (error) => error.code === "CANCELLATION_CRYPTO_LINK_INVALID");

  const mutableAccount = Buffer.alloc(16, 0xfd); // Not the signed account.
  const mutableQuery = { ...f.query, account_id: mutableAccount };
  const queryRun = inspectCancellationCryptoLinkV1({
    ...base, query: mutableQuery, nonce: f.nonce,
  });
  queueMicrotask(() => mutableAccount.set(f.query.account_id));
  await assert.rejects(queryRun, (error) => error.code === "CANCELLATION_CRYPTO_LINK_INVALID");
});
