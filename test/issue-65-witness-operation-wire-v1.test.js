"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const {
  inspectVerifiedWitnessReservationV1,
  inspectVerifiedWitnessCommitV1,
  inspectVerifiedWitnessCancellationV1,
} = require("../src/crypto/rootark-zk-witness-operation-wire-v1");

function setup() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pinned = { keyId: Buffer.alloc(16, 0x11), publicKey };
  const scope = {
    account_id: Buffer.alloc(16, 0x12),
    compartment_id: Buffer.from("compartment"),
    keyring_id: Buffer.alloc(16, 0x13),
  };
  const operation = {
    ...scope, reservation_id: Buffer.alloc(16, 0x14), operation_id: Buffer.alloc(16, 0x15),
    expected_revision: 1, expected_manifest_digest: Buffer.alloc(32, 0x16),
    proposed_revision: 2, proposed_manifest_digest: Buffer.alloc(32, 0x17),
    request_digest: Buffer.alloc(32, 0x18), package_envelope_digest: null,
  };
  const reservation = {
    type: "rootark-recovery-witness-reservation/v1", reservation_id: operation.reservation_id,
    witness_key_id: pinned.keyId, ...scope, expected_revision: operation.expected_revision,
    expected_manifest_digest: operation.expected_manifest_digest,
    proposed_revision: operation.proposed_revision, proposed_manifest_digest: operation.proposed_manifest_digest,
    operation_id: operation.operation_id, request_digest: operation.request_digest,
    package_envelope_digest: operation.package_envelope_digest, expires_at: 1760000300,
  };
  const commit = {
    type: "rootark-recovery-witness-commit/v1", reservation_id: operation.reservation_id,
    ...scope, committed_revision: operation.proposed_revision,
    committed_manifest_digest: operation.proposed_manifest_digest,
    operation_id: operation.operation_id, witness_sequence: operation.proposed_revision, status: "committed",
  };
  const verifiedTerminalProofDigest = Buffer.alloc(32, 0x19);
  const cancellation = {
    type: "rootark-recovery-witness-cancel/v1", witness_key_id: pinned.keyId,
    ...scope, reservation_id: operation.reservation_id, operation_id: operation.operation_id,
    status_authority_proof_digest: verifiedTerminalProofDigest,
    resolved_at: 1760000340, status: "cancelled",
  };
  async function sign(value, kind, signingDomain) {
    const domain = signingDomain || "Root.ark/zk-1/recovery-witness-" + kind + "/v1";
    return z.encodeDeterministic({
      ...value,
      signature: crypto.sign(null, Buffer.concat([
        Buffer.from(domain + "\0", "ascii"), await z.encodeDeterministic(value),
      ]), privateKey),
    });
  }
  return { pinned, operation, reservation, commit, cancellation, verifiedTerminalProofDigest, sign };
}
const cases = [
  ["reservation", "reservation", inspectVerifiedWitnessReservationV1],
  ["commit", "commit", inspectVerifiedWitnessCommitV1],
  ["cancellation", "cancel", inspectVerifiedWitnessCancellationV1],
];
function args(f, kind, raw) {
  return { raw, pinned: f.pinned, operation: f.operation,
    ...(kind === "cancellation" ? { verifiedTerminalProofDigest: f.verifiedTerminalProofDigest } : {}) };
}

test("independently pinned Ed25519 receipts verify canonical v1 bytes but cannot authorize recovery", async () => {
  const f = setup();
  for (const [kind, domain, verifier] of cases) {
    const value = await verifier(args(f, kind, await f.sign(f[kind], domain)));
    assert.equal(value.verifiedSignatureOnly, true);
    assert.equal(value.authorizesRecovery, false);
    assert.equal(Object.isFrozen(value), true);
  }
});

test("signed wrong operations, types, statuses, digests, and sequence fail closed", async () => {
  const f = setup();
  for (const [kind, domain, verifier] of cases) {
    for (const mutation of [
      { operation_id: Buffer.alloc(16, 0xee) },
      { account_id: Buffer.alloc(16, 0xee) },
      { reservation_id: Buffer.alloc(16, 0xee) },
      { type: "rootark-recovery-witness-base/v1" },
      { status: "pending" },
      { extra: 1 },
      ...(kind === "reservation" ? [
        { proposed_revision: 3 }, { request_digest: Buffer.alloc(32, 0xee) },
        { expires_at: -1 }, { witness_key_id: Buffer.alloc(16, 0xee) },
      ] : kind === "commit" ? [
        { committed_revision: 3 }, { witness_sequence: 9 },
        { committed_manifest_digest: Buffer.alloc(32, 0xee) },
      ] : [
        { status_authority_proof_digest: Buffer.alloc(32, 0xee) },
        { witness_key_id: Buffer.alloc(16, 0xee) }, { resolved_at: -1 },
      ]),
    ]) {
      const changed = { ...f[kind], ...mutation };
      if (Object.values(mutation).some((value) => value === -1)) {
        await assert.rejects(f.sign(changed, domain), (e) => e.code === "UNSUPPORTED_CBOR_VALUE");
      } else {
        await assert.rejects(verifier(args(f, kind, await f.sign(changed, domain))),
          (e) => e.code === "WITNESS_RECEIPT_INVALID", kind + "/" + Object.keys(mutation)[0]);
      }
    }
  }
});

test("initialize reservation is exact and cannot be confused with existing-head mutation", async () => {
  const f = setup();
  const first = {
    ...f.reservation, expected_revision: null, expected_manifest_digest: null, proposed_revision: 1,
  };
  const operation = {
    ...f.operation, expected_revision: null, expected_manifest_digest: null, proposed_revision: 1,
  };
  const result = await inspectVerifiedWitnessReservationV1({
    raw: await f.sign(first, "reservation"), pinned: f.pinned, operation,
  });
  assert.equal(result.authorizesRecovery, false);
  await assert.rejects(inspectVerifiedWitnessReservationV1({
    raw: await f.sign({ ...first, expected_manifest_digest: Buffer.alloc(32) }, "reservation"),
    pinned: f.pinned, operation,
  }));
});

test("missing trusted operation or cancellation proof digest, wrong key/domain and hostile CBOR fail closed", async () => {
  const f = setup();
  for (const [kind, domain, verifier] of cases) {
    const raw = await f.sign(f[kind], domain);
    await assert.rejects(verifier({ raw, pinned: f.pinned }));
    await assert.rejects(verifier({ ...args(f, kind, raw), operation: undefined }));
    await assert.rejects(verifier({
      ...args(f, kind, raw), pinned: { ...f.pinned,
        publicKey: crypto.generateKeyPairSync("ed25519").publicKey },
    }));
    await assert.rejects(verifier(args(f, kind, await f.sign(f[kind], "commit-wrong"))));
    await assert.rejects(verifier(args(f, kind, Buffer.from("a2616101616102", "hex"))));
  }
  const raw = await f.sign(f.cancellation, "cancel");
  await assert.rejects(inspectVerifiedWitnessCancellationV1({
    ...args(f, "cancellation", raw), verifiedTerminalProofDigest: undefined,
  }));
  await assert.rejects(inspectVerifiedWitnessCancellationV1({
    ...args(f, "cancellation", raw), verifiedTerminalProofDigest: Buffer.alloc(32, 0xff),
  }));
});

test("mutable operation, pinned key ID and cancellation digest cannot be repaired after invocation", async () => {
  const f = setup();
  for (const [kind, domain, verifier] of cases) {
    const raw = await f.sign(f[kind], domain);
    const mutations = [
      ["operation", Buffer.alloc(16, 0xed), (wrong) => ({
        ...args(f, kind, raw), operation: { ...f.operation, operation_id: wrong },
      }), f.operation.operation_id],
    ];
    // The v1 commit receipt has NO witness_key_id wire field; its identity
    // is bound to the independently pinned public key, not a signed key ID.
    if (kind !== "commit") {
      mutations.push(["pinned", Buffer.alloc(16, 0xed), (wrong) => ({
        ...args(f, kind, raw), pinned: { ...f.pinned, keyId: wrong },
      }), f.pinned.keyId]);
    }
    if (kind === "cancellation") {
      mutations.push(["terminal-proof digest", Buffer.alloc(32, 0xed), (wrong) => ({
        ...args(f, kind, raw), verifiedTerminalProofDigest: wrong,
      }), f.verifiedTerminalProofDigest]);
    }
    for (const [name, wrong, createInput, correct] of mutations) {
      const verification = verifier(createInput(wrong));
      queueMicrotask(() => wrong.set(correct));
      await assert.rejects(verification,
        (e) => e.code === "WITNESS_RECEIPT_INVALID",
        kind + ": " + name + " must not be repaired after call");
    }
  }
});

test("operation receipts cannot be verified under a public key substituted after invocation", async () => {
  const f = setup();
  for (const [kind, domain, verifier] of cases) {
    const pinned = {
      ...f.pinned,
      publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
    };
    const verifying = verifier({
      ...args(f, kind, await f.sign(f[kind], domain)), pinned,
    });
    queueMicrotask(() => { pinned.publicKey = f.pinned.publicKey; });
    await assert.rejects(verifying,
      (error) => error.code === "WITNESS_RECEIPT_INVALID",
      kind + " must use the invocation-time pinned public key");
  }
});
