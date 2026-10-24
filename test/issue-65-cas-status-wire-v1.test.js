"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const { inspectVerifiedCasStatusProofV1 } = require("../src/crypto/rootark-zk-cas-status-wire-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0", "ascii");
function fixture() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const keyId = Buffer.alloc(16, 0x17);
  const nonce = Buffer.alloc(32, 0x33);
  const scope = {
    account_id: Buffer.alloc(16, 0x41),
    compartment_id: Buffer.from("test compartment", "ascii"),
    keyring_id: Buffer.alloc(16, 0x42),
  };
  const query = {
    ...scope,
    reservation_id: Buffer.alloc(16, 0x43),
    operation_id: Buffer.alloc(16, 0x44),
    request_digest: Buffer.alloc(32, 0x45),
    package_envelope_digest: null,
    expected_revision: 1,
    expected_manifest_digest: Buffer.alloc(32, 0x46),
    proposed_revision: 2,
    proposed_manifest_digest: Buffer.alloc(32, 0x47),
  };
  const proof = {
    type: "rootark-recovery-cas-status/v1",
    status_authority_key_id: keyId,
    ...query,
    observed_revision: 2,
    observed_manifest_digest: query.proposed_manifest_digest,
    terminal_status: "committed",
    observed_at: 1760000000,
    nonce,
  };
  const pinned = { publicKey, keyId };
  const context = { pinned, query, nonce };
  async function sign(fields = proof, domain = DOMAIN) {
    const msg = Buffer.concat([domain, await z.encodeDeterministic(fields)]);
    return z.encodeDeterministic({
      ...fields,
      signature: crypto.sign(null, msg, privateKey),
    });
  }
  return { proof, query, pinned, context, nonce, privateKey, sign };
}

test("real v1 status-proof parser validates canonical signed bytes against pinned authority and query", async () => {
  const f = fixture();
  const raw = await f.sign();
  const result = await inspectVerifiedCasStatusProofV1({ raw, ...f.context });
  assert.equal(result.terminal_status, "committed");
  assert.equal(result.verifiedSignatureOnly, true);
  assert.equal(result.authorizesRecovery, false, "a terminal proof alone cannot release the witness gate");
});

test("validly re-signed different operation, nonce, scope, key id and observed head are refused", async () => {
  const f = fixture();
  for (const mutation of [
    { operation_id: Buffer.alloc(16, 0xee) },
    { account_id: Buffer.alloc(16, 0xee) },
    { nonce: Buffer.alloc(32, 0xee) },
    { status_authority_key_id: Buffer.alloc(16, 0xee) },
    { request_digest: Buffer.alloc(32, 0xee) },
    { package_envelope_digest: Buffer.alloc(32, 0xee) },
    { observed_manifest_digest: Buffer.alloc(32, 0xee) },
    { observed_revision: 1 },
    { terminal_status: "not-committed-final" },
  ]) {
    await assert.rejects(
      inspectVerifiedCasStatusProofV1({ raw: await f.sign({ ...f.proof, ...mutation }), ...f.context }),
      (e) => e.code === "AUTHORITY_PROOF_INVALID",
      Object.keys(mutation)[0],
    );
  }
});

test("forgery, type/domain confusion, unsigned/extra fields and malformed raw CBOR fail closed", async () => {
  const f = fixture();
  const raw = await f.sign();
  for (const modified of [
    Buffer.from("a2616101616102", "hex"),
    Buffer.from("a2616202616101", "hex"),
    Buffer.from("1801", "hex"),
    await f.sign(f.proof, Buffer.from("Root.ark/zk-1/recovery-witness-reservation/v1\0", "ascii")),
    await f.sign({ ...f.proof, type: "rootark-cas-terminal-status/v1" }),
    await f.sign({ ...f.proof, extra: true }),
    Buffer.concat([raw, Buffer.from([0])]),
  ]) {
    await assert.rejects(inspectVerifiedCasStatusProofV1({ raw: modified, ...f.context }));
  }
  const wrongKey = crypto.generateKeyPairSync("ed25519").publicKey;
  await assert.rejects(inspectVerifiedCasStatusProofV1({
    raw, ...f.context, pinned: { keyId: f.pinned.keyId, publicKey: wrongKey },
  }));
});

test("non-final outcomes and absent context never become authorization", async () => {
  const f = fixture();
  const raw = await f.sign();
  for (const changed of [
    { nonce: undefined },
    { query: undefined },
    { pinned: undefined },
    { pinned: { ...f.pinned, keyId: null } },
  ]) {
    await assert.rejects(inspectVerifiedCasStatusProofV1({ raw, ...f.context, ...changed }));
  }
  const finalNonCommit = {
    ...f.proof,
    terminal_status: "not-committed-final",
    observed_revision: 1,
    observed_manifest_digest: f.query.expected_manifest_digest,
  };
  const result = await inspectVerifiedCasStatusProofV1({
    raw: await f.sign(finalNonCommit), ...f.context,
  });
  assert.equal(result.terminal_status, "not-committed-final");
  assert.equal(result.authorizesRecovery, false, "signed no-commit without durable fence proof is insufficient");
});

test("initialize proof requires absent expected/observed head and first proposed revision", async () => {
  const f = fixture();
  const initialize = {
    ...f.proof,
    expected_revision: null,
    expected_manifest_digest: null,
    proposed_revision: 1,
    observed_revision: null,
    observed_manifest_digest: null,
    terminal_status: "not-committed-final",
  };
  const query = {
    ...f.query,
    expected_revision: null,
    expected_manifest_digest: null,
    proposed_revision: 1,
  };
  const input = { ...f.context, query };
  const verified = await inspectVerifiedCasStatusProofV1({
    raw: await f.sign(initialize), ...input,
  });
  assert.equal(verified.terminal_status, "not-committed-final");
  assert.equal(verified.authorizesRecovery, false);
  for (const bad of [
    { observed_revision: 1 },
    { observed_manifest_digest: f.query.proposed_manifest_digest },
    { proposed_revision: 2 },
    { expected_manifest_digest: f.query.expected_manifest_digest },
  ]) {
    await assert.rejects(inspectVerifiedCasStatusProofV1({
      raw: await f.sign({ ...initialize, ...bad }), ...input,
    }), (e) => e.code === "AUTHORITY_PROOF_INVALID");
  }
});

test("out of range revisions, lengths and time values reject even under valid Ed25519", async () => {
  const f = fixture();
  for (const changed of [
    { proposed_revision: 0 },
    { expected_revision: 0 },
    { proposed_revision: 0x10000000000000000n },
    { expected_revision: 0xffffffffffffffffn },
    { observed_revision: -1 },
    { observed_at: 0x10000000000000000n },
    { status_authority_key_id: Buffer.alloc(15) },
    { compartment_id: Buffer.alloc(129) },
    { nonce: Buffer.alloc(31) },
  ]) {
    const { signature: _ignored, ...unsigned } = { ...f.proof, ...changed };
    const changedValue = Object.values(changed)[0];
    if ((typeof changedValue === "number" && changedValue < 0)
      || (typeof changedValue === "bigint"
        && (changedValue < 0n || changedValue > 0xffffffffffffffffn))) {
      await assert.rejects(f.sign(unsigned), (e) => e.code === "UNSUPPORTED_CBOR_VALUE");
      continue;
    }
    await assert.rejects(
      inspectVerifiedCasStatusProofV1({
        raw: await f.sign(unsigned), ...f.context,
      }),
      (e) => e.code === "AUTHORITY_PROOF_INVALID",
      Object.keys(changed)[0],
    );
  }
});

test("caller-owned nonce, query and pinned key bytes cannot be changed while signature verification awaits", async () => {
  const f = fixture();
  const raw = await f.sign();
  for (const which of ["nonce", "query", "pinned"]) {
    const invalidBytes = Buffer.alloc(which === "nonce" ? 32 : 16, 0xed);
    const changed = which === "nonce" ? { nonce: invalidBytes }
      : which === "query" ? { query: { ...f.query, account_id: invalidBytes } }
        : { pinned: { ...f.pinned, keyId: invalidBytes } };
    const verifying = inspectVerifiedCasStatusProofV1({ raw, ...f.context, ...changed });
    const desired = which === "nonce" ? f.nonce
      : which === "query" ? f.query.account_id : f.pinned.keyId;
    queueMicrotask(() => invalidBytes.set(desired));
    await assert.rejects(verifying, (e) => e.code === "AUTHORITY_PROOF_INVALID",
      "must bind " + which + " to invocation-time bytes");
  }
});

test("pinned Ed25519 public-key identity cannot be swapped after invocation", async () => {
  const f = fixture();
  const pinned = {
    ...f.pinned,
    publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
  };
  const verifying = inspectVerifiedCasStatusProofV1({
    raw: await f.sign(), ...f.context, pinned,
  });
  queueMicrotask(() => { pinned.publicKey = f.pinned.publicKey; });
  await assert.rejects(verifying, (error) => error.code === "AUTHORITY_PROOF_INVALID");
});
