"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  signExternalCorpusCurrentClaim, verifyExternalCorpusCurrentQuorum,
} = require("../src/crypto/zk15ExternalCorpusCurrentQuorum");

const b64 = (n, bytes = 16) => Buffer.alloc(bytes, n).toString("base64url");
const HASH = (n) => b64(n, 32);
const keys = [crypto.generateKeyPairSync("ed25519"), crypto.generateKeyPairSync("ed25519")];
const owner = crypto.generateKeyPairSync("ed25519");
const ownerPin = crypto.createHash("sha256")
  .update(owner.publicKey.export({ format: "der", type: "spki" }))
  .digest("base64url");
const reject = /ZK15_EXTERNAL_CORPUS_CURRENT_UNVERIFIED/;
function fixture() {
  const accountId = b64(1);
  const ownerGenerationId = b64(2);
  const nonce = HASH(3);
  const nowSeconds = 1_800_000_000;
  const floor = {
    accountId, ownerGenerationId, ownerSpkiSha256: ownerPin,
    sequence: 4, corpusSha256: HASH(4), previousCorpusSha256: HASH(5),
  };
  const next = {
    type: "rootark-zk15-external-corpus-current/v1",
    witness_id: "witness-a", account_id: accountId,
    owner_generation_id: ownerGenerationId, owner_spki_sha256: ownerPin,
    sequence: 5, corpus_sha256: HASH(6),
    previous_corpus_sha256: floor.corpusSha256, request_nonce: nonce,
    issued_at: nowSeconds - 1, expires_at: nowSeconds + 12,
  };
  const witnessPins = [
    { witnessId: "witness-a", publicKey: keys[0].publicKey },
    { witnessId: "witness-b", publicKey: keys[1].publicKey },
  ];
  const sign = (claim) => [
    signExternalCorpusCurrentClaim({ ...claim, witness_id: "witness-a" }, keys[0].privateKey),
    signExternalCorpusCurrentClaim({ ...claim, witness_id: "witness-b" }, keys[1].privateKey),
  ];
  const input = {
    witnessPins, statements: sign(next), independentlyRetainedFloor: floor,
    independentlyExpectedAccountId: accountId,
    independentlyExpectedOwnerGenerationId: ownerGenerationId,
    independentlyExpectedOwnerSpkiSha256: ownerPin,
    requestNonce: nonce, nowSeconds,
  };
  return { input, next, sign, floor };
}

test("two pinned distinct witness signatures establish only a fresh nonauthorizing CURRENT claim", () => {
  const { input, next } = fixture();
  const result = verifyExternalCorpusCurrentQuorum(input);
  assert.equal(result.status, "VERIFIED_EXTERNAL_CORPUS_CURRENT_CLAIM_NONAUTHORIZING");
  assert.equal(result.sequence, next.sequence);
  assert.equal(result.corpusSha256, next.corpus_sha256);
  assert.equal(result.ownerGenerationId, next.owner_generation_id);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.independentOffHostCustodyProven, false);
  assert.equal(result.globalAccountCompletenessProven, false);
  assert.equal(result.currentnessGuaranteeWithoutExternalCustody, false);
  assert.deepEqual(result.candidateRetainedFloor, {
    ...input.independentlyRetainedFloor, sequence: 5,
    corpusSha256: next.corpus_sha256,
    previousCorpusSha256: input.independentlyRetainedFloor.corpusSha256,
  });
  assert.equal(Object.isFrozen(result.candidateRetainedFloor), true);
});

test("cannot establish trust from one signature, duplicate identities or co-opted owner signing key", () => {
  const { input, next, sign } = fixture();
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: [input.statements[0]],
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, witnessPins: [input.witnessPins[0], input.witnessPins[0]],
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, witnessPins: [
      input.witnessPins[0], { witnessId: "witness-b", publicKey: keys[0].publicKey },
    ],
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: [input.statements[0], input.statements[0]],
  }), reject);
  const ownerClaim = signExternalCorpusCurrentClaim({
    ...next, witness_id: "witness-b",
  }, owner.privateKey);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, witnessPins: [
      input.witnessPins[0], { witnessId: "witness-b", publicKey: owner.publicKey },
    ], statements: [input.statements[0], ownerClaim],
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: sign({ ...next, corpus_sha256: HASH(7) })
      .map((v, i) => i === 0 ? input.statements[0] : v),
  }), reject);
});

test("replayed, reverted, skipped and forked current state cannot override external retained floor", () => {
  const { input, next, sign, floor } = fixture();
  for (const candidate of [
    { ...next, sequence: 3, corpus_sha256: HASH(3), previous_corpus_sha256: HASH(2) },
    { ...next, sequence: 6 },
    { ...next, sequence: 5, previous_corpus_sha256: HASH(8) },
    { ...next, sequence: 5, corpus_sha256: floor.corpusSha256 },
    { ...next, sequence: 4, previous_corpus_sha256: HASH(5),
      corpus_sha256: HASH(7) },
  ]) assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: sign(candidate),
  }), reject);
  // An unchanged current is valid but cannot reset the old predecessor.
  const unchanged = {
    ...next, sequence: 4, corpus_sha256: floor.corpusSha256,
    previous_corpus_sha256: floor.previousCorpusSha256,
  };
  assert.equal(verifyExternalCorpusCurrentQuorum({
    ...input, statements: sign(unchanged),
  }).sequence, 4);
});

test("foreign accounts, owner generations, owner fingerprints and wrong nonce fail closed", () => {
  const { input, next, sign } = fixture();
  for (const candidate of [
    { ...next, account_id: b64(8) },
    { ...next, owner_generation_id: b64(8) },
    { ...next, owner_spki_sha256: HASH(8) },
    { ...next, request_nonce: HASH(8) },
  ]) assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: sign(candidate),
  }), reject);
  for (const missing of [
    "independentlyRetainedFloor", "independentlyExpectedAccountId",
    "independentlyExpectedOwnerGenerationId",
    "independentlyExpectedOwnerSpkiSha256", "requestNonce",
  ]) {
    const modified = { ...input };
    delete modified[missing];
    assert.throws(() => verifyExternalCorpusCurrentQuorum(modified), reject);
  }
});

test("freshness is bound to one trusted clock sample and a caller-held challenge", () => {
  const { input, next, sign } = fixture();
  for (const candidate of [
    { ...next, issued_at: input.nowSeconds - 80 },
    { ...next, issued_at: input.nowSeconds + 4 },
    { ...next, expires_at: input.nowSeconds - 1 },
    { ...next, expires_at: input.nowSeconds + 120 },
    { ...next, issued_at: input.nowSeconds - 25,
      expires_at: input.nowSeconds + 20 },
  ]) assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: sign(candidate),
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, requestNonce: HASH(7),
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, nowSeconds: input.nowSeconds + 40,
  }), reject);
});

test("reject accessor/Proxy split identity, signed extras, bad canonical encoding and malformed floor", () => {
  const { input, next, sign } = fixture();
  const bad = { ...input.statements[0] };
  Object.defineProperty(bad, "corpus_sha256", { get() { return HASH(6); }, enumerable: true });
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: [bad, input.statements[1]],
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: [
      { ...input.statements[0], extra: true }, input.statements[1],
    ],
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: [
      { ...input.statements[0], signature: HASH(1) }, input.statements[1],
    ],
  }), reject);
  const flip = new Proxy(input.statements[0], {
    getOwnPropertyDescriptor(target, property) {
      const descriptor = Reflect.getOwnPropertyDescriptor(target, property);
      if (property === "corpus_sha256" && descriptor) {
        return { ...descriptor, value: HASH(33) };
      }
      return descriptor;
    },
  });
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: [flip, input.statements[1]],
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, independentlyRetainedFloor: {
      ...input.independentlyRetainedFloor, sequence: 0,
    },
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, statements: sign({ ...next, owner_generation_id: b64(9) }),
  }), reject);
});

test("monkeypatching crypto.verify or KeyObject export cannot authenticate a forged witness", () => {
  const { input } = fixture();
  const originalVerify = crypto.verify;
  const forged = { ...input.statements[0], corpus_sha256: HASH(44) };
  // Native methods are captured on module load. A different running module
  // must not change the verifier's decision through crypto.verify mutation.
  try {
    crypto.verify = () => true;
    assert.throws(() => verifyExternalCorpusCurrentQuorum({
      ...input, statements: [forged, input.statements[1]],
    }), reject);
  } finally {
    crypto.verify = originalVerify;
  }
  const originalExport = keys[0].publicKey.export;
  try {
    keys[0].publicKey.export = () => owner.publicKey.export({ format: "der", type: "spki" });
    assert.equal(verifyExternalCorpusCurrentQuorum(input).sequence, 5);
  } finally {
    if (originalExport === undefined) delete keys[0].publicKey.export;
    else keys[0].publicKey.export = originalExport;
  }
});

test("requires pre-provisioned monotonic floor and refuses invented genesis or generation reset", () => {
  const { input } = fixture();
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, independentlyRetainedFloor: null,
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, independentlyRetainedFloor: {
      ...input.independentlyRetainedFloor, ownerGenerationId: b64(99),
    },
  }), reject);
  assert.throws(() => verifyExternalCorpusCurrentQuorum({
    ...input, independentlyRetainedFloor: {
      ...input.independentlyRetainedFloor, ownerSpkiSha256: HASH(99),
    },
  }), reject);
});
