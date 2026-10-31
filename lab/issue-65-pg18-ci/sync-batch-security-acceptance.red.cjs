"use strict";

// EXPLICIT, NONDEFAULT security-acceptance gate. Do NOT add to the normal
// disposable PG18 CI runner: this is intentionally RED until a separately
// deployed and audited issuer, independently signed physical WAL/durability
// witness, and monotonic EXTERNAL CAS floor all demonstrably exist.
// Run only as a separately requested formal security acceptance gate.
const test = require("node:test");
const assert = require("node:assert/strict");

test("RED: independently deployed issuer, signed physical witness and external CAS floor required", () => {
  const independentlyVerifiedEvidence = {
    isolatedIssuerCredentialCustody: false,
    independentlySignedPhysicalDurabilityWitness: false,
    independentlyAnchoredMonotonicCASFloor: false,
    actualPG18AdversarialEvidence: false,
  };
  assert.deepEqual(independentlyVerifiedEvidence, {
    isolatedIssuerCredentialCustody: true,
    independentlySignedPhysicalDurabilityWitness: true,
    independentlyAnchoredMonotonicCASFloor: true,
    actualPG18AdversarialEvidence: true,
  }, "SECURITY_NO_GO: no proof for independent issuer, witness and CAS floor");
});
