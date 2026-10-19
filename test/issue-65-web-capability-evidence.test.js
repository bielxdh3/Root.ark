const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { assessWebRecoveryEvidence } = require("./support/issue-65-web-capability-evidence");

function evidence(overrides = {}) {
  return {
    browserVersion: "UNKNOWN",
    osVersion: "UNKNOWN",
    originKind: "UNKNOWN",
    prfObserved: "UNKNOWN",
    userVerificationObserved: "UNKNOWN",
    credentialSyncBehavior: "UNKNOWN",
    privateKeyWrappingObserved: "UNKNOWN",
    keyCopyOrRestoreTested: "UNKNOWN",
    originDeliveryReviewed: "UNKNOWN",
    independentReviewerVerified: "UNKNOWN",
    measuredAt: "UNKNOWN",
    ...overrides,
  };
}

function assertNoTrustedClaim(result) {
  assert.ok(["UNVERIFIED", "CANDIDATE_FOR_INDEPENDENT_REVIEW"].includes(result.status));
  assert.deepEqual(Object.keys(result).sort(), ["reasons", "status"]);
  assert.ok(Array.isArray(result.reasons));
  assert.equal("freshnessProven" in result, false);
  assert.equal("trustedDevice" in result, false);
  assert.equal("authorization" in result, false);
}

test("unknownPrfNeverBecomesTrusted", () => {
  const result = assessWebRecoveryEvidence(evidence({
    browserVersion: "Observed browser 1.0",
    osVersion: "Observed OS 1.0",
    originKind: "HTTPS",
    prfObserved: "UNKNOWN",
  }));
  assert.equal(result.status, "UNVERIFIED");
  assertNoTrustedClaim(result);
});

test("syncedPasskeyDoesNotProveDeviceBoundCustody", () => {
  const result = assessWebRecoveryEvidence(evidence({
    originKind: "HTTPS",
    prfObserved: true,
    credentialSyncBehavior: "SYNCED",
    privateKeyWrappingObserved: true,
  }));
  assert.equal(result.status, "UNVERIFIED");
  assert.match(result.reasons.join(" "), /sync|device-bound/i);
  assertNoTrustedClaim(result);
});

test("restoredProfileAndDeletedCredentialDoNotClaimRecovery", () => {
  const restored = assessWebRecoveryEvidence(evidence({
    originKind: "HTTPS",
    prfObserved: true,
    credentialSyncBehavior: "PROFILE_RESTORED",
    keyCopyOrRestoreTested: true,
  }));
  const deleted = assessWebRecoveryEvidence(evidence({
    originKind: "HTTPS",
    prfObserved: true,
    credentialSyncBehavior: "CREDENTIAL_DELETED",
    keyCopyOrRestoreTested: true,
  }));
  assert.equal(restored.status, "UNVERIFIED");
  assert.equal(deleted.status, "UNVERIFIED");
  assertNoTrustedClaim(restored);
  assertNoTrustedClaim(deleted);
});

test("knownPrfStillRequiresIndependentReview", () => {
  const result = assessWebRecoveryEvidence(evidence({
    browserVersion: "Observed browser 1.0",
    osVersion: "Observed OS 1.0",
    originKind: "HTTPS",
    prfObserved: true,
    userVerificationObserved: true,
    credentialSyncBehavior: "NOT_SYNCED_OBSERVED",
    privateKeyWrappingObserved: true,
    keyCopyOrRestoreTested: true,
    originDeliveryReviewed: true,
    independentReviewerVerified: false,
    measuredAt: "2026-10-19T12:00:00Z",
  }));
  assert.equal(result.status, "CANDIDATE_FOR_INDEPENDENT_REVIEW");
  assert.match(result.reasons.join(" "), /test-only|independent review/i);
  assertNoTrustedClaim(result);
});

test("evidenceObjectRejectsSensitiveFields", () => {
  assert.throws(() => assessWebRecoveryEvidence({
    ...evidence(),
    rawPrfOutput: "must never be accepted",
  }), /unexpected|sensitive|field/i);
  assert.throws(() => assessWebRecoveryEvidence(Object.assign(Object.create({ inherited: true }), evidence())), /plain|prototype/i);
});

test("localProbeIsManualAndNeverCreatesOrTransmitsCredentials", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "support", "issue-65-web-local-probe.html"),
    "utf8",
  );
  assert.match(html, /type=["']button["']/i);
  assert.match(html, /addEventListener\(["']click["']/i);
  assert.match(html, /NOT_RUN|UNKNOWN/i);
  assert.doesNotMatch(html, /navigator\.credentials|fetch\s*\(|XMLHttpRequest|localStorage|indexedDB/i);
});
