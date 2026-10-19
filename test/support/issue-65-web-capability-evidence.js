"use strict";

const FIELDS = Object.freeze([
  "browserVersion",
  "osVersion",
  "originKind",
  "prfObserved",
  "userVerificationObserved",
  "credentialSyncBehavior",
  "privateKeyWrappingObserved",
  "keyCopyOrRestoreTested",
  "originDeliveryReviewed",
  "independentReviewerVerified",
  "measuredAt",
]);

const BOOLEAN_EVIDENCE_FIELDS = Object.freeze([
  "prfObserved",
  "userVerificationObserved",
  "privateKeyWrappingObserved",
  "keyCopyOrRestoreTested",
  "originDeliveryReviewed",
  "independentReviewerVerified",
]);

const SYNC_BEHAVIORS = new Set([
  "UNKNOWN",
  "NOT_TESTED",
  "SYNCED",
  "NOT_SYNCED_OBSERVED",
  "COPIED",
  "PROFILE_RESTORED",
  "CREDENTIAL_DELETED",
]);

function invalidEvidence(message) {
  throw new TypeError(`Invalid web recovery evidence: ${message}`);
}

function isBoundedText(value, field) {
  return value === "UNKNOWN" || (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function validateEvidence(record) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    invalidEvidence("record must be a plain object");
  }
  if (Object.getPrototypeOf(record) !== Object.prototype) {
    invalidEvidence("unexpected object prototype");
  }

  const keys = Reflect.ownKeys(record);
  if (keys.some((key) => typeof key !== "string")) {
    invalidEvidence("symbol fields are not allowed");
  }
  if (keys.length !== FIELDS.length || FIELDS.some((field) => !keys.includes(field))) {
    invalidEvidence("unexpected or missing evidence field");
  }

  for (const field of FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(record, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      invalidEvidence("accessor evidence fields are not allowed");
    }
  }

  for (const field of ["browserVersion", "osVersion"]) {
    if (!isBoundedText(record[field], field)) {
      invalidEvidence(`${field} must be bounded text or UNKNOWN`);
    }
  }

  if (!["UNKNOWN", "HTTPS", "LOCALHOST", "INSECURE"].includes(record.originKind)) {
    invalidEvidence("originKind is not an approved evidence label");
  }

  for (const field of BOOLEAN_EVIDENCE_FIELDS) {
    if (![true, false, "UNKNOWN"].includes(record[field])) {
      invalidEvidence(`${field} must be true, false, or UNKNOWN`);
    }
  }

  if (!SYNC_BEHAVIORS.has(record.credentialSyncBehavior)) {
    invalidEvidence("credentialSyncBehavior is not an approved evidence label");
  }

  if (record.measuredAt !== "UNKNOWN") {
    if (
      typeof record.measuredAt !== "string" ||
      record.measuredAt.length > 40 ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(record.measuredAt) ||
      !Number.isFinite(Date.parse(record.measuredAt))
    ) {
      invalidEvidence("measuredAt must be an ISO UTC timestamp or UNKNOWN");
    }
  }
}

function assessWebRecoveryEvidence(record) {
  validateEvidence(record);

  const reasons = [
    "This test-only result cannot grant trusted-device status, production authorization, or freshness.",
  ];

  const unknown = FIELDS.filter((field) => record[field] === "UNKNOWN");
  if (unknown.length > 0) {
    reasons.push(`Evidence remains unknown for: ${unknown.join(", ")}.`);
  }

  if (record.originKind === "INSECURE") {
    reasons.push("The observed origin is not a secure origin.");
  }
  if (record.prfObserved !== true) {
    reasons.push("A positive PRF observation was not recorded.");
  }
  if (record.userVerificationObserved !== true) {
    reasons.push("User verification was not positively observed.");
  }
  if (record.credentialSyncBehavior !== "NOT_SYNCED_OBSERVED") {
    reasons.push("Credential synchronization, copying, or restoration prevents a device-bound custody claim.");
  }
  if (record.privateKeyWrappingObserved !== true) {
    reasons.push("Private-key wrapping was not positively observed.");
  }
  if (record.keyCopyOrRestoreTested !== true) {
    reasons.push("Key copy and restore behavior has not been tested.");
  }
  if (record.originDeliveryReviewed !== true) {
    reasons.push("Origin delivery has not been independently reviewed.");
  }
  if (record.independentReviewerVerified === true) {
    reasons.push("A reviewer flag is recorded, but this test-only evaluator cannot verify reviewer provenance.");
  }

  const candidate =
    unknown.length === 0 &&
    record.originKind !== "INSECURE" &&
    record.prfObserved === true &&
    record.userVerificationObserved === true &&
    record.credentialSyncBehavior === "NOT_SYNCED_OBSERVED" &&
    record.privateKeyWrappingObserved === true &&
    record.keyCopyOrRestoreTested === true &&
    record.originDeliveryReviewed === true &&
    record.independentReviewerVerified === false;

  if (candidate) {
    reasons.push("Independent security review remains required; candidate status is not approval.");
    return { status: "CANDIDATE_FOR_INDEPENDENT_REVIEW", reasons };
  }

  return { status: "UNVERIFIED", reasons };
}

const READINESS_FIELDS = Object.freeze([
  "browserEvidenceStatus",
  "casStatus",
  "witnessStatus",
  "browserKdfStatus",
  "keyCustodyStatus",
  "cryptoInteropStatus",
]);

function assessWebRecoveryIntegrationReadiness(record) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    invalidEvidence("readiness record must be a plain object");
  }
  if (Object.getPrototypeOf(record) !== Object.prototype) {
    invalidEvidence("unexpected readiness object prototype");
  }

  const keys = Reflect.ownKeys(record);
  if (keys.some((key) => typeof key !== "string") || keys.some((key) => !READINESS_FIELDS.includes(key))) {
    invalidEvidence("unexpected readiness field");
  }

  const reasons = [];
  let allPassed = true;
  for (const field of READINESS_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(record, field);
    if (!descriptor) {
      allPassed = false;
      reasons.push(`${field} is missing; this prerequisite remains blocked.`);
      continue;
    }
    if (!Object.hasOwn(descriptor, "value")) {
      invalidEvidence("readiness accessors are not allowed");
    }
    if (descriptor.value !== "PASS") {
      allPassed = false;
      reasons.push(`${field} is not independently verified as PASS.`);
    }
  }

  if (allPassed) {
    return {
      status: "REQUIRES_SEPARATE_INTEGRATION_APPROVAL",
      reasons: ["Reported PASS inputs do not grant authority; separate owner and independent security approval remains required."],
    };
  }

  return { status: "BLOCKED_FOR_INTEGRATION", reasons };
}

module.exports = {
  assessWebRecoveryEvidence,
  assessWebRecoveryIntegrationReadiness,
};
