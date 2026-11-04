"use strict";

const crypto = require("node:crypto");

// Shared by SQLite's one-row transaction and the in-process legacy JSON path.
// Never write a stale entire-account snapshot while completing a sync resume.
function replayDigest(user) {
  return crypto.createHash("sha256").update(JSON.stringify([
    user.totpRecoveryHashes, user.totpLastUsedStep ?? null, user.totpSecret,
  ])).digest("hex");
}

function secretDigest(user) {
  return crypto.createHash("sha256").update(JSON.stringify(user.totpSecret)).digest("hex");
}

function authorizationDigest(user) {
  return crypto.createHash("sha256").update(JSON.stringify([
    user.role || "user", user.permissions || {},
  ])).digest("hex");
}

function applySyncResumeAccountProof(user, claim) {
  if (!user || user.username !== claim?.username || user.disabled || !user.totpEnabled
    || user.password !== claim.passwordHash || (user.sessionVersion || 0) !== claim.sessionVersion
    || secretDigest(user) !== claim.secretDigest
    || authorizationDigest(user) !== claim.authorizationDigest
    || !/^[0-9a-f]{64}$/.test(claim.expectedReplayDigest || "")) return "conflict";
  if (replayDigest(user) === claim.expectedReplayDigest) return "already";
  const proof = claim.proof;
  if (proof?.type === "recovery" && typeof proof.hash === "string"
    && Array.isArray(user.totpRecoveryHashes)) {
    const index = user.totpRecoveryHashes.indexOf(proof.hash);
    if (index === -1) return "conflict";
    user.totpRecoveryHashes.splice(index, 1);
  } else if (proof?.type === "totp" && Number.isSafeInteger(proof.step) && proof.step >= 0
    && (!Number.isSafeInteger(user.totpLastUsedStep) || proof.step > user.totpLastUsedStep)) {
    user.totpLastUsedStep = proof.step;
  } else {
    return "conflict";
  }
  return replayDigest(user) === claim.expectedReplayDigest ? "committed" : "conflict";
}

module.exports = { applySyncResumeAccountProof, authorizationDigest, replayDigest, secretDigest };
