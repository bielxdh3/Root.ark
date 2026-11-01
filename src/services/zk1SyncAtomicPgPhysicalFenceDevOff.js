"use strict";

// DEV-OFF ONLY: joins the verified PostgreSQL DELETE+MOVE readback to an
// independently supplied physical witness and held lease. This adapter owns
// NO witness signer, WAL barrier, client ACK path or synthetic proof fallback.
const crypto = require("node:crypto");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { WITNESS_DOMAIN } = require("./zk1SyncAtomicCasFloorLedgerDevOff");
const { createZk1SyncPgBatchIndependentReadback } =
  require("./zk1SyncPgBatchIndependentReadback");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const OP = /^[A-Za-z0-9._:-]{1,160}$/;
const HEX = /^[a-f0-9]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const COMMIT = /^[A-Za-z0-9_-]{16,128}$/;
const ID_FIELDS = ["scope", "accountId", "storeId", "username", "compartmentId"];
const RECEIPT_FIELDS = ["version", ...ID_FIELDS, "nonce", "operationIds",
  "envelopeDigests", "commitId", "storeHeadSha256", "fencingEpoch", "physicalDurable"];

function denied() {
  return Object.assign(new Error("SYNC_ATOMIC_PG_FENCE_DEV_OFF_DENIED"),
    { code: "SYNC_ATOMIC_PG_FENCE_DEV_OFF_DENIED" });
}
function need(value) { if (!value) throw denied(); }
function exact(value, fields) {
  need(value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === fields.length
    && fields.every((key) => Object.hasOwn(value, key)));
}
function detach(value) {
  try {
    const raw = protocol.canonicalJson(value);
    need(typeof raw === "string" && Buffer.byteLength(raw) < 8192);
    return JSON.parse(raw);
  } catch { throw denied(); }
}
function same(a, b) { return protocol.canonicalJson(a) === protocol.canonicalJson(b); }
function challengeOf(value) {
  const copy = detach(value);
  exact(copy, [...ID_FIELDS, "nonce", "operationIds", "envelopeDigests",
    "expectedPrevious"]);
  need(typeof copy.scope === "string" && SCOPE.test(copy.scope)
    && typeof copy.accountId === "string" && UUID.test(copy.accountId)
    && typeof copy.storeId === "string" && UUID.test(copy.storeId)
    && typeof copy.username === "string" && copy.username.length > 0
    && copy.username.length <= 512
    && typeof copy.compartmentId === "string" && copy.compartmentId.length > 0
    && copy.compartmentId.length <= 512
    && typeof copy.nonce === "string" && NONCE.test(copy.nonce)
    && Buffer.from(copy.nonce, "base64url").length === 32
    && Buffer.from(copy.nonce, "base64url").toString("base64url") === copy.nonce
    && Array.isArray(copy.operationIds) && copy.operationIds.length === 2
    && copy.operationIds.every((id) => typeof id === "string" && OP.test(id))
    && copy.operationIds[0] !== copy.operationIds[1]
    && Array.isArray(copy.envelopeDigests) && copy.envelopeDigests.length === 2
    && copy.envelopeDigests.every((digest) => typeof digest === "string" && HEX.test(digest)));
  if (copy.expectedPrevious !== null) {
    exact(copy.expectedPrevious, ["commitId", "storeHeadSha256", "fencingEpoch"]);
    need(typeof copy.expectedPrevious.commitId === "string"
      && COMMIT.test(copy.expectedPrevious.commitId)
      && typeof copy.expectedPrevious.storeHeadSha256 === "string"
      && HEX.test(copy.expectedPrevious.storeHeadSha256)
      && Number.isSafeInteger(copy.expectedPrevious.fencingEpoch)
      && copy.expectedPrevious.fencingEpoch > 0);
    Object.freeze(copy.expectedPrevious);
  }
  Object.freeze(copy.operationIds);
  Object.freeze(copy.envelopeDigests);
  return Object.freeze(copy);
}
function pinnedOwnerBindings(values) {
  need(Array.isArray(values) && values.length > 0 && values.length <= 1024);
  const bindings = new Map();
  for (const item of values) {
    const copy = detach(item);
    exact(copy, ID_FIELDS);
    need(typeof copy.scope === "string" && SCOPE.test(copy.scope)
      && typeof copy.accountId === "string" && UUID.test(copy.accountId)
      && typeof copy.storeId === "string" && UUID.test(copy.storeId)
      && typeof copy.username === "string" && copy.username.length > 0
      && copy.username.length <= 512
      && typeof copy.compartmentId === "string"
      && copy.compartmentId.length > 0 && copy.compartmentId.length <= 512
      && !bindings.has(copy.scope));
    bindings.set(copy.scope, Object.freeze(copy));
  }
  return bindings;
}
function physicalOf(value, challenge, publicKey) {
  const receipt = detach(value);
  exact(receipt, ["statement", "signature"]);
  exact(receipt.statement, RECEIPT_FIELDS);
  const statement = receipt.statement;
  need(statement.version === 2 && statement.physicalDurable === true
    && statement.nonce === challenge.nonce
    && ID_FIELDS.every((field) => statement[field] === challenge[field])
    && same(statement.operationIds, challenge.operationIds)
    && same(statement.envelopeDigests, challenge.envelopeDigests)
    && typeof statement.commitId === "string" && COMMIT.test(statement.commitId)
    && typeof statement.storeHeadSha256 === "string" && HEX.test(statement.storeHeadSha256)
    && Number.isSafeInteger(statement.fencingEpoch) && statement.fencingEpoch > 0
    && typeof receipt.signature === "string"
    && /^[A-Za-z0-9_-]{86}$/.test(receipt.signature));
  const signature = Buffer.from(receipt.signature, "base64url");
  need(signature.length === 64 && signature.toString("base64url") === receipt.signature
    && crypto.verify(null, Buffer.from(WITNESS_DOMAIN
      + protocol.canonicalJson(statement)), publicKey, signature));
  return receipt;
}

function createZk1SyncAtomicPgPhysicalFenceDevOff({ attestorPool,
  externalPhysicalFence, witnessPublicKey, ownerBindings,
  unsafeTestReadback = null, readbackTimeoutMs = 5000,
  operationTimeoutMs = 8000 } = {}) {
  // Test-only signed-fence adversarial harness. Runtime operation always uses
  // the real PostgreSQL read-only verifier; a caller cannot replace it with
  // an arbitrary callback outside the explicitly non-deployable test mode.
  need((unsafeTestReadback === null
    ? attestorPool && typeof attestorPool.connect === "function"
    : (process.env.NODE_ENV === "test" && unsafeTestReadback
      && typeof unsafeTestReadback.verifyCurrentSignedPair === "function"))
    && externalPhysicalFence && typeof externalPhysicalFence.withCurrentRead === "function"
    && witnessPublicKey instanceof crypto.KeyObject
    && witnessPublicKey.type === "public"
    && witnessPublicKey.asymmetricKeyType === "ed25519"
    && Number.isSafeInteger(readbackTimeoutMs) && readbackTimeoutMs >= 50
    && readbackTimeoutMs <= 7000
    && Number.isSafeInteger(operationTimeoutMs)
    && operationTimeoutMs >= readbackTimeoutMs && operationTimeoutMs <= 15000);
  // Input scopes and UUIDs are never admission authority. The independent
  // attestor operator must pin its immutable identities outside writer input.
  const owners = pinnedOwnerBindings(ownerBindings);
  const readback = unsafeTestReadback || createZk1SyncPgBatchIndependentReadback({ attestorPool });
  // A timeout does NOT cancel pg.Pool.connect or an already-running SQL call.
  // Keep unresolved work in a bounded set until the actual provider settles.
  const pendingReads = new Set();
  const pendingByScope = new Map();
  const pendingProviders = new Map();
  return Object.freeze({
    async withCurrentRead(input, continuation) {
      const challenge = challengeOf(input);
      need(typeof continuation === "function");
      const trusted = owners.get(challenge.scope);
      need(trusted && ID_FIELDS.every((field) => trusted[field] === challenge[field]));
      let called = false, completed = false, callbackSucceeded = false;
      let closed = false, inner;
      try {
        need(!pendingProviders.has(challenge.scope) && pendingProviders.size < 8);
        const provider = Promise.resolve().then(() => externalPhysicalFence.withCurrentRead(challenge,
          (bundle, lease) => {
            // The external provider may incorrectly drop the callback Promise.
            // Attach an observer, but return the SAME rejecting promise so a
            // well-behaved provider must still propagate the actual failure.
            const callbackPromise = (async () => {
            need(!closed && !called);
            called = true;
            need(lease && typeof lease.assertHeld === "function");
            const assertHeld = () => {
              need(!closed);
              let held = false;
              try { held = lease.assertHeld(); } catch { throw denied(); }
              need(held === true);
              return true;
            };
            try {
              assertHeld();
              const evidence = detach(bundle);
              exact(evidence, ["receipt", "lineage"]);
              const receipt = physicalOf(evidence.receipt, challenge, witnessPublicKey);
              need(pendingReads.size < 8 && !pendingByScope.has(challenge.scope));
              const inFlight = Promise.resolve().then(() => readback.verifyCurrentSignedPair({
                scope: challenge.scope, operationIds: challenge.operationIds,
                envelopeDigests: challenge.envelopeDigests,
              }));
              pendingReads.add(inFlight);
              pendingByScope.set(challenge.scope, inFlight);
              const settle = () => {
                pendingReads.delete(inFlight);
                if (pendingByScope.get(challenge.scope) === inFlight) {
                  pendingByScope.delete(challenge.scope);
                }
              };
              inFlight.then(settle, settle);
              let timer;
              let sql;
              try {
                sql = detach(await Promise.race([inFlight,
                  new Promise((_, reject) => {
                    timer = setTimeout(() => reject(denied()), readbackTimeoutMs);
                  })]));
              } finally { clearTimeout(timer); }
              assertHeld();
              // PostgreSQL readback is a separate strict SQL evidence check,
              // NEVER itself a physical witness or an ACK authorization.
              need(sql && sql.localPgRowsConsistent === true
                && sql.witnessVerified === false && sql.clientAckAuthorized === false
                && sql.scope === challenge.scope
                && sql.username === challenge.username
                && sql.compartmentId === challenge.compartmentId
                && sql.commitId === receipt.statement.commitId
                && sql.head === receipt.statement.storeHeadSha256
                && same(sql.operationIds, challenge.operationIds)
                && same(sql.envelopeDigests, challenge.envelopeDigests));
              assertHeld();
              inner = await continuation(evidence, { assertHeld });
              assertHeld();
              callbackSucceeded = true;
              return inner;
            } finally { completed = true; }
            })();
            callbackPromise.catch(() => { /* prevent unhandled rejection if detached */ });
            return callbackPromise;
          }));
        pendingProviders.set(challenge.scope, provider);
        const settleProvider = () => {
          if (pendingProviders.get(challenge.scope) === provider) {
            pendingProviders.delete(challenge.scope);
          }
        };
        provider.then(settleProvider, settleProvider);
        // An abandoned external lease provider must not stall the caller's
        // serialized CAS queue forever, even when SQL itself settled.
        let operationTimer;
        let result;
        try {
          result = await Promise.race([provider, new Promise((_, reject) => {
            operationTimer = setTimeout(() => reject(denied()), operationTimeoutMs);
          })]);
        } finally { clearTimeout(operationTimer); }
        closed = true;
        need(called && completed && callbackSucceeded && result === inner);
        return result;
      } catch {
        closed = true;
        throw denied();
      }
    },
  });
}

module.exports = { createZk1SyncAtomicPgPhysicalFenceDevOff };
