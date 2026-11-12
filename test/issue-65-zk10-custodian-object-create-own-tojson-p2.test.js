"use strict";

// Real Ed25519 A->B regression, DEV-OFF only. Do not mock Ed25519 verification.
// The same-realm callback runs AFTER the custodian module was loaded and
// BEFORE its next signed-input copy. It poisons a mutable global factory.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { signatureBytes } = require("../src/crypto/rootark-zk10-account-cutover-v1");
let observedOwnerVerification;
const nativeVerify = crypto.verify;
let createDevOffZk10MonotonicFloorCustodian;
try {
  // Instrument module capture BEFORE any adversarial callback. Every result
  // still comes from the real native crypto.verify, never an artificial GO.
  crypto.verify = (...args) => {
    const accepted = nativeVerify(...args);
    if (Buffer.isBuffer(args[1]) && args[1].toString("utf8")
      .startsWith("Root.ark/zk10/custodian-owner-lease/v1\0")) {
      const body = args[1].subarray(args[1].indexOf(0) + 1);
      observedOwnerVerification = { accepted, payload: JSON.parse(body.toString("utf8")) };
    }
    return accepted;
  };
  ({ createDevOffZk10MonotonicFloorCustodian } = require(
    "../src/services/zk10DevOffMonotonicFloorCustodian"));
} finally { crypto.verify = nativeVerify; }

const GENESIS = Buffer.from("Root.ark/zk10/custodian-owner-genesis/v1\0");
const LEASE = Buffer.from("Root.ark/zk10/custodian-owner-lease/v1\0");
const FLOOR = Buffer.from("Root.ark/zk10/external-floor-current/v1\0");
const sha = n => Buffer.alloc(32, n).toString("hex");
const base64 = data => data.toString("base64url");
const originalCreate = Object.create;

function fixture(t, suffix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark302-objectcreate-"));
  let custodian;
  t.after(() => {
    try { custodian?.close(); }
    finally { fs.rmSync(root, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 }); }
  });
  const owner = crypto.generateKeyPairSync("ed25519");
  const signer = crypto.generateKeyPairSync("ed25519");
  const sign = (payload, key, domain) => ({ ...payload,
    signature: base64(crypto.sign(null, signatureBytes(domain, payload), key)) });
  const base = { type: "rootark-zk10-custodian-owner-lease/v1",
    sequence: 1, head_digest: sha(1), enrollment_root: sha(2),
    immutable_account_id: base64(Buffer.alloc(16, 3)),
    identity_digest: sha(4), operation: "legacy:read", nonce: base64(crypto.randomBytes(32)),
    lease_id: base64(crypto.randomBytes(16)), lease_serial: 1,
    issued_at_ms: Date.now(), lease_expires_at_ms: Date.now() + 8000 };
  const bootstrap = sign({ type: "rootark-zk10-custodian-owner-genesis/v1",
    sequence: 1, head_digest: sha(1), enrollment_root: sha(2),
    immutable_account_id: base.immutable_account_id,
    identity_digest: sha(4), lease_serial: 0 }, owner.privateKey, GENESIS);
  const config = { devOff: true,
    databasePath: path.join(root, suffix + ".sqlite"),
    anchorDatabasePath: path.join(root, suffix + "-anchor.sqlite"),
    ownerPublicKey: owner.publicKey, custodianPrivateKey: signer.privateKey,
    custodianSpkiSha256: crypto.createHash("sha256")
      .update(signer.publicKey.export({ format: "der", type: "spki" })).digest("hex"),
    bootstrap };
  custodian = createDevOffZk10MonotonicFloorCustodian(config);
  const request = Object.fromEntries([
    "immutable_account_id", "identity_digest", "operation", "nonce",
    "lease_id", "lease_expires_at_ms"].map(field => [field, base[field]]));
  return { custodian, owner, signer, config, base, request, sign };
}

test("P2: malicious same-realm Object.create cannot verify owner Ed25519 A then issue CURRENT B", t => {
  const f = fixture(t, "owner-a-to-b");
  const signedA = f.sign(f.base, f.owner.privateKey, LEASE);
  const forgedB = { ...signedA, sequence: 2, head_digest: sha(98), enrollment_root: sha(99) };
  assert.equal(crypto.verify(null, signatureBytes(LEASE, f.base),
    f.owner.publicKey, Buffer.from(signedA.signature, "base64url")), true,
  "A is a genuine independently verifiable owner Ed25519 signature");
  assert.equal(crypto.verify(null, signatureBytes(LEASE, forgedB),
    f.owner.publicKey, Buffer.from(forgedB.signature, "base64url")), false,
  "B was NOT authorized by the owner; its signature was copied from A");

  const realLstat = fs.lstatSync;
  let callbacks = 0, clones = 0, wireRewrites = 0;
  fs.lstatSync = function (name, ...args) {
    if (!callbacks && name === f.config.anchorDatabasePath) {
      callbacks++;
      // Existing code checks DB pins through this caller-modifiable same-realm
      // filesystem hook before strict() and canonicalFields() run again.
      Object.create = function (prototype, properties) {
        const result = originalCreate(prototype, properties);
        if (prototype === null) {
          clones++;
          // Same-realm attacker can inspect the immediate JS call stack and
          // only poison signed LEASE serialization. Poisoning all clones
          // would be detected by strict() fieldCount on the HEAD clone.
          const stack = new Error().stack || "";
          if (stack.includes("at signatureBytes") && stack.includes("at unsignedSigned")) {
            // A forged null-proto object with *own* toJSON is NOT immune to
            // JSON.stringify; it returns signed A from applied B.
            Object.defineProperty(result, "toJSON", { configurable: true,
              value() {
                if (this.type !== "rootark-zk10-custodian-owner-lease/v1") return this;
                wireRewrites++;
                return { ...this, sequence: f.base.sequence,
                  head_digest: f.base.head_digest, enrollment_root: f.base.enrollment_root };
              } });
          }
        }
        return result;
      };
    }
    return realLstat(name, ...args);
  };
  let issued;
  try { issued = f.custodian.attest(f.request, forgedB); }
  catch (error) {
    assert.match(error.message, /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally {
    fs.lstatSync = realLstat;
    Object.create = originalCreate;
  }
  assert.equal(callbacks, 1, "hostile callback executed after module capture");
  assert.equal(clones, 0,
    "no signed clone may invoke the attacker-rebound Object.create factory");
  let retainedSerial = "poisoned";
  try { retainedSerial = f.custodian.retainedMinimum().lease_serial; }
  catch (_) { /* A denied or ambiguous write may poison the handle */ }
  console.log("PHYSICAL_OBJECT_CREATE_ATTACK_OBSERVATION",
    `issued=${issued ? issued.floor.sequence : "none"}`,
    `retainedSerial=${retainedSerial}`, `wireRewrites=${wireRewrites}`,
    `realVerifyAccepted=${observedOwnerVerification?.accepted}`,
    `realVerifySequence=${observedOwnerVerification?.payload?.sequence}`);
  if (issued) {
    console.log("EXPECTED_SECURITY_RED_OWNER_A_ISSUED_CURRENT_B",
      `sequence=${issued.floor.sequence}`);
    const body = Object.fromEntries(Object.entries(issued.floor)
      .filter(([name]) => name !== "signature"));
    assert.equal(crypto.verify(null, signatureBytes(FLOOR, body),
      f.signer.publicKey, Buffer.from(issued.floor.signature, "base64url")), true,
    "the forged CURRENT B was genuinely Ed25519-signed by custodian, not a mock");
  }
  assert.equal(issued?.floor.sequence, undefined,
    "owner-signed state A may never authorize an issued CURRENT B");
  assert.equal(wireRewrites, 0,
    "signed canonical clones must never invoke an attacker-controlled toJSON");
  assert.equal(observedOwnerVerification?.accepted, false,
    "real native owner Ed25519 verification must reject unsigned B");
  assert.equal(f.custodian.retainedMinimum().lease_serial, 0,
    "the unauthorized B must not consume a durable lease");

  // Preserve the genuine positive, even after a failed attempted forgery.
  const positive = f.custodian.attest(f.request, signedA).floor;
  assert.equal(positive.sequence, 1);
  assert.ok(crypto.verify(null, signatureBytes(FLOOR,
    Object.fromEntries(Object.entries(positive).filter(([name]) => name !== "signature"))),
  f.signer.publicKey, Buffer.from(positive.signature, "base64url")));
});

test("P2: inherited Object.prototype.toJSON cannot authenticate signed owner A while committing B", t => {
  const f = fixture(t, "inherited-tojson-signed-a-committed-b");
  const signedA = f.sign(f.base, f.owner.privateKey, LEASE);
  const forgedB = { ...signedA, sequence: 2,
    head_digest: sha(98), enrollment_root: sha(99) };
  assert.equal(crypto.verify(null, signatureBytes(LEASE, f.base),
    f.owner.publicKey, Buffer.from(signedA.signature, "base64url")), true);
  assert.equal(crypto.verify(null, signatureBytes(LEASE,
    Object.fromEntries(Object.entries(forgedB).filter(([key]) => key !== "signature"))),
  f.owner.publicKey, Buffer.from(forgedB.signature, "base64url")), false,
  "owner A never Ed25519-signed head B");

  const nativeLstat = fs.lstatSync;
  const originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  let injected = 0;
  let spoofedSerializations = 0;
  let issued;
  fs.lstatSync = function instrumentedLstat(name, ...args) {
    if (!injected && name === f.config.anchorDatabasePath) {
      injected += 1;
      // This hostile same-realm callback happens AFTER the verifier's module
      // was imported, before it snapshots ownerLease on the current request.
      Object.defineProperty(Object.prototype, "toJSON", {
        configurable: true, value: function hostileInheritedSignedSerializer() {
          if (this.type === "rootark-zk10-custodian-owner-lease/v1"
            && this.sequence === forgedB.sequence && this.head_digest === forgedB.head_digest) {
            spoofedSerializations += 1;
            return { ...this, sequence: f.base.sequence,
              head_digest: f.base.head_digest, enrollment_root: f.base.enrollment_root };
          }
          return this;
        },
      });
    }
    return nativeLstat(name, ...args);
  };
  try { issued = f.custodian.attest(f.request, forgedB); }
  catch (error) { assert.match(error.message, /ZK10_CUSTODIAN_UNAVAILABLE/); }
  finally {
    fs.lstatSync = nativeLstat;
    if (originalToJSON) Object.defineProperty(Object.prototype, "toJSON", originalToJSON);
    else delete Object.prototype.toJSON;
  }
  let observedRetainedSerial = "unavailable";
  try { observedRetainedSerial = f.custodian.retainedMinimum().lease_serial; }
  catch (_) { /* an indeterminate or rejected write must remain fail-closed */ }
  console.log("PHYSICAL_INHERITED_TOJSON_OWNER_A_FORGED_B",
    `issued=${issued?.floor.sequence ?? "none"}`,
    `retainedSerial=${observedRetainedSerial}`,
    `injections=${injected}`, `spoofedSerializations=${spoofedSerializations}`);
  assert.equal(injected, 1, "real post-import fs callback must install malicious toJSON");
  assert.equal(spoofedSerializations, 0,
    "signed wire must not dispatch to inherited Object.prototype.toJSON");
  assert.equal(issued, undefined,
    "signed head A must never produce a custodian-signed CURRENT for B");
  assert.equal(f.custodian.retainedMinimum().lease_serial, 0,
    "forged owner head must not advance durable SQLite floors");

  // The same signer still accepts the genuine A lease after the attack is
  // removed, and its freshly signed CURRENT remains DEV-OFF evidence only.
  const positive = f.custodian.attest(f.request, signedA).floor;
  assert.equal(positive.sequence, 1);
  assert.equal(crypto.verify(null, signatureBytes(FLOOR,
    Object.fromEntries(Object.entries(positive).filter(([key]) => key !== "signature"))),
  f.signer.publicKey, Buffer.from(positive.signature, "base64url")), true);
});

test("P2: malicious own-accessor in strict request cannot compare signed A then issue operation B", t => {
  const f = fixture(t, "request-accessor-a-to-b");
  const signedA = f.sign(f.base, f.owner.privateKey, LEASE);
  assert.equal(crypto.verify(null, signatureBytes(LEASE, f.base),
    f.owner.publicKey, Buffer.from(signedA.signature, "base64url")), true);
  const fakeOperationB = { ...f.base, operation: "legacy:write" };
  assert.equal(crypto.verify(null, signatureBytes(LEASE, fakeOperationB),
    f.owner.publicKey, Buffer.from(signedA.signature, "base64url")), false);

  const realLstat = fs.lstatSync;
  let callbackCount = 0, poisonedFactories = 0, getterReads = 0;
  fs.lstatSync = function (name, ...args) {
    if (!callbackCount && name === f.config.anchorDatabasePath) {
      callbackCount++;
      Object.create = function (proto, properties) {
        const copy = originalCreate(proto, properties);
        if (proto === null) {
          const stack = new Error().stack || "";
          if (stack.includes("at strict") && stack.includes("at Object.attest")
            && !stack.includes("at unsignedSigned")) {
            poisonedFactories++;
            let actualValue;
            Object.defineProperty(copy, "operation", {
              configurable: true, enumerable: true,
              set(value) { actualValue = value; },
              get() {
                getterReads++;
                // First request validation and owner-signed A comparison,
                // then switch to unsigned B for regex and CURRENT emission.
                return getterReads <= 2 ? actualValue : "legacy:write";
              },
            });
          }
        }
        return copy;
      };
    }
    return realLstat(name, ...args);
  };
  let issued;
  try { issued = f.custodian.attest(f.request, signedA); }
  catch (error) { assert.match(error.message, /ZK10_CUSTODIAN_UNAVAILABLE/); }
  finally {
    fs.lstatSync = realLstat;
    Object.create = originalCreate;
  }
  console.log("PHYSICAL_OBJECT_CREATE_ACCESSOR_OBSERVATION",
    `issued=${issued ? issued.floor.operation : "none"}`,
    `attackerFactories=${poisonedFactories}`, `accessorReads=${getterReads}`);
  assert.equal(callbackCount, 1, "hostile callback executes after custodian module load");
  assert.equal(poisonedFactories, 0, "strict may not call a rebound Object.create");
  assert.equal(getterReads, 0, "strict result must not dispatch to attacker own accessor");
  assert.equal(issued?.floor.operation, "legacy:read",
    "a genuinely signed A lease must continue issuing operation A");
  assert.equal(f.custodian.retainedMinimum().lease_serial, 1);
  assert.ok(crypto.verify(null, signatureBytes(FLOOR,
    Object.fromEntries(Object.entries(issued.floor).filter(([name]) => name !== "signature"))),
  f.signer.publicKey, Buffer.from(issued.floor.signature, "base64url")));
});

test("P2: hostile array iterator cannot omit signed request fields and issue operation B", t => {
  const f = fixture(t, "request-iterator-skip");
  const signedA = f.sign(f.base, f.owner.privateKey, LEASE);
  const unsignedRequestB = { ...f.request, operation: "legacy:write" };
  assert.equal(crypto.verify(null, signatureBytes(LEASE, f.base),
    f.owner.publicKey, Buffer.from(signedA.signature, "base64url")), true);
  assert.equal(unsignedRequestB.operation, "legacy:write");
  assert.equal(signedA.operation, "legacy:read");

  const nativeLstat = fs.lstatSync;
  const nativeArrayIterator = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.iterator);
  let callbacks = 0, skippedOwnerRequestIterations = 0, issued;
  fs.lstatSync = function interceptedLstat(name, ...args) {
    if (!callbacks && name === f.config.anchorDatabasePath) {
      callbacks += 1;
      // The custodian has already imported its native crypto functions.
      // The old `for (const field of REQUEST_FIELDS)` repeatedly dispatched
      // to this inherited iterator AFTER the attacker-controlled FS callback.
      Object.defineProperty(Array.prototype, Symbol.iterator, {
        configurable: true, writable: true, value: function* poisonedIterator() {
          if (this.length === 6 && this[0] === "immutable_account_id"
            && this[1] === "identity_digest" && this[2] === "operation"
            && this[5] === "lease_expires_at_ms") {
            skippedOwnerRequestIterations += 1;
            return;
          }
          yield* Reflect.apply(nativeArrayIterator.value, this, []);
        },
      });
    }
    return nativeLstat(name, ...args);
  };
  try { issued = f.custodian.attest(unsignedRequestB, signedA); }
  catch (error) { assert.match(error.message, /ZK10_CUSTODIAN_UNAVAILABLE/); }
  finally {
    fs.lstatSync = nativeLstat;
    Object.defineProperty(Array.prototype, Symbol.iterator, nativeArrayIterator);
  }
  console.log("PHYSICAL_OWNER_REQUEST_ITERATOR_REBIND",
    `issued=${issued?.floor.operation ?? "none"}`,
    `retainedSerial=${f.custodian.retainedMinimum().lease_serial}`,
    `callbacks=${callbacks}`, `skippedIterations=${skippedOwnerRequestIterations}`);
  assert.equal(callbacks, 1, "the hostile same-realm FS callback must execute");
  assert.equal(skippedOwnerRequestIterations, 0,
    "fixed signed schema bindings may not dispatch to a hostile inherited iterator");
  assert.equal(issued, undefined,
    "owner's Ed25519-signed READ must never authorize an unsigned WRITE request");
  assert.equal(f.custodian.retainedMinimum().lease_serial, 0);

  const control = f.custodian.attest(f.request, signedA).floor;
  assert.equal(control.operation, "legacy:read");
  assert.equal(crypto.verify(null, signatureBytes(FLOOR,
    Object.fromEntries(Object.entries(control).filter(([key]) => key !== "signature"))),
  f.signer.publicKey, Buffer.from(control.signature, "base64url")), true);
});
