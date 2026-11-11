"use strict";

// All signers and SQLite files are disposable. This does not prove off-host custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { fork } = require("node:child_process");
const { Worker } = require("node:worker_threads");
const { signatureBytes } = require("../src/crypto/rootark-zk10-account-cutover-v1");
const {
  createDevOffZk10MonotonicFloorCustodian,
} = require("../src/services/zk10DevOffMonotonicFloorCustodian");
const CUSTODIAN_MODULE = require.resolve("../src/services/zk10DevOffMonotonicFloorCustodian");

// Tests which instrument the genuine crypto.sign/verify syscall boundary must
// do so BEFORE importing the isolated module: production captures genuine
// native entrypoints at import to prevent later malicious replacement.
// This test-only reload preserves the original singleton's require.cache.
function testFactoryCapturingCurrentCrypto() {
  const cached = require.cache[CUSTODIAN_MODULE];
  try {
    delete require.cache[CUSTODIAN_MODULE];
    return require(CUSTODIAN_MODULE).createDevOffZk10MonotonicFloorCustodian;
  } finally {
    delete require.cache[CUSTODIAN_MODULE];
    if (cached) require.cache[CUSTODIAN_MODULE] = cached;
  }
}
function isOwnerLeaseVerify(data) {
  return Buffer.isBuffer(data)
    && data.subarray(0, DOMAIN_LEASE.length).equals(DOMAIN_LEASE);
}

const DOMAIN_GENESIS = Buffer.from("Root.ark/zk10/custodian-owner-genesis/v1\0");
const DOMAIN_LEASE = Buffer.from("Root.ark/zk10/custodian-owner-lease/v1\0");
const DOMAIN_FLOOR = Buffer.from("Root.ark/zk10/external-floor-current/v1\0");
const b64 = (buffer) => buffer.toString("base64url");
const id = (number) => b64(Buffer.alloc(16, number));
const sha = (number) => Buffer.alloc(32, number).toString("hex");
const keyHash = (key) => crypto.createHash("sha256")
  .update(key.export({ type: "spki", format: "der" })).digest("hex");
function sign(payload, signer, domain) {
  return { ...payload, signature: b64(crypto.sign(null, signatureBytes(domain, payload), signer)) };
}
function isActualCustodianFloorCall(data, key, publicKey, signature) {
  if (!Buffer.isBuffer(data) || !data.subarray(0, DOMAIN_FLOOR.length).equals(DOMAIN_FLOOR)
    || !(key instanceof crypto.KeyObject)
    || !crypto.KeyObject.prototype.equals.call(crypto.createPublicKey(key), publicKey)) return false;
  // Cloned private KeyObjects are a feature. Prove that the real native
  // signature verifies under the independently expected Ed25519 public key.
  if (signature !== undefined) {
    assert.equal(crypto.verify(null, data, publicKey, signature), true,
      "instrumented floor signature must be real Ed25519 from the expected custodian");
  }
  return true;
}
function setup(t, suffix = "single") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk10-custodian-w4-"));
  const opened = [];
  t.after(() => {
    for (const custodian of opened) custodian.close();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 });
  });
  const owner = crypto.generateKeyPairSync("ed25519");
  const custodian = crypto.generateKeyPairSync("ed25519");
  const paths = { databasePath: path.join(root, suffix + ".sqlite"),
    anchorDatabasePath: path.join(root, suffix + "-external-minimum.sqlite") };
  const genesis = sign({ type: "rootark-zk10-custodian-owner-genesis/v1",
    sequence: 1, head_digest: sha(1), enrollment_root: sha(2),
    immutable_account_id: id(3), identity_digest: sha(4), lease_serial: 0 },
  owner.privateKey, DOMAIN_GENESIS);
  const config = { devOff: true, ...paths,
    ownerPublicKey: owner.publicKey,
    custodianPrivateKey: custodian.privateKey,
    custodianSpkiSha256: keyHash(custodian.publicKey), bootstrap: genesis };
  let serial = 0;
  function offer(overrides = {}) {
    const at = Date.now();
    const lease = { type: "rootark-zk10-custodian-owner-lease/v1",
      sequence: 1, head_digest: sha(1), enrollment_root: sha(2),
      immutable_account_id: id(3), identity_digest: sha(4),
      operation: "legacy:read", nonce: b64(crypto.randomBytes(32)),
      lease_id: b64(crypto.randomBytes(16)), lease_serial: ++serial,
      issued_at_ms: at, lease_expires_at_ms: at + 4000, ...overrides };
    const request = Object.fromEntries([
      "immutable_account_id", "identity_digest", "operation", "nonce",
      "lease_id", "lease_expires_at_ms"].map(k => [k, lease[k]]));
    return { request, ownerLease: sign(lease, owner.privateKey, DOMAIN_LEASE) };
  }
  return { root, owner, custodian, genesis, config, offer, paths,
    track: instance => { opened.push(instance); return instance; } };
}

test("opt-in, separately pinned Ed25519 signer and owner-signed genesis required before state creation", (t) => {
  const x = setup(t);
  for (const changes of [
    { devOff: false }, { custodianPrivateKey: undefined },
    { custodianSpkiSha256: sha(8) }, { ownerPublicKey: x.custodian.publicKey },
    { bootstrap: { ...x.genesis, signature: b64(Buffer.alloc(64)) } },
  ]) {
    assert.throws(() => createDevOffZk10MonotonicFloorCustodian({ ...x.config, ...changes }),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  }
  const previous = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    assert.throws(() => createDevOffZk10MonotonicFloorCustodian(x.config),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
  assert.equal(fs.existsSync(x.paths.databasePath), false);
  assert.equal(fs.existsSync(x.paths.anchorDatabasePath), false);
});

test("P2: a shadowed KeyObject export cannot disguise one owner/custodian signing key", (t) => {
  const x = setup(t, "same-native-key-shadowed-spki");
  const unrelatedDer = x.owner.publicKey.export({ format: "der", type: "spki" });
  const actualOwner = x.custodian.publicKey;
  // The owner genesis and custodian floor would both use the SAME real
  // private key. Only an instance-shadowed export makes their hashes differ.
  Object.defineProperty(actualOwner, "export", { value: () => unrelatedDer });
  const genesis = { ...x.genesis };
  delete genesis.signature;
  const bootstrap = sign(genesis, x.custodian.privateKey, DOMAIN_GENESIS);
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, ownerPublicKey: actualOwner, bootstrap,
  }), /ZK10_CUSTODIAN_UNAVAILABLE/,
  "a false reported SPKI must not make the same native signing key independent");
  assert.equal(fs.existsSync(x.paths.databasePath), false);
  assert.equal(fs.existsSync(x.paths.anchorDatabasePath), false);
});

test("P2 native owner kHandle cannot make the physical custodian signer its own owner", (t) => {
  const x = setup(t, "owner-handle-role-alias");
  const actual = x.custodian.publicKey;
  const other = x.owner.publicKey;
  const symbol = Object.getOwnPropertySymbols(actual)
    .find((item) => String(item) === "Symbol(kHandle)");
  assert.ok(symbol);
  let reads = 0;
  const forged = Object.create(actual);
  Object.defineProperty(forged, symbol, { get() {
    return (++reads <= 2 ? other : actual)[symbol];
  } });
  const { signature: _discard, ...unsigned } = x.genesis;
  const bootstrap = sign(unsigned, x.custodian.privateKey, DOMAIN_GENESIS);
  assert.throws(() => x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, ownerPublicKey: forged, bootstrap,
  })), /ZK10_CUSTODIAN_UNAVAILABLE/,
  "one actual key A cannot serve owner and custodian despite claimed B");
  assert.equal(reads, 0, "owner key-handle getter is rejected without execution");
});

test("P2 mutable private signer cannot sign CURRENT as A while claiming custodian SPKI B", (t) => {
  const x = setup(t, "private-signer-handle-swap");
  const actual = x.custodian;
  const other = crypto.generateKeyPairSync("ed25519");
  const symbol = Object.getOwnPropertySymbols(actual.privateKey)
    .find((item) => String(item) === "Symbol(kHandle)");
  assert.ok(symbol);
  const forged = Object.create(actual.privateKey);
  let reads = 0;
  Object.defineProperty(forged, symbol, { get() {
    return (++reads === 2 ? other.privateKey : actual.privateKey)[symbol];
  } });
  try {
    const custodian = x.track(createDevOffZk10MonotonicFloorCustodian({
      ...x.config, custodianPrivateKey: forged,
      custodianSpkiSha256: keyHash(other.publicKey),
    }));
    const { request, ownerLease } = x.offer();
    const { signature, ...floor } = custodian.attest(request, ownerLease).floor;
    const data = signatureBytes(DOMAIN_FLOOR, floor);
    const signed = Buffer.from(signature, "base64url");
    assert.equal(crypto.verify(null, data, other.publicKey, signed), true,
      "signed CURRENT must verify against the pinned custodian SPKI");
    assert.equal(crypto.verify(null, data, actual.publicKey, signed), false,
      "signed CURRENT may not silently use the foreign signer A");
  } catch (error) {
    if (error.code !== "ZK10_CUSTODIAN_UNAVAILABLE") throw error;
  }
  assert.equal(reads, 0, "private key-handle getter is rejected without execution");
});

test("P2 native PKCS8 factory must not be replaceable by a private KeyObject getter", (t) => {
  const x = setup(t, "private-key-factory-swap");
  const actual = x.custodian;
  const alleged = crypto.generateKeyPairSync("ed25519");
  const handle = Object.getOwnPropertySymbols(actual.privateKey)
    .find((item) => String(item) === "Symbol(kHandle)");
  assert.ok(handle, "exercise the native Ed25519 private handle");
  const savedCreatePrivateKey = crypto.createPrivateKey;
  const forgedPinned = Object.create(actual.privateKey);
  let pinnedReads = 0;
  Object.defineProperty(forgedPinned, handle, { get() {
    // Native derive sees B; crypto.sign later sees A.
    return (++pinnedReads === 2 ? alleged.privateKey : actual.privateKey)[handle];
  } });
  const caller = Object.create(actual.privateKey);
  let callerReads = 0;
  let factoryWasReplaced = false;
  Object.defineProperty(caller, handle, { get() {
    if (++callerReads === 2) {
      factoryWasReplaced = true;
      crypto.createPrivateKey = () => forgedPinned;
    }
    return actual.privateKey[handle];
  } });
  try {
    const custodian = x.track(createDevOffZk10MonotonicFloorCustodian({
      ...x.config, custodianPrivateKey: caller,
      custodianSpkiSha256: keyHash(alleged.publicKey),
    }));
    const { request, ownerLease } = x.offer();
    const { signature, ...payload } = custodian.attest(request, ownerLease).floor;
    const message = signatureBytes(DOMAIN_FLOOR, payload);
    const signed = Buffer.from(signature, "base64url");
    assert.equal(crypto.verify(null, message, alleged.publicKey, signed), true,
      "CURRENT must verify under the actual configured custodian SPKI B");
    assert.equal(crypto.verify(null, message, actual.publicKey, signed), false,
      "the original private signer A may not impersonate B");
  } catch (error) {
    if (error.code !== "ZK10_CUSTODIAN_UNAVAILABLE") throw error;
  } finally {
    crypto.createPrivateKey = savedCreatePrivateKey;
  }
  assert.equal(callerReads, 0,
    "native private-key getter cannot run and replace crypto.createPrivateKey");
  assert.equal(factoryWasReplaced, false, "private native factory remains uncompromised");
});

test("genuine DER-imported Ed25519 owner and custodian keys remain usable", (t) => {
  const x = setup(t, "genuine-imported-native-keys");
  const ownerDer = x.owner.publicKey.export({ format: "der", type: "spki" });
  const custodianDer = x.custodian.privateKey.export({ format: "der", type: "pkcs8" });
  let importedPrivate;
  try {
    importedPrivate = crypto.createPrivateKey({
      key: custodianDer, format: "der", type: "pkcs8",
    });
  } finally {
    custodianDer.fill(0);
  }
  const importedOwner = crypto.createPublicKey({
    key: ownerDer, format: "der", type: "spki",
  });
  const c = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, ownerPublicKey: importedOwner, custodianPrivateKey: importedPrivate,
  }));
  const { request, ownerLease } = x.offer();
  const { signature, ...payload } = c.attest(request, ownerLease).floor;
  assert.equal(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, payload),
    x.custodian.publicKey, Buffer.from(signature, "base64url")), true);
  assert.equal(c.independentOffServerCustodyProven, false);
});

test("P2 proxy-verifier forged owner lease cannot install fake crypto verify", (t) => {
  const x = setup(t, "owner-lease-proxy-verify-hook");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const foreign = crypto.generateKeyPairSync("ed25519");
  const { request, ownerLease } = x.offer();
  const { signature: _discard, ...unsigned } = ownerLease;
  const unsignedByOwner = signatureBytes(DOMAIN_LEASE, unsigned);
  const forged = { ...unsigned, signature: crypto.sign(null,
    unsignedByOwner, foreign.privateKey).toString("base64url") };
  assert.equal(crypto.verify(null, unsignedByOwner,
    x.owner.publicKey, Buffer.from(forged.signature, "base64url")), false,
  "the owner did not sign this adversarial lease");

  const nativeVerify = crypto.verify;
  let descriptorTrapCalls = 0;
  const proxy = new Proxy(forged, {
    getOwnPropertyDescriptor(target, property) {
      descriptorTrapCalls++;
      crypto.verify = (algorithm, message, key, signatureBytesArg) => {
        if (Buffer.isBuffer(message)
          && message.subarray(0, DOMAIN_LEASE.length).equals(DOMAIN_LEASE)) return true;
        return nativeVerify(algorithm, message, key, signatureBytesArg);
      };
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  try {
    assert.throws(() => c.attest(request, proxy), /ZK10_CUSTODIAN_UNAVAILABLE/,
      "an injected verifier cannot turn a foreign signature into owner authorization");
  } finally {
    crypto.verify = nativeVerify;
  }
  assert.equal(descriptorTrapCalls, 0,
    "a Proxy owner lease must be rejected before its descriptor hooks execute");
});

test("P2 nested lease toJSON cannot poison verifier then authorize foreign-signed CURRENT", (t) => {
  const x = setup(t, "lease-nested-tojson-second-attempt");
  const custodian = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const foreign = crypto.generateKeyPairSync("ed25519");
  const { request, ownerLease } = x.offer();
  const { signature: _discard, ...unsigned } = ownerLease;
  const forged = sign(unsigned, foreign.privateKey, DOMAIN_LEASE);
  const savedVerify = crypto.verify;
  assert.equal(savedVerify(null, signatureBytes(DOMAIN_LEASE, unsigned),
    x.owner.publicKey, Buffer.from(forged.signature, "base64url")), false,
  "a genuine foreign Ed25519 signer is NOT the owner");
  let toJsonCalls = 0;
  const poisonedLease = { ...ownerLease, nonce: { toJSON() {
    toJsonCalls++;
    crypto.verify = () => true;
    return unsigned.nonce;
  } } };
  let result;
  try {
    assert.throws(() => custodian.attest(request, poisonedLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/, "initial nested lease must fail before journal write");
    assert.equal(custodian.retainedMinimum().lease_serial, 0,
      "first invalid lease cannot mutate either SQLite floor");
    assert.throws(() => { result = custodian.attest(request, forged); },
      /ZK10_CUSTODIAN_UNAVAILABLE/,
      "same active instance must not accept foreign owner signature after nested toJSON");
  } finally { crypto.verify = savedVerify; }
  assert.equal(toJsonCalls, 0, "nested object toJSON cannot execute before validation");
  assert.equal(result, undefined, "no owner-unauthorized CURRENT was returned");
  assert.equal(custodian.retainedMinimum().lease_serial, 0,
    "both disposable SQLite floors remain at signed genesis");
});

test("P2 nested bootstrap toJSON cannot poison subsequent forged owner genesis", (t) => {
  const x = setup(t, "genesis-nested-tojson-second-attempt");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const { signature: _discard, ...unsigned } = x.genesis;
  const forged = sign(unsigned, foreign.privateKey, DOMAIN_GENESIS);
  const nativeVerify = crypto.verify;
  assert.equal(nativeVerify(null, signatureBytes(DOMAIN_GENESIS, unsigned),
    x.owner.publicKey, Buffer.from(forged.signature, "base64url")), false);
  let toJsonCalls = 0;
  const poisoned = { ...x.genesis, head_digest: { toJSON() {
    toJsonCalls++;
    crypto.verify = () => true;
    return unsigned.head_digest;
  } } };
  try {
    assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
      ...x.config, bootstrap: poisoned,
    }), /ZK10_CUSTODIAN_UNAVAILABLE/);
    assert.throws(() => x.track(createDevOffZk10MonotonicFloorCustodian({
      ...x.config, bootstrap: forged,
    })), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "a poisoned crypto singleton cannot enroll an unowned Ed25519 genesis");
  } finally { crypto.verify = nativeVerify; }
  assert.equal(toJsonCalls, 0, "no nested bootstrap serialization hook executed");
  assert.equal(fs.existsSync(x.paths.databasePath), false);
  assert.equal(fs.existsSync(x.paths.anchorDatabasePath), false);
});

test("P2 fake-handle own DATA native kHandle cannot mutate verifier through JS export", (t) => {
  const x = setup(t, "fake-own-data-handle-verify-hook");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const { signature: _discard, ...unsigned } = x.genesis;
  const forged = sign(unsigned, foreign.privateKey, DOMAIN_GENESIS);
  const nativeVerify = crypto.verify;
  assert.equal(nativeVerify(null, signatureBytes(DOMAIN_GENESIS, unsigned),
    x.owner.publicKey, Buffer.from(forged.signature, "base64url")), false);
  const actual = x.owner.publicKey;
  const fake = Object.create(Object.getPrototypeOf(actual));
  const symbols = Object.getOwnPropertySymbols(actual);
  const handleSymbol = symbols.find((sym) => sym.description === "kHandle");
  const typeSymbol = symbols.find((sym) => sym.description === "kKeyType");
  assert.ok(handleSymbol && typeSymbol);
  let hostileExports = 0;
  Object.defineProperty(fake, typeSymbol, { value: "public" });
  Object.defineProperty(fake, handleSymbol, { value: {
    getAsymmetricKeyType() { return "ed25519"; },
    export() {
      hostileExports++;
      crypto.verify = () => true;
      return actual.export({ format: "der", type: "spki" });
    },
  } });
  try {
    assert.throws(() => x.track(createDevOffZk10MonotonicFloorCustodian({
      ...x.config, ownerPublicKey: fake, bootstrap: forged,
    })), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "brand spoof must not forge actual signed owner genesis");
  } finally { crypto.verify = nativeVerify; }
  assert.equal(hostileExports, 0, "fake JS handle export must not execute");
  assert.equal(fs.existsSync(x.paths.databasePath), false);
  assert.equal(fs.existsSync(x.paths.anchorDatabasePath), false);
});

test("P2 fake-keytype own accessor cannot poison verifier with genuine raw handle", (t) => {
  const x = setup(t, "fake-keytype-accessor");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const { signature: _discard, ...unsigned } = x.genesis;
  const forgedGenesis = sign(unsigned, foreign.privateKey, DOMAIN_GENESIS);
  const savedVerify = crypto.verify;
  assert.equal(savedVerify(null, signatureBytes(DOMAIN_GENESIS, unsigned),
    x.owner.publicKey, Buffer.from(forgedGenesis.signature, "base64url")), false);
  const actual = x.owner.publicKey;
  const symbols = Object.getOwnPropertySymbols(actual);
  const handleSym = symbols.find((sym) => sym.description === "kHandle");
  const typeSym = symbols.find((sym) => sym.description === "kKeyType");
  assert.ok(handleSym && typeSym);
  const fake = Object.create(Object.getPrototypeOf(actual));
  Object.defineProperty(fake, handleSym, { value: actual[handleSym] });
  let typeGetterCalls = 0;
  Object.defineProperty(fake, typeSym, { get() {
    typeGetterCalls++;
    crypto.verify = () => true;
    return "public";
  } });
  try {
    assert.throws(() => x.track(createDevOffZk10MonotonicFloorCustodian({
      ...x.config, ownerPublicKey: fake, bootstrap: forgedGenesis,
    })), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "caller-controlled type getter may not authorize foreign Ed25519 genesis");
  } finally { crypto.verify = savedVerify; }
  assert.equal(typeGetterCalls, 0, "no caller-owned KeyObject type getter executed");
  assert.equal(fs.existsSync(x.paths.databasePath), false);
  assert.equal(fs.existsSync(x.paths.anchorDatabasePath), false);
});

test("P2: native Ed25519 identity survives caller-shadowed KeyObject type metadata", (t) => {
  const x = setup(t, "shadowed-owner-type");
  Object.defineProperties(x.owner.publicKey, {
    type: { value: "private" }, asymmetricKeyType: { value: "rsa" },
  });
  const custodian = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  assert.equal(custodian.independentOffServerCustodyProven, false);
  assert.equal(custodian.retainedMinimum().lease_serial, 0);
});

test("two independent disposable custodians sign W170 exact floor bytes with distinct keys", (t) => {
  const a = setup(t, "first");
  const b = setup(t, "second");
  const ca = a.track(createDevOffZk10MonotonicFloorCustodian(a.config));
  const cb = b.track(createDevOffZk10MonotonicFloorCustodian(b.config));
  const { request, ownerLease } = a.offer();
  const result = ca.attest(request, ownerLease);
  assert.deepEqual(Object.keys(result), ["floor"]);
  const { signature, ...payload } = result.floor;
  assert.deepEqual(Object.keys(payload), [
    "type", "sequence", "head_digest", "enrollment_root", "immutable_account_id",
    "identity_digest", "operation", "nonce", "lease_id", "lease_expires_at_ms",
    "issued_at_ms", "expires_at_ms"]);
  assert.ok(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, payload),
    a.custodian.publicKey, Buffer.from(signature, "base64url")));
  assert.equal(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, payload),
    b.custodian.publicKey, Buffer.from(signature, "base64url")), false);
  const different = b.offer();
  const otherResult = cb.attest(different.request, different.ownerLease).floor;
  const { signature: otherSignature, ...otherPayload } = otherResult;
  assert.ok(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, otherPayload),
    b.custodian.publicKey, Buffer.from(otherSignature, "base64url")));
  assert.equal(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, otherPayload),
    a.custodian.publicKey, Buffer.from(otherSignature, "base64url")), false);
  assert.equal(ca.independentOffServerCustodyProven, false);
});

test("owner grants monotonic sequence/lease serial; stale/replayed/mismatched/forged heads fail closed", (t) => {
  const x = setup(t);
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const first = x.offer();
  assert.ok(c.attest(first.request, first.ownerLease).floor.signature);
  for (const [request, ownerLease] of [
    [first.request, first.ownerLease],
    (() => { const a = x.offer({ lease_serial: 1 }); return [a.request, a.ownerLease]; })(),
    (() => { const a = x.offer({ sequence: 0 }); return [a.request, a.ownerLease]; })(),
    (() => { const a = x.offer({ head_digest: sha(9) }); return [a.request, a.ownerLease]; })(),
    (() => { const a = x.offer(); return [{ ...a.request, nonce: b64(crypto.randomBytes(32)) }, a.ownerLease]; })(),
    (() => { const a = x.offer({ lease_expires_at_ms: Date.now() - 1 }); return [a.request, a.ownerLease]; })(),
    (() => { const a = x.offer(); return [a.request, { ...a.ownerLease, signature: b64(Buffer.alloc(64)) }]; })(),
  ]) {
    assert.throws(() => c.attest(request, ownerLease), /ZK10_CUSTODIAN_UNAVAILABLE/);
  }
  assert.equal(c.retainedMinimum().lease_serial, 1);
  const advance = x.offer({ sequence: 2, head_digest: sha(5), enrollment_root: sha(6),
    lease_serial: 2 });
  assert.equal(c.attest(advance.request, advance.ownerLease).floor.sequence, 2);
  assert.equal(c.retainedMinimum().head_digest, sha(5));
  const reuseNonce = x.offer({ sequence: 2, head_digest: sha(5),
    enrollment_root: sha(6), lease_serial: 3, nonce: first.request.nonce });
  assert.throws(() => c.attest(reuseNonce.request, reuseNonce.ownerLease),
    /ZK10_CUSTODIAN_UNAVAILABLE/);
  const reuseLease = x.offer({ sequence: 2, head_digest: sha(5),
    enrollment_root: sha(6), lease_serial: 3, lease_id: first.request.lease_id });
  assert.throws(() => c.attest(reuseLease.request, reuseLease.ownerLease),
    /ZK10_CUSTODIAN_UNAVAILABLE/);
  assert.equal(c.retainedMinimum().lease_serial, 2,
    "used challenge must be rejected before high-water writes");
});

test("concurrent same lease signs once; high-water survives restart and catches rolled-back primary SQLite", (t) => {
  const x = setup(t);
  let c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const first = x.offer();
  const results = [() => c.attest(first.request, first.ownerLease),
    () => c.attest(first.request, first.ownerLease)].map(fn => {
    try { return { value: fn() }; } catch (e) { return { error: e.code }; }
  });
  assert.equal(results.filter(r => r.value).length, 1);
  assert.equal(results.filter(r => r.error === "ZK10_CUSTODIAN_UNAVAILABLE").length, 1);
  const backup = path.join(x.root, "earlier-primary.sqlite");
  fs.copyFileSync(x.paths.databasePath, backup);
  const second = x.offer({ sequence: 2, head_digest: sha(8), enrollment_root: sha(9) });
  assert.equal(c.attest(second.request, second.ownerLease).floor.sequence, 2);
  assert.equal(c.retainedMinimum().lease_serial, 2);
  c.close();
  c = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(c.retainedMinimum().lease_serial, 2);
  c.close();
  fs.copyFileSync(backup, x.paths.databasePath);
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2: retained minimum never reports an obsolete signed head after a second writer commits", (t) => {
  const x = setup(t, "cross-writer-retained");
  const observer = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const writer = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
  }));
  assert.equal(observer.retainedMinimum().lease_serial, 0);
  const newer = x.offer({
    sequence: 2, head_digest: sha(15), enrollment_root: sha(16),
  });
  const issued = writer.attest(newer.request, newer.ownerLease).floor;
  assert.equal(issued.sequence, 2);
  assert.ok(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, Object.fromEntries(
    Object.entries(issued).filter(([field]) => field !== "signature"))),
  x.custodian.publicKey, Buffer.from(issued.signature, "base64url")));
  assert.equal(writer.retainedMinimum().lease_serial, 1);
  // An old in-memory snapshot cannot be offered as a CURRENT retained floor
  // after another legitimate, owner-authorized writer advanced both journals.
  // In particular the obsolete sequence=1 is potentially pre-revocation.
  assert.throws(() => observer.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
  assert.throws(() => observer.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "once divergence is observed the old handle stays unavailable");
  observer.close();
  const refreshed = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
  }));
  assert.equal(refreshed.retainedMinimum().lease_serial, 1);
  assert.equal(refreshed.retainedMinimum().head_digest, sha(15));
});

test("P2: retainedMinimum serializes both floor reads against a real anchor writer", (t) => {
  const x = setup(t, "retained-anchor-interleave");
  const observer = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const outside = new Database(x.paths.anchorDatabasePath, { timeout: 1 });
  const originalPrepare = Database.prototype.prepare;
  let attempted = false, committed = false, blocked = false;
  Database.prototype.prepare = function (sql, ...args) {
    if (!attempted && this.name === x.paths.databasePath
      && sql === "SELECT * FROM floor WHERE singleton = 1") {
      // The observer already read old anchor. The second real SQLite handle
      // attempts to change that same inode before observer reads primary.
      attempted = true;
      try {
        outside.prepare("UPDATE floor SET head_digest = ? WHERE singleton = 1")
          .run(sha(47));
        committed = true;
      } catch (error) {
        assert.match(error.message, /busy|locked/i);
        blocked = true;
      }
    }
    return originalPrepare.call(this, sql, ...args);
  };
  let result;
  try {
    result = observer.retainedMinimum();
  } finally {
    Database.prototype.prepare = originalPrepare;
  }
  assert.equal(attempted, true, "second writer attempted its real SQLite update at read boundary");
  assert.equal(blocked, true, "held anchor reservation must deny the concurrent update");
  assert.equal(committed, false, "anchor must not be changed between the two reads");
  assert.equal(result.head_digest, sha(1), "floor was valid while both reservations were held");
  assert.equal(observer.retainedMinimum().head_digest, sha(1));
  // This later write is deliberately AFTER the retainedMinimum linearization
  // point: returning a verified snapshot does not promise a state at return.
  try {
    outside.prepare("UPDATE floor SET head_digest = ? WHERE singleton = 1")
      .run(sha(47));
  } finally { outside.close(); }
  assert.throws(() => observer.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "a later call must detect the new floor and poison the old handle");
  observer.close();
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
  }), /ZK10_CUSTODIAN_UNAVAILABLE/, "restart must reject mismatched stores");
});

test("P2: retainedMinimum releases anchor after bounded primary lock failure", (t) => {
  const x = setup(t, "retained-primary-busy");
  const observer = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const outsideMain = new Database(x.paths.databasePath, { timeout: 1 });
  const originalExec = Database.prototype.exec;
  let primaryContested = false;
  Database.prototype.exec = function (sql, ...args) {
    if (!primaryContested && this.name === x.paths.databasePath && sql === "BEGIN IMMEDIATE") {
      primaryContested = true;
      originalExec.call(outsideMain, "BEGIN IMMEDIATE");
    }
    return originalExec.call(this, sql, ...args);
  };
  try {
    assert.throws(() => observer.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally { Database.prototype.exec = originalExec; }
  assert.equal(primaryContested, true);
  const outsideAnchor = new Database(x.paths.anchorDatabasePath, { timeout: 1 });
  try {
    assert.doesNotThrow(() => outsideAnchor.exec("BEGIN IMMEDIATE"),
      "failed acquisition of primary must release the earlier anchor reservation");
  } finally {
    if (outsideAnchor.inTransaction) outsideAnchor.exec("ROLLBACK");
    outsideAnchor.close();
    if (outsideMain.inTransaction) outsideMain.exec("ROLLBACK");
    outsideMain.close();
  }
  assert.throws(() => observer.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "ambiguous read remains unavailable after contention");
  observer.close();
  const fresh = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(fresh.retainedMinimum().lease_serial, 0);
});

test("two genuinely parallel worker-thread SQLite handles cannot both attest the same signed lease", async (t) => {
  const x = setup(t);
  const first = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  first.close();
  const offer = x.offer();
  const workerPath = path.join(__dirname, "support/issue-65-zk10-floor-custodian-worker.js");
  const race = () => new Promise((resolve, reject) => {
    let answer;
    const worker = new Worker(workerPath, { workerData: {
      config: { ...x.config, bootstrap: undefined },
      request: offer.request, ownerLease: offer.ownerLease,
    } });
    worker.once("message", message => { answer = message; });
    worker.once("error", reject);
    worker.once("exit", code => {
      if (code !== 0 || !answer) reject(new Error("disposable worker did not finish"));
      else resolve(answer);
    });
  });
  const results = await Promise.all([race(), race()]);
  assert.equal(results.filter(item => item.signed).length, 1);
  assert.equal(results.filter(item => !item.signed).length, 1);
  const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(restarted.retainedMinimum().lease_serial, 1);
});

test("erased independent anchor, mismatched key or incomplete bootstrap fails closed on restart", (t) => {
  const x = setup(t);
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const first = x.offer();
  c.attest(first.request, first.ownerLease);
  c.close();
  const alternate = crypto.generateKeyPairSync("ed25519");
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
    custodianPrivateKey: alternate.privateKey,
    custodianSpkiSha256: keyHash(alternate.publicKey) }), /ZK10_CUSTODIAN_UNAVAILABLE/);
  fs.renameSync(x.paths.anchorDatabasePath, path.join(x.root, "missing-anchor.fixture"));
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian(x.config),
    /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2 regression: deleting consumed nonce journal in primary alone fails closed on restart", (t) => {
  const x = setup(t, "deleted-primary-journal");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const initial = x.offer();
  c.attest(initial.request, initial.ownerLease);
  c.close();
  const db = new Database(x.paths.databasePath);
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS total FROM used_lease").get().total, 1);
    db.prepare("DELETE FROM used_lease").run();
  } finally { db.close(); }
  // Independent minimum retains the authentic high-water row. Omitting a
  // single consumed nonce must be detected before the next lease is signed.
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2 regression: modified/reordered journal bytes fail closed with intact anchored count", (t) => {
  const x = setup(t, "edited-primary-journal");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const first = x.offer();
  c.attest(first.request, first.ownerLease);
  const second = x.offer();
  c.attest(second.request, second.ownerLease);
  c.close();
  const db = new Database(x.paths.databasePath);
  try {
    const rows = db.prepare("SELECT nonce, lease_id, lease_serial FROM used_lease ORDER BY lease_serial").all();
    assert.equal(rows.length, 2);
    // Mutating one consumed nonce while preserving the serial/count cannot
    // impersonate a valid historical chain or defeat the anchor commitment.
    db.prepare("UPDATE used_lease SET nonce = ? WHERE lease_serial = 1")
      .run(b64(crypto.randomBytes(32)));
  } finally { db.close(); }
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2 regression: swapping serial order of two consumed leases cannot match original chain tip", (t) => {
  const x = setup(t, "reordered-primary-journal");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  for (let i = 0; i < 2; i += 1) {
    const offer = x.offer();
    c.attest(offer.request, offer.ownerLease);
  }
  c.close();
  const db = new Database(x.paths.databasePath);
  try {
    db.transaction(() => {
      db.prepare("UPDATE used_lease SET lease_serial = 3 WHERE lease_serial = 1").run();
      db.prepare("UPDATE used_lease SET lease_serial = 1 WHERE lease_serial = 2").run();
      db.prepare("UPDATE used_lease SET lease_serial = 2 WHERE lease_serial = 3").run();
    }).immediate();
    assert.deepEqual(db.prepare("SELECT lease_serial FROM used_lease ORDER BY lease_serial").all()
      .map(row => row.lease_serial), [1, 2]);
  } finally { db.close(); }
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2 regression: two actual OS processes cannot both commit the same signed journal serial", async (t) => {
  const x = setup(t, "os-process-race");
  x.track(createDevOffZk10MonotonicFloorCustodian(x.config)).close();
  const signed = x.offer();
  const childPath = path.join(__dirname, "support/issue-65-zk10-floor-custodian-worker.js");
  function processRace() {
    const child = fork(childPath, [], {
      cwd: path.join(__dirname, ".."),
      env: { ...process.env, ROOTARK_ZK10_CUSTODIAN_PROCESS_FIXTURE: "1" },
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    t.after(() => { if (child.connected) child.kill(); });
    let readyResolve, readyReject, finishResolve, finishReject;
    let readySettled = false, finishSettled = false;
    const ready = new Promise((resolve, reject) => {
      readyResolve = resolve;
      readyReject = reject;
    });
    const finished = new Promise((resolve, reject) => {
      finishResolve = resolve;
      finishReject = reject;
    });
    child.on("message", (message) => {
      if (typeof message.ready === "boolean" && !readySettled) {
        readySettled = true;
        if (message.ready) readyResolve();
        else readyReject(new Error("disposable process refused to start"));
      }
      if (typeof message.signed === "boolean" && !finishSettled) {
        finishSettled = true;
        finishResolve(message.signed);
      }
    });
    child.once("error", (error) => {
      if (!readySettled) { readySettled = true; readyReject(error); }
      if (!finishSettled) { finishSettled = true; finishReject(error); }
    });
    child.once("exit", () => {
      if (!readySettled) { readySettled = true; readyReject(new Error("process exited before ready")); }
      if (!finishSettled) { finishSettled = true; finishReject(new Error("process exited before result")); }
    });
    child.send({
      kind: "init",
      config: { ...x.config, ownerPublicKey: undefined,
        custodianPrivateKey: undefined, bootstrap: undefined },
      ownerSpki: b64(x.owner.publicKey.export({ type: "spki", format: "der" })),
      custodianPkcs8: b64(x.custodian.privateKey.export({ type: "pkcs8", format: "der" })),
      request: signed.request, ownerLease: signed.ownerLease,
    });
    return { ready, finished, start: () => child.send({ kind: "sign" }) };
  }
  // Open the two independent SQLite handles before releasing the race gate.
  const first = processRace();
  await first.ready;
  const second = processRace();
  await second.ready;
  first.start();
  second.start();
  const results = await Promise.all([first.finished, second.finished]);
  assert.deepEqual(results.sort(), [false, true]);
  const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(restarted.retainedMinimum().journal_count, 1);
  assert.equal(restarted.retainedMinimum().lease_serial, 1);
});

test("P2 regression: dangling direct symlinks never redirect either SQLite store", (t) => {
  const x = setup(t, "dangling-link");
  const redirect = path.join(x.root, "outside-expected-anchor.sqlite");
  const anchor = x.paths.anchorDatabasePath;
  try {
    fs.symlinkSync(redirect, anchor, "file");
  } catch (error) {
    if (process.platform === "win32" && ["EPERM", "EACCES"].includes(error.code)) {
      t.skip("Windows symlink privileges unavailable; POSIX/WSL test is mandatory");
      return;
    }
    throw error;
  }
  assert.equal(fs.existsSync(anchor), false, "dangling link is invisible to existsSync");
  assert.ok(fs.lstatSync(anchor).isSymbolicLink());
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian(x.config),
    /ZK10_CUSTODIAN_UNAVAILABLE/);
  assert.equal(fs.existsSync(redirect), false, "SQLite must not follow the hostile link");
  assert.equal(fs.existsSync(x.paths.databasePath), false,
    "failure must happen before any DB is created");
});

test("P2 regression: an existing parent symlink is refused without creating database", (t) => {
  const x = setup(t, "symlink-parent");
  const realDir = path.join(x.root, "real");
  fs.mkdirSync(realDir);
  const linkDir = path.join(x.root, "alias");
  try {
    fs.symlinkSync(realDir, linkDir, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (process.platform === "win32" && ["EPERM", "EACCES"].includes(error.code)) {
      t.skip("Windows junction privileges unavailable; POSIX/WSL test is mandatory");
      return;
    }
    throw error;
  }
  const aliasDb = path.join(linkDir, "hidden.sqlite");
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, anchorDatabasePath: aliasDb }), /ZK10_CUSTODIAN_UNAVAILABLE/);
  assert.equal(fs.existsSync(path.join(realDir, "hidden.sqlite")), false);
  assert.equal(fs.existsSync(x.paths.databasePath), false);
});

for (const store of ["databasePath", "anchorDatabasePath"]) {
  test(`P1: ${store} swapped for another inode during signed lease verification never attests`, (t) => {
    if (process.platform === "win32") return t.skip("POSIX rename of open SQLite inode required");
    const x = setup(t, `swapped-${store}`);
    // First enroll genuine disposable SQLite genesis, before importing the
    // separate module whose native VERIFY captures this hostile timing shim.
    const seeded = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
    seeded.close();
    let c;
    const challenge = x.offer();
    const original = x.paths[store];
    const oldInode = path.join(x.root, `orphan-${store}.sqlite`);
    const substituted = path.join(x.root, `foreign-${store}.sqlite`);
    fs.copyFileSync(original, substituted);
    const verify = crypto.verify;
    const transaction = Database.prototype.transaction;
    let swapped = false;
    let attemptedWrites = 0;
    Database.prototype.transaction = function (...args) {
      attemptedWrites += 1;
      return transaction.apply(this, args);
    };
    crypto.verify = (...args) => {
      const valid = verify(...args);
      if (valid && !swapped && isOwnerLeaseVerify(args[1])) {
        swapped = true;
        fs.renameSync(original, oldInode);
        fs.renameSync(substituted, original);
      }
      return valid;
    };
    try {
      c = x.track(testFactoryCapturingCurrentCrypto()({
        ...x.config, bootstrap: undefined }));
      assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
        /ZK10_CUSTODIAN_UNAVAILABLE/);
    } finally {
      crypto.verify = verify;
      Database.prototype.transaction = transaction;
    }
    assert.equal(swapped, true, "real replacement occurs after owner lease verification");
    assert.equal(attemptedWrites, 0, "identity mismatch must deny before any SQLite write transaction");
    assert.notEqual(fs.statSync(original).ino, fs.statSync(oldInode).ino);
    assert.equal(c.independentOffServerCustodyProven, false);
    assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
      "a detected path replacement permanently invalidates this handle");
    const actual = new Database(oldInode, { readonly: true, fileMustExist: true });
    try { assert.equal(actual.prepare("SELECT lease_serial FROM floor").get().lease_serial, 0); }
    finally { actual.close(); }
  });
}

test("P1 POSIX: symlinked primary during lease verification is rejected before signing", (t) => {
  if (process.platform === "win32") return t.skip("POSIX symlink after opened SQLite handle required");
  const x = setup(t, "lease-symlink");
  let c;
  const challenge = x.offer();
  const previous = path.join(x.root, "orphan-primary.sqlite");
  const original = x.paths.databasePath;
  const verify = crypto.verify;
  let swapped = false;
  crypto.verify = (...args) => {
    const valid = verify(...args);
    if (valid && !swapped && isOwnerLeaseVerify(args[1])) {
      swapped = true;
      fs.renameSync(original, previous);
      fs.symlinkSync(x.paths.anchorDatabasePath, original);
    }
    return valid;
  };
  try {
    c = x.track(testFactoryCapturingCurrentCrypto()(x.config));
    assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally { crypto.verify = verify; }
  assert.equal(swapped, true);
  assert.equal(fs.lstatSync(original).isSymbolicLink(), true);
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P1 POSIX: anchor switched inside signer callback cannot return a signed attestation", (t) => {
  if (process.platform === "win32") return t.skip("POSIX rename of opened SQLite required");
  const x = setup(t, "sign-time-anchor-swap");
  let c;
  const challenge = x.offer();
  const original = x.paths.anchorDatabasePath;
  const previous = path.join(x.root, "orphan-anchor.sqlite");
  const signFloor = crypto.sign;
  let swapped = false;
  crypto.sign = (...args) => {
    const signature = signFloor(...args);
    if (!swapped) {
      swapped = true;
      fs.renameSync(original, previous);
      fs.symlinkSync(x.paths.databasePath, original);
    }
    return signature;
  };
  try {
    c = x.track(testFactoryCapturingCurrentCrypto()(x.config));
    assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally { crypto.sign = signFloor; }
  assert.equal(swapped, true);
  assert.equal(fs.lstatSync(original).isSymbolicLink(), true);
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "ambiguous post-write commit must poison instance");
});

for (const target of ["anchor floor", "primary used-lease journal"]) {
  test(`P2: same-inode ${target} write during signer is blocked by held SQLite reservations`, (t) => {
    const x = setup(t, `signer-inplace-${target.replaceAll(" ", "-")}`);
    const seeded = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
    const ownerSigned = x.offer({
      sequence: 2, head_digest: sha(22), enrollment_root: sha(23),
    });
    const ownerSignature = ownerSigned.ownerLease.signature;
    assert.ok(crypto.verify(null, signatureBytes(DOMAIN_LEASE,
      Object.fromEntries(Object.entries(ownerSigned.ownerLease)
        .filter(([field]) => field !== "signature"))),
    x.owner.publicKey, Buffer.from(ownerSignature, "base64url")));
    const targetFile = target === "anchor floor"
      ? x.paths.anchorDatabasePath : x.paths.databasePath;
    const fileBefore = fs.statSync(targetFile, { bigint: true });
    const sign = crypto.sign;
    let attempted = false, blocked = false, committed = false;
    let c;
    crypto.sign = (algorithm, data, key, ...rest) => {
      const signature = sign(algorithm, data, key, ...rest);
      // Only the pinned CUSTODIAN's W170 signature triggers this synchronous
      // adversarial callback; never intercept owner bootstrap/lease signatures.
      if (isActualCustodianFloorCall(data, key, x.custodian.publicKey, signature)) {
        assert.equal(attempted, false);
        attempted = true;
        const outside = new Database(targetFile, { timeout: 1 });
        try {
          try {
            if (target === "anchor floor") {
              outside.prepare("UPDATE floor SET head_digest = ? WHERE singleton = 1")
                .run(sha(24));
            } else {
              outside.prepare("UPDATE used_lease SET nonce = ? WHERE lease_serial = 1")
                .run(b64(crypto.randomBytes(32)));
            }
            committed = true;
          } catch (error) {
            assert.match(error.message, /locked|busy/i);
            blocked = true;
          }
        } finally { outside.close(); }
      }
      return signature;
    };
    let result;
    try {
      seeded.close();
      c = x.track(testFactoryCapturingCurrentCrypto()({
        ...x.config, bootstrap: undefined }));
      result = c.attest(ownerSigned.request, ownerSigned.ownerLease);
    } finally { crypto.sign = sign; }
    assert.equal(attempted, true, "second connection attempted a real write inside signing");
    assert.equal(blocked, true, "the outside writer must encounter SQLite's exclusive reservation");
    assert.equal(committed, false, "outside writer cannot change the signed head or journal");
    assert.equal(result.floor.head_digest, sha(22));
    const fileAfter = fs.statSync(targetFile, { bigint: true });
    assert.equal(fileAfter.ino, fileBefore.ino, "the SQLite inode was not replaced");
    assert.equal(fileAfter.size, fileBefore.size, "file size stayed unchanged");
    assert.equal(c.retainedMinimum().lease_serial, 1);
    c.close();
    const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
      ...x.config, bootstrap: undefined }));
    assert.equal(restarted.retainedMinimum().lease_serial, 1,
      "a blocked writer leaves the committed floor and used journal intact");
  });
}

test("P2: a real second SQLite writer cannot slip between post-sign anchor and primary reads", (t) => {
  const x = setup(t, "postsign-cross-store-race");
  const seeded = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  let c;
  const lease = x.offer({ sequence: 2, head_digest: sha(52), enrollment_root: sha(53) });
  const outsider = new Database(x.paths.anchorDatabasePath, { timeout: 1 });
  const mutate = outsider.prepare("UPDATE floor SET head_digest = ? WHERE singleton = 1");
  const originalPrepare = Database.prototype.prepare;
  const originalSign = crypto.sign;
  let signed = false, intercepted = false, committed = false, blocked = false;
  crypto.sign = (...args) => {
    const signature = originalSign(...args);
    if (isActualCustodianFloorCall(args[1], args[2], x.custodian.publicKey, signature))
      signed = true;
    return signature;
  };
  Database.prototype.prepare = function (sql, ...args) {
    if (signed && !intercepted && this.name === x.paths.databasePath
      && sql === "SELECT * FROM floor WHERE singleton = 1") {
      intercepted = true;
      try { mutate.run(sha(54)); committed = true; }
      catch (error) {
        assert.match(error.message, /locked|busy/i);
        blocked = true;
      }
    }
    return originalPrepare.call(this, sql, ...args);
  };
  let result;
  try {
    seeded.close();
    c = x.track(testFactoryCapturingCurrentCrypto()({
      ...x.config, bootstrap: undefined }));
    result = c.attest(lease.request, lease.ownerLease);
  }
  finally {
    Database.prototype.prepare = originalPrepare;
    crypto.sign = originalSign;
    outsider.close();
  }
  assert.equal(signed, true, "pinned custodian signed the canonical floor");
  assert.equal(intercepted, true, "outside writer attempted commit after anchor read");
  assert.equal(committed, false, "second writer must not commit between floor reads");
  assert.equal(blocked, true, "a real SQLite writer receives SQLITE_BUSY during held locks");
  assert.equal(result.floor.head_digest, sha(52));
  assert.equal(c.retainedMinimum().head_digest, sha(52));
});

test("P2: failed signer releases both SQLite reservations and poisons the lease handle", (t) => {
  const x = setup(t, "signer-rollback-locks");
  let c;
  const offer = x.offer({ sequence: 2, head_digest: sha(62), enrollment_root: sha(63) });
  const originalSign = crypto.sign;
  let failedInsideSign = false;
  crypto.sign = (...args) => {
    if (isActualCustodianFloorCall(args[1], args[2], x.custodian.publicKey)) {
      failedInsideSign = true;
      throw new Error("injected signer failure");
    }
    return originalSign(...args);
  };
  try {
    c = x.track(testFactoryCapturingCurrentCrypto()(x.config));
    assert.throws(() => c.attest(offer.request, offer.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally { crypto.sign = originalSign; }
  assert.equal(failedInsideSign, true);
  const anchorWriter = new Database(x.paths.anchorDatabasePath, { timeout: 1 });
  const mainWriter = new Database(x.paths.databasePath, { timeout: 1 });
  try {
    assert.doesNotThrow(() => anchorWriter.exec("BEGIN IMMEDIATE"));
    assert.doesNotThrow(() => mainWriter.exec("BEGIN IMMEDIATE"));
  } finally {
    if (mainWriter.inTransaction) mainWriter.exec("ROLLBACK");
    if (anchorWriter.inTransaction) anchorWriter.exec("ROLLBACK");
    mainWriter.close();
    anchorWriter.close();
  }
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
  c.close();
  const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(restarted.retainedMinimum().lease_serial, 1,
    "failed signing cannot undo the already durably committed floor");
});

test("P2: bounded primary lock contention releases the anchor reservation and denies issuance", (t) => {
  const x = setup(t, "primary-lock-contention");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const lease = x.offer({ sequence: 2, head_digest: sha(64), enrollment_root: sha(65) });
  const blocker = new Database(x.paths.databasePath, { timeout: 1 });
  const originalExec = Database.prototype.exec;
  let blockedSign = false;
  Database.prototype.exec = function (sql, ...args) {
    if (!blockedSign && this.name === x.paths.databasePath && sql === "BEGIN IMMEDIATE") {
      blockedSign = true;
      // The anchor reservation is already held; a second real SQLite handle
      // acquires primary first, so the custodian's bounded BEGIN must fail.
      originalExec.call(blocker, "BEGIN IMMEDIATE");
    }
    return originalExec.call(this, sql, ...args);
  };
  try {
    assert.throws(() => c.attest(lease.request, lease.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally { Database.prototype.exec = originalExec; }
  assert.equal(blockedSign, true, "the primary lock acquisition was contested");
  const secondAnchor = new Database(x.paths.anchorDatabasePath, { timeout: 1 });
  try {
    assert.doesNotThrow(() => secondAnchor.exec("BEGIN IMMEDIATE"),
      "anchor write reservation was released despite the busy primary");
  } finally {
    if (secondAnchor.inTransaction) secondAnchor.exec("ROLLBACK");
    secondAnchor.close();
    if (blocker.inTransaction) blocker.exec("ROLLBACK");
    blocker.close();
  }
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
  c.close();
  const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(restarted.retainedMinimum().lease_serial, 1);
});

test("P1 Windows: simulated reparse during signed lease is rejected without another database open", (t) => {
  if (process.platform !== "win32") return t.skip("Windows path-validation regression");
  const x = setup(t, "win-reparse-late");
  let c;
  const challenge = x.offer();
  const lstat = fs.lstatSync;
  const open = fs.openSync;
  const verify = crypto.verify;
  let redirected = false;
  let openCalls = 0;
  fs.openSync = (...args) => {
    if (args[0] === x.paths.databasePath || args[0] === x.paths.anchorDatabasePath) openCalls += 1;
    return open(...args);
  };
  fs.lstatSync = (file, ...args) => {
    const stat = lstat(file, ...args);
    if (redirected && file === x.paths.anchorDatabasePath) {
      return new Proxy(stat, { get(target, field) {
        if (field === "isSymbolicLink") return () => true;
        const value = Reflect.get(target, field, target);
        return typeof value === "function" ? value.bind(target) : value;
      } });
    }
    return stat;
  };
  crypto.verify = (...args) => {
    const valid = verify(...args);
    if (valid && isOwnerLeaseVerify(args[1])) redirected = true;
    return valid;
  };
  try {
    c = x.track(testFactoryCapturingCurrentCrypto()(x.config));
    openCalls = 0; // Only count openings AFTER the signed lease was received.
    assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally {
    crypto.verify = verify;
    fs.lstatSync = lstat;
    fs.openSync = open;
  }
  assert.equal(redirected, true);
  assert.equal(openCalls, 0, "late reparse must be rejected without opening another path");
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "observed fake reparse must permanently poison the affected pin");
});

test("P1: both SQLite identity descriptors remain pinned until close without leaking", (t) => {
  const x = setup(t, "live-fd-pins");
  const originalOpen = fs.openSync;
  const pins = new Map();
  fs.openSync = (...args) => {
    const fd = originalOpen(...args);
    if ([x.paths.databasePath, x.paths.anchorDatabasePath].includes(args[0])) pins.set(args[0], fd);
    return fd;
  };
  let c;
  try { c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config)); }
  finally { fs.openSync = originalOpen; }
  assert.equal(pins.size, 2);
  for (const fd of pins.values()) assert.ok(fs.fstatSync(fd).isFile(), "pin stays open after bootstrap");
  const first = x.offer();
  assert.ok(c.attest(first.request, first.ownerLease).floor.signature);
  for (const fd of pins.values()) assert.ok(fs.fstatSync(fd).isFile(), "pin survives signed transaction");
  c.close();
  for (const fd of pins.values()) assert.throws(() => fs.fstatSync(fd), { code: "EBADF" });
  c.close();
});

test("P2: an owner-authorized floor expiring during signing must never be returned", (t) => {
  const x = setup(t, "signing-expiry");
  let c;
  const originalSign = crypto.sign;
  let custodianSignCalls = 0;
  crypto.sign = (...args) => {
    const signed = originalSign(...args); // Real Ed25519; only the response is delayed.
    if (isActualCustodianFloorCall(args[1], args[2], x.custodian.publicKey, signed)) {
      custodianSignCalls += 1;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2500);
    }
    return signed;
  };
  try {
    c = x.track(testFactoryCapturingCurrentCrypto()(x.config));
    const challenge = x.offer({ lease_expires_at_ms: Date.now() + 2200 });
    assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/,
      "no signed response may escape once the owner lease expires inside crypto.sign");
    assert.ok(Date.now() >= challenge.request.lease_expires_at_ms,
      "the lease actually expired before the instrumented genuine signing returned");
  } finally { crypto.sign = originalSign; }
  assert.equal(custodianSignCalls, 1, "real custodian signature was computed");
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "already-committed nonce is not silently retried after a failed signature");
  for (const file of [x.paths.databasePath, x.paths.anchorDatabasePath]) {
    const db = new Database(file, { readonly: true, fileMustExist: true });
    try {
      assert.equal(db.prepare("SELECT lease_serial FROM floor WHERE singleton = 1").get().lease_serial, 1);
    } finally { db.close(); }
  }
  c.close();
  const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
  }));
  const next = x.offer();
  assert.equal(restarted.attest(next.request, next.ownerLease).floor.sequence, 1);
  assert.equal(restarted.retainedMinimum().lease_serial, 2,
    "a fresh owner-signed lease resumes at the next durable journal serial");
});

test("P2: partial wall-clock rollback during signing cannot hide an elapsed owner lease", (t) => {
  const x = setup(t, "signing-partial-clock-rollback");
  const modulePath = require.resolve("../src/services/zk10DevOffMonotonicFloorCustodian");
  const cached = require.cache[modulePath];
  const genuineNow = Date.now;
  let startedAt = genuineNow();
  let wallNow = startedAt;
  let createWithClock;
  const originalSign = crypto.sign;
  let custodianSignCalls = 0;
  let signerHook = null;
  try {
    // The module captures Date.now at import, just as a real OS clock can
    // change after startup. Also capture the trusted test-only wrapper of
    // the REAL Ed25519 signer before importing this isolated module.
    Date.now = () => wallNow;
    crypto.sign = (...args) => signerHook
      ? signerHook(...args) : originalSign(...args);
    delete require.cache[modulePath];
    ({ createDevOffZk10MonotonicFloorCustodian: createWithClock } = require(modulePath));
  } finally {
    crypto.sign = originalSign;
    Date.now = genuineNow;
    delete require.cache[modulePath];
    if (cached) require.cache[modulePath] = cached;
  }
  const c = x.track(createWithClock(x.config));
  // Begin the lease after module initialization and SQLite bootstrap.
  // Under runner load, an expiry relative to pre-bootstrap time can
  // expire before crypto.sign is reached, invalidating this oracle.
  const challenge = x.offer({ lease_expires_at_ms: genuineNow() + 2200 });
  startedAt = challenge.ownerLease.issued_at_ms;
  wallNow = startedAt;
  signerHook = (...args) => {
    const signed = originalSign(...args);
    if (isActualCustodianFloorCall(args[1], args[2], x.custodian.publicKey, signed)) {
      custodianSignCalls++;
      // Real time passes beyond expiry, but a partial clock rollback leaves
      // the reported time AFTER issuedAt and BEFORE the expiry timestamp.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2550);
      wallNow = startedAt + 500;
    }
    return signed;
  };
  try {
    assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/,
      "a backwards wall-clock step cannot conceal expiry during synchronous Ed25519 signing");
  } finally { signerHook = null; }
  assert.equal(custodianSignCalls, 1, "real custodian Ed25519 signing was delayed");
  assert.ok(genuineNow() >= challenge.request.lease_expires_at_ms,
    "the signed owner lease truly expired during the signing operation");
  assert.ok(wallNow >= challenge.ownerLease.issued_at_ms
    && wallNow + 100 < challenge.request.lease_expires_at_ms,
  "wall-clock checks alone would incorrectly accept this partial rollback");
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
  for (const file of [x.paths.databasePath, x.paths.anchorDatabasePath]) {
    const db = new Database(file, { readonly: true, fileMustExist: true });
    try {
      assert.equal(db.prepare("SELECT lease_serial FROM floor WHERE singleton = 1")
        .get().lease_serial, 1);
    } finally { db.close(); }
  }
  c.close();
  const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
  }));
  const next = x.offer();
  assert.equal(restarted.attest(next.request, next.ownerLease).floor.sequence, 1);
  assert.equal(restarted.retainedMinimum().lease_serial, 2);
});

test("P2: reentrant retainedMinimum failure during genuine signing cannot escape a poisoned custodian", (t) => {
  const x = setup(t, "reentrant-poison-sign");
  let c;
  const signed = x.offer({ sequence: 2, head_digest: sha(42), enrollment_root: sha(43) });
  const realSign = crypto.sign;
  let signedByCustodian = false, reentrantDenied = false;
  crypto.sign = (algorithm, data, key, ...rest) => {
    const proof = realSign(algorithm, data, key, ...rest);
    if (isActualCustodianFloorCall(data, key, x.custodian.publicKey, proof)) {
      signedByCustodian = true;
      // A synchronous instrumented signer reenters the same custodian while
      // BOTH outer BEGIN IMMEDIATE reservations are held. A nested BEGIN on
      // that handle fails; retainedMinimum() poisons it. Swallowing that
      // nested failure must not let the outer CURRENT signature escape.
      try { c.retainedMinimum(); }
      catch (error) {
        assert.equal(error.code, "ZK10_CUSTODIAN_UNAVAILABLE");
        reentrantDenied = true;
      }
    }
    return proof;
  };
  try {
    c = x.track(testFactoryCapturingCurrentCrypto()(x.config));
    assert.throws(() => c.attest(signed.request, signed.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/,
      "an already-poisoned instance must not return a signed CURRENT");
  } finally { crypto.sign = realSign; }
  assert.equal(signedByCustodian, true, "a real custodian Ed25519 signature was computed");
  assert.equal(reentrantDenied, true, "the nested operation rejected and poisoned the instance");
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
  for (const file of [x.paths.databasePath, x.paths.anchorDatabasePath]) {
    const db = new Database(file, { readonly: true, fileMustExist: true });
    try {
      assert.equal(db.prepare("SELECT lease_serial FROM floor WHERE singleton = 1")
        .get().lease_serial, 1, "committed serial must not roll back on nested failure");
    } finally { db.close(); }
  }
  c.close();
  const refreshed = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
  }));
  assert.equal(refreshed.retainedMinimum().lease_serial, 1);
  const next = x.offer({ sequence: 2, head_digest: sha(42), enrollment_root: sha(43) });
  assert.ok(refreshed.attest(next.request, next.ownerLease).floor.signature);
  assert.equal(refreshed.retainedMinimum().lease_serial, 2);
});
