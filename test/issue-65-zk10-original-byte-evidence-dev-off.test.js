"use strict";

// All signer/custodian keys here are throwaway test keys, NOT off-host custody,
// production identity, a real historical upload, or an R1 permission.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { createDevOffOriginalByteEvidenceGate } = require(
  "../src/crypto/rootark-zk10-original-byte-evidence-dev-off-v1");

const OWNER_DOMAIN = Buffer.from("Root.ark/zk10/owner-original-byte-evidence/v1\0");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk10/original-byte-floor-readback/v1\0");
const OWNER_FIELDS = ["type", "immutable_account_id", "object_id", "version_id",
  "key_epoch", "original_sha256", "original_length", "nonce",
  "floor_sequence", "floor_digest", "issued_at_ms", "expires_at_ms"];
const FLOOR_FIELDS = ["type", "immutable_account_id", "owner_spki_sha256",
  "sequence", "head_digest", "nonce", "revoked", "issued_at_ms", "expires_at_ms"];
const b64 = (n) => crypto.randomBytes(n).toString("base64url");
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const spki = (key) => hash(key.export({ type: "spki", format: "der" }));
function sign(body, fields, domain, privateKey) {
  const canonical = Object.fromEntries(fields.map((key) => [key, body[key]]));
  return { ...canonical, signature: crypto.sign(null,
    Buffer.concat([domain, Buffer.from(JSON.stringify(canonical), "utf8")]),
    privateKey).toString("base64url") };
}
function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const custodian = crypto.generateKeyPairSync("ed25519");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const now = Date.now();
  const original = Buffer.from([0, 255, 4, 0, 191, 128, 14, 20, 0]);
  const expected = { immutable_account_id: b64(16), object_id: b64(16),
    version_id: b64(16), key_epoch: 3 };
  const minimum = { sequence: 17, headDigest: hash(Buffer.from("disposable-offline-floor")) };
  const body = {
    type: "rootark-zk10-owner-original-byte-evidence/v1", ...expected,
    original_sha256: hash(original), original_length: original.length,
    nonce: b64(32), floor_sequence: minimum.sequence,
    floor_digest: minimum.headDigest, issued_at_ms: now - 100,
    expires_at_ms: now + 30000,
  };
  const intent = (changes = {}, key = owner.privateKey) =>
    sign({ ...body, ...changes }, OWNER_FIELDS, OWNER_DOMAIN, key);
  let currentChanges = {};
  let floorCalls = 0;
  const options = () => ({
    devOff: true, pinnedOwnerPublicKey: owner.publicKey,
    pinnedOwnerSpkiSha256: spki(owner.publicKey),
    pinnedFloorPublicKey: custodian.publicKey,
    pinnedFloorSpkiSha256: spki(custodian.publicKey),
    independentlyRetainedMinimum: minimum,
    readSignedCurrentFloor(challenge) {
      floorCalls++;
      const response = {
        type: "rootark-zk10-original-byte-floor-readback/v1",
        immutable_account_id: expected.immutable_account_id,
        owner_spki_sha256: spki(owner.publicKey),
        sequence: minimum.sequence, head_digest: minimum.headDigest,
        nonce: challenge, revoked: false, issued_at_ms: Date.now() - 50,
        expires_at_ms: Date.now() + 5000, ...currentChanges,
      };
      return sign(response, FLOOR_FIELDS, FLOOR_DOMAIN, custodian.privateKey);
    },
  });
  const open = (override = {}) => createDevOffOriginalByteEvidenceGate({
    ...options(), ...override,
  });
  return { owner, custodian, foreign, original, expected, minimum, body,
    intent, open, options, setCurrent(changes) { currentChanges = changes; },
    get floorCalls() { return floorCalls; } };
}
const bad = /ZK10_ORIGINAL_BYTE_EVIDENCE_UNVERIFIED/;

test("P2: Array species cannot transmute fresh signed floor nonce A into stale signed nonce B", () => {
  const f = fixture();
  const stolenNonce = b64(32);
  const oldDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "constructor");
  let callbackCalls = 0;
  let rewrittenNonceFields = 0;
  let hostileSpeciesCalls = 0;
  const signedFloorB = sign({
    type: "rootark-zk10-original-byte-floor-readback/v1",
    immutable_account_id: f.expected.immutable_account_id,
    owner_spki_sha256: spki(f.owner.publicKey),
    sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
    nonce: stolenNonce, revoked: false, issued_at_ms: Date.now() - 50,
    expires_at_ms: Date.now() + 5000,
  }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
  assert.equal(crypto.verify(null, Buffer.concat([FLOOR_DOMAIN, Buffer.from(JSON.stringify(
    Object.fromEntries(FLOOR_FIELDS.map((field) => [field, signedFloorB[field]]))
  ), "utf8")]), f.custodian.publicKey,
  Buffer.from(signedFloorB.signature, "base64url")), true,
  "signed B must have a genuine separate custodian Ed25519 signature");
  try {
    const gate = f.open({
      readSignedCurrentFloor(challenge) {
        callbackCalls += 1;
        assert.notEqual(challenge, stolenNonce);
        // Authenticated signature belongs to B, but the wire falsely claims
        // the unpredictable fresh challenge A. A same-realm callback changes
        // ONLY the later ArraySpeciesCreate result during serializing A.
        Object.defineProperty(Array.prototype, "constructor", {
          ...oldDescriptor, value: { [Symbol.species]: function PollutedArray(size) {
            hostileSpeciesCalls += 1;
            return new Proxy(new Array(size), {
              defineProperty(target, property, descriptor) {
                if (typeof descriptor.value === "string"
                  && descriptor.value.includes(`\"nonce\":\"${challenge}\"`)) {
                  rewrittenNonceFields += 1;
                  descriptor.value = descriptor.value.replace(
                    `\"nonce\":\"${challenge}\"`, `\"nonce\":\"${stolenNonce}\"`);
                }
                return Reflect.defineProperty(target, property, descriptor);
              },
            });
          } },
        });
        return { ...signedFloorB, nonce: challenge };
      },
    });
    assert.throws(() => gate.beginBeforeBody({
      ownerEvidence: f.intent(), expected: f.expected,
    }), bad, "signer B must not authorize nonce challenge A via Array species");
    assert.ok(callbackCalls > 0, "hostile callback must have run after signed owner admission");
    assert.equal(rewrittenNonceFields, 0,
      "canonical signed floor must not use hostile Array species for serialization");
  } finally {
    Object.defineProperty(Array.prototype, "constructor", oldDescriptor);
  }
  assert.equal(hostileSpeciesCalls, 0,
    "secure field copy and signed serialization must not construct attacker species");
  const positive = fixture();
  assert.equal(positive.open().beginBeforeBody({
    ownerEvidence: positive.intent(), expected: positive.expected,
  }).authorizesIo, false, "legitimate Ed25519 control stays supported and DEV-OFF");
});
// Public, disposable 512-bit RSA negative-test fixture. It is deliberately
// BREAKABLE and must NEVER be provisioned, generated, or used for a real key.
// A fixed DER fixture avoids generating insecure cryptographic keys at runtime.
const REJECT_ONLY_RSA512_PKCS8 = Buffer.from(
  "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA3JXVfnIi+iWowOBmrotFOWQVdE5lrj+1X+re2poRZETZT24VI6ynYpbQX7QCHuDwOyFtndb3cdOSKgZfW5ap2QIDAQABAkB9LLG4TYC3vwMiYLUkO3gO91KNa6eb2B9OzPOlzWQtJy7q9dUtwSCslf3eGD5f8q7Zry7NCMQtHspcW+Y9h/BhAiEA9WCo5KzfVMvsVDmrmlIE/5+LUIt1UTeAXQVa7bzFNBUCIQDmImtfHCg12D9/VAOqlVQ3yAbHz3ZcTI9RiXUILog7tQIhAO1EkSvFyZJKOXRb64YmZzTyhhjVMRTekR3hjsIxdZLdAiAMYpfSs4o6c5vfN19HI+g3ZE1xHWoqR3iDE9m3igGM7QIhAOHHx9o6lMS8QydfHqFnNuJaWWBXtPefsBGQ8AYi8Cwr",
  "base64");

test("signed opaque original bytes verify once but NEVER authorize upload, stage or R1", () => {
  const f = fixture(), gate = f.open();
  const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
  assert.deepEqual({ authorizesIo: ticket.authorizesIo, stagePermitted: ticket.stagePermitted,
    independentCustodyProven: ticket.independentCustodyProven },
  { authorizesIo: false, stagePermitted: false, independentCustodyProven: false });
  const result = gate.verifyOriginalBytes({ ticket,
    chunks: [f.original.subarray(0, 3), Uint8Array.from(f.original.subarray(3))] });
  assert.equal(result.originalByteDigestVerified, true);
  assert.equal(result.originalLength, f.original.length);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.stagePermitted, false);
  assert.equal(result.independentCustodyProven, false);
  assert.equal(result.offHostMonotonicFloorProven, false);
  assert.equal(result.historicalCorpusComplete, false);
  assert.equal(f.floorCalls, 3, "check before body, before hashing and after hashing");
  assert.throws(() => gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected }), bad);
  assert.throws(() => gate.verifyOriginalBytes({ ticket, chunks: [f.original] }), bad);
});

test("P2: owner statement expiring during final floor callback cannot verify original bytes", () => {
  const f = fixture();
  const options = f.options();
  const realNow = Date.now;
  const modulePath = require.resolve("../src/crypto/rootark-zk10-original-byte-evidence-dev-off-v1");
  let virtualNow = realNow();
  const ownerExpiresAt = virtualNow + 2000;
  let readbacks = 0;
  try {
    // The DEV-OFF verifier deliberately captures Date.now.bind(Date) at
    // module load. Reload only this module under a deterministic clock.
    // No sleeping or timing dependence is necessary to prove expiry.
    Date.now = () => virtualNow;
    delete require.cache[modulePath];
    const { createDevOffOriginalByteEvidenceGate: createWithClock } = require(modulePath);
    const gate = createWithClock({
      ...options,
      readSignedCurrentFloor(challenge) {
        readbacks += 1;
        if (readbacks === 3) virtualNow = ownerExpiresAt + 1;
        return options.readSignedCurrentFloor(challenge);
      },
    });
    const ownerEvidence = f.intent({
      issued_at_ms: virtualNow - 50, expires_at_ms: ownerExpiresAt,
    });
    const ticket = gate.beginBeforeBody({ ownerEvidence, expected: f.expected });
    assert.throws(() => gate.verifyOriginalBytes({ ticket, chunks: [f.original] }), bad,
      "a fresh signed floor returned after owner expiry cannot revive expired consent");
    assert.equal(readbacks, 3, "the final post-hash callback must cross owner expiry");
  } finally {
    Date.now = realNow;
    delete require.cache[modulePath];
  }
});

test("wrong owner, unsigned intent, changed account/object/version/epoch/nonce and floor fail closed", () => {
  const variations = [
    (f) => ({ ownerEvidence: f.intent({}, f.foreign.privateKey), expected: f.expected }),
    (f) => ({ ownerEvidence: { ...f.intent(), signature: undefined }, expected: f.expected }),
    (f) => ({ ownerEvidence: f.intent(), expected: { ...f.expected, object_id: b64(16) } }),
    (f) => ({ ownerEvidence: f.intent(), expected: { ...f.expected, version_id: b64(16) } }),
    (f) => ({ ownerEvidence: f.intent(), expected: { ...f.expected, key_epoch: 4 } }),
    (f) => ({ ownerEvidence: f.intent(), expected: { ...f.expected, immutable_account_id: b64(16) } }),
    (f) => ({ ownerEvidence: f.intent({ floor_digest: hash("different") }), expected: f.expected }),
    (f) => ({ ownerEvidence: f.intent({ floor_sequence: f.minimum.sequence + 1 }), expected: f.expected }),
    (f) => ({ ownerEvidence: f.intent({ nonce: b64(32), original_length: -1 }), expected: f.expected }),
    (f) => ({ ownerEvidence: f.intent({ expires_at_ms: Date.now() - 500 }), expected: f.expected }),
    (f) => ({ ownerEvidence: f.intent({ expires_at_ms: Date.now() + 80000 }), expected: f.expected }),
    (f) => ({ ownerEvidence: { ...f.intent(), injected: true }, expected: f.expected }),
  ];
  for (const [index, make] of variations.entries()) {
    const f = fixture();
    assert.throws(() => f.open().beginBeforeBody(make(f)), bad, `signed scope negative ${index}`);
  }
  const f = fixture();
  for (const overrides of [
    { devOff: false }, { pinnedOwnerPublicKey: f.foreign.publicKey },
    { pinnedOwnerSpkiSha256: hash("not-pinned") },
    { pinnedFloorPublicKey: undefined },
    { pinnedFloorSpkiSha256: hash("not-a-custodian") },
    { independentlyRetainedMinimum: undefined },
    { readSignedCurrentFloor: undefined },
  ]) {
    assert.throws(() => f.open(overrides), bad);
  }
});

test("owner and floor cannot share Ed25519 key material, even via copied or shadowed keys", () => {
  for (const variant of ["same-object", "same-material", "shadowed-spki"]) {
    const f = fixture();
    const ownerDer = f.owner.publicKey.export({ format: "der", type: "spki" });
    const floorPublicKey = variant === "same-object" ? f.owner.publicKey
      : crypto.createPublicKey({ key: ownerDer, format: "der", type: "spki" });
    assert.equal(crypto.KeyObject.prototype.equals.call(f.owner.publicKey, floorPublicKey), true);
    let floorPin = spki(f.owner.publicKey);
    if (variant === "shadowed-spki") {
      // KeyObject.export is a caller-shadowable JS method. Identity must be
      // checked using the native underlying key, not the claimed SPKI alone.
      const spoofDer = f.foreign.publicKey.export({ format: "der", type: "spki" });
      Object.defineProperty(floorPublicKey, "export", { value: () => spoofDer });
      floorPin = spki(f.foreign.publicKey);
    }
    const readSignedCurrentFloor = (challenge) => sign({
      type: "rootark-zk10-original-byte-floor-readback/v1",
      immutable_account_id: f.expected.immutable_account_id,
      owner_spki_sha256: spki(f.owner.publicKey),
      sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
      nonce: challenge, revoked: false, issued_at_ms: Date.now() - 50,
      expires_at_ms: Date.now() + 5000,
    }, FLOOR_FIELDS, FLOOR_DOMAIN, f.owner.privateKey);
    assert.throws(() => f.open({ pinnedFloorPublicKey: floorPublicKey,
      pinnedFloorSpkiSha256: floorPin, readSignedCurrentFloor })
      .beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected }),
    bad, `${variant} must not impersonate a separate custodian`);
  }
});

test("native owner and floor SPKI must match pins despite caller-shadowed export methods", () => {
  for (const role of ["owner", "floor"]) {
    const f = fixture();
    const originalOptions = f.options();
    const actual = role === "owner" ? f.owner.publicKey : f.custodian.publicKey;
    const foreignDer = f.foreign.publicKey.export({ type: "spki", format: "der" });
    assert.equal(crypto.KeyObject.prototype.equals.call(actual, f.foreign.publicKey), false);
    Object.defineProperty(actual, "export", { configurable: true, value: () => foreignDer });
    const changedPin = role === "owner" ? "pinnedOwnerSpkiSha256" : "pinnedFloorSpkiSha256";
    assert.throws(() => createDevOffOriginalByteEvidenceGate({
      ...originalOptions, [changedPin]: hash(foreignDer),
    }), bad, `${role} must not claim a different pinned public key`);
    // A shadowed throwing accessor must not replace the native DER source either.
    Object.defineProperty(actual, "export", { value: () => { throw Error("shadow method"); } });
    assert.doesNotThrow(() => createDevOffOriginalByteEvidenceGate(originalOptions),
      `${role} native identity remains valid independently of shadow methods`);
  }
});

test("P2 inherited native kHandle cannot splice owner or CURRENT signer A onto pinned SPKI B", () => {
  for (const role of ["owner", "floor"]) {
    const f = fixture();
    const actual = role === "owner" ? f.owner.publicKey : f.custodian.publicKey;
    const alleged = f.foreign.publicKey;
    const symbol = Object.getOwnPropertySymbols(actual)
      .find((item) => String(item) === "Symbol(kHandle)");
    assert.ok(symbol, "exercise real Node KeyObject native handle");
    // Native property-getter caching differs across Node 22/24, so exercise
    // each possible export getter index without depending on its call count.
    for (const swappedRead of [1, 2, 3, 4]) {
      const forged = Object.create(actual);
      assert.ok(forged instanceof crypto.KeyObject);
      let reads = 0;
      Object.defineProperty(forged, symbol, { get() {
        // Native metadata sees A, native SPKI export can see B, verification
        // sees A. A mutable JavaScript wrapper is NOT a pinned signer.
        return (++reads === swappedRead ? alleged : actual)[symbol];
      } });
      const config = f.options();
      if (role === "owner") {
        config.pinnedOwnerPublicKey = forged;
        config.pinnedOwnerSpkiSha256 = spki(alleged);
        config.readSignedCurrentFloor = (challenge) => sign({
          type: "rootark-zk10-original-byte-floor-readback/v1",
          immutable_account_id: f.expected.immutable_account_id,
          owner_spki_sha256: spki(alleged),
          sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
          nonce: challenge, revoked: false, issued_at_ms: Date.now() - 50,
          expires_at_ms: Date.now() + 5000,
        }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
      } else {
        config.pinnedFloorPublicKey = forged;
        config.pinnedFloorSpkiSha256 = spki(alleged);
      }
      assert.throws(() => {
        const gate = createDevOffOriginalByteEvidenceGate(config);
        const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
        gate.verifyOriginalBytes({ ticket, chunks: [f.original] });
      }, bad, `${role} real signer A must not authenticate B at read ${swappedRead}`);
    }
  }
});

test("P2 native SPKI factory cannot be replaced by owner or CURRENT KeyObject getter", () => {
  for (const role of ["owner", "floor"]) {
    const f = fixture();
    const actual = role === "owner" ? f.owner.publicKey : f.custodian.publicKey;
    const alleged = f.foreign.publicKey;
    const claimedPin = spki(alleged);
    const handle = Object.getOwnPropertySymbols(actual)
      .find((key) => String(key) === "Symbol(kHandle)");
    assert.ok(handle, "real native Ed25519 kHandle required for this physical regression");
    let exercised = 0;
    // Some native KeyObject getters read the handle before SPKI export.
    // Try each documented observed getter position on physical Node 22.
    for (const swappedRead of [1, 2, 3]) {
      const savedCreatePublicKey = crypto.createPublicKey;
      const forgedPinned = Object.create(actual);
      let pinnedReads = 0;
      Object.defineProperty(forgedPinned, handle, { get() {
        // Spoof the DER re-export check with B, then verify A.
        return (++pinnedReads === 1 ? alleged : actual)[handle];
      } });
      const caller = Object.create(actual);
      let callerReads = 0;
      Object.defineProperty(caller, handle, { get() {
        if (++callerReads === swappedRead) {
          // The untrusted getter executes during a native SPKI operation.
          // A fresh clone MUST NOT be obtained through this mutable factory.
          exercised++;
          crypto.createPublicKey = (options) => {
            if (options && Buffer.isBuffer(options.key)
              && hash(options.key) === claimedPin) return forgedPinned;
            return savedCreatePublicKey(options);
          };
          return alleged[handle];
        }
        return actual[handle];
      } });
      const opts = f.options();
      if (role === "owner") {
        opts.pinnedOwnerPublicKey = caller;
        opts.pinnedOwnerSpkiSha256 = claimedPin;
        opts.readSignedCurrentFloor = (challenge) => sign({
          type: "rootark-zk10-original-byte-floor-readback/v1",
          immutable_account_id: f.expected.immutable_account_id,
          owner_spki_sha256: claimedPin, sequence: f.minimum.sequence,
          head_digest: f.minimum.headDigest, nonce: challenge, revoked: false,
          issued_at_ms: Date.now() - 50, expires_at_ms: Date.now() + 5000,
        }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
      } else {
        opts.pinnedFloorPublicKey = caller;
        opts.pinnedFloorSpkiSha256 = claimedPin;
      }
      try {
        assert.throws(() => {
          const gate = createDevOffOriginalByteEvidenceGate(opts);
          const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
          gate.verifyOriginalBytes({ ticket, chunks: [f.original] });
        }, bad, `${role} A may not verify as pinned B at getter ${swappedRead}`);
      } finally {
        crypto.createPublicKey = savedCreatePublicKey;
      }
      assert.equal(callerReads, 0,
        "the caller-backed native handle getter is rejected before execution");
    }
    assert.equal(exercised, 0,
      "hostile constructor replacement must not execute during key import");
  }
});

test("RSA-512 signatures cannot impersonate Ed25519 owner or floor using shadowed key type", () => {
  for (const role of ["owner", "floor"]) {
    const f = fixture();
    const rsaPrivate = crypto.createPrivateKey({
      key: REJECT_ONLY_RSA512_PKCS8, format: "der", type: "pkcs8",
    });
    const rsa = { privateKey: rsaPrivate, publicKey: crypto.createPublicKey(rsaPrivate) };
    assert.equal(crypto.sign(null, Buffer.from("rsa-probe"), rsa.privateKey).length, 64,
      "RSA-512 signatures collide with the Ed25519 signature byte length");
    const opts = f.options();
    const pin = spki(rsa.publicKey);
    Object.defineProperty(rsa.publicKey, "asymmetricKeyType", { value: "ed25519" });
    const override = role === "owner"
      ? { pinnedOwnerPublicKey: rsa.publicKey, pinnedOwnerSpkiSha256: pin }
      : { pinnedFloorPublicKey: rsa.publicKey, pinnedFloorSpkiSha256: pin };
    const readSignedCurrentFloor = (challenge) => sign({
      type: "rootark-zk10-original-byte-floor-readback/v1",
      immutable_account_id: f.expected.immutable_account_id,
      owner_spki_sha256: role === "owner" ? pin : spki(f.owner.publicKey),
      sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
      nonce: challenge, revoked: false, issued_at_ms: Date.now() - 50,
      expires_at_ms: Date.now() + 5000,
    }, FLOOR_FIELDS, FLOOR_DOMAIN, role === "floor" ? rsa.privateKey : f.custodian.privateKey);
    assert.throws(() => {
      const gate = createDevOffOriginalByteEvidenceGate({ ...opts, ...override,
        readSignedCurrentFloor });
      const evidence = role === "owner" ? f.intent({}, rsa.privateKey) : f.intent();
      const ticket = gate.beginBeforeBody({ ownerEvidence: evidence, expected: f.expected });
      gate.verifyOriginalBytes({ ticket, chunks: [f.original] });
    }, bad, `${role} algorithm identity must be native Ed25519, not RSA-512`);
  }
});

test("genuine Ed25519 key identity is read natively despite shadowed type metadata", () => {
  const f = fixture();
  const opts = f.options();
  Object.defineProperties(f.owner.publicKey, {
    type: { value: "private" },
    asymmetricKeyType: { value: "rsa" },
  });
  Object.defineProperties(f.custodian.publicKey, {
    type: { value: "private" },
    asymmetricKeyType: { value: "rsa" },
  });
  assert.doesNotThrow(() => createDevOffOriginalByteEvidenceGate(opts));
});

test("floor signer, nonce, account, immutable head, expiry and revocation fail before body", () => {
  const cases = [
    (f) => ({ revoked: true }),
    (f) => ({ nonce: b64(32) }),
    (f) => ({ immutable_account_id: b64(16) }),
    (f) => ({ owner_spki_sha256: hash("alien-owner") }),
    (f) => ({ head_digest: hash("different-head") }),
    (f) => ({ sequence: f.minimum.sequence + 1 }),
    (f) => ({ expires_at_ms: Date.now() - 1 }),
    (f) => ({ issued_at_ms: Date.now() + 2000 }),
  ];
  for (const [index, alter] of cases.entries()) {
    const f = fixture();
    f.setCurrent(alter(f));
    assert.throws(() => f.open().beginBeforeBody({
      ownerEvidence: f.intent(), expected: f.expected,
    }), bad, `floor negative ${index}`);
  }
  const f = fixture();
  const o = f.options();
  const signedByWrongCustodian = (challenge) => sign({
    type: "rootark-zk10-original-byte-floor-readback/v1",
    immutable_account_id: f.expected.immutable_account_id,
    owner_spki_sha256: spki(f.owner.publicKey), sequence: f.minimum.sequence,
    head_digest: f.minimum.headDigest, nonce: challenge, revoked: false,
    issued_at_ms: Date.now() - 10, expires_at_ms: Date.now() + 5000,
  }, FLOOR_FIELDS, FLOOR_DOMAIN, f.foreign.privateKey);
  assert.throws(() => f.open({ readSignedCurrentFloor: signedByWrongCustodian })
    .beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected }), bad);
  assert.throws(() => f.open({ independentlyRetainedMinimum: {
    sequence: f.minimum.sequence, headDigest: hash("different-retained"),
  } }).beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected }), bad);
  assert.equal(typeof o.readSignedCurrentFloor, "function");
});

test("signed raw-byte digest mismatch and replay after failed assembly stay closed", () => {
  const f = fixture(), gate = f.open();
  const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
  const changed = Buffer.from(f.original);
  changed[2] ^= 0x3f;
  assert.throws(() => gate.verifyOriginalBytes({ ticket, chunks: [changed] }), bad);
  assert.throws(() => gate.verifyOriginalBytes({ ticket, chunks: [f.original] }), bad);
  assert.throws(() => gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected }), bad);
  const gate2 = f.open();
  const ticket2 = gate2.beginBeforeBody({ ownerEvidence: f.intent({
    nonce: b64(32), original_length: f.original.length + 1,
  }), expected: f.expected });
  assert.throws(() => gate2.verifyOriginalBytes({ ticket: ticket2, chunks: [f.original] }), bad);
  assert.throws(() => f.open().verifyOriginalBytes({ ticket: ticket2, chunks: [f.original] }), bad);
});

test("mutable Proxies, spoofed lengths and shared bytes cannot manufacture signed original evidence", () => {
  const f = fixture();
  const proxyIntent = new Proxy(f.intent(), {
    getOwnPropertyDescriptor(target, name) {
      return Object.getOwnPropertyDescriptor(target, name);
    },
  });
  assert.throws(() => f.open().beginBeforeBody({
    ownerEvidence: proxyIntent, expected: f.expected,
  }), bad);
  assert.throws(() => f.open().beginBeforeBody({
    ownerEvidence: f.intent(), expected: new Proxy(f.expected, {}),
  }), bad);
  for (const kind of ["proxy-chunks", "proxy-part", "shared", "shadow"]) {
    const gate = f.open();
    const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent({ nonce: b64(32) }),
      expected: f.expected });
    let chunk = Buffer.from(f.original);
    if (kind === "shared") {
      const backing = new SharedArrayBuffer(f.original.length);
      new Uint8Array(backing).set(f.original);
      chunk = new Uint8Array(backing);
    } else if (kind === "shadow") {
      Object.defineProperty(chunk, "byteLength", { value: 0 });
    } else if (kind === "proxy-part") {
      chunk = new Proxy(chunk, {});
    }
    const chunks = kind === "proxy-chunks" ? new Proxy([chunk], {}) : [chunk];
    assert.throws(() => gate.verifyOriginalBytes({ ticket, chunks }), bad, kind);
  }
});

test("readback revocation after begin consumes ticket and no historic or provider grant emerges", () => {
  const f = fixture(), gate = f.open();
  const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
  f.setCurrent({ revoked: true });
  assert.throws(() => gate.verifyOriginalBytes({ ticket, chunks: [f.original] }), bad);
  assert.throws(() => gate.verifyOriginalBytes({ ticket, chunks: [f.original] }), bad);
  assert.equal(gate.authorizesIo, false);
  assert.equal(gate.stagePermitted, false);
});

test("missing, unsigned, async or locally untrusted floor response never admits original bytes", () => {
  const f = fixture();
  for (const reader of [
    () => undefined,
    () => ({}),
    async () => ({}),
    () => ({ type: "rootark-zk10-original-byte-floor-readback/v1" }),
  ]) {
    const gate = f.open({ readSignedCurrentFloor: reader });
    assert.throws(() => gate.beginBeforeBody({
      ownerEvidence: f.intent({ nonce: b64(32) }), expected: f.expected,
    }), bad);
  }
});

test("production NODE_ENV refuses even fully signed disposable evidence", () => {
  const f = fixture();
  const previous = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    assert.throws(() => f.open(), bad);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});

test("P2 hostile signed CURRENT callback cannot replace Buffer.from to authenticate wrong Uint8Array original bytes", () => {
  const f = fixture();
  const wrong = Uint8Array.from(f.original);
  wrong[2] ^= 0x7f;
  assert.equal(wrong.length, f.original.length);
  assert.notEqual(hash(Buffer.from(wrong)), f.body.original_sha256,
    "physical wrong bytes do not match the genuine owner-signed SHA256");
  const options = f.options();
  const genuineFloorRead = options.readSignedCurrentFloor;
  const nativeFrom = Buffer.from;
  const nativeCompare = Buffer.compare;
  let readbacks = 0, forgedCopies = 0;
  options.readSignedCurrentFloor = (challenge) => {
    // Return a GENUINELY Ed25519-signed CURRENT first. Only its untrusted
    // callback then replaces Buffer.from before the body is assembled.
    const signed = genuineFloorRead(challenge);
    readbacks++;
    Buffer.from = function (value, ...args) {
      if (value instanceof Uint8Array && !Buffer.isBuffer(value)
        && nativeCompare(value, wrong) === 0) {
        forgedCopies++;
        return nativeFrom(f.original);
      }
      return nativeFrom(value, ...args);
    };
    return signed;
  };
  let accepted;
  try {
    const gate = createDevOffOriginalByteEvidenceGate(options);
    const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
    // Prove the adversarial test hook genuinely turns wrong B into original A.
    // Otherwise a zero-hit counter would be a meaningless false GREEN.
    const probe = Buffer.from(wrong);
    assert.equal(nativeCompare(probe, f.original), 0,
      "hostile Buffer.from hook must really replace wrong bytes with signed A");
    assert.equal(forgedCopies, 1, "the adversarial hook must be reachable");
    forgedCopies = 0;
    assert.throws(() => {
      accepted = gate.verifyOriginalBytes({ ticket, chunks: [wrong] });
    }, bad, "a malicious callback cannot turn foreign body bytes into genuine owner-signed bytes");
  } finally { Buffer.from = nativeFrom; }
  assert.ok(readbacks >= 2, "genuine signed CURRENT was read before wrong body hash");
  assert.equal(forgedCopies, 0,
    "untrusted Buffer.from can never be invoked on original-byte typed copy");
  assert.equal(accepted, undefined, "no false original-byte verification");
});

test("P2 hostile signed CURRENT callback cannot replace Buffer.concat to replay a stale nonce-signed floor", () => {
  const f = fixture();
  const staleNonce = b64(32);
  const ownerPin = spki(f.owner.publicKey);
  const staleFloor = sign({
    type: "rootark-zk10-original-byte-floor-readback/v1",
    immutable_account_id: f.expected.immutable_account_id,
    owner_spki_sha256: ownerPin, sequence: f.minimum.sequence,
    head_digest: f.minimum.headDigest, nonce: staleNonce, revoked: false,
    issued_at_ms: Date.now() - 50, expires_at_ms: Date.now() + 5000,
  }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
  // Physically prove this genuine Ed25519 signature authorizes only stale B,
  // never the fresh challenge A supplied to the callback.
  const nativeConcat = Buffer.concat;
  const nativeFrom = Buffer.from;
  const { signature: staleSignature, ...stalePayload } = staleFloor;
  assert.equal(crypto.verify(null, nativeConcat([FLOOR_DOMAIN,
    nativeFrom(JSON.stringify(stalePayload), "utf8")]), f.custodian.publicKey,
  nativeFrom(staleSignature, "base64url")), true);
  const options = f.options();
  let reused = 0, intercepted = 0;
  options.readSignedCurrentFloor = challenge => {
    assert.notEqual(challenge, staleNonce);
    reused++;
    Buffer.concat = function (parts, ...args) {
      if (Array.isArray(parts) && Buffer.isBuffer(parts[0])
        && parts[0].equals(FLOOR_DOMAIN)) {
        const payload = JSON.parse(parts[1].toString("utf8"));
        if (payload.nonce === challenge) {
          // Replace ONLY the verifier's signed message A with the previously
          // signed B. Returned signed wire still says nonce=A (a false CURRENT).
          intercepted++;
          payload.nonce = staleNonce;
          return nativeConcat([parts[0],
            nativeFrom(JSON.stringify(payload), "utf8")], ...args);
        }
      }
      return nativeConcat(parts, ...args);
    };
    return { ...staleFloor, nonce: challenge };
  };
  let accepted;
  try {
    const gate = createDevOffOriginalByteEvidenceGate(options);
    assert.throws(() => {
      const ticket = gate.beginBeforeBody({
        ownerEvidence: f.intent(), expected: f.expected,
      });
      accepted = gate.verifyOriginalBytes({ ticket, chunks: [f.original] });
    }, bad, "stale nonce B cannot authorize challenge A even with untrusted Buffer.concat");
  } finally { Buffer.concat = nativeConcat; }
  assert.ok(reused >= 1, "untrusted CURRENT callback returned a reused genuine B signature");
  assert.equal(intercepted, 0, "nonce binding must never call mutable Buffer.concat");
  assert.equal(accepted, undefined, "no replayed stale CURRENT accepted");
});

test("P2: signed CURRENT cannot replay stale nonce via poisoned own descriptor after real callback", () => {
  const f = fixture();
  const staleNonce = b64(32);
  const staleFloor = sign({
    type: "rootark-zk10-original-byte-floor-readback/v1",
    immutable_account_id: f.expected.immutable_account_id,
    owner_spki_sha256: spki(f.owner.publicKey),
    sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
    nonce: staleNonce, revoked: false, issued_at_ms: Date.now() - 40,
    expires_at_ms: Date.now() + 5000,
  }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
  const originalDescriptor = Object.getOwnPropertyDescriptor;
  let getDescriptorCalls = 0, injectedDescriptorCalls = 0;
  const options = f.options();
  options.readSignedCurrentFloor = challenge => {
    assert.notEqual(challenge, staleNonce);
    getDescriptorCalls++;
    Object.getOwnPropertyDescriptor = (value, field) => {
      const found = originalDescriptor.call(Object, value, field);
      if (field === "nonce" && found?.value === challenge && Object.isFrozen(value)
        && value?.type === "rootark-zk10-original-byte-floor-readback/v1") {
        injectedDescriptorCalls++;
        return { ...found, value: staleNonce };
      }
      return found;
    };
    return { ...staleFloor, nonce: challenge };
  };
  let granted;
  try {
    const gate = createDevOffOriginalByteEvidenceGate(options);
    assert.throws(() => { granted = gate.beginBeforeBody({
      ownerEvidence: f.intent(), expected: f.expected,
    }); }, bad, "authentic stale signature for B cannot authorize unowned CURRENT challenge A");
  } finally { Object.getOwnPropertyDescriptor = originalDescriptor; }
  assert.ok(getDescriptorCalls > 0, "a separate signed floor callback must run");
  assert.equal(injectedDescriptorCalls, 0,
    "signed nonce serialization must not call attacker-rebound Object.getOwnPropertyDescriptor");
  assert.equal(granted, undefined, "no ticket accepted after stale readback nonce replay");
});

test("P2: signed CURRENT cannot replay stale nonce via rebound Array.prototype.join", () => {
  const f = fixture();
  const staleNonce = b64(32);
  const staleFloor = sign({
    type: "rootark-zk10-original-byte-floor-readback/v1",
    immutable_account_id: f.expected.immutable_account_id,
    owner_spki_sha256: spki(f.owner.publicKey),
    sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
    nonce: staleNonce, revoked: false, issued_at_ms: Date.now() - 40,
    expires_at_ms: Date.now() + 5000,
  }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
  const nativeJoin = Array.prototype.join;
  let callbacks = 0, forgedJoins = 0;
  const options = f.options();
  options.readSignedCurrentFloor = challenge => {
    assert.notEqual(challenge, staleNonce);
    callbacks++;
    Array.prototype.join = function(separator) {
      const result = nativeJoin.call(this, separator);
      if (separator === "," && this.length === FLOOR_FIELDS.length
        && result.includes('"nonce":"' + challenge + '"')) {
        forgedJoins++;
        return result.replace('"nonce":"' + challenge + '"',
          '"nonce":"' + staleNonce + '"');
      }
      return result;
    };
    return { ...staleFloor, nonce: challenge };
  };
  let granted;
  try {
    const gate = createDevOffOriginalByteEvidenceGate(options);
    assert.throws(() => { granted = gate.beginBeforeBody({
      ownerEvidence: f.intent(), expected: f.expected,
    }); }, bad, "native signature for stale B must not validate current challenge A");
  } finally { Array.prototype.join = nativeJoin; }
  assert.ok(callbacks > 0, "genuine signed CURRENT readback callback must run");
  assert.equal(forgedJoins, 0,
    "canonical signature bytes must never dispatch to attacker-mutated Array.join");
  assert.equal(granted, undefined, "no replayed nonce may produce a DEV-OFF ticket");
});

test("P2: signed CURRENT must resist Function.prototype.call retarget of captured Array.join", () => {
  const f = fixture();
  const staleNonce = b64(32);
  const staleFloor = sign({
    type: "rootark-zk10-original-byte-floor-readback/v1",
    immutable_account_id: f.expected.immutable_account_id,
    owner_spki_sha256: spki(f.owner.publicKey),
    sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
    nonce: staleNonce, revoked: false, issued_at_ms: Date.now() - 50,
    expires_at_ms: Date.now() + 5000,
  }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
  const nativeCall = Function.prototype.call;
  const nativeJoin = Array.prototype.join;
  const nativeApply = Reflect.apply;
  const options = f.options();
  let floorCallbackCalls = 0, forgedCalls = 0;
  options.readSignedCurrentFloor = challenge => {
    assert.notEqual(challenge, staleNonce);
    floorCallbackCalls++;
    // The security module captured Array.join itself, but the later `.call`
    // lookup remains a writable Function.prototype property in the SAME realm.
    Function.prototype.call = function (receiver, ...args) {
      const result = nativeApply(nativeCall, this, [receiver, ...args]);
      if (this === nativeJoin && args[0] === ","
        && Array.isArray(receiver) && receiver.length === FLOOR_FIELDS.length
        && typeof result === "string"
        && result.includes('"nonce":"' + challenge + '"')) {
        forgedCalls++;
        return result.replace('"nonce":"' + challenge + '"',
          '"nonce":"' + staleNonce + '"');
      }
      return result;
    };
    return { ...staleFloor, nonce: challenge };
  };
  let granted;
  try {
    const gate = createDevOffOriginalByteEvidenceGate(options);
    assert.throws(() => { granted = gate.beginBeforeBody({
      ownerEvidence: f.intent(), expected: f.expected,
    }); }, bad, "genuine signed B cannot authorize fresh challenge A through rewritten .call");
  } finally { Function.prototype.call = nativeCall; }
  assert.ok(floorCallbackCalls > 0, "real external-floor callback must run");
  assert.equal(forgedCalls, 0, "native signed serializer cannot dispatch via mutable .call");
  assert.equal(granted, undefined, "no ticket from signature over stale B");
});

test("P2: wrong physical chunks cannot become signed originals via poisoned array descriptor", () => {
  const f = fixture();
  const wrong = Uint8Array.from(f.original);
  wrong[2] ^= 0x6e;
  assert.notEqual(hash(Buffer.from(wrong)), f.body.original_sha256,
    "wrong bytes genuinely differ from owner-signed original SHA");
  const chunks = [wrong];
  const nativeDescriptor = Object.getOwnPropertyDescriptor;
  const options = f.options();
  const realFloor = options.readSignedCurrentFloor;
  let floorCalls = 0, injectedDescriptorCalls = 0;
  options.readSignedCurrentFloor = challenge => {
    const authentic = realFloor(challenge);
    floorCalls++;
    if (floorCalls >= 2) {
      Object.getOwnPropertyDescriptor = (value, field) => {
        const found = nativeDescriptor.call(Object, value, field);
        if (value === chunks && field === "0") {
          injectedDescriptorCalls++;
          return { ...found, value: f.original };
        }
        return found;
      };
    }
    return authentic;
  };
  let accepted;
  try {
    const gate = createDevOffOriginalByteEvidenceGate(options);
    const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
    assert.throws(() => { accepted = gate.verifyOriginalBytes({ ticket, chunks }); }, bad,
      "the exact Uint8Array physically supplied, not a swapped JS descriptor, must be hashed");
  } finally { Object.getOwnPropertyDescriptor = nativeDescriptor; }
  assert.ok(floorCalls >= 2, "verified CURRENT callback executes before body hash");
  assert.equal(injectedDescriptorCalls, 0,
    "array elements must be read through an intrinsic captured before external callbacks");
  assert.equal(accepted, undefined, "no wrong original accepted after signed callback");
});

test("P2: owner A cannot impersonate independently pinned B via own native kKeyType getter and retargeted Hash.prototype.digest", () => {
  const f = fixture();
  const opts = f.options();
  const claimedPinB = spki(f.foreign.publicKey);
  const actualPinA = spki(f.owner.publicKey);
  assert.notEqual(claimedPinB, actualPinA);
  const genuineKey = f.owner.publicKey;
  const symbols = Object.getOwnPropertySymbols(genuineKey);
  const handleSymbol = symbols.find((sym) => sym.description === "kHandle");
  const typeSymbol = symbols.find((sym) => sym.description === "kKeyType");
  assert.ok(handleSymbol && typeSymbol, "real Node22 native key handle and key type required");
  const forged = Object.create(Object.getPrototypeOf(genuineKey));
  Object.defineProperty(forged, handleSymbol, { value: genuineKey[handleSymbol] });
  const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
  const nativeDigest = Object.getOwnPropertyDescriptor(hashPrototype, "digest");
  let keyTypeGetterCalls = 0;
  let hashSpoofCalls = 0;
  Object.defineProperty(forged, typeSymbol, { get() {
    keyTypeGetterCalls += 1;
    Object.defineProperty(hashPrototype, "digest", {
      ...nativeDigest, value: function forgedDigest(encoding) {
        const result = nativeDigest.value.call(this, encoding);
        if (encoding === "hex" && result === actualPinA) {
          hashSpoofCalls += 1;
          return claimedPinB;
        }
        return result;
      },
    });
    return "public";
  } });
  opts.pinnedOwnerPublicKey = forged;
  opts.pinnedOwnerSpkiSha256 = claimedPinB;
  opts.readSignedCurrentFloor = (challenge) => sign({
    type: "rootark-zk10-original-byte-floor-readback/v1",
    immutable_account_id: f.expected.immutable_account_id,
    owner_spki_sha256: claimedPinB,
    sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
    nonce: challenge, revoked: false, issued_at_ms: Date.now() - 10,
    expires_at_ms: Date.now() + 5000,
  }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
  try {
    assert.throws(() => {
      const gate = createDevOffOriginalByteEvidenceGate(opts);
      const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
      gate.verifyOriginalBytes({ ticket, chunks: [f.original] });
    }, bad, "owner signed A must never validate as externally pinned owner B");
    assert.equal(keyTypeGetterCalls, 0,
      "forged own accessor must be rejected before it can retarget native hashing");
    assert.equal(hashSpoofCalls, 0);
  } finally {
    Object.defineProperty(hashPrototype, "digest", nativeDigest);
  }
  const control = f.open();
  const controlTicket = control.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
  assert.equal(control.verifyOriginalBytes({ ticket: controlTicket,
    chunks: [f.original] }).originalByteDigestVerified, true,
  "genuine signed owner A, genuinely pinned as A, must remain accepted");
});

test("P2: signed CURRENT callback cannot replace native digest/comparison to accept mutated original bytes", () => {
  for (const attack of ["timingSafeEqual", "hashDigest"]) {
    const f = fixture();
    const options = f.options();
    const realTimingSafeEqual = crypto.timingSafeEqual;
    const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
    const originalDigest = Object.getOwnPropertyDescriptor(hashPrototype, "digest");
    const ownerPin = spki(f.owner.publicKey);
    let callbacks = 0;
    let attackerDispatches = 0;
    options.readSignedCurrentFloor = (challenge) => {
      callbacks += 1;
      const signed = sign({
        type: "rootark-zk10-original-byte-floor-readback/v1",
        immutable_account_id: f.expected.immutable_account_id,
        owner_spki_sha256: ownerPin,
        sequence: f.minimum.sequence, head_digest: f.minimum.headDigest,
        nonce: challenge, revoked: false, issued_at_ms: Date.now() - 20,
        expires_at_ms: Date.now() + 5000,
      }, FLOOR_FIELDS, FLOOR_DOMAIN, f.custodian.privateKey);
      if (callbacks === 2 && attack === "timingSafeEqual") {
        crypto.timingSafeEqual = () => { attackerDispatches += 1; return true; };
      } else if (callbacks === 2 && attack === "hashDigest") {
        Object.defineProperty(hashPrototype, "digest", {
          ...originalDigest,
          value: function forgedDigest(encoding) {
            const real = originalDigest.value.call(this, encoding);
            if (encoding === undefined && Buffer.isBuffer(real)) {
              attackerDispatches += 1;
              return Buffer.from(f.body.original_sha256, "hex");
            }
            return real;
          },
        });
      }
      return signed;
    };
    try {
      const gate = createDevOffOriginalByteEvidenceGate(options);
      const ticket = gate.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
      const wrongBytes = Buffer.from(f.original);
      wrongBytes[0] ^= 0x7f;
      assert.throws(() => gate.verifyOriginalBytes({ ticket, chunks: [wrongBytes] }), bad,
        `${attack} callback must not accept bytes different from genuine Ed25519 owner's digest`);
      assert.ok(callbacks >= 2, "hostile callback must actually run during signed readback");
      assert.equal(attackerDispatches, 0, "native digest/compare must ignore altered JS methods");
    } finally {
      crypto.timingSafeEqual = realTimingSafeEqual;
      Object.defineProperty(hashPrototype, "digest", originalDigest);
    }
    const control = f.open();
    const controlTicket = control.beginBeforeBody({ ownerEvidence: f.intent(), expected: f.expected });
    const positive = control.verifyOriginalBytes({ ticket: controlTicket, chunks: [f.original] });
    assert.equal(positive.originalByteDigestVerified, true);
    assert.equal(positive.authorizesIo, false);
  }
});
