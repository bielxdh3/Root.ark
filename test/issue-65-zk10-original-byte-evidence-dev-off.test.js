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
