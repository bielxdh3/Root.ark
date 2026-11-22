"use strict";

// Disposable Ed25519 keys and two real SQLite files per fixture. DEV-OFF only.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { signatureBytes } = require("../src/crypto/rootark-zk10-account-cutover-v1");
const { createDevOffZk10MonotonicFloorCustodian } =
  require("../src/services/zk10DevOffMonotonicFloorCustodian");

const GENESIS_DOMAIN = Buffer.from("Root.ark/zk10/custodian-owner-genesis/v1\0");
const LEASE_DOMAIN = Buffer.from("Root.ark/zk10/custodian-owner-lease/v1\0");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk10/external-floor-current/v1\0");
const id = (n) => Buffer.alloc(16, n).toString("base64url");
const hex = (n) => Buffer.alloc(32, n).toString("hex");
const sign = (payload, privateKey, domain) => ({
  ...payload, signature: crypto.sign(null, signatureBytes(domain, payload),
    privateKey).toString("base64url"),
});
const keyDigest = (publicKey) => crypto.createHash("sha256")
  .update(publicKey.export({ type: "spki", format: "der" })).digest("hex");

function fixture(t, label) {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk10-w28-"));
  const active = [];
  t.after(() => {
    for (const instance of active) instance.close();
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 3, retryDelay: 40 });
  });
  const owner = crypto.generateKeyPairSync("ed25519");
  const custodian = crypto.generateKeyPairSync("ed25519");
  const genesis = sign({
    type: "rootark-zk10-custodian-owner-genesis/v1",
    sequence: 1, head_digest: hex(1), enrollment_root: hex(2),
    immutable_account_id: id(3), identity_digest: hex(4), lease_serial: 0,
  }, owner.privateKey, GENESIS_DOMAIN);
  const paths = {
    databasePath: path.join(folder, label + "-primary.sqlite"),
    anchorDatabasePath: path.join(folder, label + "-anchor.sqlite"),
  };
  const config = { devOff: true, ...paths, bootstrap: genesis,
    ownerPublicKey: owner.publicKey, custodianPrivateKey: custodian.privateKey,
    custodianSpkiSha256: keyDigest(custodian.publicKey) };
  function offer(overrides = {}) {
    const at = Date.now();
    const payload = { type: "rootark-zk10-custodian-owner-lease/v1",
      sequence: 1, head_digest: hex(1), enrollment_root: hex(2),
      immutable_account_id: id(3), identity_digest: hex(4),
      operation: "legacy:read", nonce: crypto.randomBytes(32).toString("base64url"),
      lease_id: crypto.randomBytes(16).toString("base64url"), lease_serial: 1,
      issued_at_ms: at, lease_expires_at_ms: at + 8000, ...overrides };
    const request = Object.fromEntries([
      "immutable_account_id", "identity_digest", "operation", "nonce",
      "lease_id", "lease_expires_at_ms"].map(field => [field, payload[field]]));
    return { request, ownerLease: sign(payload, owner.privateKey, LEASE_DOMAIN) };
  }
  return { owner, custodian, config, paths, genesis, offer,
    track(instance) { active.push(instance); return instance; } };
}

test("P2: owner A GENESIS signature cannot initialize real SQLite at unsigned B head via inherited toJSON", (t) => {
  const x = fixture(t, "genesis-tojson");
  const forged = { ...x.genesis, head_digest: hex(47) };
  assert.notEqual(forged.head_digest, x.genesis.head_digest);
  assert.equal(crypto.verify(null, signatureBytes(GENESIS_DOMAIN, {
    ...forged, signature: undefined,
  }), x.owner.publicKey, Buffer.from(forged.signature, "base64url")), false);
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  let hijackCalls = 0;
  Object.defineProperty(Object.prototype, "toJSON", { configurable: true, value() {
    if (this.type === forged.type && this.head_digest === forged.head_digest) {
      hijackCalls++;
      return { ...this, head_digest: x.genesis.head_digest };
    }
    return this;
  } });
  try {
    assert.throws(() => x.track(createDevOffZk10MonotonicFloorCustodian({
      ...x.config, bootstrap: forged,
    })), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "real owner A signature cannot bootstrap unsigned GENESIS B");
  } finally {
    if (previous) Object.defineProperty(Object.prototype, "toJSON", previous);
    else delete Object.prototype.toJSON;
  }
  assert.equal(hijackCalls, 0, "signed encoding never calls inherited toJSON");
  assert.equal(fs.existsSync(x.paths.databasePath), false);
  assert.equal(fs.existsSync(x.paths.anchorDatabasePath), false);
});

test("P2: owner A LEASE cannot commit unsigned B head or signed CURRENT after inherited toJSON", (t) => {
  const x = fixture(t, "lease-tojson");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const legitimate = x.offer();
  const forged = { ...legitimate.ownerLease, sequence: 2, head_digest: hex(52) };
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  let hijackCalls = 0;
  Object.defineProperty(Object.prototype, "toJSON", { configurable: true, value() {
    if (this.type === forged.type && this.head_digest === forged.head_digest) {
      hijackCalls++;
      return { ...this, sequence: legitimate.ownerLease.sequence,
        head_digest: legitimate.ownerLease.head_digest };
    }
    return this;
  } });
  try {
    assert.throws(() => c.attest(legitimate.request, forged),
      /ZK10_CUSTODIAN_UNAVAILABLE/,
      "cannot advance two physical SQLite heads with owner A's signature on B");
  } finally {
    if (previous) Object.defineProperty(Object.prototype, "toJSON", previous);
    else delete Object.prototype.toJSON;
  }
  assert.equal(hijackCalls, 0, "GENESIS/LEASE wire snapshots must be immune to prototype toJSON");
  assert.equal(c.retainedMinimum().lease_serial, 0);
  const genuine = c.attest(legitimate.request, legitimate.ownerLease).floor;
  const { signature, ...body } = genuine;
  assert.equal(crypto.verify(null, signatureBytes(FLOOR_DOMAIN, body),
    x.custodian.publicKey, Buffer.from(signature, "base64url")), true);
});

test("P1: disposable private Ed25519 PKCS8 clone is wiped without dispatch to mutable Buffer.fill", (t) => {
  const x = fixture(t, "private-wipe");
  const original = Buffer.prototype.fill;
  let interceptedKey = false;
  Buffer.prototype.fill = function(value, ...args) {
    if (this.length === 48 && this[0] === 0x30) {
      // Do not retain/log private bytes; prove an actual native disposable
      // Ed25519 private identity is readable inside the malicious hook.
      try {
        const candidate = crypto.createPrivateKey({
          key: Buffer.from(this), type: "pkcs8", format: "der",
        });
        interceptedKey ||= crypto.KeyObject.prototype.equals.call(
          crypto.createPublicKey(candidate), x.custodian.publicKey);
      } catch { /* unrelated buffer */ }
    }
    return original.call(this, value, ...args);
  };
  try {
    const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
    const challenge = x.offer();
    assert.ok(c.attest(challenge.request, challenge.ownerLease).floor.signature,
      "normal native Ed25519 signing still works");
  } finally {
    Buffer.prototype.fill = original;
  }
  assert.equal(interceptedKey, false,
    "no mutable JS prototype method may observe original PKCS8 plaintext");
});

test("P2: a failed real SQLite pin cannot be resurrected by malicious WeakMap.get", (t) => {
  const x = fixture(t, "pin-resurrection");
  const open = fs.openSync;
  const held = new Map();
  fs.openSync = (file, ...args) => {
    const fd = open(file, ...args);
    if (file === x.paths.databasePath || file === x.paths.anchorDatabasePath) {
      held.set(file, { file, fd, identity: fs.fstatSync(fd, { bigint: true }), failed: false });
    }
    return fd;
  };
  let c;
  try { c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config)); }
  finally { fs.openSync = open; }
  assert.equal(held.size, 2, "real SQLite identity descriptors captured");
  const lstat = fs.lstatSync;
  let rejectedPhysicalPin = false;
  fs.lstatSync = (file, ...args) => {
    if (file === x.paths.anchorDatabasePath && !rejectedPhysicalPin) {
      rejectedPhysicalPin = true;
      throw Object.assign(new Error("test-only physical pin read failed"), { code: "EIO" });
    }
    return lstat(file, ...args);
  };
  try {
    const probe = x.offer();
    assert.throws(() => c.attest(probe.request, probe.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally { fs.lstatSync = lstat; }
  assert.equal(rejectedPhysicalPin, true);
  const originalGet = WeakMap.prototype.get;
  let forgedReads = 0;
  WeakMap.prototype.get = function(key) {
    if (key && typeof key.name === "string" && held.has(key.name)) {
      forgedReads++;
      return { ...held.get(key.name), failed: false };
    }
    return originalGet.call(this, key);
  };
  try {
    assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
      "native poisoned pin cannot be resurrected through a prototype hook");
  } finally { WeakMap.prototype.get = originalGet; }
  assert.equal(forgedReads, 0, "custodian must use the early native WeakMap.get");
});

test("P2: forged Array.map/push cannot persist unsigned GENESIS sequence B under signed A", (t) => {
  const x = fixture(t, "genesis-array-push");
  const originalPush = Array.prototype.push;
  const originalMap = Array.prototype.map;
  let forgedValues = 0;
  // Parent 8ed uses a mutable Array.map on the fixed SQLite field list.
  // A transitional implementation used a mutable Array.push instead.
  Array.prototype.map = function(callback, thisArg) {
    if (this.length === 8 && this[0] === "sequence" && this[7] === "journal_tip") {
      forgedValues++;
      return Reflect.apply(originalMap, this, [
        (field, index, array) => field === "sequence"
          ? 2 : callback.call(thisArg, field, index, array),
      ]);
    }
    return Reflect.apply(originalMap, this, [callback, thisArg]);
  };
  Array.prototype.push = function (...items) {
    // In the vulnerable implementation, the first argument to SQLite's
    // floor-value array is GENESIS.sequence=1. Change that to 2 after the
    // genuine Ed25519 owner signature has already verified sequence 1.
    if (this.length === 0 && items.length === 1 && items[0] === 1) {
      forgedValues++;
      return Reflect.apply(originalPush, this, [2]);
    }
    return Reflect.apply(originalPush, this, items);
  };
  let c;
  try { c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config)); }
  finally {
    Array.prototype.map = originalMap;
    Array.prototype.push = originalPush;
  }
  assert.equal(forgedValues, 0, "trusted SQLite binding must not call mutable Array.map/push");
  assert.equal(c.retainedMinimum().sequence, 1,
    "persisted GENESIS must match owner-signed sequence 1");
});
