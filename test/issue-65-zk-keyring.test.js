"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const z = require("../src/crypto/rootark-zk-1");
const k = require("../src/crypto/rootark-zk-keyring");

const gen = () => z.hpkeSuite().kem.generateKeyPair();
const ctx = (m, deviceId, epoch, extra = {}) => ({ accountId: m.account_id, deviceId, epoch, ...extra });
const rejects = (promise, code) => assert.rejects(promise, (e) => e instanceof z.RootarkZkError && (!code || e.code === code));
const throwsCode = (fn, code) => assert.throws(fn, (e) => e instanceof z.RootarkZkError && (!code || e.code === code));
const clone = (value) => JSON.parse(JSON.stringify(value));

async function setup() {
  const ring = k.createAccountKeyring();
  const a = await gen();
  const b = await gen();
  const wa = await k.enrollDevice(ring, a.publicKey, "dev-a");
  const wb = await k.enrollDevice(ring, b.publicKey, "dev-b");
  return { ring, a, b, wa, wb };
}

test("create and enroll: device opens epoch 1 key; manifest has no secrets", async () => {
  const { ring, a, wa } = await setup();
  const m = k.exportManifest(ring);
  const key = await k.openEpochKey(wa, a.privateKey, ctx(m, "dev-a", 1));
  assert.deepEqual(key, ring.epochKeys[0].key);
  assert.equal(ring.rootKey.length, 32);
  const json = JSON.stringify(m);
  assert.ok(!json.includes(ring.rootKey.toString("base64url")));
  assert.ok(!json.includes(ring.epochKeys[0].key.toString("base64url")));
  assert.deepEqual(Object.keys(m).sort(), ["account_id", "current_epoch", "devices", "epochs", "suite", "type", "version", "wraps"]);
});

test("enroll accepts raw 32-byte public key and rejects bad input and duplicates", async () => {
  const ring = k.createAccountKeyring();
  const a = await gen();
  const raw = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(a.publicKey));
  const wrap = await k.enrollDevice(ring, raw, "dev-a");
  assert.deepEqual(await k.openEpochKey(wrap, a.privateKey, ctx(ring.manifest, "dev-a", 1)), ring.epochKeys[0].key);
  await rejects(k.enrollDevice(ring, raw, "dev-a"), "DUPLICATE_DEVICE_ID");
  await rejects(k.enrollDevice(ring, Buffer.alloc(5), "dev-x"), "INVALID_DEVICE_PUBLIC_KEY");
  await rejects(k.enrollDevice(ring, raw, "bad id!"), "INVALID_DEVICE_ID");
  await rejects(k.enrollDevice(ring, raw, "__proto__"), "INVALID_DEVICE_ID");
});

test("openEpochKey rejects wrong key, device, epoch, account, and tampering", async () => {
  const { ring, a, b, wa } = await setup();
  const m = k.exportManifest(ring);
  await rejects(k.openEpochKey(wa, b.privateKey, ctx(m, "dev-a", 1)));
  await rejects(k.openEpochKey(wa, a.privateKey, ctx(m, "dev-b", 1)), "WRAP_SCOPE_MISMATCH");
  await rejects(k.openEpochKey(wa, a.privateKey, ctx(m, "dev-a", 2)), "WRAP_SCOPE_MISMATCH");
  // relabelled wrap: claims another epoch/device, AAD binding must still fail
  await rejects(k.openEpochKey({ ...wa, epoch: 2 }, a.privateKey, ctx(m, "dev-a", 2)));
  await rejects(k.openEpochKey({ ...wa, device_id: "dev-b" }, a.privateKey, ctx(m, "dev-b", 1)));
  const other = k.createAccountKeyring();
  await rejects(k.openEpochKey(wa, a.privateKey, ctx(other.manifest, "dev-a", 1)));
  const ct = Buffer.from(wa.ciphertext, "base64url");
  ct[0] ^= 1;
  await rejects(k.openEpochKey({ ...wa, ciphertext: ct.toString("base64url") }, a.privateKey, ctx(m, "dev-a", 1)));
  const enc = Buffer.from(wa.enc, "base64url");
  enc[0] ^= 1;
  await rejects(k.openEpochKey({ ...wa, enc: enc.toString("base64url") }, a.privateKey, ctx(m, "dev-a", 1)));
  await rejects(k.openEpochKey({ ...wa, extra: 1 }, a.privateKey, ctx(m, "dev-a", 1)), "INVALID_WRAP");
  await rejects(k.openEpochKey(wa, a.privateKey, null), "INVALID_CONTEXT");
});

test("revoke rotates epoch: revoked device cannot open new key, remaining opens old and new", async () => {
  const { ring, a, b, wa } = await setup();
  const rev = await k.revokeDevice(ring, "dev-a");
  assert.equal(rev.epoch, 2);
  assert.deepEqual(rev.wraps.map((w) => w.device_id), ["dev-b"]);
  const m = k.exportManifest(ring);
  assert.equal(m.current_epoch, 2);
  assert.deepEqual(m.epochs, [1, 2]);
  assert.equal(m.devices.find((d) => d.device_id === "dev-a").revoked_at_epoch, 2);

  const newKey = await k.openEpochKeyFromManifest(m, b.privateKey, "dev-b", 2);
  const oldKey = await k.openEpochKeyFromManifest(m, b.privateKey, "dev-b", 1);
  assert.deepEqual(newKey, ring.epochKeys[1].key);
  assert.deepEqual(oldKey, ring.epochKeys[0].key);
  assert.notDeepEqual(newKey, oldKey);

  // revoked device: no epoch-2 wrap exists; reusing another device's wrap fails scope/AAD
  await rejects(k.openEpochKeyFromManifest(m, a.privateKey, "dev-a", 2), "WRAP_NOT_FOUND");
  await rejects(k.openEpochKey(rev.wraps[0], a.privateKey, ctx(m, "dev-a", 2)), "WRAP_SCOPE_MISMATCH");
  await rejects(k.openEpochKey({ ...rev.wraps[0], device_id: "dev-a" }, a.privateKey, ctx(m, "dev-a", 2)));
  await rejects(k.openEpochKey({ ...rev.wraps[0], device_id: "dev-a" }, a.privateKey, ctx(m, "dev-a", 2, { revokedAtEpoch: 2 })), "DEVICE_REVOKED");
  // forward-only: the revoked device still holds its already-issued epoch 1 wrap
  assert.deepEqual(await k.openEpochKey(wa, a.privateKey, ctx(m, "dev-a", 1, { revokedAtEpoch: 2 })), ring.epochKeys[0].key);
  await rejects(k.revokeDevice(ring, "dev-a"), "DEVICE_ALREADY_REVOKED");
  await rejects(k.revokeDevice(ring, "nope"), "UNKNOWN_DEVICE");
});

test("enrollment after rotation is non-retroactive; epoch list stays explicit", async () => {
  const { ring, b } = await setup();
  await k.revokeDevice(ring, "dev-a");
  const c = await gen();
  await k.enrollDevice(ring, c.publicKey, "dev-c");
  await k.revokeDevice(ring, "dev-b");
  const m = k.exportManifest(ring);
  assert.deepEqual(m.epochs, [1, 2, 3]);
  assert.deepEqual(await k.openEpochKeyFromManifest(m, c.privateKey, "dev-c", 3), ring.epochKeys[2].key);
  await rejects(k.openEpochKeyFromManifest(m, c.privateKey, "dev-c", 1), "WRAP_NOT_FOUND");
  await rejects(k.openEpochKeyFromManifest(m, b.privateKey, "dev-b", 3), "WRAP_NOT_FOUND");
  assert.deepEqual(await k.openEpochKeyFromManifest(m, b.privateKey, "dev-b", 2), ring.epochKeys[1].key);
});

test("validateManifest accepts a valid manifest and survives JSON round trip", async () => {
  const { ring } = await setup();
  await k.revokeDevice(ring, "dev-a");
  const m = k.exportManifest(ring);
  assert.deepEqual(k.validateManifest(clone(m)), m);
});

test("validateManifest rejects unknown versions, types, suites and shape changes", async () => {
  const { ring } = await setup();
  const m = k.exportManifest(ring);
  const mut = (fn) => { const c = clone(m); fn(c); return c; };
  throwsCode(() => k.validateManifest(mut((c) => { c.version = 2; })), "UNSUPPORTED_MANIFEST_VERSION");
  throwsCode(() => k.validateManifest(mut((c) => { c.version = "1"; })), "UNSUPPORTED_MANIFEST_VERSION");
  throwsCode(() => k.validateManifest(mut((c) => { c.type = "x"; })), "INVALID_MANIFEST");
  throwsCode(() => k.validateManifest(mut((c) => { c.suite = "rootark-zk-2"; })), "UNSUPPORTED_SUITE");
  throwsCode(() => k.validateManifest(mut((c) => { c.extra = 1; })), "INVALID_MANIFEST");
  throwsCode(() => k.validateManifest(mut((c) => { delete c.wraps; })), "INVALID_MANIFEST");
  throwsCode(() => k.validateManifest(mut((c) => { c.devices[0].extra = 1; })), "INVALID_MANIFEST");
  throwsCode(() => k.validateManifest(mut((c) => { c.account_id = "AAAA"; })), "INVALID_MANIFEST");
  throwsCode(() => k.validateManifest(null), "INVALID_MANIFEST");
  throwsCode(() => k.validateManifest([]), "INVALID_MANIFEST");
});

test("validateManifest rejects duplicate deviceIds and duplicate/missing/orphan wraps", async () => {
  const { ring } = await setup();
  const m = k.exportManifest(ring);
  const mut = (fn) => { const c = clone(m); fn(c); return c; };
  throwsCode(() => k.validateManifest(mut((c) => { c.devices[1].device_id = "dev-a"; })), "DUPLICATE_DEVICE_ID");
  throwsCode(() => k.validateManifest(mut((c) => { c.wraps.push({ ...c.wraps[0] }); })), "DUPLICATE_WRAP");
  throwsCode(() => k.validateManifest(mut((c) => { c.wraps.pop(); })), "MISSING_WRAP");
  throwsCode(() => k.validateManifest(mut((c) => { c.wraps[0].device_id = "ghost"; })), "INVALID_MANIFEST");
});

test("validateManifest rejects non-monotonic epochs and wraps issued to revoked devices", async () => {
  const { ring } = await setup();
  await k.revokeDevice(ring, "dev-a");
  const m = k.exportManifest(ring);
  const mut = (fn) => { const c = clone(m); fn(c); return c; };
  throwsCode(() => k.validateManifest(mut((c) => { c.epochs = [1, 3]; c.current_epoch = 3; })), "NON_MONOTONIC_EPOCHS");
  throwsCode(() => k.validateManifest(mut((c) => { c.epochs = [2, 1]; })), "NON_MONOTONIC_EPOCHS");
  throwsCode(() => k.validateManifest(mut((c) => { c.epochs = [1, 1, 2]; })), "NON_MONOTONIC_EPOCHS");
  throwsCode(() => k.validateManifest(mut((c) => { c.current_epoch = 1; })), "NON_MONOTONIC_EPOCHS");
  throwsCode(() => k.validateManifest(mut((c) => { c.epochs = [0, 1]; })), "INVALID_EPOCH");
  // server injecting a post-rotation wrap for the revoked device
  const forged = mut((c) => {
    c.wraps.push({ ...c.wraps.find((w) => w.device_id === "dev-b" && w.epoch === 2), device_id: "dev-a" });
  });
  throwsCode(() => k.validateManifest(forged), "WRAP_FOR_REVOKED_DEVICE");
  // a non-revoked device losing its current-epoch wrap
  const m2 = k.exportManifest((await setup()).ring);
  m2.wraps = m2.wraps.filter((w) => w.device_id !== "dev-b");
  throwsCode(() => k.validateManifest(m2), "MISSING_WRAP");
});

test("validateManifest rejects prototype-polluting keys at any depth", async () => {
  const { ring } = await setup();
  const m = k.exportManifest(ring);
  for (const key of ["__proto__", "constructor", "prototype"]) {
    const top = clone(m);
    Object.defineProperty(top, key, { value: { x: 1 }, enumerable: true, configurable: true, writable: true });
    throwsCode(() => k.validateManifest(top), "INVALID_MAP_KEY");
    const deep = clone(m);
    Object.defineProperty(deep.devices[0], key, { value: 1, enumerable: true, configurable: true, writable: true });
    throwsCode(() => k.validateManifest(deep), "INVALID_MAP_KEY");
  }
  const parsed = JSON.parse('{"__proto__":{"polluted":true},' + JSON.stringify(m).slice(1));
  throwsCode(() => k.validateManifest(parsed), "INVALID_MAP_KEY");
  assert.equal({}.polluted, undefined);
});
