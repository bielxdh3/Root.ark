"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");

const subtle = crypto.webcrypto.subtle;
const GRANT = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const OWNER_EPOCH = Buffer.from("Root.ark/zk-1/browser-owner-epoch-head/v1\0");
const OWNER_EPOCH_HASH = Buffer.from("Root.ark/zk-1/browser-owner-epoch-head-hash/v1\0");
const WITNESS = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const GRANT_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key", "manifest_revision",
  "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const OWNER_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
  "revision", "manifestDigest", "epoch", "previousDigest"];
const b64 = (value) => Buffer.from(value).toString("base64url");
const sha = (value) => crypto.createHash("sha256").update(value).digest();
const rawKey = (key) => key.export({ type: "spki", format: "der" }).subarray(-32);
const publicKey = (key) => subtle.importKey("raw", rawKey(key), "Ed25519", true, ["verify"]);
const privateKey = (key) => subtle.importKey("pkcs8",
  key.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);

// The witness uses deterministic CBOR, like the live browser's encode().
function encode(value) {
  const head = (tag, n) => n < 24 ? Buffer.from([tag + n])
    : n < 256 ? Buffer.from([tag + 24, n])
      : n < 65536 ? Buffer.from([tag + 25, n >> 8, n & 255])
        : Buffer.from([tag + 26, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === "number") return head(0, value);
  if (typeof value === "string") {
    const utf8 = Buffer.from(value);
    return Buffer.concat([head(0x60, utf8.length), utf8]);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array)
    return Buffer.concat([head(0x40, value.byteLength), Buffer.from(value)]);
  if (Array.isArray(value)) return Buffer.concat([head(0x80, value.length),
    ...value.map(encode)]);
  const fields = Object.entries(value).map(([name, entry]) => [encode(name), encode(entry)])
    .sort(([left], [right]) => left.length - right.length || Buffer.compare(left, right));
  return Buffer.concat([head(0xa0, fields.length), ...fields.flat()]);
}

function raceCrypto(target, phase) {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let entered;
  const reached = new Promise((resolve) => { entered = resolve; });
  let intercepted = false;
  const webcrypto = {
    getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto),
    subtle: new Proxy(subtle, {
      get(native, name) {
        if (name !== "importKey") {
          const method = Reflect.get(native, name, native);
          return typeof method === "function" ? method.bind(native) : method;
        }
        return async (...args) => {
          if (!intercepted && args[0] === "raw"
            && Buffer.from(args[1]).equals(target)) {
            intercepted = true;
            const alreadyImported = phase === "after-import"
              ? await native.importKey(...args) : null;
            entered();
            await gate;
            return alreadyImported || native.importKey(...args);
          }
          return native.importKey(...args);
        };
      },
    }),
  };
  return { webcrypto, reached, release, wasIntercepted: () => intercepted };
}

function loadBrowser(webcrypto) {
  const source = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-browser-opaque-catalog-commit.js"), "utf8");
  // Run the real CommonJS module in this realm: exact() requires same-realm
  // plain objects, while the module receives a controlled WebCrypto boundary.
  const initialize = vm.runInThisContext("(function (module, require) {\n"
    + source + "\n})", { filename: "rootark-zk1-browser-opaque-catalog-commit.js" });
  const loaded = { exports: {} };
  initialize(loaded, (name) => {
    assert.equal(name, "node:crypto");
    return { webcrypto };
  });
  return loaded.exports;
}

async function fixture(historical = false) {
  const owner = crypto.generateKeyPairSync("ed25519");
  const authorized = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: b64(crypto.randomBytes(16)),
    compartment_id: b64(crypto.randomBytes(16)), keyring_id: b64(crypto.randomBytes(16)) };
  const manifestDigest = crypto.randomBytes(32);
  const oldDigest = crypto.randomBytes(32);
  const revision = historical ? 2 : 1;
  const grant = (device, rev, digest) => {
    const body = { schema: "rootark-zk1-browser-owner-device-grant/v1",
      ...scope, device_id: "device-A", authorization_key_id: b64(crypto.randomBytes(16)),
      authorization_public_key: b64(rawKey(device.publicKey)), manifest_revision: rev,
      manifest_digest: b64(digest), current_epoch: rev, enrolled_epoch: 1,
      revoked_at_epoch: null };
    const signed = Object.fromEntries(GRANT_FIELDS.map((name) => [name, body[name]]));
    return { ...body, signature: b64(crypto.sign(null,
      Buffer.concat([GRANT, Buffer.from(JSON.stringify(signed))]), owner.privateKey)) };
  };
  const current = grant(authorized, revision, manifestDigest);
  const historicalValid = grant(authorized, 1, oldDigest);
  const historyHeads = [];
  let predecessor = null;
  for (let rev = 1; rev <= revision; rev++) {
    const body = { schema: "rootark-zk1-browser-owner-epoch-head/v1",
      ...scope, revision: rev, manifestDigest: b64(rev === revision
        ? manifestDigest : oldDigest), epoch: rev, previousDigest: predecessor };
    const wire = Buffer.from(JSON.stringify(Object.fromEntries(
      OWNER_FIELDS.map((key) => [key, body[key]]))));
    const signature = crypto.sign(null, Buffer.concat([OWNER_EPOCH, wire]), owner.privateKey);
    historyHeads.push({ ...body, signature: b64(signature) });
    predecessor = b64(sha(Buffer.concat([OWNER_EPOCH_HASH, wire, signature])));
  }
  const witnessKeyId = crypto.randomBytes(16);
  const config = {
    origin: "https://example.test/", fetchImpl: async () => { throw Error("unused"); },
    ownerPublicKey: await publicKey(owner.publicKey),
    pinnedOwnerKeyHash: sha(rawKey(owner.publicKey)),
    pinnedOwnerHead: { revision, digest: manifestDigest, epoch: revision },
    signedDeviceGrant: current, devicePublicKey: await publicKey(authorized.publicKey),
    devicePrivateKey: await privateKey(authorized.privateKey),
    signerGrants: [current], ownerWitnessPublicKey: await publicKey(owner.publicKey),
    ownerWitnessKeyId: witnessKeyId,
    ownerWitnessProbe: async ({ nonce }) => {
      const statement = { type: "rootark-recovery-witness-head/v1",
        witness_key_id: witnessKeyId,
        account_id: Buffer.from(scope.account_id, "base64url"),
        compartment_id: Buffer.from(scope.compartment_id, "base64url"),
        keyring_id: Buffer.from(scope.keyring_id, "base64url"),
        current_revision: revision, current_manifest_digest: manifestDigest,
        witness_sequence: revision, nonce: Buffer.from(nonce), observed_at: 1000,
        status: "committed", pending_reservation_id: null };
      return encode({ ...statement, signature: crypto.sign(null,
        Buffer.concat([WITNESS, encode(statement)]), owner.privateKey) });
    },
    catalogAuthorityPublicKey: await publicKey(owner.publicKey),
    catalogProbe: async () => { throw Error("unused"); },
    minimumCatalogHead: { sequence: 0, digest: Buffer.alloc(32) },
    csrfToken: () => "csrf", isSessionCurrent: () => true,
    assertCurrent: async () => {}, nowSeconds: () => 1000,
    journalStore: { read: async () => {}, write: async () => {}, remove: async () => {} },
    ...(historical ? { historicalOwnerEpochHistory: {
      heads: historyHeads, grants: [historicalValid] } } : {}),
  };
  return { config, current, historicalValid, attacker, authorized, oldDigest,
    signatureChallenge: Buffer.from("signed authorized device challenge") };
}

async function assertAuthorizedKey(key, authorized, challenge) {
  const signature = crypto.sign(null, challenge, authorized.privateKey);
  assert.equal(await subtle.verify("Ed25519", key, signature, challenge), true);
}

for (const phase of ["before-import", "after-import"]) {
  test(`current signer: forged grant cannot swap public key ${phase} while importKey awaits`,
    async () => {
      const f = await fixture();
      const forged = { ...f.current,
        authorization_public_key: b64(rawKey(f.attacker.publicKey)) };
      f.config.signerGrants = [forged];
      const race = raceCrypto(rawKey(f.attacker.publicKey), phase);
      const client = loadBrowser(race.webcrypto).createClient(f.config);
      const result = client.verifyAuthorizedSigner("device-A", 1);
      await race.reached;
      forged.authorization_public_key = f.current.authorization_public_key;
      race.release();
      await assert.rejects(result, /ZK_BROWSER_CATALOG_UNVERIFIED/);
      assert.equal(race.wasIntercepted(), true);

      const approved = loadBrowser(crypto.webcrypto).createClient({
        ...f.config, signerGrants: [f.current] });
      await assertAuthorizedKey(await approved.verifyAuthorizedSigner("device-A", 1),
        f.authorized, f.signatureChallenge);
    });
}

test("current signer cannot replace the caller's roster or grant after configure", async () => {
  const f = await fixture();
  const forged = { ...f.current,
    authorization_public_key: b64(rawKey(f.attacker.publicKey)) };
  const roster = [forged];
  f.config.signerGrants = roster;
  const client = loadBrowser(crypto.webcrypto).createClient(f.config);
  // Neither replacing the array entry nor repairing the forged record after
  // client creation may retroactively authorize the original attacker key.
  roster.splice(0, 1, f.current);
  forged.authorization_public_key = f.current.authorization_public_key;
  await assert.rejects(client.verifyAuthorizedSigner("device-A", 1),
    /ZK_BROWSER_CATALOG_UNVERIFIED/);
});

test("historical owner grant is snapshotted before witness and awaited importKey", async () => {
  const f = await fixture(true);
  const forged = { ...f.historicalValid,
    authorization_public_key: b64(rawKey(f.attacker.publicKey)) };
  f.config.historicalOwnerEpochHistory.grants = [forged];
  const race = raceCrypto(rawKey(f.attacker.publicKey), "after-import");
  const client = loadBrowser(race.webcrypto).createClient(f.config);
  const result = client.verifyHistoricalSigner("device-A", 1, 1, f.oldDigest);
  await race.reached;
  forged.authorization_public_key = f.historicalValid.authorization_public_key;
  race.release();
  await assert.rejects(result, /ZK_BROWSER_CATALOG_UNVERIFIED/);
  assert.equal(race.wasIntercepted(), true);

  const approved = loadBrowser(crypto.webcrypto).createClient({
    ...f.config, historicalOwnerEpochHistory: {
      ...f.config.historicalOwnerEpochHistory, grants: [f.historicalValid] } });
  await assertAuthorizedKey(await approved.verifyHistoricalSigner("device-A", 1, 1,
    f.oldDigest), f.authorized, f.signatureChallenge);
});

test("historical roster and current signed device grant remain pinned after configure",
  async () => {
    const f = await fixture(true);
    const forged = { ...f.historicalValid,
      authorization_public_key: b64(rawKey(f.attacker.publicKey)) };
    f.config.historicalOwnerEpochHistory.grants = [forged];
    const client = loadBrowser(crypto.webcrypto).createClient(f.config);
    f.config.historicalOwnerEpochHistory.grants.splice(0, 1, f.historicalValid);
    forged.authorization_public_key = f.historicalValid.authorization_public_key;
    await assert.rejects(client.verifyHistoricalSigner("device-A", 1, 1, f.oldDigest),
      /ZK_BROWSER_CATALOG_UNVERIFIED/);

    // The owner/current device proof also uses the grant as it existed when
    // the client was configured, even after awaited witness verification.
    const current = loadBrowser(crypto.webcrypto).createClient({
      ...f.config, historicalOwnerEpochHistory: {
        ...f.config.historicalOwnerEpochHistory, grants: [f.historicalValid] } });
    f.config.signedDeviceGrant.authorization_public_key = b64(rawKey(f.attacker.publicKey));
    f.config.signedDeviceGrant.signature = b64(crypto.randomBytes(64));
    await assertAuthorizedKey(await current.verifyHistoricalSigner("device-A", 1, 1,
      f.oldDigest), f.authorized, f.signatureChallenge);
  });
