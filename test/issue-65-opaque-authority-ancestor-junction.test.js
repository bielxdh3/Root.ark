"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { Zk1OpaqueCatalogIndependentFloorLedger,
  createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { Zk1OpaqueCatalogCasLedger } =
  require("../src/services/zk1OpaqueCatalogCasLedger");

function redirectedPath(t, leaf) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-authority-ancestor-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true,
    maxRetries: 10, retryDelay: 100 }));
  const real = path.join(root, "real");
  const privateDir = path.join(real, "private");
  fs.mkdirSync(privateDir, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(privateDir, 0o700);
  const alias = path.join(root, "alias");
  fs.symlinkSync(real, alias, process.platform === "win32" ? "junction" : "dir");
  // The immediate parent appears to be a regular directory, while its
  // ancestor resolves into a different authority's SQLite storage tree.
  const redirected = path.join(alias, "private", leaf);
  const actual = path.join(privateDir, leaf);
  assert.equal(fs.lstatSync(path.dirname(redirected)).isSymbolicLink(), false);
  return { redirected, actual };
}

function scope() {
  return { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("ancestor-junction"), keyring_id: crypto.randomBytes(16) };
}

test("independent floor bootstrap refuses an ancestor junction before SQLite writes", (t) => {
  const fixture = redirectedPath(t, "floor.sqlite");
  const signer = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const catalog = crypto.generateKeyPairSync("ed25519");
  let opened;
  try {
    assert.throws(() => { opened = new Zk1OpaqueCatalogIndependentFloorLedger(
      fixture.redirected, { bootstrapNew: true, trustedScope: scope(),
        signingPrivateKey: signer.privateKey, casSignerPublicKey: cas.publicKey,
        catalogSignerPublicKey: catalog.publicKey }); }, /ZK_OPAQUE_FLOOR_UNAVAILABLE/);
  } finally { opened?.db.close(); }
  assert.equal(fs.existsSync(fixture.actual), false,
    "a junction may never redirect floor bootstrap into a foreign directory");
});

test("catalog CAS bootstrap refuses an ancestor junction before SQLite writes", (t) => {
  const fixture = redirectedPath(t, "cas.sqlite");
  const trustedScope = scope();
  const signer = crypto.generateKeyPairSync("ed25519");
  const floor = crypto.generateKeyPairSync("ed25519");
  const catalog = crypto.generateKeyPairSync("ed25519");
  const independentFloor = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:65534/", ca: Buffer.from("test"),
    clientKey: Buffer.from("test"), clientCert: Buffer.from("test"),
    serverFingerprint256: Array(32).fill("AA").join(":"),
    floorPublicKey: floor.publicKey, casSignerPublicKey: signer.publicKey, trustedScope,
  });
  let opened;
  try {
    assert.throws(() => { opened = new Zk1OpaqueCatalogCasLedger(fixture.redirected,
      { bootstrapNew: true, signingPrivateKey: signer.privateKey,
        catalogSignerPublicKey: catalog.publicKey, trustedScope,
        minimumHead: { sequence: 0, digest: Buffer.alloc(32) },
        independentFloor }); }, /ZK_OPAQUE_CAS_UNAVAILABLE/);
  } finally {
    if (opened) { opened.ready.catch(() => {}); opened.db.close(); }
  }
  assert.equal(fs.existsSync(fixture.actual), false,
    "a junction may never redirect CAS bootstrap into a foreign directory");
});
