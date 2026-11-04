"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { Zk1OpaqueCatalogIndependentFloorLedger } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { Zk1OpaqueCatalogCasLedger } =
  require("../src/services/zk1OpaqueCatalogCasLedger");

const hash = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

test("independent floor rejects unrelated SQLite on startup without mutating its bytes", () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-cas-ro-preflight-"));
  if (process.platform !== "win32") fs.chmodSync(folder, 0o700);
  const filename = path.join(folder, "floor.sqlite");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("cas-preflight"), keyring_id: crypto.randomBytes(16) };
  const signer = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const catalog = crypto.generateKeyPairSync("ed25519");
  const options = { trustedScope: scope, signingPrivateKey: signer.privateKey,
    casSignerPublicKey: cas.publicKey, catalogSignerPublicKey: catalog.publicKey };
  try {
    const foreign = new Database(filename);
    foreign.exec("CREATE TABLE foreign_identity (id INTEGER PRIMARY KEY, marker TEXT)");
    foreign.prepare("INSERT INTO foreign_identity VALUES (1, 'unaltered')").run();
    foreign.close();
    if (process.platform !== "win32") fs.chmodSync(filename, 0o600);
    const before = hash(fs.readFileSync(filename));
    assert.throws(() => new Zk1OpaqueCatalogIndependentFloorLedger(filename, {
      ...options, bootstrapNew: false,
    }), /ZK_OPAQUE_FLOOR_UNAVAILABLE/);
    assert.equal(hash(fs.readFileSync(filename)), before,
      "a rejected database must never acquire CAS tables or SQLite page writes");
    const check = new Database(filename, { readonly: true, fileMustExist: true });
    assert.deepEqual(check.prepare("SELECT name FROM sqlite_master WHERE type='table'").all(),
      [{ name: "foreign_identity" }]);
    check.close();
  } finally { fs.rmSync(folder, { recursive: true, force: true }); }
});

test("catalog CAS rejects unrelated SQLite without a write before independent floor contact", () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-cas-db-preflight-"));
  if (process.platform !== "win32") fs.chmodSync(folder, 0o700);
  const filename = path.join(folder, "cas.sqlite");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("cas-preflight"), keyring_id: crypto.randomBytes(16) };
  const authority = crypto.generateKeyPairSync("ed25519");
  const floor = crypto.generateKeyPairSync("ed25519");
  const catalog = crypto.generateKeyPairSync("ed25519");
  const independentFloor = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:65534/", ca: Buffer.from("test"),
    clientKey: Buffer.from("test"), clientCert: Buffer.from("test"),
    serverFingerprint256: Array(32).fill("AA").join(":"),
    floorPublicKey: floor.publicKey, casSignerPublicKey: authority.publicKey,
    trustedScope: scope,
  });
  try {
    const foreign = new Database(filename);
    foreign.exec("CREATE TABLE foreign_identity (id INTEGER PRIMARY KEY, marker TEXT)");
    foreign.close();
    if (process.platform !== "win32") fs.chmodSync(filename, 0o600);
    const before = hash(fs.readFileSync(filename));
    assert.throws(() => new Zk1OpaqueCatalogCasLedger(filename, {
      bootstrapNew: false, signingPrivateKey: authority.privateKey,
      catalogSignerPublicKey: catalog.publicKey, trustedScope: scope,
      minimumHead: { sequence: 0, digest: Buffer.alloc(32) }, independentFloor,
    }), /ZK_OPAQUE_CAS_UNAVAILABLE/);
    assert.equal(hash(fs.readFileSync(filename)), before);
  } finally { fs.rmSync(folder, { recursive: true, force: true }); }
});
