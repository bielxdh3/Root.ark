"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { Zk1OpaqueCatalogCasLedger } = require("../src/services/zk1OpaqueCatalogCasLedger");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");

const sha = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

test("CAS bootstrap does not write to a substituted foreign SQLite after O_EXCL", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-cas-bootstrap-race-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const owned = path.join(root, "owned");
  fs.mkdirSync(owned, { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(owned, 0o700);
  const target = path.join(owned, "cas.sqlite");
  const foreign = path.join(root, "foreign.sqlite");
  const db = new Database(foreign);
  db.exec("CREATE TABLE foreign_identity (id INTEGER PRIMARY KEY, marker TEXT);");
  db.prepare("INSERT INTO foreign_identity VALUES (1, 'unmodified')").run();
  db.close();
  if (process.platform !== "win32") fs.chmodSync(foreign, 0o600);
  const originalHash = sha(foreign);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("cas-bootstrap-race"), keyring_id: crypto.randomBytes(16) };
  const signer = crypto.generateKeyPairSync("ed25519");
  const catalog = crypto.generateKeyPairSync("ed25519");
  const floor = crypto.generateKeyPairSync("ed25519");
  const independentFloor = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:65534/", ca: Buffer.from("fixture"),
    clientKey: Buffer.from("fixture"), clientCert: Buffer.from("fixture"),
    serverFingerprint256: Array(32).fill("AA").join(":"),
    floorPublicKey: floor.publicKey, casSignerPublicKey: signer.publicKey,
    trustedScope: scope,
  });
  const realOpen = fs.openSync;
  const realClose = fs.closeSync;
  let createdFd;
  let swapped = false;
  fs.openSync = function (name, flags, ...rest) {
    const fd = realOpen.call(fs, name, flags, ...rest);
    if (name === target && (flags & fs.constants.O_EXCL)) createdFd = fd;
    return fd;
  };
  fs.closeSync = function (fd, ...rest) {
    const result = realClose.call(fs, fd, ...rest);
    if (fd === createdFd && !swapped) {
      swapped = true;
      fs.renameSync(target, path.join(owned, "original.sqlite"));
      fs.linkSync(foreign, target);
    }
    return result;
  };
  let opened;
  let denied;
  try {
    opened = new Zk1OpaqueCatalogCasLedger(target, {
      bootstrapNew: true, signingPrivateKey: signer.privateKey,
      catalogSignerPublicKey: catalog.publicKey, trustedScope: scope,
      minimumHead: { sequence: 0, digest: Buffer.alloc(32) }, independentFloor,
    });
  } catch (error) {
    denied = error;
  } finally {
    fs.openSync = realOpen;
    fs.closeSync = realClose;
    if (opened) { opened.ready.catch(() => {}); opened.db.close(); }
  }
  assert.equal(swapped, true, "attack must replace the exact file after its exclusive bootstrap");
  assert.equal(sha(foreign), originalHash,
    "an untrusted hardlink must not receive new authority tables or SQLite journal writes");
  const reader = new Database(foreign, { readonly: true, fileMustExist: true });
  try {
    assert.deepEqual(reader.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all(),
      [{ name: "foreign_identity" }]);
  } finally { reader.close(); }
  assert.match(denied?.message || "", /ZK_OPAQUE_CAS_UNAVAILABLE/,
    "substituted SQLite must be rejected before the authority is initialized");
});
