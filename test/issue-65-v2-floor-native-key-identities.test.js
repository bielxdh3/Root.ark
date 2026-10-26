"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Zk1V2CheckpointRemoteFloor } =
  require("../src/services/zk1V2CheckpointRemoteFloor");

const signingKeys = () => crypto.generateKeyPairSync("ed25519");

test("V2 independent floor cannot bootstrap when CAS and FLOOR are the same signer", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-floor-key-boundary-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cas = signingKeys();
  const witness = signingKeys();
  const owner = signingKeys();
  const config = {
    bootstrapNew: true,
    scope: { account_id: crypto.randomBytes(16),
      compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) },
    casPublicKey: cas.publicKey, floorPublicKey: cas.publicKey,
    ownerPublicKey: owner.publicKey, witnessPrivateKey: witness.privateKey,
    baseHeadDigest: crypto.randomBytes(32),
    baseCheckpointDigest: crypto.randomBytes(32),
  };
  assert.throws(() => new Zk1V2CheckpointRemoteFloor(
    path.join(dir, "same-signer.sqlite"), config),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
});

test("V2 floor restart rejects CAS signer substituted with spoofed KeyObject.export", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-floor-key-rollback-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cas = signingKeys();
  const floor = signingKeys();
  const owner = signingKeys();
  const witness = signingKeys();
  const filename = path.join(dir, "trusted-floor.sqlite");
  const config = {
    scope: { account_id: crypto.randomBytes(16),
      compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) },
    casPublicKey: cas.publicKey, floorPublicKey: floor.publicKey,
    ownerPublicKey: owner.publicKey, witnessPrivateKey: witness.privateKey,
    baseHeadDigest: crypto.randomBytes(32),
    baseCheckpointDigest: crypto.randomBytes(32),
  };
  const original = new Zk1V2CheckpointRemoteFloor(filename,
    { ...config, bootstrapNew: true });
  original.close();
  if (process.platform !== "win32") fs.chmodSync(filename, 0o600);
  const legitimate = new Zk1V2CheckpointRemoteFloor(filename,
    { ...config, bootstrapNew: false });
  legitimate.close();

  const forged = signingKeys().publicKey;
  forged.export = () => cas.publicKey.export({ type: "spki", format: "der" });
  assert.throws(() => new Zk1V2CheckpointRemoteFloor(filename,
    { ...config, bootstrapNew: false, casPublicKey: forged }),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/,
  "a writable KeyObject.export must not launder another CAS signer at restart");
});
