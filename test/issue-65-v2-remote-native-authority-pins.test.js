"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { OpaqueCheckpointV2Authority } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");

test("remote V2 CAS cannot bootstrap a FLOOR authority with the same native signer and forged export", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-remote-native-pin-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  let opened;
  t.after(() => {
    opened?.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  const sign = () => crypto.generateKeyPairSync("ed25519");
  const cas = sign();
  const independentFloor = sign();
  const checkpoint = sign();
  const owner = sign();
  const witness = sign();
  const copiedCasAsFloor = crypto.createPublicKey(cas.privateKey);
  copiedCasAsFloor.export = () => independentFloor.publicKey.export({
    type: "spki", format: "der",
  });
  const opts = { role: "CAS", bootstrapNew: true,
    scope: { account_id: crypto.randomBytes(16),
      compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) },
    signingPrivateKey: cas.privateKey, casSignerPublicKey: cas.publicKey,
    floorSignerPublicKey: copiedCasAsFloor,
    checkpointPublicKey: checkpoint.publicKey,
    ownerPublicKey: owner.publicKey,
    ownerTrust: { genesisDigest: crypto.randomBytes(32),
      pinnedWitness: { keyId: crypto.randomBytes(16),
        publicKey: witness.publicKey },
      minimumHead: { revision: 1, witnessSequence: 1,
        digest: crypto.randomBytes(32) },
      freshWitnessHead: async () => Buffer.alloc(0) },
    baseDigest: crypto.randomBytes(32),
    baseCheckpoint: crypto.randomBytes(32),
  };
  assert.throws(() => { opened = new OpaqueCheckpointV2Authority(
    path.join(dir, "forged-roles.sqlite"), opts); },
  /ZK_CHECKPOINT_V2_UNAVAILABLE/,
  "distinct DER advertised by override must not satisfy independent CAS/FLOOR pins");
});
