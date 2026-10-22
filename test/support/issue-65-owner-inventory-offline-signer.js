"use strict";

// Intentionally separate process: its private Ed25519 key never enters the
// repository server's process or a test bridge. Only public proof is emitted.
const crypto = require("node:crypto");
const { SCHEMA, signOwnerInventoryCheckpoint, checkpointDigest } =
  require("../../src/crypto/rootark-zk1-owner-inventory-trust-head");

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { input += chunk; if (input.length > 65536) process.exit(2); });
process.stdin.on("end", () => {
  try {
    const request = JSON.parse(input);
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const checkpoints = [];
    for (const item of request.heads) {
      const previous = checkpoints.at(-1);
      checkpoints.push(signOwnerInventoryCheckpoint({
        ownerPrivateKey: privateKey,
        payload: { schema: SCHEMA, ...request.scope,
          inventory_signer_key_id: request.inventorySignerKeyId,
          inventory_spki_sha256: request.inventorySpkiSha256,
          counter: checkpoints.length + 1, inventory_sequence: item.sequence,
          inventory_root: item.root, snapshot_sha256: item.snapshotSha256,
          previous_checkpoint_digest: previous ? checkpointDigest(previous) : null,
          issued_at: item.issuedAt, expires_at: item.expiresAt },
      }));
    }
    process.stdout.write(JSON.stringify({
      ownerSpki: publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
      independentOwnerSpkiSha256: crypto.createHash("sha256")
        .update(publicKey.export({ type: "spki", format: "der" })).digest("hex"),
      independentRetainedCheckpointDigest: checkpointDigest(checkpoints.at(-1)),
      checkpoints,
    }));
  } catch (_) { process.exitCode = 2; }
});
