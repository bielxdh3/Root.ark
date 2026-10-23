"use strict";
// Node24 integration-only separate OS authority host. Never a prod launcher.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const z = require("../../src/crypto/rootark-zk-1");
const {
  OpaqueCheckpointV2Authority, createOpaqueCheckpointV2HttpsServer,
} = require("../../src/services/zk1OpaqueCheckpointV2Remote");
const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const decode = (value) => Buffer.from(value, "base64url");
async function main() {
  const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const file = (name) => fs.readFileSync(path.join(cfg.dir, name));
  const scope = Object.fromEntries(Object.entries(cfg.scope)
    .map(([name, value]) => [name, decode(value)]));
  const witnessSigner = crypto.createPrivateKey(file("fixture-witness.key"));
  const witnessKeyId = decode(cfg.witnessKeyId);
  const liveManifestDigest = decode(cfg.liveManifestDigest);
  const ownerTrust = {
    genesisDigest: decode(cfg.genesis),
    pinnedWitness: { keyId: witnessKeyId,
      publicKey: crypto.createPublicKey(witnessSigner) },
    minimumHead: { revision: 1, witnessSequence: 1, digest: decode(cfg.genesis) },
    async freshWitnessHead({ nonce }) {
      const body = { type: "rootark-recovery-witness-head/v1",
        witness_key_id: witnessKeyId, ...scope,
        current_revision: cfg.liveRevision,
        current_manifest_digest: liveManifestDigest,
        witness_sequence: cfg.liveRevision, nonce,
        observed_at: Math.floor(Date.now() / 1000),
        status: "committed", pending_reservation_id: null };
      return z.encodeDeterministic({ ...body, signature: crypto.sign(null,
        Buffer.concat([WITNESS_DOMAIN, await z.encodeDeterministic(body)]),
        witnessSigner) });
    },
  };
  const ledger = new OpaqueCheckpointV2Authority(
    path.join(cfg.dir, cfg.role === "CAS"
      ? "v2-cas-process.sqlite" : "v2-floor-process.sqlite"), {
      role: cfg.role, bootstrapNew: cfg.bootstrapNew, scope,
      signingPrivateKey: crypto.createPrivateKey(file(cfg.role === "CAS"
        ? "fixture-v2cas.key" : "fixture-v2floor.key")),
      casSignerPublicKey: crypto.createPublicKey(file("fixture-v2cas.pub")),
      floorSignerPublicKey: crypto.createPublicKey(file("fixture-v2floor.pub")),
      checkpointPublicKey: crypto.createPublicKey(file("fixture-checkpoint.pub")),
      ownerPublicKey: crypto.createPublicKey(file("fixture-owner.pub")),
      ownerTrust, baseDigest: decode(cfg.oldDigest),
      baseCheckpoint: decode(cfg.oldCheckpoint),
    });
  const certificate = cfg.role === "CAS" ? "v2cas" : "v2floor";
  const server = createOpaqueCheckpointV2HttpsServer({
    ledger, tlsKey: file(certificate + ".key"),
    tlsCert: file(certificate + ".pem"), clientCa: file("ca.pem"),
    clientFingerprint256: new crypto.X509Certificate(file("client.pem")).fingerprint256,
    dropAfterCommitOnce: cfg.role === "CAS" && !!cfg.dropCommit,
  });
  process.on("message", (msg) => {
    if (msg !== "stop") return;
    server.closeAllConnections();
    server.close(() => {
      ledger.close();
      process.send?.({ stopped: true }, () => process.exit(0));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  process.send?.({ port: server.address().port });
}
main().catch((error) => {
  process.send?.({ error: error.code || error.message }, () => process.exit(1));
});
