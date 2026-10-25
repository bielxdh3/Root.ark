"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const Database = require("better-sqlite3");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { Zk1WitnessCasAnchorFloor } = require("../src/services/zk1WitnessCasAnchorFloor");

test("actual standalone witness refuses signed-prefix floor rollback against separately owner-pinned head", async (t) => {
  // A runner's TEMP can be a junction or have an unsafe inherited DACL.
  const dir = require("./support/issue-65-private-authority-fixture")
    .createPrivateAuthorityFixture("rootark-witness-floor-standalone-");
  generateNativeFixtureCertificates(dir, { caSubject: "Standalone Witness CA",
    servers: ["server"], clients: ["allowed"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const witness = crypto.generateKeyPairSync("ed25519");
  const status = crypto.generateKeyPairSync("ed25519");
  const owner = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const witnessDb = path.join(dir, "recovery-witness.sqlite");
  const floorDb = path.join(dir, "cas-floor.sqlite");
  const terminalPath = path.join(dir, "real-signed-cas.log");
  const files = { witnessKey: path.join(dir, "witness-private.pem"),
    statusPub: path.join(dir, "status-public.pem"),
    ownerPub: path.join(dir, "owner-public.pem"),
    config: path.join(dir, "witness-config.json") };
  fs.writeFileSync(files.witnessKey, witness.privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(files.statusPub, status.publicKey.export({ type: "spki", format: "pem" }));
  fs.writeFileSync(files.ownerPub, owner.publicKey.export({ type: "spki", format: "pem" }));
  const ownWitness = new Zk1DurableWitnessLedger(witnessDb, {
    bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusPinned: { keyId: statusKeyId, publicKey: status.publicKey },
    statusProvider: { getTerminalProof: async () => { throw new Error("NOT_USED_IN_FLOOR_TEST"); } },
  });
  ownWitness.close();
  const floor = new Zk1WitnessCasAnchorFloor(floorDb, {
    bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey,
  });
  const anchor = new Zk1CasTerminalAnchor(terminalPath, {
    bootstrapNew: true, statusKeyId, statusPrivateKey: status.privateKey,
  });
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("witness"), keyring_id: crypto.randomBytes(16) };
  for (let i = 0; i < 2; i++) {
    const q = { ...scope, reservation_id: crypto.randomBytes(16) };
    const ticket = crypto.randomBytes(90);
    const manifest = crypto.randomBytes(90);
    anchor.prepare(q, ticket, "committed", manifest);
    await anchor.append(q, ticket, "committed", manifest, crypto.randomBytes(64));
  }
  floor.advance({ records: anchor.signedRecordPage({ afterSequence: 0 }) });
  const ownerRetained = { ...floor.head() };
  assert.equal(ownerRetained.sequence, 2);
  floor.close();
  const fingerprint = new crypto.X509Certificate(read("allowed.pem")).fingerprint256;
  const config = {
    listenHost: "127.0.0.1", listenPort: 0, bootstrapNew: false,
    dbPath: witnessDb, witnessKeyId: witnessKeyId.toString("base64url"),
    witnessPrivateKeyPath: files.witnessKey,
    statusKeyId: statusKeyId.toString("base64url"),
    statusPublicKeyPath: files.statusPub,
    serverKeyPath: path.join(dir, "server.key"),
    serverCertPath: path.join(dir, "server.pem"),
    clientCaPath: path.join(dir, "ca.pem"),
    principals: { [fingerprint]: { roles: ["cas-anchor"], scopes: [] } },
    cas: { endpoint: "https://localhost:44444/v1/terminal",
      caPath: path.join(dir, "ca.pem"),
      clientKeyPath: path.join(dir, "allowed.key"),
      clientCertPath: path.join(dir, "allowed.pem"),
      serverFingerprint256: new crypto.X509Certificate(read("server.pem")).fingerprint256 },
    casAnchorFloor: { dbPath: floorDb, trustedMinimumHead: ownerRetained },
  };
  const children = new Set();
  t.after(async () => {
    for (const child of children) {
      if (child.exitCode === null) {
        const exited = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await exited;
      }
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  async function start(candidate, expectReady, ownerPin = null, checkpointPin = null) {
    fs.writeFileSync(files.config, JSON.stringify(candidate), { mode: 0o600 });
    const child = spawn(process.execPath, [
      path.resolve(__dirname, "../scripts/zk1-witness-standalone.js"),
      "--config", files.config,
    ], { stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true,
      env: (() => {
        const env = { ...process.env };
        delete env.ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256;
        delete env.ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256;
        if (ownerPin) env.ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256 = ownerPin;
        if (checkpointPin) env.ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256 = checkpointPin;
        return env;
      })() });
    children.add(child);
    let deadline;
    try {
      const result = await Promise.race([
        new Promise((resolve, reject) => {
          child.once("message", (message) => resolve(message?.type === "ready"));
          child.once("exit", () => resolve(false));
          child.once("error", reject);
        }),
        new Promise((_, reject) => {
          deadline = setTimeout(() => reject(new Error("WITNESS_FLOOR_START_TIMEOUT")), 8000);
        }),
      ]);
      assert.equal(result, expectReady);
    } finally {
      clearTimeout(deadline);
      if (child.exitCode === null) {
        const exited = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await exited;
      }
      children.delete(child);
    }
  }
  await start(config, true);
  // The owner pins a separate Ed25519 public-key fingerprint outside the
  // witness's editable JSON. A storage-only attacker cannot lower the
  // witness floor or substitute a new owner key by editing that JSON.
  const keySpki = owner.publicKey.export({ type: "spki", format: "der" });
  const keyPin = crypto.createHash("sha256").update(keySpki).digest("hex");
  const issuedAt = Math.floor(Date.now() / 1000);
  const witnessSpkiSha256 = crypto.createHash("sha256")
    .update(witness.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const statusSpkiSha256 = crypto.createHash("sha256")
    .update(status.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  function ownerStatement(head, dates = {}) {
    return {
      type: "rootark-zk1-cas-owner-floor/v2",
      witnessKeyId: config.witnessKeyId, statusKeyId: config.statusKeyId,
      witnessSpkiSha256, statusSpkiSha256,
      sequence: head.sequence, lastHash: head.lastHash,
      issuedAt: dates.issuedAt ?? issuedAt, expiresAt: dates.expiresAt ?? issuedAt + 3600,
    };
  }
  const signedDomain = Buffer.from("Root.ark/zk-1/cas-owner-floor/v2\0", "ascii");
  function ownerSignature(head, signer = owner.privateKey, dates = {}) {
    return crypto.sign(null, Buffer.concat([
      signedDomain, Buffer.from(JSON.stringify(ownerStatement(head, dates))),
    ]), signer).toString("base64url");
  }
  function ownerCheckpointPin(head, signature, dates = {}) {
    return crypto.createHash("sha256").update(signedDomain)
      .update(Buffer.from(JSON.stringify(ownerStatement(head, dates))))
      .update(Buffer.from(signature, "base64url")).digest("hex");
  }
  const signature = ownerSignature(ownerRetained);
  const checkpointPin = ownerCheckpointPin(ownerRetained, signature);
  const signedConfig = { ...config, casAnchorFloor: {
    ...config.casAnchorFloor,
    owner: { publicKeyPath: files.ownerPub, issuedAt,
      expiresAt: issuedAt + 3600, signature },
  } };
  await start(signedConfig, true, keyPin, checkpointPin);
  // Adversarial bootstrap: zero is an authentic floor but must NOT allow an
  // editor to replace both public authorities while reusing their key IDs.
  // The owner keeps its original signed checkpoint and two environment pins.
  const bootstrapHead = { sequence: 0, lastHash: "0".repeat(64) };
  const bootstrapSignature = ownerSignature(bootstrapHead);
  const bootstrapPin = ownerCheckpointPin(bootstrapHead, bootstrapSignature);
  const newBootstrap = (prefix) => ({ ...config, bootstrapNew: true,
    dbPath: path.join(dir, prefix + "-witness.sqlite"),
    casAnchorFloor: {
      dbPath: path.join(dir, prefix + "-floor.sqlite"),
      trustedMinimumHead: bootstrapHead,
      owner: { publicKeyPath: files.ownerPub, issuedAt,
        expiresAt: issuedAt + 3600, signature: bootstrapSignature },
    },
  });
  await start(newBootstrap("legitimate-v2"), true, keyPin, bootstrapPin);
  // A previously authentic v1 owner+checkpoint pin is no longer accepted.
  // Verify actual v1 bytes rather than merely changing the v2 pin.
  const oldStatement = {
    type: "rootark-zk1-cas-owner-floor/v1",
    witnessKeyId: config.witnessKeyId, statusKeyId: config.statusKeyId,
    sequence: 0, lastHash: "0".repeat(64), issuedAt, expiresAt: issuedAt + 3600,
  };
  const oldDomain = Buffer.from("Root.ark/zk-1/cas-owner-floor/v1\0", "ascii");
  const oldPayload = Buffer.from(JSON.stringify(oldStatement));
  const oldSig = crypto.sign(null, Buffer.concat([oldDomain, oldPayload]), owner.privateKey);
  const oldCheckpointPin = crypto.createHash("sha256")
    .update(oldDomain).update(oldPayload).update(oldSig).digest("hex");
  const oldOwner = { publicKeyPath: files.ownerPub, issuedAt,
    expiresAt: issuedAt + 3600, signature: oldSig.toString("base64url") };
  const oldBootstrap = newBootstrap("legacy-owner-v1-replay");
  oldBootstrap.casAnchorFloor.owner = oldOwner;
  await start(oldBootstrap, false, keyPin, oldCheckpointPin);
  assert.equal(fs.existsSync(oldBootstrap.dbPath), false);
  assert.equal(fs.existsSync(oldBootstrap.casAnchorFloor.dbPath), false);
  const forgedWitness = crypto.generateKeyPairSync("ed25519");
  const forgedStatus = crypto.generateKeyPairSync("ed25519");
  const forgedWitnessPath = path.join(dir, "impostor-witness-private.pem");
  const forgedStatusPath = path.join(dir, "impostor-status-public.pem");
  fs.writeFileSync(forgedWitnessPath, forgedWitness.privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(forgedStatusPath, forgedStatus.publicKey.export({ type: "spki", format: "pem" }));
  const forged = { ...newBootstrap("impostor-v2"),
    witnessPrivateKeyPath: forgedWitnessPath,
    statusPublicKeyPath: forgedStatusPath,
    // The key IDs are intentionally unchanged from the legitimate service.
  };
  await start(forged, false, keyPin, bootstrapPin);
  assert.equal(fs.existsSync(forged.dbPath), false,
    "rejected signed bootstrap must not open a new witness DB");
  assert.equal(fs.existsSync(forged.casAnchorFloor.dbPath), false,
    "rejected signed bootstrap must not open a new floor DB");
  for (const [label, paths] of [
    ["witness-only", { witnessPrivateKeyPath: forgedWitnessPath }],
    ["status-only", { statusPublicKeyPath: forgedStatusPath }],
  ]) {
    const changed = { ...newBootstrap("impostor-v2-" + label), ...paths };
    await start(changed, false, keyPin, bootstrapPin);
    assert.equal(fs.existsSync(changed.dbPath), false);
    assert.equal(fs.existsSync(changed.casAnchorFloor.dbPath), false);
  }
  const oldForged = { ...newBootstrap("impostor-owner-v1-replay"),
    witnessPrivateKeyPath: forgedWitnessPath,
    statusPublicKeyPath: forgedStatusPath,
  };
  oldForged.casAnchorFloor.owner = oldOwner;
  await start(oldForged, false, keyPin, oldCheckpointPin);
  assert.equal(fs.existsSync(oldForged.dbPath), false);
  assert.equal(fs.existsSync(oldForged.casAnchorFloor.dbPath), false);
  // Actual offline CLI artifact, then actual witness process startup: no
  // exported test helper can bypass the on-disk owner pin or signature check.
  const signerInput = path.join(dir, "operator-minimum.json");
  const signerOutput = path.join(dir, "operator-checkpoint.json");
  const ownerPrivate = path.join(dir, "owner-private.pem");
  const witnessPublic = path.join(dir, "witness-public.pem");
  fs.writeFileSync(ownerPrivate, owner.privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(witnessPublic, witness.publicKey.export({ type: "spki", format: "pem" }));
  fs.writeFileSync(signerInput, JSON.stringify({
    source: "owner-retained-independent-floor/v1",
    witnessKeyId: config.witnessKeyId, statusKeyId: config.statusKeyId,
    trustedMinimumHead: ownerRetained, issuedAt, expiresAt: issuedAt + 3600,
  }));
  const cli = spawnSync(process.execPath, [
    path.resolve(__dirname, "../scripts/zk1-owner-cas-floor-sign-offline.js"),
    "--owned-dir", dir, "--input", signerInput,
    "--owner-private-key", ownerPrivate, "--owner-public-key", files.ownerPub,
    "--witness-public-key", witnessPublic, "--status-public-key", files.statusPub,
    "--output", signerOutput, "--confirm-independent-minimum",
  ], { encoding: "utf8", windowsHide: true });
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(cli.stdout, "OWNER_FLOOR_SIGNED\n");
  const cliArtifact = JSON.parse(fs.readFileSync(signerOutput, "utf8"));
  assert.deepEqual(cliArtifact.casAnchorFloor.trustedMinimumHead, ownerRetained);
  assert.equal(cliArtifact.envPins.ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256, keyPin);
  assert.equal(cliArtifact.envPins.ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256, checkpointPin);
  const cliConfig = { ...config, casAnchorFloor: {
    ...config.casAnchorFloor, ...cliArtifact.casAnchorFloor,
  } };
  await start(cliConfig, true, cliArtifact.envPins.ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256,
    cliArtifact.envPins.ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256);
  await start({ ...cliConfig, casAnchorFloor: {
    ...cliConfig.casAnchorFloor, trustedMinimumHead: { sequence: 1, lastHash: "f".repeat(64) },
  } }, false, keyPin, checkpointPin);
  await start({ ...cliConfig, casAnchorFloor: {
    ...cliConfig.casAnchorFloor, owner: { ...cliConfig.casAnchorFloor.owner,
      publicKeyPath: path.join(dir, "status-public.pem") },
  } }, false, keyPin, checkpointPin);
  await start(signedConfig, false, "f".repeat(64), checkpointPin);
  await start(signedConfig, false, keyPin, "f".repeat(64));
  await start(signedConfig, false, keyPin); // refusing missing independent latest-floor pin
  await start(signedConfig, false); // refusing silently skipped owner policy
  await start(config, false, keyPin); // refusing stripped signature
  await start({ ...signedConfig, casAnchorFloor: {
    ...signedConfig.casAnchorFloor, trustedMinimumHead: {
      sequence: 0, lastHash: "0".repeat(64),
    },
  } }, false, keyPin, checkpointPin);
  await start({ ...signedConfig, casAnchorFloor: {
    ...signedConfig.casAnchorFloor, owner: { ...signedConfig.casAnchorFloor.owner,
      signature: ownerSignature(ownerRetained, crypto.generateKeyPairSync("ed25519").privateKey) },
  } }, false, keyPin, checkpointPin);
  await start({ ...signedConfig, casAnchorFloor: {
    ...signedConfig.casAnchorFloor, owner: { ...signedConfig.casAnchorFloor.owner,
      issuedAt: issuedAt - 7200, expiresAt: issuedAt - 3600,
      signature: ownerSignature(ownerRetained, owner.privateKey,
        { issuedAt: issuedAt - 7200, expiresAt: issuedAt - 3600 }) },
  } }, false, keyPin, checkpointPin);
  // A legitimate *older* owner signature is insufficient once the owner has
  // independently pinned the latest signed-checkpoint digest in its service
  // environment. The old signed floor is authentic, not current.
  const floorReader = new Database(floorDb, { readonly: true });
  const oldHash = floorReader.prepare("SELECT hash FROM witness_cas_floor_event WHERE sequence=1").get().hash;
  floorReader.close();
  const priorMinimum = { sequence: 1, lastHash: oldHash };
  const priorSignature = ownerSignature(priorMinimum);
  const replayedOldOwnerConfig = { ...signedConfig, casAnchorFloor: {
    ...signedConfig.casAnchorFloor, trustedMinimumHead: priorMinimum,
    owner: { ...signedConfig.casAnchorFloor.owner, signature: priorSignature },
  } };
  await start(replayedOldOwnerConfig, false, keyPin, checkpointPin);
  const { trustedMinimumHead: absent, ...withoutOwnerFloor } = config.casAnchorFloor;
  await start({ ...config, casAnchorFloor: withoutOwnerFloor }, false);
  const db = new Database(floorDb);
  try { db.prepare("DELETE FROM witness_cas_floor_event WHERE sequence=2").run(); }
  finally { db.close(); }
  await start(config, false);
  await start(replayedOldOwnerConfig, false, keyPin, checkpointPin);
  // An owner-supplied mismatch at exactly the same signed sequence must also
  // fail; comparing just numeric revision would permit signed parallel forks.
  await start({ ...config, casAnchorFloor: { ...config.casAnchorFloor,
    trustedMinimumHead: { sequence: 1, lastHash: "f".repeat(64) } } }, false);
});
