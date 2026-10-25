"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { generateNativeFixtureCertificates } = require("./support/issue-65-native-openssl-fixture");
const { Zk1WitnessCasAnchorHttpsClient } = require("../src/services/zk1WitnessCasAnchorHttpsClient");
const { Zk1IndependentWitnessFloorQuorum } = require("../src/services/zk1IndependentWitnessFloorQuorum");
const { Zk1SharedPgWitnessCasEgressGuard } =
  require("../src/services/zk1SharedPgWitnessCasEgressGuard");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const ownerRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");

const DOMAIN = Buffer.from("Root.ark/zk-1/witness-cas-physical-floor/v2\0", "ascii");
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomId = () => crypto.randomBytes(16);
const floor = (sequence, lastHash, physicalFenceDigest) =>
  ({ sequence, lastHash, physicalFenceDigest });

test("separate pinned mTLS witnesses expose fork; distributed floor denies split-brain, rollback and missing peer", async (t) => {
  const dir = createPrivateAuthorityFixture("zk65-multihost-witness-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true,
    maxRetries: 8, retryDelay: 100 }));
  generateNativeFixtureCertificates(dir, { caSubject: "Independent floor test CA",
    servers: ["servera", "serverb"], clients: ["operator"] });
  const read = (file) => fs.readFileSync(path.join(dir, file));
  const fp = (name) => new crypto.X509Certificate(read(name + ".pem")).fingerprint256;
  const operatorFp = fp("operator");
  const statusId = randomId();
  const minimum = floor(4, "1".repeat(64), digest("physical-4"));
  const states = [floor(5, "2".repeat(64), digest("physical-5")),
    floor(5, "3".repeat(64), digest("physical-5"))];
  const witnesses = [], servers = [], calls = [0, 0];
  for (let i = 0; i < 2; i += 1) {
    const name = i === 0 ? "servera" : "serverb";
    const witness = crypto.generateKeyPairSync("ed25519");
    const witnessId = randomId();
    const server = https.createServer({ key: read(name + ".key"),
      cert: read(name + ".pem"), ca: read("ca.pem"), requestCert: true,
      rejectUnauthorized: true, minVersion: "TLSv1.3" }, async (req, res) => {
      if (!req.socket.authorized || req.socket.getPeerCertificate().fingerprint256 !== operatorFp
        || req.method !== "POST" || req.url !== "/v1/cas-anchor/head") {
        res.writeHead(403); res.end(); return;
      }
      calls[i] += 1;
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const incoming = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const s = states[i];
      const unsigned = { type: "rootark-zk1-witness-cas-physical-floor/v2",
        witnessKeyId: witnessId.toString("base64url"),
        statusKeyId: statusId.toString("base64url"),
        ...s, nonce: incoming.nonce };
      const signature = crypto.sign(null, Buffer.concat([DOMAIN,
        Buffer.from(JSON.stringify(unsigned))]), witness.privateKey).toString("base64url");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ head: { ...unsigned, signature },
        authority: "WITNESS_CAS_ANCHOR_FLOOR_V1" }));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    servers.push(server);
    witnesses.push(new Zk1WitnessCasAnchorHttpsClient({
      endpoint: `https://localhost:${server.address().port}`,
      ca: read("ca.pem"), clientKey: read("operator.key"),
      clientCert: read("operator.pem"), serverFingerprint256: fp(name),
      pinnedWitnessPublicKey: witness.publicKey,
      pinnedWitnessKeyId: witnessId, pinnedStatusKeyId: statusId,
      requirePhysicalAdmission: true,
    }));
  }
  t.after(async () => Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve)))));

  // Baseline bug: individually valid, distinct signed *higher* heads both
  // satisfy the old minimum. Neither single-witness signature proves ancestry.
  const [viewA, viewB] = await Promise.all(witnesses.map((w) => w.freshHead(minimum)));
  assert.equal(viewA.sequence, viewB.sequence);
  assert.notEqual(viewA.lastHash, viewB.lastHash);

  const trusted = floor(5, "2".repeat(64), digest("physical-5"));
  const quorum = new Zk1IndependentWitnessFloorQuorum({
    witnesses, externallyRetainedFloor: trusted });
  class ForgedQuorum extends Zk1IndependentWitnessFloorQuorum {
    async freshHead() { return { ...trusted }; }
  }
  const forged = new ForgedQuorum({ witnesses, externallyRetainedFloor: trusted });
  await assert.rejects(Zk1SharedPgWitnessCasEgressGuard.establish({
    witness: forged, witnessFloor: trusted,
  }), /ZK_LAB_QUORUM_UNAVAILABLE/,
  "a subclass cannot replace physical mTLS challenges with unsigned fixture booleans");
  await assert.rejects(quorum.freshHead(), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
    "two independent valid signatures on a fork must veto restore/GET");
  states[1] = { ...trusted };
  assert.deepEqual(await quorum.freshHead(), trusted,
    "two separate TLS challenges and Ed25519 signatures must agree exactly");
  assert.ok(calls[0] >= 3 && calls[1] >= 3);

  // Positive guarded GET, not merely a detached trust-comparison helper.
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("private"), keyring_id: crypto.randomBytes(16) };
  const scopeWire = Object.fromEntries(Object.entries(scope)
    .map(([name, value]) => [name, value.toString("base64url")]));
  const io = { scope, workerId: crypto.randomBytes(16),
    principal: "AB:".repeat(31) + "AB", action: "get",
    objectId: crypto.randomBytes(16).toString("base64url"), revision: 7,
    digest: crypto.randomBytes(32) };
  const sealedRoot = crypto.randomBytes(32);
  const owner = crypto.generateKeyPairSync("ed25519");
  const spki = owner.publicKey.export({ format: "der", type: "spki" });
  const ownerPrivate = await crypto.webcrypto.subtle.importKey("pkcs8",
    owner.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const ownerPublic = await crypto.webcrypto.subtle.importKey("spki", spki,
    "Ed25519", false, ["verify"]);
  const signerKeyId = randomId();
  const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope: scopeWire, signerKey: ownerPrivate, signerPublicKey: ownerPublic,
    signerKeyId, deviceId: "fixture-owner", revision: io.revision,
    manifestDigest: io.digest, issuedAt: 101, previous: null });
  const checkpoint = await ownerRoots.signOwnerCiphertextRootCheckpoint({
    scope: scopeWire, signerKey: ownerPrivate, signerKeyId,
    deviceId: "fixture-owner", manifestRevision: io.revision,
    manifestDigest: io.digest, manifestEpoch: 2, objectId: io.objectId,
    objectRevision: io.revision, ciphertextEpoch: 1,
    ciphertextRoot: sealedRoot, issuedAt: 102 });
  const egress = { witness: quorum, witnessFloor: trusted,
    ownerPublicSpki: spki,
    externallyPinnedOwnerSpkiSha256: crypto.createHash("sha256").update(spki).digest(),
    ownerProofInput: { checkpoint, ownerHistoryCheckpoint,
      previousHistoryProof: null,
      pinnedOwner: { scope: scopeWire, deviceId: "fixture-owner",
        signerKeyId, publicKey: ownerPublic },
      expected: { manifestRevision: io.revision, manifestDigest: Buffer.from(io.digest),
        manifestEpoch: 2, objectId: io.objectId, objectRevision: io.revision,
        ciphertextEpoch: 1, ciphertextRoot: Buffer.from(sealedRoot) } } };
  await assert.rejects(Zk1SharedPgWitnessCasEgressGuard.establish({ ...egress,
    witnessFloor: { sequence: trusted.sequence, lastHash: trusted.lastHash } }),
  /ZK_LAB_QUORUM_UNAVAILABLE/,
  "distributed GET cannot use CAS-only operator retention");
  const authorizedGuard = await Zk1SharedPgWitnessCasEgressGuard.establish(egress);
  assert.equal(await authorizedGuard.authorize({ io, expectedRootHash: sealedRoot }), true);
  states[0] = { ...minimum };
  await assert.rejects(quorum.freshHead(), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
    "an old but authentic witness head must not roll back the external high-water");
  await assert.rejects(authorizedGuard.authorize({ io, expectedRootHash: sealedRoot }),
    /ZK_LAB_QUORUM_UNAVAILABLE/,
  "witness rollback prevents the next supervised ciphertext frame");
  states[0] = { ...trusted };
  states[1] = floor(6, "4".repeat(64), digest("physical-6"));
  await assert.rejects(quorum.freshHead(), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
    "advancing only one host cannot silently update an operator-owned floor");
  states[0] = { ...states[1] };
  await assert.rejects(quorum.freshHead(), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
    "a prior process floor cannot silently advance even when both witnesses agree");
  const newlyRetained = new Zk1IndependentWitnessFloorQuorum({
    witnesses, externallyRetainedFloor: { ...states[0] } });
  assert.deepEqual(await newlyRetained.freshHead(), states[0],
    "explicit out-of-band high-water advancement enables new restart readback");
  await assert.rejects(quorum.freshHead(minimum), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
    "a caller cannot weaken the independent minimum on an existing fence");
  assert.throws(() => new Zk1IndependentWitnessFloorQuorum({
    witnesses: [witnesses[0], witnesses[0]], externallyRetainedFloor: trusted,
  }), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
  "one pinned signing identity cannot masquerade as two remote authorities");
  assert.throws(() => new Zk1IndependentWitnessFloorQuorum({
    witnesses: [witnesses[0]], externallyRetainedFloor: trusted,
  }), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/);
  assert.throws(() => new Zk1IndependentWitnessFloorQuorum({
    witnesses, externallyRetainedFloor: { sequence: 5, lastHash: trusted.lastHash },
  }), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
  "a CAS-only floor cannot authorize physical ciphertext GET");
  await new Promise((resolve) => servers[1].close(resolve));
  servers[1] = { close(done) { done(); } };
  await assert.rejects(quorum.freshHead(), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
    "network partition must fail closed without single-witness fallback");
  witnesses[1].freshHead = async () => ({ ...states[0] });
  await assert.rejects(newlyRetained.freshHead(), /INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE/,
    "a later caller method override cannot replace a native nonce/TLS proof");
});
