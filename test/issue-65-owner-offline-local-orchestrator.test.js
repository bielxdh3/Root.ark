"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const manifest = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const z = require("../src/crypto/rootark-zk-1");
const commit = require("../src/crypto/rootark-zk1-offline-commitment-receipt");
const browserPop = require("../public/client/rootark-zk1-v2-browser-pop");
const { executeOwnerEnrollment } = require("../src/services/zk1OwnerOfflineEnrollmentOrchestrator");

test("offline owner CLI rejects context module traversal outside the owned directory", (t) => {
  const shell = require("../scripts/zk1-owner-offline-enroll-local");
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-owner-context-traversal-"));
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  const owned = path.join(workspace, "owned");
  fs.mkdirSync(owned);
  fs.writeFileSync(path.join(workspace, "foreign.js"), "module.exports = () => ({});\n");
  assert.throws(() => shell.fileAt(owned, `..${path.sep}foreign.js`),
    /ZK_OWNER_LOCAL_CLI_DENIED/);
  assert.throws(() => shell.fileAt(owned, "../foreign.js"),
    /ZK_OWNER_LOCAL_CLI_DENIED/);
});

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const spki = (key) => b64(crypto.createHash("sha256").update(
  key.export({ format: "der", type: "spki" })).digest());
function signed(fields, scope, key) {
  const value = { schema: commit.SCHEMA, status: "committed",
    ...Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
      .map((name) => [name, b64(scope[name])])),
    revision: null, digest: null, epoch: null, previous_revision: null,
    previous_digest: null, operation_id: null, pop_challenge_id: null,
    request_nonce: null, commit_nonce: null, sequence: null,
    previous_receipt_sha256: null, issued_at: null, expires_at: null, ...fields };
  const unsigned = Object.fromEntries(commit.FIELDS.map((name) => [name, value[name]]));
  return { ...unsigned, signature: b64(crypto.sign(null,
    commit.commitmentSigningBytes(unsigned), key)) };
}
function receiptDigest(value) {
  return b64(crypto.createHash("sha256").update(Buffer.concat([
    commit.commitmentSigningBytes(Object.fromEntries(commit.FIELDS.map(
      (name) => [name, value[name]]))), Buffer.from(value.signature, "base64url")])).digest());
}
async function setup() {
  const state = await fixtures.createInitialState(2);
  const owner = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const target = crypto.generateKeyPairSync("ed25519");
  const hpke = await z.hpkeSuite().kem.generateKeyPair();
  const hpkeDer = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"),
    Buffer.from(await z.hpkeSuite().kem.serializePrivateKey(hpke.privateKey))]);
  const request = { schema: "rootark-zk1-device-enrollment-request/v1",
    device_id: "fresh-offline-local-device",
    authorization_key_id: b64(crypto.randomBytes(16)),
    authorization_public_key: b64(target.publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
    hpke_key_id: b64(crypto.randomBytes(16)),
    hpke_public_key: b64(await z.hpkeSuite().kem.serializePublicKey(hpke.publicKey)),
    challenge: b64(crypto.randomBytes(32)),
    approval: "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT" };
  const head = state.headManifest;
  const currentDigest = b64(await manifest.recoveryManifestDigestV2(head));
  const at = Math.floor(Date.now() / 1000);
  const prior = signed({ revision: head.revision, digest: currentDigest,
    epoch: head.current_epoch, sequence: 40, issued_at: at - 1,
    expires_at: at + 280 }, state.scope, witness.privateKey);
  const pins = {
    ownerSpkiSha256: spki(owner.publicKey), witnessSpkiSha256: spki(witness.publicKey),
    priorCommitmentSha256: receiptDigest(prior), revision: head.revision,
    digest: currentDigest, epoch: head.current_epoch };
  const actor = state.actors.get(Buffer.from(head.devices[0].authorization_key_id).toString("hex"));
  const trusted = { verifiedHistory: state.verifiedHistory, trustedOwnerPublicKey: owner.publicKey,
    trustedCommitmentSignerPublicKey: witness.publicKey, trustedPriorCommitment: prior,
    ownerPrivateKey: owner.privateKey, trustedActorPrivateKey: actor };
  const answer = (challenge) => browserPop.respond({ request, challenge,
    deviceHpkePrivateDer: hpkeDer,
    deviceAuthorizationPrivateDer: target.privateKey.export({ type: "pkcs8", format: "der" }),
    nowSeconds: Math.floor(Date.now() / 1000) });
  const issueReceipt = (candidate, fields = {}, signer = witness.privateKey) => signed({
    revision: candidate.revision, digest: candidate.digest, epoch: candidate.epoch,
    previous_revision: head.revision, previous_digest: currentDigest,
    operation_id: candidate.operationId, pop_challenge_id: candidate.popChallengeId,
    request_nonce: request.challenge, commit_nonce: candidate.commitNonce,
    sequence: prior.sequence + 1, previous_receipt_sha256: receiptDigest(prior),
    issued_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 150, ...fields,
  }, state.scope, signer);
  return { state, owner, witness, target, hpkeDer, request, pins, trusted, answer,
    issueReceipt, prior };
}
test("owner local orchestrator publishes exactly one delivery only after independently signed commitment", async () => {
  const f = await setup();
  const outputs = [];
  let latest;
  const result = await executeOwnerEnrollment({
    trusted: f.trusted, externalPins: f.pins, request: f.request,
    publishChallenge: async (challenge) => { outputs.push("challenge"); latest = challenge; },
    awaitTargetPoP: async () => f.answer(latest),
    publishCandidate: async (candidate) => {
      assert.equal(candidate.committed, false);
      assert.equal(candidate.ownerApproved, false);
      assert.equal(candidate.signedCandidateOnly, true);
      outputs.push("uncommitted"); latest = candidate;
    },
    awaitWitnessCommitment: async () => {
      assert.deepEqual(outputs, ["challenge", "uncommitted"]);
      return f.issueReceipt(latest);
    },
    publishDelivery: async (delivery) => {
      outputs.push("delivery");
      assert.equal(delivery.schema, "rootark-zk1-v2-owner-browser-delivery/v1");
      assert.equal(delivery.signedDeviceGrant.device_id, f.request.device_id);
      assert.equal(JSON.stringify(delivery).includes("BEGIN PRIVATE KEY"), false);
    },
  });
  assert.equal(result.completed, true);
  assert.equal(result.physicalDurabilityProven, false);
  assert.deepEqual(outputs, ["challenge", "uncommitted", "delivery"]);
});
test("owner local orchestrator rejects forged pins, PoP, unsigned head, witnessed nonce/expiry/fork/replay and clock rollback without emitting delivery", async () => {
  for (const mode of ["owner-pin", "witness-pin", "prior-pin", "head",
    "wrong-pop", "unsigned", "foreign-witness", "nonce", "replay",
    "expired", "fork", "clock-rollback", "wrong-owner-key", "cancel-after-stage"]) {
    const f = await setup();
    let challenge, staged, releases = 0;
    const pins = { ...f.pins };
    if (mode === "owner-pin") pins.ownerSpkiSha256 = b64(crypto.randomBytes(32));
    if (mode === "witness-pin") pins.witnessSpkiSha256 = b64(crypto.randomBytes(32));
    if (mode === "prior-pin") pins.priorCommitmentSha256 = b64(crypto.randomBytes(32));
    if (mode === "head") pins.digest = b64(crypto.randomBytes(32));
    const trusted = { ...f.trusted };
    if (mode === "wrong-owner-key") trusted.ownerPrivateKey =
      crypto.generateKeyPairSync("ed25519").privateKey;
    await assert.rejects(executeOwnerEnrollment({
      trusted, externalPins: pins, request: f.request,
      clock: mode === "clock-rollback" ? () => Math.floor(Date.now() / 1000) - 70 : undefined,
      publishChallenge: async (input) => { challenge = input; },
      awaitTargetPoP: () => mode === "wrong-pop"
        ? f.answer({ ...challenge, ciphertext: b64(crypto.randomBytes(65)) })
        : f.answer(challenge),
      publishCandidate: async (input) => { staged = input; },
      awaitWitnessCommitment: async () => {
        if (mode === "cancel-after-stage") throw Error("physical operator declined commit");
        if (mode === "unsigned") return { revision: staged.revision, digest: staged.digest };
        if (mode === "foreign-witness") return f.issueReceipt(staged, {},
          crypto.generateKeyPairSync("ed25519").privateKey);
        if (mode === "nonce") return f.issueReceipt(staged,
          { request_nonce: b64(crypto.randomBytes(32)) });
        if (mode === "replay") return f.issueReceipt(staged,
          { sequence: f.prior.sequence });
        if (mode === "expired") return f.issueReceipt(staged,
          { issued_at: Math.floor(Date.now() / 1000) - 120,
            expires_at: Math.floor(Date.now() / 1000) - 1 });
        if (mode === "fork") return f.issueReceipt(staged,
          { digest: b64(crypto.randomBytes(32)) });
        return f.issueReceipt(staged);
      },
      publishDelivery: async () => { releases++; },
    }), /ZK_OWNER_CEREMONY_DENIED/, mode);
    assert.equal(releases, 0, mode + " must not release owner grant");
  }
});

test("executable Node owner CLI interchanges real browser PoP + signed receipt using disposable owner files", async (t) => {
  const f = await setup();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-owner-ceremony-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const source = path.resolve(__dirname, "../");
  const state = f.state;
  const head = state.headManifest;
  const file = (name) => path.join(root, name);
  const write = (name, object) => fs.writeFileSync(file(name), JSON.stringify(object));
  const full = {
    scope: Object.fromEntries(Object.entries(state.scope).map(([name, bytes]) => [name, b64(bytes)])),
    base: b64(await z.encodeDeterministic(state.baseManifest)),
    transitions: state.transitions.map(b64),
    baseReceipt: Object.fromEntries(Object.entries(state.baseReceipt).map(
      ([name, value]) => [name, Buffer.isBuffer(value) ? b64(value) : value])),
    baseWitnessKeyId: b64(state.pinnedWitness.keyId),
    baseWitnessPublicDer: b64(state.pinnedWitness.publicKey.export({ type: "spki", format: "der" })),
    epochs: state.epochKeys.map(({ epoch, key }) => ({ epoch, key: b64(key) })),
    ownerPrivatePem: f.owner.privateKey.export({ type: "pkcs8", format: "pem" }),
    actorPrivatePem: f.trusted.trustedActorPrivateKey.export({ type: "pkcs8", format: "pem" }),
    witnessPublicPem: f.witness.publicKey.export({ type: "spki", format: "pem" }),
    prior: f.prior,
  };
  write("offline-state.json", full);
  write("request.json", f.request);
  // Owner-controlled local script; every signed history byte is reverified
  // by the real Node crypto implementation, not a self-declared boolean.
  fs.writeFileSync(file("owner-context.js"), `"use strict";
    const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
    const z=require(${JSON.stringify(path.join(source, "src/crypto/rootark-zk-1.js"))});
    const verifier=require(${JSON.stringify(path.join(source, "src/crypto/rootark-zk-recovery-history-v2.js"))});
    module.exports=async()=>{
      const input=JSON.parse(fs.readFileSync(path.join(__dirname,"offline-state.json"),"utf8"));
      const dec=s=>Buffer.from(s,"base64url");
      const scope=Object.fromEntries(Object.entries(input.scope).map(([name,value])=>[name,dec(value)]));
      const base=await z.decodeDeterministic(dec(input.base));
      const receipt=Object.fromEntries(Object.entries(input.baseReceipt).map(([name,value])=>
        [name,["witness_key_id","account_id","compartment_id","keyring_id","manifest_digest",
        "nonce","signature"].includes(name)?dec(value):value]));
      const verifiedHistory=await verifier.verifyTrustedDeviceRecoveryHistoryV2({
        expectedScope:scope,baseManifest:base,baseReceipt:receipt,
        pinnedWitness:{keyId:dec(input.baseWitnessKeyId),
          publicKey:crypto.createPublicKey({key:dec(input.baseWitnessPublicDer),type:"spki",format:"der"})},
        transitions:input.transitions.map(dec),
        epochKeys:input.epochs.map(e=>({epoch:e.epoch,key:dec(e.key)}))});
      const ownerPrivateKey=crypto.createPrivateKey(input.ownerPrivatePem);
      return {verifiedHistory,ownerPrivateKey,
        trustedOwnerPublicKey:crypto.createPublicKey(ownerPrivateKey),
        trustedCommitmentSignerPublicKey:crypto.createPublicKey(input.witnessPublicPem),
        trustedPriorCommitment:input.prior,
        trustedActorPrivateKey:crypto.createPrivateKey(input.actorPrivatePem)};
    };`);
  const cli = path.join(source, "scripts/zk1-owner-offline-enroll-local.js");
  const args = [cli, "--owned-dir", root, "--context-module", "owner-context.js",
    "--owner-spki", f.pins.ownerSpkiSha256, "--witness-spki", f.pins.witnessSpkiSha256,
    "--head-revision", String(head.revision), "--head-digest", f.pins.digest,
    "--head-epoch", String(head.current_epoch),
    "--prior-receipt-sha256", f.pins.priorCommitmentSha256];
  const child = spawn(process.execPath, args, {
    cwd: root, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  // Attach exit tracking BEFORE the last output appears. On fast Node22
  // runtimes the process may exit before we observe browser-delivery.json.
  const exit = new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal }));
    child.once("error", (error) => resolve({ code: -1, error }));
  });
  t.after(() => { if (!child.killed) child.kill(); });
  let stderr = "", stdout = "";
  child.stderr.on("data", (c) => { stderr += c; });
  child.stdout.on("data", (c) => { stdout += c; });
  async function until(filename) {
    for (let i = 0; i < 150; i++) {
      if (fs.existsSync(file(filename))) return JSON.parse(fs.readFileSync(file(filename), "utf8"));
      if (child.exitCode !== null) throw Error("CLI early exit: " + stderr);
      await new Promise((resolve) => setTimeout(resolve, 70));
    }
    throw Error("CLI no file " + filename + ": " + stderr);
  }
  const challenge = await until("challenge.json");
  write("response.json", await f.answer(challenge));
  const candidate = await until("candidate.json");
  assert.equal(candidate.signedCandidateOnly, true);
  assert.equal(fs.existsSync(file("browser-delivery.json")), false);
  write("committed-receipt.json", f.issueReceipt(candidate));
  const delivery = await until("browser-delivery.json");
  assert.equal(delivery.signedDeviceGrant.device_id, f.request.device_id);
  assert.equal(delivery.schema, "rootark-zk1-v2-owner-browser-delivery/v1");
  assert.equal((await exit).code, 0, stderr);
  assert.match(stdout, /"completed":true/);
  assert.equal(stderr, "");
});
