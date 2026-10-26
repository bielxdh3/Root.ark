"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { fork } = require("node:child_process");
const z = require("../src/crypto/rootark-zk-1");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { createCatalogAuthorityHttpsServer, createCatalogAuthorityHttpsClient } =
  require("../src/services/zk1CatalogExternalAuthorityHttps");

test("external catalog authority never starts without pinned independent signers and live authorization contracts", () => {
  const ed = () => crypto.generateKeyPairSync("ed25519");
  const keys = [ed(), ed(), ed(), ed()];
  const base = { key: Buffer.from("invalid"), cert: Buffer.from("invalid"), clientCa: Buffer.from("invalid"),
    authorizedClientFingerprint256: "AA:".repeat(31) + "AA",
    policyPrivateKey: keys[0].privateKey, floorPrivateKey: keys[1].privateKey,
    witnessPublicKey: keys[2].publicKey, physicalPublicKey: keys[3].publicKey };
  assert.throws(() => createCatalogAuthorityHttpsServer(base), /CATALOG_EXTERNAL_DENIED/,
    "no owner authorization and no independent physical commit source => never expose issuer");
  assert.throws(() => createCatalogAuthorityHttpsServer({
    ...base, trustedOwnerPolicy: async () => null, trustedPhysicalProof: async () => null,
    floorPrivateKey: keys[0].privateKey,
  }), /CATALOG_EXTERNAL_DENIED/, "policy and FLOOR signing key reuse is forbidden");
  assert.throws(() => createCatalogAuthorityHttpsClient({}), /CATALOG_EXTERNAL_DENIED/,
    "client must carry pinned server TLS SPKI and mTLS certificate");
});

for (const scenario of ["normal", "revoked-before-commit", "revoked-after-commit",
  "revoked-during-delayed-proof-after-commit", "revoked-during-delayed-proof-before-commit"]) {
test(`real TLS1.3/mTLS catalog issuer W30 owner/physical fence (${scenario})`, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-catalog-external-"));
  const witness = crypto.generateKeyPairSync("ed25519");
  const status = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  let ledger;
  let child;
  t.after(async () => {
    try { ledger?.close(); child?.kill(); } catch (_) { /* cleanup */ }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 });
  });
  generateNativeFixtureCertificates(dir, {
    caSubject: "Catalog Authority Test CA", servers: ["server"],
    clients: ["allowed", "other"],
  });
  const read = (n) => fs.readFileSync(path.join(dir, n));
  const expectedPrincipal = new crypto.X509Certificate(read("allowed.pem")).fingerprint256;
  const pinnedServer = crypto.createHash("sha256").update(
    new crypto.X509Certificate(read("server.pem")).publicKey
      .export({ type: "spki", format: "der" })).digest();
  child = fork(path.join(__dirname, "support/issue-65-catalog-external-issuer-child.js"), [], {
    stdio: ["ignore", "ignore", "ignore", "ipc"], windowsHide: true,
    env: { ...process.env, NODE_ENV: "test" },
  });
  const step = (expected, input) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("CATALOG_FIXTURE_CHILD_TIMEOUT")), 15000);
    const got = (message) => {
      if (message.kind !== expected) {
        if (message.kind === "failed") {
          clearTimeout(timer); child.off("message", got); reject(Error("CATALOG_FIXTURE_CHILD_FAILED"));
        }
        return;
      }
      clearTimeout(timer); child.off("message", got); resolve(message);
    };
    child.on("message", got);
    if (input) child.send(input);
  });
  const pins = await step("ready", { kind: "init", dir,
    witnessSpki: witness.publicKey.export({ type: "spki", format: "der" }).toString("base64url") });
  assert.notEqual(pins.policySpki, pins.floorSpki);
  assert.notEqual(pins.floorSpki, pins.physicalSpki);
  const endpoint = `https://localhost:${pins.port}`;
  const clientOpts = { endpoint, ca: read("ca.pem"), key: read("allowed.key"),
    cert: read("allowed.pem"), serverSpkiSha256: pinnedServer };
  const client = createCatalogAuthorityHttpsClient(clientOpts);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("remote-catalog"), keyring_id: crypto.randomBytes(16) };
  const ownerDigest = crypto.randomBytes(32);
  const first = { ...scope, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: null,
    expected_manifest_digest: null, proposed_revision: 1,
    proposed_manifest_digest: ownerDigest, request_digest: crypto.randomBytes(32),
    package_envelope_digest: null, expires_at: Math.floor(Date.now() / 1000) + 120 };
  const policyRequest = { scope, ownerRevision: 1, ownerDigest,
    operationId: crypto.randomBytes(16), signerDeviceId: crypto.randomBytes(16),
    epoch: 1, sequence: 1, catalogDigest: crypto.randomBytes(32),
    floorCasSignerFingerprint: crypto.randomBytes(32),
    expiresAt: Math.floor(Date.now() / 1000) + 60 };
  const witnessOpts = {
    witnessPrivateKey: witness.privateKey, witnessKeyId,
    statusPinned: { keyId: statusKeyId, publicKey: status.publicKey },
    statusProvider: { async getTerminalProof({ query, nonce }) {
      const unsigned = { type: "rootark-recovery-cas-status/v1",
        status_authority_key_id: statusKeyId, ...query,
        observed_revision: query.proposed_revision,
        observed_manifest_digest: query.proposed_manifest_digest,
        terminal_status: "committed", observed_at: Math.floor(Date.now() / 1000), nonce };
      const signature = crypto.sign(null, Buffer.concat([
        Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0"),
        Buffer.from(await z.encodeDeterministic(unsigned))]), status.privateKey);
      return Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
    } },
    catalogPolicyPublicKey: crypto.createPublicKey({ key: Buffer.from(pins.policySpki, "base64url"),
      format: "der", type: "spki" }),
    catalogFloorPublicKey: crypto.createPublicKey({ key: Buffer.from(pins.floorSpki, "base64url"),
      format: "der", type: "spki" }),
  };
  const filename = path.join(dir, "independent-witness.sqlite");
  ledger = new Zk1DurableWitnessLedger(filename, { ...witnessOpts, bootstrapNew: true });
  await ledger.reserve(first);
  await ledger.resolve({ scope });

  await assert.rejects(client.policyGrant(policyRequest), /CATALOG_EXTERNAL_DENIED/,
    "an unprovisioned operator policy must never sign arbitrary caller fields");
  const allow = { ...Object.fromEntries(Object.entries(scope).map(([k, v]) =>
    [k, v.toString("base64url")])),
    operation_id: policyRequest.operationId.toString("base64url"),
    owner_revision: policyRequest.ownerRevision, owner_digest: ownerDigest.toString("base64url"),
    signer_device_id: policyRequest.signerDeviceId.toString("base64url"),
    epoch: policyRequest.epoch, sequence: policyRequest.sequence,
    catalog_digest: policyRequest.catalogDigest.toString("base64url"),
    cas_signer_spki_sha256: policyRequest.floorCasSignerFingerprint.toString("base64url"),
    expires_at: policyRequest.expiresAt, principal: expectedPrincipal };
  await step("authorized", { kind: "authorize", policy: allow });
  await assert.rejects(client.policyGrant({ ...policyRequest, epoch: 2 }),
    /CATALOG_EXTERNAL_DENIED/, "external authority must pin exact owner-authorized epoch");
  await assert.rejects(createCatalogAuthorityHttpsClient({
    ...clientOpts, serverSpkiSha256: crypto.randomBytes(32),
  }).policyGrant(policyRequest), /CATALOG_EXTERNAL_DENIED/, "wrong TLS server SPKI must fail");
  await assert.rejects(createCatalogAuthorityHttpsClient({
    ...clientOpts, key: read("other.key"), cert: read("other.pem"),
  }).policyGrant(policyRequest), /CATALOG_EXTERNAL_DENIED/,
  "another CA-trusted TLS client cannot borrow the allowed principal");
  const policyGrant = await client.policyGrant(policyRequest);
  const started = await ledger.beginCatalogAdmission({
    ...policyRequest, principal: expectedPrincipal, policyGrant });
  assert.ok(Buffer.isBuffer(started.ticket));
  await assert.rejects(client.floorTerminal(started.ticket), /CATALOG_EXTERNAL_DENIED/,
    "ticket and a generic signed floor alone cannot invent a physical terminal");
  const forged = Buffer.from(await z.decodeDeterministic(started.ticket).then(async (body) => {
    const copy = { ...body, principal: "CD:".repeat(31) + "CD" };
    return z.encodeDeterministic(copy);
  }));
  await assert.rejects(client.floorTerminal(forged), /CATALOG_EXTERNAL_DENIED/,
    "tampered witness signed admission may not obtain FLOOR terminal");
  if (scenario === "revoked-before-commit" || scenario === "revoked-during-delayed-proof-before-commit") {
    await step("revoked", { kind: "revoke" });
  }
  if (scenario !== "revoked-during-delayed-proof-before-commit") {
    await step("physicalCommitted", { kind: "physicalCommit",
      ticket: started.ticket.toString("base64url") });
  }
  let delayedTerminal;
  if (scenario.startsWith("revoked-during-delayed-proof")) {
    await step("holding", { kind: "holdPhysical" });
    const physicalEntered = step("physicalEntered");
    delayedTerminal = client.floorTerminal(started.ticket);
    await physicalEntered;
    if (scenario === "revoked-during-delayed-proof-after-commit") {
      await step("revoked", { kind: "revoke" });
    } else {
      await step("physicalCommitted", { kind: "physicalCommit",
        ticket: started.ticket.toString("base64url") });
    }
    await step("released", { kind: "releasePhysical" });
  }
  if (scenario === "revoked-before-commit" || scenario === "revoked-during-delayed-proof-before-commit") {
    // Never accept FLOOR if the durable revocation fence won the race,
    // even when another process claims a subsequently committed record.
    await assert.rejects(delayedTerminal || client.floorTerminal(started.ticket), /CATALOG_EXTERNAL_DENIED/,
      "W30 P2: terminal signing must reconsult revoked owner policy even with a signed physical proof");
    await assert.rejects(client.floorTerminal(started.ticket), /CATALOG_EXTERNAL_DENIED/,
      "a previously denied operation cannot mint FLOOR via nonce/ticket replay");
    assert.deepEqual(await ledger.prepareQuiesce({ ...first, reservation_id: crypto.randomBytes(16),
      operation_id: crypto.randomBytes(16), expected_revision: 1, expected_manifest_digest: ownerDigest,
      proposed_revision: 2, proposed_manifest_digest: crypto.randomBytes(32) }),
    { status: "QUIESCING", activeCount: 1 }, "owner must not be allowed to DRAIN");
    return;
  }
  if (scenario === "revoked-after-commit") {
    await step("revoked", { kind: "revoke" });
  }
  const terminal = await (delayedTerminal || client.floorTerminal(started.ticket));
  if (scenario !== "normal") {
    assert.deepEqual(await client.floorTerminal(started.ticket), terminal,
      "already-committed exact admission can replay its terminal after revocation");
  }
  const badTerminal = Buffer.from(terminal);
  badTerminal[badTerminal.length - 1] ^= 1;
  await assert.rejects(ledger.completeCatalogAdmission({ scope,
    admissionId: started.admissionId, principal: expectedPrincipal,
    floorProof: badTerminal }), /WITNESS_CATALOG_DENIED/);
  assert.deepEqual(await ledger.completeCatalogAdmission({ scope,
    admissionId: started.admissionId, principal: expectedPrincipal,
    floorProof: terminal }), { status: "completed" });
  const next = { ...first, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: 1,
    expected_manifest_digest: ownerDigest, proposed_revision: 2,
    proposed_manifest_digest: crypto.randomBytes(32) };
  assert.deepEqual(await ledger.prepareQuiesce(next), { status: "DRAINED", activeCount: 0 });
  ledger.close();
  ledger = new Zk1DurableWitnessLedger(filename, { ...witnessOpts, bootstrapNew: false });
  assert.deepEqual(await ledger.completeCatalogAdmission({ scope,
    admissionId: started.admissionId, principal: expectedPrincipal,
    floorProof: terminal }), { status: "completed" });
  if (scenario !== "revoked-after-commit") await step("revoked", { kind: "revoke" });
  await assert.rejects(client.policyGrant(policyRequest), /CATALOG_EXTERNAL_DENIED/,
    "live external policy revocation cannot keep signing old grants");
});
}
