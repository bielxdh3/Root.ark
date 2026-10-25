"use strict";

// This covers ONLY the independent witness-side START/FINISH/revoke lock.
// The actual CAS/FLOOR mTLS integration is NOT enabled by this module.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const z = require("../src/crypto/rootark-zk-1");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const STATUS = Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0");
const FLOOR = Buffer.from("Root.ark/zk-1/opaque-catalog-witness-terminal/v1\0");
const LEGACY_FLOOR = Buffer.from("Root.ark/zk-1/opaque-catalog-independent-floor/v1\0");
const CATALOG = Buffer.from("Root.ark/zk-1/recovery-witness-catalog-admission/v1\0");
const POLICY = Buffer.from("Root.ark/zk-1/recovery-witness-catalog-policy-grant/v1\0");

async function fixture(t, { catalogEnabled = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-witness-catalog-"));
  const file = path.join(dir, "witness.sqlite");
  const connections = [];
  t.after(() => {
    for (const db of connections) db.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 });
  });
  const witness = crypto.generateKeyPairSync("ed25519");
  const status = crypto.generateKeyPairSync("ed25519");
  const floor = crypto.generateKeyPairSync("ed25519");
  const policy = crypto.generateKeyPairSync("ed25519");
  const keyId = crypto.randomBytes(16);
  const statusId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("catalog"),
    keyring_id: crypto.randomBytes(16) };
  const digest = crypto.randomBytes(32);
  let clock = 900;
  const options = { witnessPrivateKey: witness.privateKey, witnessKeyId: keyId,
    statusPinned: { publicKey: status.publicKey, keyId: statusId },
    catalogFloorPublicKey: catalogEnabled ? floor.publicKey : null,
    catalogPolicyPublicKey: catalogEnabled ? policy.publicKey : null,
    nowSeconds: () => clock,
    statusProvider: { async getTerminalProof({ query, nonce }) {
      const unsigned = { type: "rootark-recovery-cas-status/v1",
        status_authority_key_id: statusId, ...query, observed_revision: query.proposed_revision,
        observed_manifest_digest: query.proposed_manifest_digest,
        terminal_status: "committed", observed_at: clock, nonce };
      const encoded = await z.encodeDeterministic(unsigned);
      const signature = crypto.sign(null, Buffer.concat([STATUS, Buffer.from(encoded)]), status.privateKey);
      return z.encodeDeterministic({ ...unsigned, signature });
    } } };
  const open = () => {
    const ledger = new Zk1DurableWitnessLedger(file, { ...options,
      bootstrapNew: !fs.existsSync(file) });
    connections.push(ledger);
    return ledger;
  };
  const first = { ...scope, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: null,
    expected_manifest_digest: null, proposed_revision: 1,
    proposed_manifest_digest: digest, request_digest: crypto.randomBytes(32),
    package_envelope_digest: null, expires_at: 1000 };
  const ledger = open();
  await ledger.reserve(first);
  await ledger.resolve({ scope });
  const next = { ...first, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: 1,
    expected_manifest_digest: digest, proposed_revision: 2,
    proposed_manifest_digest: crypto.randomBytes(32) };
  const input = { scope, ownerRevision: 1, ownerDigest: digest,
    operationId: crypto.randomBytes(16), signerDeviceId: crypto.randomBytes(16),
    epoch: 1, sequence: 1, catalogDigest: crypto.randomBytes(32),
    floorCasSignerFingerprint: crypto.randomBytes(32),
    expiresAt: 950, principal: "AB:".repeat(31) + "AB" };
  const signPolicy = async (request, changes = {}) => {
    const body = { type: "rootark-recovery-witness-catalog-policy-grant/v1",
      ...request.scope, operation_id: request.operationId,
      owner_revision: request.ownerRevision, owner_digest: request.ownerDigest,
      signer_device_id: request.signerDeviceId, epoch: request.epoch,
      sequence: request.sequence, catalog_digest: request.catalogDigest,
      cas_signer_spki_sha256: request.floorCasSignerFingerprint,
      expires_at: request.expiresAt, principal: request.principal,
      nonce: crypto.randomBytes(32), issued_at: clock, ...changes };
    const signature = crypto.sign(null, Buffer.concat([POLICY,
      Buffer.from(await z.encodeDeterministic(body))]), policy.privateKey);
    return Buffer.from(await z.encodeDeterministic({ ...body, signature }));
  };
  input.policyGrant = await signPolicy(input);
  const signFloor = async (admitted, changes = {}) => {
    const body = { type: "rootark-zk1-opaque-catalog-witness-terminal/v1",
      ...scope, cas_signer_spki_sha256: input.floorCasSignerFingerprint,
      sequence: input.sequence, digest: input.catalogDigest,
      admission_id: admitted.admissionId, operation_id: input.operationId,
      owner_revision: input.ownerRevision, owner_digest: input.ownerDigest,
      signer_device_id: input.signerDeviceId, epoch: input.epoch, expires_at: input.expiresAt,
      nonce: admitted.floorNonce, observed_at: clock, ...changes };
    const signature = crypto.sign(null, Buffer.concat([FLOOR,
      Buffer.from(await z.encodeDeterministic(body))]), floor.privateKey);
    return Buffer.from(await z.encodeDeterministic({ ...body, signature }));
  };
  return { ledger, open, file, options, input, next, floor, policy, signPolicy, witness, keyId, signFloor,
    setClock(v) { clock = v; } };
}

test("opted-in FULL witness catalog admission blocks owner revoke before floor finalization and survives restart", async (t) => {
  const f = await fixture(t);
  const admission = await f.ledger.beginCatalogAdmission(f.input);
  const decoded = await z.decodeDeterministic(admission.ticket);
  const { signature, ...body } = decoded;
  assert.equal(crypto.verify(null, Buffer.concat([CATALOG,
    Buffer.from(await z.encodeDeterministic(body))]), f.witness.publicKey, signature), true);
  assert.equal(decoded.owner_revision, 1);
  assert.deepEqual(await f.ledger.beginCatalogAdmission(f.input), admission,
    "lost START ACK must replay same signed token without extending expiry");
  await assert.rejects(f.ledger.beginCatalogAdmission({ ...f.input,
    catalogDigest: crypto.randomBytes(32) }), /WITNESS_CATALOG_DENIED/);
  assert.deepEqual(await f.ledger.prepareQuiesce(f.next),
    { status: "QUIESCING", activeCount: 1 });
  await assert.rejects(f.ledger.reserve(f.next), /WITNESS_CATALOG_ACTIVE/);
  f.ledger.close();
  const restarted = f.open();
  await assert.rejects(restarted.reserve(f.next), /WITNESS_CATALOG_ACTIVE/,
    "restart cannot discard admitted floor work");
  await assert.rejects(restarted.completeCatalogAdmission({ scope: f.input.scope,
    admissionId: admission.admissionId, principal: "CD:".repeat(31) + "CD",
    floorProof: await f.signFloor(admission) }), /WITNESS_CATALOG_DENIED/);
  await assert.rejects(restarted.completeCatalogAdmission({ scope: f.input.scope,
    admissionId: admission.admissionId, principal: f.input.principal,
    floorProof: crypto.randomBytes(128) }), /WITNESS_CATALOG_DENIED/);
  const oldRead = { type: "rootark-zk1-opaque-catalog-independent-floor/v1",
    ...f.input.scope, cas_signer_spki_sha256: f.input.floorCasSignerFingerprint,
    sequence: f.input.sequence, digest: f.input.catalogDigest,
    nonce: admission.floorNonce, observed_at: 900 };
  const oldSignature = crypto.sign(null, Buffer.concat([LEGACY_FLOOR,
    Buffer.from(await z.encodeDeterministic(oldRead))]), f.floor.privateKey);
  await assert.rejects(restarted.completeCatalogAdmission({ scope: f.input.scope,
    admissionId: admission.admissionId, principal: f.input.principal,
    floorProof: Buffer.from(await z.encodeDeterministic({
      ...oldRead, signature: oldSignature })) }),
  /WITNESS_CATALOG_DENIED/,
  "a fully valid signature on a floor READ cannot fake a terminal for an unfinished CAS");
  await assert.rejects(restarted.completeCatalogAdmission({ scope: f.input.scope,
    admissionId: admission.admissionId, principal: f.input.principal,
    floorProof: await f.signFloor(admission, { operation_id: crypto.randomBytes(16) }) }),
  /WITNESS_CATALOG_DENIED/, "even a correctly signed FLOOR response must bind the original operation ID");
  await assert.rejects(restarted.completeCatalogAdmission({ scope: f.input.scope,
    admissionId: admission.admissionId, principal: f.input.principal,
    floorProof: await f.signFloor(admission, { catalog_digest: crypto.randomBytes(32) }) }),
  /WITNESS_CATALOG_DENIED/, "unrecognized terminal fields are forbidden");
  await assert.rejects(restarted.beginCatalogAdmission({ ...f.input,
    ownerDigest: crypto.randomBytes(32), operationId: crypto.randomBytes(16) }),
  /WITNESS_CATALOG_DENIED/);
  await assert.rejects(restarted.reserve(f.next), /WITNESS_CATALOG_ACTIVE/);
  const completed = { scope: f.input.scope, admissionId: admission.admissionId,
    principal: f.input.principal, floorProof: await f.signFloor(admission) };
  assert.deepEqual(await restarted.completeCatalogAdmission(completed), { status: "completed" });
  assert.deepEqual(await restarted.completeCatalogAdmission(completed), { status: "completed" });
  assert.deepEqual(await restarted.prepareQuiesce(f.next), { status: "DRAINED", activeCount: 0 });
  await restarted.reserve(f.next);
  await restarted.resolve({ scope: f.input.scope });
  assert.equal(restarted.db.prepare("SELECT revision FROM witness_scope").get().revision, 2,
    "the old owner HEAD must have advanced before replaying the FLOOR FINISH");
  // FLOOR finished durably, but the ACK to its original principal was lost.
  // Owner revocation can subsequently advance and the identical FINISH must
  // remain replayable without reviving any catalog admission or grant.
  f.setClock(951);
  assert.deepEqual(await restarted.completeCatalogAdmission(completed), { status: "completed" });
  restarted.close();
  const afterOwnerAdvance = f.open();
  assert.deepEqual(await afterOwnerAdvance.completeCatalogAdmission(completed),
    { status: "completed" }, "restart and expiry cannot erase an already durable terminal");
  await assert.rejects(afterOwnerAdvance.completeCatalogAdmission({
    ...completed, floorProof: await f.signFloor(admission, { observed_at: 951 }),
  }), /WITNESS_CATALOG_DENIED/, "a new correctly signed terminal cannot replace the stored one");
  await assert.rejects(afterOwnerAdvance.beginCatalogAdmission({ ...f.input,
    operationId: crypto.randomBytes(16) }), /WITNESS_CATALOG_DENIED/);
});

test("an untrusted START without independent signed policy authorization cannot block owner revocation", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.ledger.beginCatalogAdmission({
    ...f.input, policyGrant: Buffer.from([0xa0]),
  }), /WITNESS_CATALOG_DENIED/);
  assert.equal(f.ledger.db.prepare("SELECT COUNT(*) AS n FROM witness_catalog_admission").get().n, 0);
  assert.deepEqual(await f.ledger.prepareQuiesce(f.next),
    { status: "DRAINED", activeCount: 0 });
});

test("catalog policy must bind signer, epoch, sequence, principal, operation and every nonce to the external signature", async (t) => {
  const f = await fixture(t);
  const mutated = [
    { signerDeviceId: crypto.randomBytes(16) }, { epoch: 2 },
    { sequence: 2 }, { principal: "CD:".repeat(31) + "CD" },
    { operationId: crypto.randomBytes(16) },
    { floorCasSignerFingerprint: crypto.randomBytes(32) },
    { catalogDigest: crypto.randomBytes(32) },
    { ownerRevision: 2 },
  ];
  for (const change of mutated) {
    await assert.rejects(f.ledger.beginCatalogAdmission({ ...f.input, ...change }),
      /WITNESS_CATALOG_DENIED/);
  }
  const parsed = await z.decodeDeterministic(f.input.policyGrant);
  await assert.rejects(f.ledger.beginCatalogAdmission({
    ...f.input, policyGrant: Buffer.from(await z.encodeDeterministic({
      ...parsed, nonce: crypto.randomBytes(32),
    })),
  }), /WITNESS_CATALOG_DENIED/, "caller cannot replace a signed grant nonce");
  await assert.rejects(f.ledger.beginCatalogAdmission({
    ...f.input, policyGrant: await f.signPolicy(f.input, { issued_at: 800 }),
  }), /WITNESS_CATALOG_DENIED/, "even signed stale policy grants cannot be started");
  assert.equal(f.ledger.db.prepare("SELECT COUNT(*) AS n FROM witness_catalog_admission").get().n, 0);
  assert.deepEqual(await f.ledger.prepareQuiesce(f.next), { status: "DRAINED", activeCount: 0 });
});

test("policy nonce cannot be reused for another operation, and restart cannot downgrade pinned signer", async (t) => {
  const f = await fixture(t);
  const admission = await f.ledger.beginCatalogAdmission(f.input);
  await f.ledger.completeCatalogAdmission({ scope: f.input.scope, admissionId: admission.admissionId,
    principal: f.input.principal, floorProof: await f.signFloor(admission) });
  const originalGrant = await z.decodeDeterministic(f.input.policyGrant);
  const second = { ...f.input, operationId: crypto.randomBytes(16) };
  second.policyGrant = await f.signPolicy(second, { nonce: originalGrant.nonce });
  await assert.rejects(f.ledger.beginCatalogAdmission(second), /WITNESS_CATALOG_DENIED/);
  assert.equal(f.ledger.db.prepare("SELECT COUNT(*) AS n FROM witness_catalog_admission").get().n, 1);
  f.ledger.close();
  assert.throws(() => new Zk1DurableWitnessLedger(f.file, {
    ...f.options, catalogPolicyPublicKey: crypto.generateKeyPairSync("ed25519").publicKey,
    bootstrapNew: false,
  }), /WITNESS_CATALOG_DENIED/);
  assert.throws(() => new Zk1DurableWitnessLedger(f.file, {
    ...f.options, catalogPolicyPublicKey: null, bootstrapNew: false,
  }), /WITNESS_CATALOG_DENIED/);
  const restarted = f.open();
  f.setClock(951);
  const later = { ...f.input, operationId: crypto.randomBytes(16) };
  later.policyGrant = await f.signPolicy(later);
  await assert.rejects(restarted.beginCatalogAdmission(later), /WITNESS_CATALOG_DENIED/,
    "expiry cannot turn a previously granted operation into a new authority");
  assert.deepEqual(await restarted.prepareQuiesce(f.next), { status: "DRAINED", activeCount: 0 });
});

test("catalog reservation persists strict identity: no silent legacy upgrade, signer-key downgrade, or forged immutability trigger", async (t) => {
  const unmarked = await fixture(t, { catalogEnabled: false });
  await assert.rejects(unmarked.ledger.beginCatalogAdmission(unmarked.input),
    /WITNESS_CATALOG_DENIED/);
  unmarked.ledger.close();
  assert.throws(() => new Zk1DurableWitnessLedger(unmarked.file, {
    ...unmarked.options, bootstrapNew: false,
    catalogFloorPublicKey: unmarked.floor.publicKey,
  }), /WITNESS_CATALOG_DENIED/,
  "an existing witness SQLite cannot be silently auto-migrated into catalog admission");

  const enrolled = await fixture(t);
  enrolled.ledger.close();
  assert.throws(() => new Zk1DurableWitnessLedger(enrolled.file, {
    ...enrolled.options, bootstrapNew: false, catalogFloorPublicKey: null,
  }), /WITNESS_CATALOG_DENIED/,
  "a restarted witness cannot drop its persisted, floor-pinned reservation barrier");
  const extra = require("better-sqlite3");
  const db = new extra(enrolled.file);
  try {
    db.exec(`DROP TRIGGER catalog_admission_delete;
      CREATE TRIGGER catalog_admission_delete BEFORE DELETE ON witness_identity
        BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
  } finally { db.close(); }
  assert.throws(enrolled.open, /WITNESS_CATALOG_DENIED/,
    "forged trigger on another table may never count as an immutable reservation ledger");
});

test("expired signed catalog reservation cannot be cleared by the caller and keeps owner revocation stopped", async (t) => {
  const f = await fixture(t);
  const admitted = await f.ledger.beginCatalogAdmission(f.input);
  f.setClock(951);
  await assert.rejects(f.ledger.completeCatalogAdmission({
    scope: f.input.scope, admissionId: admitted.admissionId,
    principal: f.input.principal, floorProof: await f.signFloor(admitted),
  }), /WITNESS_CATALOG_DENIED/);
  await assert.rejects(f.ledger.reserve({ ...f.next, expires_at: 1100 }),
    /WITNESS_CATALOG_ACTIVE/,
    "expired authorization is not license to auto-prune an in-flight remote floor transition");
  f.ledger.close();
  const restarted = f.open();
  await assert.rejects(restarted.reserve({ ...f.next, expires_at: 1100 }),
    /WITNESS_CATALOG_ACTIVE/, "restart cannot bypass an unresolved expired admission");
});

test("owner revocation quiescence wins before witness catalog admission and denies every late grant", async (t) => {
  const f = await fixture(t);
  assert.deepEqual(await f.ledger.prepareQuiesce(f.next),
    { status: "DRAINED", activeCount: 0 });
  await assert.rejects(f.ledger.beginCatalogAdmission(f.input), /WITNESS_CATALOG_DENIED/,
    "signed owner changes quiesce the same durable SQLite scope before new catalog starts");
  assert.equal(f.ledger.db.prepare("SELECT COUNT(*) AS n FROM witness_catalog_admission").get().n, 0);
  await f.ledger.reserve(f.next);
  await assert.rejects(f.ledger.beginCatalogAdmission(f.input), /WITNESS_CATALOG_DENIED/,
    "PENDING owner revision cannot issue any late catalog authorization");
});

test("P2 RED: forged SQLite terminal cannot subtract an unfinished physical admission", async (t) => {
  const f = await fixture(t);
  const admitted = await f.ledger.beginCatalogAdmission(f.input);
  const Database = require("better-sqlite3");
  const foreign = new Database(f.file);
  try {
    foreign.prepare("INSERT INTO witness_catalog_terminal(admission_id,floor_proof,terminal_seal) VALUES(?,?,?)")
      .run(admitted.admissionId, Buffer.from([0x82, 0x01, 0x02, 0x03]),
        crypto.randomBytes(64));
    assert.equal(foreign.pragma("quick_check", { simple: true }), "ok");
  } finally { foreign.close(); }
  await assert.rejects(f.ledger.prepareQuiesce(f.next), /WITNESS_CATALOG_DENIED/,
    "unsigned terminal injected into intact SQLite cannot mark physical work drained");
  await assert.rejects(f.ledger.reserve(f.next), /WITNESS_CATALOG_DENIED|WITNESS_CATALOG_ACTIVE/,
    "owner cannot revoke while the job remains physically ACTIVE");
  f.ledger.close();
  assert.throws(f.open, /WITNESS_CATALOG_DENIED/,
    "restarting may not trust a forged terminal despite SQLite quick_check=ok");
});

test("a valid FLOOR completion cannot be altered in SQL while retaining the witness terminal seal", async (t) => {
  const f = await fixture(t);
  const admitted = await f.ledger.beginCatalogAdmission(f.input);
  await f.ledger.completeCatalogAdmission({ scope: f.input.scope,
    admissionId: admitted.admissionId, principal: f.input.principal,
    floorProof: await f.signFloor(admitted) });
  const Database = require("better-sqlite3");
  const foreign = new Database(f.file);
  try {
    // Simulate a DB editor restoring the exact native immutability trigger
    // after modifying a terminal. SQLite integrity checks still report OK.
    foreign.exec("DROP TRIGGER catalog_terminal_update");
    foreign.prepare("UPDATE witness_catalog_terminal SET floor_proof=? WHERE admission_id=?")
      .run(Buffer.from([0xa0, 0xa1, 0xa2, 0xa3]), admitted.admissionId);
    foreign.exec(`CREATE TRIGGER catalog_terminal_update
      BEFORE UPDATE ON witness_catalog_terminal
      BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END`);
    assert.equal(foreign.pragma("quick_check", { simple: true }), "ok");
  } finally { foreign.close(); }
  await assert.rejects(f.ledger.prepareQuiesce(f.next), /WITNESS_CATALOG_DENIED/,
    "terminal proof modified under restored trigger cannot falsely drain revocation");
  f.ledger.close();
  assert.throws(f.open, /WITNESS_CATALOG_DENIED/,
    "valid terminal witness seal cannot be replayed over changed FLOOR bytes after restart");
});

test("P2 RED: lost START ACK replays exact grant for cleanup only after QUIESCING or expiry", async (t) => {
  const f = await fixture(t);
  const admitted = await f.ledger.beginCatalogAdmission(f.input);
  assert.deepEqual(await f.ledger.prepareQuiesce(f.next),
    { status: "QUIESCING", activeCount: 1 });
  const quiescedReplay = await f.ledger.beginCatalogAdmission(f.input);
  assert.deepEqual(quiescedReplay, { admissionId: admitted.admissionId, proceed: false },
    "a retry gives only the original completion identity, no usable fresh ticket");
  await assert.rejects(f.ledger.beginCatalogAdmission({
    ...f.input, policyGrant: await f.signPolicy(f.input),
  }), /WITNESS_CATALOG_DENIED/,
  "a newly signed token is NOT the original replay during quiescence");
  f.ledger.close();
  const restarted = f.open();
  f.setClock(951);
  assert.deepEqual(await restarted.beginCatalogAdmission(f.input),
    { admissionId: admitted.admissionId, proceed: false },
    "exact durable replay survives restart and expiry without extending authority");
  assert.deepEqual(await restarted.prepareQuiesce(f.next),
    { status: "QUIESCING", activeCount: 1 });
  await assert.rejects(restarted.reserve({ ...f.next, expires_at: 1100 }),
    /WITNESS_QUIESCING|WITNESS_CATALOG_ACTIVE/,
    "replay cannot unquiesce or release owner STOP");
});
