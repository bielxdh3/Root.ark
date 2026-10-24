"use strict";

// Separate real PostgreSQL authority and durable signed SQLite witness
// sharing only a synthetic scope in a disposable laboratory. Not a claim of
// cross-host durability, actual provider stop proofs or production readiness.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Pool } = require("pg");
const z = require("../src/crypto/rootark-zk-1");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedGateWitnessCoordinator } = require("../src/services/zk1SharedGateWitnessCoordinator");

const url = process.env.ROOTARK_ZK1_TEST_PG_URL;
const STATUS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0", "ascii");

test("real durable witness + shared PG gate withhold signed ticket until both workers drain and survive restart", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-gate-witness-real-"));
  const pool = new Pool({ connectionString: url, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => pool.end());
  const pg = new Zk1SharedPgGateAuthority({ pool });
  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(9),
    keyring_id: crypto.randomBytes(16) };
  const scopedKey = scope.account_id.toString("hex") + ":"
    + scope.compartment_id.length.toString(16) + ":" + scope.compartment_id.toString("hex");
  const digest = crypto.randomBytes(32);
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const statusKeys = crypto.generateKeyPairSync("ed25519");
  let now = 900;
  const statusProvider = { async getTerminalProof({ query, nonce }) {
    const unsigned = { type: "rootark-recovery-cas-status/v1",
      status_authority_key_id: statusKeyId, ...query,
      observed_revision: query.proposed_revision,
      observed_manifest_digest: query.proposed_manifest_digest,
      terminal_status: "committed", observed_at: now, nonce };
    const signature = crypto.sign(null, Buffer.concat([STATUS_DOMAIN,
      Buffer.from(await z.encodeDeterministic(unsigned))]), statusKeys.privateKey);
    return Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
  } };
  const filename = path.join(dir, "witness.sqlite");
  const options = { witnessKeyId, witnessPrivateKey: witnessKeys.privateKey,
    statusPinned: { keyId: statusKeyId, publicKey: statusKeys.publicKey },
    statusProvider, nowSeconds: () => now };
  let witness = new Zk1DurableWitnessLedger(filename, { ...options, bootstrapNew: true });
  t.after(() => witness.close());
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10,
    retryDelay: 100 }));
  const genesis = { ...scope, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: null,
    expected_manifest_digest: null, proposed_revision: 1,
    proposed_manifest_digest: digest, request_digest: crypto.randomBytes(32),
    package_envelope_digest: null, expires_at: 1100 };
  await witness.reserve(genesis);
  assert.equal((await witness.resolve({ scope })).status, "committed");
  await pool.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [scopedKey, scope.keyring_id, digest]);
  const operation = { ...scope, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: 1,
    expected_manifest_digest: digest, proposed_revision: 2,
    proposed_manifest_digest: crypto.randomBytes(32), request_digest: crypto.randomBytes(32),
    package_envelope_digest: null, expires_at: 1100 };
  const principal = "AB:".repeat(31) + "AB";
  const objectId = crypto.randomBytes(16).toString("base64url");
  const worker = { scope, revision: 1, digest, action: "put", objectId,
    workerId: crypto.randomBytes(16), principal };
  const pgWorker = await pg.beginIoAdmission(worker);
  const witnessWorker = await witness.beginIoAdmission(worker);
  // Coordinator intentionally depends on the normalized HTTPS-client
  // contract, not on the direct trusted engine's positional API.
  const witnessAdapter = {
    prepareQuiesce: ({ operation: request }) => witness.prepareQuiesce(request),
    reserve: ({ operation: request }) => witness.reserve(request),
  };
  const coordinator = () => new Zk1SharedGateWitnessCoordinator({ gate: pg,
    witness: witnessAdapter,
    witnessPinned: { keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
    nowSeconds: () => now,
    verifyOwnerIntent: async ({ operation: candidate, ownerAuthorization }) =>
      ownerAuthorization === "trusted-owner" && candidate.operation_id.equals(operation.operation_id),
  });
  const invoke = () => coordinator().reserveAfterDrain({ operation,
    ownerAuthorization: "trusted-owner" });

  const first = await invoke();
  assert.deepEqual([first.status, first.pgActive, first.witnessActive],
    ["QUIESCING", 1, 1]);
  await assert.rejects(pg.putCiphertextChunk({ ...worker,
    admissionId: pgWorker.admissionId, generation: pgWorker.generation }, 0,
  crypto.randomBytes(32)), /ZK_GATE_DENIED/,
  "a previously authorized old-generation physical write may not run after PG quiesce");
  await pg.finishIoAdmission({ scope, admissionId: pgWorker.admissionId,
    workerId: worker.workerId, principal });
  const waitingWitness = await invoke();
  assert.deepEqual([waitingWitness.status, waitingWitness.pgActive,
    waitingWitness.witnessActive], ["QUIESCING", 0, 1]);
  await witness.finishIoAdmission({ scope, admissionId: witnessWorker.admissionId,
    workerId: worker.workerId, principal });
  const pending = await invoke();
  assert.equal(pending.status, "PENDING");
  assert.ok(pending.reservation.length > 64, "a genuine witness signed reservation was issued");
  const remote = await pool.query("SELECT phase FROM zk1_gate.head WHERE scope_key=$1",
    [scopedKey]);
  assert.equal(remote.rows[0].phase, "PENDING");
  const signedHead = await z.decodeDeterministic(await witness.freshHead({ scope,
    nonce: crypto.randomBytes(32) }));
  assert.equal(signedHead.status, "pending");
  await assert.rejects(pg.beginIoAdmission({ ...worker,
    workerId: crypto.randomBytes(16) }), /ZK_GATE_DENIED/);

  // A crash of the witness cannot reopen the existing PG PENDING fence.
  witness.close();
  witness = new Zk1DurableWitnessLedger(filename, { ...options, bootstrapNew: false });
  const retried = await invoke();
  assert.deepEqual(retried.reservation, pending.reservation,
    "lost reservation ACK after restart is recovered without issuing new operation");
  assert.equal((await pool.query("SELECT phase FROM zk1_gate.head WHERE scope_key=$1",
    [scopedKey])).rows[0].phase, "PENDING");
  now = 1000;
});
