"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const { Pool } = require("pg");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");
const { Zk1SharedPgCiphertextSink } = require("../src/services/zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");
const { Zk1PgPhysicalInventoryBridge } =
  require("../src/services/zk1PgPhysicalInventoryBridge");

const enabled = Boolean(process.env.ROOTARK_ZK1_TEST_PG_URL
  && process.env.ROOTARK_ZK1_RUNTIME_PG_URL
  && process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);

async function fixture(t) {
  const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL,
    max: 2, connectionTimeoutMillis: 2500 });
  const gatePool = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL,
    max: 2, connectionTimeoutMillis: 2500 });
  // A separate PG connection pool independently re-reads the physically
  // committed ciphertext; it has no INSERT/UPDATE/DELETE privileges.
  const proofPool = new Pool({ connectionString: process.env.ROOTARK_ZK1_ATTESTOR_PG_URL,
    max: 2, connectionTimeoutMillis: 2500 });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-physical-inventory-"));
  const dbPath = path.join(dir, "signed-inventory.sqlite");
  const keys = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(8), keyring_id: crypto.randomBytes(16) };
  const digest = crypto.randomBytes(32);
  const key = scope.account_id.toString("hex") + ":"
    + scope.compartment_id.length.toString(16) + ":" + scope.compartment_id.toString("hex");
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_physical_inventory_intent)
    VALUES($1,$2,1,$3,TRUE)`,
    [key, scope.keyring_id, digest]);
  let ledger = await Zk1DurableContentInventoryLedger.open(dbPath, {
    bootstrapNew: true, signerKeyId, signerPrivateKey: keys.privateKey, scope,
  });
  const gate = new Zk1SharedPgGateAuthority({ pool: gatePool });
  const sealedStore = new Zk1SharedPgSealedObjectStore({ pool: gatePool });
  const calls = [];
  const principal = "physical-inventory-lab";
  const gateClient = {
    beginIoAdmission: async (op) => {
      calls.push("begin");
      return gate.beginIoAdmission({ ...op, principal });
    },
    putCiphertextChunk: async (op, index, bytes) => {
      calls.push("chunk");
      return gate.putCiphertextChunk({ ...op, principal }, index, bytes);
    },
    sealCiphertextObject: async (op, count, root) => {
      calls.push("seal");
      return sealedStore.seal({ ...op, principal, expectedChunkCount: count,
        expectedRootHash: root });
    },
    finishIoAdmission: async (op) => {
      calls.push("finish");
      return gate.finishIoAdmission({ ...op, principal });
    },
  };
  const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: proofPool });
  const intentAuthority = new Zk1SharedPgPhysicalInventoryIntent({ pool: gatePool });
  const sink = new Zk1SharedPgCiphertextSink({ gateClient });
  const bridge = () => new Zk1PgPhysicalInventoryBridge({ sink, verifier, intentAuthority, ledger,
    pinnedPublicKey: keys.publicKey, pinnedSignerKeyId: signerKeyId });
  t.after(async () => {
    try { ledger.close(); } catch (_) {}
    await Promise.all([admin.end(), gatePool.end(), proofPool.end()]);
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 });
  });
  const chunks = [crypto.randomBytes(100), crypto.randomBytes(66)];
  const objectId = crypto.randomBytes(16);
  const ciphertext = Buffer.concat(chunks);
  const root = computeZk1CiphertextRoot(chunks);
  const op = { operation_id: crypto.randomBytes(16), expected_sequence: 0,
    expected_root: (await ledger.readLocalHead()).root,
    object_id: objectId, revision: 1, epoch: 1,
    ciphertext_sha256: crypto.createHash("sha256").update(ciphertext).digest() };
  const physical = { scope, operation: op, digest, chunks,
    expectedRootHash: root, expectedChunkCount: chunks.length };
  const noChunks = () => ({ scope, operation: op, digest,
    expectedRootHash: root, expectedChunkCount: chunks.length });
  return { admin, gate, gatePool, proofPool, intentAuthority, sealedStore, calls, verifier, bridge,
    physical, noChunks,
    scope, key, op, root, chunks, digest, keys, signerKeyId, restart: async () => {
      ledger.close();
      ledger = await Zk1DurableContentInventoryLedger.open(dbPath, {
        bootstrapNew: false, signerKeyId, signerPrivateKey: keys.privateKey, scope,
      });
      return bridge();
    }, get ledger() { return ledger; } };
}

test("real PostgreSQL seal is physically reread before exact Ed25519 inventory commit, replay survives restart", {
  skip: !enabled && "requires a disposable restricted PG18 gate fixture",
}, async (t) => {
  const f = await fixture(t);
  const result = await f.bridge().putAndAttest(f.physical);
  assert.equal(result.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(result.authorizesIo, false);
  assert.equal(result.externalProviderDurabilityProven, false);
  assert.equal(result.localPgWalFlushConfirmed, true);
  assert.equal(result.independentlyAnchoredFloorProven, false);
  assert.deepEqual(result.verifiedReceipt.operationId, f.op.operation_id);
  const bound = await f.admin.query(`SELECT operation_id,expected_inventory_root,
    expected_inventory_sequence,ciphertext_sha256,expected_root_hash
    FROM zk1_gate.physical_inventory_intent WHERE scope_key=$1 AND object_id=$2`,
  [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(bound.rowCount, 1);
  assert.deepEqual(bound.rows[0].operation_id, f.op.operation_id);
  assert.deepEqual(bound.rows[0].ciphertext_sha256, f.op.ciphertext_sha256);
  assert.deepEqual(result.verifiedReceipt.tuple.ciphertext_sha256, f.op.ciphertext_sha256);
  assert.deepEqual(f.calls, ["begin", "chunk", "chunk", "seal", "finish"]);
  const exactRow = await f.admin.query(`SELECT root_hash,generation,expected_chunks
    FROM zk1_gate.sealed_object WHERE scope_key=$1 AND object_id=$2`,
  [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(exactRow.rowCount, 1);
  assert.deepEqual(exactRow.rows[0].root_hash, f.root);
  assert.equal(exactRow.rows[0].expected_chunks, 2);
  const again = await f.bridge().putAndAttest(f.physical);
  assert.equal(again.status, result.status);
  assert.deepEqual(f.calls, ["begin", "chunk", "chunk", "seal", "finish"],
    "an exact signed replay must never launch a new physical PUT admission");
  const restarted = await f.restart();
  const recovered = await restarted.reconcile(f.noChunks());
  assert.equal(recovered.status, result.status);
  assert.equal(recovered.sequence, result.sequence);
  assert.deepEqual(recovered.root, result.root);
  await assert.rejects(restarted.reconcile({ ...f.noChunks(),
    operation: { ...f.op, operation_id: crypto.randomBytes(16) } }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "a different operation ID now fails at the durable physical prewrite binding");
});

test("unverified physical write, partial seal, and generation fencing never publish a signed success", {
  skip: !enabled && "requires a disposable restricted PG18 gate fixture",
}, async (t) => {
  const f = await fixture(t);
  const originalVerifier = f.verifier.verifyExact.bind(f.verifier);
  let failReadback = true;
  f.verifier.verifyExact = async (...args) => {
    if (failReadback) throw new Error("synthetic independent readback unavailable");
    return originalVerifier(...args);
  };
  await assert.rejects(f.bridge().putAndAttest(f.physical),
    /synthetic independent readback unavailable/,
    "successful PostgreSQL SEALED response is insufficient to attest the signed inventory");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown",
    "physical sealed bytes must be left intact for recovery, not falsely signed");
  failReadback = false;
  const reconciled = await f.bridge().publishExisting(f.noChunks());
  assert.equal(reconciled.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY",
    "restart can sign after separately verifying genuine physical commit");
  const op = { scope: f.scope, revision: 1, digest: f.digest,
    operationId: crypto.randomBytes(16), reservationId: crypto.randomBytes(16) };
  assert.equal((await f.gate.beginQuiesce(op)).activeCount, 0);
  assert.equal((await f.gate.markPending(op)).status, "PENDING");
  await assert.rejects(f.bridge().reconcile(f.noChunks()), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "signed historical inventory and ciphertext still on disk cannot bypass the newer fenced generation");
});

test("wrong owner-verified chunk hash rejects before physical IO and DB access", {
  skip: !enabled && "requires a disposable restricted PG18 gate fixture",
}, async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.bridge().putAndAttest({ ...f.physical,
    chunks: [Buffer.from("wrong"), Buffer.from("payload")] }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.deepEqual(f.calls, []);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown");
});

test("attestor has physical SELECT only; gate, writer and superuser cannot masquerade as attestor", {
  skip: !enabled && "requires disposable read-only attestor and gate roles",
}, async (t) => {
  const f = await fixture(t);
  const checks = await f.proofPool.query(`SELECT
    pg_catalog.has_table_privilege(current_user,'zk1_gate.head','UPDATE') AS can_update_head,
    pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','INSERT') AS can_insert,
    pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','DELETE') AS can_delete,
    pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','MEMBER') AS gate_member,
    pg_catalog.pg_has_role(current_user,'zk1_stop_runtime','MEMBER') AS stop_member,
    pg_catalog.pg_has_role(current_user,'zk1_chunk_writer_runtime','MEMBER') AS writer_member`);
  assert.equal(checks.rowCount, 1);
  assert.deepEqual(checks.rows[0], {
    can_update_head: false, can_insert: false, can_delete: false,
    gate_member: false, stop_member: false, writer_member: false,
  });
  assert.equal((await f.proofPool.query("SELECT COUNT(*)::integer AS n FROM zk1_gate.head"))
    .rows[0].n > 0, true);
  await assert.rejects(f.proofPool.query("UPDATE zk1_gate.head SET phase='OPEN' WHERE false"),
    /permission denied/);
  const privileged = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: f.gatePool });
  await assert.rejects(privileged.verifyExact({
    scope: f.scope, objectId: f.op.object_id.toString("base64url"),
    revision: 1, digest: f.digest, expectedRootHash: f.root,
    expectedChunkCount: 2, expectedSha256: f.op.ciphertext_sha256,
    operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
    expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
  }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
});

test("superuser-altered physical ciphertext is detected despite an authentic earlier Ed25519 receipt", {
  skip: !enabled && "requires disposable PG18 with a restricted attestor",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  await f.admin.query(`UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1
    WHERE scope_key=$2 AND object_id=$3 AND chunk_index=1`,
  [crypto.randomBytes(66), f.key, f.op.object_id.toString("base64url")]);
  await assert.rejects(f.bridge().reconcile(f.noChunks()),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "a previously valid signed inventory cannot mask later physical corruption");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "committed",
    "the signature remains historical evidence, NOT physical release authorization");
});

test("a partially inserted chunk stream never causes an Ed25519 signed inventory success", {
  skip: !enabled && "requires disposable PG18 with a restricted attestor",
}, async (t) => {
  const f = await fixture(t);
  const originalPut = f.bridge().sink.gate.putCiphertextChunk;
  f.bridge().sink.gate.putCiphertextChunk = async (op, index, chunk) => {
    if (index === 1) throw new Error("simulated persistent physical provider outage");
    return originalPut(op, index, chunk);
  };
  await assert.rejects(f.bridge().putAndAttest(f.physical),
    /ZK_GATE_SINK_UNAVAILABLE/);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown");
  const chunks = await f.admin.query(`SELECT chunk_index FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1 AND object_id=$2`, [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(chunks.rowCount, 1);
  assert.equal(chunks.rows[0].chunk_index, 0);
  const seal = await f.admin.query(`SELECT 1 FROM zk1_gate.sealed_object
    WHERE scope_key=$1 AND object_id=$2`, [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(seal.rowCount, 0, "partial storage must have no SEALED evidence");
  await assert.rejects(f.bridge().publishExisting(f.noChunks()),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "disconnected or incomplete provider cannot be reconstructed as signed success");
});

test("read-only attestor rejects a poisoned column-level INSERT grant hidden from table-level preflight", {
  skip: !enabled && "requires disposable PostgreSQL attestor role",
}, async (t) => {
  const f = await fixture(t);
  const login = "zkattestorpoison_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  await f.admin.query(`GRANT INSERT(ciphertext) ON zk1_gate.ciphertext_chunk TO ${login}`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  try {
    const granted = await poisonedPool.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','INSERT') AS table_insert,
      pg_catalog.has_any_column_privilege(current_user,'zk1_gate.ciphertext_chunk','INSERT') AS column_insert`);
    assert.deepEqual(granted.rows[0], { table_insert: false, column_insert: true });
    const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool });
    await assert.rejects(verifier.verifyExact({
      scope: f.scope, objectId: f.op.object_id.toString("base64url"),
      revision: 1, digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: 2, expectedSha256: f.op.ciphertext_sha256,
    operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
    expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
    }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "a read-only identity is invalid if any dormant column-level writer grant exists");
  } finally {
    // Run this before fixture(t)'s after hook closes the admin pool. Exact
    // disposable login only, never broad cleanup.
    await poisonedPool.end();
    await f.admin.query(`REVOKE INSERT(ciphertext) ON zk1_gate.ciphertext_chunk FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`DROP ROLE ${login}`);
  }
});

test("physical attestor rejects separately poisoned TRUNCATE/DELETE privileges before touching bytes", {
  skip: !enabled && "requires disposable PostgreSQL attestor role",
}, async (t) => {
  const f = await fixture(t);
  const login = "zkattestordestruct_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  const objectId = f.op.object_id.toString("base64url");
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  // Runtime-role REVOKE cannot erase a direct poisoned LOGIN grant. TRUNCATE
  // bypasses BEFORE DELETE triggers and is more powerful than a read-only
  // physical proof identity can ever possess.
  await f.admin.query(`GRANT TRUNCATE ON zk1_gate.physical_inventory_intent TO ${login}`);
  await f.admin.query(`GRANT DELETE ON zk1_gate.sealed_object TO ${login}`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  try {
    const check = await poisonedPool.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_gate.physical_inventory_intent','TRUNCATE') AS truncate_intent,
      pg_catalog.has_table_privilege(current_user,'zk1_gate.sealed_object','DELETE') AS delete_seal`);
    assert.deepEqual(check.rows[0], { truncate_intent: true, delete_seal: true });
    const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool });
    await assert.rejects(verifier.verifyExact({
      scope: f.scope, objectId, revision: 1, digest: f.digest,
      expectedRootHash: f.root, expectedChunkCount: f.chunks.length,
      expectedSha256: f.op.ciphertext_sha256, operationId: f.op.operation_id,
      expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
    }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "destructive powers must invalidate physical readback even if bytes are intact");
    assert.equal((await f.admin.query(`SELECT COUNT(*)::integer AS n
      FROM zk1_gate.physical_inventory_intent
      WHERE scope_key=$1 AND object_id=$2`, [f.key, objectId])).rows[0].n, 1);
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE TRUNCATE ON zk1_gate.physical_inventory_intent FROM ${login}`);
    await f.admin.query(`REVOKE DELETE ON zk1_gate.sealed_object FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`DROP ROLE ${login}`);
  }
});

test("physical attestor separately rejects poisoned admission UPDATE and head INSERT grants", {
  skip: !enabled && "requires disposable PostgreSQL attestor role",
}, async (t) => {
  const f = await fixture(t);
  const login = "zkattestorgatepoison_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  const verify = () => new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool })
    .verifyExact({ scope: f.scope, objectId: f.op.object_id.toString("base64url"),
      revision: 1, digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: f.chunks.length, expectedSha256: f.op.ciphertext_sha256,
      operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch });
  try {
    await f.admin.query(`GRANT UPDATE(state) ON zk1_gate.admission TO ${login}`);
    assert.equal((await poisonedPool.query(`SELECT
      pg_catalog.has_any_column_privilege(current_user,'zk1_gate.admission','UPDATE') AS capability`))
      .rows[0].capability, true);
    await assert.rejects(verify(), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "a login able to finish or alter admissions is not a read-only physical attestor");
    await f.admin.query(`REVOKE UPDATE(state) ON zk1_gate.admission FROM ${login}`);
    await f.admin.query(`GRANT INSERT(scope_key,keyring_id,revision,digest)
      ON zk1_gate.head TO ${login}`);
    assert.equal((await poisonedPool.query(`SELECT
      pg_catalog.has_any_column_privilege(current_user,'zk1_gate.head','INSERT') AS capability`))
      .rows[0].capability, true);
    await assert.rejects(verify(), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "a login able to provision fabricated gate heads cannot attest ciphertext");
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE UPDATE(state) ON zk1_gate.admission FROM ${login}`);
    await f.admin.query(`REVOKE INSERT(scope_key,keyring_id,revision,digest)
      ON zk1_gate.head FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`DROP ROLE ${login}`);
  }
});

test("physical attestor rejects destructive SET ROLE reachability hidden behind NOINHERIT", {
  skip: !enabled && "requires disposable PostgreSQL 18 membership options",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const login = "zkattestorswitch_" + crypto.randomBytes(6).toString("hex");
  const hidden = "zkhiddenwriter_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  await f.admin.query(`CREATE ROLE ${hidden} NOLOGIN NOINHERIT`);
  await f.admin.query(`CREATE ROLE ${login} LOGIN INHERIT PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  await f.admin.query(`GRANT USAGE ON SCHEMA zk1_gate TO ${hidden}`);
  await f.admin.query(`GRANT TRUNCATE ON zk1_gate.physical_inventory_intent TO ${hidden}`);
  // Deliberately no inherited DML: existing direct-login privilege preflight
  // will report false until SET ROLE switches to the hidden destructive role.
  await f.admin.query(`GRANT ${hidden} TO ${login} WITH INHERIT FALSE, SET TRUE`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  try {
    const c = await poisonedPool.connect();
    try {
      const before = await c.query(`SELECT
        pg_catalog.has_table_privilege(current_user,
          'zk1_gate.physical_inventory_intent','TRUNCATE') AS direct_power,
        pg_catalog.pg_has_role(current_user,'zk1_physical_attestor_runtime','USAGE') AS normal_attestor,
        pg_catalog.pg_has_role(current_user,$1,'SET') AS may_set_role`, [hidden]);
      assert.deepEqual(before.rows[0],
        { direct_power: false, normal_attestor: true, may_set_role: true });
      await c.query(`SET ROLE ${hidden}`);
      const after = await c.query(`SELECT pg_catalog.has_table_privilege(current_user,
        'zk1_gate.physical_inventory_intent','TRUNCATE') AS gained_power`);
      assert.equal(after.rows[0].gained_power, true,
        "the poisoned login really can obtain TRUNCATE via SET ROLE");
      await c.query("RESET ROLE");
    } finally {
      c.release();
    }
    const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool });
    await assert.rejects(verifier.verifyExact({
      scope: f.scope, objectId: f.op.object_id.toString("base64url"),
      revision: 1, digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: f.chunks.length, expectedSha256: f.op.ciphertext_sha256,
      operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
    }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "read-only attestation must fail if its login can SET ROLE into destructive privilege");
    assert.equal((await f.admin.query(`SELECT COUNT(*)::integer AS n FROM
      zk1_gate.physical_inventory_intent WHERE scope_key=$1`, [f.key])).rows[0].n, 1,
    "the proof must not mutate owner physical evidence");
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE ${hidden} FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`REVOKE TRUNCATE ON zk1_gate.physical_inventory_intent FROM ${hidden}`);
    await f.admin.query(`REVOKE USAGE ON SCHEMA zk1_gate FROM ${hidden}`);
    await f.admin.query(`DROP ROLE ${login}`);
    await f.admin.query(`DROP ROLE ${hidden}`);
  }
});

test("physical attestor refuses schema CREATE and table MAINTAIN grants on its SQL identity", {
  skip: !enabled && "requires disposable PostgreSQL 18 MAINTAIN capability",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const login = "zkattestorddl_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  const verify = () => new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool })
    .verifyExact({ scope: f.scope,
      objectId: f.op.object_id.toString("base64url"), revision: 1,
      digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: f.chunks.length, expectedSha256: f.op.ciphertext_sha256,
      operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch });
  try {
    await f.admin.query(`GRANT MAINTAIN ON zk1_gate.sealed_object TO ${login}`);
    assert.equal((await poisonedPool.query(`SELECT pg_catalog.has_table_privilege(
      current_user,'zk1_gate.sealed_object','MAINTAIN') AS capability`)).rows[0].capability,
    true);
    await assert.rejects(verify(), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "VACUUM/REINDEX/CLUSTER capability is not strictly read-only");
    await f.admin.query(`REVOKE MAINTAIN ON zk1_gate.sealed_object FROM ${login}`);
    await f.admin.query(`GRANT CREATE ON SCHEMA zk1_gate TO ${login}`);
    assert.equal((await poisonedPool.query(`SELECT pg_catalog.has_schema_privilege(
      current_user,'zk1_gate','CREATE') AS capability`)).rows[0].capability, true);
    await assert.rejects(verify(), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "ability to create objects in the protected schema is not read-only");
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE MAINTAIN ON zk1_gate.sealed_object FROM ${login}`);
    await f.admin.query(`REVOKE CREATE ON SCHEMA zk1_gate FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`DROP ROLE ${login}`);
  }
});

test("physical attestor rejects indirect privileged PostgreSQL OS role without executing commands", {
  skip: !enabled && "requires disposable PostgreSQL 18 predefined role membership",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const login = "zkattestorescape_" + crypto.randomBytes(6).toString("hex");
  const hidden = "zkhostrole_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  await f.admin.query(`CREATE ROLE ${hidden} NOLOGIN NOINHERIT`);
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  await f.admin.query(`GRANT pg_execute_server_program TO ${hidden}
    WITH INHERIT FALSE, SET TRUE`);
  await f.admin.query(`GRANT ${hidden} TO ${login} WITH INHERIT FALSE, SET TRUE`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  try {
    const observed = await poisonedPool.query(`SELECT
      pg_catalog.pg_has_role(current_user,'pg_execute_server_program','USAGE') AS effective,
      pg_catalog.pg_has_role(current_user,'pg_execute_server_program','SET') AS reachable`);
    assert.deepEqual(observed.rows[0], { effective: false, reachable: true },
      "a non-inherited predefined role grants dangerous future SET ROLE powers");
    // NEVER actually run COPY TO PROGRAM, filesystem writes, shell or remote
    // services. Prove the privilege graph only, then require verifier denial.
    const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool });
    await assert.rejects(verifier.verifyExact({
      scope: f.scope, objectId: f.op.object_id.toString("base64url"),
      revision: 1, digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: f.chunks.length, expectedSha256: f.op.ciphertext_sha256,
      operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
    }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "predefined PostgreSQL execution powers invalidate read-only physical attestation");
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE ${hidden} FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`REVOKE pg_execute_server_program FROM ${hidden}`);
    await f.admin.query(`DROP ROLE ${login}`);
    await f.admin.query(`DROP ROLE ${hidden}`);
  }
});

test("a different physical scope cannot poison the fixed-scope Ed25519 inventory before rejection", {
  skip: !enabled && "requires disposable PostgreSQL 18 lab",
}, async (t) => {
  const f = await fixture(t);
  const foreign = { ...f.scope, compartment_id: crypto.randomBytes(8) };
  await assert.rejects(f.bridge().putAndAttest({ ...f.physical, scope: foreign }),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  await assert.rejects(f.bridge().publishExisting({ ...f.noChunks(), scope: foreign }),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.deepEqual(f.calls, []);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown",
    "cross-scope failure must never leave a signed local SQLite commit");
  const row = await f.admin.query(`SELECT 1 FROM zk1_gate.physical_inventory_intent
    WHERE scope_key=$1 AND object_id=$2`, [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(row.rowCount, 0, "scope denial also precedes the physical PREWRITE bind");
});

test("immutable prewrite intent cannot be relabeled to another operation after physical seal", {
  skip: !enabled && "requires disposable PostgreSQL 18 lab",
}, async (t) => {
  const f = await fixture(t);
  const status = await f.bridge().putAndAttest(f.physical);
  assert.equal(status.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const relabeled = { ...f.op, operation_id: crypto.randomBytes(16) };
  await assert.rejects(f.bridge().publishExisting({
    ...f.noChunks(), operation: relabeled,
  }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "a SEALED object cannot be given a different physical operation ID");
  await assert.rejects(f.intentAuthority.reserveExact({
    ...f.noChunks(), operation: relabeled,
  }), /ZK_PHYSICAL_INTENT_UNAVAILABLE/,
  "immutable first-writer physical reservation denies conflicting retransmission");
  assert.equal((await f.ledger.getOperationStatus(relabeled.operation_id)).status, "unknown");
});

test("operator WAL barrier flushes an independently async-committed PG transaction", {
  skip: !enabled && "requires disposable PostgreSQL 18 lab",
}, async (t) => {
  const f = await fixture(t);
  const other = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(8), keyring_id: crypto.randomBytes(16) };
  const key = other.account_id.toString("hex") + ":"
    + other.compartment_id.length.toString(16) + ":" + other.compartment_id.toString("hex");
  const c = await f.admin.connect();
  try {
    await c.query("BEGIN");
    await c.query("SET LOCAL synchronous_commit = off");
    await c.query(`INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest)
      VALUES($1,$2,1,$3)`, [key, other.keyring_id, crypto.randomBytes(32)]);
    await c.query("COMMIT");
  } finally { c.release(); }
  const barrier = await f.proofPool.query(
    "SELECT zk1_gate.physical_inventory_wal_flush_barrier() AS flushed");
  assert.equal(barrier.rows[0]?.flushed, true,
    "flush fence must not depend on a separate writer session's synchronous_commit");
  assert.equal((await f.proofPool.query(
    "SELECT 1 FROM zk1_gate.head WHERE scope_key=$1", [key])).rowCount, 1);
});

test("strict PG SQL trigger blocks gate role raw chunks without exact immutable operation intent", {
  skip: !enabled && "requires disposable PG18",
}, async (t) => {
  const f = await fixture(t);
  const objectId = f.op.object_id.toString("base64url");
  const workerId = crypto.randomBytes(16);
  const principal = "strict-raw-sql-adversary";
  await assert.rejects(f.gate.beginIoAdmission({
    scope: f.scope, workerId, principal, action: "put",
    objectId, revision: 1, digest: f.digest,
  }), /ZK_GATE_UNAVAILABLE/,
  "an admission cannot precede its immutable operation intent on strict scope");
  const prewrite = await f.intentAuthority.reserveExact(f.noChunks());
  assert.equal(prewrite.status, "IMMUTABLE_PREWRITE_INTENT");
  const started = await f.gate.beginIoAdmission({
    scope: f.scope, workerId, principal, action: "put",
    objectId, revision: 1, digest: f.digest,
  });
  assert.equal(started.proceed, true);
  const directPut = (index, object = objectId) => f.gatePool.query(
    `INSERT INTO zk1_gate.ciphertext_chunk(scope_key,object_id,chunk_index,ciphertext)
      VALUES($1,$2,$3,$4)`, [f.key, object, index, f.chunks[0]]);
  const binding = await f.admin.query(`SELECT operation_id,admission_id FROM
    zk1_gate.physical_inventory_admission WHERE scope_key=$1 AND object_id=$2`,
  [f.key, objectId]);
  assert.equal(binding.rowCount, 1);
  assert.deepEqual(binding.rows[0].operation_id, f.op.operation_id);
  assert.deepEqual(binding.rows[0].admission_id, started.admissionId);
  const count = await f.admin.query(
    "SELECT COUNT(*)::integer AS n FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1", [f.key]);
  assert.equal(count.rows[0].n, 0);
  await assert.rejects(f.gate.beginIoAdmission({
    scope: f.scope, workerId: crypto.randomBytes(16),
    principal: "other-admission", action: "put",
    objectId, revision: 1, digest: f.digest,
  }), /ZK_GATE_UNAVAILABLE/,
  "second admission must not usurp the immutable operation binding");
  await assert.rejects(f.admin.query(`UPDATE zk1_gate.physical_inventory_admission
    SET admission_id=$1 WHERE scope_key=$2 AND object_id=$3`,
  [crypto.randomBytes(16), f.key, objectId]), /physical admission binding is immutable/i);
  await assert.rejects(directPut(f.chunks.length), /strict chunk requires exact prewrite/i,
    "even a privileged gate login cannot exceed the operation-intent chunk boundary");
  await assert.rejects(directPut(0, crypto.randomBytes(16).toString("base64url")),
    /strict chunk requires exact prewrite/i,
    "a valid admission cannot retarget another unbound object");
  await assert.rejects(f.gatePool.query(
    `INSERT INTO zk1_gate.sealed_object
      (scope_key,object_id,revision,digest,generation,admission_id,expected_chunks,root_hash)
      VALUES($1,$2,1,$3,$4,$5,$6,$7)`,
    [f.key, objectId, f.digest, started.generation, started.admissionId,
      f.chunks.length + 1, f.root]), /strict seal requires exact prewrite/i);
  await f.admin.query("SELECT 1");
  await assert.rejects(f.admin.query(`UPDATE zk1_gate.head
    SET require_physical_inventory_intent=FALSE WHERE scope_key=$1`, [f.key]),
  /gate head identity is immutable/i,
  "an operator cannot downgrade strict physical intent after provisioning");
  await assert.rejects(f.admin.query(`UPDATE zk1_gate.physical_inventory_intent
    SET operation_id=$1 WHERE scope_key=$2 AND object_id=$3`,
  [crypto.randomBytes(16), f.key, objectId]), /physical inventory intent is immutable/i);
  await directPut(0);
  assert.equal((await f.admin.query(`SELECT COUNT(*)::integer AS n
    FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1`, [f.key])).rows[0].n, 1);
});

test("strict physical operation reservation races quiesce and forbids obsolete generation write", {
  skip: !enabled && "requires disposable PG18",
}, async (t) => {
  const f = await fixture(t);
  const guard = await f.admin.connect();
  await guard.query("BEGIN");
  try {
    await guard.query("SELECT 1 FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE", [f.key]);
    const pending = f.intentAuthority.reserveExact(f.noChunks());
    // Already blocked by independent PG row lock. Quiesce goes after the
    // initial committed intent, then generation must permanently advance.
    await guard.query("COMMIT");
    assert.equal((await pending).status, "IMMUTABLE_PREWRITE_INTENT");
  } finally {
    try { await guard.query("ROLLBACK"); } catch (_) {}
    guard.release();
  }
  const fenced = { scope: f.scope, revision: 1, digest: f.digest,
    operationId: crypto.randomBytes(16), reservationId: crypto.randomBytes(16) };
  assert.equal((await f.gate.beginQuiesce(fenced)).activeCount, 0);
  await assert.rejects(f.intentAuthority.reserveExact(f.noChunks()), /ZK_PHYSICAL_INTENT_UNAVAILABLE/,
    "a previous-generation operation is not reopened by a replayed reserve");
  await assert.rejects(f.gate.beginIoAdmission({
    scope: f.scope, workerId: crypto.randomBytes(16), principal: "obsolete-physical",
    action: "put", objectId: f.op.object_id.toString("base64url"),
    revision: 1, digest: f.digest,
  }), /ZK_GATE_DENIED/,
  "a previous gate generation cannot mint any new physical writer");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown",
    "an orphan prewrite intent must never be promoted to signed ciphertext");
});

test("strict SQL seal persists the exact immutable physical operation ID, not a caller-chosen substitute", {
  skip: !enabled && "requires disposable PG18",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const row = await f.admin.query(`SELECT operation_id FROM zk1_gate.sealed_object
    WHERE scope_key=$1 AND object_id=$2`, [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(row.rowCount, 1);
  assert.deepEqual(row.rows[0].operation_id, f.op.operation_id);
  // The signed catalog cannot authorize after a physical superuser rewrites
  // even the apparently matching bytes' operation binding.
  await f.admin.query(`UPDATE zk1_gate.sealed_object SET operation_id=$1
    WHERE scope_key=$2 AND object_id=$3`,
  [crypto.randomBytes(16), f.key, f.op.object_id.toString("base64url")]);
  await assert.rejects(f.bridge().reconcile(f.noChunks()),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "committed",
    "a historical signature survives tampering but does not prove current physical bytes");
});
