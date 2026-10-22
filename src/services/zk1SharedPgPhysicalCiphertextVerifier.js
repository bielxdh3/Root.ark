"use strict";

// Post-commit, independent physical PostgreSQL readback. Does not authorize
// owner devices, content release, external provider durability or rollback.
// A distinct read-only attestor login is mandatory. The gate/STOP/writer
// operator and any dormant SET ROLE permissions are explicitly forbidden.
const crypto = require("node:crypto");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { createZk1CiphertextRootBuilder } = require("../crypto/rootark-zk-chunk-root-v1");

function fail() {
  const e = new Error("ZK_PHYSICAL_INVENTORY_UNAVAILABLE");
  e.code = e.message;
  throw e;
}
function bytes(value, size, max = size) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)
    || value.length < size || value.length > max) fail();
  return Buffer.from(value);
}
function same(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}
function exact(input, fields) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    || Reflect.ownKeys(input).length !== fields.length
    || fields.some((name) => !Object.hasOwn(input, name))) fail();
  const result = Object.create(null);
  for (const name of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
    result[name] = descriptor.value;
  }
  return result;
}
function checked(input) {
  const raw = exact(input, ["scope", "objectId", "revision", "digest",
    "expectedRootHash", "expectedChunkCount", "expectedSha256", "operationId",
    "expectedInventorySequence", "expectedInventoryRoot", "epoch"]);
  const scope = inventory.normalizeScope(raw.scope);
  if (typeof raw.objectId !== "string" || !/^[a-zA-Z0-9_-]{22}$/.test(raw.objectId)
    || Buffer.from(raw.objectId, "base64url").toString("base64url") !== raw.objectId
    || !Number.isSafeInteger(raw.revision) || raw.revision < 1
    || !Number.isSafeInteger(raw.epoch) || raw.epoch < 0
    || !Number.isSafeInteger(raw.expectedInventorySequence)
    || raw.expectedInventorySequence < 0
    || raw.expectedInventorySequence >= inventory.MAX_ENTRIES
    || !Number.isSafeInteger(raw.expectedChunkCount)
    || raw.expectedChunkCount < 1 || raw.expectedChunkCount > 16) fail();
  return { scope, scopeKey: scope.account_id.toString("hex") + ":"
      + scope.compartment_id.length.toString(16) + ":" + scope.compartment_id.toString("hex"),
    objectId: raw.objectId, revision: raw.revision,
    digest: bytes(raw.digest, 32), expectedRootHash: bytes(raw.expectedRootHash, 32),
    expectedChunkCount: raw.expectedChunkCount, expectedSha256: bytes(raw.expectedSha256, 32),
    operationId: bytes(raw.operationId, 16), expectedInventorySequence: raw.expectedInventorySequence,
    expectedInventoryRoot: bytes(raw.expectedInventoryRoot, 32), epoch: raw.epoch };
}

class Zk1SharedPgPhysicalCiphertextVerifier {
  constructor({ pool } = {}) {
    if (!pool || typeof pool.connect !== "function") fail();
    this.pool = pool;
  }
  async verifyExact(input) {
    const v = checked(input); // detach all untrusted bytes before first await
    let client;
    let inTransaction = false;
    try {
      client = await this.pool.connect();
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
      inTransaction = true;
      await client.query("SET LOCAL statement_timeout = '8000ms'");
      const role = await client.query(`SELECT session_user AS login,current_user AS role,
        r.rolsuper AS superuser, r.rolcreatedb AS create_db,
        r.rolcreaterole AS create_role, r.rolreplication AS replication,
        r.rolbypassrls AS bypass_rls,
        pg_catalog.has_schema_privilege(current_user,'zk1_gate','CREATE') AS can_create_gate_schema,
        pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','USAGE') AS gate,
        pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','MEMBER') AS gate_member,
        pg_catalog.pg_has_role(current_user,'zk1_chunk_writer_runtime','USAGE') AS writer,
        pg_catalog.pg_has_role(current_user,'zk1_chunk_writer_runtime','MEMBER') AS writer_member,
        pg_catalog.pg_has_role(current_user,'zk1_stop_runtime','USAGE') AS stop,
        pg_catalog.pg_has_role(current_user,'zk1_stop_runtime','MEMBER') AS stop_member,
        pg_catalog.pg_has_role(current_user,'zk1_physical_attestor_runtime','USAGE') AS attestor,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','SELECT') AS can_read_chunks,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.sealed_object','SELECT') AS can_read_seal,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.head','SELECT') AS can_read_head,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','INSERT') AS can_insert_chunks,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.sealed_object','INSERT') AS can_insert_seal,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.head','UPDATE') AS can_update_head,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','DELETE') AS can_delete_chunks,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','TRUNCATE') AS can_truncate_chunks,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.ciphertext_chunk','INSERT') AS can_insert_chunk_column,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.ciphertext_chunk','UPDATE') AS can_update_chunk_column,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.sealed_object','INSERT') AS can_insert_seal_column,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.sealed_object','UPDATE') AS can_update_seal_column,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.head','UPDATE') AS can_update_head_column,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.physical_inventory_intent','INSERT') AS can_insert_intent,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.physical_inventory_intent','UPDATE') AS can_update_intent,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.physical_inventory_admission','SELECT') AS can_read_binding,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.physical_inventory_admission','INSERT') AS can_insert_binding,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.physical_inventory_admission','UPDATE') AS can_update_binding,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.head','DELETE, TRUNCATE, REFERENCES, TRIGGER') AS dangerous_head,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.admission','DELETE, TRUNCATE, REFERENCES, TRIGGER') AS dangerous_admission,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.sealed_object','DELETE, TRUNCATE, REFERENCES, TRIGGER') AS dangerous_seal,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.physical_inventory_intent','DELETE, TRUNCATE, REFERENCES, TRIGGER') AS dangerous_intent,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.physical_inventory_admission','DELETE, TRUNCATE, REFERENCES, TRIGGER') AS dangerous_binding,
        pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','DELETE, TRUNCATE, REFERENCES, TRIGGER') AS dangerous_chunks,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.head','REFERENCES') AS refs_head,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.sealed_object','REFERENCES') AS refs_seal,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.physical_inventory_intent','REFERENCES') AS refs_intent,
        pg_catalog.has_any_column_privilege(current_user,'zk1_gate.physical_inventory_admission','REFERENCES') AS refs_binding,
        EXISTS (SELECT 1 FROM (VALUES
          ('zk1_gate.head'), ('zk1_gate.admission'),
          ('zk1_gate.writer_binding'), ('zk1_gate.physical_stop_receipt'),
          ('zk1_gate.ciphertext_chunk'), ('zk1_gate.sealed_object'),
          ('zk1_gate.physical_inventory_intent'),
          ('zk1_gate.physical_inventory_admission')
        ) AS protected_table(name)
        WHERE pg_catalog.has_any_column_privilege(current_user,protected_table.name,
          'INSERT, UPDATE, REFERENCES')
          OR pg_catalog.has_table_privilege(current_user,protected_table.name,
            'DELETE, TRUNCATE, TRIGGER, MAINTAIN')) AS any_protected_mutation,
        -- NOINHERIT and GRANT ... WITH INHERIT FALSE can hide capabilities
        -- from checks on current_user. A login that can SET ROLE to any other
        -- MEMBER with destructive access is not a read-only attestation
        -- identity, even when it chooses not to switch during this request.
        EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS reachable
          WHERE reachable.rolname<>current_user
            AND pg_catalog.pg_has_role(current_user,reachable.oid,'MEMBER')
            AND (reachable.rolsuper OR reachable.rolcreatedb OR reachable.rolcreaterole
              OR reachable.rolreplication OR reachable.rolbypassrls
              -- PostgreSQL predefined roles can run host OS commands, write
              -- server files, access other tenants, checkpoint or signal
              -- backends without ordinary DML grants on these tables.
              OR pg_catalog.left(reachable.rolname,3)='pg_'
              OR pg_catalog.has_schema_privilege(reachable.oid,'zk1_gate','CREATE')
              OR EXISTS (SELECT 1 FROM (VALUES
                ('zk1_gate.head'), ('zk1_gate.admission'),
                ('zk1_gate.writer_binding'), ('zk1_gate.physical_stop_receipt'),
                ('zk1_gate.ciphertext_chunk'), ('zk1_gate.sealed_object'),
                ('zk1_gate.physical_inventory_intent'),
                ('zk1_gate.physical_inventory_admission')
              ) AS protected_table(name)
              WHERE pg_catalog.has_any_column_privilege(reachable.oid,protected_table.name,
                'INSERT, UPDATE, REFERENCES')
                OR pg_catalog.has_table_privilege(reachable.oid,protected_table.name,
                  'DELETE, TRUNCATE, TRIGGER, MAINTAIN')))) AS any_dormant_mutation
        FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
      const r = role.rows?.[0];
      if (role.rowCount !== 1 || !r || r.login !== r.role || r.superuser !== false
        || r.create_db !== false || r.create_role !== false
        || r.replication !== false || r.bypass_rls !== false
        || r.can_create_gate_schema !== false || r.attestor !== true
        || r.gate !== false || r.gate_member !== false
        || r.writer !== false || r.writer_member !== false
        || r.stop !== false || r.stop_member !== false
        || r.can_read_chunks !== true || r.can_read_seal !== true || r.can_read_head !== true
        || r.can_insert_chunks !== false || r.can_insert_seal !== false
        || r.can_update_head !== false || r.can_delete_chunks !== false
        || r.can_truncate_chunks !== false || r.can_insert_chunk_column !== false
        || r.can_update_chunk_column !== false || r.can_insert_seal_column !== false
        || r.can_update_seal_column !== false || r.can_update_head_column !== false
        || r.can_insert_intent !== false || r.can_update_intent !== false
        || r.can_read_binding !== true || r.can_insert_binding !== false
        || r.can_update_binding !== false
        || r.dangerous_head !== false || r.dangerous_admission !== false
        || r.dangerous_seal !== false || r.dangerous_intent !== false
        || r.dangerous_binding !== false || r.dangerous_chunks !== false
        || r.refs_head !== false || r.refs_seal !== false
        || r.refs_intent !== false || r.refs_binding !== false
        || r.any_protected_mutation !== false
        || r.any_dormant_mutation !== false) fail();
      const settings = await client.query("SHOW fsync");
      const synchronous = await client.query("SHOW synchronous_commit");
      const full = await client.query("SHOW full_page_writes");
      if (settings.rows?.[0]?.fsync !== "on"
        || synchronous.rows?.[0]?.synchronous_commit !== "on"
        || full.rows?.[0]?.full_page_writes !== "on") fail();
      const state = await client.query(`SELECT s.revision,s.digest,s.root_hash,s.expected_chunks,
        s.operation_id AS physically_sealed_operation_id,
        s.generation,s.admission_id,h.generation AS live_generation,
        h.phase,h.keyring_id,h.revision AS live_revision,h.digest AS live_digest,
        h.require_physical_inventory_intent AS intent_required,
        i.operation_id,i.expected_inventory_sequence,i.expected_inventory_root,
        i.keyring_id AS intent_keyring,i.revision AS intent_revision,
        i.epoch AS intent_epoch,i.digest AS intent_digest,
        i.generation AS intent_generation,i.ciphertext_sha256 AS intent_sha256,
        i.expected_root_hash AS intent_root,i.expected_chunks AS intent_count,
        b.operation_id AS admission_operation_id,
        b.admission_id AS bound_admission_id,b.generation AS bound_generation
        FROM zk1_gate.sealed_object s
        JOIN zk1_gate.head h ON h.scope_key=s.scope_key
        JOIN zk1_gate.physical_inventory_intent i
          ON i.scope_key=s.scope_key AND i.object_id=s.object_id
        JOIN zk1_gate.physical_inventory_admission b
          ON b.scope_key=s.scope_key AND b.object_id=s.object_id
        WHERE s.scope_key=$1 AND s.object_id=$2`, [v.scopeKey, v.objectId]);
      if (state.rowCount !== 1) fail();
      const s = state.rows[0];
      if (s.intent_required !== true
        || !same(s.physically_sealed_operation_id, v.operationId)
        || !same(s.admission_operation_id, v.operationId)
        || !same(s.bound_admission_id, s.admission_id)
        || Number(s.bound_generation) !== Number(s.generation)
        || Number(s.revision) !== v.revision || !same(s.digest, v.digest)
        || !same(s.root_hash, v.expectedRootHash)
        || s.expected_chunks !== v.expectedChunkCount
        || !same(s.operation_id, v.operationId)
        || Number(s.expected_inventory_sequence) !== v.expectedInventorySequence
        || !same(s.expected_inventory_root, v.expectedInventoryRoot)
        || !same(s.intent_keyring, v.scope.keyring_id)
        || Number(s.intent_revision) !== v.revision || Number(s.intent_epoch) !== v.epoch
        || !same(s.intent_digest, v.digest)
        || Number(s.intent_generation) !== Number(s.generation)
        || !same(s.intent_sha256, v.expectedSha256)
        || !same(s.intent_root, v.expectedRootHash)
        || s.intent_count !== v.expectedChunkCount
        || !same(s.keyring_id, v.scope.keyring_id)
        || s.phase !== "OPEN" || Number(s.live_generation) !== Number(s.generation)
        || Number(s.live_revision) !== v.revision || !same(s.live_digest, v.digest)
        || !Buffer.isBuffer(s.admission_id) || s.admission_id.length !== 16) fail();
      const chunks = await client.query(`SELECT chunk_index,ciphertext
        FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1 AND object_id=$2
        ORDER BY chunk_index LIMIT $3`, [v.scopeKey, v.objectId, v.expectedChunkCount + 1]);
      if (chunks.rowCount !== v.expectedChunkCount) fail();
      const root = createZk1CiphertextRootBuilder(v.expectedChunkCount);
      const hash = crypto.createHash("sha256");
      for (let index = 0; index < v.expectedChunkCount; index += 1) {
        const row = chunks.rows[index];
        if (row.chunk_index !== index || !Buffer.isBuffer(row.ciphertext)
          || row.ciphertext.length < 1 || row.ciphertext.length > 4 * 1024 * 1024) fail();
        root.append(row.ciphertext);
        hash.update(row.ciphertext);
      }
      if (!same(root.finish(), v.expectedRootHash) || !same(hash.digest(), v.expectedSha256)) fail();
      // A visible committed row is NOT sufficient when the writer may have
      // SET LOCAL synchronous_commit=off. Fence against WAL insert LSN at the
      // moment after all physical rows were independently re-read; only the
      // trusted SECURITY DEFINER function may wait on the real WAL flush.
      const durable = await client.query(
        "SELECT zk1_gate.physical_inventory_wal_flush_barrier() AS flushed");
      if (durable.rowCount !== 1 || durable.rows[0]?.flushed !== true) fail();
      await client.query("COMMIT");
      inTransaction = false;
      return Object.freeze({ status: "PHYSICALLY_REREAD_PG_COMMITTED",
        verified: true, generation: Number(s.generation),
        admissionId: Buffer.from(s.admission_id), operationId: Buffer.from(v.operationId),
        walFlushConfirmed: true, chunkCount: v.expectedChunkCount,
        root: Buffer.from(v.expectedRootHash), ciphertextSha256: Buffer.from(v.expectedSha256),
        authorizesIo: false, provesIndependentOperator: false });
    } catch (_) {
      if (client && inTransaction) { try { await client.query("ROLLBACK"); } catch (_) {} }
      fail();
    } finally {
      if (client) client.release();
    }
  }
}
module.exports = { Zk1SharedPgPhysicalCiphertextVerifier };
