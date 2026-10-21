"use strict";

// Optional, isolated physical PostgreSQL chunk-writer SQL identity.
// The writer is NOT the GateAuthority and must never share its admission,
// gate-transition, sealing or STOP credential. This verifies privileges at
// startup only; a compromised PostgreSQL administrator is outside this proof.
function refuse() {
  const error = new Error("ZK_CHUNK_WRITER_RUNTIME_INVALID");
  error.code = error.message;
  throw error;
}

async function verifyZk1ChunkWriterRuntimePool(pool) {
  if (!pool || typeof pool.connect !== "function") refuse();
  let c;
  try {
    c = await pool.connect();
    const result = await c.query(`SELECT
      session_user AS session_identity, current_user AS active_identity,
      r.rolcanlogin AS can_login, r.rolsuper AS is_superuser,
      r.rolcreatedb AS can_create_db, r.rolcreaterole AS can_create_role,
      pg_catalog.pg_has_role(current_user,'zk1_chunk_writer_runtime','USAGE') AS writer_access,
      pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','USAGE') AS gate_access,
      pg_catalog.pg_has_role(current_user,'zk1_stop_runtime','USAGE') AS stop_access,
      pg_catalog.has_schema_privilege(current_user,'zk1_gate','USAGE') AS schema_access,
      pg_catalog.has_schema_privilege(current_user,'zk1_gate','CREATE') AS schema_create,
      pg_catalog.has_table_privilege(current_user,'zk1_gate.head','SELECT') AS head_read,
      pg_catalog.has_table_privilege(current_user,'zk1_gate.admission','SELECT') AS admission_read,
      pg_catalog.has_table_privilege(current_user,'zk1_gate.sealed_object','SELECT') AS seal_read,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.ciphertext_chunk','scope_key','INSERT') AS write_scope,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.ciphertext_chunk','object_id','INSERT') AS write_object,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.ciphertext_chunk','chunk_index','INSERT') AS write_index,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.ciphertext_chunk','ciphertext','INSERT') AS write_bytes,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.head','phase','UPDATE') AS mutate_gate,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.head','generation','UPDATE') AS mutate_generation,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.admission','id','INSERT') AS mint_admission,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.admission','state','UPDATE') AS mutate_admission,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.sealed_object','root_hash','INSERT') AS forge_seal,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.physical_stop_receipt','admission_id','INSERT') AS forge_stop,
      pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','DELETE') AS delete_chunk,
      pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','TRUNCATE') AS truncate_chunk
      FROM pg_catalog.pg_roles AS r WHERE r.rolname=current_user`);
    const x = result.rows?.[0];
    if (result.rowCount !== 1 || !x || x.session_identity !== x.active_identity
      || x.active_identity === "zk1_chunk_writer_runtime" || x.can_login !== true
      || x.is_superuser !== false || x.can_create_db !== false
      || x.can_create_role !== false || x.writer_access !== true
      || x.gate_access !== false || x.stop_access !== false
      || x.schema_access !== true || x.schema_create !== false
      || x.head_read !== true || x.admission_read !== true || x.seal_read !== true
      || x.write_scope !== true || x.write_object !== true
      || x.write_index !== true || x.write_bytes !== true
      || x.mutate_gate !== false || x.mutate_generation !== false
      || x.mint_admission !== false || x.mutate_admission !== false
      || x.forge_seal !== false || x.forge_stop !== false
      || x.delete_chunk !== false || x.truncate_chunk !== false) refuse();
    return Object.freeze({ verified: true, runtimeRole: x.active_identity });
  } catch (_) { refuse(); }
  finally { if (c) c.release(); }
}

module.exports = { verifyZk1ChunkWriterRuntimePool };
