"use strict";

// DEV-OFF defense in depth. A compromised DB owner can bypass this check;
// role isolation, independent custody and an external witness remain required.
// Audit every protected table AND individual column. Table-level privilege
// checks alone miss PostgreSQL GRANT UPDATE(column) / INSERT(column).
// IMPORTANT: an automatically updatable VIEW in another application schema
// runs against the underlying table using its owner's privileges by default.
// A role with only UPDATE(view) can thus modify protected physical rows even
// when no direct base-table DML or SECURITY DEFINER EXECUTE was granted.
// Refuse ALL application-schema DML except the issuer's explicit ticket INSERT.
const PROTECTED_TABLE_COUNT = 7;

async function hasUnexpectedProtectedDml(client, { allowTicketInsert = false } = {}) {
  const result = await client.query(`SELECT
      pg_catalog.count(DISTINCT c.oid) FILTER (
        WHERE n.nspname='zk1_sync_batch' AND c.relkind IN ('r','p')
      )::integer AS table_count,
      COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege(current_user,c.oid,'UPDATE')
        OR pg_catalog.has_table_privilege(current_user,c.oid,'DELETE')
        OR pg_catalog.has_table_privilege(current_user,c.oid,'TRUNCATE')
        OR pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')
        OR (NOT ($1::boolean AND n.nspname='zk1_sync_batch'
          AND c.relname='admission_ticket' AND c.relkind IN ('r','p')) AND (
          pg_catalog.has_table_privilege(current_user,c.oid,'INSERT')
          OR pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'INSERT')
        ))
      ),true) AS unsafe_dml
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
      AND a.attnum > 0 AND NOT a.attisdropped
    WHERE n.nspname NOT IN ('pg_catalog','information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
      AND c.relkind IN ('r','p','v','m','f')`, [allowTicketInsert]);
  const row = result.rows[0];
  return !row || row.table_count !== PROTECTED_TABLE_COUNT || row.unsafe_dml !== false;
}

// PostgreSQL role attributes are not inherited like table ACLs. A login can
// SET ROLE into a powerful custom group granted WITH INHERIT FALSE, even when
// has_table_privilege(current_user, ...) reports no destructive privilege.
// Strict isolated operator credentials are allowed only their one designated
// service group. Additional memberships fail closed, including transitive
// grants and groups with SET TRUE but INHERIT FALSE.
async function hasUnexpectedRoleMembership(client, allowedRole) {
  if (!["zk1_sync_batch_attestor_reader", "zk1_sync_batch_admission_issuer",
    "zk1_sync_batch_verifier"].includes(allowedRole)) return true;
  const result = await client.query(`SELECT (session_user <> current_user OR
      COALESCE(pg_catalog.bool_or(
        pg_catalog.pg_has_role(current_user,r.rolname,'MEMBER')),false)) AS unexpected
    FROM pg_catalog.pg_roles r
    WHERE r.rolname <> current_user AND r.rolname <> $1::name`, [allowedRole]);
  return result.rowCount !== 1 || result.rows[0].unexpected !== false;
}

module.exports = { hasUnexpectedProtectedDml, hasUnexpectedRoleMembership };
