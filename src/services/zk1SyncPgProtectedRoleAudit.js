"use strict";

// DEV-OFF defense in depth. A compromised DB owner can bypass this check;
// role isolation, independent custody and an external witness remain required.
// Audit every protected table AND individual column. Table-level privilege
// checks alone miss PostgreSQL GRANT UPDATE(column) / INSERT(column).
const PROTECTED_TABLE_COUNT = 7;

async function hasUnexpectedProtectedDml(client, { allowTicketInsert = false } = {}) {
  const result = await client.query(`SELECT
      pg_catalog.count(DISTINCT c.oid)::integer AS table_count,
      pg_catalog.coalesce(pg_catalog.bool_or(
        pg_catalog.has_table_privilege(current_user,c.oid,'UPDATE')
        OR pg_catalog.has_table_privilege(current_user,c.oid,'DELETE')
        OR pg_catalog.has_table_privilege(current_user,c.oid,'TRUNCATE')
        OR pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')
        OR (NOT ($1::boolean AND c.relname='admission_ticket') AND (
          pg_catalog.has_table_privilege(current_user,c.oid,'INSERT')
          OR pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'INSERT')
        ))
      ),true) AS unsafe_dml
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
      AND a.attnum > 0 AND NOT a.attisdropped
    WHERE n.nspname='zk1_sync_batch'
      AND c.relkind IN ('r','p')`, [allowTicketInsert]);
  const row = result.rows[0];
  return !row || row.table_count !== PROTECTED_TABLE_COUNT || row.unsafe_dml !== false;
}

module.exports = { hasUnexpectedProtectedDml };
