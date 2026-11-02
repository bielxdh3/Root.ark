"use strict";

// Exercise the real operator migration against deliberately inconsistent
// pre-versioned PostgreSQL rows. The parent disposable PG18 fixture owns this
// database; no application database or ambient credentials are involved.
const scope = "'" + "a".repeat(40) + "'";
const objectId = "'legacy-object'";
const hex = (pair, n) => `decode(repeat('${pair}',${n}),'hex')`;
const digest = hex("11", 32);
const keyring = hex("22", 16);
const root = hex("33", 32);
const operation = hex("44", 16);
const admission = hex("55", 16);

function runPhysicalMigrationNegativeFixtures(fixture, sql) {
  function prepareLegacy() {
    fixture.sql("DROP SCHEMA zk1_gate CASCADE;");
    fixture.sql(sql);
    // Current DDL is converted to the exact unversioned identity columns of
    // the previous migration. Security trigger functions remain in place;
    // admin fixture inserts below disable them only for the synthetic rows.
    fixture.sql(`ALTER TABLE zk1_gate.ciphertext_chunk
      DROP CONSTRAINT ciphertext_chunk_pkey;
      ALTER TABLE zk1_gate.ciphertext_chunk DROP COLUMN revision;
      ALTER TABLE zk1_gate.ciphertext_chunk
      ADD PRIMARY KEY(scope_key,object_id,chunk_index);
      ALTER TABLE zk1_gate.physical_inventory_admission
      DROP CONSTRAINT physical_inventory_admission_pkey;
      ALTER TABLE zk1_gate.physical_inventory_admission DROP COLUMN revision;
      ALTER TABLE zk1_gate.physical_inventory_admission
      ADD PRIMARY KEY(scope_key,object_id);`);
  }

  function seed(strict, detail) {
    fixture.sql(`BEGIN;
      SET LOCAL session_replication_role = replica;
      INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest,
        require_physical_inventory_intent)
      VALUES(${scope},${keyring},1,${digest},${strict});
      ${detail}
      COMMIT;`);
  }

  const put = (id, worker, revision) => `INSERT INTO zk1_gate.admission
    (id,scope_key,worker_id,principal,action,object_id,revision,digest,generation,state)
    VALUES(${hex(id,16)},${scope},${hex(worker,16)},'lab','put',${objectId},
      ${revision},${digest},1,'ACTIVE');`;
  const intent = (revision) => `INSERT INTO zk1_gate.physical_inventory_intent
    (scope_key,object_id,operation_id,expected_inventory_sequence,
      expected_inventory_root,keyring_id,revision,epoch,digest,generation,
      ciphertext_sha256,expected_root_hash,expected_chunks)
    VALUES(${scope},${objectId},${operation},0,${root},${keyring},
      ${revision},1,${digest},1,${root},${root},1);`;
  const bound = `INSERT INTO zk1_gate.physical_inventory_admission
    (scope_key,object_id,operation_id,admission_id,generation)
    VALUES(${scope},${objectId},${operation},${admission},1);`;
  const chunk = `INSERT INTO zk1_gate.ciphertext_chunk
    (scope_key,object_id,chunk_index,ciphertext)
    VALUES(${scope},${objectId},0,${hex("66",16)});`;
  const seal = (operationId) => `INSERT INTO zk1_gate.sealed_object
    (scope_key,object_id,revision,digest,generation,admission_id,
      expected_chunks,root_hash,operation_id)
    VALUES(${scope},${objectId},1,${digest},1,${admission},1,${root},${operationId});`;

  const cases = [
    { name: "conflicting old admissions for one chunk", strict: false,
      rows: put("55", "77", 1) + put("88", "99", 2) + chunk },
    { name: "admitted strict revision contradicts bound intent", strict: true,
      rows: intent(2) + put("55", "77", 1) + bound },
    { name: "sealed operation contradicts immutable intent", strict: true,
      rows: intent(1) + put("55", "77", 1) + bound +
        seal(hex("aa",16)) + chunk },
  ];
  for (const item of cases) {
    prepareLegacy();
    seed(item.strict, item.rows);
    let rejected = false;
    try { fixture.sql(sql); }
    catch (_) { rejected = true; }
    if (!rejected) throw Error("ZK65_MIGRATION_ACCEPTED_CONFLICT: " + item.name);
    // The failed BEGIN/COMMIT migration must leave the original unversioned
    // schema untouched, including its invalid-but-preserved synthetic bytes.
    const state = fixture.sql(`SELECT COUNT(*)::int AS legacy_column_count
      FROM information_schema.columns WHERE table_schema='zk1_gate'
        AND table_name='ciphertext_chunk' AND column_name='revision';`);
    if (!/\b0\b/.test(state)) {
      throw Error("ZK65_MIGRATION_DID_NOT_ROLL_BACK: " + item.name);
    }
  }
  return cases.length;
}

module.exports = { runPhysicalMigrationNegativeFixtures };
