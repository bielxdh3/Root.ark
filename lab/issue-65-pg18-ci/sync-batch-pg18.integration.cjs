"use strict";

// Real PostgreSQL 18 ONLY. Invoked by the disposable lab runner, not npm test.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../../sync-client/rootark-sync-authorization");
const { createZk1SyncPgAtomicBatchStore } =
  require("../../src/services/zk1SyncPgAtomicBatchStore");
const { createZk1SyncPgIndependentAdmissionIssuer } =
  require("../../src/services/zk1SyncPgIndependentAdmissionIssuer");
const { createZk1SyncPgBatchIndependentReadback } =
  require("../../src/services/zk1SyncPgBatchIndependentReadback");
const { hasUnexpectedProtectedDml } =
  require("../../src/services/zk1SyncPgProtectedRoleAudit");

if (!process.env.ROOTARK_ZK1_TEST_PG_URL || !process.env.ROOTARK_ZK1_RUNTIME_PG_URL
  || !process.env.ROOTARK_ZK1_VERIFIER_PG_URL
  || !process.env.ROOTARK_ZK1_ATTESTOR_PG_URL
  || !process.env.ROOTARK_ZK1_ADMISSION_ISSUER_PG_URL) {
  throw Error("ZK65_SYNC_BATCH_DISPOSABLE_PG18_REQUIRED");
}
const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL, max: 4 });
const runtime = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL, max: 4 });
const verifier = new Pool({ connectionString: process.env.ROOTARK_ZK1_VERIFIER_PG_URL, max: 4 });
const attestor = new Pool({ connectionString: process.env.ROOTARK_ZK1_ATTESTOR_PG_URL, max: 2 });
const issuer = new Pool({ connectionString: process.env.ROOTARK_ZK1_ADMISSION_ISSUER_PG_URL, max: 2 });
const store = createZk1SyncPgAtomicBatchStore({ verifierPool: verifier });
const admissionIssuer = createZk1SyncPgIndependentAdmissionIssuer({
  readerPool: attestor, issuerPool: issuer,
});
const readback = createZk1SyncPgBatchIndependentReadback({ attestorPool: attestor });
test.after(async () => {
  await Promise.all([runtime.end(), verifier.end(), attestor.end(), issuer.end(), admin.end()]);
});
const hash = (input) => crypto.createHash("sha256").update(input).digest();

// TEST FIXTURE ONLY: exercise the real separate issuer implementation with
// disposable credentials. All four pools coexist ONLY inside this one PG18
// lab runner; never deploy this combined process or give HTTP issuer secrets.
async function mintTestAdmission(f, operations) {
  const result = await admissionIssuer.issueTicket({
    scope: f.scope, username: f.username, operations,
  });
  assert.equal(result.clientAckAuthorized, false);
  assert.equal(result.witnessVerified, false);
  return result.admissionTicket;
}

async function commitTestBatch(f, operations, batchStore = store) {
  return batchStore.commitSignedOverwritePair({
    ...f, operations, admissionTicket: await mintTestAdmission(f, operations),
  });
}

async function fixture() {
  const scope = "w222-" + crypto.randomUUID();
  const signKey = crypto.generateKeyPairSync("ed25519");
  const publicKey = signKey.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const fileKey = crypto.randomBytes(32);
  const deviceId = "device-a";
  const username = "fixture";
  await admin.query(`INSERT INTO zk1_sync_batch.scope_policy
    (scope,username,compartment_id,key_epoch,enabled,allow_delete)
    VALUES ($1,$2,'private','epoch-1',true,true)`, [scope, username]);
  await admin.query("INSERT INTO zk1_sync_batch.scope_head(scope) VALUES ($1)", [scope]);
  await admin.query(`INSERT INTO zk1_sync_batch.device_grant
    (scope,device_id,public_key,revoked) VALUES ($1,$2,$3,false)`,
  [scope, deviceId, publicKey]);
  const create = (kind, objectId, path, rev = 1, sourcePath,
    baseCounter = rev - 1, signedOperationId = crypto.randomUUID()) =>
    protocol.createOperation({
      operation: kind, objectId, fileId: "file-" + objectId,
      versionId: crypto.randomUUID(), operationId: signedOperationId,
      deviceId, keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: rev, deviceId },
      baseRevision: rev > 1 ? { counter: baseCounter, deviceId } : null,
      metadata: { path, ...(sourcePath ? { sourcePath } : {}) },
      plaintext: Buffer.from("disposable " + objectId), fileKey,
    });
  for (const [objectId, path] of [["dest", "dest.ct"], ["src", "src.ct"]]) {
    const initial = create("create", objectId, path);
    const canonical = protocol.canonicalJson(initial);
    await admin.query(`INSERT INTO zk1_sync_batch.object_state
      (scope,object_id,file_id,version_id,device_id,revision_counter,
       revision_device,compartment_id,key_epoch,logical_path,tombstone,
       canonical_envelope,envelope_digest,ciphertext)
      VALUES ($1,$2,$3,$4,$5,1,$5,'private','epoch-1',$6,false,$7,$8,$9)`,
    [scope, objectId, initial.fileId, initial.versionId, deviceId, path,
      canonical, hash(canonical), Buffer.from(initial.ciphertext,"base64url")]);
  }
  async function signedPair({ moveBaseCounter = 1,
    eventId = crypto.randomUUID(), deleteEventId = eventId, moveEventId = eventId } = {}) {
    const webdavId = (verb, event) => "webdav-" + event + "-" +
      hash(verb + ":dest.ct").toString("hex").slice(0, 24);
    const ops = [
      create("delete", "dest", "dest.ct", 2, undefined, 1,
        webdavId("delete", deleteEventId)),
      create("move", "src", "dest.ct", 2, "src.ct", moveBaseCounter,
        webdavId("move", moveEventId)),
    ];
    for (const op of ops) {
      op.authorization = await createAuthorizationProof(op, {
        username, publicKey, privateKey: signKey.privateKey,
        expiresAt: Date.now() + 120000,
      });
    }
    return ops;
  }
  const state = async () => {
    const [head, markers, seen, rows] = await Promise.all([
      admin.query("SELECT sequence,head FROM zk1_sync_batch.scope_head WHERE scope=$1", [scope]),
      admin.query("SELECT * FROM zk1_sync_batch.batch_commit WHERE scope=$1", [scope]),
      admin.query("SELECT * FROM zk1_sync_batch.seen_envelope WHERE scope=$1 ORDER BY ordinal", [scope]),
      admin.query("SELECT * FROM zk1_sync_batch.object_state WHERE scope=$1 ORDER BY object_id", [scope]),
    ]);
    return { head: head.rows[0], markers: markers.rows, seen: seen.rows, rows: rows.rows };
  };
  return { scope, username, signedPair, state, publicKey };
}

test("PG18 scope accepts 256 ASCII characters and rejects 257 without invalid SQL regex", async () => {
  const maxScope = "s".repeat(256);
  await admin.query(`INSERT INTO zk1_sync_batch.scope_policy
    (scope,username,compartment_id,key_epoch,enabled,allow_delete)
    VALUES ($1,'fixture','private','epoch-1',true,true)`, [maxScope]);
  await assert.rejects(admin.query(`INSERT INTO zk1_sync_batch.scope_policy
    (scope,username,compartment_id,key_epoch,enabled,allow_delete)
    VALUES ($1,'fixture','private','epoch-1',true,true)`, ["s".repeat(257)]),
  { code: "23514" });
  const actual = await admin.query(`SELECT scope FROM zk1_sync_batch.scope_policy WHERE scope=$1`,
    [maxScope]);
  assert.equal(actual.rowCount, 1);
});

test("PG18 independent roles satisfy complete live table-and-column DML auditor", async () => {
  for (const [role, pool, opts] of [
    ["READER", attestor, {}],
    ["VERIFIER", verifier, {}],
    ["ISSUER", issuer, { allowTicketInsert: true }],
  ]) {
    const client = await pool.connect();
    try {
      let unsafe;
      try { unsafe = await hasUnexpectedProtectedDml(client, opts); }
      catch (error) {
        throw Object.assign(new Error("live protected role audit query rejected"),
          { code: "PG_MATRIX_" + role + "_" + String(error?.code || "UNKNOWN") });
      }
      if (unsafe) {
        throw Object.assign(new Error("live protected role audit detected DML"),
          { code: "PG_MATRIX_" + role + "_FORBIDDEN" });
      }
    } finally { client.release(); }
  }
});

test("PG18 atomic batch persists 2 original signed envelopes, ciphertext, state and one chained marker", async () => {
  const f = await fixture();
  const operations = await f.signedPair();
  const result = await commitTestBatch(f, operations);
  assert.equal(result.sequence, 1);
  assert.equal(result.clientAckAuthorized, false);
  assert.equal(result.witnessVerified, false);
  const s = await f.state();
  assert.equal(Number(s.head.sequence), 1);
  assert.equal(s.markers.length, 1);
  assert.equal(s.seen.length, 2);
  assert.deepEqual(s.head.head, s.markers[0].head);
  assert.equal(s.markers[0].commit_id, result.commitId);
  assert.equal(s.markers[0].head.toString("hex"), result.storeHeadSha256);
  for (let i = 0; i < 2; i++) {
    const exact = protocol.canonicalJson(operations[i]);
    assert.equal(s.seen[i].canonical_envelope, exact);
    assert.deepEqual(s.seen[i].envelope_digest, hash(exact));
    assert.deepEqual(s.seen[i].ciphertext, Buffer.from(operations[i].ciphertext, "base64url"));
    assert.equal(s.seen[i].commit_id, result.commitId);
  }
  assert.equal(s.rows.find((r) => r.object_id === "dest").tombstone, true);
  assert.equal(s.rows.find((r) => r.object_id === "src").logical_path, "dest.ct");
  assert.equal(s.rows.every((r) => r.last_commit_id === result.commitId), true);
  await assert.rejects(admin.query(`UPDATE zk1_sync_batch.batch_commit
    SET policy_epoch=999 WHERE scope=$1`, [f.scope]));
  await assert.rejects(admin.query(`UPDATE zk1_sync_batch.seen_envelope
    SET ciphertext=decode('00','hex') WHERE scope=$1`, [f.scope]));
});

test("PG18 expired pending ticket can be reissued for the SAME signed pair without replay or stale ACK", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const expiredTicket = await mintTestAdmission(f, pair);
  // Disposable DB operator advances only this ticket's expiry. The original
  // Ed25519 envelopes remain fresh; no client-side clock mocking or waiting.
  const expired = await admin.query(`UPDATE zk1_sync_batch.admission_ticket
    SET issued_at=clock_timestamp() - interval '90 seconds',
        expires_at=clock_timestamp() - interval '60 seconds'
    WHERE ticket_id=$1 AND consumed=false
    RETURNING expires_at < clock_timestamp() AS expired`, [expiredTicket]);
  assert.equal(expired.rowCount, 1);
  assert.equal(expired.rows[0].expired, true);
  const replacement = await mintTestAdmission(f, pair);
  assert.notEqual(replacement, expiredTicket);
  const pre = await f.state();
  await assert.rejects(store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: expiredTicket,
  }), { code: "SYNC_PG_BATCH_UNAVAILABLE" });
  assert.deepEqual(await f.state(), pre, "expired handle cannot change any committed state");
  const committed = await store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: replacement,
  });
  assert.equal(committed.sequence, 1);
  assert.equal(committed.witnessVerified, false);
  assert.equal(committed.clientAckAuthorized, false);
  const consumed = await admin.query(`SELECT ticket_id,consumed,superseded
    FROM zk1_sync_batch.admission_ticket WHERE ticket_id IN ($1,$2)`,
  [expiredTicket, replacement]);
  assert.equal(consumed.rowCount, 2);
  assert.equal(consumed.rows.find((r) => r.ticket_id === expiredTicket).consumed, false);
  assert.equal(consumed.rows.find((r) => r.ticket_id === expiredTicket).superseded, true);
  assert.equal(consumed.rows.find((r) => r.ticket_id === replacement).consumed, true);
  assert.equal(consumed.rows.find((r) => r.ticket_id === replacement).superseded, false);
  await assert.rejects(store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: replacement,
  }), { code: "SYNC_PG_BATCH_UNAVAILABLE" });
  const after = await f.state();
  assert.equal(after.markers.length, 1);
  assert.equal(after.seen.length, 2);
  assert.equal(Number(after.head.sequence), 1);
});

test("PG18 INSERT-only issuer cannot bypass ticket uniqueness or create future-lived handles", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const ticket = await mintTestAdmission(f, pair);
  const original = (await admin.query(`SELECT * FROM zk1_sync_batch.admission_ticket
    WHERE ticket_id=$1`, [ticket])).rows[0];
  const submit = ({ consumed = false, superseded = false,
    issuedAt = original.issued_at, expiresAt = original.expires_at } = {}) =>
    issuer.query(`INSERT INTO zk1_sync_batch.admission_ticket
      (ticket_id,scope,username,device_id,public_key,policy_epoch,
       sequence,previous_head,delete_digest,move_digest,expires_at,
       consumed,superseded,issued_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, [
      crypto.randomUUID(), original.scope, original.username,
      original.device_id, original.public_key, original.policy_epoch,
      original.sequence, original.previous_head, original.delete_digest,
      original.move_digest, expiresAt, consumed, superseded, issuedAt,
    ]);
  await assert.rejects(submit({ superseded: true }), { code: "23514" });
  await assert.rejects(submit({ consumed: true }), { code: "23514" });
  const farFuture = new Date(Date.now() + 86400000);
  await assert.rejects(submit({ issuedAt: farFuture,
    expiresAt: new Date(farFuture.valueOf() + 30000) }), { code: "23514" });
  await assert.rejects(submit({ expiresAt: new Date(Date.now() + 60000) }),
    { code: "23514" });
  await assert.rejects(submit(), { code: "23505" },
    "active signed pair must remain unique even if issuer has INSERT");
  const count = await admin.query(`SELECT count(*)::integer AS tickets FROM
    zk1_sync_batch.admission_ticket WHERE scope=$1`, [f.scope]);
  assert.equal(count.rows[0].tickets, 1);
  const committed = await store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: ticket,
  });
  assert.equal(committed.clientAckAuthorized, false);
  assert.equal((await f.state()).markers.length, 1);
});

test("PG18 concurrent duplicate ticket requests cannot flood live same-pair handles", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const operator = await admin.connect();
  let held = false;
  let pending;
  let issuances;
  try {
    await operator.query("BEGIN");
    held = true;
    await operator.query(`SELECT sequence FROM zk1_sync_batch.scope_head
      WHERE scope=$1 FOR UPDATE`, [f.scope]);
    pending = Promise.allSettled([
      mintTestAdmission(f, pair), mintTestAdmission(f, pair),
    ]);
    let observedLockWait = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      const waiting = await admin.query(`SELECT 1 FROM pg_catalog.pg_stat_activity
        WHERE usename LIKE 'zkbatchissuer%'
          AND wait_event_type='Lock'
          AND query LIKE '%INSERT INTO zk1_sync_batch.admission_ticket%'
        LIMIT 1`);
      if (waiting.rowCount === 1) { observedLockWait = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
    assert.equal(observedLockWait, true,
      "duplicate issuance must genuinely wait behind scope_head row lock");
    await operator.query("COMMIT");
    held = false;
    issuances = await pending;
  } finally {
    if (held) {
      try { await operator.query("ROLLBACK"); } catch { /* test cleanup */ }
    }
    operator.release();
    if (pending) await pending;
  }
  assert.equal(issuances.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(issuances.filter((r) => r.status === "rejected").length, 1);
  assert.equal(issuances.find((r) => r.status === "rejected").reason.code,
    "SYNC_PG_ISSUER_DENIED");
  const ticket = issuances.find((r) => r.status === "fulfilled").value;
  const issued = await admin.query(`SELECT COUNT(*)::integer AS live
    FROM zk1_sync_batch.admission_ticket WHERE scope=$1 AND superseded=false`, [f.scope]);
  assert.equal(issued.rows[0].live, 1);
  const committed = await store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: ticket,
  });
  assert.equal(committed.clientAckAuthorized, false);
  await assert.rejects(store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: ticket,
  }), { code: "SYNC_PG_BATCH_UNAVAILABLE" });
  const state = await f.state();
  assert.equal(Number(state.head.sequence), 1);
  assert.equal(state.markers.length, 1);
  assert.equal(state.seen.length, 2);
});

test("PG18 full protected-role audit denies unlisted destructive table and column misgrants", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const ticket = await mintTestAdmission(f, pair);
  const before = await f.state();
  await admin.query(`GRANT DELETE ON zk1_sync_batch.seen_envelope
    TO zk1_sync_batch_verifier`);
  try {
    const effective = await verifier.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.seen_envelope','DELETE') AS granted`);
    assert.equal(effective.rows[0].granted, true);
    await assert.rejects(store.commitSignedOverwritePair({
      ...f, operations: pair, admissionTicket: ticket,
    }), { code: "SYNC_PG_BATCH_UNTRUSTED_DATABASE_ROLE" });
    assert.deepEqual(await f.state(), before);
  } finally {
    await admin.query(`REVOKE DELETE ON zk1_sync_batch.seen_envelope
      FROM zk1_sync_batch_verifier`);
  }
  await admin.query(`GRANT UPDATE(public_key) ON zk1_sync_batch.device_grant
    TO zk1_sync_batch_admission_issuer`);
  try {
    const effective = await issuer.query(`SELECT
      pg_catalog.has_column_privilege(current_user,'zk1_sync_batch.device_grant','public_key','UPDATE') AS granted`);
    assert.equal(effective.rows[0].granted, true);
    await assert.rejects(admissionIssuer.issueTicket({
      ...f, operations: pair,
    }), { code: "SYNC_PG_ISSUER_DENIED" });
  } finally {
    await admin.query(`REVOKE UPDATE(public_key) ON zk1_sync_batch.device_grant
      FROM zk1_sync_batch_admission_issuer`);
  }
  const committed = await store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: ticket,
  });
  await admin.query(`GRANT DELETE ON zk1_sync_batch.scope_policy
    TO zk1_sync_batch_attestor_reader`);
  try {
    const effective = await attestor.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_policy','DELETE') AS granted`);
    assert.equal(effective.rows[0].granted, true);
    await assert.rejects(readback.verifyLatestSignedPair({
      scope: f.scope, commitId: committed.commitId,
    }), { code: "ZK1_SYNC_PG_READBACK_UNVERIFIED" });
  } finally {
    await admin.query(`REVOKE DELETE ON zk1_sync_batch.scope_policy
      FROM zk1_sync_batch_attestor_reader`);
  }
  const after = await f.state();
  assert.equal(after.markers.length, 1);
  assert.equal(after.seen.length, 2);
});

test("PG18 invalid second revision rolls back both writes and leaves no marker", async () => {
  const f = await fixture();
  // Sign an internally valid envelope whose signed base revision is stale.
  // The first object passes; the second fails inside the PG row-lock boundary.
  const pair = await f.signedPair({ moveBaseCounter: 0 });
  await assert.rejects(commitTestBatch(f, pair));
  const s = await f.state();
  assert.equal(Number(s.head.sequence), 0);
  assert.equal(s.markers.length, 0);
  assert.equal(s.seen.length, 0);
  assert.equal(s.rows.every((r) => r.revision_counter === "1"), true);
});

test("two valid Ed25519 WebDAV envelopes with same path but DIFFERENT journal events fail closed", async () => {
  const f = await fixture();
  const operations = await f.signedPair({ moveEventId: crypto.randomUUID() });
  assert.equal(operations[0].metadata.path, operations[1].metadata.path);
  for (const op of operations) {
    await require("../../sync-client/rootark-sync-authorization")
      .verifyAuthorizationProof(op.authorization, op, {
        username: f.username,
        trustedDevicePublicKeys: { [op.deviceId]: f.publicKey },
        revokedDeviceIds: [],
      });
  }
  await assert.rejects(admissionIssuer.issueTicket({
    scope: f.scope, username: f.username, operations,
  }), { code: "SYNC_PG_ISSUER_DENIED" });
  await assert.rejects(store.commitSignedOverwritePair({
    ...f, operations, admissionTicket: crypto.randomUUID(),
  }), { code: "SYNC_PG_BATCH_INVALID" });

  // Operator-only adversarial fixture: INSERT a ticket matching BOTH exact
  // signed envelopes despite their different authentic WebDAV event IDs,
  // proving the OWNER SQL guard independently rejects even with a ticket.
  const [pinned, head] = await Promise.all([
    admin.query(`SELECT p.policy_epoch,g.public_key
      FROM zk1_sync_batch.scope_policy p JOIN zk1_sync_batch.device_grant g
      ON g.scope=p.scope WHERE p.scope=$1 AND g.device_id=$2`,
    [f.scope, operations[0].deviceId]),
    admin.query("SELECT sequence,head FROM zk1_sync_batch.scope_head WHERE scope=$1",
      [f.scope]),
  ]);
  const id = crypto.randomUUID();
  await admin.query(`INSERT INTO zk1_sync_batch.admission_ticket
    (ticket_id,scope,username,device_id,public_key,policy_epoch,
      sequence,previous_head,delete_digest,move_digest,expires_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()+interval '30 seconds')`,
  [id, f.scope, f.username, operations[0].deviceId,
    pinned.rows[0].public_key, pinned.rows[0].policy_epoch,
    Number(head.rows[0].sequence) + 1, head.rows[0].head,
    hash(protocol.canonicalJson(operations[0])),
    hash(protocol.canonicalJson(operations[1]))]);
  await assert.rejects(verifier.query(`SELECT
    zk1_sync_batch.commit_admitted_pair($1,$2,$3,$4,$5)`, [
    f.scope, f.username, id, protocol.canonicalJson(operations[0]),
    protocol.canonicalJson(operations[1]),
  ]), { code: "23514" }, "owner SQL must independently reject cross-event splice");
  const remaining = await f.state();
  assert.equal(Number(remaining.head.sequence), 0);
  assert.equal(remaining.markers.length, 0);
  assert.equal(remaining.seen.length, 0);
});

test("PG18 stale signature mutation and revoked device fail closed before any write", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const corrupt = structuredClone(pair);
  corrupt[1].ciphertext = (corrupt[1].ciphertext.startsWith("A") ? "B" : "A")
    + corrupt[1].ciphertext.slice(1);
  await assert.rejects(commitTestBatch(f, corrupt));
  const ticket = await mintTestAdmission(f, pair);
  await admin.query(`UPDATE zk1_sync_batch.device_grant SET revoked=true
    WHERE scope=$1 AND device_id='device-a'`, [f.scope]);
  await assert.rejects(store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: ticket,
  }),
    { code: "SYNC_PG_BATCH_UNAUTHORIZED" });
  const s = await f.state();
  assert.equal(Number(s.head.sequence), 0);
  assert.equal(s.seen.length, 0);
});

test("PG18 concurrent competing batches serialize and cannot commit two updates", async () => {
  const f = await fixture();
  const first = await f.signedPair();
  const second = await f.signedPair();
  const tickets = await Promise.all([first, second].map((operations) =>
    mintTestAdmission(f, operations)));
  const results = await Promise.allSettled([first, second].map((operations, i) =>
    store.commitSignedOverwritePair({ ...f, operations, admissionTicket: tickets[i] })));
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(results.filter((r) => r.status === "rejected").length, 1);
  const s = await f.state();
  assert.equal(Number(s.head.sequence), 1);
  assert.equal(s.markers.length, 1);
  assert.equal(s.seen.length, 2);
  await assert.rejects(store.commitSignedOverwritePair({ ...f,
    operations: results[0].status === "fulfilled" ? first : second,
    admissionTicket: results[0].status === "fulfilled" ? tickets[0] : tickets[1],
  }), /./);
  assert.equal((await f.state()).markers.length, 1);
});

test("PG18 concurrently committed revocation fences an issuer-admitted batch at the SQL scope lock", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const admissionTicket = await mintTestAdmission(f, pair);
  const before = await f.state();
  const operator = await admin.connect();
  let held = false;
  let pending;
  try {
    await operator.query("BEGIN");
    held = true;
    await operator.query(`SELECT sequence FROM zk1_sync_batch.scope_head
      WHERE scope=$1 FOR UPDATE`, [f.scope]);
    // This is an actual lock conflict: do not accept a timing-only, never-
    // overlapping test as evidence of concurrent revocation correctness.
    pending = store.commitSignedOverwritePair({
      ...f, operations: pair, admissionTicket,
    }).then((value) => ({ accepted: true, value }),
      (error) => ({ accepted: false, error }));
    let observedLockWait = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      const waiting = await admin.query(`SELECT 1 FROM pg_catalog.pg_stat_activity
        WHERE usename LIKE 'zkbatchverify\\_%' ESCAPE '\\'
          AND wait_event_type='Lock'
          AND query LIKE '%zk1_sync_batch.commit_admitted_pair%'
        LIMIT 1`);
      if (waiting.rowCount === 1) {
        observedLockWait = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
    assert.equal(observedLockWait, true,
      "the verifier must actually wait for the same scope_head lock");
    await operator.query(`UPDATE zk1_sync_batch.device_grant SET revoked=true
      WHERE scope=$1 AND device_id='device-a'`, [f.scope]);
    await operator.query("COMMIT");
    held = false;
    const outcome = await pending;
    assert.equal(outcome.accepted, false,
      "a revoked grant must never admit an already verified signed pair");
    assert.equal(outcome.error?.code, "SYNC_PG_BATCH_UNAVAILABLE");
    const after = await f.state();
    assert.deepEqual(after, before,
      "revocation must not partially write objects, envelopes, marker or head");
    const revoked = await admin.query(`SELECT g.revoked,p.policy_epoch FROM
      zk1_sync_batch.device_grant g JOIN zk1_sync_batch.scope_policy p
        ON p.scope=g.scope WHERE g.scope=$1 AND g.device_id='device-a'`, [f.scope]);
    assert.equal(revoked.rows[0].revoked, true);
    assert.ok(Number(revoked.rows[0].policy_epoch) > 1);
  } finally {
    if (held) {
      try { await operator.query("ROLLBACK"); } catch { /* failed test cleanup */ }
    }
    operator.release();
    if (pending) await pending;
  }
});

test("PG18 injected second object SQL trigger failure rolls back both physical writes", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const admissionTicket = await mintTestAdmission(f, pair);
  // Inject a real error INSIDE PostgreSQL after the second object UPDATE.
  // The temporary custom GUC is scoped to this one verifier transaction.
  await admin.query(`CREATE FUNCTION zk1_sync_batch.test_only_abort_second_write()
    RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
    BEGIN
      IF NEW.object_id='src' AND
        NEW.scope=current_setting('zk1_sync_batch_test.abort_scope',true) THEN
        RAISE EXCEPTION 'TEST_SECOND_PHYSICAL_WRITE_ABORT' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END $$`);
  await admin.query(`CREATE TRIGGER test_only_abort_second_write
    AFTER UPDATE ON zk1_sync_batch.object_state FOR EACH ROW
    EXECUTE FUNCTION zk1_sync_batch.test_only_abort_second_write()`);
  const sabotaged = createZk1SyncPgAtomicBatchStore({
    verifierPool: { async connect() {
      const actual = await verifier.connect();
      return {
        async query(text, args) {
          if (typeof text === "string" && text.includes("SELECT\n          zk1_sync_batch.commit_admitted_pair")) {
            await actual.query("SELECT set_config('zk1_sync_batch_test.abort_scope',$1,true)",
              [f.scope]);
          }
          return actual.query(text, args);
        },
        release: () => actual.release(),
      };
    } },
  });
  try {
    await assert.rejects(sabotaged.commitSignedOverwritePair({
      ...f, operations: pair, admissionTicket,
    }));
  } finally {
    await admin.query("DROP TRIGGER IF EXISTS test_only_abort_second_write ON zk1_sync_batch.object_state");
    await admin.query("DROP FUNCTION IF EXISTS zk1_sync_batch.test_only_abort_second_write()");
  }
  const s = await f.state();
  assert.equal(Number(s.head.sequence), 0);
  assert.equal(s.markers.length, 0);
  assert.equal(s.seen.length, 0);
  assert.equal(s.rows.every((r) => r.revision_counter === "1"), true);
});

test("PG18 changing a device grant or scope policy always advances the policy epoch", async () => {
  const f = await fixture();
  const epoch = async () => Number((await admin.query(
    "SELECT policy_epoch FROM zk1_sync_batch.scope_policy WHERE scope=$1",
    [f.scope])).rows[0].policy_epoch);
  const before = await epoch();
  assert.ok(before >= 2, "initial device grant must advance epoch");
  await admin.query(`UPDATE zk1_sync_batch.device_grant SET revoked=true
    WHERE scope=$1 AND device_id='device-a'`, [f.scope]);
  assert.equal(await epoch(), before + 1);
  await admin.query(`UPDATE zk1_sync_batch.device_grant SET revoked=false
    WHERE scope=$1 AND device_id='device-a'`, [f.scope]);
  assert.equal(await epoch(), before + 2);
  await admin.query(`UPDATE zk1_sync_batch.scope_policy
    SET allow_delete=false,policy_epoch=1 WHERE scope=$1`, [f.scope]);
  assert.equal(await epoch(), before + 3, "operator cannot override next epoch");
  await admin.query(`UPDATE zk1_sync_batch.scope_policy
    SET allow_delete=true WHERE scope=$1`, [f.scope]);
  assert.equal(await epoch(), before + 4);
});

test("PG18 device_grant scope OLD->NEW UPDATE is denied BEFORE old authority can be bypassed", async () => {
  const old = await fixture();
  const newScope = "w222-new-" + crypto.randomUUID();
  // A real, initialized NEW scope with NO matching grant avoids incidental
  // primary-key/unique errors: the rejection must be the owner SQL invariant,
  // not a constraint on the attempted relocation destination.
  await admin.query(`INSERT INTO zk1_sync_batch.scope_policy
    (scope,username,compartment_id,key_epoch,enabled,allow_delete)
    VALUES ($1,$2,'private','epoch-1',true,true)`, [newScope, old.username]);
  await admin.query("INSERT INTO zk1_sync_batch.scope_head(scope) VALUES ($1)", [newScope]);
  const signed = await old.signedPair();
  const existingAdmission = await mintTestAdmission(old, signed);
  const snapshot = async () => {
    const [heads, policies, grants, markers] = await Promise.all([
      admin.query(`SELECT scope,sequence,head FROM zk1_sync_batch.scope_head
        WHERE scope IN ($1,$2) ORDER BY scope`, [old.scope, newScope]),
      admin.query(`SELECT scope,policy_epoch,enabled,allow_delete
        FROM zk1_sync_batch.scope_policy WHERE scope IN ($1,$2) ORDER BY scope`,
      [old.scope, newScope]),
      admin.query(`SELECT scope,device_id,public_key,revoked
        FROM zk1_sync_batch.device_grant WHERE scope IN ($1,$2)
        ORDER BY scope,device_id`, [old.scope, newScope]),
      admin.query(`SELECT scope,sequence,commit_id FROM zk1_sync_batch.batch_commit
        WHERE scope IN ($1,$2) ORDER BY scope,sequence`, [old.scope, newScope]),
    ]);
    return { heads: heads.rows, policies: policies.rows,
      grants: grants.rows, markers: markers.rows };
  };
  const trigger = await admin.query(`SELECT t.tgenabled,
    p.prosecdef AS security_definer, pg_catalog.pg_get_userbyid(p.proowner) AS owner,
    (t.tgtype & 1)<>0 AS row_level, (t.tgtype & 2)<>0 AS before_row,
    (t.tgtype & 16)<>0 AS on_update
    FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
    WHERE t.tgrelid='zk1_sync_batch.device_grant'::regclass
      AND t.tgname='deny_device_grant_scope_reassignment' AND NOT t.tgisinternal`);
  assert.equal(trigger.rowCount, 1, "dedicated owner trigger must exist");
  assert.equal(trigger.rows[0].tgenabled, "O", "scope immutability cannot be disabled");
  assert.equal(trigger.rows[0].security_definer, true);
  assert.equal(trigger.rows[0].row_level, true);
  assert.equal(trigger.rows[0].before_row, true);
  assert.equal(trigger.rows[0].on_update, true);
  assert.equal(trigger.rows[0].owner, (await admin.query("SELECT current_user AS owner")).rows[0].owner);
  const before = await snapshot();
  assert.equal(before.grants.length, 1, "only OLD scope has the signing key");
  assert.equal(before.grants[0].scope, old.scope);

  for (const update of [
    `UPDATE zk1_sync_batch.device_grant SET scope=$2
      WHERE scope=$1 AND device_id='device-a' RETURNING scope,device_id`,
    `UPDATE zk1_sync_batch.device_grant SET scope=$2,
      device_id='moved-a',revoked=true
      WHERE scope=$1 AND device_id='device-a' RETURNING scope,device_id`,
  ]) {
    const conn = await admin.connect();
    try {
      await conn.query("BEGIN");
      await assert.rejects(conn.query(update, [old.scope, newScope]),
        { code: "23514" },
        "BEFORE ROW trigger must reject OLD->NEW before either scope can change");
    } finally {
      try { await conn.query("ROLLBACK"); } catch { /* aborted transaction */ }
      conn.release();
    }
    assert.deepEqual(await snapshot(), before,
      "failed grant reassignment must roll back OLD and NEW grants, epochs, heads and markers");
  }

  // A legitimate same-scope revocation still locks/fences the OLD scope, not
  // the target scope. A previously issued admission cannot survive it.
  await admin.query(`UPDATE zk1_sync_batch.device_grant SET revoked=true
    WHERE scope=$1 AND device_id='device-a'`, [old.scope]);
  const afterRevocation = await snapshot();
  assert.equal(Number(afterRevocation.policies.find((x) => x.scope === old.scope).policy_epoch),
    Number(before.policies.find((x) => x.scope === old.scope).policy_epoch) + 1);
  assert.equal(Number(afterRevocation.policies.find((x) => x.scope === newScope).policy_epoch),
    Number(before.policies.find((x) => x.scope === newScope).policy_epoch));
  assert.deepEqual(afterRevocation.heads, before.heads,
    "ordinary revocation must not rewrite either physical scope head");
  assert.equal(afterRevocation.grants.length, 1);
  assert.equal(afterRevocation.grants[0].scope, old.scope);
  assert.equal(afterRevocation.grants[0].revoked, true);
  await assert.rejects(store.commitSignedOverwritePair({
    ...old, operations: signed, admissionTicket: existingAdmission,
  }), { code: "SYNC_PG_BATCH_UNAUTHORIZED" },
  "revoked OLD grant must fence the already-issued admission");
  assert.deepEqual((await snapshot()).markers, before.markers);
});

test("PG18 refuses direct SQL mutation of a committed state under the same marker", async () => {
  const f = await fixture();
  await commitTestBatch(f, await f.signedPair());
  await assert.rejects(runtime.query(`UPDATE zk1_sync_batch.object_state
    SET ciphertext=decode('00','hex') WHERE scope=$1 AND object_id='src'`,
  [f.scope]), /./);
  assert.equal((await f.state()).markers.length, 1);
});

test("PG18 denies incomplete direct-SQL marker without the exact seen originals", async () => {
  const f = await fixture();
  const ops = await f.signedPair();
  const digests = ops.map((o) => hash(protocol.canonicalJson(o)));
  const id = crypto.randomUUID();
  const conn = await admin.connect();
  try {
    await conn.query("BEGIN");
    const current = await conn.query("SELECT sequence,head FROM zk1_sync_batch.scope_head WHERE scope=$1 FOR UPDATE", [f.scope]);
    const epoch = await conn.query("SELECT policy_epoch FROM zk1_sync_batch.scope_policy WHERE scope=$1", [f.scope]);
    const previous = current.rows[0].head;
    const fakeState = hash("unverified-physical-state");
    const marker = await conn.query(`INSERT INTO zk1_sync_batch.batch_commit
      (scope,sequence,commit_id,policy_epoch,previous_head,head,
      delete_id,move_id,delete_digest,move_digest,state_digest)
      VALUES ($1,1,$2,$3,$4,
      zk1_sync_batch.commit_head($1,1,$2,$3,$4,$5,$6,$7,$8,$9),
      $5,$6,$7,$8,$9) RETURNING head`,
    [f.scope, id, Number(epoch.rows[0].policy_epoch), previous,
      ops[0].operationId, ops[1].operationId, digests[0], digests[1], fakeState]);
    await conn.query("UPDATE zk1_sync_batch.scope_head SET sequence=1,head=$2 WHERE scope=$1",
      [f.scope, marker.rows[0].head]);
    await assert.rejects(conn.query("COMMIT"), /./,
      "marker without either physical envelope must fail at deferred SQL constraint");
  } finally {
    try { await conn.query("ROLLBACK"); } catch { /* aborted transaction */ }
    conn.release();
  }
  assert.equal((await f.state()).markers.length, 0);
});

test("PG18 deferred marker denies different but self-consistent physical MOVE bytes", async () => {
  const f = await fixture();
  const original = await f.signedPair();
  const alternative = await f.signedPair();
  const stored = [original[0], alternative[1]];
  const originalDigests = original.map((o) => hash(protocol.canonicalJson(o)));
  const commitId = crypto.randomUUID();
  const conn = await admin.connect();
  try {
    await conn.query("BEGIN");
    const head = (await conn.query(`SELECT sequence,head FROM zk1_sync_batch.scope_head
      WHERE scope=$1 FOR UPDATE`, [f.scope])).rows[0];
    const epoch = (await conn.query(`SELECT policy_epoch FROM zk1_sync_batch.scope_policy
      WHERE scope=$1`, [f.scope])).rows[0].policy_epoch;
    for (const op of stored) {
      const canonical = protocol.canonicalJson(op);
      await conn.query(`UPDATE zk1_sync_batch.object_state SET
        version_id=$3,revision_counter=$4,revision_device=$5,logical_path=$6,
        tombstone=$7,canonical_envelope=$8,envelope_digest=$9,
        ciphertext=$10,last_commit_id=$11 WHERE scope=$1 AND object_id=$2`, [
        f.scope, op.objectId, op.versionId, op.revision.counter,
        op.revision.deviceId, op.metadata.path, op.tombstone, canonical,
        hash(canonical), Buffer.from(op.ciphertext, "base64url"), commitId,
      ]);
    }
    const stateDigest = (await conn.query(`SELECT zk1_sync_batch.state_digest($1,'dest','src') AS digest`,
      [f.scope])).rows[0].digest;
    const marker = await conn.query(`INSERT INTO zk1_sync_batch.batch_commit
      (scope,sequence,commit_id,policy_epoch,previous_head,head,
      delete_id,move_id,delete_digest,move_digest,state_digest)
      VALUES ($1,1,$2,$3,$4,
        zk1_sync_batch.commit_head($1,1,$2,$3,$4,$5,$6,$7,$8,$9),
        $5,$6,$7,$8,$9) RETURNING head`, [
      f.scope, commitId, Number(epoch), head.head,
      original[0].operationId, original[1].operationId,
      originalDigests[0], originalDigests[1], stateDigest,
    ]);
    for (let i = 0; i < original.length; i++) {
      const op = original[i];
      const canonical = protocol.canonicalJson(op);
      await conn.query(`INSERT INTO zk1_sync_batch.seen_envelope
        (scope,operation_id,replay_id,idempotency_key,commit_id,
        ordinal,kind,canonical_envelope,envelope_digest,ciphertext)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [
        f.scope, op.operationId, op.authorization.replayId,
        op.authorization.idempotencyKey, commitId, i, op.operation,
        canonical, originalDigests[i], Buffer.from(op.ciphertext,"base64url"),
      ]);
    }
    await conn.query(`UPDATE zk1_sync_batch.scope_head SET sequence=1,head=$2
      WHERE scope=$1`, [f.scope, marker.rows[0].head]);
    await assert.rejects(conn.query("COMMIT"), /./,
      "two independently matching digests must not bypass original-envelope equality");
  } finally {
    try { await conn.query("ROLLBACK"); } catch { /* aborted transaction */ }
    conn.release();
  }
  const after = await f.state();
  assert.equal(after.markers.length, 0);
  assert.equal(Number(after.head.sequence), 0);
  assert.equal(after.seen.length, 0);
  assert.equal(after.rows.every((r) => r.revision_counter === "1"), true);
});

test("runtime, verifier, issuer and reader DENY raw protected DML, including column ACLs", async () => {
  for (const rolePool of [runtime, verifier, issuer, attestor]) {
    const access = await rolePool.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.scope_head','UPDATE') AS head_write,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','UPDATE') AS state_write,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.batch_commit','INSERT') AS marker_write,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.seen_envelope','INSERT') AS seen_write,
      pg_catalog.has_column_privilege(current_user,'zk1_sync_batch.scope_head','head','UPDATE') AS head_col_write,
      pg_catalog.has_column_privilege(current_user,'zk1_sync_batch.object_state','ciphertext','UPDATE') AS cipher_col_write,
      pg_catalog.has_column_privilege(current_user,'zk1_sync_batch.batch_commit','commit_id','INSERT') AS marker_col_write,
      pg_catalog.has_column_privilege(current_user,'zk1_sync_batch.seen_envelope','canonical_envelope','INSERT') AS seen_col_write`);
    assert.ok(Object.values(access.rows[0]).every((allowed) => allowed === false),
      "all untrusted and readback DB roles must lack table AND column DML");
    await assert.rejects(rolePool.query(`UPDATE zk1_sync_batch.scope_head
      SET sequence=sequence WHERE scope='blocked'`), /permission denied/i);
    await assert.rejects(rolePool.query(`UPDATE zk1_sync_batch.object_state
      SET ciphertext=ciphertext WHERE scope='blocked'`), /permission denied/i);
    await assert.rejects(rolePool.query(`INSERT INTO zk1_sync_batch.batch_commit (scope,sequence)
      VALUES ('blocked',1)`), /permission denied/i);
    await assert.rejects(rolePool.query(`INSERT INTO zk1_sync_batch.seen_envelope
      (scope,operation_id) VALUES ('blocked','denied')`), /permission denied/i);
  }
});

test("PG18 verifier, runtime, issuer and attestor real DELETE/TRUNCATE return 42501 without changing physical state", async () => {
  const f = await fixture();
  const before = await f.state();
  for (const rolePool of [runtime, verifier, issuer, attestor]) {
    const grants = await rolePool.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS may_delete,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS may_truncate`);
    assert.deepEqual(grants.rows[0], { may_delete: false, may_truncate: false });
    await assert.rejects(rolePool.query(`DELETE FROM zk1_sync_batch.object_state
      WHERE scope=$1 AND object_id='dest'`, [f.scope]), { code: "42501" },
    "DELETE with a real existing target row must fail at the ACL boundary");
    await assert.rejects(rolePool.query("TRUNCATE TABLE zk1_sync_batch.object_state"),
      { code: "42501" }, "TRUNCATE must fail even without a WHERE clause");
    assert.deepEqual(await f.state(), before,
      "failed DELETE/TRUNCATE cannot alter objects, head, history or replay state");
  }
});

test("PG18 accidental direct DELETE/TRUNCATE grants make verifier, readback and admission issuer fail closed", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const ticket = await mintTestAdmission(f, pair);
  const before = await f.state();
  await admin.query(`GRANT DELETE,TRUNCATE ON zk1_sync_batch.object_state
    TO zk1_sync_batch_verifier`);
  try {
    const effective = await verifier.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS can_delete,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS can_truncate`);
    assert.deepEqual(effective.rows[0], { can_delete: true, can_truncate: true },
      "the test must genuinely elevate the verifier's destructive privileges");
    await assert.rejects(store.commitSignedOverwritePair({
      ...f, operations: pair, admissionTicket: ticket,
    }), { code: "SYNC_PG_BATCH_UNTRUSTED_DATABASE_ROLE" });
    assert.deepEqual(await f.state(), before);
  } finally {
    await admin.query(`REVOKE DELETE,TRUNCATE ON zk1_sync_batch.object_state
      FROM zk1_sync_batch_verifier`);
  }
  const committed = await store.commitSignedOverwritePair({
    ...f, operations: pair, admissionTicket: ticket,
  });
  await admin.query(`GRANT DELETE,TRUNCATE ON zk1_sync_batch.object_state
    TO zk1_sync_batch_attestor_reader`);
  try {
    const effective = await attestor.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','DELETE') AS can_delete,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.object_state','TRUNCATE') AS can_truncate`);
    assert.deepEqual(effective.rows[0], { can_delete: true, can_truncate: true });
    await assert.rejects(readback.verifyLatestSignedPair({
      scope: f.scope, commitId: committed.commitId,
    }), { code: "ZK1_SYNC_PG_READBACK_UNVERIFIED" });
    await assert.rejects(admissionIssuer.issueTicket({
      ...f, operations: pair,
    }), { code: "SYNC_PG_ISSUER_DENIED" });
  } finally {
    await admin.query(`REVOKE DELETE,TRUNCATE ON zk1_sync_batch.object_state
      FROM zk1_sync_batch_attestor_reader`);
  }
  const next = await fixture();
  const nextPair = await next.signedPair();
  await admin.query(`GRANT DELETE,TRUNCATE ON zk1_sync_batch.admission_ticket
    TO zk1_sync_batch_admission_issuer`);
  try {
    const effective = await issuer.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','DELETE') AS can_delete,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','TRUNCATE') AS can_truncate`);
    assert.deepEqual(effective.rows[0], { can_delete: true, can_truncate: true });
    await assert.rejects(admissionIssuer.issueTicket({
      ...next, operations: nextPair,
    }), { code: "SYNC_PG_ISSUER_DENIED" });
    assert.equal((await next.state()).markers.length, 0);
  } finally {
    await admin.query(`REVOKE DELETE,TRUNCATE ON zk1_sync_batch.admission_ticket
      FROM zk1_sync_batch_admission_issuer`);
  }
});

test("admission tickets are issuer-only; verifier cannot fabricate or edit them", async () => {
  const grants = await Promise.all([runtime, verifier, attestor, issuer].map((pool) =>
    pool.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','INSERT') AS mint,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','UPDATE') AS edit,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','DELETE') AS erase,
      pg_catalog.has_table_privilege(current_user,'zk1_sync_batch.admission_ticket','SELECT') AS read,
      pg_catalog.has_column_privilege(current_user,'zk1_sync_batch.admission_ticket','consumed','UPDATE') AS consume`)));
  assert.equal(grants[0].rows[0].mint, false);
  assert.equal(grants[1].rows[0].mint, false);
  assert.equal(grants[2].rows[0].mint, false);
  assert.deepEqual(grants[3].rows[0], {
    mint: true, edit: false, erase: false, read: false, consume: false,
  });
  await assert.rejects(verifier.query(`INSERT INTO zk1_sync_batch.admission_ticket
    (ticket_id,scope) VALUES ($1,'unauthorized')`, [crypto.randomUUID()]),
  /permission denied/i);
  const verifierConn = await verifier.connect();
  try {
    await assert.rejects(verifierConn.query("SET ROLE zk1_sync_batch_admission_issuer"),
      /permission denied/i);
  } finally {
    verifierConn.release();
  }
  await assert.rejects(issuer.query("SELECT 1 FROM zk1_sync_batch.scope_head"),
    /permission denied/i);
  await assert.rejects(issuer.query(`SELECT zk1_sync_batch.commit_admitted_pair(
    'blocked','blocked',$1,'{}','{}')`, [crypto.randomUUID()]),
  /permission denied/i);
});

test("future SECURITY DEFINER functions inherit global owner default with NO PUBLIC EXECUTE", async () => {
  // PostgreSQL's default PUBLIC EXECUTE is GLOBAL, not schema-scoped. Verify
  // owner metadata and effective ACL on a real newly created definer function.
  const ownerDefault = await admin.query(`SELECT
    d.defaclnamespace AS namespace, d.defaclacl::text AS acl,
    pg_catalog.pg_get_userbyid(d.defaclrole) AS owner,
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(d.defaclacl) grant_entry
      WHERE grant_entry.grantee=0 AND grant_entry.privilege_type='EXECUTE') AS public_execute
    FROM pg_catalog.pg_default_acl d
    WHERE d.defaclnamespace=0 AND d.defaclobjtype='f'
      AND d.defaclrole=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)`);
  assert.equal(ownerDefault.rowCount, 1,
    "dedicated owner must have an explicit GLOBAL revoked default ACL");
  assert.equal(ownerDefault.rows[0].public_execute, false,
    "global function defaults must not grant EXECUTE to PUBLIC");
  const name = "test_future_definer_" + crypto.randomBytes(6).toString("hex");
  try {
    await admin.query(`CREATE FUNCTION zk1_sync_batch.${name}()
      RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog
      AS $$ SELECT true $$`);
    const meta = await admin.query(`SELECT p.prosecdef AS security_definer,
      p.proacl::text AS acl, pg_catalog.pg_get_userbyid(p.proowner) AS owner
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n
        ON n.oid=p.pronamespace
      WHERE n.nspname='zk1_sync_batch' AND p.proname=$1`, [name]);
    assert.equal(meta.rowCount, 1);
    assert.equal(meta.rows[0].security_definer, true);
    assert.equal(meta.rows[0].owner, ownerDefault.rows[0].owner);
    for (const rolePool of [runtime, verifier, issuer, attestor]) {
      const granted = await rolePool.query(`SELECT
        pg_catalog.has_function_privilege(current_user,$1::regprocedure,'EXECUTE') AS allowed`,
      [`zk1_sync_batch.${name}()`]);
      assert.equal(granted.rows[0].allowed, false,
        "future SECURITY DEFINER EXECUTE must not leak through PUBLIC");
      await assert.rejects(rolePool.query(`SELECT zk1_sync_batch.${name}()`),
        { code: "42501" });
    }
  } finally {
    await admin.query(`DROP FUNCTION IF EXISTS zk1_sync_batch.${name}()`);
  }
});

test("untrusted verifier cannot mutate any physical state or invent admission via its function", async () => {
  const f = await fixture();
  const original = await f.signedPair();
  await assert.rejects(store.commitSignedOverwritePair({
    ...f, operations: original, admissionTicket: crypto.randomUUID(),
  }), { code: "SYNC_PG_BATCH_UNAVAILABLE" });
  const validTicket = await mintTestAdmission(f, original);
  const alternate = await f.signedPair();
  await assert.rejects(store.commitSignedOverwritePair({
    ...f, operations: alternate, admissionTicket: validTicket,
  }), { code: "SYNC_PG_BATCH_UNAVAILABLE" },
  "ticket for one signed pair must not authorize a different valid signed pair");
  const current = await f.state();
  assert.equal(current.markers.length, 0);
  assert.equal(current.seen.length, 0);
  const committed = await store.commitSignedOverwritePair({
    ...f, operations: original, admissionTicket: validTicket,
  });
  assert.equal(committed.clientAckAuthorized, false);
  await assert.rejects(store.commitSignedOverwritePair({
    ...f, operations: original, admissionTicket: validTicket,
  }), { code: "SYNC_PG_BATCH_UNAVAILABLE" },
  "single-use admission ticket must not be replayable");
  assert.equal((await f.state()).markers.length, 1);
});

test("operator epoch/head changes fence a valid independently minted admission ticket", async () => {
  const epochFixture = await fixture();
  const signed = await epochFixture.signedPair();
  const staleTicket = await mintTestAdmission(epochFixture, signed);
  await admin.query(`UPDATE zk1_sync_batch.scope_policy SET allow_delete=true
    WHERE scope=$1`, [epochFixture.scope]);
  await assert.rejects(store.commitSignedOverwritePair({
    ...epochFixture, operations: signed, admissionTicket: staleTicket,
  }), { code: "SYNC_PG_BATCH_UNAVAILABLE" });
  assert.equal((await epochFixture.state()).markers.length, 0);

  const headFixture = await fixture();
  const signedHead = await headFixture.signedPair();
  const ticketForOldHead = await mintTestAdmission(headFixture, signedHead);
  await admin.query(`UPDATE zk1_sync_batch.scope_head
    SET head=decode(repeat('ab',32),'hex') WHERE scope=$1`, [headFixture.scope]);
  await assert.rejects(store.commitSignedOverwritePair({
    ...headFixture, operations: signedHead, admissionTicket: ticketForOldHead,
  }), { code: "SYNC_PG_BATCH_UNAVAILABLE" });
  assert.equal((await headFixture.state()).markers.length, 0);
});

test("unprivileged runtime cannot call admission entrypoint or mint fake admission", async () => {
  const f = await fixture();
  await assert.rejects(runtime.query(`SELECT zk1_sync_batch.commit_admitted_pair(
    $1,$2,$3,'{}','{}')`, [f.scope, f.username, crypto.randomUUID()]),
  /permission denied/i);
  await assert.rejects(runtime.query(`INSERT INTO zk1_sync_batch.admission_ticket
    (ticket_id,scope) VALUES ($1,$2)`, [crypto.randomUUID(), f.scope]),
  /permission denied/i);
  const state = await f.state();
  assert.equal(state.markers.length, 0);
  assert.equal(Number(state.head.sequence), 0);
});

test("issuer rejects signature forgery, revoked grants, and substituted DB identities", async () => {
  const f = await fixture();
  const original = await f.signedPair();
  const forged = structuredClone(original);
  forged[1].ciphertext = (forged[1].ciphertext.startsWith("A") ? "B" : "A")
    + forged[1].ciphertext.slice(1);
  await assert.rejects(admissionIssuer.issueTicket({
    ...f, operations: forged,
  }), { code: "SYNC_PG_ISSUER_DENIED" });
  await assert.rejects(createZk1SyncPgIndependentAdmissionIssuer({
    readerPool: verifier, issuerPool: issuer,
  }).issueTicket({ ...f, operations: original }),
  { code: "SYNC_PG_ISSUER_DENIED" });
  await assert.rejects(createZk1SyncPgIndependentAdmissionIssuer({
    readerPool: attestor, issuerPool: verifier,
  }).issueTicket({ ...f, operations: original }),
  { code: "SYNC_PG_ISSUER_DENIED" });
  await admin.query(`UPDATE zk1_sync_batch.device_grant SET revoked=true
    WHERE scope=$1 AND device_id='device-a'`, [f.scope]);
  await assert.rejects(admissionIssuer.issueTicket({
    ...f, operations: original,
  }), { code: "SYNC_PG_ISSUER_DENIED" });
  assert.equal((await f.state()).markers.length, 0);
});

test("runtime cannot SET ROLE verifier, inherit verifier membership or impersonate admission pool", async () => {
  const membership = await runtime.query(`SELECT
    pg_catalog.pg_has_role(current_user,'zk1_sync_batch_verifier','MEMBER') AS verifier_member,
    pg_catalog.pg_has_role(current_user,'zk1_sync_batch_verifier','USAGE') AS verifier_usage,
    pg_catalog.pg_has_role(current_user,'zk1_sync_batch_attestor_reader','MEMBER') AS reader_member,
    pg_catalog.pg_has_role(current_user,'zk1_sync_batch_admission_issuer','MEMBER') AS issuer_member`);
  assert.deepEqual(membership.rows[0],
    { verifier_member: false, verifier_usage: false, reader_member: false, issuer_member: false });
  const conn = await runtime.connect();
  try {
    await assert.rejects(conn.query("SET ROLE zk1_sync_batch_verifier"), /permission denied/i);
  } finally {
    try { await conn.query("RESET ROLE"); } catch { /* role never switched */ }
    conn.release();
  }
  const f = await fixture();
  await assert.rejects(createZk1SyncPgAtomicBatchStore({ verifierPool: runtime })
    .commitSignedOverwritePair({
      ...f, operations: await f.signedPair(), admissionTicket: crypto.randomUUID(),
    }),
  { code: "SYNC_PG_BATCH_UNTRUSTED_DATABASE_ROLE" });
  assert.equal((await f.state()).markers.length, 0);
});

test("attestor reader can inspect committed marker, state and signed originals without writer rights", async () => {
  const f = await fixture();
  const operations = await f.signedPair();
  await commitTestBatch(f, operations);
  const visible = await attestor.query(`SELECT m.commit_id, m.sequence,
    m.head, s.ordinal,s.canonical_envelope,s.envelope_digest,s.ciphertext,
    o.canonical_envelope AS state_envelope,o.envelope_digest AS state_digest,
    o.ciphertext AS state_ciphertext
    FROM zk1_sync_batch.batch_commit m
    JOIN zk1_sync_batch.seen_envelope s ON s.scope=m.scope AND s.commit_id=m.commit_id
    JOIN zk1_sync_batch.object_state o ON o.scope=s.scope
      AND o.object_id=(s.canonical_envelope::jsonb->>'objectId')
    WHERE m.scope=$1 ORDER BY s.ordinal`, [f.scope]);
  assert.equal(visible.rowCount, 2);
  for (const [index, row] of visible.rows.entries()) {
    assert.equal(row.canonical_envelope, protocol.canonicalJson(operations[index]));
    assert.equal(row.canonical_envelope, row.state_envelope);
    assert.deepEqual(row.envelope_digest, row.state_digest);
    assert.deepEqual(row.ciphertext, row.state_ciphertext);
  }
  const proof = await readback.verifyLatestSignedPair({
    scope: f.scope, commitId: visible.rows[0].commit_id,
  });
  assert.equal(proof.localPgRowsConsistent, true);
  assert.equal(proof.witnessVerified, false);
  assert.equal(proof.clientAckAuthorized, false);
  assert.deepEqual(proof.operationIds, operations.map((op) => op.operationId));
});

test("independent readback rejects revocation and runtime impersonation", async () => {
  const f = await fixture();
  const operations = await f.signedPair();
  const result = await commitTestBatch(f, operations);
  await assert.rejects(createZk1SyncPgBatchIndependentReadback({ attestorPool: runtime })
    .verifyLatestSignedPair({ scope: f.scope, commitId: result.commitId }),
  { code: "ZK1_SYNC_PG_READBACK_UNVERIFIED" });
  await admin.query(`UPDATE zk1_sync_batch.device_grant SET revoked=true
    WHERE scope=$1 AND device_id='device-a'`, [f.scope]);
  await assert.rejects(readback.verifyLatestSignedPair({
    scope: f.scope, commitId: result.commitId,
  }), { code: "ZK1_SYNC_PG_READBACK_UNVERIFIED" });
});

test("PG18 direct SQL rejects missing JSON-bound fields, including NULL ciphertext", async () => {
  const f = await fixture();
  const original = (await f.state()).rows.find((row) => row.object_id === "dest");
  const variants = [
    (op) => { delete op.objectId; },
    (op) => { delete op.fileId; },
    (op) => { delete op.versionId; },
    (op) => { delete op.deviceId; },
    (op) => { delete op.revision.deviceId; },
    (op) => { delete op.revision.counter; },
    (op) => { delete op.compartmentId; },
    (op) => { delete op.keyEpoch; },
    (op) => { delete op.metadata.path; },
    (op) => { delete op.tombstone; },
    (op) => { delete op.ciphertext; },
    (op) => { op.metadata = null; },
    (op) => { op.revision = null; },
  ];
  for (const mutate of variants) {
    const operation = JSON.parse(original.canonical_envelope);
    mutate(operation);
    const canonical = protocol.canonicalJson(operation);
    const ciphertext = Buffer.from(operation.ciphertext || "", "base64url");
    await assert.rejects(admin.query(`UPDATE zk1_sync_batch.object_state
      SET canonical_envelope=$2,envelope_digest=$3,ciphertext=$4
      WHERE scope=$1 AND object_id='dest'`, [
      f.scope, canonical, hash(canonical), ciphertext,
    ]), { code: "23514" }, "missing JSON field must violate CHECK, not pass UNKNOWN");
  }
  assert.equal((await f.state()).rows.find((row) => row.object_id === "dest")
    .canonical_envelope, original.canonical_envelope);
});

test("PG18 direct SQL rejects missing original signed-envelope proof fields", async () => {
  const f = await fixture();
  const pair = await f.signedPair();
  const result = await commitTestBatch(f, pair);
  const variants = [
    (op) => { delete op.operationId; },
    (op) => { delete op.operation; },
    (op) => { delete op.authorization; },
    (op) => { delete op.authorization.replayId; },
    (op) => { delete op.authorization.idempotencyKey; },
    (op) => { delete op.authorization.signature; },
    (op) => { delete op.authorization.publicKey; },
    (op) => { delete op.ciphertext; },
  ];
  for (const mutate of variants) {
    const op = structuredClone(pair[0]);
    const operationId = crypto.randomUUID();
    const replayId = crypto.randomUUID();
    const idempotencyKey = crypto.randomBytes(18).toString("base64url");
    op.operationId = operationId;
    op.authorization.replayId = replayId;
    op.authorization.idempotencyKey = idempotencyKey;
    mutate(op);
    const canonical = protocol.canonicalJson(op);
    await assert.rejects(admin.query(`INSERT INTO zk1_sync_batch.seen_envelope
      (scope,operation_id,replay_id,idempotency_key,commit_id,ordinal,kind,
       canonical_envelope,envelope_digest,ciphertext)
      VALUES ($1,$2,$3,$4,$5,0,'delete',$6,$7,$8)`, [
      f.scope, operationId, replayId, idempotencyKey, result.commitId,
      canonical, hash(canonical), Buffer.from(op.ciphertext || "", "base64url"),
    ]), { code: "23514" }, "missing signed proof field must fail SQL CHECK");
  }
  assert.equal((await f.state()).seen.length, 2);
});

test("independent readback rejects an actual PostgreSQL old-head rollback", async () => {
  const f = await fixture();
  const result = await commitTestBatch(f, await f.signedPair());
  assert.equal((await readback.verifyLatestSignedPair({
    scope: f.scope, commitId: result.commitId,
  })).localPgRowsConsistent, true);
  // Operator-only adversarial rollback in a disposable test scope. Restoring
  // the genesis head while leaving the committed rows must fail closed.
  await admin.query(`UPDATE zk1_sync_batch.scope_head
    SET sequence=0,head=decode(repeat('00',32),'hex') WHERE scope=$1`, [f.scope]);
  assert.equal(Number((await f.state()).head.sequence), 0);
  await assert.rejects(readback.verifyLatestSignedPair({
    scope: f.scope, commitId: result.commitId,
  }), { code: "ZK1_SYNC_PG_READBACK_UNVERIFIED" });
});

test("independent readback rejects physically forged ciphertext with a self-consistent replacement envelope", async () => {
  const f = await fixture();
  const operations = await f.signedPair();
  const result = await commitTestBatch(f, operations);
  const alternative = (await f.signedPair())[1];
  assert.notEqual(protocol.canonicalJson(alternative),
    protocol.canonicalJson(operations[1]));
  const canonical = protocol.canonicalJson(alternative);
  // Operator-only corruption fixture: disable the protective object UPDATE
  // trigger for a single transaction, replace all JSON-derived columns and
  // actual ciphertext consistently, then re-enable the trigger BEFORE COMMIT.
  // The ordinary SQL CHECKs should allow the internally coherent replacement;
  // independent readback must still reject it against ORIGINAL seen/marker.
  const conn = await admin.connect();
  let begun = false;
  try {
    await conn.query("BEGIN");
    begun = true;
    await conn.query(`ALTER TABLE zk1_sync_batch.object_state
      DISABLE TRIGGER object_revision_requires_new_commit`);
    const changed = await conn.query(`UPDATE zk1_sync_batch.object_state
      SET version_id=$3,canonical_envelope=$4,envelope_digest=$5,ciphertext=$6
      WHERE scope=$1 AND object_id=$2`, [
      f.scope, alternative.objectId, alternative.versionId, canonical,
      hash(canonical), Buffer.from(alternative.ciphertext, "base64url"),
    ]);
    assert.equal(changed.rowCount, 1);
    await conn.query(`ALTER TABLE zk1_sync_batch.object_state
      ENABLE TRIGGER object_revision_requires_new_commit`);
    await conn.query("COMMIT");
    begun = false;
  } finally {
    if (begun) {
      try { await conn.query("ROLLBACK"); } catch { /* test-only rollback */ }
    }
    conn.release();
  }
  const forged = (await f.state()).rows.find((row) => row.object_id === alternative.objectId);
  assert.equal(forged.canonical_envelope, canonical);
  assert.deepEqual(forged.ciphertext, Buffer.from(alternative.ciphertext, "base64url"));
  await assert.rejects(readback.verifyLatestSignedPair({
    scope: f.scope, commitId: result.commitId,
  }), { code: "ZK1_SYNC_PG_READBACK_UNVERIFIED" });
});

test("P1 adversarial RED requirement: verifier direct SQL state/head/marker/seen mutation is denied", async () => {
  // Retain the ORIGINAL verifier-bypass regression as executable, real SQL
  // attacks. Introspection alone is insufficient. Every attempt must be
  // rejected with PostgreSQL SQLSTATE 42501, not by unrelated data CHECKs.
  const f = await fixture();
  const signed = await f.signedPair();
  const before = await f.state();
  const marker = crypto.randomUUID();
  const attackQueries = [
    [`UPDATE zk1_sync_batch.scope_head SET head=decode(repeat('ac',32),'hex')
      WHERE scope=$1`, [f.scope]],
    [`UPDATE zk1_sync_batch.object_state SET ciphertext=decode('deadbeef','hex')
      WHERE scope=$1 AND object_id='src'`, [f.scope]],
    [`INSERT INTO zk1_sync_batch.batch_commit
      (scope,sequence,commit_id,policy_epoch,previous_head,head,
       delete_id,move_id,delete_digest,move_digest,state_digest)
      VALUES ($1,1,$2,1,decode(repeat('00',32),'hex'),
        decode(repeat('ab',32),'hex'),$3,$4,$5,$6,$7)`, [
      f.scope, marker, signed[0].operationId, signed[1].operationId,
      hash(protocol.canonicalJson(signed[0])),
      hash(protocol.canonicalJson(signed[1])), hash("attacker-state"),
    ]],
    [`INSERT INTO zk1_sync_batch.seen_envelope
      (scope,operation_id,replay_id,idempotency_key,commit_id,ordinal,kind,
       canonical_envelope,envelope_digest,ciphertext)
      VALUES ($1,$2,$3,$4,$5,0,'delete',$6,$7,$8)`, [
      f.scope, signed[0].operationId, signed[0].authorization.replayId,
      signed[0].authorization.idempotencyKey, marker,
      protocol.canonicalJson(signed[0]), hash(protocol.canonicalJson(signed[0])),
      Buffer.from(signed[0].ciphertext, "base64url"),
    ]],
  ];
  for (const [sql, parameters] of attackQueries) {
    await assert.rejects(verifier.query(sql, parameters), { code: "42501" },
      "verifier must never reach protected DML even with valid-looking values");
  }
  const after = await f.state();
  assert.deepEqual(after, before,
    "direct SQL attack cannot change physical state or authoritative marker");
});
