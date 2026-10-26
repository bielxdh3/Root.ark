"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedGetReader } = require("../src/services/zk1SharedPgSealedGetReader");

function makeSealedGetFixture(expectedChunks) {
  const io = {
    scope: { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(8),
      keyring_id: crypto.randomBytes(16) },
    workerId: crypto.randomBytes(16), principal: "independent-get-worker", action: "get",
    objectId: crypto.randomBytes(16).toString("base64url"), revision: 7,
    digest: crypto.randomBytes(32),
  };
  const process = { hostKeyId: crypto.randomBytes(16), processEpoch: crypto.randomBytes(16),
    processPid: 12345 };
  const admissionId = crypto.randomBytes(16);
  const generation = 9;
  const expectedRootHash = crypto.randomBytes(32);
  const ciphertext = crypto.randomBytes(64);
  const scopeKey = io.scope.account_id.toString("hex") + ":"
    + io.scope.compartment_id.length.toString(16) + ":"
    + io.scope.compartment_id.toString("hex");
  const stats = { ciphertextQueries: 0, transactionsCommitted: 0 };
  const connection = {
    async query(sql) {
      if (sql === "BEGIN" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (sql === "COMMIT") { ++stats.transactionsCommitted; return { rowCount: 0, rows: [] }; }
      if (sql.includes("FROM zk1_gate.head")) return { rowCount: 1, rows: [{
        keyring_id: io.scope.keyring_id, require_stop_proof: true, phase: "OPEN",
        generation, revision: io.revision, digest: io.digest,
      }] };
      if (sql.includes("FROM zk1_gate.admission")) return { rowCount: 1, rows: [{
        id: admissionId, scope_key: scopeKey, worker_id: io.workerId,
        principal: io.principal, action: "get", object_id: io.objectId,
        state: "ACTIVE", generation, revision: io.revision, digest: io.digest,
        host_key_id: process.hostKeyId, process_epoch: process.processEpoch,
        process_pid: process.processPid,
      }] };
      if (sql.includes("FROM zk1_gate.sealed_object")) return { rowCount: 1, rows: [{
        revision: io.revision, digest: io.digest, generation,
        expected_chunks: expectedChunks, root_hash: expectedRootHash,
      }] };
      if (sql.includes("FROM zk1_gate.ciphertext_chunk")) {
        ++stats.ciphertextQueries;
        return { rowCount: 1, rows: [{ ciphertext }] };
      }
      throw new Error("Unexpected query in sealed GET fixture");
    },
    release() {},
  };
  const gate = new Zk1SharedPgGateAuthority({ pool: { connect: async () => connection } });
  return { reader: new Zk1SharedPgSealedGetReader({ gate }), io, process,
    admissionId, generation, expectedRootHash, ciphertext, stats };
}

test("sealed PostgreSQL GET serves valid one-, two-, three- and 4096-chunk objects", async (t) => {
  for (const [expectedChunks, chunkIndex] of [[1, 0], [2, 1], [3, 2], [4096, 4095]]) {
    await t.test(`${expectedChunks} sealed chunks: legal final index ${chunkIndex}`, async () => {
      const f = makeSealedGetFixture(expectedChunks);
      const bytes = await f.reader.readChunk({ io: f.io, process: f.process,
        admissionId: f.admissionId, generation: f.generation,
        expectedRootHash: f.expectedRootHash, chunkIndex });
      assert.deepEqual(bytes, f.ciphertext);
      assert.equal(f.stats.ciphertextQueries, 1);
      assert.equal(f.stats.transactionsCommitted, 1);
    });
  }
});

test("sealed PostgreSQL GET rejects invalid counts and out-of-bound chunk indices before ciphertext access", async (t) => {
  for (const [count, index] of [[0, 0], [4097, 0], [1.5, 0], [-1, 0],
    [NaN, 0], [1, 1], [3, 3], [4096, 4096]]) {
    await t.test(`sealed count=${count}, requested index=${index}`, async () => {
      const f = makeSealedGetFixture(count);
      await assert.rejects(f.reader.readChunk({ io: f.io, process: f.process,
        admissionId: f.admissionId, generation: f.generation,
        expectedRootHash: f.expectedRootHash, chunkIndex: index }), /ZK_GATE_GET_DENIED/);
      assert.equal(f.stats.ciphertextQueries, 0);
      assert.equal(f.stats.transactionsCommitted, 0);
    });
  }
});
