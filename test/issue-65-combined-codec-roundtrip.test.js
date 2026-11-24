"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { encodeDeterministic, decodeDeterministic } = require("../src/crypto/rootark-zk-1");

test("deterministic codec round-trips ordinary nested array records", async () => {
  const source = { records: [{ revision: 1, values: ["a", "b"] }, { revision: 2, values: [] }] };
  const encoded = await encodeDeterministic(source);
  const decoded = await decodeDeterministic(encoded);
  assert.equal(decoded.records.length, 2);
  assert.equal(decoded.records[0].revision, 1);
  assert.equal(decoded.records[0].values[1], "b");
  assert.equal(decoded.records[1].values.length, 0);
  assert.deepEqual(await encodeDeterministic(decoded), encoded);
});

test("deterministic codec can re-encode its own decoded top-level array", async () => {
  const encoded = await encodeDeterministic([1, 2, ["a", "b"]]);
  const decoded = await decodeDeterministic(encoded);
  assert.equal(decoded.length, 3);
  assert.deepEqual(await encodeDeterministic(decoded), encoded);
});
