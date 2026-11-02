"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createZk1CiphertextRootBuilder, computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");

test("a malformed chunk does not consume a position or change the ciphertext root", () => {
  const first = Buffer.from("valid-first-chunk");
  const second = Buffer.from("valid-second-chunk");
  const expected = computeZk1CiphertextRoot([first, second]);
  for (const malformed of [Buffer.alloc(0), Buffer.alloc(4 * 1024 * 1024 + 1),
    "not-bytes", null]) {
    const builder = createZk1CiphertextRootBuilder(2);
    builder.append(first);
    assert.throws(() => builder.append(malformed), /ZK_CHUNK_ROOT_INVALID/);
    assert.throws(() => builder.finish(), /ZK_CHUNK_ROOT_INVALID/);
    builder.append(second);
    assert.deepEqual(builder.finish(), expected);
  }
});
