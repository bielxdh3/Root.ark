"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { canonicalJson } = require("../sync-client/rootark-sync-protocol");
const { createIdempotencyKey, runIdempotent } =
  require("../src/services/deploymentResilience");

test("canonical JSON and idempotency keys do not drop own __proto__ fields", async () => {
  const ordinary = { operation: "upload", objectId: "object-A" };
  const adversarial = JSON.parse(
    '{"operation":"upload","objectId":"object-A","__proto__":{"objectId":"object-B"}}');
  assert.equal(Object.hasOwn(adversarial, "__proto__"), true);
  assert.notEqual(canonicalJson(adversarial), canonicalJson(ordinary),
    "canonical bytes must bind every own JSON key, including prototype-looking names");
  const normalKey = createIdempotencyKey(ordinary);
  const otherKey = createIdempotencyKey(adversarial);
  assert.notEqual(otherKey, normalKey,
    "two distinct requests must not share a replay/idempotency slot");
  const cache = new Map();
  const applied = await runIdempotent(normalKey, () => "original", cache);
  const second = await runIdempotent(otherKey, () => "different", cache);
  assert.deepEqual([applied, second], ["original", "different"]);
});

test("nested prototype-looking JSON fields remain represented and do not pollute any prototype", () => {
  const originalPrototype = Object.prototype;
  const one = JSON.parse('{"outer":{"__proto__":{"injected":true}}}');
  const two = { outer: {} };
  assert.notEqual(canonicalJson(one), canonicalJson(two));
  assert.notEqual(createIdempotencyKey(one), createIdempotencyKey(two));
  assert.equal(Object.prototype.injected, undefined);
  assert.equal(Object.prototype, originalPrototype);
});
