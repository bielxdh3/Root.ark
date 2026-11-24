"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { newNativePromise, nativePromiseThen } = require("../src/crypto/rootark-zk10-native-intrinsics-v1");

test("native promise reactions propagate a fulfillment callback error to the next promise", async () => {
  const failure = new Error("ordinary callback error");
  let rejectionCalls = 0;
  const source = newNativePromise((resolve) => resolve(42));
  const next = nativePromiseThen.call(source, () => { throw failure; }, () => {
    rejectionCalls += 1;
    return 0;
  });
  await assert.rejects(next, (error) => error === failure);
  assert.equal(rejectionCalls, 0);
});

test("native promise reactions preserve ordinary fulfillment and rejection handling", async () => {
  const fulfilled = newNativePromise((resolve) => resolve(21));
  assert.equal(await nativePromiseThen.call(fulfilled, (value) => value * 2), 42);
  assert.equal(await nativePromiseThen.call(fulfilled), 21);
  const failure = new Error("ordinary source error");
  const rejected = newNativePromise((_resolve, reject) => reject(failure));
  assert.equal(await nativePromiseThen.call(rejected, undefined, (error) => {
    assert.equal(error, failure);
    return "handled";
  }), "handled");
  await assert.rejects(nativePromiseThen.call(rejected), (error) => error === failure);
});
