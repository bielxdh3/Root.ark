"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { setTimeout: delay } = require("node:timers/promises");
const { waitForBrowserValue } = require("./support/issue-65-browser-wait");

test("browser polling rejects a value arriving after its existing deadline", async () => {
  await assert.rejects(waitForBrowserValue(async () => {
    await delay(80);
    return "late";
  }, 10), /EDGE_LOCAL_TIMEOUT/);
});

test("browser polling stops waiting for an unresolved asynchronous read", { timeout: 1000 }, async () => {
  // A later resolution ensures the old implementation terminates too.
  let complete;
  const read = new Promise((resolve) => { complete = resolve; });
  const timer = setTimeout(() => complete("late"), 80);
  try {
    await assert.rejects(waitForBrowserValue(() => read, 10), /EDGE_LOCAL_TIMEOUT/);
  } finally {
    clearTimeout(timer);
    complete("cleanup");
  }
});

test("browser polling preserves immediate values and read errors", async () => {
  assert.equal(await waitForBrowserValue(() => "ready", 100), "ready");
  const failure = new Error("ordinary read failure");
  await assert.rejects(waitForBrowserValue(() => { throw failure; }, 100),
    (error) => error === failure);
});

test("browser polling retries empty values and does not retry after the deadline", async () => {
  let calls = 0;
  assert.equal(await waitForBrowserValue(() => ++calls === 2 ? "ready" : null, 1000), "ready");
  assert.equal(calls, 2);
  let lateCalls = 0;
  await assert.rejects(waitForBrowserValue(async () => {
    lateCalls += 1;
    await delay(80);
    return null;
  }, 10), /EDGE_LOCAL_TIMEOUT/);
  await delay(150);
  assert.equal(lateCalls, 1);
});
