"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createZk1ProviderDeadline } = require("../src/services/zk1ProviderDeadline");

test("silent provider is cancelled on operator deadline and cannot claim a result", async () => {
  const deadline = createZk1ProviderDeadline({ deadlineMs: 80 });
  let aborted = false;
  try {
    await assert.rejects(deadline.run((signal) => new Promise((_, reject) => {
      signal.addEventListener("abort", () => { aborted = true; reject(Error("cancelled")); }, { once: true });
    })), /cancelled|ZK_PROVIDER_DEADLINE_EXCEEDED/);
    assert.equal(aborted, true);
    assert.equal(deadline.signal.aborted, true);
  } finally { deadline.close(); }
});

test("a noncooperative provider never causes early IO admission release", async () => {
  const deadline = createZk1ProviderDeadline({ deadlineMs: 60 });
  let release;
  let settled = false;
  try {
    const call = deadline.run(() => new Promise((resolve) => { release = resolve; }))
      .finally(() => { settled = true; });
    await new Promise((resolve) => setTimeout(resolve, 105));
    assert.equal(deadline.signal.aborted, true);
    assert.equal(settled, false, "do not falsely claim remote physical IO has stopped");
    release(true);
    await assert.rejects(call, /ZK_PROVIDER_DEADLINE_EXCEEDED/);
  } finally { deadline.close(); }
});

test("client disconnection cancels cooperatively and rejects finished results", async () => {
  const disconnected = new AbortController();
  const deadline = createZk1ProviderDeadline({ deadlineMs: 2000, parentSignal: disconnected.signal });
  try {
    const inFlight = deadline.run((signal) => new Promise((resolve) => {
      signal.addEventListener("abort", () => resolve("late provider acknowledgement"), { once: true });
    }));
    disconnected.abort();
    await assert.rejects(inFlight, /ZK_PROVIDER_DEADLINE_EXCEEDED/);
  } finally { deadline.close(); }
});
