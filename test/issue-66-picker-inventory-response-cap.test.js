"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");

test("issue 66 P2 RED: an oversized valid advisory JSON page is rejected before the picker parses it", async () => {
  // The 64-entry limit is not an HTTP byte limit. This is valid JSON with
  // zero entries; the original response.json() accepted its ignored padding
  // after allocating the entire body, enabling hostile unbounded replies.
  const payload = new TextEncoder().encode(JSON.stringify({
    protocolVersion: 2, view: "metadata", objects: [], nextCursor: null,
    padding: "x".repeat(2 * 1024 * 1024),
  }));
  let position = 0;
  let cancelled = false;
  let seenSignal = false;
  const stream = new ReadableStream({
    pull(controller) {
      if (position === payload.byteLength) { controller.close(); return; }
      const end = Math.min(position + 32 * 1024, payload.byteLength);
      controller.enqueue(payload.subarray(position, end));
      position = end;
    },
    cancel() { cancelled = true; },
  });
  const adapter = createOpaqueSyncAdapter({
    baseUrl: "https://untrusted-sync.example",
    fetchImpl: async (url, request) => {
      assert.equal(url, "https://untrusted-sync.example/sync/v1/objects?view=metadata&limit=64");
      assert.equal(request.redirect, "error");
      seenSignal = Boolean(request.signal);
      return new Response(stream, { status: 200,
        headers: { "content-type": "application/json" } });
    },
  });

  await assert.rejects(adapter.listInventory(), { code: "inventory_response_too_large" });
  assert.equal(seenSignal, true, "inventory fetch should have a total-time abort signal");
  assert.equal(cancelled, true, "limit rejection must cancel the remaining response body");
  assert.ok(position < payload.byteLength,
    "reader must reject before consuming the giant but JSON-valid response");
});

test("issue 66: a small legitimate advisory page still passes the bounded inventory reader", async () => {
  const adapter = createOpaqueSyncAdapter({ fetchImpl: async () => new Response(JSON.stringify({
    protocolVersion: 2, view: "metadata", objects: [], nextCursor: null,
  }), { status: 200, headers: { "content-type": "application/json" } }) });
  assert.deepEqual(await adapter.listInventory(), {
    protocolVersion: 2, view: "metadata", objects: [], nextCursor: null,
  });
});

async function withManualDeadline(check) {
  const originalSet = global.setTimeout;
  const originalClear = global.clearTimeout;
  let fire;
  global.setTimeout = (callback, delay, ...args) => {
    if (delay === 20_000) {
      assert.equal(fire, undefined, "one total inventory deadline per request");
      fire = callback;
      return { manualInventoryDeadline: true };
    }
    return originalSet(callback, delay, ...args);
  };
  global.clearTimeout = (handle) => {
    if (!handle?.manualInventoryDeadline) originalClear(handle);
  };
  try {
    await check(() => {
      assert.equal(typeof fire, "function", "a real deadline must be scheduled");
      fire();
    });
  } finally {
    global.setTimeout = originalSet;
    global.clearTimeout = originalClear;
  }
}

test("issue 66 P2: a fetch implementation ignoring abort cannot hang inventory forever", async () => {
  await withManualDeadline(async (expire) => {
    let originalSignal;
    const adapter = createOpaqueSyncAdapter({ fetchImpl: (_url, request) => {
      originalSignal = request.signal;
      return new Promise(() => {}); // hostile peer never resolves response headers
    } });
    const pending = adapter.listInventory();
    assert.ok(originalSignal, "inventory fetch received a real abort controller");
    expire();
    await assert.rejects(pending, { code: "inventory_response_timeout" });
    assert.equal(originalSignal.aborted, true);
  });
});

test("issue 66 P2: a response stream ignoring abort cannot stall inventory read", async () => {
  await withManualDeadline(async (expire) => {
    let pendingPull = false;
    const stalledBody = new ReadableStream({
      pull() {
        pendingPull = true;
        return new Promise(() => {}); // never yields a next byte
      },
    });
    const adapter = createOpaqueSyncAdapter({ fetchImpl: async () =>
      new Response(stalledBody, { status: 200,
        headers: { "content-type": "application/json" } }) });
    const pending = adapter.listInventory();
    for (let i = 0; i < 6 && !pendingPull; i += 1) await Promise.resolve();
    assert.equal(pendingPull, true, "a real body reader was stalled");
    expire();
    await assert.rejects(pending, { code: "inventory_response_timeout" });
  });
});

test("issue 66 P2: a never-settling stream cancellation cannot block oversized-body rejection", async () => {
  let cancels = 0;
  const stream = new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(600 * 1024)); },
    cancel() { cancels++; return new Promise(() => {}); },
  });
  const adapter = createOpaqueSyncAdapter({ fetchImpl: async () =>
    new Response(stream, { status: 200,
      headers: { "content-type": "application/json" } }) });
  await assert.rejects(adapter.listInventory(), { code: "inventory_response_too_large" });
  assert.equal(cancels, 1, "cleanup was attempted but never awaited");
});

test("issue 66: inventory fails closed when a fetch response has no streaming body", async () => {
  const adapter = createOpaqueSyncAdapter({ fetchImpl: async () =>
    ({ ok: true, status: 200, body: null }) });
  await assert.rejects(adapter.listInventory(), /Invalid inventory response/);
});
