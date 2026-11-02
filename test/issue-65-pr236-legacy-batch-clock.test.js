"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const source = fs.readFileSync(path.resolve(__dirname,
  "../public/client/rootark-zk1-legacy-batch-migration.js"), "utf8");

async function fixture({ selectionApproval = false, transitions = false } = {}) {
  let ms = 1_400_000;
  class ClockDate extends Date { static now() { return ms; } }
  const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, ArrayBuffer,
    TextEncoder, TextDecoder, AbortController, atob, btoa,
    setTimeout, clearTimeout, Date: ClockDate });
  const starts = [], stages = [], selectionTimes = [];
  ctx.RootarkZk1LegacyMigrationWorkflow = {
    async beginLegacyMigration(input) {
      starts.push({ name: input.legacy.name, now: input.nowSeconds });
      return { phase: "awaiting-independent-owner-checkpoint", root: "readback-root" };
    },
    async stageLegacyMigrationTransition(input) {
      stages.push({ name: input.legacy.name, now: input.nowSeconds });
      return { phase: "verified-protected", state: "verified-protected" };
    },
  };
  ctx.RootarkZk1OwnerLegacyBatchSelection = {
    async verifyOwnerSelection(input) {
      selectionTimes.push(input.nowSeconds);
      return { ownerSelectionVerified: true };
    },
  };
  vm.runInContext(source, ctx);
  const input = vm.runInContext(`({
    optIn: true, migrationSecret: new Uint8Array(32),
    trust: { signedDeviceGrant: { account_id: "a", compartment_id: "b", keyring_id: "c" },
      independentOwnerSpkiSha256: new Uint8Array(32),
      pinnedCurrentHead: { revision: 1, epoch: 1, digest: new Uint8Array(32) } },
    origin: "http://localhost/", fetchImpl: null, journal: null, nowSeconds: 1400,
    entries: ["first.txt", "second.txt"].map((name) => ({
      legacy: { name, folderId: "" },
      sourcePin: { version: 1, storedAs: name + ".v1",
        uploadedAt: "2026-10-22T01:00:00.000Z", size: 1,
        lastModified: "Thu, 22 Oct 2026 01:00:00 GMT",
        sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        mediaType: "text/plain" }, cek: null,
    })),
  })`, ctx);
  for (const entry of input.entries) entry.cek = await webcrypto.subtle.importKey("raw",
    new Uint8Array(32), "AES-GCM", false, ["encrypt", "decrypt"]);
  input.fetchImpl = async (url) => {
    const name = decodeURIComponent(url.split("/versions/")[1].split("?")[0]);
    return new Response(JSON.stringify({ fileName: name, folderId: "root", versions: [{
      version: 1, storedAs: name + ".v1", uploadedAt: "2026-10-22T01:00:00.000Z",
      size: 1,
    }] }), { headers: { "content-type": "application/json" } });
  };
  if (selectionApproval) input.selectionApproval = vm.runInContext(`({
    signedSelection: { issuedAt: 1390, expiresAt: 1470 },
    independentlyPinnedSelectionSha256: new Uint8Array(32),
  })`, ctx);
  if (transitions) input.transitionApprovals = vm.runInContext(`[
    { signedRootCheckpoint: {}, signedTransitionReceipt: {} },
    { signedRootCheckpoint: {}, signedTransitionReceipt: {} },
  ]`, ctx);
  return { input, ctx, starts, stages, selectionTimes, advance(seconds) { ms += seconds * 1000; } };
}

test("batch resamples current time for each signed operation after a 50s item", async () => {
  const f = await fixture();
  const original = f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration;
  f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration = async (arg) => {
    const result = await original(arg);
    if (f.starts.length === 1) f.advance(50);
    return result;
  };
  const result = await f.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(f.input);
  assert.equal(result.verified, 2);
  assert.deepEqual(f.starts.map((s) => s.now), [1400, 1450],
    "second PUT must be signed with current, not batch-start time");
});

test("trusted injected clock independently resamples transition approval, not prior PUT", async () => {
  const f = await fixture({ transitions: true });
  let instant = 1400;
  f.input.clockSeconds = () => instant;
  const original = f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration;
  f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration = async (arg) => {
    const result = await original(arg);
    instant += 50;
    return result;
  };
  const result = await f.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(f.input);
  assert.equal(result.verifiedProtected, 2);
  assert.deepEqual(f.starts.map((s) => s.now), [1400, 1450]);
  assert.deepEqual(f.stages.map((s) => s.now), [1450, 1500],
    "receipt approval needs a new trusted clock observation");
});

test("expiring owner selection cannot authorize subsequent batch items", async () => {
  const f = await fixture({ selectionApproval: true });
  f.input.selectionApproval.signedSelection.expiresAt = 1430;
  const original = f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration;
  f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration = async (arg) => {
    const result = await original(arg);
    f.advance(50);
    return result;
  };
  const result = await f.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(f.input);
  assert.deepEqual(f.selectionTimes, [1400]);
  assert.equal(result.verified, 1);
  assert.equal(result.results[1].phase, "needs-manual-review");
  assert.deepEqual(f.starts.map((s) => s.name), ["first.txt"],
    "an expired owner selection must not authorize a new PUT");
});

test("forged or asynchronously mutated owner approval never reaches signing", async () => {
  const forged = await fixture({ selectionApproval: true });
  forged.ctx.RootarkZk1OwnerLegacyBatchSelection.verifyOwnerSelection = async () => {
    throw Error("forged owner signature");
  };
  await assert.rejects(forged.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(forged.input),
    /ZK_LEGACY_BATCH_UNVERIFIED/);
  assert.equal(forged.starts.length, 0);

  const mutated = await fixture({ selectionApproval: true });
  mutated.ctx.RootarkZk1OwnerLegacyBatchSelection.verifyOwnerSelection = async () => {
    mutated.input.selectionApproval.signedSelection.expiresAt = 1900;
    return { ownerSelectionVerified: true };
  };
  await assert.rejects(mutated.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(mutated.input),
    /ZK_LEGACY_BATCH_UNVERIFIED/);
  assert.equal(mutated.starts.length, 0);
});

test("invalid initial, forged, backward and unsafe clock samples fail closed", async () => {
  for (const invalid of [undefined, NaN, -1, 0, 1.5, Infinity,
    Number.MAX_SAFE_INTEGER + 1]) {
    const f = await fixture();
    f.input.nowSeconds = invalid;
    await assert.rejects(f.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(f.input),
      /ZK_LEGACY_BATCH_UNVERIFIED/, `bad initial time ${String(invalid)}`);
    assert.equal(f.starts.length, 0);
  }
  for (const invalid of [undefined, NaN, -1, 1.5, Infinity,
    Number.MAX_SAFE_INTEGER + 1, 1399]) {
    const f = await fixture();
    f.input.clockSeconds = () => invalid;
    const result = await f.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(f.input);
    assert.equal(result.verified, 0, `bad sampled time ${String(invalid)}`);
    assert.equal(f.starts.length, 0);
  }
});
