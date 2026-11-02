"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function indexedDb() {
  const records = new Map();
  const db = {
    objectStoreNames: { contains: () => true }, close() {},
    transaction() {
      let aborted = false;
      const tx = {
        oncomplete: null, onabort: null, onerror: null,
        abort() { aborted = true; queueMicrotask(() => tx.onabort?.()); },
        objectStore() {
          return {
            get(id) {
              const request = { result: undefined, onsuccess: null };
              queueMicrotask(() => {
                request.result = records.has(id) ? structuredClone(records.get(id)) : undefined;
                request.onsuccess?.();
                queueMicrotask(() => { if (!aborted) tx.oncomplete?.(); });
              });
              return request;
            },
            put(record, id) { records.set(id, structuredClone(record)); },
          };
        },
      };
      return tx;
    },
  };
  return { records, api: { open() {
    const request = { result: db, onsuccess: null };
    queueMicrotask(() => request.onsuccess?.());
    return request;
  } } };
}

async function fixture() {
  const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, ArrayBuffer,
    TextEncoder, TextDecoder, AbortController, atob, btoa,
    setTimeout, clearTimeout });
  const plaintext = new Uint8Array([65, 66, 67, 68]);
  let seconds = 1400;
  let reads = 0;
  let roots = 0;
  const signed = [];
  const getRoot = async (chunks) => {
    roots += 1;
    // The second invocation occurs inside reconciliation, after its signer
    // and local ciphertext have already been snapshotted.
    if (roots === 2) seconds += 50;
    return new Uint8Array(await webcrypto.subtle.digest("SHA-256", chunks[0]));
  };
  ctx.RootarkDevVaultMigration = { async readLegacyPlaintext() {
    reads += 1;
    // More than the entire signed request's 45-second lifetime elapses
    // inside the FIRST item's legacy source HTTP read, not between batch items.
    if (reads === 1) seconds += 50;
    return { name: "legacy.txt", mediaType: "text/plain",
      lastModified: "Thu, 22 Oct 2026 01:00:00 GMT", data: new Uint8Array(plaintext) };
  } };
  ctx.RootarkZk1FileContent = { async encryptFile() {
    return new Uint8Array(32).fill(7);
  } };
  ctx.RootarkZk1CiphertextRoot = { computeCiphertextRoot: getRoot };
  ctx.RootarkZk1ProtectedHttpClient = {
    async signProtectedContentOperation(input) {
      signed.push({ op: input.operation, seconds: input.nowSeconds });
      return { op: input.operation };
    },
    async postProtectedCiphertextPut({ request }) {
      assert.equal(request.op, "put");
      return { id: input.metadata.object_id, revision: 1 };
    },
    async postProtectedCiphertextRead({ request }) {
      assert.equal(request.op, "get");
      return { data: new Uint8Array(plaintext), authorizesRelease: false };
    },
  };
  ctx.RootarkZk1NormalBrowserContent = { async verifyOwnerGrant() {} };
  ctx.RootarkZk1NormalBrowserTrustFloor = { async verifyExternalAnchor() {} };
  ctx.RootarkZk1OwnerCiphertextRootCheckpoint = {};
  ctx.RootarkZk1LegacyTransitionReceipt = {};
  ctx.RootarkZk1OwnerLegacyBatchSelection = {
    async verifyOwnerSelection() { return { ownerSelectionVerified: true }; },
  };
  for (const name of ["rootark-zk1-uncertain-put-reconciliation",
    "rootark-zk1-legacy-migration-workflow", "rootark-zk1-legacy-batch-migration"]) {
    vm.runInContext(fs.readFileSync(path.resolve(__dirname,
      "../public/client/" + name + ".js"), "utf8"), ctx);
  }
  const disk = indexedDb();
  const journal = await ctx.RootarkZk1LegacyMigrationWorkflow.openMigrationJournal(disk.api);
  const input = vm.runInContext(`({
    optIn: true, legacy: { name: "legacy.txt", folderId: "" },
    metadata: { account_id: "AAAAAAAAAAAAAAAAAAAAAA", compartment_id: "AQ",
      keyring_id: "AAAAAAAAAAAAAAAAAAAAAA", object_id: "AAAAAAAAAAAAAAAAAAAAAA",
      version_id: "AAAAAAAAAAAAAAAAAAAAAA", parent_version_id: null,
      epoch: 1, kind: "file" },
    trust: { ownerPublicKey: null, pinnedOwnerKeyHash: null,
      independentOwnerSpkiSha256: new Uint8Array(32),
      pinnedCurrentHead: { revision: 1, digest: new Uint8Array(32), epoch: 1 },
      signedDeviceGrant: { account_id: "AAAAAAAAAAAAAAAAAAAAAA", compartment_id: "AQ",
        keyring_id: "AAAAAAAAAAAAAAAAAAAAAA", device_id: "trusted-device" },
      ownerHistoryCheckpoint: {}, previousOwnerHistoryProof: null,
      devicePublicKey: null, devicePrivateKey: null },
    cek: null, origin: "http://localhost/", fetchImpl: null,
    journal: null, nowSeconds: 1400,
  })`, ctx);
  input.fetchImpl = () => Promise.reject(Error("network should be stubbed"));
  input.journal = journal;
  return { ctx, input, signed, disk, get reads() { return reads; },
    get seconds() { return seconds; }, set seconds(value) { seconds = value; },
    sample: () => seconds, async batchInput(expiresAt) {
      const pin = { version: 1, storedAs: "legacy.txt.v1",
        uploadedAt: "2026-10-22T01:00:00.000Z", size: plaintext.length,
        lastModified: "Thu, 22 Oct 2026 01:00:00 GMT",
        mediaType: "text/plain",
        sha256: Buffer.from(await webcrypto.subtle.digest("SHA-256", plaintext))
          .toString("base64url") };
      const selected = vm.runInContext(`({ optIn: true, entries: [],
        migrationSecret: new Uint8Array(32), trust: null,
        origin: "http://localhost/", fetchImpl: null, journal: null,
        nowSeconds: 1400, clockSeconds: null,
        selectionApproval: { signedSelection: { issuedAt: 1390, expiresAt: 1600 },
          independentlyPinnedSelectionSha256: new Uint8Array(32) } })`, ctx);
      selected.trust = input.trust;
      selected.entries = [vm.runInContext(`({ legacy: { name: "legacy.txt", folderId: "" },
        sourcePin: null, cek: null })`, ctx)];
      selected.entries[0].sourcePin = vm.runInContext("(" + JSON.stringify(pin) + ")", ctx);
      selected.entries[0].cek = await webcrypto.subtle.importKey("raw",
        new Uint8Array(32), "AES-GCM", false, ["encrypt", "decrypt"]);
      selected.journal = journal;
      selected.clockSeconds = () => seconds;
      selected.selectionApproval.signedSelection.expiresAt = expiresAt;
      selected.fetchImpl = async () => new Response(JSON.stringify({
        folderId: "root", fileName: "legacy.txt", versions: [{
          version: pin.version, storedAs: pin.storedAs,
          uploadedAt: pin.uploadedAt, size: pin.size,
        }],
      }), { headers: { "content-type": "application/json" } });
      return selected;
    } };
}

test("delayed inner source GET and reconciliation digest sign fresh PUT and GET", async () => {
  const f = await fixture();
  f.input.clockSeconds = f.sample;
  const result = await f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration(f.input);
  assert.equal(result.verifiedLocalReadback, true);
  assert.deepEqual(f.signed, [
    { op: "put", seconds: 1450 },
    { op: "get", seconds: 1500 },
  ], "both signed operations must sample after their own awaited work");
  assert.equal(f.reads, 2);
  assert.equal((await f.input.journal.read(f.input.metadata.object_id)).phase, "readback");
});

test("direct legacy caller with no clock callback preserves existing timestamps", async () => {
  const f = await fixture();
  assert.equal((await f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration(f.input))
    .verifiedLocalReadback, true);
  assert.deepEqual(f.signed, [
    { op: "put", seconds: 1400 }, { op: "get", seconds: 1400 },
  ]);
});

test("batch passes owner-expiry-checked clock into inner PUT and reconciliation GET", async () => {
  const fresh = await fixture();
  const allowed = await fresh.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(
    await fresh.batchInput(1600));
  assert.equal(allowed.verified, 1);
  assert.deepEqual(fresh.signed, [
    { op: "put", seconds: 1450 }, { op: "get", seconds: 1500 },
  ]);

  const expired = await fixture();
  const blocked = await expired.ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(
    await expired.batchInput(1430));
  assert.equal(blocked.verified, 0);
  assert.equal(blocked.results[0].phase, "needs-manual-review");
  assert.deepEqual(expired.signed, [],
    "owner-selected window expiring during inner source read blocks PUT before signing");
});

test("invalid or regressive trusted inner clock refuses a new signed request", async () => {
  for (const bad of [undefined, NaN, -1, Infinity, 1399, 1.5,
    Number.MAX_SAFE_INTEGER + 1]) {
    const f = await fixture();
    f.input.clockSeconds = () => bad;
    await assert.rejects(f.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration(f.input),
      /ZK_LEGACY_MIGRATION_AMBIGUOUS/);
    assert.equal(f.signed.length, 0, `no PUT with ${String(bad)}`);
  }
  const rollback = await fixture();
  let samples = 0;
  rollback.input.clockSeconds = () => ++samples === 1 ? 1450 : 1449;
  await assert.rejects(
    rollback.ctx.RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration(rollback.input),
    /ZK_LEGACY_MIGRATION_AMBIGUOUS/);
  assert.deepEqual(rollback.signed, [{ op: "put", seconds: 1450 }],
    "a failed reconciliation may never issue a GET with a backward timestamp");
  assert.equal((await rollback.input.journal.read(rollback.input.metadata.object_id)).phase,
    "uncertain", "ambiguous PUT stays journaled and never retries");
});
