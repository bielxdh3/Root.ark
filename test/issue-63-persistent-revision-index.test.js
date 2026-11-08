"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const batch = require("../public/client/rootark-zk1-protected-text-batch");
const index = require("../public/client/rootark-zk1-protected-revision-index");
const content = require("../public/client/rootark-zk1-file-content");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const sha = (bytes) => b64(crypto.createHash("sha256").update(bytes).digest());
const id = () => b64(crypto.randomBytes(16));

// A disposable browser-shaped IndexedDB: transaction completion follows the
// entire request chain, including get -> conditional put inside one transaction.
function memoryDB() {
  const rows = new Map();
  let ready = false, readonlySnapshot = null, beforeWriteGet = null;
  return { rows, forceStaleReadonlySnapshot(record) {
    readonlySnapshot = record === null ? null : structuredClone(record);
  }, beforeWriteReadOnce(callback) { beforeWriteGet = callback; }, open(_name, version) {
    assert.equal(version, 1);
    const request = {};
    const db = {
      objectStoreNames: { contains: (name) => ready && name === "revisions" },
      createObjectStore(name) { assert.equal(name, "revisions"); },
      close() {},
      transaction(name, mode) {
        assert.equal(name, "revisions");
        let pending = 0, aborted = false;
        const tx = { abort() { aborted = true; queueMicrotask(() => tx.onabort?.()); },
          objectStore() {
            function action(fn) {
              const req = {};
              pending++;
              queueMicrotask(() => {
                if (aborted) return;
                try { req.result = fn(); req.onsuccess?.(); }
                catch (_) { req.onerror?.(); tx.onerror?.(); }
                pending--;
                queueMicrotask(() => { if (!aborted && pending === 0) tx.oncomplete?.(); });
              });
              return req;
            }
            return { get(key) { return action(() => {
              if (mode === "readwrite" && beforeWriteGet) {
                const callback = beforeWriteGet;
                beforeWriteGet = null;
                callback();
              }
              return mode === "readonly" && readonlySnapshot
                ? structuredClone(readonlySnapshot) : rows.get(key);
            }); },
              put(value, key) {
                assert.equal(mode, "readwrite");
                return action(() => { rows.set(key, structuredClone(value)); return key; });
              },
              delete(key) {
                assert.equal(mode, "readwrite");
                return action(() => rows.delete(key));
              } };
          } };
        return tx;
      },
    };
    queueMicrotask(() => {
      request.result = db;
      if (!ready) request.onupgradeneeded?.();
      ready = true;
      queueMicrotask(() => request.onsuccess?.());
    });
    return request;
  } };
}

async function fixture(count = 2) {
  const scope = { account_id: id(), compartment_id: id(), keyring_id: id() };
  const ownerDigest = b64(crypto.randomBytes(32));
  const grant = { ...scope, device_id: id(), current_epoch: 3,
    manifest_revision: 11, manifest_digest: ownerDigest, revoked_at_epoch: null };
  const ownerHead = { revision: 11, epoch: 3, digest: ownerDigest };
  const baseline = { head: { sequence: 19, digest: b64(crypto.randomBytes(32)) }, entries: [] };
  const objectId = id();
  const selected = [], checked = new Map(), keys = new Map();
  const versions = Array.from({ length: count }, (_, i) => [i + 1,
    i === 0 ? "Histórico original: orçamento janeiro"
      : i === 1 ? "Histórico alterado: orçamento fevereiro"
        : "Histórico revisão " + (i + 1) + ": orçamento reservado"]);
  for (const [revision, text] of versions) {
    const metadata = { ...scope, object_id: objectId, version_id: id(),
      parent_version_id: null, epoch: 3, kind: "file" };
    const rawCek = crypto.randomBytes(32);
    const ciphertext = await content.encryptFile({
      cek: await content.importFileCek(rawCek), metadata,
      name: "relatorio-confidencial.txt", mediaType: "text/plain",
      data: new TextEncoder().encode(text),
    });
    const entry = { objectId, revision, epoch: 3, ciphertextDigestBase64: sha(ciphertext) };
    baseline.entries.push(entry);
    checked.set(objectId + ":" + revision, { ...entry, verifiedCiphertext: true,
      plaintextAvailable: false, authorizesMutation: false,
      ciphertextBase64: b64(ciphertext) });
    const cekFile = "offline-" + revision + ".bin";
    keys.set(cekFile, rawCek);
    selected.push({ selected: entry, metadata, cekFile, cekSha256Pin: sha(rawCek) });
  }
  let rejected = false, verified = 0, gets = 0, requested = [];
  const signer = crypto.generateKeyPairSync("ed25519");
  const signed = () => crypto.sign(null, Buffer.from(JSON.stringify({
    head: baseline.head, entries: baseline.entries,
  })), signer.privateKey);
  let signature = signed();
  let trustedGrant = structuredClone(grant), trustedHead = structuredClone(ownerHead);
  const ownerSigned = () => crypto.sign(null, Buffer.from(JSON.stringify({
    grant: trustedGrant, ownerHead: trustedHead,
  })), signer.privateKey);
  let ownerSignature = ownerSigned();
  const client = {
    async verifyPrivateListingHead(...args) {
      requested.push(args);
      verified++;
      if (rejected) throw Error("REVOKED");
      if (!crypto.verify(null, Buffer.from(JSON.stringify({
        head: baseline.head, entries: baseline.entries,
      })), signer.publicKey, signature)) throw Error("INVALID_SIGNED_CATALOG");
      return { scope, head: baseline.head };
    },
  };
  const database = memoryDB(), metadataRaw = crypto.randomBytes(32);
  const core = () => ({ grant, ownerHead, baseline, client,
    indexedDBImpl: database, metadataRaw,
    async verifyOwnerGrant() {
      const signed = crypto.verify(null, Buffer.from(JSON.stringify({
        grant: trustedGrant, ownerHead: trustedHead,
      })), signer.publicKey, ownerSignature);
      if (!signed) throw Error("INVALID_OWNER_GRANT_SIGNATURE");
      return { verifiedCurrent: true, grant: structuredClone(trustedGrant),
        ownerHead: structuredClone(trustedHead) };
    },
    assertLive() { if (rejected) throw Error("LOGOUT"); } });
  const scan = async (rows = selected, extras = {}) => {
    let final = null, lastCek = null;
    const result = await batch.search({ ...core(), query: "orçamento", items: rows,
      async getChecked(oid, rev) { gets++; return checked.get(oid + ":" + rev); },
      async readCek(name) {
        if (lastCek) assert.ok(lastCek.every((value) => value === 0),
          "previous CEK must be wiped before the next read");
        lastCek = new Uint8Array(keys.get(name));
        return lastCek;
      },
      onVerifiedBatch: async (entries) => {
        assert.ok(lastCek?.every((value) => value === 0),
          "the last CEK is wiped before the persist callback starts");
        final = entries;
        return index.append({ ...core(), entries });
      }, ...extras });
    return { final, result };
  };
  return { scan, core, selected, checked, database, metadataRaw,
    get gets() { return gets; }, get verified() { return verified; },
    get requested() { return requested; },
    revoke() { rejected = true; },
    advanceCatalog({ removeRevision, changeRevisionDigest } = {}) {
      baseline.head = { sequence: baseline.head.sequence + 1,
        digest: b64(crypto.randomBytes(32)) };
      if (removeRevision) baseline.entries = baseline.entries.filter((entry) =>
        entry.revision !== removeRevision);
      if (changeRevisionDigest) baseline.entries = baseline.entries.map((entry) =>
        entry.revision === changeRevisionDigest ? {
          ...entry, ciphertextDigestBase64: b64(crypto.randomBytes(32)),
        } : entry);
      signature = signed();
    },
    updateOwnerGrant(nextGrant, nextHead = ownerHead) {
      trustedGrant = structuredClone(nextGrant);
      trustedHead = structuredClone(nextHead);
      ownerSignature = ownerSigned();
    },
    invalidateSignature() { baseline.head.sequence++; }, objectId };
}

test("unrelated valid signed catalog CAS advance preserves previously selected historical revisions", async () => {
  const f = await fixture(3);
  await f.scan([f.selected[0]]);
  await f.scan([f.selected[1]]);
  f.advanceCatalog();
  const migrated = await f.scan([f.selected[2]]);
  assert.equal(migrated.result.indexedDiscardedCount, 0);
  const now = await index.search({ ...f.core(), query: "histórico" });
  assert.equal(now.indexedCount, 3, "unchanged signed old row digests survive benign CAS");
  assert.deepEqual(now.entries.map((row) => row.revision), [1, 2, 3]);
});

test("a removed or digest-diverged signed revision is explicitly excluded on CAS advance", async () => {
  for (const change of [{ removeRevision: 1 }, { changeRevisionDigest: 1 }]) {
    const f = await fixture(3);
    await f.scan([f.selected[0]]);
    f.advanceCatalog(change);
    const migrated = await f.scan([f.selected[2]]);
    assert.equal(migrated.result.indexedDiscardedCount, 1,
      "removed or digest-diverged versions must be reported explicitly");
    const now = await index.search({ ...f.core(), query: "histórico" });
    assert.equal(now.indexedCount, 1);
    assert.equal(now.entries[0].revision, 3);
    const persisted = await f.scan([f.selected[1]]);
    assert.equal(persisted.result.totalSearched, 1);
    assert.equal(persisted.final.length, 1);
    assert.equal(persisted.result.indexedDiscardedCount, 0);
  }
});

test("new owner epoch/grant cannot inherit previous decrypted texts", async () => {
  const f = await fixture(2);
  await f.scan([f.selected[0]]);
  const old = f.core();
  f.advanceCatalog();
  const grant = { ...old.grant, current_epoch: 4 };
  const ownerHead = { ...old.ownerHead, epoch: 4 };
  f.updateOwnerGrant(grant, ownerHead);
  await assert.rejects(index.search({ ...old, grant, ownerHead, query: "histórico" }),
    /ZK_REVISION_INDEX_DENIED/);
  const replaced = await index.append({ ...old, grant, ownerHead, entries: [{
    objectId: f.selected[1].selected.objectId,
    revision: 2, epoch: 3,
    ciphertextDigestBase64: f.selected[1].selected.ciphertextDigestBase64,
    name: "safe", mediaType: "text/plain", text: "fresh",
  }] });
  assert.equal(replaced.indexedCount, 1);
  assert.equal(replaced.replacedIncompatibleIndex, true);
  const now = await index.search({ ...old, grant, ownerHead, query: "original" });
  assert.equal(now.totalMatches, 0, "previous owner epoch text must not be inherited");
  await assert.rejects(index.append({ ...old, entries: [{
    objectId: f.selected[0].selected.objectId, revision: 1, epoch: 3,
    ciphertextDigestBase64: f.selected[0].selected.ciphertextDigestBase64,
    name: "old", mediaType: "text/plain", text: "historical proof",
  }], verifyOwnerGrant: async () => ({
    verifiedCurrent: true, grant: old.grant, ownerHead: old.ownerHead,
  }) }), /ZK_REVISION_INDEX_DENIED/,
  "even a previously signed owner/grant must not roll back a newer local epoch");
});

test("changed signed grant fields at unchanged owner head never inherit old index content", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const changedGrant = { ...f.core().grant, permission: "restricted-read" };
  f.updateOwnerGrant(changedGrant);
  const fresh = f.selected[1];
  const result = await index.append({ ...f.core(), grant: changedGrant, entries: [{
    objectId: fresh.selected.objectId, revision: fresh.selected.revision,
    epoch: fresh.selected.epoch, ciphertextDigestBase64: fresh.selected.ciphertextDigestBase64,
    name: "new grant", mediaType: "text/plain", text: "only-new-authorization",
  }] });
  assert.equal(result.replacedIncompatibleIndex, true);
  assert.equal(result.indexedCount, 1);
  const indexed = await index.search({ ...f.core(), grant: changedGrant,
    query: "histórico" });
  assert.equal(indexed.totalMatches, 0);
});

test("all 128 historical matches are reachable at offsets 0,50,100 after fresh signed CAS", async () => {
  const f = await fixture(128);
  await f.scan(f.selected.slice(0, 64));
  await f.scan(f.selected.slice(64));
  const first = await index.search({ ...f.core(), query: "histórico" });
  assert.equal(first.offset, 0);
  assert.equal(first.hasNext, true);
  assert.equal(first.hasPrevious, false);
  const second = await first.readPage(50);
  const third = await first.readPage(100);
  assert.deepEqual([first.entries.length, second.entries.length, third.entries.length], [50, 50, 28]);
  assert.deepEqual([first.entries[0].revision, second.entries[0].revision,
    third.entries[0].revision, third.entries.at(-1).revision], [1, 51, 101, 128]);
  assert.equal(third.hasNext, false);
  assert.equal(third.hasPrevious, true);
  await assert.rejects(first.readPage(125), /ZK_REVISION_INDEX_DENIED/);
  await assert.rejects(first.readPage(150), /ZK_REVISION_INDEX_DENIED/);
  f.advanceCatalog();
  await assert.rejects(first.readPage(50), /ZK_REVISION_INDEX_DENIED/,
    "old pages are invalid after a freshly signed CAS change");
});

test("old pending page denied on session revocation and no unverified page emitted", async () => {
  const f = await fixture(51);
  await f.scan(f.selected);
  const first = await index.search({ ...f.core(), query: "histórico" });
  const verifiedBefore = f.verified;
  await first.readPage(50);
  assert.ok(f.verified > verifiedBefore);
  f.revoke();
  await assert.rejects(first.readPage(50), /ZK_REVISION_INDEX_DENIED/);
});

test("owner-signed grant revocation blocks old cached page although catalog CAS remains identical", async () => {
  const f = await fixture(51);
  await f.scan(f.selected);
  const page = await index.search({ ...f.core(), query: "histórico" });
  const originalHead = f.core().baseline.head.digest;
  f.updateOwnerGrant({ ...f.core().grant, revoked_at_epoch: 3 });
  assert.equal(f.core().baseline.head.digest, originalHead,
    "catalog CAS deliberately unchanged while independent owner revokes grant");
  await assert.rejects(page.readPage(50), /ZK_REVISION_INDEX_DENIED/);
});

test("two historical revisions persist after completed signed batch; later searches reverify CAS without CEKs", async () => {
  const f = await fixture();
  const first = await f.scan([f.selected[0]]);
  assert.equal(first.result.totalSearched, 1);
  assert.equal(first.final.length, 1);
  assert.equal(first.final[0].revision, 1);
  const second = await f.scan([f.selected[1]]);
  assert.equal(second.final[0].revision, 2);
  const saved = JSON.stringify([...f.database.rows.values()]);
  assert.doesNotMatch(saved, /Histórico|orçamento|relatorio-confidencial|janeiro|fevereiro/i);
  for (const selected of f.selected) {
    assert.ok(!saved.includes(selected.cekSha256Pin), "offline CEK fingerprint must not be stored");
    assert.ok(!saved.includes(selected.cekFile), "offline CEK filename must not be stored");
    const ciphertext = f.checked.get(selected.selected.objectId + ":"
      + selected.selected.revision).ciphertextBase64;
    assert.ok(!saved.includes(ciphertext), "selected ciphertext must not be stored as plaintext");
  }
  const previousGets = f.gets, previousChecks = f.verified;
  const result = await index.search({ ...f.core(), query: "histórico orçamento", matchMode: "all-terms" });
  assert.equal(result.indexedCount, 2);
  assert.equal(result.totalMatches, 2);
  assert.deepEqual(result.entries.map((row) => row.revision), [1, 2]);
  assert.equal(result.coverage, "owner-selected-revisions-only");
  assert.equal(result.plaintextSentToServer, false);
  assert.equal(result.authorizesMutation, false);
  assert.equal(f.gets, previousGets, "cached search makes no ciphertext GET");
  assert.ok(f.verified > previousChecks, "cached plaintext requires fresh signed CAS");
  assert.ok(f.requested.every((args) => args.length === 1
    && args[0] === f.core().baseline), "head verifier must receive only prior signed baseline");
});

test("concurrent batches cannot overwrite a newer transaction from the same scope", async () => {
  const f = await fixture(3);
  await f.scan([f.selected[0]]);
  const before = structuredClone([...f.database.rows.values()][0]);
  f.database.forceStaleReadonlySnapshot(before);
  const concurrent = await Promise.allSettled([
    f.scan([f.selected[1]]), f.scan([f.selected[2]]),
  ]);
  assert.equal(concurrent.filter((outcome) => outcome.status === "fulfilled").length, 1);
  assert.equal(concurrent.filter((outcome) => outcome.status === "rejected").length, 1);
  assert.match(String(concurrent.find((outcome) => outcome.status === "rejected").reason),
    /ZK_BATCH_TEXT_SEARCH_DENIED/);
  f.database.forceStaleReadonlySnapshot(null);
  const actual = await index.search({ ...f.core(), query: "histórico" });
  assert.equal(actual.indexedCount, 2, "old rows stay, exactly one competing batch wins");
  assert.equal(actual.entries[0].revision, 1);
  assert.ok([2, 3].includes(actual.entries[1].revision));
});

test("stale session inside verified callback rejects without persisting or displaying matches", async () => {
  const f = await fixture();
  await assert.rejects(f.scan(undefined, { onVerifiedBatch: async (entries) => {
    await Promise.resolve();
    f.revoke();
    return index.append({ ...f.core(), entries });
  } }), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(f.database.rows.size, 0, "logout before index authorization cannot persist");
});

test("logout after encryption during IndexedDB conditional-put read aborts transaction", async () => {
  const f = await fixture();
  f.database.beforeWriteReadOnce(() => f.revoke());
  await assert.rejects(f.scan([f.selected[0]]), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(f.database.rows.size, 0, "session invalidation aborts the queued write");
});

test("same explicit revision may be reverified without duplicate cache entries", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  await f.scan([f.selected[0]]);
  const indexed = await index.search({ ...f.core(), query: "janeiro" });
  assert.equal(indexed.indexedCount, 1);
  assert.equal(indexed.totalMatches, 1);
});

test("two 64-revision windows accumulate up to 128, report partial coverage, and reject overflow", async () => {
  const f = await fixture(129);
  await f.scan(f.selected.slice(0, 64));
  const second = await f.scan(f.selected.slice(64, 128));
  assert.equal(second.final.length, 64);
  const matches = await index.search({ ...f.core(), query: "histórico" });
  assert.equal(matches.indexedCount, 128);
  assert.equal(matches.totalMatches, 128);
  assert.equal(matches.entries.length, 50);
  assert.equal(matches.hasMore, true, "limited display must disclose unmatched result pages");
  assert.equal(matches.coverage, "owner-selected-revisions-only");
  await assert.rejects(f.scan(f.selected.slice(128, 129)),
    /ZK_BATCH_TEXT_SEARCH_DENIED/, "a third batch must not overwrite prior validated rows");
  const after = await index.search({ ...f.core(), query: "revisão 128" });
  assert.equal(after.indexedCount, 128);
  assert.equal(after.totalMatches, 1);
  assert.equal(after.entries[0].revision, 128);
});

test("cancellation after the eighth checked GET never persists earlier texts", async () => {
  const f = await fixture(9);
  let cancelled = false;
  await assert.rejects(f.scan(f.selected, {
    onProgress: ({ completed }) => { if (completed === 8) cancelled = true; },
    isCancelled: () => cancelled,
  }), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(f.gets, 8);
  assert.equal(f.database.rows.size, 0);
});

test("tampered later GET never appends a partially verified slice", async () => {
  const f = await fixture();
  const next = f.selected[1].selected;
  f.checked.set(next.objectId + ":" + next.revision, {
    ...f.checked.get(next.objectId + ":" + next.revision),
    ciphertextBase64: b64(crypto.randomBytes(64)),
  });
  await assert.rejects(f.scan(), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(f.database.rows.size, 0);
});

test("revoked session, changed head, wrong key and tampered sealed index fail closed", async () => {
  const f = await fixture();
  await f.scan();
  await assert.rejects(index.search({ ...f.core(), metadataRaw: crypto.randomBytes(32),
    query: "original" }), /ZK_REVISION_INDEX_DENIED/);
  await assert.rejects(index.search({ ...f.core(), ownerHead: {
    ...f.core().ownerHead, revision: 12 }, query: "original" }),
  /ZK_REVISION_INDEX_DENIED/);
  await assert.rejects(index.search({ ...f.core(), ownerHead: {
    ...f.core().ownerHead, epoch: 2 }, query: "original" }),
  /ZK_REVISION_INDEX_DENIED/, "owner epoch rollback must deny cached content");
  await assert.rejects(index.search({ ...f.core(), grant: {
    ...f.core().grant, revoked_at_epoch: 3 }, query: "original" }),
  /ZK_REVISION_INDEX_DENIED/, "revoked grant must deny before revealing cache");
  await assert.rejects(index.search({ ...f.core(), baseline: {
    ...f.core().baseline, head: { ...f.core().baseline.head,
      digest: b64(crypto.randomBytes(32)) } }, query: "original" }),
  /ZK_REVISION_INDEX_DENIED/, "stale catalog CAS must deny cached results");
  const key = [...f.database.rows.keys()][0];
  f.database.rows.get(key).ciphertext = b64(crypto.randomBytes(80));
  await assert.rejects(index.search({ ...f.core(), query: "original" }),
    /ZK_REVISION_INDEX_DENIED/);
  f.revoke();
  await assert.rejects(index.search({ ...f.core(), query: "original" }),
    /ZK_REVISION_INDEX_DENIED/);
});

test("index refuses unsupported or oversized revisions before touching storage", async () => {
  const f = await fixture();
  const source = { objectId: f.objectId, revision: 1, epoch: 3,
    ciphertextDigestBase64: f.core().baseline.entries[0].ciphertextDigestBase64,
    name: "name", mediaType: "text/plain", text: "test" };
  await assert.rejects(index.append({ ...f.core(), entries: Array(129).fill(source) }),
    /ZK_REVISION_INDEX_DENIED/);
  assert.equal(f.database.rows.size, 0);
  await assert.rejects(index.append({ ...f.core(), entries: [{ ...source,
    text: "X".repeat(65537) }] }), /ZK_REVISION_INDEX_DENIED/);
  assert.equal(f.database.rows.size, 0);
});

test("4 MiB aggregate serialized plaintext cap rejects a 64-revision oversized slice", async () => {
  const f = await fixture(64);
  const entries = f.core().baseline.entries.map((entry) => ({
    objectId: entry.objectId, revision: entry.revision, epoch: entry.epoch,
    ciphertextDigestBase64: entry.ciphertextDigestBase64,
    name: "owned.txt", mediaType: "text/plain", text: "X".repeat(65500),
  }));
  await assert.rejects(index.append({ ...f.core(), entries }),
    /ZK_REVISION_INDEX_DENIED/);
  assert.equal(f.database.rows.size, 0);
});
