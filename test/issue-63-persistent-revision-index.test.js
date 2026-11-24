"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const batch = require("../public/client/rootark-zk1-protected-text-batch");
const index = require("../public/client/rootark-zk1-protected-revision-index");
const content = require("../public/client/rootark-zk1-file-content");
const productionFloor = require("../public/client/rootark-zk1-normal-browser-trust-floor");
const ownerCheckpoints = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const recoveryV2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const recoveryV2Fixtures = require("./support/issue-65-recovery-v2-fixtures");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const sha = (bytes) => b64(crypto.createHash("sha256").update(bytes).digest());
const id = () => b64(crypto.randomBytes(16));

// A disposable browser-shaped IndexedDB: transaction completion follows the
// entire request chain, including get -> conditional put inside one transaction.
function memoryDB() {
  const rows = new Map();
  let ready = false, readonlySnapshot = null, beforeWriteGet = null;
  let afterQueuedPut = null, beforeReadonlyGet = null;
  return { rows, forceStaleReadonlySnapshot(record) {
    readonlySnapshot = record === null ? null : structuredClone(record);
  }, beforeWriteReadOnce(callback) { beforeWriteGet = callback; },
    beforeReadonlyGetOnce(callback) { beforeReadonlyGet = callback; },
    afterQueuedPutOnce(callback) { afterQueuedPut = callback; }, open(_name, version) {
    assert.equal(version, 1);
    const request = {};
    const db = {
      objectStoreNames: { contains: (name) => ready && name === "revisions" },
      createObjectStore(name) { assert.equal(name, "revisions"); },
      close() {},
      transaction(name, mode) {
        assert.equal(name, "revisions");
        let pending = 0, aborted = false, lastWrite = null;
        const tx = { abort() {
          aborted = true;
          // The disposable fixture models IndexedDB's rollback on abort,
          // even if the put request was acknowledged inside this transaction.
          if (lastWrite && rows.get(lastWrite.key) === lastWrite.inserted) {
            if (lastWrite.previous === undefined) rows.delete(lastWrite.key);
            else rows.set(lastWrite.key, lastWrite.previous);
          }
          queueMicrotask(() => tx.onabort?.());
        },
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
              if (mode === "readonly" && beforeReadonlyGet) {
                const callback = beforeReadonlyGet;
                beforeReadonlyGet = null;
                callback();
              }
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
                // Logout in a microtask AFTER put is queued but BEFORE its
                // IndexedDB completion event reproduces the real Edge race.
                if (afterQueuedPut) {
                  const callback = afterQueuedPut;
                  afterQueuedPut = null;
                  queueMicrotask(callback);
                }
                return action(() => {
                  const inserted = structuredClone(value);
                  lastWrite = { key, previous: rows.get(key), inserted };
                  rows.set(key, inserted);
                  return key;
                });
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

async function fixture(count = 2, suppliedScope = null, suppliedEpoch = 3) {
  const scope = suppliedScope || { account_id: id(), compartment_id: id(), keyring_id: id() };
  const ownerDigest = b64(crypto.randomBytes(32));
  const grant = { ...scope, device_id: id(), current_epoch: suppliedEpoch,
    manifest_revision: 11, manifest_digest: ownerDigest, revoked_at_epoch: null };
  const ownerHead = { revision: 11, epoch: suppliedEpoch, digest: ownerDigest };
  const baseline = { head: { sequence: 19, digest: b64(crypto.randomBytes(32)) }, entries: [] };
  const objectId = id();
  const selected = [], checked = new Map(), keys = new Map();
  const versions = Array.from({ length: count }, (_, i) => [i + 1,
    i === 0 ? "Histórico original: orçamento janeiro"
      : i === 1 ? "Histórico alterado: orçamento fevereiro"
        : "Histórico revisão " + (i + 1) + ": orçamento reservado"]);
  for (const [revision, text] of versions) {
    const metadata = { ...scope, object_id: objectId, version_id: id(),
      parent_version_id: null, epoch: suppliedEpoch, kind: "file" };
    const rawCek = crypto.randomBytes(32);
    const ciphertext = await content.encryptFile({
      cek: await content.importFileCek(rawCek), metadata,
      name: "relatorio-confidencial.txt", mediaType: "text/plain",
      data: new TextEncoder().encode(text),
    });
    const entry = { objectId, revision, epoch: suppliedEpoch, ciphertextDigestBase64: sha(ciphertext) };
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

test("P2 RED: index reader cannot swap out the revoked live-session guard during signed await", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const positive = await index.search({ ...f.core(), query: "histórico" });
  assert.equal(positive.totalMatches, 1,
    "the genuine AES-GCM sealed revision index must release one valid match");

  const input = { ...f.core(), query: "histórico" };
  let loggedIn = true, verifications = 0;
  input.assertLive = () => { if (!loggedIn) throw Error("LOGOUT"); };
  const signedGrant = input.verifyOwnerGrant;
  const forgedGuard = () => true;
  input.verifyOwnerGrant = async () => {
    const verified = await signedGrant();
    if (++verifications === 1) {
      loggedIn = false;
      input.assertLive = forgedGuard;
    }
    return verified;
  };
  await assert.rejects(index.search(input), /ZK_REVISION_INDEX_DENIED/,
    "logout during an authentic signed owner-grant read must prohibit plaintext excerpts");
  assert.equal(verifications, 1, "the real owner signature verifier ran before logout");
  assert.equal(input.assertLive, forgedGuard, "the callback changed during the awaited verification");
});

test("P2 RED: index append cannot persist signed plaintext after an awaited logout guard swap", async () => {
  const f = await fixture();
  const selected = f.selected[0].selected;
  const input = { ...f.core(), entries: [{ ...selected, name: "local-private.txt",
    mediaType: "text/plain", text: "confidential index content" }] };
  let loggedIn = true, verifications = 0;
  input.assertLive = () => { if (!loggedIn) throw Error("LOGOUT"); };
  const signedGrant = input.verifyOwnerGrant;
  const forgedGuard = () => true;
  input.verifyOwnerGrant = async () => {
    const verified = await signedGrant();
    if (++verifications === 1) {
      loggedIn = false;
      input.assertLive = forgedGuard;
    }
    return verified;
  };
  await assert.rejects(index.append(input), /ZK_REVISION_INDEX_DENIED/,
    "logout during genuine owner approval must prevent a durable encrypted plaintext write");
  assert.equal(verifications, 1, "a signed owner-grant check was genuinely completed");
  assert.equal(input.assertLive, forgedGuard);
  assert.equal(f.database.rows.size, 0, "denied append cannot write a local index");
});

test("P2 RED: index search must reuse genuine signed owner reader after async grant revocation", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico" };
  const signedReader = input.verifyOwnerGrant;
  let authenticReads = 0;
  input.verifyOwnerGrant = async () => {
    const signed = await signedReader();
    if (++authenticReads === 1) {
      // The owner signs revocation while the initial genuine reader is awaited.
      f.updateOwnerGrant({ ...f.core().grant, revoked_at_epoch: 3 });
      // A caller-controlled callback slot now impersonates the stale grant.
      input.verifyOwnerGrant = async () => ({ verifiedCurrent: true,
        grant: structuredClone(input.grant), ownerHead: structuredClone(input.ownerHead) });
    }
    return signed;
  };
  await assert.rejects(index.search(input), /ZK_REVISION_INDEX_DENIED/,
    "a replaced callback cannot release cached plaintext after signed revocation");
  assert.equal(authenticReads, 2,
    "the same originally captured signed reader must recheck the revoked grant");
});

test("P2 RED: index append must not persist after a signed owner reader swap", async () => {
  const f = await fixture();
  const selected = f.selected[0].selected;
  const input = { ...f.core(), entries: [{ ...selected, name: "private.txt",
    mediaType: "text/plain", text: "authenticated confidential content" }] };
  const signedReader = input.verifyOwnerGrant;
  let authenticReads = 0;
  input.verifyOwnerGrant = async () => {
    const signed = await signedReader();
    if (++authenticReads === 1) {
      f.updateOwnerGrant({ ...f.core().grant, revoked_at_epoch: 3 });
      input.verifyOwnerGrant = async () => ({ verifiedCurrent: true,
        grant: structuredClone(input.grant), ownerHead: structuredClone(input.ownerHead) });
    }
    return signed;
  };
  await assert.rejects(index.append(input), /ZK_REVISION_INDEX_DENIED/,
    "a replaced callback cannot bless an encrypted index after signed revocation");
  assert.equal(authenticReads, 2,
    "append must recheck the revocation with the original signed reader");
  assert.equal(f.database.rows.size, 0, "revoked append cannot commit plaintext-derived bytes");
});

test("P2 RED: index search must reuse genuine signed catalog reader after async revocation", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico", assertLive() { return true; } };
  const signedReader = input.client.verifyPrivateListingHead.bind(input.client);
  let authenticAttempts = 0;
  input.client = { async verifyPrivateListingHead(...args) {
    authenticAttempts++;
    const signed = await signedReader(...args);
    if (authenticAttempts === 1) {
      // The signed listing is revoked after the initial genuine verification.
      f.revoke();
      input.client.verifyPrivateListingHead = async () => signed;
    }
    return signed;
  } };
  await assert.rejects(index.search(input), /ZK_REVISION_INDEX_DENIED/,
    "a swapped stale catalog reader must never release private index excerpts");
  assert.equal(authenticAttempts, 2,
    "the original signed verifier must attempt the final revocation check");
});

// Revoke with the fixture's genuine Ed25519 owner key, without changing the
// independently signed listing CAS or the live local-session callback.
function revokeSignedOwner(f) {
  const grant = f.core().grant;
  f.updateOwnerGrant({ ...grant, revoked_at_epoch: grant.current_epoch });
}

test("P2 RED: search FIRST page leaks when owner grant revokes during LAST genuine catalog await", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico" };
  const realCatalog = input.client.verifyPrivateListingHead.bind(input.client);
  let catalogReads = 0;
  input.client = { async verifyPrivateListingHead(...args) {
    const signed = await realCatalog(...args);
    if (++catalogReads === 2) revokeSignedOwner(f);
    return signed;
  } };
  await assert.rejects(index.search(input), /ZK_REVISION_INDEX_DENIED/,
    "grant revoked after final genuine owner check cannot release private excerpts");
  assert.equal(catalogReads, 2, "both genuine catalog verifications must run");
  assert.equal((await f.core().verifyOwnerGrant()).grant.revoked_at_epoch, 3,
    "revocation is genuinely owner-signed, not a forged verifier result");
});

test("P2 RED: readPage leaks when owner grant revokes during LAST genuine catalog await", async () => {
  const f = await fixture(51);
  await f.scan(f.selected);
  const input = { ...f.core(), query: "histórico" };
  const realCatalog = input.client.verifyPrivateListingHead.bind(input.client);
  let catalogReads = 0, navigating = false, pageCatalogReads = 0;
  input.client = { async verifyPrivateListingHead(...args) {
    const signed = await realCatalog(...args);
    catalogReads++;
    if (navigating && ++pageCatalogReads === 1) revokeSignedOwner(f);
    return signed;
  } };
  const first = await index.search(input);
  assert.equal(first.entries.length, 50);
  navigating = true;
  await assert.rejects(first.readPage(50), /ZK_REVISION_INDEX_DENIED/,
    "revocation after readPage's signed owner check cannot release page 2 excerpts");
  assert.equal(pageCatalogReads, 1, "the genuine catalog must be read during page navigation");
  assert.ok(catalogReads >= 3, "initial search and next page must both verify signed catalog");
  assert.equal((await f.core().verifyOwnerGrant()).grant.revoked_at_epoch, 3);
});

test("P2 RED: append persists after owner grant revokes during LAST genuine catalog await", async () => {
  const f = await fixture();
  const input = { ...f.core(), entries: [{ ...f.selected[0].selected,
    name: "revoke-before-commit.txt", mediaType: "text/plain",
    text: "OWNER_REVOKED_BEFORE_COMMIT" }] };
  const realCatalog = input.client.verifyPrivateListingHead.bind(input.client);
  let catalogReads = 0;
  input.client = { async verifyPrivateListingHead(...args) {
    const signed = await realCatalog(...args);
    if (++catalogReads === 2) revokeSignedOwner(f);
    return signed;
  } };
  await assert.rejects(index.append(input), /ZK_REVISION_INDEX_DENIED/,
    "post-check owner revocation must block encrypted local index persistence");
  assert.equal(catalogReads, 2);
  assert.equal((await f.core().verifyOwnerGrant()).grant.revoked_at_epoch, 3);
  assert.equal(f.database.rows.size, 0, "no encrypted index may commit after revocation");
});

test("P2 RED: search FIRST page leaks after signed grant revokes in final queued IDB read", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico" };
  const realCatalog = input.client.verifyPrivateListingHead.bind(input.client);
  let catalogReads = 0, reachedFinalIdb = false;
  input.client = { async verifyPrivateListingHead(...args) {
    const signed = await realCatalog(...args);
    if (++catalogReads === 2) f.database.beforeReadonlyGetOnce(() => {
      reachedFinalIdb = true;
      revokeSignedOwner(f);
    });
    return signed;
  } };
  await assert.rejects(index.search(input), /ZK_REVISION_INDEX_DENIED/,
    "IDB await can outlive the final owner check; no post-revocation plaintext release");
  assert.equal(reachedFinalIdb, true, "revocation occurred at final readonly IDB request");
  assert.equal(catalogReads, 3, "the post-IDB independent catalog recheck must execute before denial");
  assert.equal((await f.core().verifyOwnerGrant()).grant.revoked_at_epoch, 3);
});

test("P2 RED: readPage leaks after signed grant revokes in queued IDB read", async () => {
  const f = await fixture(51);
  await f.scan(f.selected);
  const first = await index.search({ ...f.core(), query: "histórico" });
  assert.equal(first.entries.length, 50);
  let reachedIdb = false;
  f.database.beforeReadonlyGetOnce(() => {
    reachedIdb = true;
    revokeSignedOwner(f);
  });
  await assert.rejects(first.readPage(50), /ZK_REVISION_INDEX_DENIED/,
    "readPage cannot release cached excerpts after revocation in final IDB await");
  assert.equal(reachedIdb, true, "revocation happened at real queued readonly get");
  assert.equal((await f.core().verifyOwnerGrant()).grant.revoked_at_epoch, 3);
});

test("P2 RED: append commits after signed grant revokes during queued IDB write admission", async () => {
  const f = await fixture();
  const input = { ...f.core(), entries: [{ ...f.selected[0].selected,
    name: "revoke-in-idb.txt", mediaType: "text/plain",
    text: "OWNER_REVOKED_DURING_IDB_WRITE" }] };
  let reachedWrite = false;
  f.database.beforeWriteReadOnce(() => {
    reachedWrite = true;
    revokeSignedOwner(f);
  });
  await assert.rejects(index.append(input), /ZK_REVISION_INDEX_DENIED/,
    "last owner check before async IDB get cannot report successful post-revocation append");
  assert.equal(reachedWrite, true, "revocation occurred during actual IDB readwrite get");
  assert.equal((await f.core().verifyOwnerGrant()).grant.revoked_at_epoch, 3);
  // A remote owner-signed revocation cannot atomically roll back an IndexedDB
  // transaction already committed in another asynchronous authority domain.
  // The corrected contract can deny success and retain only AEAD ciphertext;
  // it must NOT claim zero durable bytes after a post-admission revoke.
  assert.doesNotMatch(JSON.stringify([...f.database.rows.values()]),
    /OWNER_REVOKED_DURING_IDB_WRITE|revoke-in-idb\.txt/,
    "any post-revocation IndexedDB residue must remain encrypted");
});

// Models the essential browser Web Locks contract: an exclusive lock is held
// until its async callback settles; a second same-name request must queue.
// Expose that queue edge and permit explicit test-only cancellation so a RED
// test can prove a cycle without sleeping or leaving a pending process alive.
function observableExclusiveWebLocks() {
  const held = new Set(), queued = [];
  let queuedCount = 0;
  let reportQueue;
  const firstQueued = new Promise((resolve) => { reportQueue = resolve; });
  const advance = (name) => {
    held.delete(name);
    const at = queued.findIndex((entry) => entry.name === name);
    if (at !== -1) start(queued.splice(at, 1)[0]);
  };
  const start = (entry) => {
    held.add(entry.name);
    Promise.resolve().then(() => entry.work({ name: entry.name, mode: "exclusive" }))
      .then((value) => { advance(entry.name); entry.resolve(value); },
        (error) => { advance(entry.name); entry.reject(error); });
  };
  return {
    locks: { request(name, options, work) {
      assert.equal(options?.mode, "exclusive");
      assert.equal(typeof work, "function");
      return new Promise((resolve, reject) => {
        const entry = { name, work, resolve, reject };
        if (held.has(name)) { queuedCount++; queued.push(entry); reportQueue(name); }
        else start(entry);
      });
    } },
    get queuedCount() { return queuedCount; },
    firstQueued,
    cancelQueued(name) {
      const at = queued.findIndex((entry) => entry.name === name);
      assert.notEqual(at, -1, "the same-key waiter must actually be queued");
      queued.splice(at, 1)[0].reject(Error("TEST_CANCEL_REENTRANT_LOCK_WAIT"));
    },
  };
}

test("P2 RED: browser-like exclusive Web Lock cannot wait for signed verifier that awaits same-scope clear", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico" };
  const genuineCatalogReader = input.client.verifyPrivateListingHead.bind(input.client);
  const manager = observableExclusiveWebLocks();
  const sharedStore = new Map();
  const originalGlobals = new Map(["document", "navigator", "localStorage"].map(
    (name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  let catalogReads = 0, settledNestedClear;
  const nestedClearSettled = new Promise((resolve) => { settledNestedClear = resolve; });
  const key = JSON.stringify([input.grant.account_id, input.grant.compartment_id,
    input.grant.keyring_id]);
  const lockName = "rootark-zk1-protected-revision-index-v1/" + key;
  const clearNonceKey = "rootark-zk1-protected-revision-index-v1/clear/" + key;
  input.client = { async verifyPrivateListingHead(...args) {
    const authentic = await genuineCatalogReader(...args);
    if (++catalogReads === 3) {
      // This is a possible FUTURE revocation callback, not a behavior of the
      // current production reader: the actual signed reader ran successfully,
      // then an owner-signed revocation provokes awaited local invalidation.
      revokeSignedOwner(f);
      try {
        await index.clear({ grant: input.grant, indexedDBImpl: input.indexedDBImpl,
          assertLive: input.assertLive });
        settledNestedClear("cleared");
      } catch (error) { settledNestedClear("clear-rejected"); throw error; }
    }
    return authentic;
  } };
  try {
    for (const [name, value] of [
      ["document", {}], ["navigator", { locks: manager.locks }],
      ["localStorage", { getItem: (key) => sharedStore.get(key) ?? null,
        setItem: (key, value) => { sharedStore.set(key, String(value)); } }],
    ]) Object.defineProperty(globalThis, name,
      { configurable: true, writable: true, value });
    const pending = index.search(input);
    // A queued same-name request while the original verifier waits for it is
    // a deterministically observable dependency cycle. No timeout is needed.
    const observed = await Promise.race([
      manager.firstQueued.then((name) => ({ state: "blocked", name })),
      nestedClearSettled.then((state) => ({ state })),
      pending.then(() => ({ state: "search-resolved" }),
        () => ({ state: "search-rejected-early" })),
    ]);
    if (observed.state === "blocked") {
      manager.cancelQueued(observed.name); // Always break the RED cycle first.
      assert.equal(observed.name, lockName, "the pending clear requests the HELD scope lock");
    }
    await assert.rejects(pending, /ZK_REVISION_INDEX_DENIED/,
      "a revoked owner must never receive the private index search page");
    assert.equal(catalogReads, 3,
      "the actual third signed catalog verifier must be reached");
    assert.equal((await f.core().verifyOwnerGrant()).grant.revoked_at_epoch, 3,
      "owner grant revocation is verified with the real Ed25519 fixture key");
    assert.notEqual(observed.state, "blocked",
      "genuine signed verifier waiting for same-scope clear cannot hold that exclusive Web Lock");
    assert.equal(observed.state, "cleared",
      "the nested clear must complete durably without requiring queue cancellation");
    assert.match(sharedStore.get(clearNonceKey), /^[A-Za-z0-9_-]{22}$/,
      "the clear publishes an opaque cross-tab invalidation nonce");
    assert.equal([...f.database.rows.values()][0]?.format,
      "rootark-zk1-protected-revision-index-clear/v1",
      "the completed nested clear must persist a durable IDB tombstone");
  } finally {
    for (const [name, previous] of originalGlobals) {
      if (previous) Object.defineProperty(globalThis, name, previous);
      else delete globalThis[name];
    }
  }
});

test("browser-like Web Locks: signed revocation rejects first, then same-scope clear completes outside verifier", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico" };
  const authenticReader = input.client.verifyPrivateListingHead.bind(input.client);
  const manager = observableExclusiveWebLocks(), sharedStore = new Map();
  const originalGlobals = new Map(["document", "navigator", "localStorage"].map(
    (name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const key = JSON.stringify([input.grant.account_id, input.grant.compartment_id,
    input.grant.keyring_id]);
  let genuineCatalogReads = 0;
  input.client = { async verifyPrivateListingHead(...args) {
    const signed = await authenticReader(...args);
    if (++genuineCatalogReads === 3) {
      revokeSignedOwner(f);
      // Legitimate integration: do NOT await index.clear here while a Web Lock
      // might be held; reject immediately, let the owner caller clear below.
      throw Error("GENUINE_SIGNED_OWNER_REVOKED");
    }
    return signed;
  } };
  try {
    for (const [name, value] of [
      ["document", {}], ["navigator", { locks: manager.locks }],
      ["localStorage", { getItem: (key) => sharedStore.get(key) ?? null,
        setItem: (key, value) => { sharedStore.set(key, String(value)); } }],
    ]) Object.defineProperty(globalThis, name,
      { configurable: true, writable: true, value });
    await assert.rejects(index.search(input), /ZK_REVISION_INDEX_DENIED/,
      "signed owner revocation must fail closed before releasing indexed plaintext");
    assert.equal(genuineCatalogReads, 3);
    assert.equal((await f.core().verifyOwnerGrant()).grant.revoked_at_epoch, 3);
    await index.clear({ grant: input.grant, indexedDBImpl: input.indexedDBImpl,
      assertLive: input.assertLive });
    assert.equal(manager.queuedCount, 0,
      "no callback awaited a second exclusive lock while the first was held");
    assert.match(sharedStore.get("rootark-zk1-protected-revision-index-v1/clear/" + key),
      /^[A-Za-z0-9_-]{22}$/);
    assert.equal([...f.database.rows.values()][0]?.format,
      "rootark-zk1-protected-revision-index-clear/v1",
      "a post-unwind clear must durably replace the index with its tombstone");
  } finally {
    for (const [name, previous] of originalGlobals) {
      if (previous) Object.defineProperty(globalThis, name, previous);
      else delete globalThis[name];
    }
  }
});

test("P2 RED: signed owner-selected replacement during final readPage check cannot release stale excerpt", async () => {
  const f = await fixture(2);
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico" };
  const realCatalog = input.client.verifyPrivateListingHead.bind(input.client);
  let navigating = false, pageCatalogReads = 0, replaced = false;
  input.client = { async verifyPrivateListingHead(...args) {
    const signed = await realCatalog(...args);
    if (navigating && ++pageCatalogReads === 2) {
      replaced = true;
      await index.append({ ...f.core(), replaceExisting: true,
        entries: [{ ...f.selected[1].selected, name: "new-private.txt",
          mediaType: "text/plain", text: "fresh replacement confidential text" }] });
    }
    return signed;
  } };
  const previous = await index.search(input);
  assert.equal(previous.entries[0].revision, 1,
    "positive signed/AEAD index contains the original revision");
  navigating = true;
  await assert.rejects(previous.readPage(0), /ZK_REVISION_INDEX_DENIED/,
    "page captured before a newly committed selected index cannot release obsolete excerpts");
  assert.equal(pageCatalogReads, 2, "the replacement raced the real final signed catalog read");
  assert.equal(replaced, true);
  const fresh = await index.search({ ...f.core(), query: "fresh replacement" });
  assert.equal(fresh.entries[0].revision, 2, "new signed selection remains accessible");
});

test("P2 RED: initial private page cannot outlive index replacement during final signed read", async () => {
  const f = await fixture(2);
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico" };
  const realCatalog = input.client.verifyPrivateListingHead.bind(input.client);
  let catalogReads = 0, replaced = false;
  input.client = { async verifyPrivateListingHead(...args) {
    const signed = await realCatalog(...args);
    if (++catalogReads === 3) {
      replaced = true;
      await index.append({ ...f.core(), replaceExisting: true,
        entries: [{ ...f.selected[1].selected, name: "fresh-private.txt",
          mediaType: "text/plain", text: "second selected private revision" }] });
    }
    return signed;
  } };
  await assert.rejects(index.search(input), /ZK_REVISION_INDEX_DENIED/,
    "the first result cannot release an older owner selection after concurrent signed replacement");
  assert.ok(catalogReads >= 3, "real signed catalog reads were performed");
  assert.equal(replaced, true);
  const current = await index.search({ ...f.core(), query: "second selected" });
  assert.equal(current.entries[0].revision, 2);
});

test("P2 RED: caller-mutated grant G1 cannot revive G0 signed private index excerpts", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const input = { ...f.core(), query: "histórico" };
  const first = await index.search(input);
  assert.equal(first.entries[0].revision, 1,
    "positive control decrypts the authentic AES-GCM index using original signed G0");
  const newSignedGrant = { ...structuredClone(input.grant),
    permissions: ["metadata-only-after-owner-rotation"] };
  // The genuine owner signs G1 at the same manifest/head. Only its contents
  // change; a stale G0 cached page is no longer justified by the new grant.
  f.updateOwnerGrant(newSignedGrant);
  const proof = await f.core().verifyOwnerGrant();
  assert.deepEqual(proof.grant, newSignedGrant, "fresh G1 is truly Ed25519-signed");
  input.grant = newSignedGrant; // attacker replaces the caller-owned reference
  await assert.rejects(first.readPage(0), /ZK_REVISION_INDEX_DENIED/,
    "a mutable input grant cannot overwrite the originally sealed G0 digest");
});

// Only IndexedDB storage is mocked. Owner signatures, WIRE admission, the
// offline trust floor, owner checkpoint, and V2 authorized roster are real.
function disposableOwnerFloorIDB() {
  const databases = new Map();
  return { open(name, version) {
    assert.equal(version, 1);
    const request = {};
    queueMicrotask(() => {
      const fresh = !databases.has(name);
      if (fresh) databases.set(name, new Map());
      const tables = databases.get(name);
      const db = {
        objectStoreNames: { contains: (table) => tables.has(table) },
        createObjectStore(table) { assert.equal(tables.has(table), false);
          tables.set(table, new Map()); },
        transaction(table, mode) {
          assert.ok(tables.has(table));
          let aborted = false;
          const tx = { abort() { aborted = true; queueMicrotask(() => tx.onabort?.()); },
            objectStore() { return {
              get(key) {
                const req = {};
                queueMicrotask(() => {
                  if (aborted) return;
                  req.result = tables.get(table).get(key);
                  req.onsuccess?.();
                  queueMicrotask(() => { if (!aborted) tx.oncomplete?.(); });
                });
                return req;
              },
              put(value, key) {
                assert.equal(mode, "readwrite");
                tables.get(table).set(key, structuredClone(value));
              },
            }; } };
          return tx;
        },
        close() {},
      };
      request.result = db;
      if (fresh) request.onupgradeneeded?.();
      queueMicrotask(() => request.onsuccess?.());
    });
    return request;
  } };
}

test("P2 RED: real WIRE/trust-floor G0 to roster-authorized G1 never releases stale signed AES-GCM excerpts", async (t) => {
  // The G0 and G1 devices were both ACTUALLY enrolled in the same verified V2
  // manifest, not invented by switching an illegal `permissions` field.
  const state = await recoveryV2Fixtures.createInitialState(2);
  const manifest = state.headManifest;
  const roster = manifest.devices.filter((device) => device.revoked_at_epoch === null);
  assert.equal(roster.length, 2, "two authentic enrolled, non-revoked devices");
  const manifestDigest = await recoveryV2.recoveryManifestDigestV2(manifest);
  const scope = Object.fromEntries(Object.entries(state.scope).map(
    ([field, bytes]) => [field, b64(bytes)]));
  const head = { revision: manifest.revision, epoch: manifest.current_epoch,
    digest: b64(manifestDigest) };
  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerSpki = owner.publicKey.export({ format: "der", type: "spki" });
  const ownerPublicKey = await crypto.webcrypto.subtle.importKey("spki", ownerSpki,
    "Ed25519", true, ["verify"]);
  const ownerSigningKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    owner.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const signerKeyId = crypto.randomBytes(16);
  const ownerHistoryCheckpoint = await ownerCheckpoints.signOwnerCheckpoint({
    scope, signerKey: ownerSigningKey, signerPublicKey: ownerPublicKey,
    signerKeyId, deviceId: "offline-owner", revision: manifest.revision,
    manifestDigest, issuedAt: 1600, previous: null,
  });
  const grantFields = ["schema", "account_id", "compartment_id", "keyring_id",
    "device_id", "authorization_key_id", "authorization_public_key",
    "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch",
    "revoked_at_epoch"];
  const domain = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const signGrant = (device) => {
    const body = { schema: "rootark-zk1-browser-owner-device-grant/v1", ...scope,
      device_id: device.device_id,
      authorization_key_id: b64(device.authorization_key_id),
      authorization_public_key: b64(device.authorization_public_key),
      manifest_revision: manifest.revision, manifest_digest: b64(manifestDigest),
      current_epoch: manifest.current_epoch, enrolled_epoch: device.enrolled_epoch,
      revoked_at_epoch: null };
    const wire = Object.fromEntries(grantFields.map((field) => [field, body[field]]));
    const signature = crypto.sign(null, Buffer.concat([domain,
      Buffer.from(JSON.stringify(wire))]), owner.privateKey);
    return { ...wire, signature: b64(signature) };
  };
  const G0 = signGrant(roster[0]), G1 = signGrant(roster[1]);
  assert.notEqual(G0.device_id, G1.device_id);
  assert.notEqual(G0.authorization_public_key, G1.authorization_public_key);
  const trust = { ownerPublicKey,
    independentOwnerSpkiSha256: crypto.createHash("sha256").update(ownerSpki).digest(),
    pinnedCurrentHead: { revision: head.revision, epoch: head.epoch,
      digest: Buffer.from(manifestDigest) },
    ownerHistoryCheckpoint, previousOwnerHistoryProof: null };
  const previousIDB = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
  Object.defineProperty(globalThis, "indexedDB", { configurable: true,
    writable: true, value: disposableOwnerFloorIDB() });
  t.after(() => {
    if (previousIDB) Object.defineProperty(globalThis, "indexedDB", previousIDB);
    else delete globalThis.indexedDB;
  });
  // Real production trust floor verifies exact WIRE, domain-separated Ed25519
  // signatures, owner-signed checkpoint, independently pinned SPKI, and the
  // durable monotonic owner head. No fabricated `verifiedCurrent` is admitted.
  await productionFloor.provisionOffline({ ...trust, signedDeviceGrant: G0 });
  const proof0 = await productionFloor.assertCurrent({ ...trust, signedDeviceGrant: G0 });
  const proof1 = await productionFloor.assertCurrent({ ...trust, signedDeviceGrant: G1 });
  assert.equal(proof0.signedOwnerGrantVerified, true);
  assert.equal(proof1.signedOwnerGrantVerified, true);
  assert.equal(proof1.localMonotonicFloorChecked, true);

  const f = await fixture(2, scope, head.epoch); // AES-GCM scope AND epoch match the V2 manifest.
  let selectedGrant = G0;
  let currentG1Reads = 0;
  const verifyOwnerGrant = async () => {
    const signedGrant = selectedGrant;
    const proof = await productionFloor.assertCurrent({
      ...trust, signedDeviceGrant: signedGrant });
    assert.equal(proof.signedOwnerGrantVerified, true);
    if (signedGrant === G1) currentG1Reads++;
    return { verifiedCurrent: true, grant: structuredClone(signedGrant),
      ownerHead: structuredClone(head) };
  };
  const input = { ...f.core(), grant: G0, ownerHead: head,
    verifyOwnerGrant, query: "histórico" };
  await f.scan([f.selected[0]], { grant: G0, ownerHead: head, verifyOwnerGrant,
    onVerifiedBatch: (entries) => index.append({ ...input, entries }) });
  const first = await index.search(input);
  assert.equal(first.entries[0].revision, 1,
    "positive: the real G0 trust-floor authority opens the AES-GCM index");
  const positivePage = await first.readPage(0);
  assert.equal(positivePage.entries[0].revision, 1,
    "positive: readPage really releases the authentic G0 excerpt before signed grant change");

  selectedGrant = G1;
  input.grant = G1; // Only the caller's reference changes; G0 index stays sealed.
  const legalG1 = await productionFloor.assertCurrent({ ...trust, signedDeviceGrant: G1 });
  assert.equal(legalG1.signedOwnerGrantVerified, true,
    "G1 is a REAL enrolled owner's signed device grant at unchanged owner head");
  await assert.rejects(first.readPage(0), /ZK_REVISION_INDEX_DENIED/,
    "a previously cached G0 page cannot be released under another legal grant G1");
  assert.ok(currentG1Reads > 0,
    "the denied page must actually invoke the current G1 production-floor-backed owner verifier");
});

test("P2 RED: a tab cannot adopt another tab's write marker before append capture", async () => {
  const f = await fixture(2);
  await f.scan([f.selected[0]]);
  const original = structuredClone([...f.database.rows.values()][0]);
  const manager = observableExclusiveWebLocks();
  const sharedStore = new Map();
  const descriptors = new Map(["document", "navigator", "localStorage"].map(
    (name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  let superseded = false;
  try {
    for (const [name, value] of [
      ["document", {}], ["navigator", { locks: manager.locks }],
      ["localStorage", {
        getItem: (key) => sharedStore.get(key) ?? null,
        setItem: (key, value) => {
          sharedStore.set(key, String(value));
          if (!superseded && key.includes("/write/")) {
            // A second tab's synchronous mutation wins before tab A captures.
            superseded = true;
            sharedStore.set(key, String(value)[0] === "A"
              ? "B".repeat(22) : "A".repeat(22));
          }
        },
      }],
    ]) Object.defineProperty(globalThis, name,
      { configurable: true, writable: true, value });
    await assert.rejects(index.append({ ...f.core(), replaceExisting: true,
      entries: [{ ...f.selected[1].selected, name: "new-signed-owner.txt",
        mediaType: "text/plain", text: "second owner-approved text" }] }),
    /ZK_REVISION_INDEX_DENIED/,
    "tab A must not adopt tab B's newer marker as authority to write after B");
    assert.equal(superseded, true, "actual shared storage overwrite must occur");
    assert.equal([...f.database.rows.values()][0]?.nonce, original.nonce,
      "a superseded append may not replace the original encrypted index");
  } finally {
    for (const [name, descriptor] of descriptors) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
});

test("one explicitly owner-selected 128-revision batch verifies all 16 windows before one encrypted commit", async () => {

  const f = await fixture(128);
  let saves = 0;
  const progress = [];
  const { final, result } = await f.scan(undefined, {
    onProgress({ completed, total }) { progress.push([completed, total]); },
    async onVerifiedBatch(entries) {
      saves++;
      assert.equal(f.gets, 128, "persist only after the final signed GET succeeds");
      assert.equal(entries.length, 128, "never split the verified set into partial commits");
      assert.equal(f.database.rows.size, 0, "no early partial IndexedDB persistence");
      return index.append({ ...f.core(), entries });
    },
  });
  assert.equal(saves, 1);
  assert.equal(final, null, "the test supplies a one-shot callback");
  assert.equal(result.totalSearched, 128);
  assert.equal(result.totalMatches, 128);
  assert.deepEqual(progress, Array.from({ length: 16 }, (_, i) => [(i + 1) * 8, 128]));
  const stored = [...f.database.rows.values()][0];
  assert.equal(stored.format, "rootark-zk1-protected-revision-index/v1");
  assert.doesNotMatch(JSON.stringify(stored), /Histórico revisão|relatorio-confidencial|orçamento reservado/);
  const page = await index.search({ ...f.core(), query: "orçamento" });
  assert.equal(page.indexedCount, 128);
  assert.equal(page.entries.length, 50);
  assert.equal((await page.readPage(50)).entries.length, 50);
  assert.equal((await page.readPage(100)).entries.length, 28);
  assert.equal(page.coverage, "owner-selected-revisions-only");
});

test("late revision 128 ciphertext tamper denies the entire selected set without any IndexedDB write", async () => {
  const f = await fixture(128);
  const last = f.selected[127].selected;
  const key = last.objectId + ":" + last.revision;
  f.checked.set(key, { ...f.checked.get(key), ciphertextBase64: "###" });
  let writes = 0;
  await assert.rejects(f.scan(undefined, { onVerifiedBatch: async (entries) => {
    writes++;
    return index.append({ ...f.core(), entries });
  } }), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(f.gets, 128, "signed GET of the final selected revision is performed");
  assert.equal(writes, 0, "partial verified subsets cannot persist");
  assert.equal(f.database.rows.size, 0);
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

test("logout after put is queued aborts the entire IndexedDB transaction", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const previous = structuredClone([...f.database.rows.values()][0]);
  f.database.afterQueuedPutOnce(() => f.revoke());
  await assert.rejects(f.scan([f.selected[1]]), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(f.database.rows.size, 1);
  assert.equal([...f.database.rows.values()][0].nonce, previous.nonce,
    "a rejected queued put may not silently commit a new encrypted index");
});

test("a previously authorized result cannot page after a scoped index clear", async () => {
  const f = await fixture(51);
  await f.scan(f.selected);
  const result = await index.search({ ...f.core(), query: "histórico" });
  assert.equal((await result.readPage(50)).entries.length, 1);
  await index.clear({ grant: f.core().grant, indexedDBImpl: f.database,
    assertLive: f.core().assertLive });
  const [marker] = [...f.database.rows.values()];
  assert.equal(marker?.format, "rootark-zk1-protected-revision-index-clear/v1",
    "clear must leave an opaque scoped tombstone, not an empty CAS slot");
  assert.match(marker.nonce, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(Object.keys(marker).sort().join(","), "format,nonce");
  await assert.rejects(result.readPage(50), /ZK_REVISION_INDEX_DENIED/);
});

test("clear during an in-flight signed append cannot resurrect the scoped index", async () => {
  const f = await fixture();
  const input = f.core();
  let calls = 0, release, reached;
  const gate = new Promise((resolve) => { release = resolve; });
  const paused = new Promise((resolve) => { reached = resolve; });
  const client = { async verifyPrivateListingHead(...args) {
    if (++calls === 2) { reached(); await gate; }
    return input.client.verifyPrivateListingHead(...args);
  } };
  const row = { ...f.selected[0].selected, name: "local-only.txt",
    mediaType: "text/plain", text: "private local content" };
  const pending = index.append({ ...input, client, entries: [row] });
  await paused;
  try {
    await index.clear({ grant: input.grant,
      indexedDBImpl: input.indexedDBImpl, assertLive: input.assertLive });
  } finally { release(); }
  await assert.rejects(pending, /ZK_REVISION_INDEX_DENIED/,
    "append authorized before clear must be denied after clear completes");
  const [marker] = [...f.database.rows.values()];
  assert.equal(marker?.format, "rootark-zk1-protected-revision-index-clear/v1");
  assert.equal(Object.keys(marker).sort().join(","), "format,nonce");
  assert.equal(f.database.rows.size, 1);
  const fresh = await index.append({ ...input, entries: [row] });
  assert.equal(fresh.indexedCount, 1,
    "a new signed append started after clear must be allowed");
  const saved = [...f.database.rows.values()][0];
  assert.notEqual(saved.nonce, marker.nonce, "fresh ciphertext must get a new nonce");
  assert.doesNotMatch(JSON.stringify(saved), /private local content|local-only\.txt/);
});

test("clear invalidates append invoked before async context digest even if its first IDB read is later", async () => {
  const f = await fixture();
  const input = f.core();
  const subtle = crypto.webcrypto.subtle;
  const originalDigest = subtle.digest;
  let reached, release, paused = false;
  const waiting = new Promise((resolve) => { reached = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  subtle.digest = async function (...args) {
    if (!paused && args[0] === "SHA-256") { paused = true; reached(); await gate; }
    return originalDigest.apply(this, args);
  };
  const selected = f.selected[0].selected;
  const row = { ...selected, name: "pre-context-clear-private.txt",
    mediaType: "text/plain", text: "PRIVATE_PRE_CONTEXT_CLEAR_SENTINEL" };
  let pending;
  try {
    pending = index.append({ ...input, entries: [row] });
    await waiting;
    await index.clear({ grant: input.grant, indexedDBImpl: input.indexedDBImpl,
      assertLive: input.assertLive });
  } finally { subtle.digest = originalDigest; release(); }
  await assert.rejects(pending, /ZK_REVISION_INDEX_DENIED/);
  const record = [...f.database.rows.values()][0];
  assert.equal(record?.format, "rootark-zk1-protected-revision-index-clear/v1");
  assert.equal(Object.keys(record).sort().join(","), "format,nonce");
  const fresh = await index.append({ ...input, entries: [row] });
  assert.equal(fresh.indexedCount, 1, "new operation after clear still works");
  assert.doesNotMatch(JSON.stringify([...f.database.rows.values()][0]),
    /PRIVATE_PRE_CONTEXT_CLEAR_SENTINEL|pre-context-clear-private/);
});

test("clear during signed search revalidation denies its FIRST page of decrypted private excerpts", async () => {
  const f = await fixture();
  await f.scan([f.selected[0]]);
  const input = f.core();
  let count = 0, release, reached;
  const gate = new Promise((resolve) => { release = resolve; });
  const waiting = new Promise((resolve) => { reached = resolve; });
  const client = { async verifyPrivateListingHead(...args) {
    if (++count === 2) { reached(); await gate; }
    return input.client.verifyPrivateListingHead(...args);
  } };
  const pending = index.search({ ...input, client, query: "histórico" });
  await waiting;
  try {
    await index.clear({ grant: input.grant, indexedDBImpl: input.indexedDBImpl,
      assertLive: input.assertLive });
  } finally { release(); }
  await assert.rejects(pending, /ZK_REVISION_INDEX_DENIED/,
    "a first page must not expose excerpts after a completed scoped clear");
  const record = [...f.database.rows.values()][0];
  assert.equal(record?.format, "rootark-zk1-protected-revision-index-clear/v1");
});

test("repeated clears rotate durable tombstones even without an encrypted row", async () => {
  const f = await fixture();
  const input = f.core();
  await index.clear({ grant: input.grant, indexedDBImpl: input.indexedDBImpl,
    assertLive: input.assertLive });
  const first = structuredClone([...f.database.rows.values()][0]);
  assert.equal(first?.format, "rootark-zk1-protected-revision-index-clear/v1");
  await index.clear({ grant: input.grant, indexedDBImpl: input.indexedDBImpl,
    assertLive: input.assertLive });
  const second = structuredClone([...f.database.rows.values()][0]);
  assert.equal(second?.format, first.format);
  assert.notEqual(second.nonce, first.nonce);
  assert.equal(Object.keys(second).sort().join(","), "format,nonce");
  await assert.rejects(index.search({ ...input, query: "histórico" }),
    /ZK_REVISION_INDEX_DENIED/);
  const selected = f.selected[0].selected;
  await index.append({ ...input, entries: [{ ...selected, name: "new.txt",
    mediaType: "text/plain", text: "verified after two clears" }] });
  const current = [...f.database.rows.values()][0];
  assert.notEqual(current.nonce, second.nonce);
  assert.doesNotMatch(JSON.stringify(current), /verified after two clears|new\.txt/);
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

test("explicit owner-selected replacement rotates a full 128-revision encrypted snapshot atomically", async () => {
  const f = await fixture(129);
  await f.scan(f.selected.slice(0, 128));
  const oldPage = await index.search({ ...f.core(), query: "janeiro" });
  assert.equal(oldPage.indexedCount, 128);
  const oldRecord = structuredClone([...f.database.rows.values()][0]);
  const last = f.selected[128].selected;
  await assert.rejects(index.append({ ...f.core(), replaceExisting: true,
    entries: [{ ...last, name: "new.txt", mediaType: "text/plain",
      text: "X".repeat(65537) }] }), /ZK_REVISION_INDEX_DENIED/);
  await assert.rejects(index.append({ ...f.core(), replaceExisting: true,
    entries: f.core().baseline.entries.slice(0, 128).map((entry) => ({
      ...entry, name: "oversize.txt", mediaType: "text/plain",
      text: "X".repeat(34 * 1024),
    })) }), /ZK_REVISION_INDEX_DENIED/,
  "the 4 MiB cap also applies when replacing a previously full index");
  assert.deepEqual([...f.database.rows.values()][0], oldRecord,
    "failed replacement must retain the complete old encrypted snapshot");
  const rotated = await f.scan(f.selected.slice(128), {
    onVerifiedBatch: (entries) => index.append({ ...f.core(), entries,
      replaceExisting: true }),
  });
  assert.equal(rotated.result.totalSearched, 1);
  assert.equal(rotated.result.totalMatches, 1);
  const fresh = await index.search({ ...f.core(), query: "revisão 129" });
  assert.equal(fresh.indexedCount, 1);
  assert.equal(fresh.totalMatches, 1);
  assert.equal(fresh.entries[0].revision, 129);
  const removed = await index.search({ ...f.core(), query: "janeiro" });
  assert.equal(removed.totalMatches, 0);
  await assert.rejects(oldPage.readPage(0), /ZK_REVISION_INDEX_DENIED/,
    "old plaintext excerpts must not reappear after replacement");
  const stored = [...f.database.rows.values()][0];
  assert.notEqual(stored.nonce, oldRecord.nonce);
  assert.doesNotMatch(JSON.stringify(stored), /Histórico revisão|relatorio-confidencial/);
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

test("single 128-selection keeps the existing 4 MiB encrypted-index size gate", async () => {
  const f = await fixture(128);
  const entries = f.core().baseline.entries.map((entry) => ({
    objectId: entry.objectId, revision: entry.revision, epoch: entry.epoch,
    ciphertextDigestBase64: entry.ciphertextDigestBase64,
    name: "owner-only.txt", mediaType: "text/plain", text: "X".repeat(34 * 1024),
  }));
  await assert.rejects(index.append({ ...f.core(), entries }),
    /ZK_REVISION_INDEX_DENIED/);
  assert.equal(f.database.rows.size, 0,
    "oversized 128-item input may not leave a partially persisted index");
});
