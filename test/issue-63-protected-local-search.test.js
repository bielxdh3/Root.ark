"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const search = require("../public/client/rootark-zk1-protected-local-search");

// Only IndexedDB and independent catalog I/O are substituted. AES-GCM/HKDF is real.
function indexedDBMemory() {
  const rows = new Map();
  let opened = false;
  let rejectWrites = false;
  return {
    rows,
    denyWrites() { rejectWrites = true; },
    open() {
      const req = {};
      const db = {
        objectStoreNames: { contains: (name) => name === "catalogs" && opened },
        createObjectStore(name) { assert.equal(name, "catalogs"); },
        close() {},
        transaction(name, mode) {
          assert.equal(name, "catalogs");
          const tx = {
            objectStore() {
              return {
                get(key) { return request(() => rows.get(key)); },
                put(value, key) {
                  assert.equal(mode, "readwrite");
                  if (rejectWrites) {
                    const call = {};
                    queueMicrotask(() => { call.onerror?.(); tx.onabort?.(); });
                    return call;
                  }
                  return request(() => { rows.set(key, structuredClone(value)); return key; });
                },
                delete(key) {
                  assert.equal(mode, "readwrite");
                  return request(() => { rows.delete(key); return undefined; });
                },
              };
            },
          };
          function request(fn) {
            const call = {};
            queueMicrotask(() => {
              call.result = fn();
              call.onsuccess?.();
              queueMicrotask(() => tx.oncomplete?.());
            });
            return call;
          }
          return tx;
        },
      };
      queueMicrotask(() => {
        req.result = db;
        if (!opened) req.onupgradeneeded?.();
        opened = true;
        queueMicrotask(() => req.onsuccess?.());
      });
      return req;
    },
  };
}

function fixture(database, names = ["Relato\u0301rio [2026].txt", "secret-private-name.txt", null]) {
  const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((key) => [key, crypto.randomBytes(16).toString("base64url")]));
  scope.compartment_id = Buffer.from("fixture-compartment").toString("base64url");
  const ownerDigest = crypto.randomBytes(32).toString("base64url");
  const grant = { ...scope, device_id: "device-current", revoked_at_epoch: null,
    manifest_revision: 7, manifest_digest: ownerDigest, current_epoch: 2 };
  const entries = names.map((name, i) => ({
    objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 1, epoch: 2,
    name, logicalTrashCandidate: name === null,
  }));
  const baseline = { head: { sequence: 12,
    digest: crypto.randomBytes(32).toString("base64url") },
    entries: entries.map(({ objectId, revision, epoch }) => ({ objectId, revision, epoch })) };
  let remoteReads = 0, opened = 0, denied = false;
  const client = {
    async verifyPrivateListingHead() {
      remoteReads++;
      if (denied) throw Error("CAS_CHANGED_OR_REVOKED");
      return { head: baseline.head, scope };
    },
    async readPrivateListing(_previous, _key, term) {
      remoteReads++;
      assert.equal(term, "", "the server-backed read never receives a query");
      opened++;
      return { head: baseline.head, scope, entries, totalMatches: entries.length,
        plaintextSentToServer: false, independentlySignedCatalog: true,
        authorizesMutation: false };
    },
  };
  function input(raw, term = "") {
    return { indexedDBImpl: database, client, baseline, grant, ownerRevision: 7,
      ownerEpoch: 2, ownerDigest: crypto.randomBytes(32).toString("base64url"),
      metadataRaw: raw, term, assertLive() { if (denied) throw Error("SESSION_DENIED"); } };
  }
  return { input: (raw, term) => ({ ...input(raw, term), ownerDigest }), baseline,
    get remoteReads() { return remoteReads; }, get opened() { return opened; },
    revoke() { denied = true; }, scope };
}

test("local protected index persists encrypted names; reload uses verified CAS and no plaintext outbound", async () => {
  const database = indexedDBMemory();
  const f = fixture(database);
  const key = crypto.randomBytes(32);
  const first = await search.search(f.input(key, "RELATÓRIO [2026]"));
  assert.equal(first.totalMatches, 1);
  assert.equal(first.entries[0].name.normalize("NFC"), "Relatório [2026].txt");
  assert.equal(f.opened, 1);
  assert.equal(database.rows.size, 1);
  assert.doesNotMatch(JSON.stringify([...database.rows.values()]),
    /secret-private-name|Retato|relat[oó]rio/i);
  const second = await search.search(f.input(key, "secret-"));
  assert.equal(second.entries[0].name, "secret-private-name.txt");
  assert.equal(f.opened, 1, "same authenticated head must reuse encrypted cache");
  assert.equal(f.remoteReads, 2, "every invocation freshly verifies signed catalog");
  const all = await search.search(f.input(key, ""));
  assert.equal(all.entries.length, 3);
  assert.equal(all.entries.at(-1).logicalTrashCandidate, true);
  f.revoke();
  await assert.rejects(search.search(f.input(key, "secret")), /ZK_LOCAL_SEARCH_DENIED/);
});

test("full 4096-row signed catalog is indexed, returns a bounded 100-hit UI page", async () => {
  const database = indexedDBMemory();
  const f = fixture(database, Array.from({ length: 4096 },
    (_, i) => "report-" + "a".repeat(209) + i.toString(16).padStart(4, "0")));
  const key = crypto.randomBytes(32);
  const first = await search.search(f.input(key, "REPORT-"));
  assert.equal(first.totalMatches, 4096);
  assert.equal(first.entries.length, 100);
  assert.equal(f.opened, 1);
  const again = await search.search(f.input(key, "report-"));
  assert.equal(again.totalMatches, 4096);
  assert.equal(f.opened, 1, "persistent cache covers maximum signed catalog size");
});

test("explicit local invalidation deletes only the scoped encrypted index", async () => {
  const database = indexedDBMemory();
  const f = fixture(database);
  const key = crypto.randomBytes(32);
  const input = f.input(key, "private");
  await search.search(input);
  assert.equal(database.rows.size, 1);
  await search.clear({ grant: input.grant, indexedDBImpl: database, assertLive() {} });
  assert.equal(database.rows.size, 0);
  await search.search(input);
  assert.equal(f.opened, 2, "mutation must not retain the old index");
  const offline = await search.search({ ...input, indexedDBImpl: null });
  assert.equal(offline.persistedIndex, false);
  assert.equal(offline.totalMatches, 1);
});

test("a denied IndexedDB write returns authenticated ephemeral matches without weakening revocation", async () => {
  const database = indexedDBMemory();
  database.denyWrites();
  const f = fixture(database);
  const key = crypto.randomBytes(32);
  const result = await search.search(f.input(key, "secret"));
  assert.equal(result.totalMatches, 1);
  assert.equal(result.entries[0].name, "secret-private-name.txt");
  assert.equal(result.persistedIndex, false);
  assert.equal(database.rows.size, 0);
  assert.equal(f.opened, 1);
  const repeated = await search.search(f.input(key, "secret"));
  assert.equal(repeated.totalMatches, 1);
  assert.equal(repeated.persistedIndex, false);
  assert.equal(f.opened, 2);
  f.revoke();
  await assert.rejects(search.search(f.input(key, "secret")), /ZK_LOCAL_SEARCH_DENIED/);
});

test("wrong key, tampered ciphertext, epoch change and stale CAS cannot reveal cached names", async () => {
  const database = indexedDBMemory();
  const f = fixture(database);
  const key = crypto.randomBytes(32);
  await search.search(f.input(key, ""));
  await assert.rejects(search.search(f.input(crypto.randomBytes(32), "secret")),
    /ZK_LOCAL_SEARCH_DENIED/);
  const [id, old] = [...database.rows][0];
  database.rows.set(id, { ...old,
    ciphertext: (old.ciphertext[0] === "A" ? "B" : "A") + old.ciphertext.slice(1) });
  await assert.rejects(search.search(f.input(key, "secret")),
    /ZK_LOCAL_SEARCH_DENIED/);
  database.rows.set(id, old);
  const rotated = f.input(key, "secret");
  rotated.ownerEpoch = 3;
  await assert.rejects(search.search(rotated), /ZK_LOCAL_SEARCH_DENIED/);
  f.baseline.head.digest = crypto.randomBytes(32).toString("base64url");
  const changed = await search.search(f.input(key, "secret"));
  assert.equal(changed.entries.length, 1);
  assert.equal(f.opened, 2, "new authenticated head must rebuild from current verified catalog");
});

test("search cap, scope fence and malformed full listing fail closed", async () => {
  const database = indexedDBMemory();
  const f = fixture(database);
  const key = crypto.randomBytes(32);
  const forbidden = f.input(key, "x".repeat(121));
  await assert.rejects(search.search(forbidden), /ZK_LOCAL_SEARCH_DENIED/);
  const bad = f.input(key, "secret");
  bad.grant = { ...bad.grant, revoked_at_epoch: 2 };
  await assert.rejects(search.search(bad), /ZK_LOCAL_SEARCH_DENIED/);
  const wrongOwner = f.input(key, "secret");
  wrongOwner.grant = { ...wrongOwner.grant,
    manifest_digest: crypto.randomBytes(32).toString("base64url") };
  await assert.rejects(search.search(wrongOwner), /ZK_LOCAL_SEARCH_DENIED/,
    "a forged owner head must not select cached corpus");
  const first = await search.search(f.input(key, "secret"));
  assert.equal(first.totalMatches, 1);
  const mixed = f.input(key, "secret");
  mixed.grant = { ...mixed.grant, compartment_id: crypto.randomBytes(16).toString("base64url") };
  await assert.rejects(search.search(mixed), /ZK_LOCAL_SEARCH_DENIED/,
    "a client for one account must not populate another account's cache");
  assert.equal(f.opened, 2);
});

test("multi-revision signed catalog indexes only latest revision per object and never resurrects trashed names", async () => {
  const database = indexedDBMemory();
  const scope = {
    account_id: crypto.randomBytes(16).toString("base64url"),
    compartment_id: Buffer.from("fixture-compartment").toString("base64url"),
    keyring_id: crypto.randomBytes(16).toString("base64url"),
  };
  const ownerDigest = crypto.randomBytes(32).toString("base64url");
  const grant = { ...scope, device_id: "device-current", revoked_at_epoch: null,
    manifest_revision: 7, manifest_digest: ownerDigest, current_epoch: 2 };
  const trashedId = crypto.randomBytes(16).toString("base64url");
  const renamedId = crypto.randomBytes(16).toString("base64url");
  const rawEntries = [
    { objectId: trashedId, revision: 1, epoch: 2, name: "deleted-report.txt", logicalTrashCandidate: false },
    { objectId: renamedId, revision: 1, epoch: 2, name: "old-draft.txt", logicalTrashCandidate: false },
    { objectId: trashedId, revision: 2, epoch: 2, name: null, logicalTrashCandidate: true },
    { objectId: renamedId, revision: 2, epoch: 2, name: "current-report.txt", logicalTrashCandidate: false },
  ];
  // Mirror COS #257's latestByObject deduplication from readPrivateListing:
  const latestMap = new Map();
  for (const row of rawEntries) {
    const prev = latestMap.get(row.objectId);
    if (!prev || row.revision > prev.revision) {
      latestMap.delete(row.objectId);
      latestMap.set(row.objectId, row);
    }
  }
  const latest = [...latestMap.values()];
  const baseline = {
    head: { sequence: 14, digest: crypto.randomBytes(32).toString("base64url") },
    entries: rawEntries.map(({ objectId, revision, epoch }) => ({ objectId, revision, epoch })),
  };
  let opened = 0;
  const client = {
    async verifyPrivateListingHead() { return { head: baseline.head, scope }; },
    async readPrivateListing(_prev, _key, term) {
      assert.equal(term, "");
      opened++;
      return { head: baseline.head, scope, entries: latest, totalMatches: latest.length,
        plaintextSentToServer: false, independentlySignedCatalog: true, authorizesMutation: false };
    },
  };
  const key = crypto.randomBytes(32);
  const baseInput = { indexedDBImpl: database, client, baseline, grant,
    ownerRevision: 7, ownerEpoch: 2, ownerDigest, metadataRaw: key, assertLive() {} };

  const currentMatch = await search.search({ ...baseInput, term: "current-report" });
  assert.equal(currentMatch.totalMatches, 1);
  assert.equal(currentMatch.entries[0].objectId, renamedId);
  assert.equal(currentMatch.entries[0].revision, 2);

  // Cached reuse must succeed on multi-revision catalogs and exclude superseded/trashed names:
  const cachedResurrect = await search.search({ ...baseInput, term: "deleted-report" });
  assert.equal(cachedResurrect.reusedIndex, true);
  assert.equal(cachedResurrect.totalMatches, 0);
  const cachedOldName = await search.search({ ...baseInput, term: "old-draft" });
  assert.equal(cachedOldName.reusedIndex, true);
  assert.equal(cachedOldName.totalMatches, 0);
  const unfiltered = await search.search({ ...baseInput, term: "" });
  assert.equal(unfiltered.totalMatches, 2);
  assert.equal(unfiltered.entries.length, 2);
  assert.equal(opened, 1);

  // Adversarial: forged opening returning superseded revision 1 instead of revision 2 must deny.
  database.rows.clear();
  const forgedClient = {
    async verifyPrivateListingHead() { return { head: baseline.head, scope }; },
    async readPrivateListing() {
      return { head: baseline.head, scope,
        entries: [rawEntries[0], rawEntries[3]], totalMatches: 2,
        plaintextSentToServer: false, independentlySignedCatalog: true, authorizesMutation: false };
    },
  };
  await assert.rejects(search.search({ ...baseInput, client: forgedClient, term: "deleted" }),
    /ZK_LOCAL_SEARCH_DENIED/);
});
