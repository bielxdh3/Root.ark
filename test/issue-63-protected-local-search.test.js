"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
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

test("an authenticated empty catalog accepts only its zero sequence and zero digest", async () => {
  for (const database of [indexedDBMemory(), null]) {
    const f = fixture(database, []);
    f.baseline.head = { sequence: 0, digest: Buffer.alloc(32).toString("base64url") };
    const result = await search.search(f.input(crypto.randomBytes(32), ""));
    assert.equal(result.totalMatches, 0);
    assert.deepEqual(result.entries, []);
    assert.equal(f.opened, 1);
  }

  const invalid = fixture(null, []);
  invalid.baseline.head = { sequence: 0,
    digest: crypto.randomBytes(32).toString("base64url") };
  await assert.rejects(search.search(invalid.input(crypto.randomBytes(32), "")),
    /ZK_LOCAL_SEARCH_DENIED/);
  assert.equal(invalid.opened, 0, "an invalid empty-head digest is rejected before catalog I/O");
});

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
  assert.equal(f.remoteReads, 4,
    "each invocation verifies signed catalog and rechecks the CAS before release");
  const all = await search.search(f.input(key, ""));
  assert.equal(all.entries.length, 3);
  assert.equal(all.entries.at(-1).logicalTrashCandidate, true);
  f.revoke();
  await assert.rejects(search.search(f.input(key, "secret")), /ZK_LOCAL_SEARCH_DENIED/);
});

test("P2: cached AES-GCM results remain hidden if signed CAS advances during decryption", async () => {
  const database = indexedDBMemory();
  const f = fixture(database);
  const key = crypto.randomBytes(32);
  const created = await search.search(f.input(key, "secret"));
  assert.equal(created.totalMatches, 1, "real AES-GCM creates an authenticated cache");
  assert.equal(f.opened, 1);

  const input = f.input(key, "secret");
  const originalVerify = input.client.verifyPrivateListingHead.bind(input.client);
  let signedReads = 0;
  input.client.verifyPrivateListingHead = async (...args) => {
    const signed = await originalVerify(...args);
    signedReads++;
    if (signedReads === 1) return signed;
    // Another valid owner mutation arrives after the initial signed CAS
    // recheck while the cached ciphertext is being decrypted locally.
    return { ...signed, head: {
      ...signed.head, sequence: signed.head.sequence + 1,
      digest: crypto.randomBytes(32).toString("base64url"),
    } };
  };

  await assert.rejects(search.search(input), /ZK_LOCAL_SEARCH_DENIED/,
    "a changed independently signed CAS may not release cached private names");
  assert.equal(signedReads, 2, "the post-AEAD independent signed read is mandatory");
  assert.equal(f.opened, 1, "the attack exercises cached data, not a new full listing");
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

test("signed 4096-revision history pages locally without retaining the metadata key", async () => {
  const database = indexedDBMemory();
  const names = Array.from({ length: 4096 }, (_, i) => "history-" + String(i).padStart(4, "0"));
  const f = fixture(database, names);
  const key = crypto.randomBytes(32);
  const first = await search.search(f.input(key, ""));
  assert.equal(first.totalMatches, 4096);
  assert.equal(first.entries.length, 100, "unfiltered listing must also be bounded");
  assert.equal(first.entries[0].name, "history-0000");
  assert.equal(first.hasNext, true);
  assert.equal(first.offset, 0);
  key.fill(0); // The workspace zeroizes the local key immediately after its action.

  const readsBeforePage = f.remoteReads;
  const second = await first.readPage(100);
  assert.equal(f.remoteReads, readsBeforePage + 1, "each page rechecks signed CAS");
  assert.equal(second.entries.length, 100);
  assert.equal(second.entries[0].name, "history-0100");
  assert.equal(second.offset, 100);
  assert.equal(second.totalMatches, 4096);
  assert.equal(f.opened, 1, "page requests must not re-import the CEK or re-fetch plaintext");

  const last = await first.readPage(4000);
  assert.equal(last.entries.length, 96);
  assert.equal(last.entries.at(-1).name, "history-4095");
  assert.equal(last.hasNext, false);
  assert.equal(f.opened, 1);
  await assert.rejects(first.readPage(-100), /ZK_LOCAL_SEARCH_DENIED/);
  await assert.rejects(first.readPage(4096), /ZK_LOCAL_SEARCH_DENIED/);
  await assert.rejects(first.readPage(12), /ZK_LOCAL_SEARCH_DENIED/);
  f.baseline.head.digest = crypto.randomBytes(32).toString("base64url");
  await assert.rejects(first.readPage(200), /ZK_LOCAL_SEARCH_DENIED/,
    "a changed signed head invalidates every old in-memory page");
  f.revoke();
  await assert.rejects(first.readPage(200), /ZK_LOCAL_SEARCH_DENIED/,
    "a revoked session must never reveal another cached page");
});

test("rejected old page cannot clear a newer authenticated search, but current page denial clears", async () => {
  // Minimal browser DOM with real parentage, so replaceChildren() detaches old controls.
  const doc = {};
  const makeNode = (tag) => ({
    tag, ownerDocument: doc, parent: null, children: [], dataset: {},
    listeners: {}, textContent: "", value: "",
    addEventListener(type, callback) { this.listeners[type] = callback; },
    click() { return this.listeners.click?.(); },
    append(...children) {
      for (const child of children) { child.parent = this; this.children.push(child); }
    },
    replaceChildren(...children) {
      for (const child of this.children) child.parent = null;
      this.children = [];
      for (const child of children) {
        if (child.tag === "fragment") {
          this.append(...child.children);
          child.children = [];
        } else this.append(child);
      }
    },
    contains(target) {
      for (let current = target; current; current = current.parent)
        if (current === this) return true;
      return false;
    },
    focus() {},
  });
  doc.createDocumentFragment = () => makeNode("fragment");
  doc.createElement = (tag) => makeNode(tag);
  const container = makeNode("section");
  const selected = makeNode("input");
  const revision = makeNode("input");
  const find = (node, predicate) => {
    if (predicate(node)) return node;
    for (const child of node.children) {
      const match = find(child, predicate);
      if (match) return match;
    }
    return null;
  };
  const row = (name) => ({ name, objectId: "AAAAAAAAAAAAAAAAAAAAAA", revision: 1,
    logicalTrashCandidate: false });
  const page = (readPage, onDenied) => ({ offset: 0, totalMatches: 101,
    pageSize: 100, readPage, onDenied });
  let rejectOld, deniedOld = 0, summary = "old-query";
  search.renderVerifiedResults(container, [row("old-query")], selected, () => true,
    revision, page(() => new Promise((_, reject) => { rejectOld = reject; }),
      () => { deniedOld++; summary = "old-denied"; }));
  const oldNext = find(container, (node) => node.dataset.zk1Page === "next");
  assert.ok(oldNext);
  const pendingOld = oldNext.click();
  assert.equal(typeof rejectOld, "function");
  search.renderVerifiedResults(container, [row("new-authorized-result")], selected,
    () => true, revision);
  summary = "new-query";
  rejectOld(Error("STALE_SIGNED_CAS"));
  await pendingOld;
  assert.ok(find(container, (node) => node.textContent.includes("new-authorized-result")),
    "old async failure must preserve newer verified result nodes");
  assert.equal(deniedOld, 0, "stale callback must not issue denial for newer query");
  assert.equal(summary, "new-query", "stale callback must not overwrite newer summary");

  let rejectCurrent, deniedCurrent = 0;
  search.renderVerifiedResults(container, [row("current-revoked")], selected,
    () => true, revision, page(() => new Promise((_, reject) => {
      rejectCurrent = reject;
    }), () => { deniedCurrent++; }));
  const currentNext = find(container, (node) => node.dataset.zk1Page === "next");
  const pendingCurrent = currentNext.click();
  rejectCurrent(Error("GRANT_REVOKED"));
  await pendingCurrent;
  assert.equal(container.children.length, 0,
    "rejected current generation must still clear sensitive results");
  assert.equal(deniedCurrent, 1, "current revocation must call denial handler");
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

test("a failed index encryption wipes the transient plaintext catalog", async () => {
  const database = indexedDBMemory();
  const f = fixture(database);
  let rawBytes, sawPrivateName = false;
  const subtle = new Proxy(crypto.webcrypto.subtle, {
    get(target, property) {
      if (property === "encrypt") return async (_algorithm, _key, plaintext) => {
        rawBytes = plaintext;
        sawPrivateName = new TextDecoder().decode(plaintext)
          .includes("secret-private-name.txt");
        throw Error("FORCED_INDEX_ENCRYPT_FAILURE");
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  const context = { crypto: { subtle,
    getRandomValues: (bytes) => crypto.webcrypto.getRandomValues(bytes) },
  TextEncoder, TextDecoder, Uint8Array, btoa, atob };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-protected-local-search.js"), "utf8"), context);

  await assert.rejects(context.RootarkZk1ProtectedLocalSearch.search(
    f.input(crypto.randomBytes(32), "secret")), /ZK_LOCAL_SEARCH_DENIED/);
  assert.equal(sawPrivateName, true, "fixture proves the buffer held a real private name");
  assert.equal(f.opened, 1, "the signed catalog was opened before encryption failed");
  assert.equal(database.rows.size, 0, "no failed index may be persisted");
  assert.ok(rawBytes instanceof Uint8Array && rawBytes.every((byte) => byte === 0),
    "failure must zero the exact plaintext bytes passed to WebCrypto");
});

test("P2: signed cache verification cannot replace the original guard after revocation", async () => {
  const database = indexedDBMemory();
  const f = fixture(database);
  const raw = crypto.randomBytes(32);
  const positive = await search.search(f.input(raw, "secret-private-name"));
  assert.equal(positive.totalMatches, 1, "real AES-GCM must create a readable encrypted cache");
  assert.equal(database.rows.size, 1);

  const input = f.input(raw, "secret-private-name");
  const originalVerify = input.client.verifyPrivateListingHead;
  const originalGuard = input.assertLive;
  let signedChecks = 0;
  const bypass = () => {};
  input.client = { ...input.client, async verifyPrivateListingHead(...args) {
    const signed = await originalVerify(...args);
    signedChecks++;
    // The genuine signed read was completed while the session was live;
    // revocation then races the awaited callback's return to the searcher.
    f.revoke();
    input.assertLive = bypass;
    return signed;
  } };
  await assert.rejects(search.search(input), /ZK_LOCAL_SEARCH_DENIED/,
    "a replaced caller-owned guard must not release cached private filenames");
  assert.equal(signedChecks, 1, "fresh signed head validation really completed");
  assert.equal(input.assertLive, bypass, "the malicious callback replacement occurred");
  assert.notEqual(originalGuard, bypass);
  assert.throws(originalGuard, /SESSION_DENIED/,
    "the originally authenticated session guard detects the actual revocation");
  assert.equal(f.opened, 1, "attack targeted existing encrypted cache, not a new listing");
});

test("P2: IndexedDB callbacks cannot substitute an unsigned reader before first index build", async () => {
  const database = indexedDBMemory();
  const f = fixture(database);
  const raw = crypto.randomBytes(32);
  const input = f.input(raw, "forged-audit-name");
  const trustedReader = input.client.readPrivateListing;
  const signed = await trustedReader(input.baseline, null, "");
  assert.equal(signed.entries.some((entry) => entry.name === "forged-audit-name"), false);
  const injectedUnsigned = { ...signed, entries: signed.entries.map((entry, index) =>
    index === 0 ? { ...entry, name: "forged-audit-name" } : entry) };
  const open = database.open.bind(database);
  let replaced = false, unsignedReads = 0;
  database.open = () => {
    replaced = true;
    input.client.readPrivateListing = async () => {
      unsignedReads++;
      return injectedUnsigned;
    };
    return open();
  };
  const result = await search.search(input);
  assert.equal(replaced, true, "the reader replacement occurred while opening IndexedDB");
  assert.equal(unsignedReads, 0, "the forged reader must never replace the captured signed reader");
  assert.equal(result.totalMatches, 0, "unsigned names must never enter search results");
  assert.equal(f.opened, 2, "the original independently checked reader actually ran");
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
