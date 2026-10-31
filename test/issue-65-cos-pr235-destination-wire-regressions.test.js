"use strict";

// TEST_UNRUN. Run Node22 only when the prime grants its exclusive window:
// NODE_COUNT=0, free RAM >=4096 MiB and this worker owns the test window.
// All HTTP operations use a real, loopback-bound WebDAV server and private
// disposable disk; no monkeypatch of fs, http, URL, journal or lock authority.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-destination-wire-private-test";
const SOURCE_BYTES = "ORIGINAL_SOURCE_FOR_WIRE_DESTINATION_GUARD";
const AFTER_BYTES = "PROTOTYPE_HOOK_LEGACY_POSITIVE_BYTES";

function stat(file) {
  return fs.lstatSync(file, { bigint: true });
}

function assertSameIdentity(actual, expected, description) {
  assert.equal(actual.dev, expected.dev, `${description}: device changed`);
  assert.equal(actual.ino, expected.ino, `${description}: inode changed`);
  assert.equal(actual.isFile(), expected.isFile(), `${description}: type changed`);
}

async function fixture(t) {
  const parent = createPrivateAuthorityFixture("cos-pr235-wire-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const journalPath = path.join(parent, "mutation.json");
  const journal = await new SyncJournal(journalPath).open();
  const bridges = [];
  t.after(async () => {
    await Promise.allSettled(bridges.map((bridge) => bridge.stop()));
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  const makeBridge = (options = {}) => {
    const bridge = new LocalSyncWebDavBridge({
      rootDir: root, token: TOKEN, port: 0, ...options,
    });
    bridges.push(bridge);
    return bridge;
  };
  return { parent, root, journalPath, journal, bridges, makeBridge };
}

function wire(bridge, method, route, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1", port: bridge.address().port,
      method, path: route, agent: false,
      headers: { authorization: `Bearer ${TOKEN}`, ...headers },
    }, (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode, body: Buffer.concat(parts).toString("utf8"),
      }));
    });
    req.setTimeout(30000, () => req.destroy(new Error("Real WebDAV HTTP request timed out")));
    req.on("error", reject);
    req.end(body);
  });
}

function diskJournal(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

test("real MOVE rejects mixed-case raw Destination dot segments before durable admission; valid absolute wire MOVE works", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  const source = path.join(f.root, "source.txt");
  const stage = path.join(f.root, "stage");
  const alias = path.join(f.root, "alias.txt");
  fs.writeFileSync(source, SOURCE_BYTES, { mode: 0o600 });
  fs.mkdirSync(stage, { mode: 0o700 });
  const sourceIdentity = stat(source);
  const admissions = [];
  const bridge = f.makeBridge({ journal: f.journal, onOperation: async (operation) => {
    admissions.push(operation);
    await f.journal.enqueue(operation); // real durable admission, not a no-op spy
  } });
  await bridge.start();
  const port = bridge.address().port;
  const origin = `http://127.0.0.1:${port}`;
  const before = fs.readFileSync(f.journalPath);
  const blocked = [
    "/stage/.%2E/alias.txt", // encoded final dot of '..'
    "/stage/%2e./alias.txt", // encoded first dot of '..'
    "/stage/%2E%2e/alias.txt?version=1", // mixed-case encoded pair + query
    "/stage/../alias.txt?version=1", // raw traversal before URL normalization
    "/stage/./alias.txt?x=1", // dot segment is forbidden even when inside root
    "/%2E./alias.txt#ignored-fragment", // dot pair + fragment
    "/stage/%2e%2E/alias.txt#wire", // mixed-case pair + fragment
  ];
  for (const rawPath of blocked) {
    const rawDestination = origin + rawPath;
    // Causality check: WHATWG would erase the forbidden segment. The test
    // exercises the ORIGINAL header, not a harmless pre-normalized URL.
    assert.notEqual(new URL(rawDestination).pathname,
      rawPath.split(/[?#]/, 1)[0],
    `wire sample must actually normalize: ${rawPath}`);
    const response = await wire(bridge, "MOVE", "/source.txt", {
      headers: { Destination: rawDestination, Overwrite: "F" },
    });
    assert.equal(response.status, 400,
      `raw forbidden Destination must be refused as input validation: ${rawPath}`);
    assert.match(response.body, /(?:Unsafe|Invalid).*path/i,
      "must not count unrelated server failures as successful validation");
    assert.equal(admissions.length, 0,
      "no rejected Destination may reach the durable WebDAV operation hook");
    assert.equal(fs.readFileSync(f.journalPath).equals(before), true,
      "rejected Destination must not even rewrite the on-disk mutation journal");
    assert.equal(fs.readFileSync(source, "utf8"), SOURCE_BYTES);
    assertSameIdentity(stat(source), sourceIdentity, "rejected MOVE source");
    assert.equal(fs.existsSync(alias), false);
    assert.equal(fs.existsSync(path.join(stage, "alias.txt")), false);
    assert.deepEqual(fs.readdirSync(path.join(f.root, ".rootark-trash")), []);
  }

  // Positive HTTP control: a legitimate absolute destination traverses the
  // same parser, real onOperation and journal, then physically publishes the
  // SAME inode to the requested destination. This prevents a trivial always-400.
  const allowed = await wire(bridge, "MOVE", "/source.txt", {
    headers: { Destination: `${origin}/alias.txt?client=webdav`, Overwrite: "F" },
  });
  assert.equal(allowed.status, 201);
  assert.equal(admissions.length, 1);
  assert.equal(admissions[0].kind, "move");
  assert.equal(admissions[0].source, "/source.txt");
  assert.equal(admissions[0].destination, "/alias.txt");
  assert.equal(fs.existsSync(source), false);
  assert.equal(fs.readFileSync(alias, "utf8"), SOURCE_BYTES);
  assertSameIdentity(stat(alias), sourceIdentity, "successful MOVE destination");
  assert.equal(f.journal.pending().length, 0);
  assert.equal(f.journal.hasSeen(admissions[0].operationId), true);
  const reopened = await new SyncJournal(f.journalPath).open();
  assert.equal(reopened.hasSeen(admissions[0].operationId), true);
  assert.deepEqual(reopened.pending(), []);
});

test("prototype-inherited onOperation is an actual legacy HTTP hook, but cannot bypass protected durable admission", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  let getterReads = 0;
  let hookCalls = 0;
  const inherited = Object.create(null);
  Object.defineProperty(inherited, "onOperation", {
    enumerable: false,
    get() {
      getterReads++;
      return async (operation) => {
        hookCalls++;
        await f.journal.enqueue(operation);
      };
    },
  });
  const options = Object.create(inherited);
  Object.assign(options, { rootDir: f.root, token: TOKEN, port: 0, journal: f.journal });
  const legacy = new LocalSyncWebDavBridge(options);
  f.bridges.push(legacy);
  assert.equal(Object.hasOwn(options, "onOperation"), false,
    "the inherited getter must be absent from own property enumeration");
  assert.equal("onOperation" in options, true);
  assert.equal(legacy.hasCustomMutationJournalHook, true);
  await legacy.start();
  const response = await wire(legacy, "PUT", "/legacy.txt", { body: AFTER_BYTES });
  assert.equal(response.status, 201,
    "unprotected inherited hook must still permit a genuine successful HTTP control");
  assert.equal(fs.readFileSync(path.join(f.root, "legacy.txt"), "utf8"), AFTER_BYTES);
  assert.equal(hookCalls, 1, "inherited hook must actually run on legacy HTTP admission");
  assert.ok(getterReads >= 1);
  assert.equal(diskJournal(f.journalPath).seen.length, 1,
    "legacy hook must have persisted the real operation, not skipped journaling");
  await legacy.stop();

  // Identical inherited accessor placed on protected options. Valid-looking
  // signed ingress configuration must not allow this custom hook to replace
  // the bridge-owned durable mutation admission before any HTTP listener.
  const protectedOptions = Object.create(inherited);
  const outboxPath = path.join(f.parent, "signed-outbox.json");
  Object.assign(protectedOptions, {
    rootDir: f.root, token: TOKEN, port: 0,
    journal: new SyncJournal(f.journalPath),
    protocolJournal: new SyncJournal(outboxPath),
    requireSignedProtocolIngress: true,
    toProtocolOperation: async () => [],
    trustedProtocolPolicy: async () => ({ trusted: false }),
    resolveProtectedFileKey: async () => Buffer.alloc(32),
  });
  const protectedBridge = new LocalSyncWebDavBridge(protectedOptions);
  f.bridges.push(protectedBridge);
  const beforeLocal = fs.readFileSync(f.journalPath);
  await assert.rejects(protectedBridge.start(), /durable admission hook/i);
  assert.equal(protectedBridge.server.listening, false);
  assert.equal(protectedBridge.address(), null);
  assert.equal(hookCalls, 1, "protected bridge must not invoke inherited hook");
  assert.equal(fs.readFileSync(f.journalPath).equals(beforeLocal), true);
  assert.equal(fs.existsSync(outboxPath), false,
    "rejected prototype hook must not initialize a signed outbox");
  assert.equal(fs.existsSync(path.join(f.root, ".rootark-webdav-owner.lock")), false);
  assert.equal(fs.existsSync(outboxPath + ".webdav-owner.lock"), false);
});

test("simultaneous bridges distinguish root conflict from independent journal conflict without corrupting either disk", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  const otherRoot = path.join(f.parent, "other-root");
  fs.mkdirSync(otherRoot, { mode: 0o700 });
  const otherJournalPath = path.join(f.parent, "other-mutation.json");
  const otherJournal = await new SyncJournal(otherJournalPath).open();
  const owner = f.makeBridge({ journal: f.journal });
  await owner.start();
  const original = await wire(owner, "PUT", "/owned.txt", { body: SOURCE_BYTES });
  assert.equal(original.status, 201);
  const owned = path.join(f.root, "owned.txt");
  const ownerFileIdentity = stat(owned);
  const firstJournalBytes = fs.readFileSync(f.journalPath);
  const secondJournalBytes = fs.readFileSync(otherJournalPath);

  const sameRoot = f.makeBridge({ journal: otherJournal });
  await assert.rejects(sameRoot.start(), (error) => error?.code === "EEXIST",
    "two distinct journals cannot bypass the exclusive physical root claim");
  assert.equal(sameRoot.address(), null);
  assert.equal(fs.readFileSync(otherJournalPath).equals(secondJournalBytes), true);

  const sameJournalDifferentRoot = f.makeBridge({ rootDir: otherRoot,
    journal: new SyncJournal(f.journalPath) });
  await assert.rejects(sameJournalDifferentRoot.start(), (error) => error?.code === "EEXIST",
    "distinct roots sharing one real journal must not bypass its independent claim");
  assert.equal(sameJournalDifferentRoot.address(), null);
  assert.equal(fs.existsSync(path.join(otherRoot, ".rootark-webdav-owner.lock")), false,
    "journal lock denial must release the second bridge's root claim");
  assert.equal(fs.readFileSync(f.journalPath).equals(firstJournalBytes), true,
    "a refused contender cannot erase or rewrite existing durable receipt bytes");
  assert.equal(fs.readFileSync(owned, "utf8"), SOURCE_BYTES);
  assertSameIdentity(stat(owned), ownerFileIdentity, "root/journal contender safety");
  assert.equal((await wire(owner, "GET", "/owned.txt")).status, 200);

  await owner.stop();
  // Real, independent successor after the original owner releases its claim.
  const successor = f.makeBridge({ journal: new SyncJournal(f.journalPath) });
  await successor.start();
  assert.equal((await wire(successor, "GET", "/owned.txt")).status, 200);
  assertSameIdentity(stat(owned), ownerFileIdentity, "successor ownership preservation");
  assert.equal(fs.readFileSync(owned, "utf8"), SOURCE_BYTES);
  assert.deepEqual((await new SyncJournal(f.journalPath).open()).state.seen,
    diskJournal(f.journalPath).seen);
});
