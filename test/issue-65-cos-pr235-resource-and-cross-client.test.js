"use strict";

// TEST_UNRUN: exclusive Node22 gate required. All mutations travel through
// actual authenticated loopback HTTP; only per-bridge hooks/barriers are used.
// No shared fs implementation is replaced, and every paused request is
// released in a finally block.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { setImmediate: nextTurn } = require("node:timers/promises");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-resource-cross-client-216";
const ORIGINAL = "ORIGINAL_EXACT_FILE_CONTENT";
const REPLACEMENT = "CONCURRENT_AUTHORIZED_NEW_CONTENT";
const FIRST = "FIRST_INSTALLED_PAYLOAD";
const SECOND = "SECOND_INSTALLED_PAYLOAD";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function request(bridge, method, route, { headers = {}, data } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1", port: bridge.address().port,
      method, path: route,
      headers: { authorization: `Bearer ${TOKEN}`, ...headers },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode, body: Buffer.concat(chunks).toString("utf8"),
        headers: res.headers,
      }));
    });
    req.setTimeout(30000, () => req.destroy(new Error(`Timed out: ${method} ${route}`)));
    req.on("error", reject);
    req.end(data);
  });
}

async function fixture(t, onOperation = async () => {}) {
  const parent = createPrivateAuthorityFixture("cos-pr235-resource-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN,
    port: 0, onOperation });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  return { root, bridge };
}

function stat(filename) {
  return fs.lstatSync(filename, { bigint: true });
}

function sameInode(actual, original) {
  assert.equal(actual.dev, original.dev);
  assert.equal(actual.ino, original.ino);
}

function trashEntries(root) {
  return fs.readdirSync(path.join(root, ".rootark-trash"));
}

function noStaging(root) {
  assert.equal(fs.readdirSync(root).some((entry) => entry.startsWith(".rootark-put-")),
    false, "no abandoned PUT staging pathname");
}

async function waitForCondition(predicate, description, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  do {
    if (predicate()) return;
    await nextTurn();
  } while (Date.now() < deadline);
  assert.fail(`Timed out awaiting real bridge condition: ${description}`);
}

function moveHeaders(target, overwrite = "F") {
  return { destination: `http://127.0.0.1/${target}`, overwrite };
}

test("control: uncontended real HTTP PUT overwrite, MOVE file, DELETE and MKCOL yield exact content", {
  timeout: 120000,
}, async (t) => {
  const hooks = [];
  const { root, bridge } = await fixture(t, async (op) => { hooks.push(op); });
  const source = path.join(root, "control.txt");
  fs.writeFileSync(source, ORIGINAL, { mode: 0o600 });
  const originalIdentity = stat(source);
  assert.equal((await request(bridge, "PUT", "/control.txt", { data: REPLACEMENT })).status, 204);
  assert.equal(fs.readFileSync(source, "utf8"), REPLACEMENT);
  const putIdentity = stat(source);
  assert.notEqual(putIdentity.ino, originalIdentity.ino);
  assert.equal((await request(bridge, "MOVE", "/control.txt",
    { headers: moveHeaders("moved.txt") })).status, 201);
  assert.equal(fs.existsSync(source), false);
  sameInode(stat(path.join(root, "moved.txt")), putIdentity);
  assert.equal(fs.readFileSync(path.join(root, "moved.txt"), "utf8"), REPLACEMENT);
  assert.equal((await request(bridge, "DELETE", "/moved.txt")).status, 204);
  assert.equal(fs.existsSync(path.join(root, "moved.txt")), false);
  assert.equal((await request(bridge, "MKCOL", "/fresh-collection")).status, 201);
  assert.equal(stat(path.join(root, "fresh-collection")).isDirectory(), true);
  assert.deepEqual(hooks.map((op) => op.kind), ["put", "move", "delete"]);
  assert.equal(hooks[0].existed, true);
  assert.equal(hooks[1].source, "/control.txt");
  assert.equal(hooks[2].source, "/moved.txt");
  assert.equal(trashEntries(root).length, 2,
    "PUT overwrite and DELETE each preserve one physically backed-up inode");
  noStaging(root);
});

test("same-instance lock serializes two genuine concurrent PUTs to one destination after first physical install", {
  timeout: 120000,
}, async (t) => {
  const installed = deferred();
  const admittedSecond = deferred();
  const release = deferred();
  const operations = [];
  const { root, bridge } = await fixture(t, async (operation) => {
    operations.push(operation);
    if (operations.length === 2) admittedSecond.resolve(operation);
  });
  const update = bridge.updateJournal.bind(bridge);
  let pauses = 0;
  bridge.updateJournal = async (id, patch) => {
    if (operations[0]?.operationId === id && patch.phase === "source-moved") {
      pauses++;
      installed.resolve();
      await release.promise;
    }
    return update(id, patch);
  };
  const firstPath = path.join(root, "shared.txt");
  const first = request(bridge, "PUT", "/shared.txt", { data: FIRST });
  let second;
  try {
    await Promise.race([
      installed.promise,
      first.then((r) => { throw Error(`first PUT ended before physical barrier: ${r.status}`); }),
    ]);
    assert.equal(pauses, 1);
    assert.equal(operations.length, 1);
    assert.equal(operations[0].kind, "put");
    assert.equal(operations[0].existed, false);
    assert.equal(fs.readFileSync(firstPath, "utf8"), FIRST);
    const firstIdentity = stat(firstPath);
    let secondSettled = false;
    second = request(bridge, "PUT", "/shared.txt", { data: SECOND });
    second.then(() => { secondSettled = true; }, () => { secondSettled = true; });
    const secondOperation = await Promise.race([
      admittedSecond.promise,
      second.then((r) => { throw Error(`second PUT ended before hook: ${r.status}`); }),
    ]);
    assert.equal(secondOperation.kind, "put");
    assert.equal(secondOperation.existed, true,
      "second request must observe first PUT's physically published destination");
    assert.equal(secondOperation.destination, "/shared.txt");
    await nextTurn();
    assert.equal(secondSettled, false, "second PUT must still await the first lock");
    assert.equal(fs.readFileSync(firstPath, "utf8"), FIRST);
    sameInode(stat(firstPath), firstIdentity);
    assert.equal(bridge.inflightMutations, 2);
    release.resolve();
    assert.equal((await first).status, 201);
    assert.equal((await second).status, 204);
    assert.equal(fs.readFileSync(firstPath, "utf8"), SECOND);
    assert.notEqual(stat(firstPath).ino, firstIdentity.ino);
    const entries = trashEntries(root).filter((name) => name.startsWith(".rootark-put-"));
    assert.equal(entries.length, 1, "second overwrite must preserve first payload in trash");
    assert.equal(fs.readFileSync(path.join(root, ".rootark-trash", entries[0]), "utf8"), FIRST);
    assert.deepEqual(operations.map((op) => op.kind), ["put", "put"]);
    assert.equal(bridge.inflightMutations, 0);
    noStaging(root);
  } finally {
    release.resolve();
    await Promise.allSettled([first, second].filter(Boolean));
  }
});

test("8 real suspended HTTP PUT admissions reject ninth before hook and release capacity after settlement", {
  timeout: 120000,
}, async (t) => {
  const allEight = deferred();
  const release = deferred();
  const operations = [];
  const { root, bridge } = await fixture(t, async (operation) => {
    operations.push(operation);
    if (operations.length === 8) allEight.resolve();
    await release.promise;
  });
  const requests = Array.from({ length: 8 }, (_, index) =>
    request(bridge, "PUT", `/admission-${index}.txt`, { data: `BODY_${index}` }));
  try {
    await Promise.race([
      allEight.promise,
      ...requests.map((item, index) => item.then(
        (result) => { throw Error(`admission ${index} returned early ${result.status}`); },
        (error) => { throw error; },
      )),
    ]);
    assert.equal(operations.length, 8, "eight independent HTTP paths must reach hook");
    assert.equal(new Set(operations.map((op) => op.destination)).size, 8);
    assert.ok(operations.every((op) => op.kind === "put" && op.existed === false));
    assert.equal(bridge.inflightMutations, 8);
    for (let i = 0; i < 8; i++) {
      assert.equal(fs.existsSync(path.join(root, `admission-${i}.txt`)), false);
    }
    const denied = await request(bridge, "PUT", "/admission-nine.txt", {
      data: "NINTH_MUST_NOT_REACH_HOOK",
    });
    assert.equal(denied.status, 503);
    assert.equal(denied.body, "Too many pending WebDAV mutations");
    assert.equal(denied.headers["retry-after"], "1");
    assert.equal(operations.length, 8, "ninth request must be denied before any mutation hook");
    assert.equal(fs.existsSync(path.join(root, "admission-nine.txt")), false);
    assert.equal(bridge.inflightMutations, 8, "rejected request does not consume a slot");
    release.resolve();
    const completed = await Promise.all(requests);
    assert.deepEqual(completed.map((result) => result.status), Array(8).fill(201));
    for (let i = 0; i < 8; i++) {
      assert.equal(fs.readFileSync(path.join(root, `admission-${i}.txt`), "utf8"), `BODY_${i}`);
    }
    assert.equal(bridge.inflightMutations, 0, "all admitted requests release resources");
    const admittedAfterRelease = await request(bridge, "PUT", "/admission-nine.txt", {
      data: "NINTH_NOW_ADMITTED",
    });
    assert.equal(admittedAfterRelease.status, 201);
    assert.equal(fs.readFileSync(path.join(root, "admission-nine.txt"), "utf8"),
      "NINTH_NOW_ADMITTED");
    assert.equal(operations.length, 9, "after release the ninth admission must reach hook");
    assert.equal(bridge.inflightMutations, 0);
    assert.deepEqual(trashEntries(root), []);
    noStaging(root);
  } finally {
    release.resolve();
    await Promise.allSettled(requests);
  }
});

async function sourceSwapRace(t, interruptedMethod, competingMethod) {
  const admitted = deferred();
  const release = deferred();
  const hooks = [];
  const { root, bridge } = await fixture(t, async (op) => {
    hooks.push(op);
    if (hooks.length === 1) {
      admitted.resolve(op);
      await release.promise;
    }
  });
  const seen = [];
  const physicalPhases = [];
  const markSeen = bridge.markJournalSeen.bind(bridge);
  const update = bridge.updateJournal.bind(bridge);
  bridge.markJournalSeen = async (operationId) => {
    seen.push(operationId);
    return markSeen(operationId);
  };
  bridge.updateJournal = async (operationId, patch) => {
    physicalPhases.push({ operationId, phase: patch.phase });
    return update(operationId, patch);
  };
  const source = path.join(root, "source.txt");
  const dest = path.join(root, "new-destination.txt");
  fs.writeFileSync(source, ORIGINAL, { mode: 0o600 });
  const oldIdentity = stat(source);
  const first = interruptedMethod === "PUT"
    ? request(bridge, "PUT", "/source.txt", { data: FIRST })
    : interruptedMethod === "MOVE"
      ? request(bridge, "MOVE", "/source.txt",
        { headers: moveHeaders("new-destination.txt") })
      : request(bridge, "DELETE", "/source.txt");
  try {
    const record = await Promise.race([
      admitted.promise,
      first.then((r) => { throw Error(`${interruptedMethod} returned before hook: ${r.status}`); }),
    ]);
    assert.equal(record.kind, interruptedMethod.toLowerCase());
    assert.equal(record.source, "/source.txt");
    assert.equal(hooks.length, 1);
    sameInode(stat(source), oldIdentity);
    assert.equal(fs.readFileSync(source, "utf8"), ORIGINAL);
    if (interruptedMethod === "MOVE") {
      assert.equal(record.trash, null);
      assert.equal(fs.existsSync(dest), false);
    }
    const competitor = competingMethod === "PUT"
      ? await request(bridge, "PUT", "/source.txt", { data: REPLACEMENT })
      : await request(bridge, "DELETE", "/source.txt");
    assert.equal(competitor.status, 204,
      "competing authenticated HTTP writer must succeed before original is released");
    assert.equal(hooks.length, 2);
    assert.equal(hooks[1].kind, competingMethod.toLowerCase());
    if (competingMethod === "PUT") {
      assert.equal(hooks[1].existed, true);
      assert.equal(fs.readFileSync(source, "utf8"), REPLACEMENT);
      assert.notEqual(stat(source).ino, oldIdentity.ino);
    } else {
      assert.equal(fs.existsSync(source), false);
    }
    assert.equal(fs.existsSync(dest), false);
    release.resolve();
    const result = await first;
    assert.equal(result.status, 500,
      `${interruptedMethod} must fail closed on changed pinned source inode`);
    assert.equal(result.body, "Bridge operation failed",
      "only the expected source-identity fail-closed path may satisfy this test");
    assert.deepEqual(seen, [hooks[1].operationId, record.operationId],
      "competing writer commits first, then rejected request marks only its abort");
    assert.equal(physicalPhases.some((patch) => patch.operationId === record.operationId),
      false, "rejected original mutation must never reach physical journal phase");
    assert.equal(physicalPhases.filter((patch) =>
      patch.operationId === hooks[1].operationId
      && patch.phase === "source-moved").length, 1,
    "the competitor must reach its real post-publication journal phase");
    assert.equal(fs.existsSync(dest), false);
    if (competingMethod === "PUT") {
      assert.equal(fs.readFileSync(source, "utf8"), REPLACEMENT);
      const preserved = trashEntries(root).filter((name) => name.startsWith(".rootark-put-"));
      assert.equal(preserved.length, 1);
      assert.equal(fs.readFileSync(path.join(root, ".rootark-trash", preserved[0]), "utf8"), ORIGINAL);
      sameInode(stat(path.join(root, ".rootark-trash", preserved[0])), oldIdentity);
    } else {
      assert.equal(fs.existsSync(source), false);
      const deleteTrash = trashEntries(root).filter((name) =>
        !name.startsWith(".rootark-put-") && !name.startsWith(".rootark-move-"));
      assert.equal(deleteTrash.length, 1);
      assert.equal(fs.readFileSync(path.join(root, ".rootark-trash", deleteTrash[0]), "utf8"),
        ORIGINAL);
      sameInode(stat(path.join(root, ".rootark-trash", deleteTrash[0])), oldIdentity);
    }
    assert.equal(bridge.inflightMutations, 0);
    noStaging(root);
  } finally {
    release.resolve();
    await first.catch(() => {});
  }
}

test("DELETE pinned source rejects concurrent authenticated PUT replacement without deleting it", {
  timeout: 120000,
}, async (t) => sourceSwapRace(t, "DELETE", "PUT"));

test("MOVE pinned source rejects concurrent authenticated PUT replacement without moving it", {
  timeout: 120000,
}, async (t) => sourceSwapRace(t, "MOVE", "PUT"));

test("PUT overwrite pinned original rejects concurrent authenticated DELETE without resurrection", {
  timeout: 120000,
}, async (t) => sourceSwapRace(t, "PUT", "DELETE"));

test("same-instance queued MKCOL wins before legacy directory MOVE, preserving both directory inodes", {
  timeout: 120000,
}, async (t) => {
  const holderEntered = deferred();
  const releaseHolder = deferred();
  const moveEntered = deferred();
  const hooks = [];
  const { root, bridge } = await fixture(t, async (op) => {
    hooks.push(op);
    if (op.kind === "move") moveEntered.resolve(op);
  });
  const source = path.join(root, "source-directory");
  const destination = path.join(root, "new-collection");
  fs.mkdirSync(source, { mode: 0o700 });
  fs.writeFileSync(path.join(source, "child.txt"), ORIGINAL, { mode: 0o600 });
  const original = stat(source);
  const update = bridge.updateJournal.bind(bridge);
  bridge.updateJournal = async (id, patch) => {
    if (patch.phase === "source-moved" && hooks[0]?.operationId === id) {
      holderEntered.resolve();
      await releaseHolder.promise;
    }
    return update(id, patch);
  };
  // First genuinely authenticated PUT enters the lock and pins its physical
  // publication. Queue MKCOL next and MOVE last; this differs from the earlier
  // test that suspended MOVE in onOperation and ran MKCOL without a held lock.
  const holder = request(bridge, "PUT", "/holder.txt", { data: FIRST });
  let mkcol;
  let move;
  try {
    await Promise.race([
      holderEntered.promise,
      holder.then((r) => { throw Error(`HTTP lock holder returned early ${r.status}`); }),
    ]);
    assert.equal(fs.readFileSync(path.join(root, "holder.txt"), "utf8"), FIRST);
    assert.equal(hooks.length, 1);
    const firstTail = bridge.localMutationTail;
    mkcol = request(bridge, "MKCOL", "/new-collection");
    await waitForCondition(() => bridge.localMutationTail !== firstTail,
      "MKCOL actually enqueued behind first HTTP lock holder");
    const mkcolTail = bridge.localMutationTail;
    assert.equal(fs.existsSync(destination), false);
    move = request(bridge, "MOVE", "/source-directory", {
      headers: moveHeaders("new-collection"),
    });
    const operation = await Promise.race([
      moveEntered.promise,
      move.then((r) => { throw Error(`directory MOVE ended before hook ${r.status}`); }),
    ]);
    assert.equal(operation.kind, "move");
    assert.equal(operation.source, "/source-directory");
    assert.equal(operation.destination, "/new-collection");
    assert.equal(operation.trash, null);
    await waitForCondition(() => bridge.localMutationTail !== mkcolTail,
      "MOVE actually enqueued after MKCOL under same per-instance lock");
    assert.equal(fs.existsSync(destination), false);
    sameInode(stat(source), original);
    assert.equal(bridge.inflightMutations, 3);
    releaseHolder.resolve();
    assert.equal((await holder).status, 201);
    assert.equal((await mkcol).status, 201,
      "MKCOL must acquire the lock before directory MOVE");
    const created = stat(destination);
    assert.equal(created.isDirectory(), true);
    assert.deepEqual(fs.readdirSync(destination), []);
    const rejected = await move;
    assert.equal(rejected.status, 500,
      "legacy directory MOVE must fail closed after queued MKCOL creation");
    assert.equal(rejected.body, "Bridge operation failed");
    sameInode(stat(destination), created);
    sameInode(stat(source), original);
    assert.equal(fs.readFileSync(path.join(source, "child.txt"), "utf8"), ORIGINAL);
    assert.deepEqual(fs.readdirSync(destination), []);
    assert.deepEqual(trashEntries(root), []);
    assert.deepEqual(hooks.map((op) => op.kind), ["put", "move"]);
    assert.equal(bridge.inflightMutations, 0);
    noStaging(root);
  } finally {
    releaseHolder.resolve();
    await Promise.allSettled([holder, mkcol, move].filter(Boolean));
  }
});
