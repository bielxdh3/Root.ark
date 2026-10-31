"use strict";

// TEST_UNRUN: requires the exclusive Node22 gate (NODE_COUNT==0,
// RAM >=4096 MiB and exclusive owner). These are real loopback HTTP races:
// first request observes ENOENT, waits in onOperation, then another authenticated
// HTTP request creates the destination before the first is allowed to continue.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-no-clobber-disposable-only";
const FIRST_PUT = "FIRST_HTTP_PUT_MUST_NOT_CLOBBER";
const MOVE_SOURCE = "FIRST_HTTP_MOVE_SOURCE";
const FOREIGN = "SECOND_INDEPENDENT_HTTP_WRITER_MUST_SURVIVE";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function setup(t, onOperation) {
  const parent = createPrivateAuthorityFixture("cos-pr235-noclobber-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root, token: TOKEN, port: 0, onOperation,
  });
  t.after(async () => {
    await bridge.stop();
    fs.rmSync(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  return { root, bridge };
}

function request(bridge, method, pathname, { headers = {}, data } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1", port: bridge.address().port, method,
      path: pathname, headers: { authorization: `Bearer ${TOKEN}`, ...headers },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.setTimeout(30000, () => req.destroy(new Error(`Timed out: ${method}`)));
    req.on("error", reject);
    req.end(data);
  });
}

test("uncontended authenticated HTTP PUT creates the exact requested bytes", {
  timeout: 120000,
}, async (t) => {
  const observed = [];
  const { root, bridge } = await setup(t, async (operation) => {
    observed.push(operation);
  });
  const target = path.join(root, "control-create.txt");
  assert.equal(fs.existsSync(target), false);
  const response = await request(bridge, "PUT", "/control-create.txt", {
    data: FIRST_PUT,
  });
  assert.equal(response.status, 201, "uncontended create must succeed");
  assert.equal(fs.readFileSync(target, "utf8"), FIRST_PUT);
  assert.equal(observed.length, 1);
  assert.equal(observed[0].kind, "put");
  assert.equal(observed[0].existed, false);
  assert.deepEqual(fs.readdirSync(path.join(root, ".rootark-trash")), []);
});

test("uncontended authenticated HTTP MOVE Overwrite:F moves the exact source", {
  timeout: 120000,
}, async (t) => {
  const observed = [];
  const { root, bridge } = await setup(t, async (operation) => {
    observed.push(operation);
  });
  const source = path.join(root, "control-source.txt");
  const target = path.join(root, "control-moved.txt");
  fs.writeFileSync(source, MOVE_SOURCE, { mode: 0o600 });
  const oldIdentity = fs.lstatSync(source, { bigint: true });
  assert.equal(fs.existsSync(target), false);
  const response = await request(bridge, "MOVE", "/control-source.txt", {
    headers: { destination: "http://127.0.0.1/control-moved.txt", overwrite: "F" },
  });
  assert.equal(response.status, 201, "uncontended MOVE with absent destination must succeed");
  assert.equal(fs.existsSync(source), false);
  assert.equal(fs.readFileSync(target, "utf8"), MOVE_SOURCE);
  const newIdentity = fs.lstatSync(target, { bigint: true });
  assert.equal(newIdentity.dev, oldIdentity.dev);
  assert.equal(newIdentity.ino, oldIdentity.ino);
  assert.equal(observed.length, 1);
  assert.equal(observed[0].kind, "move");
  assert.equal(observed[0].trash, null);
  assert.deepEqual(fs.readdirSync(path.join(root, ".rootark-trash")), []);
});

test("uncontended legacy directory MOVE Overwrite:F succeeds before raced MKCOL control", {
  timeout: 120000,
}, async (t) => {
  const observed = [];
  const { root, bridge } = await setup(t, async (operation) => {
    observed.push(operation);
  });
  const source = path.join(root, "control-directory");
  const destination = path.join(root, "control-directory-destination");
  fs.mkdirSync(source, { mode: 0o700 });
  fs.writeFileSync(path.join(source, "owned.txt"), MOVE_SOURCE, { mode: 0o600 });
  const original = fs.lstatSync(source, { bigint: true });
  assert.equal(fs.existsSync(destination), false);
  const response = await request(bridge, "MOVE", "/control-directory", {
    headers: {
      destination: "http://127.0.0.1/control-directory-destination", overwrite: "F",
    },
  });
  assert.equal(response.status, 201, "an uncontended legacy directory rename must work");
  assert.equal(fs.existsSync(source), false);
  assert.equal(fs.readFileSync(path.join(destination, "owned.txt"), "utf8"), MOVE_SOURCE);
  const moved = fs.lstatSync(destination, { bigint: true });
  assert.equal(moved.isDirectory(), true);
  assert.equal(moved.dev, original.dev);
  assert.equal(moved.ino, original.ino);
  assert.equal(observed.length, 1);
  assert.equal(observed[0].kind, "move");
  assert.equal(observed[0].trash, null);
  assert.deepEqual(fs.readdirSync(path.join(root, ".rootark-trash")), []);
});

async function assertNoClobberAfterConcurrentHttpPut(t, firstMethod) {
  const entered = deferred();
  const release = deferred();
  const observed = [];
  const { root, bridge } = await setup(t, async (operation) => {
    observed.push(operation);
    if (observed.length === 1) {
      entered.resolve(operation);
      await release.promise;
    }
  });
  const destination = path.join(root, "destination.txt");
  const source = path.join(root, "source.txt");
  if (firstMethod === "MOVE") {
    fs.writeFileSync(source, MOVE_SOURCE, { mode: 0o600 });
  }
  assert.equal(fs.existsSync(destination), false, "destination must start ENOENT");

  const first = firstMethod === "PUT"
    ? request(bridge, "PUT", "/destination.txt", { data: FIRST_PUT })
    : request(bridge, "MOVE", "/source.txt", {
      headers: {
        destination: "http://127.0.0.1/destination.txt",
        overwrite: "F",
      },
    });

  try {
    // Wait for actual first HTTP ingress and its already computed ENOENT
    // decision. An early 4xx/5xx must fail instead of producing false GREEN.
    const operation = await Promise.race([
      entered.promise,
      first.then(
        (response) => { throw new Error(`First HTTP returned before barrier: ${response.status}`); },
        (error) => { throw error; },
      ),
    ]);
    assert.equal(operation.kind, firstMethod.toLowerCase());
    assert.equal(operation.destination, "/destination.txt");
    if (firstMethod === "PUT") {
      assert.equal(operation.existed, false,
        "first PUT must have selected its create path before the second writer");
    } else {
      assert.equal(operation.trash, null,
        "first MOVE must have selected destination-absent path with Overwrite:F");
    }
    assert.equal(observed.length, 1);
    assert.equal(fs.existsSync(destination), false,
      "first request is paused before installing any destination");

    // This is a second authenticated HTTP writer, not a mocked rename or
    // a direct fixture write. It must complete while the first is suspended.
    const second = await request(bridge, "PUT", "/destination.txt", {
      data: FOREIGN,
    });
    assert.equal(second.status, 201,
      "the competing HTTP PUT must actually install the new destination");
    assert.equal(observed.length, 2, "both operations must traverse HTTP onOperation");
    assert.equal(observed[1].kind, "put");
    assert.equal(observed[1].existed, false);
    assert.equal(fs.readFileSync(destination, "utf8"), FOREIGN);
    const foreignIdentity = fs.lstatSync(destination, { bigint: true });
    assert.equal(foreignIdentity.isFile(), true);

    // Link-exclusivity must cause EEXIST (mapped by the HTTP handler to 405),
    // never an unrelated 500 that could otherwise give a false GREEN.
    release.resolve();
    const result = await first;
    assert.equal(result.status, 405,
      `first ${firstMethod} must fail by exclusive-link EEXIST, not another error`);
    assert.match(result.body, /EEXIST/,
      "HTTP conflict must originate from an existing destination entry");
    assert.equal(fs.readFileSync(destination, "utf8"), FOREIGN,
      "original request must not overwrite the competing writer's bytes");
    const finalIdentity = fs.lstatSync(destination, { bigint: true });
    assert.equal(finalIdentity.dev, foreignIdentity.dev);
    assert.equal(finalIdentity.ino, foreignIdentity.ino,
      "the exact independently installed destination inode must survive");
    if (firstMethod === "MOVE") {
      assert.equal(fs.readFileSync(source, "utf8"), MOVE_SOURCE,
        "failed MOVE must preserve the original source");
    }
    assert.deepEqual(fs.readdirSync(path.join(root, ".rootark-trash")), [],
      "conflict must leave no staged original or unrelated trash entries");
    assert.equal(fs.readdirSync(root).some((name) => name.startsWith(".rootark-put-")),
      false, "failed PUT must not leave its owned staging pathname behind");
  } finally {
    release.resolve();
    await first.catch(() => {});
  }
}

test("HTTP PUT create cannot replace destination installed by second HTTP PUT during onOperation", {
  timeout: 120000,
}, async (t) => {
  await assertNoClobberAfterConcurrentHttpPut(t, "PUT");
});

test("HTTP MOVE Overwrite:F cannot replace new destination installed during onOperation", {
  timeout: 120000,
}, async (t) => {
  await assertNoClobberAfterConcurrentHttpPut(t, "MOVE");
});

test("legacy directory MOVE Overwrite:F cannot clobber concurrent HTTP MKCOL destination", {
  timeout: 120000,
}, async (t) => {
  const entered = deferred();
  const release = deferred();
  const observed = [];
  const { root, bridge } = await setup(t, async (operation) => {
    observed.push(operation);
    if (observed.length === 1) {
      entered.resolve(operation);
      await release.promise;
    }
  });
  const source = path.join(root, "original-directory");
  const destination = path.join(root, "raced-directory");
  fs.mkdirSync(source, { mode: 0o700 });
  fs.writeFileSync(path.join(source, "owned.txt"), MOVE_SOURCE, { mode: 0o600 });
  const sourceIdentity = fs.lstatSync(source, { bigint: true });
  assert.equal(fs.existsSync(destination), false);
  const first = request(bridge, "MOVE", "/original-directory", {
    headers: { destination: "http://127.0.0.1/raced-directory", overwrite: "F" },
  });
  try {
    // Fail instead of silently passing when a changed source rejects the
    // legacy directory MOVE before this genuine HTTP admission barrier.
    const operation = await Promise.race([
      entered.promise,
      first.then(
        (response) => { throw new Error(`Legacy MOVE returned before barrier: ${response.status}`); },
        (error) => { throw error; },
      ),
    ]);
    assert.equal(operation.kind, "move");
    assert.equal(operation.source, "/original-directory");
    assert.equal(operation.destination, "/raced-directory");
    assert.equal(operation.trash, null);
    assert.equal(observed.length, 1);
    assert.equal(fs.existsSync(destination), false);

    // MKCOL must complete while the first MOVE is still blocked; mutation
    // lock acquisition begins AFTER onOperation in the legacy bridge.
    const second = await request(bridge, "MKCOL", "/raced-directory");
    assert.equal(second.status, 201, "concurrent authenticated MKCOL must succeed");
    assert.equal(observed.length, 1, "MKCOL has no legacy journal callback");
    const created = fs.lstatSync(destination, { bigint: true });
    assert.equal(created.isDirectory(), true);
    assert.deepEqual(fs.readdirSync(destination), [], "MKCOL must create an empty collection");

    release.resolve();
    const result = await first;
    // Legacy directory rename has no atomic NOREPLACE variant. The current
    // fail-closed reoccupation fence reports this exact indeterminate state
    // as HTTP 500; 201 or 204 would silently overwrite MKCOL's collection.
    assert.equal(result.status, 500,
      "legacy MOVE must reject a destination occupied after onOperation");
    assert.equal(result.body, "Bridge operation failed");
    const after = fs.lstatSync(destination, { bigint: true });
    assert.equal(after.isDirectory(), true);
    assert.equal(after.dev, created.dev);
    assert.equal(after.ino, created.ino,
      "the exact independently created MKCOL inode must survive MOVE");
    assert.deepEqual(fs.readdirSync(destination), []);
    const sourceAfter = fs.lstatSync(source, { bigint: true });
    assert.equal(sourceAfter.dev, sourceIdentity.dev);
    assert.equal(sourceAfter.ino, sourceIdentity.ino);
    assert.equal(fs.readFileSync(path.join(source, "owned.txt"), "utf8"), MOVE_SOURCE);
    assert.deepEqual(fs.readdirSync(path.join(root, ".rootark-trash")), [],
      "rejected directory MOVE must not create a stray backup");
  } finally {
    release.resolve();
    await first.catch(() => {});
  }
});
