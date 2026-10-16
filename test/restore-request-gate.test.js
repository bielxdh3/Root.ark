const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createRestoreRequestGate } = require("../services/restoreRequestGate");

function mockResponse() {
  const response = new EventEmitter();
  response.statusCode = null;
  response.headers = {};
  response.body = null;
  response.status = (code) => { response.statusCode = code; return response; };
  response.set = (name, value) => { response.headers[name] = value; return response; };
  response.json = (body) => { response.body = body; return response; };
  return response;
}

function withLeaseDirectory(body) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-request-gate-"));
  try { body(directory); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test("restore request gate rejects new requests while a coordinator blocks service", () => {
  withLeaseDirectory((directory) => {
    const gate = createRestoreRequestGate({ directory, isBlocked: () => true });
    const response = mockResponse();
    let continued = false;
    gate.middleware({}, response, () => { continued = true; });
    assert.equal(response.statusCode, 503);
    assert.equal(response.headers["Retry-After"], "30");
    assert.equal(response.body.recoveryRequired, true);
    assert.match(response.body.error, /Reinicie todas as instâncias/);
    assert.equal(continued, false);
    assert.deepEqual(fs.readdirSync(directory), []);
  });
});

test("restore request gate records active requests and releases their lease on response completion", () => {
  withLeaseDirectory((directory) => {
    const gate = createRestoreRequestGate({ directory, isBlocked: () => false });
    const request = {};
    const response = mockResponse();
    let continued = false;
    gate.middleware(request, response, () => { continued = true; });
    assert.equal(continued, true);
    assert.equal(fs.readdirSync(directory).length, 1);
    response.emit("finish");
    assert.deepEqual(fs.readdirSync(directory), []);
  });
});

test("restore quiescence waits for other active requests but excludes the restore request", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-request-drain-"));
  try {
    const gate = createRestoreRequestGate({ directory, isBlocked: () => false });
    const restoreLease = path.join(directory, "restore.json");
    const activeLease = path.join(directory, "active.json");
    fs.writeFileSync(restoreLease, JSON.stringify({ pid: process.pid }));
    fs.writeFileSync(activeLease, JSON.stringify({ pid: process.pid }));
    const wait = gate.waitForQuiescence(restoreLease, 1000);
    setTimeout(() => fs.rmSync(activeLease, { force: true }), 75);
    await wait;
    assert.equal(fs.existsSync(restoreLease), true);
    assert.equal(fs.existsSync(activeLease), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("restore quiescence drains background work held by an operation lease", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-worker-drain-"));
  try {
    let blocked = false;
    const gate = createRestoreRequestGate({ directory, isBlocked: () => blocked });
    let finishWork;
    let enteredWork;
    const entered = new Promise((resolve) => { enteredWork = resolve; });
    const work = gate.run(async () => {
      enteredWork();
      await new Promise((resolve) => { finishWork = resolve; });
    });
    await entered;
    blocked = true;
    let drained = false;
    const drain = gate.waitForQuiescence(null, 1000).then(() => { drained = true; });
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(drained, false, "restore must wait for background work already in progress");
    finishWork();
    await Promise.all([work, drain]);
    assert.equal(drained, true);
    assert.deepEqual(fs.readdirSync(directory), []);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("stale shared-volume leases fail closed and are not removed using local PID checks", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-stale-lease-"));
  const staleLease = path.join(directory, "remote-process-lease.json");
  try {
    const gate = createRestoreRequestGate({ directory, isBlocked: () => true });
    fs.writeFileSync(staleLease, JSON.stringify({ pid: 2147483000, createdAt: "2026-01-01T00:00:00.000Z" }));
    await assert.rejects(gate.waitForQuiescence(null, 1000), (error) => error.code === "RESTORE_QUIESCE_TIMEOUT");
    assert.equal(fs.existsSync(staleLease), true, "PID namespaces cannot establish ownership across shared volumes");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
