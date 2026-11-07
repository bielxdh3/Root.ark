"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createCfapiFetchGate } = require("../sync-client/rootark-sync-windows-cfapi-fetch-gate");

async function fixture(t, gateOptions = {}) {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-fetch-"));
  t.after(() => fs.rm(rootDir, { recursive: true, force: true }));
  await fs.mkdir(path.join(rootDir, "docs"));
  await fs.writeFile(path.join(rootDir, "docs", "file.bin"), "ordinary bytes untouched");
  const calls = { inspect: [], fail: [], transfer: [], register: [] };
  const native = {
    async inspectPlaceholder(relativePath) {
      calls.inspect.push(relativePath);
      return { placeholder: true, reparsePoint: true, syncRootMatch: true };
    },
    async failFetch(key, code) { calls.fail.push({ key, code }); },
    async transferData(...args) { calls.transfer.push(args); throw new Error("TRANSFER FORBIDDEN"); },
    async registerSyncRoot(...args) { calls.register.push(args); throw new Error("REGISTRATION FORBIDDEN"); },
  };
  const gate = createCfapiFetchGate({ rootDir, native, ...gateOptions });
  const request = (overrides = {}) => ({ type: "FETCH_DATA", requestKey: "request-1",
    relativePath: "docs/file.bin", placeholderId: "opaque-object-1", offset: 0,
    length: 16, ...overrides });
  return { rootDir, native, gate, calls, request };
}

test("issue 66 CFAPI: even plausible placeholder metadata never authorizes native transfer", async (t) => {
  const { rootDir, gate, calls, request } = await fixture(t);
  const before = await fs.readFile(path.join(rootDir, "docs", "file.bin"));
  const result = await gate.fetchData(request());
  assert.deepEqual(result, { status: "denied", code: "authority_unavailable" });
  assert.deepEqual(calls.inspect, ["docs/file.bin"]);
  assert.deepEqual(calls.fail, [{ key: "request-1", code: "authority_unavailable" }]);
  assert.deepEqual(calls.transfer, []);
  assert.deepEqual(calls.register, []);
  assert.deepEqual(await fs.readFile(path.join(rootDir, "docs", "file.bin")), before);
});

test("issue 66 CFAPI: forged admission, journal and CAS claims never enable plaintext transfer", async (t) => {
  const { gate, calls, request } = await fixture(t);
  const result = await gate.fetchData(request({
    signedAdmission: true, journalPinned: true, casFloor: 999,
  }));
  assert.equal(result.code, "invalid_callback");
  assert.equal(calls.inspect.length, 0);
  assert.equal(calls.transfer.length, 0);
});

test("issue 66 CFAPI: traversal, ADS, reserved names, path aliases and ranges denied before any native inspection", async (t) => {
  const { gate, calls, request } = await fixture(t);
  const variants = [
    { relativePath: "../escape" }, { relativePath: "/docs/file.bin" },
    { relativePath: "docs\\file.bin" }, { relativePath: "docs/../file.bin" },
    { relativePath: "docs/file.bin:stream" }, { relativePath: "docs/CON.txt" },
    { relativePath: "docs/file.bin." }, { relativePath: "docs/%2e%2e/file.bin" },
    { relativePath: "docs//file.bin" }, { relativePath: "docs/file.bin\u0000other" },
    { offset: -1 }, { offset: Number.MAX_SAFE_INTEGER, length: 2 },
    { offset: 0.3 }, { length: 0 }, { length: 1024 * 1024 + 1 },
    { requestKey: "bad key" }, { placeholderId: "" }, { placeholderId: 999 },
  ];
  for (let i = 0; i < variants.length; i++) {
    const result = await gate.fetchData(request({ requestKey: `bad-${i}`, ...variants[i] }));
    assert.equal(result.code, "invalid_callback", `variant ${i}`);
  }
  assert.deepEqual(calls.inspect, []);
  assert.deepEqual(calls.transfer, []);
});

test("issue 66 CFAPI: links and intermediate directory swaps fail closed without reading target", async (t) => {
  const { rootDir, gate, calls, request } = await fixture(t);
  const sibling = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-outside-"));
  t.after(() => fs.rm(sibling, { recursive: true, force: true }));
  await fs.writeFile(path.join(sibling, "file.bin"), "outside should not be touched");
  const link = path.join(rootDir, "link");
  try { await fs.symlink(sibling, link, process.platform === "win32" ? "junction" : "dir"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) { t.skip("symlink privilege unavailable"); return; }
    throw error;
  }
  assert.equal((await gate.fetchData(request({ relativePath: "link/file.bin" }))).code, "unsafe_path");
  assert.equal(await fs.readFile(path.join(sibling, "file.bin"), "utf8"), "outside should not be touched");
  assert.deepEqual(calls.transfer, []);
  assert.deepEqual(calls.inspect, []);
});

test("issue 66 CFAPI: native inspection must confirm an exact local placeholder", async (t) => {
  const { native, gate, calls, request } = await fixture(t);
  native.inspectPlaceholder = async (relativePath) => {
    calls.inspect.push(relativePath);
    return { placeholder: false, reparsePoint: false, syncRootMatch: false };
  };
  assert.equal((await gate.fetchData(request())).code, "placeholder_untrusted");
  assert.deepEqual(calls.transfer, []);
});

test("issue 66 CFAPI: case-folded Windows path aliases cannot be used as callback identities", { skip: process.platform !== "win32" }, async (t) => {
  const { gate, calls, request } = await fixture(t);
  assert.equal((await gate.fetchData(request({ relativePath: "DOCS/file.bin" }))).code, "unsafe_path");
  assert.equal((await gate.fetchData(request({ relativePath: "docs/FILE.BIN", requestKey: "case-2" }))).code, "unsafe_path");
  assert.deepEqual(calls.inspect, []);
  assert.deepEqual(calls.transfer, []);
});

test("issue 66 CFAPI: missing target, hardlink and hostile callback accessors fail without inspecting or reading bytes", async (t) => {
  const { rootDir, gate, calls, request } = await fixture(t);
  assert.equal((await gate.fetchData(request({ relativePath: "docs/missing.bin" }))).code, "unsafe_path");
  const original = path.join(rootDir, "docs", "file.bin");
  const hardlink = path.join(rootDir, "docs", "linked.bin");
  await fs.link(original, hardlink);
  assert.equal((await gate.fetchData(request({ relativePath: "docs/linked.bin", requestKey: "request-hardlink" }))).code, "unsafe_path");
  assert.equal((await gate.fetchData(request({ requestKey: "request-claimed", placeholderId: { toString() { throw new Error("getter"); } } }))).code, "invalid_callback");
  const hostile = { ...request({ requestKey: "request-accessor" }) };
  Object.defineProperty(hostile, "relativePath", { enumerable: true, get() { throw new Error("must not execute"); } });
  assert.equal((await gate.fetchData(hostile)).code, "invalid_callback");
  assert.deepEqual(calls.inspect, []);
  assert.deepEqual(calls.transfer, []);
});

test("issue 66 CFAPI: native inspection failures and missing failure acknowledgement never report success", async (t) => {
  const { native, gate, calls, request } = await fixture(t);
  native.inspectPlaceholder = async () => { throw new Error("provider disconnected"); };
  assert.equal((await gate.fetchData(request())).code, "unsafe_path");
  assert.equal(calls.fail.length, 1);
  native.failFetch = async () => { throw new Error("native failure ACK missing"); };
  await assert.rejects(gate.fetchData(request({ requestKey: "failure-ack" })), /native failure ACK missing/);
  assert.deepEqual(calls.transfer, []);
});

test("issue 66 CFAPI: cancellation during native inspection prevents authorization", async (t) => {
  const { native, gate, calls, request } = await fixture(t);
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  native.inspectPlaceholder = async () => { await pending; return { placeholder: true, reparsePoint: true, syncRootMatch: true }; };
  const response = gate.fetchData(request());
  assert.equal(gate.cancelFetch("request-1"), true);
  release();
  assert.equal((await response).code, "cancelled");
  assert.deepEqual(calls.transfer, []);
  assert.equal(calls.fail.length, 1);
});

test("issue 66 CFAPI: duplicate request keys are never completed twice and shutdown rejects new callbacks", async (t) => {
  const { native, gate, calls, request } = await fixture(t);
  let release;
  let started;
  const entered = new Promise((resolve) => { started = resolve; });
  native.inspectPlaceholder = () => new Promise((resolve) => { release = resolve; started(); });
  const first = gate.fetchData(request());
  await entered;
  assert.deepEqual(await gate.fetchData(request({ relativePath: "docs/another.bin" })),
    { status: "denied", code: "duplicate_request" });
  const close = gate.shutdown();
  release({ placeholder: true, reparsePoint: true, syncRootMatch: true });
  assert.equal((await first).code, "shutdown");
  await close;
  assert.equal((await gate.fetchData(request({ requestKey: "request-2" }))).code, "shutdown");
  assert.equal(calls.fail.filter((item) => item.key === "request-1").length, 1);
  assert.deepEqual(calls.transfer, []);
  assert.deepEqual(calls.register, []);
});

async function within(promise, milliseconds = 80) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`operation did not settle within ${milliseconds} ms`)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

test("issue 66 W2 P2: cancel drains never-resolving native inspection, aborts signal and fails exactly once", async (t) => {
  const { native, gate, calls, request } = await fixture(t);
  let inspectorSignal;
  let inspectStarted;
  const entered = new Promise((resolve) => { inspectStarted = resolve; });
  native.inspectPlaceholder = (_path, options) => {
    inspectorSignal = options?.signal;
    inspectStarted();
    return new Promise(() => {});
  };
  const first = gate.fetchData(request());
  await within(entered);
  assert.ok(inspectorSignal instanceof AbortSignal, "native inspector must receive a cancelable signal");
  assert.equal(gate.cancelFetch("request-1"), true);
  assert.equal((await within(first)).code, "cancelled");
  await within(gate.shutdown());
  assert.equal(inspectorSignal.aborted, true);
  assert.deepEqual(calls.fail, [{ key: "request-1", code: "cancelled" }]);
  assert.deepEqual(calls.transfer, []);
  assert.deepEqual(calls.register, []);
});

test("issue 66 W2 P2: cooperative inspector receives AbortSignal and rejects without a second ACK", async (t) => {
  const { native, gate, calls, request } = await fixture(t);
  let started;
  const entered = new Promise((resolve) => { started = resolve; });
  let aborts = 0;
  native.inspectPlaceholder = (_relative, { signal }) => new Promise((_, reject) => {
    signal.addEventListener("abort", () => {
      aborts++;
      reject(new Error("cooperatively aborted"));
    }, { once: true });
    started();
  });
  const first = gate.fetchData(request());
  await within(entered);
  assert.equal(gate.cancelFetch("request-1"), true);
  assert.deepEqual(await within(first), { status: "denied", code: "cancelled" });
  await within(gate.shutdown());
  assert.equal(aborts, 1);
  assert.deepEqual(calls.fail, [{ key: "request-1", code: "cancelled" }]);
});

test("issue 66 W2 P2: shutdown drains noncooperative native inspector and rejects all later callbacks", async (t) => {
  const { native, gate, calls, request } = await fixture(t);
  let inspectStarted;
  const entered = new Promise((resolve) => { inspectStarted = resolve; });
  native.inspectPlaceholder = () => { inspectStarted(); return new Promise(() => {}); };
  const first = gate.fetchData(request());
  await within(entered);
  await within(gate.shutdown());
  assert.deepEqual(await within(first), { status: "denied", code: "shutdown" });
  assert.deepEqual(await gate.fetchData(request({ requestKey: "after-stop" })),
    { status: "denied", code: "shutdown" });
  assert.equal(gate.cancelFetch("request-1"), false);
  assert.deepEqual(calls.fail, [{ key: "request-1", code: "shutdown" }]);
});

test("issue 66 W2 P2: idle native inspection reaches deadline and never accepts a late positive result", async (t) => {
  const { native, gate, calls, request } = await fixture(t, { inspectionTimeoutMs: 25 });
  let release;
  let observedSignal;
  native.inspectPlaceholder = (_path, options) => {
    observedSignal = options?.signal;
    return new Promise((resolve) => { release = resolve; });
  };
  const result = await within(gate.fetchData(request()), 150);
  assert.deepEqual(result, { status: "denied", code: "inspection_timeout" });
  assert.equal(observedSignal.aborted, true);
  release({ placeholder: true, reparsePoint: true, syncRootMatch: true });
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(calls.fail, [{ key: "request-1", code: "inspection_timeout" }]);
  assert.deepEqual(calls.transfer, []);
  assert.equal(gate.cancelFetch("request-1"), false);
  assert.deepEqual(await gate.fetchData(request()), { status: "denied", code: "duplicate_request" },
    "do not retry a completed/indeterminate CFAPI request key");
});

test("issue 66 W2 P2: limit accepted callback concurrency and retain unresolved native inspection capacity", async (t) => {
  const { native, gate, calls, request } = await fixture(t,
    { maxInFlight: 2, inspectionTimeoutMs: 1000 });
  const releases = [];
  let started;
  let startedCount = 0;
  const both = new Promise((resolve) => { started = resolve; });
  native.inspectPlaceholder = () => new Promise((resolve) => {
    releases.push(resolve);
    if (++startedCount === 2) started();
  });
  const a = gate.fetchData(request({ requestKey: "one" }));
  const b = gate.fetchData(request({ requestKey: "two" }));
  await within(both);
  assert.deepEqual(await gate.fetchData(request({ requestKey: "overload" })),
    { status: "denied", code: "capacity_exceeded" });
  assert.equal(gate.cancelFetch("one"), true);
  assert.equal(gate.cancelFetch("two"), true);
  assert.equal((await within(a)).code, "cancelled");
  assert.equal((await within(b)).code, "cancelled");
  assert.deepEqual(await within(gate.fetchData(request({ requestKey: "three" }))),
    { status: "denied", code: "inspector_capacity_exceeded" },
    "orphaned native promises must continue consuming the bounded inspector budget");
  assert.equal(releases.length, 2);
  releases.forEach((release) => release({ placeholder: true, reparsePoint: true, syncRootMatch: true }));
  await within(gate.shutdown());
  assert.deepEqual(calls.fail.map((item) => item.key).sort(), ["one", "three", "two"]);
  assert.deepEqual(calls.transfer, []);
});

test("issue 66 W2 P2: an unresolved path lstat also consumes the bounded inspector budget", async (t) => {
  const { rootDir, gate, calls, request } = await fixture(t,
    { maxInFlight: 1, inspectionTimeoutMs: 1000 });
  const actualLstat = fs.lstat;
  let started;
  const entered = new Promise((resolve) => { started = resolve; });
  fs.lstat = (candidate, ...args) => {
    if (candidate === rootDir) {
      started();
      return new Promise(() => {});
    }
    return actualLstat(candidate, ...args);
  };
  try {
    const first = gate.fetchData(request());
    await within(entered);
    assert.equal(gate.cancelFetch("request-1"), true);
    assert.equal((await within(first)).code, "cancelled");
    assert.deepEqual(await within(gate.fetchData(request({ requestKey: "second" }))),
      { status: "denied", code: "inspector_capacity_exceeded" });
    await within(gate.shutdown());
  } finally { fs.lstat = actualLstat; }
  assert.deepEqual(calls.fail.map((entry) => entry.key), ["request-1", "second"]);
  assert.deepEqual(calls.inspect, []);
});

test("issue 66 W2 P2: even stalled failure acknowledgement cannot block callback or shutdown forever", async (t) => {
  const { native, gate, request, calls } = await fixture(t, { ackTimeoutMs: 25 });
  let acks = 0;
  let ackSignal;
  native.failFetch = (_key, _code, options) => {
    ++acks;
    ackSignal = options?.signal;
    return new Promise(() => {});
  };
  const result = await within(gate.fetchData(request()), 150);
  assert.deepEqual(result, { status: "denied", code: "failure_ack_timeout" });
  assert.equal(acks, 1);
  assert.equal(ackSignal.aborted, true);
  await within(gate.shutdown());
  assert.deepEqual(await gate.fetchData(request({ requestKey: "another" })),
    { status: "denied", code: "shutdown" });
  assert.deepEqual(calls.transfer, []);
});

test("issue 66 W2 P2: invalid timeout/concurrency options fail before constructing boundary", async (t) => {
  const { rootDir, native } = await fixture(t);
  for (const invalid of [
    { inspectionTimeoutMs: 0 }, { inspectionTimeoutMs: Infinity },
    { inspectionTimeoutMs: -1 }, { inspectionTimeoutMs: 300001 },
    { ackTimeoutMs: 0 }, { ackTimeoutMs: Infinity },
    { ackTimeoutMs: 300001 }, { maxInFlight: 0 },
    { maxInFlight: 100000 }, { maxInFlight: 1.5 },
    { maxLifetimeRequests: 0 }, { maxLifetimeRequests: 4097 },
  ]) {
    assert.throws(() => createCfapiFetchGate({ rootDir, native, ...invalid }),
      { code: "invalid_cfapi_boundary" });
  }
});

test("issue 66 W2 P2: lifetime request-key budget quarantines boundary without reusing retired keys", async (t) => {
  const { gate, request, calls } = await fixture(t, { maxLifetimeRequests: 2 });
  assert.equal((await gate.fetchData(request({ requestKey: "first" }))).code, "authority_unavailable");
  assert.equal((await gate.fetchData(request({ requestKey: "second" }))).code, "authority_unavailable");
  assert.deepEqual(await gate.fetchData(request({ requestKey: "third" })),
    { status: "denied", code: "capacity_exceeded" });
  assert.deepEqual(await gate.fetchData(request({ requestKey: "fourth" })),
    { status: "denied", code: "shutdown" });
  assert.deepEqual(calls.fail.map((entry) => entry.key), ["first", "second"]);
  await within(gate.shutdown());
});
