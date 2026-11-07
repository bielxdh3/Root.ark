"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createCfapiFetchGate } = require("../sync-client/rootark-sync-windows-cfapi-fetch-gate");

async function fixture(t) {
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
  const gate = createCfapiFetchGate({ rootDir, native });
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
