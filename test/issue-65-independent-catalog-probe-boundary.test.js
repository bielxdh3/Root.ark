"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname,
  "../public/client/rootark-zk1-authenticated-workspace.js"), "utf8");
const exposed = source.replace(/\n}\(\)\);\s*$/, "\n  window.testCatalog = { independentCatalogEndpoint, independentCatalogProbe };\n}());");
assert.notEqual(exposed, source, "the fixture must execute the actual browser implementation");

function browser(fetchImpl, options = {}) {
  const window = { RootarkApi: {}, addEventListener() {} };
  const timeouts = [];
  const context = { window, fetch: fetchImpl, URL, TextDecoder, Uint8Array,
    AbortController, btoa, atob, setTimeout(fn, delay) {
      timeouts.push(delay);
      return setTimeout(fn, options.accelerateTimeout ? 60 : delay);
    }, clearTimeout };
  vm.runInNewContext(exposed, context, { timeout: 2000 });
  return { ...window.testCatalog, timeouts };
}

function response(body, headers = { "content-type": "application/cbor" }) {
  return {
    status: 200, headers: { get: (key) => headers[key] ?? null }, body,
    arrayBuffer() { throw new Error("unbounded arrayBuffer must never be called"); },
  };
}

function stream(parts, hooks = {}) {
  let index = 0;
  return { getReader() {
    return {
      async read() {
        hooks.onRead?.();
        return index === parts.length ? { done: true } : { done: false, value: parts[index++] };
      },
      cancel() { hooks.onCancel?.(); },
      releaseLock() {},
    };
  } };
}

const scope = { account_id: "owner", compartment_id: "private", keyring_id: "vault" };
const nonce = new Uint8Array(32);

async function settledWithin(promise, milliseconds = 450) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("probe hung beyond test deadline")), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

test("independent catalog URL rejects same-origin, insecure, credentials and noncanonical paths", () => {
  const { independentCatalogEndpoint: endpoint } = browser(() => { throw new Error("unused"); });
  assert.equal(endpoint("https://cas.example/probe", "https://root.example").href,
    "https://cas.example/probe");
  assert.equal(endpoint("http://127.0.0.1:8081/probe", "https://root.example").protocol, "http:");
  for (const invalid of ["https://root.example/probe", "http://cas.example/probe",
    "https://cas.example/", "https://cas.example/a/../probe",
    "https://cas.example/probe?token=oops", "https://u:p@cas.example/probe",
    "https://cas.example/probe#fragment", "https://cas.example:443/probe"]) {
    assert.throws(() => endpoint(invalid, "https://root.example"), /ZK_WORKSPACE_INPUT_DENIED/);
  }
});

test("direct browser catalog probe reads bounded chunks and preserves cross-origin anonymous POST", async () => {
  let called = 0, observed;
  const bytes = [new Uint8Array(3), new Uint8Array(8189)];
  const { independentCatalogProbe: probe } = browser(async (url, init) => {
    observed = { url, init };
    return response(stream(bytes, { onRead: () => { called++; } }),
      { "content-type": "application/cbor; charset=binary", "content-length": "1" });
  });
  const raw = await probe(new URL("https://cas.example/probe"), () => {})({ scope, nonce });
  assert.equal(raw.length, 8192);
  assert.equal(called, 3, "incremental read and end-of-stream");
  assert.equal(observed.url, "https://cas.example/probe");
  assert.equal(observed.init.method, "POST");
  assert.equal(observed.init.mode, "cors");
  assert.equal(observed.init.credentials, "omit");
  assert.equal(observed.init.redirect, "error");
  assert.equal(observed.init.referrerPolicy, "no-referrer");
  assert.equal(observed.init.headers.accept, "application/cbor");
  assert.equal(JSON.parse(observed.init.body).scope.account_id, scope.account_id);
  assert.ok(observed.init.signal instanceof AbortSignal);
});

test("historical snapshot probe binds exact sequence without cookies and enforces its larger bounded CBOR limit", async () => {
  let observed;
  const { independentCatalogProbe: probe } = browser(async (url, init) => {
    observed = { url, init };
    return response(stream([new Uint8Array(8193)]),
      { "content-type": "application/cbor", "content-length": "8193" });
  });
  const endpoint = probe(new URL("https://historical-cas.example/snapshot"), () => {}, true);
  const bytes = await endpoint({ scope, nonce, sequence: 3 });
  assert.equal(bytes.length, 8193, "historical snapshot may exceed 8192-byte head receipts");
  assert.deepEqual(JSON.parse(observed.init.body), {
    scope, nonceBase64: Buffer.alloc(32).toString("base64url"), sequence: 3 });
  assert.equal(observed.init.credentials, "omit");
  assert.equal(observed.init.referrerPolicy, "no-referrer");
  await assert.rejects(endpoint({ scope, nonce, sequence: 129 }), /ZK_WORKSPACE_INPUT_DENIED/);
  let canceled = false;
  const bad = browser(async () => response(stream([
    new Uint8Array(3 * 1024 * 1024), new Uint8Array(1),
  ], { onCancel() { canceled = true; } })));
  await assert.rejects(bad.independentCatalogProbe(new URL("https://historical-cas.example/snapshot"),
    () => {}, true)({ scope, nonce, sequence: 3 }), /ZK_WORKSPACE_INPUT_DENIED/);
  assert.equal(canceled, true);
});

test("lying Content-Length cannot bypass streamed 8192-byte proof limit", async () => {
  let reads = 0, canceled = false;
  const { independentCatalogProbe: probe } = browser(async () => response(stream([
    new Uint8Array(4096), new Uint8Array(4096), new Uint8Array(1), new Uint8Array(4096),
  ], { onRead: () => { reads++; }, onCancel: () => { canceled = true; } }),
  { "content-type": "application/cbor", "content-length": "1" }));
  await assert.rejects(probe(new URL("https://cas.example/probe"), () => {})({ scope, nonce }),
    /ZK_WORKSPACE_INPUT_DENIED/);
  assert.equal(reads, 3, "reject at first oversized chunk without draining attacker body");
  assert.equal(canceled, true);
});

test("direct cross-origin probe aborts stalled headers and stalled chunked bodies by absolute deadline", async () => {
  let headerSignal, bodySignal, cancelCount = 0;
  const first = browser((_url, init) => {
    headerSignal = init.signal;
    return new Promise(() => {});
  }, { accelerateTimeout: true });
  await assert.rejects(settledWithin(first.independentCatalogProbe(new URL("https://cas.example/probe"),
    () => {})({ scope, nonce })), /ZK_WORKSPACE_INPUT_DENIED/);
  assert.equal(headerSignal.aborted, true);
  assert.equal(first.timeouts.length, 1);

  const second = browser((_url, init) => {
    bodySignal = init.signal;
    return Promise.resolve(response({ getReader() {
      let index = 0;
      return { read() {
        if (index++ === 0) return Promise.resolve({ done: false, value: new Uint8Array(2) });
        return new Promise(() => {});
      }, cancel() { cancelCount++; }, releaseLock() {} };
    } }));
  }, { accelerateTimeout: true });
  await assert.rejects(settledWithin(second.independentCatalogProbe(new URL("https://cas.example/probe"),
    () => {})({ scope, nonce })), /ZK_WORKSPACE_INPUT_DENIED/);
  assert.equal(bodySignal.aborted, true);
  assert.ok(cancelCount > 0, "reader cancellation releases a stalled response body");
  assert.equal(second.timeouts.length, 1);
});

test("bad MIME, empty chunks, missing stream and expired session fail closed", async () => {
  for (const factory of [
    () => response(stream([new Uint8Array(1)]), { "content-type": "text/html" }),
    () => response(stream([new Uint8Array(0)])),
    () => response(null),
  ]) {
    const { independentCatalogProbe: probe } = browser(async () => factory());
    await assert.rejects(probe(new URL("https://cas.example/probe"), () => {})({ scope, nonce }),
      /ZK_WORKSPACE_INPUT_DENIED/);
  }
  let live = true;
  const { independentCatalogProbe: probe } = browser(async () => response(stream([
    new Uint8Array(3), new Uint8Array(4),
  ], { onRead() { live = false; } })));
  await assert.rejects(probe(new URL("https://cas.example/probe"), () => {
    if (!live) throw new Error("session ended");
  })({ scope, nonce }), /session ended/);
});

const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
test("Edge cross-origin CORS: oversized chunked CBOR and stalled body deny without cookies", {
  timeout: 35_000, skip: process.platform !== "win32" || !fs.existsSync(EDGE),
}, async (t) => {
  const requests = [];
  const authority = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "content-type");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Cache-Control", "no-store");
    if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
    requests.push({ method: req.method, cookie: req.headers.cookie,
      authorization: req.headers.authorization });
    res.writeHead(200, { "Content-Type": "application/cbor" });
    if (req.url === "/huge") {
      res.write(Buffer.alloc(4096));
      res.write(Buffer.alloc(4096));
      res.end(Buffer.alloc(100));
    } else {
      res.write(Buffer.from([0xa1, 0x61]));
      // A peer can withhold the final chunk forever. Browser abort closes it.
    }
  });
  await new Promise((resolve) => authority.listen(0, "127.0.0.1", resolve));
  t.after(() => { authority.closeAllConnections(); authority.close(); });
  const authorityOrigin = `http://127.0.0.1:${authority.address().port}`;
  const script = `window.RootarkApi = {};
    const nativeTimeout = window.setTimeout.bind(window);
    window.setTimeout = (fn, ms, ...args) => nativeTimeout(fn, ms === 10000 ? 250 : ms, ...args);
    const originalFetch = window.fetch.bind(window), signals = [];
    window.fetch = (url, options) => { signals.push(options.signal);
      return originalFetch(url, options); };
    async function check(name) {
      try { await window.testCatalog.independentCatalogProbe(
        new URL(${JSON.stringify(authorityOrigin)} + name), () => {})({
          scope: ${JSON.stringify(scope)}, nonce: new Uint8Array(32),
        }); return "ACCEPTED";
      } catch (error) { return error.message === "ZK_WORKSPACE_INPUT_DENIED" ? "DENIED" : "ERROR"; }
    }
    (async () => {
      const huge = await check("/huge"), stalled = await check("/stall");
      document.getElementById("result").textContent =
        [huge, stalled, signals.every(s => s?.aborted) ? "ABORTED" : "NOT_ABORTED"].join(",");
    })();`;
  const server = http.createServer((req, res) => {
    if (req.url === "/probe.js") {
      res.writeHead(200, { "Content-Type": "text/javascript", "Cache-Control": "no-store" });
      res.end(exposed);
    } else {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end('<!doctype html><output id="result">PENDING</output><script src="/probe.js"></script>'
        + `<script>${script}</script>`);
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-probe-edge-"));
  t.after(() => fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const html = await new Promise((resolve, reject) => {
    const edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--disable-extensions",
      "--no-first-run", `--user-data-dir=${path.join(profile, "profile")}`,
      "--virtual-time-budget=7000", "--dump-dom", origin],
    { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    const chunks = [];
    let bytes = 0, finished = false;
    const timer = setTimeout(() => { edge.kill(); done(new Error("Edge timed out")); }, 25000);
    function done(error, result) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(result);
    }
    edge.stdout.on("data", (part) => {
      bytes += part.length;
      if (bytes > 262144) { edge.kill(); done(new Error("Edge output too large")); }
      else chunks.push(part);
    });
    edge.stderr.resume();
    edge.once("error", done);
    edge.once("exit", (code) => done(code ? new Error(`Edge exited ${code}`) : null,
      Buffer.concat(chunks).toString("utf8")));
  });
  assert.match(html, /<output id="result">DENIED,DENIED,ABORTED<\/output>/);
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.method, "POST");
    assert.equal(request.cookie, undefined);
    assert.equal(request.authorization, undefined);
  }
});
