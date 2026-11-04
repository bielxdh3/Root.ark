"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const http = require("node:http");
const test = require("node:test");
const { waitForZk10HttpResponse, createZk10HttpResponseLeaseGuard } =
  require("../src/services/zk10LegacyHttpResponseLease");

function response({ finished = false, destroyed = false, ended = false } = {}) {
  const res = new EventEmitter();
  res.writableFinished = finished;
  res.writableEnded = ended;
  res.destroyed = destroyed;
  res.destroyCalls = 0;
  res.destroy = () => {
    res.destroyCalls++;
    res.destroyed = true;
    res.emit("close");
  };
  res.finish = () => {
    res.writableEnded = true;
    res.writableFinished = true;
    res.emit("finish");
  };
  return res;
}

function active(signal) {
  return () => {
    if (signal.aborted) throw new Error("ZK10_LEASE_EXPIRED");
  };
}

async function pendingUntilFinish(res, signal) {
  let settled = "pending";
  const promise = waitForZk10HttpResponse(res, signal, active(signal)).then(
    () => { settled = "resolved"; },
    () => { settled = "rejected"; },
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, "pending", "an unfinished HTTP response cannot release its legacy lease");
  res.finish();
  await promise;
  assert.equal(settled, "resolved");
}

test("ZK10 holds the lease for a streaming response even before writableEnded", async () => {
  const res = response({ ended: false });
  const abort = new AbortController();
  await pendingUntilFinish(res, abort.signal);
  assert.equal(res.destroyCalls, 0);
  assert.equal(res.listenerCount("finish"), 0);
  assert.equal(res.listenerCount("close"), 0);
});

test("ZK10 holds the lease after end but before actual finish", async () => {
  await pendingUntilFinish(response({ ended: true }), new AbortController().signal);
});

test("ZK10 rejects a client close before response finish", async () => {
  const res = response();
  const abort = new AbortController();
  const terminal = waitForZk10HttpResponse(res, abort.signal, active(abort.signal));
  res.destroy();
  await assert.rejects(terminal, /ZK10_RESPONSE_INTERRUPTED/);
  assert.equal(res.listenerCount("finish"), 0);
  assert.equal(res.listenerCount("close"), 0);
});

test("ZK10 closes a live HTTP stream when the external lease expires", async () => {
  const res = response();
  const abort = new AbortController();
  const terminal = waitForZk10HttpResponse(res, abort.signal, active(abort.signal));
  abort.abort();
  await assert.rejects(terminal, /ZK10_LEASE_EXPIRED/);
  assert.equal(res.destroyCalls, 1, "expiry must stop any further data-plane egress");
  assert.equal(res.listenerCount("finish"), 0);
  assert.equal(res.listenerCount("close"), 0);
});

test("ZK10 arms the abort guard BEFORE an asynchronous handler starts streaming", async () => {
  const res = response();
  const abort = new AbortController();
  const guard = createZk10HttpResponseLeaseGuard(res, abort.signal,
    active(abort.signal));
  let handlerCompleted = false;
  // A future handler may keep its Promise unresolved while a stream is open.
  const handler = new Promise((resolve) => setImmediate(() => {
    if (!res.destroyed) res.emit("chunk");
    handlerCompleted = true;
    resolve();
  }));
  abort.abort();
  assert.equal(res.destroyCalls, 1, "expiry must destroy an in-flight stream before handler returns");
  await handler;
  assert.equal(handlerCompleted, true);
  await assert.rejects(guard.waitForFinish(), /ZK10_LEASE_EXPIRED/);
  guard.disarm();
  assert.equal(res.listenerCount("finish"), 0);
  assert.equal(res.listenerCount("close"), 0);
});

test("ZK10 refuses a stream with a pre-expired lease and accepts an already flushed response", async () => {
  const abort = new AbortController();
  abort.abort();
  const streaming = response();
  await assert.rejects(waitForZk10HttpResponse(streaming, abort.signal,
    active(abort.signal)), /ZK10_LEASE_EXPIRED/);
  assert.equal(streaming.destroyCalls, 1);

  const complete = response({ finished: true, ended: true });
  const valid = new AbortController();
  await waitForZk10HttpResponse(complete, valid.signal, active(valid.signal));
  assert.equal(complete.destroyCalls, 0);
  await assert.rejects(waitForZk10HttpResponse(response({ destroyed: true }),
    valid.signal, active(valid.signal)), /ZK10_RESPONSE_INTERRUPTED/);
});

test("ZK10 real HTTP prevents late body bytes even if a busy event loop delays the abort timer", { timeout: 10000 }, async (t) => {
  const server = http.createServer((req, res) => {
    const controller = new AbortController();
    const deadline = Date.now() + 25;
    const timer = setTimeout(() => controller.abort(), 25);
    let guard;
    try {
      guard = createZk10HttpResponseLeaseGuard(res, controller.signal, () => {
        if (controller.signal.aborted || Date.now() >= deadline)
          throw new Error("ZK10_LEASE_EXPIRED");
      });
      const until = Date.now() + 110;
      while (Date.now() < until) { /* deliberately block timers before byte egress */ }
      res.end("DISPOSABLE_LATE_BYTE");
    } catch {
      res.destroy();
    } finally {
      clearTimeout(timer);
      if (guard) {
        guard.waitForFinish().catch(() => {});
        guard.disarm();
      }
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const bytes = [];
  await new Promise((resolve, reject) => {
    const req = http.get({ hostname: "127.0.0.1", port: server.address().port,
      path: "/", agent: false }, (res) => {
      res.on("data", (chunk) => bytes.push(chunk));
      res.once("end", resolve);
      res.once("error", (error) => error.code === "ECONNRESET" ? resolve() : reject(error));
    });
    req.once("error", (error) => error.code === "ECONNRESET" ? resolve() : reject(error));
  });
  assert.equal(Buffer.concat(bytes).length, 0,
    "the physical HTTP client must not receive bytes after external lease deadline");
});

test("ZK10 synchronously rejects every available HTTP egress method at a stale wall-clock deadline", async () => {
  for (const method of ["write", "end", "writeHead", "flushHeaders", "writeContinue",
    "writeProcessing", "writeEarlyHints", "addTrailers", "uncork"]) {
    const res = response();
    let emitted = 0;
    res[method] = () => { emitted++; };
    const abort = new AbortController();
    const deadline = Date.now() + 5;
    const guard = createZk10HttpResponseLeaseGuard(res, abort.signal, () => {
      if (abort.signal.aborted || Date.now() >= deadline)
        throw new Error("ZK10_LEASE_EXPIRED");
    });
    const until = Date.now() + 15;
    while (Date.now() < until) { /* timer-free, no signal.abort() */ }
    assert.equal(abort.signal.aborted, false);
    assert.throws(() => res[method](), /ZK10_LEASE_EXPIRED/, method);
    assert.equal(emitted, 0, `${method} must not pass through to the underlying response`);
    assert.equal(res.destroyCalls, 1, `${method} must close the stream`);
    await assert.rejects(guard.waitForFinish(), /ZK10_RESPONSE_INTERRUPTED/);
    guard.disarm();
  }
});
