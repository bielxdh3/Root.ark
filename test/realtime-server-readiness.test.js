"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const http = require("node:http");
const test = require("node:test");
const { waitForFixtureListen, request, stop } = require("./support/realtime-server-readiness");

function fixture() {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.exitCode = null;
  child.signalCode = null;
  const controller = new AbortController();
  return { child, controller, ready: waitForFixtureListen(child, 43210, controller.signal) };
}

test("realtime readiness waits for the owned child announcement, including split lines", async () => {
  const { child, ready } = fixture();
  let resolved = false;
  ready.then(() => { resolved = true; });
  child.stdout.write("unrelated startup output\n");
  child.stdout.write("Servidor rodando em http://127.0.0.1:");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(resolved, false);
  child.stdout.write("43210\r\n");
  await ready;
  assert.equal(resolved, true);
  assert.equal(child.listenerCount("exit"), 0);
  assert.equal(child.listenerCount("error"), 0);
  child.stdout.end();
});

test("realtime readiness rejects a different child-announced port", async () => {
  const { child, ready } = fixture();
  const denied = assert.rejects(ready, /unexpected port/);
  child.stdout.write("Servidor rodando em http://[::]:43211\n");
  await denied;
  child.stdout.end();
});

test("realtime readiness rejects child exit and the existing test deadline", async () => {
  const first = fixture();
  const exited = assert.rejects(first.ready, /exited before announcing readiness/);
  first.child.emit("exit", 1);
  await exited;
  first.child.stdout.end();
  const second = fixture();
  const aborted = assert.rejects(second.ready, /readiness aborted/);
  second.controller.abort();
  await aborted;
  second.child.stdout.end();
});

test("realtime teardown never signals a child which has already exited by signal", async () => {
  const child = new EventEmitter();
  child.pid = 123;
  child.exitCode = null;
  child.signalCode = "SIGTERM";
  child.kill = () => { throw new Error("already exited"); };
  await stop(child);
  assert.equal(child.listenerCount("exit"), 0);
});

test("realtime readiness rejects a stdout pipe error without exposing its message", async (t) => {
  const { child, controller, ready } = fixture();
  const outcome = ready.then(() => null, (error) => error);
  t.after(() => { controller.abort(); child.stdout.end(); });
  assert.doesNotThrow(() => child.stdout.emit("error", new Error("private child output")));
  assert.match((await outcome).message, /^fixture stdout read failed$/);
});

test("realtime teardown reports a stdout error after readiness without leaking output", async (t) => {
  const { child, ready } = fixture();
  t.after(() => child.stdout.destroy());
  child.stdout.write("Servidor rodando em http://127.0.0.1:43210\n");
  await ready;
  assert.doesNotThrow(() => child.stdout.emit("error", new Error("private child output")));
  child.stdout.destroy();
  await assert.rejects(stop(child), { message: "fixture stdout read failed" });
  assert.equal(child.stdout.listenerCount("error"), 0);
});

async function httpFixture(t, handler) {
  const server = http.createServer(handler);
  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return server.address().port;
}

test("realtime readiness HTTP request rejects a truncated response", { timeout: 2000 }, async (t) => {
  const port = await httpFixture(t, (_req, res) => {
    res.writeHead(200, { "content-length": "20" });
    res.write("partial", () => res.destroy());
  });
  await assert.rejects(request(port, "/login.html", { signal: t.signal }));
});

test("realtime readiness HTTP request obeys abort after response headers", { timeout: 2000 }, async (t) => {
  let started;
  const entered = new Promise((resolve) => { started = resolve; });
  const port = await httpFixture(t, (_req, res) => {
    res.writeHead(200, { "content-length": "20" });
    res.write("partial", started);
  });
  const controller = new AbortController();
  const denied = assert.rejects(request(port, "/login.html", { signal: controller.signal }));
  await entered;
  controller.abort();
  await denied;
});
