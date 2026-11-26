"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const test = require("node:test");
const { waitForFixtureListen } = require("./support/realtime-server-readiness");

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
