"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const nativeAcl = require("../services/chunkUploadWindowsAcl");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

// The bridge captures its native factory on import. A controlled verifier
// prevents timing-based assertions and lets this test prove startup ordering.
const realFactory = nativeAcl.createWindowsLocalWebDavAclVerifier;
let factory = realFactory;
nativeAcl.createWindowsLocalWebDavAclVerifier = (...args) => factory(...args);
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
nativeAcl.createWindowsLocalWebDavAclVerifier = realFactory;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test("Windows bridge does not listen until its native verifier has answered a fresh root ACL check", {
  skip: process.platform !== "win32", timeout: 35_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-warm-start-");
  const created = deferred();
  const queried = deferred();
  const release = deferred();
  let checks = 0;
  let stopped = 0;
  factory = () => {
    created.resolve();
    return {
      verify: async (target) => { assert.equal(target, root); checks++; queried.resolve(); await release.promise; },
      verifyFile: async () => { throw Error("unexpected leaf check"); },
      stop: () => { stopped++; release.resolve(); },
    };
  };
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "warm-start-fixture", port: 0 });
  t.after(async () => {
    release.resolve();
    await bridge.stop();
    factory = realFactory;
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const starting = bridge.start();
  await created.promise;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(bridge.server.listening, false, "not even a bound listener before native READY");
  release.resolve();
  await queried.promise;
  await starting;
  assert.equal(checks, 1, "exactly one mandatory startup probe is enough");
  assert.equal(bridge.server.listening, true);
  await bridge.stop();
  assert.equal(stopped, 1);
});

test("Windows stop during native warm-up aborts startup without a late listener", {
  skip: process.platform !== "win32", timeout: 35_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-warm-cancel-");
  const created = deferred();
  const queried = deferred();
  const release = deferred();
  let stopped = 0;
  factory = () => {
    created.resolve();
    return {
      verify: async () => { queried.resolve(); await release.promise; },
      verifyFile: async () => { throw Error("unexpected leaf check"); },
      stop: () => { stopped++; release.resolve(); },
    };
  };
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "warm-cancel-fixture", port: 0 });
  t.after(async () => {
    release.resolve();
    await bridge.stop();
    factory = realFactory;
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const starting = bridge.start();
  await created.promise;
  await queried.promise;
  await bridge.stop();
  await assert.rejects(starting, /start cancelled by stop/);
  assert.equal(bridge.server.listening, false);
  assert.equal(bridge.windowsAclVerifier, null);
  assert.equal(stopped, 1);
});

test("Windows failed native warm-up rejects startup and releases its verifier", {
  skip: process.platform !== "win32", timeout: 35_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-bridge-warm-deny-");
  let checks = 0;
  let stops = 0;
  factory = () => ({
    verify: async (target) => {
      assert.equal(target, root);
      checks++;
      throw new Error("Untrusted test ACL");
    },
    verifyFile: async () => { throw Error("unexpected leaf check"); },
    stop: () => { stops++; },
  });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "warm-deny-fixture", port: 0 });
  t.after(async () => {
    await bridge.stop();
    factory = realFactory;
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await assert.rejects(bridge.start(), /Untrusted test ACL/);
  assert.equal(checks, 1);
  assert.equal(stops, 1);
  assert.equal(bridge.server.listening, false);
  assert.equal(bridge.windowsAclVerifier, null);
});
