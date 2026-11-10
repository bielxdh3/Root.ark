"use strict";

const assert = require("node:assert/strict");
const fsp = require("node:fs/promises");
const fs = require("node:fs");
const test = require("node:test");

const {
  ROOT_SESSION_CONTRACT,
  ROOT_SESSION_ERROR,
  openNativeRootSession,
  requireNativeRecoveryAuthority,
} = require("../sync-client/rootark-sync-native-root-session-contract");

const rejects = (work, code) => assert.throws(work, (error) =>
  error?.code === code && error?.name === "RootSessionUnavailableError");

test("#66 native RootSession is disabled by default and does not treat truthy settings as an enable gate", () => {
  for (const gate of [undefined, null, false, 1, "true", {}, [], new Boolean(true)]) {
    rejects(() => openNativeRootSession(gate), ROOT_SESSION_ERROR.FEATURE_DISABLED);
  }
  rejects(() => openNativeRootSession(true), ROOT_SESSION_ERROR.NATIVE_UNAVAILABLE);
});

test("#66 a supplied user-land native-looking binding cannot satisfy the feature gate", () => {
  let invoked = 0;
  const forged = Object.freeze({
    platform: process.platform,
    native: true,
    trustedParent: true,
    openRootFromTrustedParent() { invoked += 1; return this; },
    enumerateDirectory() { invoked += 1; return []; },
    commitDurableRecovery() { invoked += 1; return true; },
  });
  rejects(() => openNativeRootSession(true, forged), ROOT_SESSION_ERROR.NATIVE_UNAVAILABLE);
  rejects(() => requireNativeRecoveryAuthority(forged), ROOT_SESSION_ERROR.UNVERIFIED_AUTHORITY);
  assert.equal(invoked, 0, "the contract cannot invoke user-supplied fake native methods");
});

test("#66 no path, lstat metadata, Node FileHandle, or plausible native-function text authorizes recovery", async () => {
  const handle = await fsp.open(__filename, fs.constants.O_RDONLY);
  try {
    const stat = await handle.stat({ bigint: true });
    const forgedNative = function openRootFromTrustedParent() {};
    forgedNative.toString = () => "function openRootFromTrustedParent() { [native code] }";
    for (const candidate of [
      __filename,
      { rootPath: __dirname, rootStats: stat },
      stat,
      handle,
      { fd: handle.fd, stat, isDirectory: () => true },
      { openRootFromTrustedParent: forgedNative, native: true },
    ]) {
      rejects(() => requireNativeRecoveryAuthority(candidate), ROOT_SESSION_ERROR.UNVERIFIED_AUTHORITY);
      rejects(() => openNativeRootSession(true, candidate), ROOT_SESSION_ERROR.NATIVE_UNAVAILABLE);
    }
  } finally {
    await handle.close();
  }
});

test("#66 a hostile Proxy is never inspected as native authority", () => {
  let touched = 0;
  const poison = new Proxy({}, {
    get() { touched += 1; throw new Error("candidate property access"); },
    getOwnPropertyDescriptor() { touched += 1; throw new Error("candidate descriptor access"); },
    ownKeys() { touched += 1; throw new Error("candidate enumeration"); },
  });
  rejects(() => requireNativeRecoveryAuthority(poison), ROOT_SESSION_ERROR.UNVERIFIED_AUTHORITY);
  rejects(() => openNativeRootSession(true, poison), ROOT_SESSION_ERROR.NATIVE_UNAVAILABLE);
  rejects(() => openNativeRootSession(poison), ROOT_SESSION_ERROR.FEATURE_DISABLED);
  assert.equal(touched, 0);
});

test("#66 the native contract covers rooted recovery I/O and cold reopening on both platforms", () => {
  assert.equal(ROOT_SESSION_CONTRACT.version, 1);
  const required = [
    "openRootFromTrustedParent", "openChildDirectory", "enumerateDirectory",
    "openContainedFile", "readOpenedFile", "createExclusiveFile", "renameNoReplace",
    "removeEntry", "syncOpenedFile", "syncDirectory", "reacquireRoot",
    "commitDurableRecovery", "close",
  ];
  assert.deepEqual(ROOT_SESSION_CONTRACT.requiredOperations, required);
  for (const platform of ["win32", "linux"]) {
    const contract = ROOT_SESSION_CONTRACT.platforms[platform];
    assert.ok(contract);
    for (const operation of required) {
      assert.ok(contract[operation], `${platform} lacks native requirement for ${operation}`);
    }
  }
  assert.equal(ROOT_SESSION_CONTRACT.guards.nativeExecutionRequired, true);
  assert.equal(ROOT_SESSION_CONTRACT.guards.noPathnameFallback, true);
  assert.equal(ROOT_SESSION_CONTRACT.guards.rejectCrossMountTraversal, true);
  assert.equal(ROOT_SESSION_CONTRACT.guards.requireSamePrincipalWriterIsolation, true);
  assert.equal(ROOT_SESSION_CONTRACT.guards.requiredMarkerUntilDurableCommit, true);
});

test("#66 native deletion contract forbids stat-to-unlink authority for hostile same-principal writers", () => {
  const { guards, platforms } = ROOT_SESSION_CONTRACT;
  assert.equal(guards.noStatThenUnlinkAsIdentityAuthority, true,
    "pre-unlink stat is never atomic removal of the observed inode");
  assert.equal(guards.requireTrustedParentBeforeDestructiveRemove, true,
    "an owner-independent directory writer policy must exist before removal");
  assert.match(platforms.win32.removeEntry, /SetFileInformationByHandle/i);
  assert.match(platforms.win32.removeEntry, /opened.*HANDLE/i);
  assert.match(platforms.linux.removeEntry, /unlinkat/);
  assert.match(platforms.linux.removeEntry, /same-UID.*writer isolation/i,
    "dirfd-relative unlink does not protect against same-UID leaf swap");
  rejects(() => openNativeRootSession(true), ROOT_SESSION_ERROR.NATIVE_UNAVAILABLE);
  rejects(() => requireNativeRecoveryAuthority(), ROOT_SESSION_ERROR.UNVERIFIED_AUTHORITY);
});

test("#66 root contract requires streaming 16,385 legitimate trash entries and exact Unicode names", () => {
  const { genesisEnumeration } = ROOT_SESSION_CONTRACT;
  assert.equal(genesisEnumeration.streaming, true);
  assert.equal(genesisEnumeration.acceptsLegitimateEntriesAtLeast, 16385);
  assert.equal(genesisEnumeration.truncateAt16384, false);
  assert.equal(genesisEnumeration.preserveExactNames, true);
  assert.equal(genesisEnumeration.rejectAmbiguousAliases, true);
  const examples = ["ação", "𝄞-音楽", "e\u0301", "é", "İ", "ı"];
  assert.equal(new Set(examples).size, examples.length);
  assert.equal(ROOT_SESSION_CONTRACT.guards.renormalizeNamesInJavaScript, false);
});

test("#66 published native requirements cannot be modified at runtime to relax checks", () => {
  assert.equal(Object.isFrozen(ROOT_SESSION_CONTRACT), true);
  assert.equal(Object.isFrozen(ROOT_SESSION_CONTRACT.requiredOperations), true);
  assert.equal(Object.isFrozen(ROOT_SESSION_CONTRACT.platforms.win32), true);
  assert.equal(Object.isFrozen(ROOT_SESSION_CONTRACT.platforms.linux), true);
  assert.equal(Object.isFrozen(ROOT_SESSION_CONTRACT.guards), true);
  assert.throws(() => { ROOT_SESSION_CONTRACT.guards.noPathnameFallback = false; }, TypeError);
});
