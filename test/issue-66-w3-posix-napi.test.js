"use strict";

// Test-only Linux Node22 N-API bridge. The production RootSession gate stays
// unconditional NO-GO. No npm deps, automatic cleanup, or binary in checkout.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { openNativeRootSession, requireNativeRecoveryAuthority } =
  require("../sync-client/rootark-sync-native-root-session-contract");

const enabled = process.platform === "linux" &&
  process.env.ROOTARK_ISSUE66_W3_NAPI_LAB === "1";
const source = path.resolve(__dirname, "../experiments/issue66-w3-posix-napi/native_bridge.c");
let addon;

function loadLab() {
  if (addon) return addon;
  assert.match(process.version, /^v22\./);
  assert.match(os.release(), /wsl|microsoft/i);
  const home = os.homedir();
  assert.equal(fs.realpathSync(home), home);
  assert.equal(fs.statfsSync(home).type, 0xef53, "must use Linux ext4 HOME");
  assert.ok(fs.statSync("/usr/include/node/node_api.h").isFile());
  const build = fs.mkdtempSync(path.join(home, ".rootark-w3-napi-build-"));
  assert.equal(fs.statSync(build).mode & 0o777, 0o700);
  assert.equal(fs.statfsSync(build).type, 0xef53);
  const target = path.join(build, "rooted-native.node");
  const compilation = spawnSync("/usr/bin/gcc", [
    "-std=c11", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror",
    "-I/usr/include/node", "-Wl,-z,relro", "-Wl,-z,now",
    source, "-o", target,
  ], {
    cwd: build, timeout: 30000, encoding: "utf8", maxBuffer: 4096,
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C", LANG: "C", TMPDIR: build },
  });
  assert.equal(compilation.status, 0, `gcc compilation failed: ${compilation.stderr?.slice(0, 1500)}`);
  addon = require(target);
  return addon;
}

test("#66 W3 native bridge loads in Node22 and cannot activate integrated RootSession",
  { skip: !enabled }, () => {
    const bridge = loadLab();
    assert.equal(bridge.authority(), "LAB_ONLY_NO_GO");
    assert.throws(() => openNativeRootSession(true, bridge),
      (e) => e.code === "root_session_native_unavailable");
    assert.throws(() => requireNativeRecoveryAuthority(bridge),
      (e) => e.code === "root_session_unverified_authority");
    assert.throws(() => bridge.openTestSession({ fd: 1, trusted: true }), /NATIVE_ARGUMENT_REJECTED/);
  });

test("#66 W3 token minted in native code rejects JS fd/object/path spoofing",
  { skip: !enabled }, () => {
    const bridge = loadLab();
    assert.throws(() => bridge.enumerate({ fd: 42, native: true }), /NATIVE_TOKEN_REJECTED/);
    assert.throws(() => bridge.read(42, "original.bin"), /NATIVE_TOKEN_REJECTED/);
    assert.throws(() => bridge.read("00000000000000000000000000000000", "original.bin"), /NATIVE_TOKEN_REJECTED/);
    assert.throws(() => bridge.read({ toString() { throw Error("should not invoke"); } }, "original.bin"),
      /NATIVE_TOKEN_REJECTED/);
  });

test("#66 W3 pinned native fd enumerates and reads exact Unicode across deterministic A-B-A",
  { skip: !enabled }, () => {
    const bridge = loadLab();
    const token = bridge.openTestSession();
    assert.match(token, /^[0-9a-f]{32}$/);
    assert.equal(bridge.authority(), "LAB_ONLY_NO_GO");
    const initial = bridge.enumerate(token);
    assert.deepEqual(initial.sort(), ["alias", "original.bin", "café-中-😀.bin"].sort());
    assert.equal(bridge.read(token, "original.bin").toString("utf8"), "TRUSTED_ORIGINAL");
    assert.equal(bridge.read(token, "café-中-😀.bin").toString("utf8"), "UNICODE");
    for (const leaf of ["/etc/passwd", "../secret", "a/b", ".", "", "original.bin/..", "bad\\name"]) {
      assert.throws(() => bridge.read(token, leaf), /NATIVE_LEAF_REJECTED/);
    }
    assert.throws(() => bridge.read(token, "alias"), /NATIVE_OPEN_DENIED/);
    assert.equal(bridge.swapToForeign(token), "HELD_ORIGINAL_FOREIGN_AT_NAME");
    assert.deepEqual(bridge.enumerate(token).sort(), initial);
    assert.equal(bridge.read(token, "original.bin").toString("utf8"), "TRUSTED_ORIGINAL");
    assert.equal(bridge.restoreOriginal(token), "ORIGINAL_RESTORED_FOREIGN_RETAINED");
    assert.equal(bridge.read(token, "café-中-😀.bin").toString("utf8"), "UNICODE");
    assert.equal(bridge.closeTestSession(token), "CLOSED_NO_AUTHORITY");
    assert.throws(() => bridge.read(token, "original.bin"), /NATIVE_TOKEN_REJECTED/);
  });

test("#66 W3 native openat2 denies read-only traversal into a mounted procfs",
  { skip: !enabled }, () => {
    const bridge = loadLab();
    // Negative probe starts from the OS '/' fd (not the protected fixture).
    // It is not an adversarial bind-mount injection into the lab directory.
    assert.equal(bridge.probeExistingMount(), "NO_XDEV_DENIED");
  });

test("#66 W3 hostile same-UID bind-mount swap and root authority attestation",
  { skip: "SKIP: requires independently protected parent, CAP_SYS_ADMIN and live competing-writer model" }, () => {});
