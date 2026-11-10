"use strict";

// Test-only Linux Node22 N-API bridge. The production RootSession gate stays
// unconditional NO-GO. No npm deps, automatic cleanup, or binary in checkout.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { Worker } = require("node:worker_threads");
const { openNativeRootSession, requireNativeRecoveryAuthority } =
  require("../sync-client/rootark-sync-native-root-session-contract");

const enabled = process.platform === "linux" &&
  process.env.ROOTARK_ISSUE66_W3_NAPI_LAB === "1";
// Each stress run deliberately leaves >16k files in an auditable ext4 HOME
// fixture. Require a separate opt-in so normal CI and repeated N-API tests
// never silently consume that inode/disk budget.
const stressEnabled = enabled && process.env.ROOTARK_ISSUE66_W3_STREAM_STRESS === "1";
const source = path.resolve(__dirname, "../experiments/issue66-w3-posix-napi/native_bridge.c");
let addon;
let addonPath;

test("#66 W3 native stress seeding has an explicit C-level opt-in gate", () => {
  const nativeSource = fs.readFileSync(source, "utf8");
  const seed = nativeSource.split("static napi_value seed_many(")[1]?.split("static napi_value seed_raw_byte_name(")[0];
  assert.ok(seed, "native seed function must remain present");
  assert.match(seed, /getenv\("ROOTARK_ISSUE66_W3_STREAM_STRESS"\)/,
    "JS test-only skip does not protect another addon caller from expensive seeding");
});

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
  addonPath = target;
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
    assert.throws(() => bridge.seedMany({ fd: 42, native: true }), /NATIVE_TOKEN_REJECTED/);
    assert.throws(() => bridge.beginStream(42), /NATIVE_TOKEN_REJECTED/);
    assert.throws(() => bridge.nextStreamPage("00000000000000000000000000000000"),
      /NATIVE_TOKEN_REJECTED/);
  });

test("#66 W3 pinned native fd enumerates and reads exact Unicode across deterministic A-B-A",
  { skip: !enabled }, () => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    assert.match(token, /^[0-9a-f]{32}$/);
    const freshNames = fs.readdirSync(home).filter((name) =>
      name.startsWith(".rootark-w3-napi-") && !before.has(name));
    assert.equal(freshNames.length, 1, "one native-owned parent fixture was created");
    assert.equal(freshNames[0].includes(token), false,
      "directory suffix must be generated independently of the bearer token");
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

test("#66 W3 streamed name Buffers preserve invalid POSIX UTF-8 bytes exactly",
  { skip: !enabled }, () => {
    const bridge = loadLab();
    const token = bridge.openTestSession();
    const raw = Buffer.from([0x72, 0x61, 0x77, 0x2d, 0xff, 0x2e, 0x62, 0x69, 0x6e]);
    assert.equal(bridge.seedRawByteName(token), "LAB_SEEDED_RAW_NAME");
    assert.equal(bridge.beginStream(token), "LAB_STREAM_READY");
    const names = [];
    for (let i = 0; i < 4; i++) {
      const page = bridge.nextStreamPage(token);
      names.push(...page.names);
      if (page.done) break;
    }
    assert.ok(names.every(Buffer.isBuffer));
    assert.ok(names.some((name) => name.equals(raw)), "exact 0xff must be preserved by native readdir");
    assert.equal(bridge.closeTestSession(token), "CLOSED_NO_AUTHORITY");
  });

test("#66 W3 native seeding refuses missing stress opt-in without writing 16k inodes",
  { skip: !enabled || stressEnabled }, () => {
    const bridge = loadLab();
    const token = bridge.openTestSession();
    assert.throws(() => bridge.seedMany(token), /NATIVE_STRESS_DISABLED/);
    assert.equal(bridge.read(token, "original.bin").toString("utf8"), "TRUSTED_ORIGINAL");
    assert.equal(bridge.closeTestSession(token), "CLOSED_NO_AUTHORITY");
  });

test("#66 W3 held native fd streams 16,385 extra entries across A-B-A in bounded raw-name pages",
  { skip: !stressEnabled, timeout: 180000 }, () => {
    const bridge = loadLab();
    const token = bridge.openTestSession();
    assert.equal(bridge.seedMany(token), "LAB_SEEDED_16385");
    assert.equal(bridge.seedRawByteName(token), "LAB_SEEDED_RAW_NAME");
    assert.throws(() => bridge.seedMany(token), /NATIVE_SEED_DENIED/,
      "a native session cannot reseed or overwrite its retained fixture");
    // A count and unique-name assertion can still pass if an attacker hides
    // an intermediate seed and supplies a foreign extra name. Compare the
    // complete 16,389-entry raw byte universe, not just sentinel endpoints.
    const expectedHex = ["original.bin", "alias", "café-中-😀.bin"]
      .map((name) => Buffer.from(name, "utf8").toString("hex"));
    expectedHex.push(Buffer.from([0x72, 0x61, 0x77, 0x2d, 0xff, 0x2e, 0x62, 0x69, 0x6e]).toString("hex"));
    for (let index = 0; index < 16385; index++) {
      expectedHex.push(Buffer.from(`entry-${String(index).padStart(5, "0")}.bin`, "ascii").toString("hex"));
    }
    expectedHex.sort();
    const scan = () => {
      assert.equal(bridge.beginStream(token), "LAB_STREAM_READY");
      const rawNames = [];
      let pageCount = 0;
      while (true) {
        assert.ok(++pageCount <= 300, "a 64-entry stream must terminate after 258 pages");
        const page = bridge.nextStreamPage(token);
        assert.ok(Array.isArray(page.names) && page.names.length <= 64);
        for (const name of page.names) {
          assert.ok(Buffer.isBuffer(name), "native returns exact name bytes, not lossy UTF-8 strings");
          rawNames.push(name.toString("hex"));
        }
        if (page.done) break;
      }
      assert.equal(rawNames.length, 16385 + 4);
      assert.equal(new Set(rawNames).size, rawNames.length);
      assert.ok(rawNames.includes(Buffer.from("caf\u00e9-\u4e2d-\ud83d\ude00.bin", "utf8").toString("hex")));
      assert.ok(rawNames.includes(Buffer.from("entry-16384.bin", "ascii").toString("hex")));
      assert.ok(rawNames.includes(Buffer.from([0x72, 0x61, 0x77, 0x2d, 0xff, 0x2e, 0x62, 0x69, 0x6e]).toString("hex")),
        "invalid UTF-8 POSIX leaf must be preserved as exact raw bytes without replacement");
      rawNames.sort();
      assert.deepEqual(rawNames, expectedHex,
        "all 16,385 legitimate entries must be present by exact bytes; no foreign substitutions");
      return rawNames;
    };
    const before = scan();
    assert.throws(() => bridge.enumerate(token), /NATIVE_STREAM_BUSY/,
      "legacy full-array enumerator cannot silently rewind a retained cursor");
    assert.equal(bridge.read(token, "entry-16384.bin").toString(), "x");
    assert.equal(bridge.swapToForeign(token), "HELD_ORIGINAL_FOREIGN_AT_NAME");
    assert.deepEqual(scan(), before, "the same retained directory, not replacement B, is enumerated");
    assert.equal(bridge.restoreOriginal(token), "ORIGINAL_RESTORED_FOREIGN_RETAINED");
    assert.equal(bridge.closeTestSession(token), "CLOSED_NO_AUTHORITY");
    assert.throws(() => bridge.nextStreamPage(token), /NATIVE_TOKEN_REJECTED/);
    assert.throws(() => requireNativeRecoveryAuthority(bridge),
      (e) => e.code === "root_session_unverified_authority");
  });

test("#66 W3 Node Worker environments own separate native descriptors and session tokens",
  { skip: !enabled, timeout: 30000 }, async () => {
    loadLab();
    const code = `
      const { parentPort, workerData } = require("node:worker_threads");
      const native = require(workerData.addonPath);
      const mine = native.openTestSession();
      parentPort.postMessage({ type: "ready", token: mine });
      parentPort.once("message", (other) => {
        let rejected = false;
        try { native.read(other.token, "original.bin"); }
        catch (error) { rejected = error.message === "NATIVE_TOKEN_REJECTED"; }
        const own = native.read(mine, "original.bin").toString() === "TRUSTED_ORIGINAL";
        native.closeTestSession(mine);
        parentPort.postMessage({ type: "result", rejected, own });
        parentPort.close();
      });
    `;
    function oneMessage(worker) {
      return new Promise((resolve, reject) => {
        worker.once("message", resolve);
        worker.once("error", reject);
        worker.once("exit", (code) => {
          if (code !== 0) reject(new Error("worker native session failed"));
        });
      });
    }
    const a = new Worker(code, { eval: true, workerData: { addonPath } });
    const b = new Worker(code, { eval: true, workerData: { addonPath } });
    try {
      const [startA, startB] = await Promise.all([oneMessage(a), oneMessage(b)]);
      assert.equal(startA.type, "ready");
      assert.equal(startB.type, "ready");
      assert.notEqual(startA.token, startB.token);
      const replies = Promise.all([oneMessage(a), oneMessage(b)]);
      a.postMessage({ token: startB.token });
      b.postMessage({ token: startA.token });
      const [resultA, resultB] = await replies;
      for (const result of [resultA, resultB]) {
        assert.deepEqual(result, { type: "result", rejected: true, own: true });
      }
    } finally {
      await Promise.all([a.terminate(), b.terminate()]);
    }
  });

test("#66 W3 native openat2 denies read-only traversal into a mounted procfs",
  { skip: !enabled }, () => {
    const bridge = loadLab();
    // Negative probe starts from the OS '/' fd (not the protected fixture).
    // It is not an adversarial bind-mount injection into the lab directory.
    assert.equal(bridge.probeExistingMount(), "NO_XDEV_DENIED");
  });

test("#66 W3 native bridge survives an unrelated addon taking instance data in the same Node environment",
  { skip: !enabled, timeout: 30000 }, () => {
    loadLab();
    const home = os.homedir();
    const build = fs.mkdtempSync(path.join(home, ".rootark-w3-napi-slot-"));
    assert.equal(fs.statSync(build).mode & 0o777, 0o700);
    assert.equal(fs.statfsSync(build).type, 0xef53);
    const competitor = path.join(build, "instance-slot-competitor.node");
    const competitorSource = path.resolve(__dirname,
      "../experiments/issue66-w3-posix-napi/instance_slot_competitor.c");
    const compiled = spawnSync("/usr/bin/gcc", [
      "-std=c11", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror",
      "-I/usr/include/node", competitorSource, "-o", competitor,
    ], {
      cwd: build, timeout: 30000, encoding: "utf8", maxBuffer: 4096,
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", TMPDIR: build },
    });
    assert.equal(compiled.status, 0, `competitor addon compile failed: ${compiled.stderr}`);
    const childCode = [
      "'use strict';",
      "const bridge = require(process.argv[1]);",
      "const competitor = require(process.argv[2]);",
      "const token = bridge.openTestSession();",
      "if (competitor.install() !== 'COMPETITOR_SLOT_EMPTY') process.exit(71);",
      "if (bridge.read(token, 'original.bin').toString('utf8') !== 'TRUSTED_ORIGINAL') process.exit(72);",
      "bridge.closeTestSession(token);",
      "process.stdout.write('LAB_COEXISTENCE_OK' + String.fromCharCode(10));",
    ].join("\n");
    const result = spawnSync(process.execPath, ["-e", childCode, addonPath, competitor], {
      cwd: build, timeout: 15000, encoding: "utf8", maxBuffer: 4096,
      env: { ROOTARK_ISSUE66_W3_NAPI_LAB: "1", PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    });
    assert.equal(result.status, 0, `native instance data collision broke lab: ${result.stderr}`);
    assert.equal(result.stdout, "LAB_COEXISTENCE_OK\n");
    assert.equal(result.stderr, "");
  });

test("#66 W3 native session cannot be overwritten through the shared N-API instance-data slot",
  { skip: !enabled }, () => {
    const nativeSource = fs.readFileSync(source, "utf8");
    assert.doesNotMatch(nativeSource, /\bnapi_(?:set|get)_instance_data\s*\(/,
      "native ownership must not depend on a replaceable instance-data slot");
    assert.match(nativeSource, /\bnapi_get_cb_info\s*\(/,
      "each method must retrieve its own private callback state");
    assert.match(nativeSource, /\bnapi_add_env_cleanup_hook\s*\(/,
      "the private native state must still have one environment cleanup hook");
  });

test("#66 W3 hostile same-UID bind-mount swap and root authority attestation",
  { skip: "SKIP: requires independently protected parent, CAP_SYS_ADMIN and live competing-writer model" }, () => {});
