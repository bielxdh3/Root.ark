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
const txnEnabled = enabled && process.env.ROOTARK_ISSUE66_W3_TXN_LAB === "1";
const source = path.resolve(__dirname, "../experiments/issue66-w3-posix-napi/native_bridge.c");
const coldSource = path.resolve(__dirname, "../experiments/issue66-w3-posix-napi/cold_inspector.c");
let addon;
let addonPath;
let coldInspectorPath;

// Assertions must inspect the same opened inode that supplies the bytes.
// Comparing fs.statSync(path) and later fs.readFileSync(path) would admit a
// foreign same-UID replacement between those two independent path lookups.
function observeOpenedFixture(fd) {
  const before = fs.fstatSync(fd, { bigint: true });
  assert.equal(before.isFile(), true);
  assert.equal(before.isSymbolicLink(), false);
  assert.ok(before.ino > 0n && before.size <= 8192n);
  const bytes = Buffer.alloc(Number(before.size) + 1);
  let count = 0;
  while (count < bytes.length) {
    const read = fs.readSync(fd, bytes, count, bytes.length - count, count);
    if (!read) break;
    count += read;
  }
  const after = fs.fstatSync(fd, { bigint: true });
  assert.equal(after.dev, before.dev);
  assert.equal(after.ino, before.ino);
  assert.equal(after.size, before.size);
  assert.equal(after.mtimeNs, before.mtimeNs);
  assert.equal(BigInt(count), before.size);
  return { stat: before, bytes: bytes.subarray(0, count).toString("utf8") };
}

function openFixtureLeaf(dirfd, leaf, flags = fs.constants.O_RDONLY) {
  assert.match(leaf, /^[a-zA-Z0-9._-]+$/, "native lab leaves are fixed names");
  return fs.openSync(`/proc/self/fd/${dirfd}/${leaf}`,
    flags | fs.constants.O_NOFOLLOW | (fs.constants.O_NONBLOCK || 0), 0o600);
}

function withHeldFixtureDirectory(held, action) {
  const fd = fs.openSync(held, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY
    | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd, { bigint: true });
    assert.equal(stat.isDirectory(), true);
    assert.equal(stat.isSymbolicLink(), false);
    return action(fd);
  } finally { fs.closeSync(fd); }
}

function withOpenedFixtureLeaves(dirfd, leaves, action) {
  const opened = [];
  try {
    for (const leaf of leaves) opened.push(openFixtureLeaf(dirfd, leaf));
    return action(...opened);
  } finally {
    // If a later leaf open rejects (foreign rename/ENOENT), all earlier
    // descriptors must still close. The test may not leak a writer HANDLE.
    for (let i = opened.length - 1; i >= 0; i--) fs.closeSync(opened[i]);
  }
}

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

function loadColdInspector() {
  if (coldInspectorPath) return coldInspectorPath;
  assert.match(process.version, /^v22\./);
  assert.match(os.release(), /wsl|microsoft/i);
  const home = os.homedir();
  const build = fs.mkdtempSync(path.join(home, ".rootark-w3-cold-build-"));
  assert.equal(fs.statSync(build).mode & 0o777, 0o700);
  assert.equal(fs.statfsSync(build).type, 0xef53);
  const output = path.join(build, "rooted-cold-inspector");
  const compiled = spawnSync("/usr/bin/gcc", [
    "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
    "-Wl,-z,relro", "-Wl,-z,now", coldSource, "-o", output,
  ], {
    cwd: build, timeout: 30000, encoding: "utf8", maxBuffer: 4096,
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", TMPDIR: build },
  });
  assert.equal(compiled.status, 0, `C cold inspection compilation failed: ${compiled.stderr}`);
  coldInspectorPath = output;
  return output;
}

function inspectNativeColdFixture(held, allowed = true) {
  const home = os.homedir();
  const fixture = path.basename(path.dirname(held));
  assert.match(fixture, /^\.rootark-w3-napi-[0-9a-f]{32}$/);
  assert.equal(path.resolve(held), path.join(home, fixture, "held"));
  return spawnSync(loadColdInspector(), [fixture.slice(".rootark-w3-napi-".length)], {
    cwd: home, timeout: 15000, encoding: "utf8", maxBuffer: 4096,
    env: {
      PATH: "/usr/bin:/bin", HOME: home, LANG: "C", LC_ALL: "C",
      ROOTARK_ISSUE66_W3_COLD_INSPECT_LAB: allowed ? "1" : "0",
    },
  });
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

test("#66 W3 native fixed stage and durable no-replace publication stay bound to A while B occupies its path",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const beforeNames = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const created = fs.readdirSync(home).filter((name) =>
      name.startsWith(".rootark-w3-napi-") && !beforeNames.has(name));
    assert.equal(created.length, 1);
    const parent = path.join(home, created[0]);
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/);
    assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED");
    assert.throws(() => bridge.stageProof(token), /NATIVE_TXN_PHASE_REJECTED/);
    assert.equal(bridge.read(token, ".rootark-w3-staged-v1").toString(), "STAGED_ROOT_CANARY_V1");
    assert.equal(bridge.read(token, ".rootark-w3-journal-v1").toString(), "PREPARED_V1");
    assert.equal(bridge.swapToForeign(token), "HELD_ORIGINAL_FOREIGN_AT_NAME");
    assert.equal(fs.readFileSync(path.join(parent, "held", "original.bin"), "utf8"), "FOREIGN_ORIGINAL");
    assert.equal(fs.existsSync(path.join(parent, "held", ".rootark-w3-committed-v1")), false);
    assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    assert.equal(fs.existsSync(path.join(parent, "held", ".rootark-w3-committed-v1")), false,
      "native publication must not write B under the rebound pathname");
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/);
    // An opened-source hardlink cannot safely retire its same-UID-writable
    // original name. Both names remain, so the generic native read correctly
    // rejects nlink=2 rather than promoting a hardlink alias to authority.
    const stagedPath = path.join(parent, "parked", ".rootark-w3-staged-v1");
    const publishedPath = path.join(parent, "parked", ".rootark-w3-committed-v1");
    assert.equal(fs.readFileSync(publishedPath, "utf8"), "STAGED_ROOT_CANARY_V1");
    assert.equal(fs.statSync(publishedPath, { bigint: true }).ino,
      fs.statSync(stagedPath, { bigint: true }).ino, "published bytes belong to original staged inode");
    assert.equal(fs.statSync(publishedPath, { bigint: true }).nlink, 2n,
      "source stage name is deliberately retained for later custodian-only cleanup");
    assert.throws(() => bridge.read(token, ".rootark-w3-committed-v1"), /NATIVE_OPEN_DENIED/);
    assert.equal(bridge.read(token, ".rootark-w3-commit-marker-v1").toString(), "COMMITTED_V1");
    assert.equal(bridge.restoreOriginal(token), "ORIGINAL_RESTORED_FOREIGN_RETAINED");
    assert.equal(fs.readFileSync(path.join(parent, "held", ".rootark-w3-committed-v1"), "utf8"),
      "STAGED_ROOT_CANARY_V1");
    assert.equal(fs.existsSync(path.join(parent, "foreign-parked", ".rootark-w3-committed-v1")), false);
    assert.throws(() => bridge.read(token, ".rootark-w3-committed-v1"), /NATIVE_OPEN_DENIED/);
    assert.equal(bridge.closeTestSession(token), "CLOSED_NO_AUTHORITY");
    assert.throws(() => bridge.publishProof(token), /NATIVE_TOKEN_REJECTED/);
    assert.throws(() => requireNativeRecoveryAuthority(bridge),
      (error) => error.code === "root_session_unverified_authority");
  });

test("#66 W3 native publication refuses a same-UID destination collision without replacing foreign bytes",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const created = fs.readdirSync(home).filter((name) =>
      name.startsWith(".rootark-w3-napi-") && !before.has(name));
    assert.equal(created.length, 1);
    const held = path.join(home, created[0], "held");
    const foreignDest = path.join(held, ".rootark-w3-committed-v1");
    assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED");
    fs.writeFileSync(foreignDest, "FOREIGN_NOT_TO_REPLACE", { flag: "wx", mode: 0o600 });
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_NO_REPLACE_CONFLICT/);
    assert.equal(fs.readFileSync(foreignDest, "utf8"), "FOREIGN_NOT_TO_REPLACE");
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-commit-marker-v1")), false);
    assert.equal(bridge.read(token, ".rootark-w3-staged-v1").toString(), "STAGED_ROOT_CANARY_V1");
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/,
      "a collided native publication cannot retry after a foreign destination disappears");
    assert.equal(bridge.closeTestSession(token), "CLOSED_NO_AUTHORITY");
  });

test("#66 W3 external same-UID writer cannot replace the original opened ext4 native stage", {
  skip: !txnEnabled,
}, (t) => {
  const bridge = loadLab();
  const home = os.homedir();
  const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
  const token = bridge.openTestSession();
  t.after(() => { try { bridge.closeTestSession(token); } catch {} });
  const created = fs.readdirSync(home).filter((name) =>
    name.startsWith(".rootark-w3-napi-") && !before.has(name));
  assert.equal(created.length, 1);
  const held = path.join(home, created[0], "held");
  assert.equal(fs.statfsSync(held).type, 0xef53, "external writer must exercise ext4");
  assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED");
  // A separate process inheriting this UID creates+fsyncs the foreign inode
  // while the parent continues to retain the native root/stage descriptors.
  // This proves no-overwrite under an externally planted destination, NOT
  // independently controlled ancestors, isolation, or powercut recovery.
  const writer = spawnSync("/usr/bin/node", ["-e", String.raw`
    const fs = require('node:fs');
    const path = require('node:path');
    const held = process.argv[1];
    const file = path.join(held, '.rootark-w3-committed-v1');
    const fd = fs.openSync(file, 'wx', 0o600);
    try {
      const bytes = Buffer.from('FOREIGN_EXTERNAL_WRITER');
      let offset = 0;
      while (offset < bytes.length) offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    process.stdout.write('FOREIGN_DURABLE');
  `, held], {
    encoding: "utf8", timeout: 10000, maxBuffer: 1024,
    env: { ...process.env, ROOTARK_ISSUE66_W3_STREAM_STRESS: "0" },
  });
  assert.equal(writer.status, 0, writer.stderr || "external same-UID writer failed");
  assert.equal(writer.stdout, "FOREIGN_DURABLE");
  withHeldFixtureDirectory(held, (dirfd) => {
    withOpenedFixtureLeaves(dirfd, [".rootark-w3-staged-v1", ".rootark-w3-committed-v1"],
      (stageFd, foreignFd) => {
        const stage = observeOpenedFixture(stageFd);
        const foreign = observeOpenedFixture(foreignFd);
        assert.notEqual(stage.stat.ino, foreign.stat.ino);
        assert.equal(stage.bytes, "STAGED_ROOT_CANARY_V1");
        assert.equal(foreign.bytes, "FOREIGN_EXTERNAL_WRITER");
        assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_NO_REPLACE_CONFLICT/);
        const stageAfter = observeOpenedFixture(stageFd);
        const foreignAfter = observeOpenedFixture(foreignFd);
        assert.equal(stageAfter.stat.ino, stage.stat.ino);
        assert.equal(foreignAfter.stat.ino, foreign.stat.ino);
        assert.equal(stageAfter.stat.size, stage.stat.size);
        assert.equal(foreignAfter.stat.size, foreign.stat.size);
        assert.equal(stageAfter.stat.mtimeNs, stage.stat.mtimeNs);
        assert.equal(foreignAfter.stat.mtimeNs, foreign.stat.mtimeNs);
        assert.equal(stageAfter.bytes, stage.bytes);
        assert.equal(foreignAfter.bytes, foreign.bytes);
      });
  });
  assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/,
    "an externally collided publication cannot retry without new authority");
});

test("#66 W3 equal-byte foreign inode cannot be published instead of original stage",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const created = fs.readdirSync(home).filter((name) =>
      name.startsWith(".rootark-w3-napi-") && !before.has(name));
    assert.equal(created.length, 1);
    const held = path.join(home, created[0], "held");
    const destination = path.join(held, ".rootark-w3-committed-v1");
    const commit = path.join(held, ".rootark-w3-commit-marker-v1");
    assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED");
    withHeldFixtureDirectory(held, (dirfd) => {
      const originalFd = openFixtureLeaf(dirfd, ".rootark-w3-staged-v1");
      let foreignFd;
      try {
        const original = observeOpenedFixture(originalFd);
        fs.renameSync(`/proc/self/fd/${dirfd}/.rootark-w3-staged-v1`,
          `/proc/self/fd/${dirfd}/.rootark-w3-original-stage-parked`);
        // Open EXCLUSIVE under the retained directory, not check(path)->
        // writeFile(path). Preserve the foreign FD through native rejection.
        foreignFd = openFixtureLeaf(dirfd, ".rootark-w3-staged-v1",
          fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL);
        fs.writeSync(foreignFd, "STAGED_ROOT_CANARY_V1");
        fs.fsyncSync(foreignFd);
        const foreign = observeOpenedFixture(foreignFd);
        assert.notEqual(foreign.stat.ino, original.stat.ino,
          "replacement must be a distinct physical inode");
        assert.equal(original.bytes, "STAGED_ROOT_CANARY_V1");
        assert.equal(foreign.bytes, original.bytes,
          "identical bytes alone must not authorize the foreign inode");
        assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_INDETERMINATE/,
          "equal bytes of an untrusted inode must not authorize the native stage");
        assert.equal(fs.existsSync(destination), false, "foreign stage must not be published");
        assert.equal(fs.existsSync(commit), false, "no COMMIT after stage inode replacement");
        withOpenedFixtureLeaves(dirfd,
          [".rootark-w3-staged-v1", ".rootark-w3-original-stage-parked"],
          (visibleFd, parkedFd) => {
          const visible = observeOpenedFixture(visibleFd);
          const parkedOriginal = observeOpenedFixture(parkedFd);
          assert.equal(visible.stat.ino, foreign.stat.ino,
            "current stage name must still refer to the foreign inode");
          assert.equal(parkedOriginal.stat.ino, original.stat.ino,
            "parked name must still refer to the original held inode");
          assert.equal(visible.bytes, "STAGED_ROOT_CANARY_V1");
          assert.equal(parkedOriginal.bytes, "STAGED_ROOT_CANARY_V1");
          });
        assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/,
          "the rejected same-byte substitution must permanently poison the session");
      } finally {
        if (foreignFd !== undefined) fs.closeSync(foreignFd);
        fs.closeSync(originalFd);
      }
    });
  });

test("#66 W3 native publish links original held inode after post-check stage-name replacement",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const created = fs.readdirSync(home).filter((name) =>
      name.startsWith(".rootark-w3-napi-") && !before.has(name));
    assert.equal(created.length, 1);
    const held = path.join(home, created[0], "held");
    assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED");
    withHeldFixtureDirectory(held, (dirfd) => {
      const originalFd = openFixtureLeaf(dirfd, ".rootark-w3-staged-v1");
      try {
        const original = observeOpenedFixture(originalFd);
        const saved = process.env.ROOTARK_ISSUE66_W3_REBIND_AFTER_CHECK;
        process.env.ROOTARK_ISSUE66_W3_REBIND_AFTER_CHECK = "1";
        try { assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED"); }
        finally {
          if (saved === undefined) delete process.env.ROOTARK_ISSUE66_W3_REBIND_AFTER_CHECK;
          else process.env.ROOTARK_ISSUE66_W3_REBIND_AFTER_CHECK = saved;
        }
        withOpenedFixtureLeaves(dirfd, [".rootark-w3-postcheck-parked",
          ".rootark-w3-staged-v1", ".rootark-w3-committed-v1"],
        (parkedFd, foreignFd, publishedFd) => {
          const parked = observeOpenedFixture(parkedFd);
          const foreign = observeOpenedFixture(foreignFd);
          const published = observeOpenedFixture(publishedFd);
          assert.equal(parked.stat.dev, original.stat.dev);
          assert.equal(parked.stat.ino, original.stat.ino,
            "native adversarial hook must actually park original opened inode");
          assert.notEqual(foreign.stat.ino, original.stat.ino,
            "foreign same-byte stage must be a different physical inode");
          assert.equal(published.stat.dev, original.stat.dev);
          assert.equal(published.stat.ino, original.stat.ino,
            "publication must link original opened inode, not the late foreign occupant");
          assert.equal(published.stat.nlink, 2n,
            "lab link-publish still has a second name and grants no production custody");
          assert.equal(parked.bytes, "STAGED_ROOT_CANARY_V1");
          assert.equal(published.bytes, "STAGED_ROOT_CANARY_V1");
          assert.equal(foreign.bytes, "STAGED_ROOT_CANARY_V1");
        });
      } finally { fs.closeSync(originalFd); }
    });
    assert.equal(fs.readFileSync(path.join(held, ".rootark-w3-commit-marker-v1"), "utf8"), "COMMITTED_V1");
    assert.throws(() => bridge.read(token, ".rootark-w3-committed-v1"), /NATIVE_OPEN_DENIED/,
      "remaining hardlink alias cannot be promoted to independently trusted read authority");
  });

test("#66 W3 anonymous native stage publishes a single-link inode with no unsafe visible stage retirement",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const created = fs.readdirSync(home).filter((name) =>
      name.startsWith(".rootark-w3-napi-") && !before.has(name));
    assert.equal(created.length, 1);
    const held = path.join(home, created[0], "held");
    const staged = path.join(held, ".rootark-w3-staged-v1");
    const published = path.join(held, ".rootark-w3-committed-v1");
    const saved = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
    try {
      assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED");
      assert.equal(fs.existsSync(staged), false,
        "O_TMPFILE PREPARE may not expose a second writable stage name");
      assert.equal(fs.readFileSync(path.join(held, ".rootark-w3-journal-v1"), "utf8"), "PREPARED_V1");
      assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    } finally {
      if (saved === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = saved;
    }
    assert.equal(fs.existsSync(staged), false, "anonymous original must have no abandoned stage pathname");
    withHeldFixtureDirectory(held, (dirfd) => {
      const publishedFd = openFixtureLeaf(dirfd, ".rootark-w3-committed-v1");
      try {
        const publishedProof = observeOpenedFixture(publishedFd);
        assert.equal(publishedProof.stat.nlink, 1n,
          "single no-replace published inode must be readable after cold open");
        assert.equal(publishedProof.bytes, "STAGED_ROOT_CANARY_V1");
        assert.equal(bridge.read(token, ".rootark-w3-committed-v1").toString(),
          "STAGED_ROOT_CANARY_V1");
      } finally { fs.closeSync(publishedFd); }
    });
    assert.equal(fs.readFileSync(path.join(held, ".rootark-w3-commit-marker-v1"), "utf8"), "COMMITTED_V1");
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/);
    assert.throws(() => requireNativeRecoveryAuthority(bridge),
      (e) => e.code === "root_session_unverified_authority");
  });

test("#66 W3 anonymous publication never overwrites a physical foreign destination",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const created = fs.readdirSync(home).filter((name) =>
      name.startsWith(".rootark-w3-napi-") && !before.has(name));
    assert.equal(created.length, 1);
    const held = path.join(home, created[0], "held");
    const saved = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (saved === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = saved;
    }
    const published = path.join(held, ".rootark-w3-committed-v1");
    fs.writeFileSync(published, "FOREIGN_DESTINATION", { flag: "wx", mode: 0o600 });
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_NO_REPLACE_CONFLICT/);
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/);
    assert.equal(fs.readFileSync(published, "utf8"), "FOREIGN_DESTINATION");
    assert.equal(fs.statSync(published, { bigint: true }).nlink, 1n);
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-staged-v1")), false);
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-commit-marker-v1")), false);
  });

test("#66 W3 anonymous post-link hard exit retains PREPARED without granting cold COMMIT",
  { skip: !txnEnabled }, () => {
    loadLab(); // compile exact current C in a disposable ext4 HOME fixture
    const child = [
      "const fs=require('node:fs');",
      "const path=require('node:path');",
      "const os=require('node:os');",
      "const bridge=require(process.argv[1]);",
      "const home=os.homedir();",
      "const before=new Set(fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')));",
      "const token=bridge.openTestSession();",
      "const created=fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')&&!before.has(n));",
      "if(created.length!==1)process.exit(61);",
      "const held=path.join(home,created[0],'held');",
      "if(bridge.stageProof(token)!=='LAB_TXN_PREPARED')process.exit(62);",
      "fs.writeSync(1,held+'\\n');",
      "bridge.publishProof(token);",
      "process.exit(63);",
    ].join("");
    const crash = spawnSync(process.execPath, ["-e", child, addonPath], {
      timeout: 10000, encoding: "utf8", maxBuffer: 4096,
      env: {
        PATH: "/usr/bin:/bin", HOME: os.homedir(), LANG: "C", LC_ALL: "C",
        ROOTARK_ISSUE66_W3_NAPI_LAB: "1", ROOTARK_ISSUE66_W3_TXN_LAB: "1",
        ROOTARK_ISSUE66_W3_ANON_LAB: "1",
        ROOTARK_ISSUE66_W3_HARD_EXIT_POST_LINK: "1",
      },
    });
    assert.equal(crash.status, 73, crash.stderr || crash.stdout);
    const held = crash.stdout.trim();
    assert.ok(held.startsWith(path.join(os.homedir(), ".rootark-w3-napi-")));
    withHeldFixtureDirectory(held, (dirfd) => {
      const pinnedParent = `/proc/self/fd/${dirfd}`;
      assert.equal(fs.existsSync(path.join(pinnedParent, ".rootark-w3-staged-v1")), false);
      withOpenedFixtureLeaves(dirfd,
        [".rootark-w3-committed-v1", ".rootark-w3-journal-v1"],
        (publishedFd, preparedFd) => {
        const published = observeOpenedFixture(publishedFd);
        assert.equal(published.stat.nlink, 1n);
        assert.equal(published.bytes, "STAGED_ROOT_CANARY_V1");
        assert.equal(observeOpenedFixture(preparedFd).bytes, "PREPARED_V1");
        assert.equal(fs.existsSync(path.join(pinnedParent, ".rootark-w3-commit-marker-v1")), false,
          "a real child-process hard exit before COMMIT cannot be deemed complete");
        });
    });
    assert.throws(() => openNativeRootSession(true),
      (e) => e.code === "root_session_native_unavailable");
  });

test("#66 W3 anonymous pre-link hard exit loses unnamed stage but retains only nonauthorizing PREPARED",
  { skip: !txnEnabled }, () => {
    loadLab();
    const child = [
      "const fs=require('node:fs');",
      "const path=require('node:path');",
      "const os=require('node:os');",
      "const bridge=require(process.argv[1]);",
      "const home=os.homedir();",
      "const before=new Set(fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')));",
      "const token=bridge.openTestSession();",
      "const created=fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')&&!before.has(n));",
      "if(created.length!==1)process.exit(61);",
      "const held=path.join(home,created[0],'held');",
      "if(bridge.stageProof(token)!=='LAB_TXN_PREPARED')process.exit(62);",
      "fs.writeSync(1,held+'\\n');",
      "process.exit(74);",
    ].join("");
    const crash = spawnSync(process.execPath, ["-e", child, addonPath], {
      timeout: 10000, encoding: "utf8", maxBuffer: 4096,
      env: {
        PATH: "/usr/bin:/bin", HOME: os.homedir(), LANG: "C", LC_ALL: "C",
        ROOTARK_ISSUE66_W3_NAPI_LAB: "1", ROOTARK_ISSUE66_W3_TXN_LAB: "1",
        ROOTARK_ISSUE66_W3_ANON_LAB: "1",
      },
    });
    assert.equal(crash.status, 74, crash.stderr || crash.stdout);
    const held = crash.stdout.trim();
    assert.ok(held.startsWith(path.join(os.homedir(), ".rootark-w3-napi-")));
    assert.equal(fs.statSync(held).isDirectory(), true);
    assert.equal(fs.readFileSync(path.join(held, ".rootark-w3-journal-v1"), "utf8"), "PREPARED_V1");
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-staged-v1")), false);
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-committed-v1")), false);
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-commit-marker-v1")), false);
    assert.throws(() => requireNativeRecoveryAuthority({ root: held }),
      (e) => e.code === "root_session_unverified_authority");
  });

test("#66 W3 native cold inspector binds original ext4 inode to PREPARE and COMMIT",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((n) => n.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const names = fs.readdirSync(home).filter((n) =>
      n.startsWith(".rootark-w3-napi-") && !before.has(n));
    assert.equal(names.length, 1);
    const held = path.join(home, names[0], "held");
    const originalAnon = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (originalAnon === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = originalAnon;
    }
    withHeldFixtureDirectory(held, (dirfd) => {
      withOpenedFixtureLeaves(dirfd, [".rootark-w3-prepared-id-v2"], (idFd) => {
        const id = observeOpenedFixture(idFd);
        assert.match(id.bytes, /^PREPARED_ID_V2:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:A\n$/);
        assert.equal(id.stat.nlink, 1n);
      });
    });
    const disabled = inspectNativeColdFixture(held, false);
    assert.equal(disabled.status, 41);
    assert.equal(disabled.stdout, "");
    assert.equal(disabled.stderr, "ROOTARK_W3_COLD_INSPECT_REJECTED\n");
    const prepared = inspectNativeColdFixture(held);
    assert.equal(prepared.status, 0, prepared.stderr);
    assert.equal(prepared.stdout,
      "ROOTARK_W3_COLD_INSPECT phase=PREPARED_ONLY authority=LAB_ONLY_NO_GO\n");
    assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    const completed = inspectNativeColdFixture(held);
    assert.equal(completed.status, 0, completed.stderr);
    assert.equal(completed.stdout,
      "ROOTARK_W3_COLD_INSPECT phase=COMMIT_OBSERVED authority=LAB_ONLY_NO_GO\n");
    assert.throws(() => openNativeRootSession(true),
      (error) => error.code === "root_session_native_unavailable");
  });

test("#66 W3 cold native inspector verifies legitimate named-stage two-link COMMIT by exact inode",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((n) => n.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const fresh = fs.readdirSync(home).filter((n) =>
      n.startsWith(".rootark-w3-napi-") && !before.has(n));
    assert.equal(fresh.length, 1);
    const held = path.join(home, fresh[0], "held");
    const oldAnon = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (oldAnon === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = oldAnon;
    }
    assert.equal(inspectNativeColdFixture(held).stdout,
      "ROOTARK_W3_COLD_INSPECT phase=PREPARED_ONLY authority=LAB_ONLY_NO_GO\n");
    assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    withHeldFixtureDirectory(held, (dirfd) => {
      withOpenedFixtureLeaves(dirfd, [".rootark-w3-prepared-id-v2"], (idFd) => {
        assert.match(observeOpenedFixture(idFd).bytes,
          /^PREPARED_ID_V2:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:N\n$/,
          "cold mode must come from ORIGINAL PREPARE, not a current stage-name guess");
      });
      withOpenedFixtureLeaves(dirfd,
        [".rootark-w3-staged-v1", ".rootark-w3-committed-v1"],
        (stageFd, publishedFd) => {
          const stage = observeOpenedFixture(stageFd);
          const published = observeOpenedFixture(publishedFd);
          assert.equal(stage.stat.dev, published.stat.dev);
          assert.equal(stage.stat.ino, published.stat.ino,
            "the native no-replace destination must be the ORIGINAL named stage inode");
          assert.equal(stage.stat.nlink, 2n);
          assert.equal(published.stat.nlink, 2n);
          assert.equal(stage.bytes, "STAGED_ROOT_CANARY_V1");
          assert.equal(published.bytes, stage.bytes);
        });
    });
    const observed = inspectNativeColdFixture(held);
    assert.equal(observed.status, 0, observed.stderr);
    assert.equal(observed.stdout,
      "ROOTARK_W3_COLD_INSPECT phase=COMMIT_OBSERVED authority=LAB_ONLY_NO_GO\n");
    assert.throws(() => requireNativeRecoveryAuthority(bridge),
      (error) => error.code === "root_session_unverified_authority");
  });

test("#66 W3 named original PREPARE denies cold commit if same-UID writer removes original stage alias",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((n) => n.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const fresh = fs.readdirSync(home).filter((n) =>
      n.startsWith(".rootark-w3-napi-") && !before.has(n));
    assert.equal(fresh.length, 1);
    const held = path.join(home, fresh[0], "held");
    const originalAnon = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (originalAnon === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = originalAnon;
    }
    assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    assert.equal(inspectNativeColdFixture(held).status, 0);
    withHeldFixtureDirectory(held, (dirfd) => {
      const originalStage = openFixtureLeaf(dirfd, ".rootark-w3-staged-v1");
      const published = openFixtureLeaf(dirfd, ".rootark-w3-committed-v1");
      try {
        const original = observeOpenedFixture(originalStage);
        assert.equal(original.stat.nlink, 2n,
          "named publication is born with two hardlinks to the same inode");
        assert.equal(observeOpenedFixture(published).stat.ino, original.stat.ino);
        // Only remove this freshly generated disposable lab leaf. The
        // ORIGINAL inode and COMMIT remain held; no production cleanup path.
        fs.unlinkSync(`/proc/self/fd/${dirfd}/.rootark-w3-staged-v1`);
        const after = observeOpenedFixture(published);
        assert.equal(after.stat.ino, original.stat.ino);
        assert.equal(after.stat.nlink, 1n,
          "physical alias removal must convert named topology to apparent anonymous topology");
        assert.equal(after.bytes, original.bytes);
        assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-staged-v1`), false);
        const cold = inspectNativeColdFixture(held);
        assert.equal(cold.status, 41,
          "original PREPARE says named; same-UID alias retirement must never be reclassified anonymous");
        assert.equal(cold.stdout, "");
        assert.equal(cold.stderr, "ROOTARK_W3_COLD_INSPECT_REJECTED\n");
        assert.equal(fs.readFileSync(`/proc/self/fd/${dirfd}/.rootark-w3-commit-marker-v1`, "utf8"),
          "COMMITTED_V1", "attacker must not alter the original marker to force a denial");
      } finally {
        fs.closeSync(published);
        fs.closeSync(originalStage);
      }
    });
  });

test("#66 W3 cold named-stage inspector rejects equal-byte foreign alias after valid COMMIT",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((n) => n.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const fresh = fs.readdirSync(home).filter((n) =>
      n.startsWith(".rootark-w3-napi-") && !before.has(n));
    assert.equal(fresh.length, 1);
    const held = path.join(home, fresh[0], "held");
    const oldAnon = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (oldAnon === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = oldAnon;
    }
    assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    assert.equal(inspectNativeColdFixture(held).status, 0);
    withHeldFixtureDirectory(held, (dirfd) => {
      const staged = ".rootark-w3-staged-v1";
      const parked = ".rootark-w3-cold-original-stage-parked";
      const original = openFixtureLeaf(dirfd, staged);
      let foreign;
      try {
        const originalProof = observeOpenedFixture(original);
        fs.renameSync(`/proc/self/fd/${dirfd}/${staged}`,
          `/proc/self/fd/${dirfd}/${parked}`);
        foreign = openFixtureLeaf(dirfd, staged,
          fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL);
        const bytes = Buffer.from(originalProof.bytes);
        assert.equal(fs.writeSync(foreign, bytes), bytes.length);
        fs.fsyncSync(foreign);
        const planted = observeOpenedFixture(foreign);
        assert.notEqual(planted.stat.ino, originalProof.stat.ino,
          "the attacker must install a distinct inode with byte-identical alias bytes");
        assert.equal(planted.bytes, originalProof.bytes);
        const cold = inspectNativeColdFixture(held);
        assert.equal(cold.status, 41,
          "same-byte foreign alias cannot validate the original stage FileId and link count");
        assert.equal(cold.stdout, "");
        assert.equal(cold.stderr, "ROOTARK_W3_COLD_INSPECT_REJECTED\n");
        assert.equal(observeOpenedFixture(original).stat.ino, originalProof.stat.ino);
        assert.equal(observeOpenedFixture(foreign).stat.ino, planted.stat.ino);
      } finally {
        if (foreign !== undefined) fs.closeSync(foreign);
        fs.closeSync(original);
      }
    });
    assert.equal(fs.readFileSync(path.join(held, ".rootark-w3-commit-marker-v1"), "utf8"),
      "COMMITTED_V1", "foreign name replacement must not corrupt original COMMIT bytes");
  });

test("#66 W3 named-stage hard exit after fsynced no-replace link preserves exact two-link PREPARE without COMMIT",
  { skip: !txnEnabled }, () => {
    loadLab();
    const child = [
      "const fs=require('node:fs');",
      "const path=require('node:path');",
      "const os=require('node:os');",
      "const bridge=require(process.argv[1]);",
      "const home=os.homedir();",
      "const old=new Set(fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')));",
      "const token=bridge.openTestSession();",
      "const fresh=fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')&&!old.has(n));",
      "if(fresh.length!==1)process.exit(61);",
      "if(bridge.stageProof(token)!=='LAB_TXN_PREPARED')process.exit(62);",
      "fs.writeSync(1,path.join(home,fresh[0],'held')+'\\n');",
      "bridge.publishProof(token);",
      "process.exit(63);",
    ].join("");
    const crash = spawnSync(process.execPath, ["-e", child, addonPath], {
      timeout: 10000, encoding: "utf8", maxBuffer: 4096,
      env: {
        PATH: "/usr/bin:/bin", HOME: os.homedir(), LANG: "C", LC_ALL: "C",
        ROOTARK_ISSUE66_W3_NAPI_LAB: "1", ROOTARK_ISSUE66_W3_TXN_LAB: "1",
        ROOTARK_ISSUE66_W3_ANON_LAB: "0",
        ROOTARK_ISSUE66_W3_HARD_EXIT_POST_LINK_NAMED: "1",
      },
    });
    assert.equal(crash.status, 73, crash.stderr || crash.stdout);
    const held = crash.stdout.trim();
    assert.ok(held.startsWith(path.join(os.homedir(), ".rootark-w3-napi-")));
    withHeldFixtureDirectory(held, (dirfd) => {
      withOpenedFixtureLeaves(dirfd,
        [".rootark-w3-staged-v1", ".rootark-w3-committed-v1"],
        (stageFd, publishedFd) => {
          const stage = observeOpenedFixture(stageFd);
          const published = observeOpenedFixture(publishedFd);
          assert.equal(stage.stat.ino, published.stat.ino);
          assert.equal(stage.stat.nlink, 2n);
          assert.equal(published.stat.nlink, 2n);
          assert.equal(stage.bytes, published.bytes);
        });
      assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-commit-marker-v1`), false);
    });
    const reopened = inspectNativeColdFixture(held);
    assert.equal(reopened.status, 0, reopened.stderr);
    assert.equal(reopened.stdout,
      "ROOTARK_W3_COLD_INSPECT phase=PUBLISHED_NO_COMMIT authority=LAB_ONLY_NO_GO\n");
    assert.throws(() => openNativeRootSession(true),
      (e) => e.code === "root_session_native_unavailable");
  });

test("#66 W3 native cold new process observes published-no-COMMIT after hard exit",
  { skip: !txnEnabled }, () => {
    loadLab();
    const code = [
      "const fs=require('node:fs');",
      "const path=require('node:path');",
      "const os=require('node:os');",
      "const bridge=require(process.argv[1]);",
      "const home=os.homedir();",
      "const old=new Set(fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')));",
      "const token=bridge.openTestSession();",
      "const fresh=fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')&&!old.has(n));",
      "if(fresh.length!==1)process.exit(61);",
      "if(bridge.stageProof(token)!=='LAB_TXN_PREPARED')process.exit(62);",
      "fs.writeSync(1,path.join(home,fresh[0],'held')+'\\n');",
      "bridge.publishProof(token);",
      "process.exit(63);",
    ].join("");
    const crashed = spawnSync(process.execPath, ["-e", code, addonPath], {
      timeout: 10000, encoding: "utf8", maxBuffer: 4096,
      env: {
        PATH: "/usr/bin:/bin", HOME: os.homedir(), LC_ALL: "C", LANG: "C",
        ROOTARK_ISSUE66_W3_NAPI_LAB: "1", ROOTARK_ISSUE66_W3_TXN_LAB: "1",
        ROOTARK_ISSUE66_W3_ANON_LAB: "1",
        ROOTARK_ISSUE66_W3_HARD_EXIT_POST_LINK: "1",
      },
    });
    assert.equal(crashed.status, 73, crashed.stderr || crashed.stdout);
    const held = crashed.stdout.trim();
    const result = inspectNativeColdFixture(held);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout,
      "ROOTARK_W3_COLD_INSPECT phase=PUBLISHED_NO_COMMIT authority=LAB_ONLY_NO_GO\n");
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-commit-marker-v1")), false);
  });

test("#66 W3 cold native inspector rejects equal-byte foreign published ext4 inode with COMMIT intact",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((n) => n.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const fresh = fs.readdirSync(home).filter((n) =>
      n.startsWith(".rootark-w3-napi-") && !before.has(n));
    assert.equal(fresh.length, 1);
    const held = path.join(home, fresh[0], "held");
    const originalAnon = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (originalAnon === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = originalAnon;
    }
    assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    assert.equal(inspectNativeColdFixture(held).status, 0);
    withHeldFixtureDirectory(held, (dirfd) => {
      const leaf = ".rootark-w3-committed-v1";
      const parked = ".rootark-w3-cold-original-parked";
      const originalFd = openFixtureLeaf(dirfd, leaf);
      let foreignFd;
      try {
        const original = observeOpenedFixture(originalFd);
        fs.renameSync(`/proc/self/fd/${dirfd}/${leaf}`,
          `/proc/self/fd/${dirfd}/${parked}`);
        foreignFd = openFixtureLeaf(dirfd, leaf,
          fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL);
        const bytes = Buffer.from(original.bytes);
        assert.equal(fs.writeSync(foreignFd, bytes), bytes.length);
        fs.fsyncSync(foreignFd);
        const foreign = observeOpenedFixture(foreignFd);
        assert.notEqual(foreign.stat.ino, original.stat.ino);
        assert.equal(foreign.bytes, original.bytes);
        assert.equal(foreign.stat.nlink, 1n);
        const denied = inspectNativeColdFixture(held);
        assert.equal(denied.status, 41,
          "a different inode with byte-identical published content cannot satisfy original PREPARE");
        assert.equal(denied.stdout, "");
        assert.equal(denied.stderr, "ROOTARK_W3_COLD_INSPECT_REJECTED\n");
        assert.equal(observeOpenedFixture(originalFd).stat.ino, original.stat.ino);
        assert.equal(observeOpenedFixture(foreignFd).stat.ino, foreign.stat.ino);
        assert.equal(observeOpenedFixture(originalFd).bytes, original.bytes);
        assert.equal(observeOpenedFixture(foreignFd).bytes, foreign.bytes);
      } finally {
        if (foreignFd !== undefined) fs.closeSync(foreignFd);
        fs.closeSync(originalFd);
      }
    });
    assert.equal(fs.readFileSync(path.join(held, ".rootark-w3-commit-marker-v1"), "utf8"),
      "COMMITTED_V1", "foreign leaves cannot mutate original COMMIT evidence");
  });

test("#66 W3 native cold inspector rejects an embedded-NUL COMMIT suffix on the same inode",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((n) => n.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const fresh = fs.readdirSync(home).filter((n) =>
      n.startsWith(".rootark-w3-napi-") && !before.has(n));
    assert.equal(fresh.length, 1);
    const held = path.join(home, fresh[0], "held");
    const originalAnon = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (originalAnon === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = originalAnon;
    }
    assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    assert.equal(inspectNativeColdFixture(held).status, 0);
    withHeldFixtureDirectory(held, (dirfd) => {
      const marker = openFixtureLeaf(dirfd, ".rootark-w3-commit-marker-v1", fs.constants.O_RDWR);
      try {
        const original = observeOpenedFixture(marker);
        assert.equal(original.bytes, "COMMITTED_V1");
        const injection = Buffer.from([0, 0x46, 0x4f, 0x52, 0x45, 0x49, 0x47, 0x4e]);
        assert.equal(fs.writeSync(marker, injection, 0, injection.length, Number(original.stat.size)),
          injection.length);
        fs.fsyncSync(marker);
        const changed = fs.fstatSync(marker, { bigint: true });
        assert.equal(changed.ino, original.stat.ino,
          "the attack must corrupt the SAME opened inode, not swap a pathname");
        assert.equal(changed.size, original.stat.size + BigInt(injection.length));
        const denied = inspectNativeColdFixture(held);
        assert.equal(denied.status, 41,
          "C strcmp must not hide bytes after embedded NUL in cold COMMIT marker");
        assert.equal(denied.stdout, "");
        assert.equal(denied.stderr, "ROOTARK_W3_COLD_INSPECT_REJECTED\n");
      } finally { fs.closeSync(marker); }
    });
  });

test("#66 W3 native cold new process rejects torn PREPARE before original inode identity proof",
  { skip: !txnEnabled }, () => {
    loadLab();
    const code = [
      "const fs=require('node:fs');",
      "const path=require('node:path');",
      "const os=require('node:os');",
      "const native=require(process.argv[1]);",
      "const home=os.homedir();",
      "const before=new Set(fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')));",
      "const token=native.openTestSession();",
      "const fresh=fs.readdirSync(home).filter(n=>n.startsWith('.rootark-w3-napi-')&&!before.has(n));",
      "if(fresh.length!==1)process.exit(61);",
      "fs.writeSync(1,path.join(home,fresh[0],'held')+'\\n');",
      "native.stageProof(token);",
      "process.exit(62);",
    ].join("");
    const crashed = spawnSync(process.execPath, ["-e", code, addonPath], {
      timeout: 10000, encoding: "utf8", maxBuffer: 4096,
      env: {
        PATH: "/usr/bin:/bin", HOME: os.homedir(), LANG: "C", LC_ALL: "C",
        ROOTARK_ISSUE66_W3_NAPI_LAB: "1", ROOTARK_ISSUE66_W3_TXN_LAB: "1",
        ROOTARK_ISSUE66_W3_ANON_LAB: "1",
        ROOTARK_ISSUE66_W3_HARD_EXIT_BEFORE_ID_PROOF: "1",
      },
    });
    assert.equal(crashed.status, 75, crashed.stderr || crashed.stdout);
    const held = crashed.stdout.trim();
    assert.ok(held.startsWith(path.join(os.homedir(), ".rootark-w3-napi-")));
    withHeldFixtureDirectory(held, (dirfd) => {
      withOpenedFixtureLeaves(dirfd, [".rootark-w3-journal-v1"], (preparedFd) => {
        assert.equal(observeOpenedFixture(preparedFd).bytes, "PREPARED_V1");
      });
      assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-prepared-id-v2`), false);
      assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-committed-v1`), false);
      assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-commit-marker-v1`), false);
    });
    const rejected = inspectNativeColdFixture(held);
    assert.equal(rejected.status, 41,
      "durable PREPARE without original inode ID cannot be promoted to a cold transaction");
    assert.equal(rejected.stdout, "");
    assert.equal(rejected.stderr, "ROOTARK_W3_COLD_INSPECT_REJECTED\n");
  });

test("#66 W3 original PREPARE identity sidecar survives separate same-UID equal-byte replacement",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((n) => n.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const fresh = fs.readdirSync(home).filter((n) =>
      n.startsWith(".rootark-w3-napi-") && !before.has(n));
    assert.equal(fresh.length, 1);
    const held = path.join(home, fresh[0], "held");
    const originalAnon = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (originalAnon === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = originalAnon;
    }
    const writer = spawnSync(process.execPath, ["-e", String.raw`
      const fs = require('node:fs');
      const path = require('node:path');
      const held = process.argv[1];
      const visible = path.join(held, '.rootark-w3-prepared-id-v2');
      const parked = path.join(held, '.rootark-w3-original-id-parked');
      const fd = fs.openSync(visible, 'r');
      let original;
      try { original = fs.readFileSync(fd); } finally { fs.closeSync(fd); }
      fs.renameSync(visible, parked);
      const foreign = fs.openSync(visible, 'wx', 0o600);
      try {
        if (fs.writeSync(foreign, original) !== original.length) process.exit(68);
        fs.fsyncSync(foreign);
      } finally { fs.closeSync(foreign); }
      process.stdout.write('EXTERNAL_SAME_UID_ID_REBIND');
    `, held], {
      timeout: 10000, encoding: "utf8", maxBuffer: 2048,
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    });
    assert.equal(writer.status, 0, writer.stderr || "external writer failed");
    assert.equal(writer.stdout, "EXTERNAL_SAME_UID_ID_REBIND");
    withHeldFixtureDirectory(held, (dirfd) => {
      withOpenedFixtureLeaves(dirfd,
        [".rootark-w3-original-id-parked", ".rootark-w3-prepared-id-v2"],
        (originalFd, foreignFd) => {
          const original = observeOpenedFixture(originalFd);
          const foreign = observeOpenedFixture(foreignFd);
          assert.notEqual(original.stat.ino, foreign.stat.ino);
          assert.equal(original.bytes, foreign.bytes,
            "the collision is a true distinct inode with byte-identical PREPARE identity");
          assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_INDETERMINATE/);
          assert.equal(observeOpenedFixture(originalFd).stat.ino, original.stat.ino);
          assert.equal(observeOpenedFixture(foreignFd).stat.ino, foreign.stat.ino);
        });
      assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-committed-v1`), false);
      assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-commit-marker-v1`), false);
    });
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/);
  });

test("#66 W3 native stage detects a separate same-UID writer's pre-commit in-place corruption",
  { skip: !txnEnabled }, (t) => {
    const bridge = loadLab();
    const home = os.homedir();
    const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const created = fs.readdirSync(home).filter((name) =>
      name.startsWith(".rootark-w3-napi-") && !before.has(name));
    assert.equal(created.length, 1);
    const held = path.join(home, created[0], "held");
    assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED");
    const stagePath = path.join(held, ".rootark-w3-staged-v1");
    const attacker = spawnSync(process.execPath, ["-e",
      "require('node:fs').writeFileSync(process.argv[1], 'SAME_UID_FOREIGN_BYTES')", stagePath], {
      cwd: held, timeout: 5000, encoding: "utf8", maxBuffer: 4096,
      env: { PATH: "/usr/bin:/bin", LANG: "C" },
    });
    assert.equal(attacker.status, 0, attacker.stderr);
    assert.equal(fs.readFileSync(stagePath, "utf8"), "SAME_UID_FOREIGN_BYTES");
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_INDETERMINATE/);
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-committed-v1")), false);
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-commit-marker-v1")), false);
  });

for (const anonymous of [false, true]) {
  test(`#66 W3 ${anonymous ? "O_TMPFILE" : "named"} PREPARE rejects an equal-byte foreign journal inode`,
    { skip: !txnEnabled }, (t) => {
      const bridge = loadLab();
      const home = os.homedir();
      const before = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
      const token = bridge.openTestSession();
      t.after(() => { try { bridge.closeTestSession(token); } catch {} });
      const created = fs.readdirSync(home).filter((name) =>
        name.startsWith(".rootark-w3-napi-") && !before.has(name));
      assert.equal(created.length, 1);
      const held = path.join(home, created[0], "held");
      const saved = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      if (anonymous) process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
      else delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
      finally {
        if (saved === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
        else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = saved;
      }
      withHeldFixtureDirectory(held, (dirfd) => {
        const originalFd = openFixtureLeaf(dirfd, ".rootark-w3-journal-v1");
        try {
          const original = observeOpenedFixture(originalFd);
          assert.equal(original.bytes, "PREPARED_V1");
          // A separate same-UID process replaces the PREPARE *inode* while
          // retaining identical payload bytes. A byte-only comparison at
          // publish would wrongly admit an unrelated journal's provenance.
          const writer = spawnSync("/usr/bin/node", ["-e", String.raw`
            const fs = require('node:fs');
            const path = require('node:path');
            const held = process.argv[1];
            fs.renameSync(path.join(held, '.rootark-w3-journal-v1'),
              path.join(held, '.rootark-w3-original-journal-parked'));
            const fd = fs.openSync(path.join(held, '.rootark-w3-journal-v1'), 'wx', 0o600);
            try {
              const bytes = Buffer.from('PREPARED_V1');
              if (fs.writeSync(fd, bytes) !== bytes.length) throw Error('SHORT_WRITE');
              fs.fsyncSync(fd);
            } finally { fs.closeSync(fd); }
            const dirfd = fs.openSync(held, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
            try { fs.fsyncSync(dirfd); } finally { fs.closeSync(dirfd); }
            process.stdout.write('FOREIGN_PREPARE_FSYNCED');
          `, held], {
            cwd: held, timeout: 10000, encoding: "utf8", maxBuffer: 1024,
            env: { PATH: "/usr/bin:/bin", LANG: "C" },
          });
          assert.equal(writer.status, 0, writer.stderr || "independent journal writer failed");
          assert.equal(writer.stdout, "FOREIGN_PREPARE_FSYNCED");
          withOpenedFixtureLeaves(dirfd,
            [".rootark-w3-journal-v1", ".rootark-w3-original-journal-parked"],
            (foreignFd, parkedFd) => {
              const foreign = observeOpenedFixture(foreignFd);
              const parked = observeOpenedFixture(parkedFd);
              assert.equal(parked.stat.ino, original.stat.ino);
              assert.equal(parked.stat.dev, original.stat.dev);
              assert.notEqual(foreign.stat.ino, original.stat.ino);
              assert.equal(foreign.bytes, original.bytes);
              assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_INDETERMINATE/,
                "a distinct PREPARE inode must never authorize native COMMIT");
              assert.equal(observeOpenedFixture(originalFd).stat.ino, original.stat.ino);
              assert.equal(observeOpenedFixture(foreignFd).bytes, foreign.bytes);
              assert.equal(observeOpenedFixture(parkedFd).bytes, parked.bytes);
              assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-committed-v1`), false);
              assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-commit-marker-v1`), false);
            });
          assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_PHASE_REJECTED/,
            "journal inode rebind must permanently poison transaction");
        } finally { fs.closeSync(originalFd); }
      });
      assert.equal(bridge.closeTestSession(token), "CLOSED_NO_AUTHORITY");
      // Cold separate-process observation after native HANDLE closure:
      // neither the foreign PREPARE nor the parked original is a COMMIT.
      // This is inspection only, not trusted independent root reacquisition.
      const cold = spawnSync("/usr/bin/node", ["-e", String.raw`
        const fs = require('node:fs');
        const assert = require('node:assert/strict');
        const held = process.argv[1];
        const dir = fs.openSync(held,
          fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
        const readLeaf = (name) => {
          const fd = fs.openSync('/proc/self/fd/' + dir + '/' + name,
            fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
          try {
            const st = fs.fstatSync(fd, { bigint: true });
            assert.ok(st.isFile() && st.ino > 0n && st.size === 11n);
            const buf = Buffer.alloc(12);
            assert.equal(fs.readSync(fd, buf, 0, buf.length, 0), 11);
            return { ino: st.ino, bytes: buf.subarray(0, 11).toString('utf8') };
          } finally { fs.closeSync(fd); }
        };
        try {
          const foreign = readLeaf('.rootark-w3-journal-v1');
          const original = readLeaf('.rootark-w3-original-journal-parked');
          assert.notEqual(foreign.ino, original.ino);
          assert.equal(foreign.bytes, 'PREPARED_V1');
          assert.equal(original.bytes, 'PREPARED_V1');
          assert.equal(fs.existsSync('/proc/self/fd/' + dir +
            '/.rootark-w3-commit-marker-v1'), false);
        } finally { fs.closeSync(dir); }
        process.stdout.write('COLD_PREPARED_ONLY_NO_AUTHORITY');
      `, held], {
        cwd: held, timeout: 10000, encoding: "utf8", maxBuffer: 1024,
        env: { PATH: "/usr/bin:/bin", LANG: "C" },
      });
      assert.equal(cold.status, 0, cold.stderr || "cold independent observer failed");
      assert.equal(cold.stdout, "COLD_PREPARED_ONLY_NO_AUTHORITY");
    });
}

for (const anonymous of [false, true]) {
  test(`#66 W3 ${anonymous ? "O_TMPFILE" : "named"} PREPARE denies same-inode byte restoration and post-link journal rebind`,
    { skip: !txnEnabled }, (t) => {
      const bridge = loadLab();
      const home = os.homedir();
      const previous = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
      const start = (token) => {
        const prior = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
        if (anonymous) process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
        else delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
        try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
        finally {
          if (prior === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
          else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = prior;
        }
      };
      const one = bridge.openTestSession();
      t.after(() => { try { bridge.closeTestSession(one); } catch {} });
      const first = fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-") && !previous.has(name));
      assert.equal(first.length, 1);
      start(one);
      const held = path.join(home, first[0], "held");
      const journal = path.join(held, ".rootark-w3-journal-v1");
      const priorFd = fs.openSync(journal, "r+");
      try {
        const before = observeOpenedFixture(priorFd);
        assert.equal(before.bytes, "PREPARED_V1");
        const changed = spawnSync("/usr/bin/node", ["-e", String.raw`
          const fs = require('node:fs');
          const fd = fs.openSync(process.argv[1], 'r+');
          try {
            fs.writeSync(fd, Buffer.from('X'), 0, 1, 0); fs.fsyncSync(fd);
            fs.writeSync(fd, Buffer.from('PREPARED_V1'), 0, 11, 0);
            fs.futimesSync(fd, 1, 1); fs.fsyncSync(fd);
          } finally { fs.closeSync(fd); }
        `, journal], {
          cwd: held, timeout: 10000, encoding: "utf8", maxBuffer: 1024,
          env: { PATH: "/usr/bin:/bin", LANG: "C" },
        });
        assert.equal(changed.status, 0, changed.stderr);
        const after = observeOpenedFixture(priorFd);
        assert.equal(after.stat.ino, before.stat.ino,
          "the writer must mutate the very same PREPARE inode");
        assert.equal(after.bytes, before.bytes,
          "the writer must restore the original exact bytes");
        assert.notEqual(after.stat.mtimeNs, before.stat.mtimeNs,
          "physical inode version must change despite equal final bytes");
        assert.throws(() => bridge.publishProof(one), /NATIVE_TXN_INDETERMINATE/);
        assert.equal(fs.existsSync(path.join(held, ".rootark-w3-committed-v1")), false);
        assert.equal(fs.existsSync(path.join(held, ".rootark-w3-commit-marker-v1")), false);
        assert.throws(() => bridge.publishProof(one), /NATIVE_TXN_PHASE_REJECTED/);
      } finally { fs.closeSync(priorFd); }
      assert.equal(bridge.closeTestSession(one), "CLOSED_NO_AUTHORITY");

      // Separate lab fixture and deterministic kernel swap AFTER the native
      // no-replace link and its fsync, before COMMIT could be emitted.
      const existing = new Set(fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-")));
      const second = bridge.openTestSession();
      t.after(() => { try { bridge.closeTestSession(second); } catch {} });
      const created = fs.readdirSync(home).filter((name) => name.startsWith(".rootark-w3-napi-") && !existing.has(name));
      assert.equal(created.length, 1);
      start(second);
      const otherHeld = path.join(home, created[0], "held");
      const originalLate = process.env.ROOTARK_ISSUE66_W3_JOURNAL_REBIND_AFTER_LINK;
      process.env.ROOTARK_ISSUE66_W3_JOURNAL_REBIND_AFTER_LINK = "1";
      try { assert.throws(() => bridge.publishProof(second), /NATIVE_TXN_INDETERMINATE/); }
      finally {
        if (originalLate === undefined) delete process.env.ROOTARK_ISSUE66_W3_JOURNAL_REBIND_AFTER_LINK;
        else process.env.ROOTARK_ISSUE66_W3_JOURNAL_REBIND_AFTER_LINK = originalLate;
      }
      withHeldFixtureDirectory(otherHeld, (dirfd) => {
        withOpenedFixtureLeaves(dirfd,
          [".rootark-w3-journal-v1", ".rootark-w3-afterlink-original-prepare"],
          (foreignFd, parkedFd) => {
            const foreign = observeOpenedFixture(foreignFd);
            const parked = observeOpenedFixture(parkedFd);
            assert.equal(foreign.bytes, parked.bytes);
            assert.equal(foreign.bytes, "PREPARED_V1");
            assert.notEqual(foreign.stat.ino, parked.stat.ino);
          });
        assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-committed-v1`), true,
          "the no-replace publication may finish before PREPARE rebind is noticed");
        assert.equal(fs.existsSync(`/proc/self/fd/${dirfd}/.rootark-w3-commit-marker-v1`), false,
          "after-link journal rebind must block durable COMMIT");
      });
      assert.throws(() => bridge.publishProof(second), /NATIVE_TXN_PHASE_REJECTED/);
    });
}

test("#66 W3 native stage and publish cannot be enabled by general NAPI lab flag alone",
  { skip: !enabled || txnEnabled }, (t) => {
    const bridge = loadLab();
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    assert.throws(() => bridge.stageProof(token), /NATIVE_TXN_TEST_DISABLED/);
    assert.throws(() => bridge.publishProof(token), /NATIVE_TXN_TEST_DISABLED/);
    assert.throws(() => bridge.read(token, ".rootark-w3-staged-v1"), /NATIVE_OPEN_DENIED/);
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
