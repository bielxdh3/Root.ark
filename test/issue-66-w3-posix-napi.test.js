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
let addon;
let addonPath;

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
