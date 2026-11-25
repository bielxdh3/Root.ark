"use strict";

// Deliberate, opt-in, LOCAL WSL laboratory only. Run a disposable native
// publisher as root, retain its 0700 root-owned ext4 ancestry, and drop the
// attacking child to the ordinary sync user's uid. This proves real kernel
// discretionary access denial in this fixture, NOT service attestation,
// product RootSession, Windows SID protection or signed monotonic custody.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { openNativeRootSession, requireNativeRecoveryAuthority } =
  require("../sync-client/rootark-sync-native-root-session-contract");

const enabled = process.platform === "linux" && typeof process.getuid === "function"
  && process.getuid() === 0
  && process.env.ROOTARK_ISSUE66_W3_ROOT_PRINCIPAL_ISOLATION_LAB === "1"
  && process.env.ROOTARK_ISSUE66_W3_NAPI_LAB === "1"
  && process.env.ROOTARK_ISSUE66_W3_TXN_LAB === "1";
const nativeSource = path.resolve(__dirname, "../experiments/issue66-w3-posix-napi/native_bridge.c");
const inspectorSource = path.resolve(__dirname,
  "../experiments/issue66-w3-posix-napi/cold_inspector.c");

function buildNative(source, output, directory, args) {
  const result = spawnSync("/usr/bin/gcc", [...args, source, "-o", output], {
    cwd: directory, timeout: 30000, encoding: "utf8", maxBuffer: 4096,
    env: { PATH: "/usr/bin:/bin", HOME: "/root", LANG: "C", LC_ALL: "C", TMPDIR: directory },
  });
  assert.equal(result.status, 0, result.stderr || "native root laboratory build failed");
}

function deniedByRealUnprivilegedProcess(held) {
  const child = String.raw`
    const fs = require('node:fs');
    const path = require('node:path');
    const held = process.argv[1];
    const parent = path.dirname(held);
    const denied = (action) => {
      try { action(); return 'UNSAFE_SUCCESS'; }
      catch (error) { return error.code || 'UNKNOWN_FAILURE'; }
    };
    process.stdout.write(JSON.stringify({uid:process.getuid(),euid:process.geteuid(),
      read:denied(()=>fs.readFileSync(path.join(held,'.rootark-w3-journal-v1'))),
      create:denied(()=>fs.writeFileSync(path.join(held,'.rootark-w3-committed-v1'),
        'FOREIGN', {flag:'wx',mode:0o600})),
      replace:denied(()=>fs.writeFileSync(path.join(held,'.rootark-w3-prepared-id-v2'),
        'FOREIGN')), // must never truncate the trusted PREPARE sidecar
      rename:denied(()=>fs.renameSync(held,path.join(parent,'hostile-rebound-held'))),
      symlink:denied(()=>fs.symlinkSync('/etc/passwd',path.join(held,'foreign-link')))
    }));
  `;
  const result = spawnSync("/usr/sbin/runuser", ["-u", "bielx", "--",
    "/usr/bin/node", "-e", child, held], {
    timeout: 15000, encoding: "utf8", maxBuffer: 4096,
    env: { PATH: "/usr/bin:/bin", HOME: "/home/bielx", LANG: "C", LC_ALL: "C" },
  });
  assert.equal(result.status, 0, result.stderr || "real unprivileged child did not complete");
  const attempted = JSON.parse(result.stdout);
  assert.equal(attempted.uid, 1000, "a genuine different non-root OS principal is required");
  assert.equal(attempted.euid, 1000);
  for (const action of ["read", "create", "replace", "rename", "symlink"]) {
    assert.ok(["EACCES", "EPERM"].includes(attempted[action]),
      `${action} must be denied by real Linux DAC, not a JS policy callback: ${attempted[action]}`);
  }
}

test("#66 W3 root-owned ext4 native custodian fixture excludes real distinct-UID client writers",
  { skip: !enabled, timeout: 40000 }, (t) => {
    assert.match(os.release(), /wsl|microsoft/i);
    assert.equal(os.homedir(), "/root");
    assert.equal(fs.statfsSync("/root").type, 0xef53);
    assert.equal(fs.statSync("/root").uid, 0);
    assert.equal(fs.statSync("/root").mode & 0o777, 0o700);
    assert.equal(fs.statSync("/").uid, 0);
    const build = fs.mkdtempSync("/root/.rootark-w3-root-principal-build-");
    assert.equal(fs.statSync(build).uid, 0);
    assert.equal(fs.statSync(build).mode & 0o777, 0o700);
    const addonFile = path.join(build, "rooted-custodian-lab.node");
    const inspectorFile = path.join(build, "rooted-inspector-lab");
    buildNative(nativeSource, addonFile, build, [
      "-std=c11", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror",
      "-I/usr/include/node", "-Wl,-z,relro", "-Wl,-z,now",
    ]);
    buildNative(inspectorSource, inspectorFile, build, [
      "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
      "-Wl,-z,relro", "-Wl,-z,now",
    ]);

    const bridge = require(addonFile);
    assert.equal(bridge.authority(), "LAB_ONLY_NO_GO");
    const before = new Set(fs.readdirSync("/root").filter((n) => n.startsWith(".rootark-w3-napi-")));
    const token = bridge.openTestSession();
    t.after(() => { try { bridge.closeTestSession(token); } catch {} });
    const fresh = fs.readdirSync("/root").filter((n) =>
      n.startsWith(".rootark-w3-napi-") && !before.has(n));
    assert.equal(fresh.length, 1);
    assert.match(fresh[0], /^\.rootark-w3-napi-[0-9a-f]{32}$/);
    const parent = path.join("/root", fresh[0]);
    const held = path.join(parent, "held");
    for (const directory of [parent, held]) {
      const stats = fs.statSync(directory, { bigint: true });
      assert.equal(stats.uid, 0n);
      assert.equal(stats.mode & 0o777n, 0o700n);
      assert.equal(stats.isDirectory(), true);
      assert.equal(fs.statfsSync(directory).type, 0xef53);
    }
    const originalAnon = process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
    process.env.ROOTARK_ISSUE66_W3_ANON_LAB = "1";
    try { assert.equal(bridge.stageProof(token), "LAB_TXN_PREPARED"); }
    finally {
      if (originalAnon === undefined) delete process.env.ROOTARK_ISSUE66_W3_ANON_LAB;
      else process.env.ROOTARK_ISSUE66_W3_ANON_LAB = originalAnon;
    }
    deniedByRealUnprivilegedProcess(held);
    assert.equal(fs.existsSync(path.join(held, ".rootark-w3-committed-v1")), false);
    assert.equal(fs.readFileSync(path.join(held, ".rootark-w3-journal-v1"), "utf8"), "PREPARED_V1");
    assert.equal(bridge.publishProof(token), "LAB_TXN_COMMITTED");
    deniedByRealUnprivilegedProcess(held);
    assert.equal(fs.readFileSync(path.join(held, ".rootark-w3-committed-v1"), "utf8"),
      "STAGED_ROOT_CANARY_V1");
    const published = fs.statSync(path.join(held, ".rootark-w3-committed-v1"), { bigint: true });
    assert.equal(published.uid, 0n);
    assert.equal(published.nlink, 1n);
    assert.equal(fs.existsSync(path.join(held, "foreign-link")), false);
    assert.equal(fs.existsSync(path.join(parent, "hostile-rebound-held")), false);
    const cold = spawnSync(inspectorFile, [fresh[0].slice(".rootark-w3-napi-".length)], {
      timeout: 15000, encoding: "utf8", maxBuffer: 4096,
      env: {
        PATH: "/usr/bin:/bin", HOME: "/root", LANG: "C", LC_ALL: "C",
        ROOTARK_ISSUE66_W3_COLD_INSPECT_LAB: "1",
      },
    });
    assert.equal(cold.status, 0, cold.stderr);
    assert.equal(cold.stdout,
      "ROOTARK_W3_COLD_INSPECT phase=COMMIT_OBSERVED authority=LAB_ONLY_NO_GO\n");
    assert.throws(() => openNativeRootSession(true, bridge),
      (error) => error.code === "root_session_native_unavailable");
    assert.throws(() => requireNativeRecoveryAuthority(bridge),
      (error) => error.code === "root_session_unverified_authority");
  });
