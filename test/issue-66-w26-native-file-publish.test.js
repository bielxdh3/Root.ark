"use strict";

// Physical Windows/NTFS, opt-in N-API-independent HANDLE identity lab.
// These fixtures cannot establish production RootSession root custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const available = process.platform === "win32"
  && process.env.ROOTARK_ISSUE66_W26_NATIVE_PUBLISH_LAB === "1";
const localAppData = process.env.LOCALAPPDATA;
const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const script = path.join(__dirname, "support", "issue-66-w26-native-file-publish-lab.ps1");

function fixture() {
  assert.ok(localAppData && path.win32.isAbsolute(localAppData));
  const directory = fs.mkdtempSync(path.join(localAppData, "rootark-w26-native-publish-"));
  assert.match(path.basename(directory), /^rootark-w26-native-publish-[A-Za-z0-9_-]{6,}$/);
  assert.equal(path.dirname(directory).toLowerCase(), localAppData.toLowerCase());
  // Deliberately retain fixtures: recursive pathname cleanup could target a
  // swapped subtree. These are unique LocalAppData test-owned directories.
  return directory;
}

function invoke(scratch, mode, enabled = true, allowHardExit = false,
  allowColdInspect = false, allowExternalWriter = false, allowAncestorAttack = false) {
  return spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", script, "-Scratch", scratch, "-Mode", mode,
  ], {
    windowsHide: true, encoding: "utf8", timeout: 20000, maxBuffer: 8192,
    env: { ...process.env,
      ROOTARK_ISSUE66_W26_NATIVE_PUBLISH_LAB: enabled ? "1" : "0",
      ROOTARK_ISSUE66_W26_HARD_EXIT_LAB: allowHardExit ? "1" : "0",
      ROOTARK_ISSUE66_W26_COLD_INSPECT_LAB: allowColdInspect ? "1" : "0",
      ROOTARK_ISSUE66_W26_EXTERNAL_WRITER_LAB: allowExternalWriter ? "1" : "0",
      ROOTARK_ISSUE66_W26_ANCESTOR_ATTACK_LAB: allowAncestorAttack ? "1" : "0" },
  });
}

test("#66 W26 Windows NTFS publishes the original opened stage HANDLE without a surviving alias",
  { skip: !available, timeout: 25000 }, () => {
    const scratch = fixture();
    const result = invoke(scratch, "NORMAL");
    assert.equal(result.status, 0, result.stderr || "HANDLE publish failed");
    assert.match(result.stdout, /^ROOTARK_W26_HANDLE_PUBLISH mode=NORMAL result=ORIGINAL_HANDLE inode=PINNED no_replace=YES\r?\n$/);
    assert.equal(result.stderr, "");
  });

test("#66 W26 Windows NTFS refuses physical foreign destination without clobber",
  { skip: !available, timeout: 25000 }, () => {
    const scratch = fixture();
    const result = invoke(scratch, "COLLISION");
    assert.equal(result.status, 0, result.stderr || "HANDLE collision proof failed");
    assert.match(result.stdout, /^ROOTARK_W26_HANDLE_PUBLISH mode=COLLISION result=DENIED foreign=INTACT stage=INTACT collisionNtstatus=0xC0000035\r?\n$/);
    assert.equal(result.stderr, "");
  });

test("#66 W26 external same-SID writer cannot overwrite the original opened NTFS publication", {
  skip: !available, timeout: 35000,
}, async () => {
  const scratch = fixture();
  // Unlike COLLISION, the foreign inode here comes from a second REAL OS
  // process, which runs while the publisher holds both native HANDLEs.
  // The signal is disposable lab coordination, not trusted root authority.
  const writerCode = String.raw`
    const fs = require('node:fs');
    const path = require('node:path');
    const scratch = process.argv[1];
    const ready = path.join(scratch, 'publisher-ready.signal');
    const target = path.join(scratch, 'held', 'published.bin');
    const ack = path.join(scratch, 'writer-ack.signal');
    const sleep = new Int32Array(new SharedArrayBuffer(4));
    let signaled = false;
    for (let i = 0; i < 1000; i++) {
      try {
        const descriptor = fs.openSync(ready, 'r');
        try { signaled = fs.readFileSync(descriptor, 'utf8') === 'PUBLISHER_READY_V1'; }
        finally { fs.closeSync(descriptor); }
        if (!signaled) throw new Error('INVALID_PUBLISHER_SIGNAL');
        break;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      Atomics.wait(sleep, 0, 0, 10);
    }
    if (!signaled) throw new Error('PUBLISHER_NOT_READY');
    const publish = (name, body) => {
      const handle = fs.openSync(name, 'wx', 0o600);
      try {
        const bytes = Buffer.from(body);
        let written = 0;
        while (written < bytes.length) written += fs.writeSync(handle, bytes, written, bytes.length - written);
        fs.fsyncSync(handle);
      } finally { fs.closeSync(handle); }
    };
    publish(target, 'FOREIGN_UNTRUSTED_TARGET_BYTES');
    publish(ack, 'WRITER_READY_V1');
  `;
  const writer = spawn(process.execPath, ["-e", writerCode, scratch], {
    windowsHide: true, stdio: "ignore",
  });
  const writerResult = new Promise((resolve, reject) => {
    writer.once("error", reject);
    writer.once("exit", (code, signal) => resolve({ code, signal }));
  });
  const publisher = invoke(scratch, "EXTERNAL_COLLISION", true, false, false, true);
  const writerExit = await writerResult;
  assert.deepEqual(writerExit, { code: 0, signal: null },
    "the independent OS writer must physically create and fsync the foreign inode");
  assert.equal(publisher.status, 0, publisher.stderr || "external NTFS collision proof failed");
  assert.match(publisher.stdout,
    /^ROOTARK_W26_HANDLE_PUBLISH mode=EXTERNAL_COLLISION result=DENIED foreign=INTACT stage=INTACT collisionNtstatus=0xC0000035\r?\n$/);
  assert.equal(publisher.stderr, "");
  assert.equal(fs.readFileSync(path.join(scratch, "writer-ack.signal"), "utf8"), "WRITER_READY_V1");
  const stage = fs.openSync(path.join(scratch, "held", "stage.bin"), "r");
  const foreign = fs.openSync(path.join(scratch, "held", "published.bin"), "r");
  try {
    const original = fs.fstatSync(stage, { bigint: true });
    const planted = fs.fstatSync(foreign, { bigint: true });
    assert.equal(original.isFile(), true);
    assert.equal(planted.isFile(), true);
    assert.notEqual(original.ino, planted.ino, "the foreign name must be a different NTFS inode");
    assert.equal(fs.readFileSync(stage, "utf8"), "ORIGINAL_OPENED_STAGE_BYTES");
    assert.equal(fs.readFileSync(foreign, "utf8"), "FOREIGN_UNTRUSTED_TARGET_BYTES");
    assert.equal(fs.fstatSync(stage, { bigint: true }).ino, original.ino);
    assert.equal(fs.fstatSync(foreign, { bigint: true }).ino, planted.ino);
  } finally {
    fs.closeSync(stage);
    fs.closeSync(foreign);
  }
});

test("#66 W26 external same-SID writer rehearsal requires a separate explicit opt-in", {
  skip: !available,
}, () => {
  const scratch = fixture();
  const denied = invoke(scratch, "EXTERNAL_COLLISION");
  assert.equal(denied.status, 41);
  assert.equal(denied.stdout, "");
  assert.match(denied.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
  assert.deepEqual(fs.readdirSync(scratch), [], "disabled laboratory must not create a held directory");
});

test("#66 W26 Windows NTFS cannot publish a late equal-byte foreign stage instead of opened HANDLE",
  { skip: !available, timeout: 25000 }, () => {
    const scratch = fixture();
    const result = invoke(scratch, "SOURCE_SWAP");
    assert.equal(result.status, 0, result.stderr || "HANDLE stage-swap proof failed");
    assert.match(result.stdout, /^ROOTARK_W26_HANDLE_PUBLISH mode=SOURCE_SWAP result=ORIGINAL_HANDLE inode=PINNED no_replace=YES\r?\n$/);
    assert.equal(result.stderr, "");
  });

test("#66 W26 Windows NTFS pinned directory HANDLE publishes into A while foreign B occupies its old path",
  { skip: !available, timeout: 25000 }, () => {
    const scratch = fixture();
    const result = invoke(scratch, "ROOT_SWAP");
    assert.equal(result.status, 0, result.stderr || "HANDLE root-swap proof failed");
    assert.match(result.stdout, /^ROOTARK_W26_HANDLE_PUBLISH mode=ROOT_SWAP result=ORIGINAL_HANDLE inode=PINNED no_replace=YES\r?\n$/);
    assert.equal(result.stderr, "");
  });

for (const mode of ["HELD_REBIND", "HELD_JUNCTION"]) {
  test(`#66 W26 rejects physical same-SID ${mode} under scratch parent before PREPARE`,
    { skip: !available, timeout: 35000 }, async () => {
      const scratch = fixture();
      const parked = path.join(scratch, "held-parked");
      // Windows denies a rename of scratch itself with a live descendant
      // directory HANDLE (EPERM). Exercise the movable held entry instead,
      // still under the unique scratch owned by this test.
      const attacker = String.raw`
        const fs = require('node:fs');
        const path = require('node:path');
        const scratch = process.argv[1];
        const mode = process.argv[2];
        const held = path.join(scratch, 'held');
        const parked = path.join(scratch, 'held-parked');
        const sleep = new Int32Array(new SharedArrayBuffer(4));
        let ready = false;
        for (let i = 0; i < 1000; i++) {
          try {
            ready = fs.readFileSync(path.join(scratch, 'ancestor-ready.signal'), 'utf8')
              === 'ANCESTOR_READY_V1';
            if (!ready) throw new Error('INVALID_ANCESTOR_SIGNAL');
            break;
          } catch (error) {
            if (error.code !== 'ENOENT') throw error;
          }
          Atomics.wait(sleep, 0, 0, 10);
        }
        if (!ready) throw new Error('ANCESTOR_NOT_READY');
        fs.renameSync(held, parked);
        if (mode === 'HELD_REBIND') {
          fs.mkdirSync(held);
          const foreign = fs.openSync(path.join(held, 'published.bin'), 'wx');
          try {
            fs.writeSync(foreign, 'FOREIGN_UNTRUSTED_TARGET_BYTES');
            fs.fsyncSync(foreign);
          } finally { fs.closeSync(foreign); }
        } else {
          // On Windows a junction is created by the real filesystem API.
          fs.symlinkSync(parked, held, 'junction');
          if (!fs.lstatSync(held).isSymbolicLink()) throw new Error('JUNCTION_NOT_PHYSICAL');
        }
        const ack = fs.openSync(path.join(scratch, 'ancestor-ack.signal'), 'wx');
        try {
          fs.writeSync(ack, 'ANCESTOR_REBOUND_V1');
          fs.fsyncSync(ack);
        } finally { fs.closeSync(ack); }
      `;
      const writer = spawn(process.execPath, ["-e", attacker, scratch, mode], {
        windowsHide: true, stdio: ["ignore", "ignore", "pipe"],
      });
      let writerError = "";
      writer.stderr.setEncoding("utf8");
      writer.stderr.on("data", (chunk) => { writerError += chunk; });
      const writerResult = new Promise((resolve, reject) => {
        writer.once("error", reject);
        writer.once("exit", (code, signal) => resolve({ code, signal }));
      });
      const publisher = invoke(scratch, mode, true, false, false, false, true);
      assert.deepEqual(await writerResult, { code: 0, signal: null }, writerError);
      assert.equal(fs.readFileSync(path.join(scratch, "ancestor-ack.signal"), "utf8"),
        "ANCESTOR_REBOUND_V1");
      assert.equal(publisher.status, 41, "rebound ancestor must fail closed");
      assert.equal(publisher.stdout, "");
      assert.match(publisher.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
      assert.equal(fs.readFileSync(path.join(parked, "stage.bin"), "utf8"),
        "ORIGINAL_OPENED_STAGE_BYTES");
      assert.equal(fs.existsSync(path.join(parked, "prepared.bin")), false,
        "rebind must be denied before PREPARE");
      assert.equal(fs.existsSync(path.join(parked, "published.bin")), false,
        "no publication may occur through the detached original handle");
      if (mode === "HELD_REBIND") {
        assert.notEqual(fs.statSync(parked, { bigint: true }).ino,
          fs.statSync(path.join(scratch, "held"), { bigint: true }).ino,
          "the same-SID process must substitute a different NTFS directory identity");
        assert.equal(fs.readFileSync(path.join(scratch, "held", "published.bin"), "utf8"),
          "FOREIGN_UNTRUSTED_TARGET_BYTES");
      } else {
        assert.equal(fs.lstatSync(path.join(scratch, "held")).isSymbolicLink(), true,
          "the held pathname under scratch must now be a physical junction");
      }
    });
}

test("#66 W26 ancestor-rebind attack requires an independent explicit opt-in", {
  skip: !available, timeout: 25000,
}, () => {
  const scratch = fixture();
  const denied = invoke(scratch, "HELD_REBIND");
  assert.equal(denied.status, 41);
  assert.equal(denied.stdout, "");
  assert.match(denied.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
  assert.deepEqual(fs.readdirSync(scratch), []);
});

test("#66 W26 native HANDLE laboratory rejects disabled and populated scratch",
  { skip: !available, timeout: 25000 }, () => {
    const disabledScratch = fixture();
    const disabled = invoke(disabledScratch, "NORMAL", false);
    assert.equal(disabled.status, 41);
    assert.equal(disabled.stdout, "");
    assert.match(disabled.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
    assert.deepEqual(fs.readdirSync(disabledScratch), []);

    const dirtyScratch = fixture();
    fs.writeFileSync(path.join(dirtyScratch, "DO_NOT_TOUCH"), "foreign fixture bytes");
    const dirty = invoke(dirtyScratch, "NORMAL");
    assert.equal(dirty.status, 41);
    assert.equal(dirty.stdout, "");
    assert.match(dirty.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
    assert.equal(fs.readFileSync(path.join(dirtyScratch, "DO_NOT_TOUCH"), "utf8"),
      "foreign fixture bytes");
  });

test("#66 W26 NTFS pre-link abrupt process exit retains only staged bytes and PREPARED",
  { skip: !available, timeout: 25000 }, () => {
    const scratch = fixture();
    const result = invoke(scratch, "PRE_LINK_HARD_EXIT", true, true);
    assert.equal(result.status, 74, result.stderr);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
    const held = path.join(scratch, "held");
    assert.equal(fs.readFileSync(path.join(held, "stage.bin"), "utf8"),
      "ORIGINAL_OPENED_STAGE_BYTES");
    assert.match(fs.readFileSync(path.join(held, "prepared.bin"), "utf8"),
      /^PREPARED_V2:[0-9A-F]{16}-[0-9A-F]{32}:[0-9A-F]{16}-[0-9A-F]{32}$/);
    assert.equal(fs.existsSync(path.join(held, "published.bin")), false);
    assert.equal(fs.existsSync(path.join(held, "commit.bin")), false);
  });

test("#66 W26 NTFS completed native lab sequence writes COMMIT only after opened-HANDLE publish",
  { skip: !available, timeout: 25000 }, () => {
    const scratch = fixture();
    const result = invoke(scratch, "TXN_COMPLETE", true, true);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^ROOTARK_W26_HANDLE_PUBLISH mode=TXN_COMPLETE result=ORIGINAL_HANDLE inode=PINNED no_replace=YES\r?\n$/);
    const held = path.join(scratch, "held");
    assert.equal(fs.existsSync(path.join(held, "stage.bin")), false);
    const prepared = fs.readFileSync(path.join(held, "prepared.bin"), "utf8");
    assert.match(prepared,
      /^PREPARED_V2:[0-9A-F]{16}-[0-9A-F]{32}:[0-9A-F]{16}-[0-9A-F]{32}$/);
    assert.equal(fs.readFileSync(path.join(held, "published.bin"), "utf8"),
      "ORIGINAL_OPENED_STAGE_BYTES");
    assert.equal(fs.readFileSync(path.join(held, "commit.bin"), "utf8"),
      prepared.replace(/^PREPARED_V2:/, "COMMITTED_V2:"));
  });

test("#66 W26 NTFS post-rename abrupt process exit retains published inode without COMMIT",
  { skip: !available, timeout: 25000 }, () => {
    const scratch = fixture();
    const result = invoke(scratch, "POST_LINK_HARD_EXIT", true, true);
    assert.equal(result.status, 73, result.stderr);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
    const held = path.join(scratch, "held");
    assert.equal(fs.existsSync(path.join(held, "stage.bin")), false);
    assert.equal(fs.readFileSync(path.join(held, "published.bin"), "utf8"),
      "ORIGINAL_OPENED_STAGE_BYTES");
    assert.match(fs.readFileSync(path.join(held, "prepared.bin"), "utf8"),
      /^PREPARED_V2:[0-9A-F]{16}-[0-9A-F]{32}:[0-9A-F]{16}-[0-9A-F]{32}$/);
    assert.equal(fs.existsSync(path.join(held, "commit.bin")), false,
      "a physical process exit before COMMIT must not be called recovered");
  });

test("#66 W26 hard-exit mode cannot be enabled by the ordinary native lab flag alone",
  { skip: !available, timeout: 25000 }, () => {
    const scratch = fixture();
    const result = invoke(scratch, "PRE_LINK_HARD_EXIT", true, false);
    assert.equal(result.status, 41);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
    assert.deepEqual(fs.readdirSync(scratch), []);
  });

test("#66 W26 new process observes PREPARED-only crash using rooted read-only native HANDLEs",
  { skip: !available, timeout: 40000 }, () => {
    const scratch = fixture();
    const crash = invoke(scratch, "PRE_LINK_HARD_EXIT", true, true);
    assert.equal(crash.status, 74, crash.stderr);
    const denied = invoke(scratch, "COLD_INSPECT");
    assert.equal(denied.status, 41, "cold read requires a separate explicit opt-in");
    assert.equal(denied.stdout, "");
    const inspected = invoke(scratch, "COLD_INSPECT", true, false, true);
    assert.equal(inspected.status, 0, inspected.stderr);
    assert.equal(inspected.stderr, "");
    assert.match(inspected.stdout,
      /^ROOTARK_W26_COLD_INSPECT phase=PREPARED_ONLY authority=LAB_ONLY_NO_GO\r?\n$/);
    assert.equal(fs.readFileSync(path.join(scratch, "held", "stage.bin"), "utf8"),
      "ORIGINAL_OPENED_STAGE_BYTES");
    assert.equal(fs.existsSync(path.join(scratch, "held", "published.bin")), false);
  });

test("#66 W26 new process observes published-uncommitted inode and never invents COMMIT",
  { skip: !available, timeout: 40000 }, () => {
    const scratch = fixture();
    const crash = invoke(scratch, "POST_LINK_HARD_EXIT", true, true);
    assert.equal(crash.status, 73, crash.stderr);
    const inspected = invoke(scratch, "COLD_INSPECT", true, false, true);
    assert.equal(inspected.status, 0, inspected.stderr);
    assert.equal(inspected.stderr, "");
    assert.match(inspected.stdout,
      /^ROOTARK_W26_COLD_INSPECT phase=PUBLISHED_NO_COMMIT authority=LAB_ONLY_NO_GO\r?\n$/);
    assert.equal(fs.existsSync(path.join(scratch, "held", "commit.bin")), false);
  });

test("#66 W26 cold native phase inspector distinguishes COMMIT and denies corrupt foreign bytes",
  { skip: !available, timeout: 40000 }, () => {
    const scratch = fixture();
    const complete = invoke(scratch, "TXN_COMPLETE", true, true);
    assert.equal(complete.status, 0, complete.stderr);
    const observed = invoke(scratch, "COLD_INSPECT", true, false, true);
    assert.equal(observed.status, 0, observed.stderr);
    assert.match(observed.stdout,
      /^ROOTARK_W26_COLD_INSPECT phase=COMMIT_OBSERVED authority=LAB_ONLY_NO_GO\r?\n$/);
    // This is the same-SID *test fixture*, never a trusted custodian. A
    // tampered unsigned marker must fail rather than becoming a recovery GO.
    fs.writeFileSync(path.join(scratch, "held", "commit.bin"), "FOREIGN_COMMIT");
    const corrupted = invoke(scratch, "COLD_INSPECT", true, false, true);
    assert.equal(corrupted.status, 41);
    assert.equal(corrupted.stdout, "");
    assert.match(corrupted.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
    const prepared = fs.readFileSync(path.join(scratch, "held", "prepared.bin"), "utf8");
    fs.writeFileSync(path.join(scratch, "held", "commit.bin"),
      prepared.replace(/^PREPARED_V2:/, "COMMITTED_V2:"));
    const published = path.join(scratch, "held", "published.bin");
    const alias = path.join(scratch, "held", "foreign-hardlink.bin");
    fs.linkSync(published, alias);
    const linked = invoke(scratch, "COLD_INSPECT", true, false, true);
    assert.equal(linked.status, 41,
      "a second physical hardlink must fail the native opened-inode admission");
    assert.equal(linked.stdout, "");
    assert.equal(fs.readFileSync(published, "utf8"), "ORIGINAL_OPENED_STAGE_BYTES");
    assert.equal(fs.readFileSync(alias, "utf8"), "ORIGINAL_OPENED_STAGE_BYTES");
  });

test("#66 W26 cold native inspector rejects same-byte foreign published FileId after real COMMIT", {
  skip: !available, timeout: 40000,
}, () => {
  const scratch = fixture();
  const complete = invoke(scratch, "TXN_COMPLETE", true, true);
  assert.equal(complete.status, 0, complete.stderr);
  const held = path.join(scratch, "held");
  const published = path.join(held, "published.bin");
  const parked = path.join(held, "original-published-inode-retained.bin");
  // Keep the original inode under a harmless new name, and introduce an
  // equal-byte FOREIGN file at the published name with wx+flush. A validator
  // checking only marker text would incorrectly report COMMIT_OBSERVED.
  fs.renameSync(published, parked);
  const originalFd = fs.openSync(parked, "r");
  let foreignFd;
  try {
    foreignFd = fs.openSync(published, "wx+", 0o600);
    const readHeld = (fd, size) => {
      const bytes = Buffer.alloc(size + 1);
      const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
      assert.equal(length, size, "the original opened inode must have exactly its checked bytes");
      return bytes.subarray(0, length);
    };
    const originalLength = Number(fs.fstatSync(originalFd, { bigint: true }).size);
    const originalBytes = readHeld(originalFd, originalLength);
    fs.writeSync(foreignFd, originalBytes, 0, originalBytes.length, 0);
    fs.fsyncSync(foreignFd);
    const originalStat = fs.fstatSync(originalFd, { bigint: true });
    const foreignStat = fs.fstatSync(foreignFd, { bigint: true });
    assert.notEqual(originalStat.ino, foreignStat.ino,
      "the attacker must insert a genuinely distinct NTFS FILE_ID");
    assert.deepEqual(readHeld(foreignFd, originalLength), originalBytes);
    const wrong = invoke(scratch, "COLD_INSPECT", true, false, true);
    assert.equal(wrong.status, 41,
      "same bytes from an unrelated FILE_ID must not become COMMIT authorization");
    assert.equal(wrong.stdout, "");
    assert.match(wrong.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
    assert.deepEqual(readHeld(originalFd, originalLength), originalBytes);
    assert.deepEqual(readHeld(foreignFd, originalLength), originalBytes);
    assert.equal(fs.fstatSync(originalFd, { bigint: true }).ino, originalStat.ino);
    assert.equal(fs.fstatSync(foreignFd, { bigint: true }).ino, foreignStat.ino);
  } finally {
    if (foreignFd !== undefined) fs.closeSync(foreignFd);
    fs.closeSync(originalFd);
  }
});
