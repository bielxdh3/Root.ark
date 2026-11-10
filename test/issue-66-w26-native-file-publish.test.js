"use strict";

// Physical Windows/NTFS, opt-in N-API-independent HANDLE identity lab.
// These fixtures cannot establish production RootSession root custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

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
  allowColdInspect = false) {
  return spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", script, "-Scratch", scratch, "-Mode", mode,
  ], {
    windowsHide: true, encoding: "utf8", timeout: 20000, maxBuffer: 8192,
    env: { ...process.env,
      ROOTARK_ISSUE66_W26_NATIVE_PUBLISH_LAB: enabled ? "1" : "0",
      ROOTARK_ISSUE66_W26_HARD_EXIT_LAB: allowHardExit ? "1" : "0",
      ROOTARK_ISSUE66_W26_COLD_INSPECT_LAB: allowColdInspect ? "1" : "0" },
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
    assert.equal(fs.readFileSync(path.join(held, "prepared.bin"), "utf8"), "PREPARED_V1");
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
    assert.equal(fs.readFileSync(path.join(held, "prepared.bin"), "utf8"), "PREPARED_V1");
    assert.equal(fs.readFileSync(path.join(held, "published.bin"), "utf8"),
      "ORIGINAL_OPENED_STAGE_BYTES");
    assert.equal(fs.readFileSync(path.join(held, "commit.bin"), "utf8"), "COMMITTED_V1");
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
    assert.equal(fs.readFileSync(path.join(held, "prepared.bin"), "utf8"), "PREPARED_V1");
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
    fs.writeFileSync(path.join(scratch, "held", "commit.bin"), "COMMITTED_V1");
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
