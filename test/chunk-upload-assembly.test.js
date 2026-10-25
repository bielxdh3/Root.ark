"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { performance } = require("node:perf_hooks");
const { spawn } = require("node:child_process");
const { assembleChunkedUpload } = require("../services/chunkUploadAssembler");

function fixture(t, count) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-assembly-bounded-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const session = path.join(root, "parts");
  fs.mkdirSync(session);
  const expected = [];
  for (let i = 0; i < count; i += 1) {
    const bytes = Buffer.from([i % 256]);
    fs.writeFileSync(path.join(session, `${i}.part`), bytes);
    expected.push(bytes);
  }
  return { session, destination: path.join(session, "assembled.upload"), expected: Buffer.concat(expected) };
}

test("assembly opens 2,000 chunks with bounded parallel I/O and commits exact ordered bytes", {
  timeout: 15_000,
}, async (t) => {
  const fixtureData = fixture(t, 2000);
  const contentionFile = path.join(path.dirname(fixtureData.session), "bounded-background-io.tmp");
  // A separate Node process introduces modest concurrent filesystem pressure,
  // as with a shared hosted CI runner, without writing to another worktree.
  const contentionScript = [
    'const fs=require("node:fs");',
    'const until=Date.now()+8000;',
    'const data=Buffer.alloc(16*1024);',
    'function tick(){if(Date.now()>=until)return;',
    'fs.writeFileSync(process.argv[1],data);',
    'fs.readFileSync(process.argv[1]);setTimeout(tick,2)}tick();',
  ].join("");
  const load = spawn(process.execPath, ["-e", contentionScript, contentionFile], {
    stdio: "ignore", windowsHide: true,
  });
  let loadClosed = false;
  load.once("close", () => { loadClosed = true; });
  let inFlight = 0;
  let peak = 0;
  const slowOpen = async (...args) => {
    inFlight += 1;
    peak = Math.max(peak, inFlight);
    try {
      await new Promise((resolve) => setTimeout(resolve, 7));
      return await fs.promises.open(...args);
    } finally { inFlight -= 1; }
  };
  try {
    const beforeRss = process.memoryUsage().rss;
    const started = performance.now();
    await assembleChunkedUpload(fixtureData.session, fixtureData.destination, 2000,
      { openPart: slowOpen });
    const elapsed = performance.now() - started;
    assert.deepEqual(fs.readFileSync(fixtureData.destination), fixtureData.expected);
    assert.ok(peak > 1 && peak <= 16, `parallel open must be bounded (peak=${peak})`);
    assert.ok(elapsed < 6000, `2,000 serialized slow opens create a 30s final-request risk (elapsed=${elapsed.toFixed(0)}ms)`);
    t.diagnostic(`assembly: total=2000 elapsedMs=${elapsed.toFixed(0)} maxConcurrentOpens=${peak} bytes=${fixtureData.expected.length} rssDeltaBytes=${process.memoryUsage().rss - beforeRss} backgroundIo=on`);
  } finally {
    // Await child close before fixture cleanup: Windows will otherwise see
    // ENOTEMPTY while its filesystem pressure worker still writes the file.
    if (load.exitCode === null && load.signalCode === null) load.kill();
    if (!loadClosed) await new Promise((resolve) => load.once("close", resolve));
  }
});

test("assembly limits file-stream memory for two full 8 MiB parts", { timeout: 20_000 }, async (t) => {
  const { session, destination } = fixture(t, 2);
  const first = Buffer.alloc(8 * 1024 * 1024, 0x32);
  const second = Buffer.alloc(8 * 1024 * 1024, 0x7a);
  fs.writeFileSync(path.join(session, "0.part"), first);
  fs.writeFileSync(path.join(session, "1.part"), second);
  const expected = require("node:crypto").createHash("sha256").update(first).update(second).digest("hex");
  await assembleChunkedUpload(session, destination, 2);
  const actual = require("node:crypto").createHash("sha256").update(fs.readFileSync(destination)).digest("hex");
  assert.equal(actual, expected, "full chunk contents and order must survive streaming");
});

test("assembly fails closed on missing part and releases open file handles", { timeout: 10_000 }, async (t) => {
  const { session, destination } = fixture(t, 45);
  fs.unlinkSync(path.join(session, "17.part"));
  await assert.rejects(assembleChunkedUpload(session, destination, 45));
  assert.equal(fs.existsSync(destination), false, "no truncated ciphertext may be promoted");
  // This exercises Windows handle cleanup rather than accepting a lingering
  // open descriptor which prevents deletion or rename of the source directory.
  fs.renameSync(session, `${session}-renamed`);
  fs.renameSync(`${session}-renamed`, session);
});

test("assembly cannot overwrite or clean up an already-owned assembled payload", { timeout: 10_000 }, async (t) => {
  const { session, destination } = fixture(t, 4);
  fs.writeFileSync(destination, "preserve-existing-assembled-payload");
  await assert.rejects(assembleChunkedUpload(session, destination, 4),
    (error) => error.code === "EEXIST");
  assert.equal(fs.readFileSync(destination, "utf8"), "preserve-existing-assembled-payload");
});

test("assembly rejects hardlinked parts before copying their data", { timeout: 10_000 }, async (t) => {
  const { session, destination } = fixture(t, 24);
  fs.unlinkSync(path.join(session, "17.part"));
  fs.linkSync(path.join(session, "0.part"), path.join(session, "17.part"));
  await assert.rejects(assembleChunkedUpload(session, destination, 24),
    /Unsafe chunk assembly input/);
  assert.equal(fs.existsSync(destination), false);
});

test("assembly refuses a part replaced after pathname validation", { timeout: 10_000 }, async (t) => {
  const { session, destination } = fixture(t, 3);
  const original = path.join(session, "0.part");
  const swapped = path.join(session, "0.prior");
  const replacement = Buffer.from("UNTRUSTED_SUBSTITUTION_NOT_A_CHUNK");
  let injected = false;
  const openPart = async (filename, flags) => {
    if (!injected && filename === original) {
      injected = true;
      await fs.promises.rename(original, swapped);
      await fs.promises.writeFile(original, replacement);
    }
    return fs.promises.open(filename, flags);
  };
  await assert.rejects(assembleChunkedUpload(session, destination, 3, { openPart }),
    /Unsafe chunk assembly input/);
  assert.equal(injected, true);
  assert.equal(fs.existsSync(destination), false);
  assert.deepEqual(fs.readFileSync(swapped), Buffer.from([0]));
});

test("assembly never follows an input symlink outside the stage", { timeout: 10_000 }, async (t) => {
  const { session, destination } = fixture(t, 1);
  const source = path.join(path.dirname(session), "other-private-file");
  fs.writeFileSync(source, "must-not-be-copied");
  const part = path.join(session, "0.part");
  fs.unlinkSync(part);
  try { fs.symlinkSync(source, part, "file"); } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "EINVAL"].includes(error.code)) return t.skip("host disallows file symlinks");
    throw error;
  }
  await assert.rejects(assembleChunkedUpload(session, destination, 1),
    /Unsafe chunk assembly input/);
  assert.equal(fs.existsSync(destination), false);
  assert.equal(fs.readFileSync(source, "utf8"), "must-not-be-copied");
});
