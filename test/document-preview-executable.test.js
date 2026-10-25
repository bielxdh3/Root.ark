const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { preflightDocx, parseDocumentInChildProcess, MAX_CONCURRENT_PARSERS } = require("../services/documentPreviewService");

function fakeSpawn({ output = JSON.stringify({ ok: true, content: "ok" }), stderr = [], delay = 0, never = false, closeOnKill = 0 } = {}) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = new EventEmitter();
  child.stdin.end = () => {};
  child.pid = Math.floor(Math.random() * 10_000) + 1000;
  child.exitCode = null;
  child.killed = false;
  child.kill = (signal) => { child.killed = true; if (signal === "SIGKILL") { child.exitCode = 137; if (closeOnKill) setTimeout(() => child.emit("close", 137), closeOnKill); } return true; };
  if (!never) setTimeout(() => {
    for (const chunk of stderr) child.stderr.emit("data", Buffer.from(chunk));
    if (output) child.stdout.emit("data", Buffer.from(output));
    child.exitCode = 0;
    child.emit("close", 0);
  }, delay);
  return child;
}

function makeZip(filePath, entries) {
  const chunks = [];
  let offset = 0;
  const central = [];
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const data = Buffer.from(entry.data || "");
    const crc = require("node:zlib").crc32 ? require("node:zlib").crc32(data) : 0;
    const flags = entry.flags || 0;
    const method = entry.method || 0;
    const compressedSize = entry.compressedSize ?? data.length;
    const uncompressedSize = entry.uncompressedSize ?? data.length;
    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc >>> 0, 14);
    local.writeUInt32LE(compressedSize >>> 0, 18);
    local.writeUInt32LE(uncompressedSize >>> 0, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);
    chunks.push(local, data);
    const record = Buffer.alloc(46 + name.length);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(entry.versionMadeBy || 20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt16LE(flags, 8);
    record.writeUInt16LE(method, 10);
    record.writeUInt32LE(crc >>> 0, 16);
    record.writeUInt32LE(compressedSize >>> 0, 20);
    record.writeUInt32LE(uncompressedSize >>> 0, 24);
    record.writeUInt16LE(name.length, 28);
    record.writeUInt32LE(entry.externalAttributes || 0, 38);
    record.writeUInt32LE(offset, 42);
    name.copy(record, 46);
    central.push(record);
    offset += local.length + data.length;
  }
  const centralOffset = offset;
  const centralBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(centralOffset, 16);
  fs.writeFileSync(filePath, Buffer.concat([...chunks, centralBytes, end]));
}

test("parser child receives an allowlisted environment and globally caps stderr", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-exec-"));
  const filePath = path.join(dir, "fixture.doc");
  fs.writeFileSync(filePath, "fixture");
  process.env.PREVIEW_SECRET_SENTINEL = "must-not-cross-boundary";
  let spawnOptions;
  await parseDocumentInChildProcess(filePath, ".doc", { spawnImpl: (...args) => { spawnOptions = args[2]; return fakeSpawn(); } });
  assert.equal(spawnOptions.env.PREVIEW_SECRET_SENTINEL, undefined);
  await assert.rejects(parseDocumentInChildProcess(filePath, ".doc", { maxOutputBytes: 16_384, spawnImpl: () => fakeSpawn({ stderr: ["x".repeat(10_000), "y".repeat(7_000)] }) }), (error) => error.code === "PREVIEW_ERROR_OUTPUT_TOO_LARGE");
  delete process.env.PREVIEW_SECRET_SENTINEL;
  fs.rmSync(dir, { recursive: true, force: true });
});

test("parser concurrency has a bounded queue and releases timed-out work", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-queue-"));
  const filePath = path.join(dir, "fixture.doc");
  fs.writeFileSync(filePath, "fixture");
  const promises = Array.from({ length: MAX_CONCURRENT_PARSERS + 17 }, () => parseDocumentInChildProcess(filePath, ".doc", { timeoutMs: 10, spawnImpl: () => fakeSpawn({ never: true }) }));
  const results = await Promise.allSettled(promises);
  assert.equal(results.filter((result) => result.status === "rejected" && result.reason.code === "PREVIEW_BUSY").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected" && result.reason.code === "PREVIEW_PROCESS_UNREAPED").length, MAX_CONCURRENT_PARSERS + 16);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("parser termination waits for confirmed close and keeps the slot occupied", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-lifecycle-"));
  const filePath = path.join(dir, "fixture.doc");
  fs.writeFileSync(filePath, "fixture");
  let spawned = 0;
  const promises = Array.from({ length: MAX_CONCURRENT_PARSERS + 1 }, () => parseDocumentInChildProcess(filePath, ".doc", {
    timeoutMs: 5,
    spawnImpl: () => { spawned += 1; return fakeSpawn({ never: true, closeOnKill: 40 }); },
  }));
  const settled = Promise.allSettled(promises);
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(spawned, MAX_CONCURRENT_PARSERS);
  await assert.rejects(promises[0], (error) => error.code === "PREVIEW_TIMEOUT");
  await settled;
  fs.rmSync(dir, { recursive: true, force: true });
});

test("DOCX preflight rejects hostile ZIP structures without extraction", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-docx-preflight-"));
  const cases = [
    ["traversal", [{ name: "../escape.txt" }], "PREVIEW_DOCX_UNSAFE_PATH"],
    ["absolute", [{ name: "/escape.txt" }], "PREVIEW_DOCX_UNSAFE_PATH"],
    ["drive", [{ name: "C:/escape.txt" }], "PREVIEW_DOCX_UNSAFE_PATH"],
    ["symlink", [{ name: "link", versionMadeBy: (3 << 8) | 20, externalAttributes: 0xa0000000 }], "PREVIEW_DOCX_SYMLINK"],
    ["encrypted", [{ name: "secret.txt", flags: 1 }], "PREVIEW_DOCX_ENCRYPTED"],
    ["duplicate", [{ name: "same.txt" }, { name: "same.txt" }], "PREVIEW_DOCX_DUPLICATE_PATH"],
    ["case-collision", [{ name: "Same.txt" }, { name: "same.txt" }], "PREVIEW_DOCX_CASE_COLLISION"],
    ["ratio", [{ name: "ratio.txt", compressedSize: 1, uncompressedSize: 101 }], "PREVIEW_DOCX_RESOURCE_LIMIT"],
    ["total-size", [{ name: "large.txt", compressedSize: 1, uncompressedSize: 50 * 1024 * 1024 + 1 }], "PREVIEW_DOCX_RESOURCE_LIMIT"],
    ["relationship", [{ name: "word/_rels/document.xml.rels", data: '<Relationship TargetMode="External" Target="https://evil.test" />' }], "PREVIEW_DOCX_EXTERNAL_RELATIONSHIP"],
  ];
  for (const [name, entries, code] of cases) {
    const filePath = path.join(dir, `${name}.docx`);
    makeZip(filePath, entries);
    await assert.rejects(preflightDocx(filePath), (error) => error.code === code, name);
  }
  const tooManyPath = path.join(dir, "too-many.docx");
  makeZip(tooManyPath, Array.from({ length: 2_001 }, (_, index) => ({ name: `entry-${index}.txt` })));
  await assert.rejects(preflightDocx(tooManyPath), (error) => error.code === "PREVIEW_DOCX_TOO_MANY_ENTRIES");
  const malformedPath = path.join(dir, "malformed.docx");
  fs.writeFileSync(malformedPath, "not a ZIP");
  await assert.rejects(preflightDocx(malformedPath));
  const validPath = path.join(dir, "valid.docx");
  makeZip(validPath, [{ name: "word/document.xml", data: "<w:document/>" }]);
  await preflightDocx(validPath);
  assert.deepEqual(fs.readdirSync(dir).filter((name) => name.endsWith(".tmp")), []);
  fs.rmSync(dir, { recursive: true, force: true });
});
