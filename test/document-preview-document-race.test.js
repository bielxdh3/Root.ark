"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createZipArchive } = require("./support/document-preview-archive");
const { parseDocumentInChildProcess, previewText, MAX_INPUT_BYTES } =
  require("../services/documentPreviewService");

async function writeDocx(file) {
  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(file);
    const archive = createZipArchive({ zlib: { level: 9 } });
    output.on("close", resolve);
    output.on("error", reject);
    archive.on("error", reject);
    archive.pipe(output);
    archive.append('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>', { name: "[Content_Types].xml" });
    archive.append('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>', { name: "_rels/.rels" });
    archive.append('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>safe</w:t></w:r></w:p></w:body></w:document>', { name: "word/document.xml" });
    archive.finalize();
  });
}

function fakeSuccess() {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = new EventEmitter();
  child.stdin.end = () => {};
  child.exitCode = null;
  child.kill = () => true;
  setImmediate(() => {
    child.exitCode = 0;
    child.stdout.emit("data", Buffer.from('{"ok":true,"content":"safe"}'));
    child.emit("close", 0);
  });
  return child;
}

for (const extension of [".doc", ".docx"]) {
  test(`DOC parser ${extension} only reads immutable private snapshot after rename swap`, async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-document-race-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const target = path.join(dir, `allowed${extension}`);
    const other = path.join(dir, `other${extension}`);
    const old = path.join(dir, `old${extension}`);
    if (extension === ".docx") {
      await writeDocx(target);
      await writeDocx(other);
    } else {
      fs.writeFileSync(target, "safe document");
      fs.writeFileSync(other, "SECRET document");
    }
    const originalDigest = crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex");
    let workerRequest;
    let capturedDigest;
    const result = await previewText(target, path.basename(target), {
      spawnImpl(_program, args) {
        workerRequest = JSON.parse(args[1]);
        fs.renameSync(target, old);
        fs.renameSync(other, target);
        const child = fakeSuccess();
        child.stdin.end = (snapshot) => {
          capturedDigest = crypto.createHash("sha256").update(snapshot).digest("hex");
        };
        return child;
      },
    });
    assert.equal(result.content, "safe");
    assert.deepEqual(workerRequest, { extension }, "child must never receive mutable pathname");
    assert.equal(capturedDigest, originalDigest, "piped snapshot must be authorized content");
  });
}

test("DOC parser rejects a replacement with oversized content between pathname stat and open", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-doc-oversized-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "allowed.doc");
  const old = path.join(dir, "old.doc");
  const oversized = path.join(dir, "too-large.doc");
  fs.writeFileSync(target, "allowed");
  fs.writeFileSync(oversized, Buffer.alloc(MAX_INPUT_BYTES + 1));
  const originalLstat = fs.lstatSync;
  const originalStat = fs.statSync;
  let swapped = false;
  const race = (original, file, opts) => {
    const stat = original.call(fs, file, ...opts);
    if (!swapped && file === target) {
      swapped = true;
      fs.renameSync(target, old);
      fs.renameSync(oversized, target);
    }
    return stat;
  };
  fs.lstatSync = (file, ...opts) => race(originalLstat, file, opts);
  fs.statSync = (file, ...opts) => race(originalStat, file, opts);
  try {
    await assert.rejects(previewText(target, "allowed.doc", {
      spawnImpl: () => { throw new Error("parser should never start"); },
    }), /PREVIEW_TOO_LARGE|PREVIEW_FILE_CHANGED/);
    assert.equal(swapped, true);
  } finally {
    fs.lstatSync = originalLstat;
    fs.statSync = originalStat;
  }
});

test("DOC parser refuses a symlink substituted between lstat and descriptor open", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-doc-symlink-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "allowed.doc");
  const old = path.join(dir, "old.doc");
  const secret = path.join(dir, "private.doc");
  fs.writeFileSync(target, "allowed");
  fs.writeFileSync(secret, "private contents");
  // Check platform symlink capabilities before installing the pathname hook.
  const probe = path.join(dir, "probe.doc");
  try { fs.symlinkSync(secret, probe, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
      t.skip(`symlink creation restricted: ${error.code}`);
      return;
    }
    throw error;
  }
  fs.unlinkSync(probe);
  const original = fs.lstatSync;
  let swapped = false;
  fs.lstatSync = (file, ...args) => {
    const stat = original.call(fs, file, ...args);
    if (!swapped && file === target) {
      swapped = true;
      fs.renameSync(target, old);
      fs.symlinkSync(secret, target, "file");
    }
    return stat;
  };
  try {
    await assert.rejects(parseDocumentInChildProcess(target, ".doc", {
      spawnImpl: () => { throw Error("parser must not start on symlink"); },
    }));
    assert.equal(swapped, true);
  } finally {
    fs.lstatSync = original;
  }
});

test("unreaped parser zeroizes captured input without creating a plaintext file", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-late-close-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "allowed.doc");
  fs.writeFileSync(target, "safe contents");
  let heldBytes;
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = new EventEmitter();
  child.stdin.end = (bytes) => { heldBytes = bytes; };
  child.exitCode = null;
  child.kill = () => true;
  await assert.rejects(parseDocumentInChildProcess(target, ".doc", {
    timeoutMs: 1,
    finalTerminationTimeoutMs: 1,
    spawnImpl: () => child,
  }), (error) => error.code === "PREVIEW_PROCESS_UNREAPED");
  assert.ok(Buffer.isBuffer(heldBytes));
  assert.ok(heldBytes.every((value) => value === 0), "unreaped parser leaves no live plaintext buffer in parent");
  child.exitCode = 137;
  child.emit("close", 137);
  assert.ok(heldBytes.every((value) => value === 0));
});

test("actual Mammoth child can extract DOCX bytes from a private snapshot", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-real-docx-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "real.docx");
  await writeDocx(target);
  const result = await previewText(target, "real.docx");
  assert.match(result.content, /safe/);
  assert.equal(result.format, "document");
});
