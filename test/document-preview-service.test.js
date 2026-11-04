const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { MAX_INPUT_BYTES, MAX_OUTPUT_CHARS, previewText } = require("../services/documentPreviewService");

test("document preview bounds text inputs", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const write = (name, value) => { const target = path.join(dir, name); fs.writeFileSync(target, value); return target; };
  await t.test("small UTF-8 text is returned", async () => assert.equal((await previewText(write("small.txt", "olá"), "small.txt")).content, "olá"));
  await t.test("Unicode filenames are accepted", async () => assert.equal((await previewText(write("文档.md", "ok"), "文档.md")).language, "md"));
  await t.test("binary extension is rejected", async () => await assert.rejects(previewText(write("binary.exe", Buffer.from([0, 255])), "binary.exe"), /PREVIEW_UNSUPPORTED/));
  await t.test("unsupported extension is rejected", async () => await assert.rejects(previewText(write("image.png", "x"), "image.png"), /PREVIEW_UNSUPPORTED/));
  await t.test("script-like text stays literal", async () => {
    for (const value of ["<script>alert(1)</script>", "<ScRiPt>alert(1)</ScRiPt>"]) {
      assert.equal((await previewText(write("script.txt", value), "script.txt")).content, value);
    }
  });
  await t.test("event-handler-like text stays literal", async () => assert.match((await previewText(write("event.txt", "onerror=alert(1)"), "event.txt")).content, /onerror/));
  await t.test("oversized input is rejected before parsing", async () => await assert.rejects(previewText(write("large.txt", Buffer.alloc(MAX_INPUT_BYTES + 1)), "large.txt"), /PREVIEW_TOO_LARGE/));
  await t.test("large text output is truncated deterministically", async () => {
    const result = await previewText(write("long.txt", "x".repeat(MAX_OUTPUT_CHARS + 1)), "long.txt");
    assert.equal(result.content.endsWith("[preview truncated]"), true); assert.ok(result.content.length <= MAX_OUTPUT_CHARS + 32);
  });
  await t.test("malformed DOCX returns a parser failure", async () => await assert.rejects(previewText(write("broken.docx", "not a zip"), "broken.docx")));
  for (const extension of [".json", ".csv", ".log", ".xml", ".yaml", ".yml"]) {
    await t.test(`${extension} is accepted as bounded text`, async () => assert.equal((await previewText(write(`data${extension}`, "ok"), `data${extension}`)).language, extension.slice(1)));
  }
  await t.test("invalid UTF-8 is decoded without executing content", async () => assert.ok((await previewText(write("invalid.txt", Buffer.from([0xc3, 0x28])), "invalid.txt")).content.length > 0));
  await t.test("uppercase supported extension is normalized", async () => assert.equal((await previewText(write("upper.TXT", "ok"), "upper.TXT")).language, "txt"));
  await t.test("missing input fails without creating artifacts", async () => await assert.rejects(previewText(path.join(dir, "missing.txt"), "missing.txt")));
  await t.test("directory input is rejected", async () => { const nested = path.join(dir, "folder.txt"); fs.mkdirSync(nested); await assert.rejects(previewText(nested, "folder.txt"), /PREVIEW_TOO_LARGE/); });
  await t.test("malformed DOC is rejected", async () => await assert.rejects(previewText(write("broken.doc", "not an ole document"), "broken.doc")));
  await t.test("text format reports its extension", async () => assert.equal((await previewText(write("language.xml", "<x/>"), "language.xml")).format, "text"));
  await t.test("empty text is stable", async () => assert.equal((await previewText(write("empty.txt", ""), "empty.txt")).content, ""));
  await t.test("preview creates no temporary files", async () => { const target = write("clean.txt", "ok"); const before = fs.readdirSync(dir).sort(); await previewText(target, "clean.txt"); assert.deepEqual(fs.readdirSync(dir).sort(), before); });
});
