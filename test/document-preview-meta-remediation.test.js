const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { ZipArchive } = require("archiver");

const servicePath = path.join(__dirname, "..", "services", "documentPreviewService.js");
const workerPath = path.join(__dirname, "..", "services", "documentPreviewWorker.js");
const serverPath = path.join(__dirname, "..", "server.js");
const source = fs.readFileSync(servicePath, "utf8");
const serverSource = fs.readFileSync(serverPath, "utf8");
const { MAX_OUTPUT_CHARS, PARSER_WORKER, parseDocumentInChildProcess, previewText } = require("../services/documentPreviewService");

function fakeSpawn({ output = "", code = 0, delay = 0, never = false, error = null } = {}) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.pid = 43123;
  child.exitCode = null;
  child.killed = false;
  child.kill = () => { child.killed = true; child.exitCode = 137; return true; };
  if (!never) setTimeout(() => {
    if (error) child.emit("error", error);
    else {
      if (output) child.stdout.emit("data", Buffer.from(output));
      child.exitCode = code;
      child.emit("close", code);
    }
  }, delay);
  return child;
}

test("document preview killable parser and route boundary matrix", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-meta-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const textPath = path.join(dir, "fixture.txt");
  const docxPath = path.join(dir, "fixture.docx");
  const docPath = path.join(dir, "fixture.doc");
  fs.writeFileSync(textPath, "fixture");
  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(docxPath);
    const archive = new ZipArchive({ zlib: { level: 9 } });
    output.on("close", resolve); output.on("error", reject); archive.on("error", reject); archive.pipe(output);
    archive.append("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>", { name: "[Content_Types].xml" });
    archive.append("<document><body>fixture</body></document>", { name: "word/document.xml" });
    archive.finalize();
  });
  fs.writeFileSync(docPath, "not an ole document");
  const cases = [
    ["01 worker file exists", () => assert.equal(fs.existsSync(workerPath), true)],
    ["02 worker path is absolute", () => assert.equal(path.isAbsolute(PARSER_WORKER), true)],
    ["03 service uses child_process spawn", () => assert.match(source, /require\("node:child_process"\)/)],
    ["04 service does not use Promise.race", () => assert.equal(source.includes("Promise.race"), false)],
    ["05 service does not instantiate WordExtractor", () => assert.equal(source.includes("new WordExtractor"), false)],
    ["06 service does not import Mammoth parser", () => assert.equal(source.includes('require("mammoth")'), false)],
    ["07 worker imports Mammoth", () => assert.match(fs.readFileSync(workerPath, "utf8"), /require\("mammoth"\)/)],
    ["08 worker imports WordExtractor", () => assert.match(fs.readFileSync(workerPath, "utf8"), /require\("word-extractor"\)/)],
    ["09 docx extension is dispatched", async () => await assert.rejects(previewText(docxPath, "fixture.docx"))],
    ["10 doc extension is dispatched", async () => await assert.rejects(previewText(docPath, "fixture.doc"))],
    ["11 unsupported extension is rejected before spawn", async () => { let called = false; await assert.rejects(previewText(textPath, "fixture.png", { spawnImpl: () => { called = true; return fakeSpawn(); } }), /PREVIEW_UNSUPPORTED/); assert.equal(called, false); }],
    ["12 oversized parser input is rejected before spawn", async () => { const file = path.join(dir, "oversized.doc"); fs.writeFileSync(file, Buffer.alloc(5 * 1024 * 1024 + 1)); let called = false; await assert.rejects(previewText(file, "oversized.doc", { spawnImpl: () => { called = true; return fakeSpawn(); } }), /PREVIEW_TOO_LARGE/); assert.equal(called, false); }],
    ["13 directory parser input is rejected before spawn", async () => { const folder = path.join(dir, "folder.doc"); fs.mkdirSync(folder); await assert.rejects(previewText(folder, "folder.doc", { spawnImpl: () => fakeSpawn() }), /PREVIEW_TOO_LARGE/); }],
    ["14 missing parser input is rejected", async () => await assert.rejects(previewText(path.join(dir, "missing.doc"), "missing.doc"))],
    ["15 text preview bypasses child process", async () => { let called = false; const result = await previewText(textPath, "fixture.txt", { spawnImpl: () => { called = true; return fakeSpawn(); } }); assert.equal(result.content, "fixture"); assert.equal(called, false); }],
    ["16 child receives the node executable", async () => { let command; await parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: (...args) => { command = args; return fakeSpawn({ output: JSON.stringify({ ok: true, content: "ok" }) }); } }); assert.equal(command[0], process.execPath); }],
    ["17 child receives worker path", async () => { let command; await parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: (...args) => { command = args; return fakeSpawn({ output: JSON.stringify({ ok: true, content: "ok" }) }); } }); assert.equal(command[1][0], PARSER_WORKER); }],
    ["18 child receives only serialized request metadata", async () => { let command; await parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: (...args) => { command = args; return fakeSpawn({ output: JSON.stringify({ ok: true, content: "ok" }) }); } }); assert.deepEqual(JSON.parse(command[1][1]), { filePath: docxPath, extension: ".docx" }); }],
    ["19 child stdout response succeeds", async () => assert.equal(await parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: () => fakeSpawn({ output: JSON.stringify({ ok: true, content: "parsed" }) }) }), "parsed")],
    ["20 child document result keeps docx language", async () => assert.equal((await previewText(docxPath, "fixture.docx", { spawnImpl: () => fakeSpawn({ output: JSON.stringify({ ok: true, content: "parsed" }) }) })).language, "docx")],
    ["21 child document result keeps doc language", async () => assert.equal((await previewText(docPath, "fixture.doc", { spawnImpl: () => fakeSpawn({ output: JSON.stringify({ ok: true, content: "parsed" }) }) })).language, "doc")],
    ["22 nonzero child exit is rejected", async () => await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: () => fakeSpawn({ code: 1 }) }), /Falha no parser/)],
    ["23 malformed child JSON is rejected", async () => await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: () => fakeSpawn({ output: "not json" }) }), /Resposta de parser invalida/)],
    ["24 child ok=false is rejected", async () => await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: () => fakeSpawn({ output: JSON.stringify({ ok: false }) }) }), /Resposta de parser invalida/)],
    ["25 child error without close is surfaced as unreaped", async () => await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: () => fakeSpawn({ error: new Error("child failure") }) }), (error) => error.code === "PREVIEW_PROCESS_UNREAPED")],
    ["26 parser timeout without close is surfaced as unreaped", async () => { await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { timeoutMs: 10, spawnImpl: () => fakeSpawn({ never: true }) }), (error) => error.code === "PREVIEW_PROCESS_UNREAPED"); }],
    ["27 parser timeout kills child process", async () => { let child; await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { timeoutMs: 10, spawnImpl: () => { child = fakeSpawn({ never: true }); return child; } })); assert.equal(child.killed, true); }],
    ["28 parser timeout does not wait for parser completion", async () => { const started = Date.now(); await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { timeoutMs: 10, spawnImpl: () => fakeSpawn({ never: true }) })); assert.ok(Date.now() - started < 500); }],
    ["29 output cap rejects oversized parser response", async () => { let child; await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { maxOutputBytes: 16, spawnImpl: () => { child = fakeSpawn({ output: JSON.stringify({ ok: true, content: "too much output" }) }); return child; } }), /PREVIEW_OUTPUT_TOO_LARGE/); assert.equal(child.killed, true); }],
    ["30 output is bounded in parent process", async () => { const result = await parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: () => fakeSpawn({ output: JSON.stringify({ ok: true, content: "x".repeat(MAX_OUTPUT_CHARS + 100) }) }) }); assert.ok(result.length <= MAX_OUTPUT_CHARS + 32); assert.match(result, /preview truncated/); }],
    ["31 parser start failure is sanitized", async () => await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: () => { throw new Error("secret path"); } }), /Falha ao iniciar parser/)],
    ["32 parser stderr is not returned", async () => { const child = fakeSpawn({ code: 1 }); const original = child.stderr.emit.bind(child.stderr); child.stderr.emit = (...args) => original(...args); await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: () => child }), (error) => !String(error.message).includes("secret")); }],
    ["33 parser timeout option is honored", async () => { let child; await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { timeoutMs: 5, spawnImpl: () => { child = fakeSpawn({ output: JSON.stringify({ ok: true, content: "parsed" }), delay: 100 }); child.kill = () => { child.killed = true; child.exitCode = 137; queueMicrotask(() => child.emit("close", 137)); return true; }; return child; } }), (error) => error.code === "PREVIEW_TIMEOUT"); assert.equal(child.killed, true); }],
    ["34 parser output option is honored", async () => await assert.rejects(parseDocumentInChildProcess(docxPath, ".docx", { maxOutputBytes: 8, spawnImpl: () => fakeSpawn({ output: "123456789" }) }), /PREVIEW_OUTPUT_TOO_LARGE/)],
    ["35 successful preview creates no temp file", async () => { const before = fs.readdirSync(dir).sort(); await previewText(docxPath, "fixture.docx", { spawnImpl: () => fakeSpawn({ output: JSON.stringify({ ok: true, content: "parsed" }) }) }); assert.deepEqual(fs.readdirSync(dir).sort(), before); }],
    ["36 parser does not mutate source fixture", async () => { const before = fs.readFileSync(docxPath); await previewText(docxPath, "fixture.docx", { spawnImpl: () => fakeSpawn({ output: JSON.stringify({ ok: true, content: "parsed" }) }) }); assert.deepEqual(fs.readFileSync(docxPath), before); }],
    ["37 route invokes bounded preview service", () => assert.match(serverSource, /res\.json\(await previewText\(target\.filePath, target\.name\)\)/)],
    ["38 route maps oversized input", () => assert.match(serverSource, /error\.message === "PREVIEW_TOO_LARGE"/)],
    ["39 route maps unsupported input", () => assert.match(serverSource, /error\.message === "PREVIEW_UNSUPPORTED"/)],
    ["40 route has generic parser failure response", () => assert.match(serverSource, /Nao foi possivel gerar a previa/)],
    ["41 route remains authenticated", () => { const start = serverSource.indexOf('app.get("/preview/text'); assert.ok(serverSource.slice(start, start + 180).includes("authenticate")); }],
    ["42 worker process is launched without a shell", async () => { let options; await parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: (...args) => { options = args[2]; return fakeSpawn({ output: JSON.stringify({ ok: true, content: "ok" }) }); } }); assert.equal(options.shell, undefined); }],
    ["43 child process hides Windows window", async () => { let options; await parseDocumentInChildProcess(docxPath, ".docx", { spawnImpl: (...args) => { options = args[2]; return fakeSpawn({ output: JSON.stringify({ ok: true, content: "ok" }) }); } }); assert.equal(options.windowsHide, true); }],
    ["44 worker failure exits nonzero", () => { const worker = fs.readFileSync(workerPath, "utf8"); assert.match(worker, /process\.exitCode\s*=\s*1/); }],
  ];
  for (const [name, body] of cases) await t.test(name, body);
  assert.equal(cases.length, 44);
});
