"use strict";

// Isolated PR #298 feasibility gate. Never targets Root.ark user data.
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");

const source = path.resolve(__dirname, "../scripts/issue-67-native-contained-open.cpp");
const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";
const isWin = process.platform === "win32";

function run(file, args, cwd, timeout = 10000) {
  return spawnSync(file, args, { cwd, encoding: "utf8", timeout, windowsHide: true });
}

function invoke(exe, ...args) {
  const result = run(exe, args);
  assert.notEqual(result.status, null, `native timeout/error: ${result.error}`);
  return result;
}

async function observed(exe, root) {
  const result = invoke(exe, "--fingerprint", root);
  assert.equal(result.status, 0, `fingerprint: ${result.stdout} ${result.stderr}`);
  const data = JSON.parse(result.stdout.trim());
  assert.match(data.rootId, /^[0-9a-f]{48}$/);
  return data.rootId;
}

function denied(exe, root, relative, rootId) {
  const result = invoke(exe, "--open", root, relative, rootId);
  assert.notEqual(result.status, 0, `unsafe open accepted: ${result.stdout} ${result.stderr}`);
  assert.notEqual(result.stdout.includes('"contained":true'), true);
}

async function readyHold(exe, args, stdinMode = "ignore") {
  const child = spawn(exe, args, { windowsHide: true, stdio: [stdinMode, "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (data) => { stdout += data; });
  let notify;
  const signaled = new Promise((resolve, reject) => {
    notify = resolve;
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(
      `native exited before READY (${code}); stdout=${stdout}; stderr=${stderr}`)));
  });
  child.stderr.on("data", (data) => {
    stderr += data.toString();
    if (stderr.includes("READY")) notify();
  });
  await Promise.race([
    signaled,
    new Promise((_, reject) => setTimeout(() => reject(new Error("native READY timed out")), 4000)),
  ]);
  return {
    child,
    complete: () => new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, stdout, stderr }));
    }),
  };
}

test("#67 NT native helper has no path-based descendant open or mutations", async () => {
  const code = await fs.readFile(source, "utf8");
  assert.match(code, /RootDirectory|relativeOpen/);
  assert.match(code, /FILE_OPEN_REPARSE_POINT/);
  assert.match(code, /FILE_SHARE_READ \| \(directory \? FILE_SHARE_WRITE : 0\)/);
  assert.match(code, /FileIdInfo/);
  for (const operation of [/\bMoveFile(?:Ex)?W\s*\(/, /\bDeleteFileW\s*\(/,
    /\bWriteFile\s*\(/, /\bSetFileInformationByHandle\s*\(/,
    /\bCfRegisterSyncRoot\s*\(/]) {
    assert.doesNotMatch(code, operation);
  }
});

test("#67 Windows SDK /W4 /WX real NTFS containment, rename and alias gates",
  { skip: !isWin, timeout: 90000 }, async (t) => {
    const where = run(vswhere, ["-all", "-products", "*", "-prerelease",
      "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"], undefined, 6000);
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 SDK toolchain missing"); return; }
    const scratch = await fs.mkdtemp(path.join(path.resolve(__dirname, "..", ".."),
      "issue67-w9-native-fixture-"));
    t.after(() => fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));
    const exe = path.join(scratch, "native-contained-open.exe");
    const batch = path.join(scratch, "compile.cmd");
    await fs.writeFile(batch, ["@echo off", `call "${vcvars}" >nul`,
      "if errorlevel 1 exit /b 1",
      `cl /nologo /std:c++17 /W4 /WX /EHsc /Fe:"${exe}" "${source}"`,
      "exit /b %errorlevel%", ""].join("\r\n"));
    const built = run("cmd.exe", ["/d", "/c", batch], scratch, 40000);
    assert.equal(built.status, 0, `MSVC failed: ${built.stdout}\n${built.stderr}`);

    const root = path.join(scratch, "owned", ".rootark-trash");
    const outside = path.join(scratch, "external-canary");
    await fs.mkdir(root, { recursive: true });
    await fs.mkdir(outside);
    const file = path.join(root, "local.txt");
    await fs.writeFile(file, "owned bytes");
    await fs.writeFile(path.join(outside, "canary.txt"), "external bytes");
    const pinnedRoot = await observed(exe, root);
    assert.equal((await observed(exe, root.toUpperCase())), pinnedRoot,
      "case-insensitive aliases must retain the physical root FileIdInfo");

    await t.test("normal owned file has physical containment, without content read", () => {
      const result = invoke(exe, "--open", root, "local.txt", pinnedRoot);
      assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
      assert.deepEqual(JSON.parse(result.stdout.trim()), {
        ok: true, contained: true, fileContentRead: false, fileWritten: false,
      });
    });
    await t.test("traversal, ADS, path aliases and reserved names fail closed", () => {
      for (const name of ["..\\external-canary\\canary.txt", ".\\local.txt",
        "local.txt:ads", "local.txt.", "CON.txt", "\\\\?\\E:\\outside",
        "\\local.txt", "dir//file", "sub\\..\\local.txt"]) {
        denied(exe, root, name, pinnedRoot);
      }
    });
    await t.test("external hardlink and final symlink cannot be opened", async () => {
      const link = path.join(root, "crosslinked.txt");
      await fs.link(path.join(outside, "canary.txt"), link);
      denied(exe, root, "crosslinked.txt", pinnedRoot);
      try {
        await fs.symlink(path.join(outside, "canary.txt"), path.join(root, "file-symlink.txt"), "file");
        denied(exe, root, "file-symlink.txt", pinnedRoot);
      } catch (error) {
        if (!["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) throw error;
        t.diagnostic("file symlink privilege unavailable; hardlink check completed");
      }
    });
    await t.test("junction placed at checked root or ancestor never escapes", async () => {
      const moved = path.join(scratch, "original-root");
      await fs.rename(root, moved);
      const mklink = run("cmd.exe", ["/d", "/c", "mklink", "/J", root, outside], scratch);
      assert.equal(mklink.status, 0, `junction fixture failed: ${mklink.stderr}`);
      denied(exe, root, "canary.txt", pinnedRoot);
      await fs.rm(root, { recursive: false, force: true });
      await fs.rename(moved, root);

      // The trusted root itself remains unchanged. A parent path replaced
      // before the fresh open must not resolve through a junction.
      const originalParent = path.join(scratch, "owned");
      const relocated = path.join(scratch, "old-owned");
      await fs.rename(originalParent, relocated);
      const another = run("cmd.exe", ["/d", "/c", "mklink", "/J", originalParent, outside], scratch);
      assert.equal(another.status, 0);
      denied(exe, root, "canary.txt", pinnedRoot);
      await fs.rm(originalParent, { recursive: false, force: true });
      await fs.rename(relocated, originalParent);
      assert.equal(await fs.readFile(path.join(outside, "canary.txt"), "utf8"), "external bytes");
    });
    await t.test("a stale root FileIdInfo is denied even if a new plain directory takes its name", async () => {
      const moved = path.join(scratch, "old-root-normal");
      await fs.rename(root, moved);
      await fs.mkdir(root);
      await fs.writeFile(path.join(root, "local.txt"), "unrelated replacement");
      denied(exe, root, "local.txt", pinnedRoot);
      await fs.rm(root, { recursive: true, force: true });
      await fs.rename(moved, root);
    });
    await t.test("existing write handle denies admission", async () => {
      const writer = await fs.open(file, "r+");
      try { denied(exe, root, "local.txt", pinnedRoot); }
      finally { await writer.close(); }
      assert.equal(invoke(exe, "--open", root, "local.txt", pinnedRoot).status, 0);
    });
    await t.test("active pinned directory and leaf handles deny rename and new writers", async () => {
      const held = await readyHold(exe, ["--open", root, "local.txt", pinnedRoot, "--hold-ms", "2000"]);
      try {
        await assert.rejects(fs.rename(root, path.join(scratch, "relocated-while-open")),
          (error) => ["EPERM", "EACCES", "EBUSY"].includes(error.code));
        await assert.rejects(fs.rename(file, path.join(root, "renamed-while-open")),
          (error) => ["EPERM", "EACCES", "EBUSY"].includes(error.code));
        await assert.rejects(fs.open(file, "r+"),
          (error) => ["EPERM", "EACCES", "EBUSY"].includes(error.code));
      } finally {
        const ended = await held.complete();
        assert.equal(ended.code, 0, `native held handles failed: ${ended.stderr} ${ended.stdout}`);
      }
    });
    await t.test("existing writable mapped section is rejected, even after writer HANDLE closes", async () => {
      // A mapped section retains writable pages even after its CREATEFILE
      // writer handle is closed. Demand that native open fail while it exists.
      // This test alone does not prove every mapped-writer lifecycle safe.
      const mapSource = path.join(scratch, "mapped-view-writer.cpp");
      const mapExe = path.join(scratch, "mapped-view-writer.exe");
      const mapBatch = path.join(scratch, "mapped-view-build.cmd");
      await fs.writeFile(mapSource, [
        "#define WIN32_LEAN_AND_MEAN",
        "#include <Windows.h>",
        "#include <cstdio>",
        "int wmain(int argc, wchar_t** argv) {",
        "  if (argc != 2) return 2;",
        "  HANDLE file = CreateFileW(argv[1], GENERIC_READ | GENERIC_WRITE,",
        "    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,",
        "    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);",
        "  if (file == INVALID_HANDLE_VALUE) return 3;",
        "  HANDLE section = CreateFileMappingW(file, nullptr, PAGE_READWRITE, 0, 0, nullptr);",
        "  if (!section) { CloseHandle(file); return 4; }",
        "  void* view = MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, 0);",
        "  CloseHandle(file);",
        "  if (!view) { CloseHandle(section); return 5; }",
        "  std::fputs(\"READY\\n\", stderr); std::fflush(stderr);",
        "  if (std::getchar() == EOF) return 6;",
        "  static_cast<char*>(view)[0] = 'M';",
        "  if (!FlushViewOfFile(view, 1)) return 7;",
        "  UnmapViewOfFile(view); CloseHandle(section);",
        "  return 0;",
        "}",
        "",
      ].join("\n"));
      await fs.writeFile(mapBatch, ["@echo off", `call "${vcvars}" >nul`,
        "if errorlevel 1 exit /b 1",
        `cl /nologo /std:c++17 /W4 /WX /EHsc /Fe:"${mapExe}" "${mapSource}"`,
        "exit /b %errorlevel%", ""].join("\r\n"));
      const mapBuild = run("cmd.exe", ["/d", "/c", mapBatch], scratch, 40000);
      assert.equal(mapBuild.status, 0, `mapped fixture build: ${mapBuild.stdout} ${mapBuild.stderr}`);
      await fs.writeFile(file, "stable old bytes");
      const mapped = await readyHold(mapExe, [file], "pipe");
      try {
        await assert.rejects(
          readyHold(exe, ["--open", root, "local.txt", pinnedRoot, "--hold-ms", "2000"]),
          /native exited before READY \(4\)/,
          "a writable mapped view already exists; native read admission must refuse it");
        mapped.child.stdin.write("GO\n");
        const wrote = await mapped.complete();
        assert.equal(wrote.code, 0, `mapped writer failed: ${wrote.stderr}`);
        assert.equal(await fs.readFile(file, "utf8"), "Mtable old bytes",
          "mapped view wrote its own disposable content after its writer HANDLE closed");
      } finally {
        if (!mapped.child.killed && mapped.child.exitCode === null) {
          mapped.child.stdin.end();
          mapped.child.kill();
        }
      }
    });
    assert.equal(await fs.readFile(path.join(outside, "canary.txt"), "utf8"), "external bytes");
  });
