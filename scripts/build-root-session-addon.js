"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const SOURCE = path.join(ROOT, "native", "rootark_root_session.cc");
const OUT_DIR = path.join(ROOT, "native", "build");
const OUTPUT = path.join(OUT_DIR, `rootark_root_session_${process.platform}_${process.arch}.node`);

function findWindowsNodeCache() {
  const cacheRoot = path.join(process.env.LOCALAPPDATA || "", "node-gyp", "Cache");
  if (!fs.existsSync(cacheRoot)) return null;
  const exact = process.versions.node;
  const candidates = [exact, ...fs.readdirSync(cacheRoot).filter((v) => v !== exact).sort().reverse()];
  for (const ver of candidates) {
    const inc = path.join(cacheRoot, ver, "include", "node");
    const lib = path.join(cacheRoot, ver, "x64", "node.lib");
    if (fs.existsSync(path.join(inc, "node_api.h")) && fs.existsSync(lib)) return { inc, lib };
  }
  return null;
}

function buildWindows() {
  const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";
  if (!fs.existsSync(vswhere)) throw new Error("vswhere.exe not found");
  const where = spawnSync(vswhere, ["-all", "-products", "*", "-prerelease", "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"],
    { encoding: "utf8", windowsHide: true });
  const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
  if (!vcvars) throw new Error("vcvars64.bat not found");
  let nodeCache = findWindowsNodeCache();
  if (!nodeCache) {
    spawnSync("npx.cmd", ["--yes", "node-gyp", "install"], { encoding: "utf8", windowsHide: true });
    nodeCache = findWindowsNodeCache();
  }
  if (!nodeCache) throw new Error("node-gyp cache with node_api.h and node.lib not found");

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-napi-"));
  try {
    const batPath = path.join(scratch, "build.bat");
    const cmd = `@echo off\r\ncall "${vcvars}" >nul || exit /b 1\r\ncl /nologo /std:c++17 /O2 /LD /EHsc /DUNICODE /D_UNICODE /DNODE_GYP_MODULE_NAME=rootark_root_session /I"${nodeCache.inc}" "${SOURCE}" /Fe:"${OUTPUT}" /Fo:"${path.join(scratch, "rootark_root_session.obj")}" /link "${nodeCache.lib}" cldapi.lib advapi32.lib\r\n`;
    fs.writeFileSync(batPath, cmd, "utf8");
    const res = spawnSync("cmd.exe", ["/d", "/c", batPath], { encoding: "utf8", windowsHide: true });
    if (res.status !== 0) throw new Error(`MSVC build failed:\n${res.stdout}\n${res.stderr}`);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

function buildPosix() {
  const incCandidates = [
    "/usr/include/node",
    path.join(path.dirname(process.execPath), "..", "include", "node"),
  ].filter((d) => fs.existsSync(path.join(d, "node_api.h")));
  if (!incCandidates.length) throw new Error("node_api.h not found on POSIX");
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const args = [
    "-std=c++17", "-O2", "-shared", "-fPIC",
    "-DNODE_GYP_MODULE_NAME=rootark_root_session",
    `-I${incCandidates[0]}`,
    SOURCE, "-o", OUTPUT,
  ];
  const res = spawnSync("g++", args, { encoding: "utf8" });
  if (res.status !== 0) throw new Error(`g++ build failed:\n${res.stdout}\n${res.stderr}`);
}

function buildAddon() {
  if (process.platform === "win32") buildWindows();
  else buildPosix();
  return OUTPUT;
}

if (require.main === module) {
  console.log(buildAddon());
}

module.exports = { buildAddon, OUTPUT };
