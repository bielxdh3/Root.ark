"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync, spawn } = require("node:child_process");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const project = path.resolve(__dirname, "..");
const repositoryPath = path.join(project, "repositories", "auditRepository.js");
const pause = () => new Promise((resolve) => setTimeout(resolve, 20));

function fixtureRoot(prefix) {
  if (process.platform !== "win32") return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const root = path.join(process.env.LOCALAPPDATA || os.homedir(),
    `${prefix}${crypto.randomBytes(10).toString("hex")}`);
  ensureWindowsChunkUploadRoot(root);
  return root;
}

async function eventually(predicate, child) {
  for (let attempt = 0; attempt < 250; attempt += 1) {
    if (predicate()) return;
    if (child && child.exitCode !== null) {
      assert.fail(`fixture exited ${child.exitCode} before readiness: ${child.output()}`);
    }
    await pause();
  }
  assert.fail("cross-process fixture did not reach its synchronization point");
}

function subprocess(script, cwd, extra = {}) {
  const child = spawn(process.execPath, ["-e", script], {
    cwd, windowsHide: true,
    env: { ...process.env, DB_ENABLED: "false", ...extra },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (part) => { output += part; });
  child.stderr.on("data", (part) => { output += part; });
  child.result = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal, output })));
  child.output = () => output;
  return child;
}

test("JSON audit writers across Node processes serialize read, archive and overwrite", { timeout: 30_000 }, async (t) => {
  const root = fixtureRoot("rootark-json-audit-lock-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  fs.mkdirSync(path.join(root, "data"));
  fs.writeFileSync(path.join(root, "data", "audit-logs.json"), JSON.stringify({ logs: [{ id: "acknowledged" }] }));
  fs.writeFileSync(path.join(root, "data", "audit-logs-archive.json"), JSON.stringify({ logs: [{ id: "archived" }] }));
  const writer = (id, shouldPause) => `
    const fs=require('node:fs'),path=require('node:path'),repo=require(${JSON.stringify(repositoryPath)});
    const file=path.join(process.cwd(),'data','audit-logs.json');
    repo.withJsonAuditLock(()=>{
      const rows=repo.readJsonAuditHistory(file);
      fs.writeFileSync(${JSON.stringify(path.join(root, "ready-"))}+${JSON.stringify(id)},'ready');
      if(${JSON.stringify(shouldPause)}) {
        const deadline=Date.now()+10000;
        while(!fs.existsSync(${JSON.stringify(path.join(root, "go"))}) && Date.now()<deadline)
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,20);
        if(Date.now()>=deadline)throw Error('fixture wait timed out');
      }
      rows.logs.push({id:${JSON.stringify(id)},timestamp:new Date().toISOString()});
      repo.persistJsonAuditFile(rows,file);
    });`;
  const first = subprocess(writer("first", true), root);
  t.after(() => first.kill());
  await eventually(() => fs.existsSync(path.join(root, "ready-first")), first);
  const second = subprocess(writer("second", false), root);
  t.after(() => second.kill());
  await pause();
  assert.equal(fs.existsSync(path.join(root, "ready-second")), false, "second writer cannot read before first commits");
  fs.writeFileSync(path.join(root, "go"), "resume");
  assert.deepEqual(await first.result, { code: 0, signal: null, output: "" });
  assert.deepEqual(await second.result, { code: 0, signal: null, output: "" });
  const ids = JSON.parse(fs.readFileSync(path.join(root, "data", "audit-logs.json"), "utf8")).logs.map((entry) => entry.id);
  assert.deepEqual(ids, ["acknowledged", "first", "second"]);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, "data", "audit-logs-archive.json"), "utf8")).logs.map((entry) => entry.id), ["archived"]);
});

test("JSON audit lock rejects ordinary writes under coordinator and releases after process crash", { timeout: 30_000 }, async (t) => {
  const root = fixtureRoot("rootark-json-audit-crash-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  fs.mkdirSync(path.join(root, "data"));
  const child = subprocess(`
    const fs=require('node:fs'),path=require('node:path');
    const repo=require(${JSON.stringify(repositoryPath)});
    repo.withJsonAuditLock(()=>{
      fs.writeFileSync(path.join(process.cwd(),'ready'),'ready');
      while(true) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,100);
    });`, root);
  t.after(() => child.kill());
  await eventually(() => fs.existsSync(path.join(root, "ready")), child);
  child.kill("SIGKILL");
  assert.notEqual((await child.result).code, 0);
  const probe = subprocess(`
    const fs=require('node:fs'),path=require('node:path');
    const repo=require(${JSON.stringify(repositoryPath)});
    repo.withJsonAuditLock(()=>fs.writeFileSync(path.join(process.cwd(),'after-crash'),'ok'));
    fs.writeFileSync(path.join(process.cwd(),'data','.rootark-restore-coordinator.json'),'{}');
    try { repo.withJsonAuditLock(()=>{}); throw Error('ordinary write crossed barrier'); }
    catch(error) { if(error.code!=='SYNC_ATOMIC_ACCOUNT_UNAVAILABLE')throw error; }
    repo.withJsonAuditLock(()=>{}, { allowCoordinator: true });`, root);
  assert.deepEqual(await probe.result, { code: 0, signal: null, output: "" });
  assert.equal(fs.readFileSync(path.join(root, "after-crash"), "utf8"), "ok");
});

test("Windows JSON audit lock rejects an ancestor writable by unrelated users", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async (t) => {
  const root = fixtureRoot("rootark-json-audit-unsafe-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const unsafe = path.join(root, "untrusted-parent");
  fs.mkdirSync(unsafe);
  const canary = path.join(unsafe, "canary.txt");
  fs.writeFileSync(canary, "preserve disposable data");
  execFileSync("C:\\Windows\\System32\\icacls.exe", [
    unsafe, "/grant", "*S-1-5-32-545:(OI)(CI)M",
  ], { stdio: "ignore", windowsHide: true, timeout: 12000 });
  const runtime = path.join(unsafe, "runtime");
  fs.mkdirSync(runtime);
  const child = subprocess(`
    const fs=require('node:fs'),path=require('node:path');
    const { withJsonAuditLock, JSON_AUDIT_COORDINATION_FILE }=
      require(${JSON.stringify(path.join(project, "repositories", "jsonAuditLock.js"))});
    try { withJsonAuditLock(()=>{throw Error('UNTRUSTED_CALLBACK_RAN')});
      throw Error('UNTRUSTED_LOCK_ALLOWED'); }
    catch(error) {
      if(!/Untrusted principal can replace chunk staging path|Windows chunk staging ACL validation failed/.test(error.message)) throw error;
    }
    if(fs.existsSync(JSON_AUDIT_COORDINATION_FILE)) throw Error('UNTRUSTED_LOCK_CREATED');`, runtime);
  assert.deepEqual(await child.result, { code: 0, signal: null, output: "" });
  assert.equal(fs.readFileSync(canary, "utf8"), "preserve disposable data");
});
