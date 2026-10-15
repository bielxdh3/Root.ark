const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const SERVICE = process.env.BACKUP_SERVICE_UNDER_TEST || path.resolve(__dirname, "..", "services", "backupService.js");

function newRuntime() {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-lock-takeover-race-"));
  fs.mkdirSync(path.join(runtime, "data", "backups"), { recursive: true });
  return runtime;
}

function startChild(runtime, source) {
  const child = spawn(process.execPath, ["-e", source], {
    cwd: runtime,
    env: { ...process.env, DB_ENABLED: "false" },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const result = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, result };
}

async function waitFor(filePath, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (fs.existsSync(filePath)) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out waiting for ${filePath}`);
}

function waitSource(filePath) {
  return `const waitFor=(file)=>{const signal=new Int32Array(new SharedArrayBuffer(4)); while(!fs.existsSync(file)) Atomics.wait(signal,0,0,20);}; waitFor(${JSON.stringify(filePath)});`;
}

function acquireSource(servicePath, enteredPath, resultCode = 0, afterAcquire = "") {
  return `const fs=require("fs"); const service=require(${JSON.stringify(servicePath)}); let release; try { release=service.acquireLock("backup"); ${afterAcquire} ${resultCode === 0 ? "release(); process.exit(0);" : "process.exit(12);"} } catch (error) { if (release) release(); process.exit(error.code === "BACKUP_LOCKED" ? 10 : 11); }`;
}

test("backup takeover preserves exact adjacent 64-bit file IDs in durable authority", { timeout: 30_000 }, async () => {
  const runtime = newRuntime();
  const lockPath = path.join(runtime, "data", "backups", ".backup.lock");
  const evidencePath = lockPath + ".takeover" + path.sep + "evidence";
  const authorityPath = lockPath + ".takeover" + path.sep + "authority.json";
  try {
    const ownerSource = 'const service=require(' + JSON.stringify(SERVICE) + '); service.acquireLock("backup"); process.exit(0);';
    const owner = startChild(runtime, ownerSource);
    const ownerResult = await owner.result;
    assert.equal(ownerResult.code, 0, ownerResult.stderr);
    assert.equal(fs.existsSync(lockPath), true, "the disposable child leaves its lock as a stale recovery fixture");

    const id = 9_007_199_254_740_992n;
    const contenderSource = [
      'const fs=require("node:fs");',
      'const path=require("node:path");',
      'const service=require(' + JSON.stringify(SERVICE) + ');',
      'const lock=path.resolve(service.LOCK_FILE);',
      'const evidence=path.resolve(service.LOCK_FILE + ".takeover" + path.sep + "evidence");',
      'const adjacent=9007199254740992n;',
      'const stat=fs.statSync;',
      'const lstat=fs.lstatSync;',
      'const identify=(value,args,ino)=>new Proxy(value,{get(target,key,receiver){if(key==="dev")return args[0]?.bigint===true?1n:1;if(key==="ino")return args[0]?.bigint===true?ino:Number(ino);return Reflect.get(target,key,receiver);}});',
      'fs.statSync=function(target,...args){const value=stat.call(this,target,...args);return path.resolve(String(target))===lock?identify(value,args,adjacent):value;};',
      'fs.lstatSync=function(target,...args){const value=lstat.call(this,target,...args);const resolved=path.resolve(String(target));return resolved===lock?identify(value,args,adjacent):resolved===evidence?identify(value,args,adjacent+1n):value;};',
      'try{const release=service.acquireLock("backup");release();process.exit(12);}catch(error){process.exit(error.code==="BACKUP_LOCKED"?10:11);}'
    ].join('');
    const contender = startChild(runtime, contenderSource);
    const result = await contender.result;
    assert.equal(result.code, 10, result.stderr || result.stdout);
    assert.equal(Number(id), Number(id + 1n), "the injected adjacent IDs collide under Number conversion");
    assert.equal(fs.existsSync(evidencePath), true, "ambiguous renamed evidence remains available for safe recovery");
    const authority = JSON.parse(fs.readFileSync(authorityPath, "utf8"));
    assert.equal(authority.observed.stat.ino, id.toString(), "durable takeover evidence stores the exact decimal file ID");
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("stale takeover contenders preserve a newer live lock", { timeout: 30_000 }, async () => {
  const runtime = newRuntime();
  const backupDir = path.join(runtime, "data", "backups");
  const lockPath = path.join(backupDir, ".backup.lock");
  const observedPath = path.join(runtime, "b-observed");
  const resumePath = path.join(runtime, "b-resume");
  const aReadyPath = path.join(runtime, "a-ready");
  const aReleasePath = path.join(runtime, "a-release");
  const enteredPath = path.join(runtime, "entered.log");
  let contender;
  let owner;
  try {
    fs.writeFileSync(lockPath, JSON.stringify({ token: "stale", operation: "backup", pid: 99999999 }));
    fs.utimesSync(lockPath, new Date(0), new Date(0));

    const bSource = `const fs=require("fs"); const path=require("path"); const service=require(${JSON.stringify(SERVICE)}); let paused=false; const originalMkdir=fs.mkdirSync; fs.mkdirSync=(target,options)=>{const value=path.resolve(String(target)); const takeover=service.LOCK_TAKEOVER_DIR ? path.resolve(service.LOCK_TAKEOVER_DIR) : null; const oldClaim=value.startsWith(path.resolve(service.LOCK_FILE)+".claim-"); if(!paused && (value===takeover || oldClaim)){paused=true; fs.writeFileSync(${JSON.stringify(observedPath)},"observed"); ${waitSource(resumePath)}} return originalMkdir(target,options);}; try { service.acquireLock("backup"); process.exit(12); } catch (error) { process.exit(error.code === "BACKUP_LOCKED" ? 10 : 11); }`;
    contender = startChild(runtime, bSource);
    await waitFor(observedPath);

    const aSource = `const fs=require("fs"); const service=require(${JSON.stringify(SERVICE)}); let release; try { release=service.acquireLock("backup"); fs.appendFileSync(${JSON.stringify(enteredPath)}, process.pid+"\\n"); fs.writeFileSync(${JSON.stringify(aReadyPath)},"ready"); ${waitSource(aReleasePath)} release(); process.exit(0); } catch (error) { if (release) release(); process.exit(error.code === "BACKUP_LOCKED" ? 10 : 11); }`;
    owner = startChild(runtime, aSource);
    await waitFor(aReadyPath);
    const liveLock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    assert.notEqual(liveLock.token, "stale");

    fs.writeFileSync(resumePath, "resume");
    const contenderResult = await Promise.race([contender.result, new Promise((resolve) => setTimeout(() => resolve(null), 5_000))]);
    if (contenderResult) assert.equal(contenderResult.code, 10, contenderResult.stderr);
    assert.deepEqual(JSON.parse(fs.readFileSync(lockPath, "utf8")), liveLock);

    const c = startChild(runtime, acquireSource(SERVICE, enteredPath));
    const cResult = await Promise.race([c.result, new Promise((resolve) => setTimeout(() => resolve(null), 5_000))]);
    assert.ok(cResult, "C did not settle");
    assert.equal(cResult.code, 10, cResult.stderr);
    assert.equal(fs.readFileSync(enteredPath, "utf8").trim().split(/\r?\n/).length, 1);

    fs.writeFileSync(aReleasePath, "release");
    const ownerResult = await Promise.race([owner.result, new Promise((resolve) => setTimeout(() => resolve(null), 5_000))]);
    assert.ok(ownerResult, "A did not settle");
    assert.equal(ownerResult.code, 0, ownerResult.stderr);
    assert.equal(fs.existsSync(lockPath), false);
    assert.equal(fs.existsSync(`${lockPath}.takeover`), false);
  } finally {
    if (contender?.exitCode === null) contender.kill("SIGKILL");
    if (owner?.exitCode === null) owner.kill("SIGKILL");
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});
