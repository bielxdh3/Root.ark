const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const SERVER = process.env.SERVER_UNDER_TEST || path.join(ROOT, "server.js");
const CLOUD = process.env.CLOUD_UNDER_TEST || require.resolve(path.join(ROOT, "services", "cloudStorage.js"));

function freePort() {
  return new Promise((resolve, reject) => {
    const listener = net.createServer();
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => { const port = listener.address().port; listener.close(() => resolve(port)); });
  });
}

function findAbsentPid() {
  for (let candidate = 2_147_000_000, attempts = 0; candidate > 1_000_000 && attempts < 4096; candidate -= 1, attempts += 1) {
    try {
      process.kill(candidate, 0);
    } catch (error) {
      if (error.code === "ESRCH") return candidate;
      if (error.code === "EPERM" || error.code === "EACCES") continue;
      throw error;
    }
  }
  throw new Error("Could not find a provably absent process id for the disposable lock fixture");
}

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, ...options }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.once("error", reject);
    req.end(options.body);
  });
}

async function waitFor(predicate, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 40));
  }
  throw new Error("timed out waiting for state");
}

function childSource(localCrash = false) {
  return `
    const fs=require("fs");
    const path=require("path");
    const crypto=require("crypto");
    if(process.env.CLAIM_TIMER_DELAY_MS){const expectedDelay=Number(process.env.CLAIM_TIMER_DELAY_MS);const originalSetInterval=global.setInterval;global.setInterval=function(callback,delay,...args){if(delay!==expectedDelay)return originalSetInterval(callback,delay,...args);return originalSetInterval(function(...callbackArgs){const result=callback.apply(this,callbackArgs);if(fs.existsSync(process.env.CLAIM_SWAP_COMPLETED))fs.writeFileSync(process.env.CLAIM_TIMER_SIGNAL,"tick");return result;},delay,...args);};}
    const cloudPath=${JSON.stringify(CLOUD)};
    const logPath=process.env.FAKE_PROVIDER_LOG;
    const statePath=process.env.FAKE_PROVIDER_STATE;
    const readState=()=>{try{return JSON.parse(fs.readFileSync(statePath,"utf8"))}catch{return {destination:false,source:true}}};
    const writeState=(value)=>fs.writeFileSync(statePath,JSON.stringify(value));
    const call=(operation,folderId,fileName)=>{const id=crypto.randomUUID();const target=path.join(logPath,id+".json");const temporary=path.join(logPath,"."+id+".tmp");fs.writeFileSync(temporary,JSON.stringify({operation,folderId,fileName,identity:operation+":"+folderId+":"+fileName}),{flag:"wx"});fs.renameSync(temporary,target);};
    const waitFor=(file)=>{const signal=new Int32Array(new SharedArrayBuffer(4)); while(!fs.existsSync(file)) Atomics.wait(signal,0,0,20);};
    let installPause=null; if(process.env.CLAIM_PAUSE_LOCK_PATH){let installed=false; installPause=()=>{if(installed)return; installed=true; let paused=false; const pause=()=>{if(paused)return; paused=true; fs.writeFileSync(process.env.CLAIM_PAUSE_OBSERVED,"observed"); waitFor(process.env.CLAIM_PAUSE_RESUME);}; const originalMkdir=fs.mkdirSync; const originalOpen=fs.openSync; fs.mkdirSync=(target,options)=>{if(path.resolve(String(target))===path.resolve(process.env.CLAIM_PAUSE_LOCK_PATH+".takeover")) pause(); return originalMkdir(target,options);}; fs.openSync=(target,flags,...args)=>{if(String(target).startsWith(process.env.CLAIM_PAUSE_LOCK_PATH+".takeover-")) pause(); return originalOpen(target,flags,...args);};};}
    const fake={
      enabled:()=>true,
      status:()=>({provider:"fake",enabled:true}),
      key:(folderId,fileName,area)=>[area,folderId,fileName].join("/"),
      inventory:async()=>[],
      upload:async(localPath,folderId,fileName)=>{call("upload",folderId,fileName); const state=readState(); state.destination=true; writeState(state); if(process.env.FAKE_PROVIDER_MODE==="crash-after-upload") process.kill(process.pid,"SIGKILL"); if(process.env.FAKE_PROVIDER_MODE==="wait-upload") await new Promise((resolve)=>{const poll=()=>fs.existsSync(process.env.FAKE_PROVIDER_RELEASE)?resolve():setTimeout(poll,10); poll();}); return {provider:"fake",key:"uploads:"+folderId+":"+fileName};},
      remove:async(folderId,fileName)=>{call("remove",folderId,fileName); const state=readState(); state.source=false; writeState(state); if(process.env.FAKE_PROVIDER_MODE==="crash-after-delete") process.kill(process.pid,"SIGKILL"); return true;},
      removePrefix:async()=>true,
      list:async()=>[],
      download:async()=>false,
    };
    require.cache[cloudPath]={id:cloudPath,filename:cloudPath,loaded:true,exports:{createCloudStorage:()=>fake}};
    ${localCrash ? `const originalRename=fs.renameSync; fs.renameSync=(from,to)=>{const result=originalRename(from,to); if(process.env.LOCAL_CRASH_TO&&String(from).includes(".rootark-move-")&&String(from).endsWith(".source")&&path.resolve(to)===path.resolve(process.env.LOCAL_CRASH_TO)) process.kill(process.pid,"SIGKILL"); return result;};` : ""}
    if(process.env.CLAIM_SWAP_LOCK_PATH){const lockPath=path.resolve(process.env.CLAIM_SWAP_LOCK_PATH);const evidencePath=path.resolve(process.env.CLAIM_SWAP_EVIDENCE_PATH);const originalRename=fs.renameSync;const originalOpenSync=fs.openSync;const originalReadSync=fs.readSync;let evidenceFd=null;let swapped=false;let completionQueued=false;fs.renameSync=(from,to)=>{if(!swapped&&path.resolve(String(from))===lockPath&&path.resolve(String(to))===evidencePath){swapped=true;fs.writeFileSync(lockPath,process.env.CLAIM_SWAP_CONTENTS);const result=originalRename(from,to);fs.writeFileSync(process.env.CLAIM_SWAP_OBSERVED,"swapped");return result;}return originalRename(from,to);};fs.openSync=(file,...args)=>{const fd=originalOpenSync(file,...args);if(path.resolve(String(file))===evidencePath)evidenceFd=fd;return fd;};fs.readSync=(fd,...args)=>{const result=originalReadSync(fd,...args);if(swapped&&!completionQueued&&fd===evidenceFd&&result>0){completionQueued=true;setImmediate(()=>fs.writeFileSync(process.env.CLAIM_SWAP_COMPLETED,"verified"));}return result;};}
    require(${JSON.stringify(SERVER)});
    if(process.env.CLAIM_PAUSE_POST_START) setImmediate(installPause); else if(installPause) installPause();
  `;
}

function serverEnv(dir, port, extra = {}) {
  return {
    ...process.env,
    NODE_ENV: "test",
    PORT: String(port),
    DB_ENABLED: "false",
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
    WEBDAV_ENABLED: "true",
    WEBDAV_ALLOW_MOVE: "true",
    UPLOAD_SCAN_ENABLED: "false",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    CLOUD_STORAGE_PROVIDER: "s3",
    WEBDAV_MOVE_RECONCILIATION_LEASE_MS: "1000",
    WEBDAV_MOVE_RECONCILIATION_INTERVAL_MS: "1000",
    FAKE_PROVIDER_LOG: path.join(dir, "provider-calls"),
    FAKE_PROVIDER_STATE: path.join(dir, "provider-state.json"),
    ...extra,
  };
}

function startServer(dir, extra = {}, localCrash = false) {
  return freePort().then((port) => {
    const child = spawn(process.execPath, ["-e", childSource(localCrash)], { cwd: dir, env: serverEnv(dir, port, extra), stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    const ready = (async () => { for (let i = 0; i < 150; i += 1) { try { await request(port, "/login.html"); return; } catch { await new Promise((resolve) => setTimeout(resolve, 40)); } } throw new Error("server did not start"); })();
    const exited = new Promise((_, reject) => child.once("exit", (code, signal) => reject(new Error(`server exited before readiness: ${code || signal}; stderr=${stderr}`))));
    return Promise.race([ready, exited]).then(() => ({ child, port, stderr: () => stderr }));
  });
}

function stop(child, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    const streamsClosed = child.stdio.every((stream) => stream === null || stream.closed);
    if ((child.exitCode !== null || child.signalCode !== null) && streamsClosed) return resolve(child.exitCode);
    let timer;
    const done = (code) => { clearTimeout(timer); resolve(code); };
    child.once("close", done);
    timer = setTimeout(() => {
      child.removeListener("close", done);
      reject(new Error("child process " + child.pid + " did not close within " + timeoutMs + "ms after termination"));
    }, timeoutMs);
    if (child.exitCode !== null || child.signalCode !== null) return;
    if (process.platform === "win32") spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else child.kill("SIGKILL");
  });
}

test("stop rejects when a process does not close after termination", { timeout: 3_000 }, async () => {
  const child = new EventEmitter();
  Object.assign(child, { exitCode: null, signalCode: null, stdio: [null, null, null], pid: "not-a-pid" });
  child.kill = () => true;
  await assert.rejects(stop(child, 5), /did not close within 5ms/);
});

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-crash-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 }]));
  fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source bytes");
  fs.writeFileSync(path.join(dir, "uploads", "target.txt"), "old destination");
  fs.writeFileSync(path.join(dir, "provider-state.json"), JSON.stringify({ destination: false, source: true }));
  fs.mkdirSync(path.join(dir, "provider-calls"));
  return { dir, source: path.join(dir, "uploads", "source.txt"), target: path.join(dir, "uploads", "target.txt"), backup: path.join(dir, "uploads") };
}

async function move(dir, port) {
  const authorization = `Basic ${Buffer.from("agent:password").toString("base64")}`;
  return request(port, "/dav/source.txt", { method: "MOVE", headers: { authorization, destination: `http://127.0.0.1:${port}/dav/target.txt`, overwrite: "T" } });
}

function journalPaths(dir) {
  const incoming = path.join(dir, "temp", ".incoming");
  const journal = fs.existsSync(incoming) ? fs.readdirSync(incoming).find((name) => name.endsWith(".json") && name.startsWith("rootark-webdav-move-")) : null;
  return journal ? path.join(incoming, journal) : null;
}

function readJournal(dir) {
  const journalPath = journalPaths(dir);
  if (!journalPath) return null;
  try { return JSON.parse(fs.readFileSync(journalPath, "utf8")); } catch { return null; }
}

function calls(dir) {
  const logDirectory = path.join(dir, "provider-calls");
  return fs.readdirSync(logDirectory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => JSON.parse(fs.readFileSync(path.join(logDirectory, name), "utf8")));
}

test("WebDAV MOVE persists remote intent before provider effects", { timeout: 90_000 }, async (t) => {
  await t.test("uncertain upload is retained and reconciled without local rollback", async () => {
    const f = fixture();
    let first;
    let second;
    try {
      first = await startServer(f.dir, { FAKE_PROVIDER_MODE: "crash-after-upload" });
      try { await move(f.dir, first.port); } catch {}
      await waitFor(() => readJournal(f.dir)?.cloud?.state === "destination_upload_uncertain");
      await stop(first.child);
      const journalPath = journalPaths(f.dir);
      assert.ok(journalPath);
      const journal = JSON.parse(fs.readFileSync(journalPath, "utf8"));
      assert.equal(journal.cloud.state, "destination_upload_uncertain");
      assert.equal(fs.readFileSync(f.target, "utf8"), "source bytes");
      assert.equal(fs.existsSync(f.source), false);
      second = await startServer(f.dir);
      await waitFor(() => !journalPaths(f.dir)).catch((error) => { throw new Error(`${error.message}; stderr=${second.stderr()}`); });
      assert.equal(fs.readFileSync(f.target, "utf8"), "source bytes");
      assert.equal(fs.existsSync(f.backup), true);
      const uploadCalls = calls(f.dir).filter((entry) => entry.operation === "upload");
      assert.equal(uploadCalls.length, 2);
      assert.equal(new Set(uploadCalls.map((entry) => entry.identity)).size, 1);
    } finally {
      if (first?.child.exitCode === null) await stop(first.child);
      if (second?.child.exitCode === null) await stop(second.child);
      fs.rmSync(f.dir, { recursive: true, force: true });
    }
  });

  await t.test("uncertain source deletion is retried idempotently", async () => {
    const f = fixture();
    let first;
    let second;
    try {
      first = await startServer(f.dir, { FAKE_PROVIDER_MODE: "crash-after-delete" });
      try { await move(f.dir, first.port); } catch {}
      await waitFor(() => readJournal(f.dir)?.cloud?.state === "source_delete_uncertain");
      await stop(first.child);
      const journal = readJournal(f.dir);
      assert.equal(journal.cloud.state, "source_delete_uncertain");
      second = await startServer(f.dir);
      await waitFor(() => !journalPaths(f.dir)).catch((error) => { throw new Error(`${error.message}; stderr=${second.stderr()}`); });
      const values = calls(f.dir);
      assert.equal(values.filter((entry) => entry.operation === "upload").length, 1);
      const deletes = values.filter((entry) => entry.operation === "remove");
      assert.equal(deletes.length, 2);
      assert.equal(new Set(deletes.map((entry) => entry.identity)).size, 1);
      assert.equal(fs.readFileSync(f.target, "utf8"), "source bytes");
    } finally {
      if (first?.child.exitCode === null) await stop(first.child);
      if (second?.child.exitCode === null) await stop(second.child);
      fs.rmSync(f.dir, { recursive: true, force: true });
    }
  });

  await t.test("durably completed remote effects are not repeated after restart", async () => {
    const f = fixture();
    let first;
    let second;
    try {
      first = await startServer(f.dir);
      const result = await move(f.dir, first.port);
      assert.ok([201, 204, 202].includes(result.status), result.body);
      await waitFor(() => !journalPaths(f.dir));
      const before = calls(f.dir).length;
      second = await startServer(f.dir);
      await new Promise((resolve) => setTimeout(resolve, 500));
      assert.equal(calls(f.dir).length, before);
    } finally {
      if (first?.child.exitCode === null) await stop(first.child);
      if (second?.child.exitCode === null) await stop(second.child);
      fs.rmSync(f.dir, { recursive: true, force: true });
    }
  });

  await t.test("a crash after replacement rename rolls back using byte evidence", async () => {
    const f = fixture();
    const stage = path.join(f.dir, "uploads", ".rootark-move-crash.source");
    let first;
    let second;
    try {
      first = await startServer(f.dir, { CLOUD_STORAGE_PROVIDER: "local", LOCAL_CRASH_FROM: stage, LOCAL_CRASH_TO: f.target }, true);
      try { await move(f.dir, first.port); } catch {}
      await waitFor(() => Boolean(journalPaths(f.dir)) && fs.existsSync(f.target) && !fs.existsSync(f.source));
      await stop(first.child);
      assert.equal(fs.readFileSync(f.target, "utf8"), "source bytes");
      assert.equal(fs.existsSync(f.source), false);
      second = await startServer(f.dir, { CLOUD_STORAGE_PROVIDER: "local" });
      await waitFor(() => !journalPaths(f.dir));
      assert.equal(fs.readFileSync(f.source, "utf8"), "source bytes");
      assert.equal(fs.readFileSync(f.target, "utf8"), "old destination");
    } finally {
      if (first?.child.exitCode === null) await stop(first.child);
      if (second?.child.exitCode === null) await stop(second.child);
      fs.rmSync(f.dir, { recursive: true, force: true });
    }
  });

  await t.test("two restart workers cannot claim one uncertain journal", async () => {
    const f = fixture();
    let crashed;
    let first;
    let second;
    const release = path.join(f.dir, "release-upload");
    try {
      crashed = await startServer(f.dir, { FAKE_PROVIDER_MODE: "crash-after-upload" });
      try { await move(f.dir, crashed.port); } catch {}
      await waitFor(() => readJournal(f.dir)?.cloud?.state === "destination_upload_uncertain");
      await stop(crashed.child);
      first = await startServer(f.dir, { FAKE_PROVIDER_MODE: "wait-upload", FAKE_PROVIDER_RELEASE: release });
      second = await startServer(f.dir, { FAKE_PROVIDER_MODE: "wait-upload", FAKE_PROVIDER_RELEASE: release });
      await waitFor(() => calls(f.dir).filter((entry) => entry.operation === "upload").length >= 2);
      assert.equal(calls(f.dir).filter((entry) => entry.operation === "upload").length, 2);
      fs.writeFileSync(release, "go");
      await waitFor(() => !journalPaths(f.dir));
    } finally {
      if (crashed?.child.exitCode === null) await stop(crashed.child);
      if (first?.child.exitCode === null) await stop(first.child);
      if (second?.child.exitCode === null) await stop(second.child);
      fs.rmSync(f.dir, { recursive: true, force: true });
    }
  });

  await t.test("stale takeover cannot remove a live claim during a slow provider call", async () => {
    const f = fixture();
    const releaseUpload = path.join(f.dir, "release-upload");
    const bObserved = path.join(f.dir, "b-observed");
    const bResume = path.join(f.dir, "b-resume");
    let crashed;
    let first;
    let second;
    let third;
    try {
      crashed = await startServer(f.dir, { FAKE_PROVIDER_MODE: "crash-after-upload" });
      try { await move(f.dir, crashed.port); } catch {}
      await waitFor(() => readJournal(f.dir)?.cloud?.state === "destination_upload_uncertain");
      await stop(crashed.child);
      const journal = readJournal(f.dir);
      const claimPath = path.join(f.dir, "temp", ".incoming", `rootark-webdav-move-${journal.transactionId}.lock`);
      const journalPath = journalPaths(f.dir);
      const heldUntil = new Date(Date.now() + 60_000).toISOString();
      fs.writeFileSync(journalPath, JSON.stringify({ ...journal, cloud: { ...journal.cloud, leaseUntil: heldUntil, nextAttemptAt: null } }));
      const stale = { ...JSON.parse(fs.readFileSync(claimPath, "utf8")), pid: 99999999, processStartIdentity: null, claimedAt: heldUntil };
      fs.writeFileSync(claimPath, JSON.stringify(stale));
      fs.utimesSync(claimPath, new Date(Date.now() + 60_000), new Date(Date.now() + 60_000));

      second = await startServer(f.dir, { FAKE_PROVIDER_MODE: "wait-upload", FAKE_PROVIDER_RELEASE: releaseUpload, CLAIM_PAUSE_LOCK_PATH: claimPath, CLAIM_PAUSE_OBSERVED: bObserved, CLAIM_PAUSE_RESUME: bResume });
      const expiredJournal = { ...journal, cloud: { ...journal.cloud, leaseUntil: new Date(Date.now() - 5000).toISOString(), nextAttemptAt: null } };
      fs.writeFileSync(journalPath, JSON.stringify(expiredJournal));
      const expiredClaim = { ...stale, claimedAt: new Date(Date.now() - 5000).toISOString() };
      fs.writeFileSync(claimPath, JSON.stringify(expiredClaim));
      fs.utimesSync(claimPath, new Date(0), new Date(0));
      await waitFor(() => fs.existsSync(bObserved));
      first = await startServer(f.dir, { FAKE_PROVIDER_MODE: "wait-upload", FAKE_PROVIDER_RELEASE: releaseUpload });
      await waitFor(() => calls(f.dir).filter((entry) => entry.operation === "upload").length >= 2);
      const ownerClaim = fs.readFileSync(claimPath, "utf8");
      assert.notEqual(JSON.parse(ownerClaim).token, stale.token);
      await new Promise((resolve) => setTimeout(resolve, 1600));
      assert.equal(first.child.exitCode, null);

      fs.writeFileSync(bResume, "resume");
      await new Promise((resolve) => setTimeout(resolve, 400));
      assert.equal(fs.readFileSync(claimPath, "utf8"), ownerClaim);

      third = await startServer(f.dir, { FAKE_PROVIDER_MODE: "wait-upload", FAKE_PROVIDER_RELEASE: releaseUpload });
      await new Promise((resolve) => setTimeout(resolve, 2200));
      assert.equal(calls(f.dir).filter((entry) => entry.operation === "upload").length, 2);
      assert.equal(first.child.exitCode, null);
      fs.writeFileSync(releaseUpload, "go");
      await waitFor(() => !journalPaths(f.dir));
      assert.equal(fs.readFileSync(f.target, "utf8"), "source bytes");
      assert.equal(calls(f.dir).filter((entry) => entry.operation === "upload").length, 2);
    } finally {
      if (crashed?.child.exitCode === null) await stop(crashed.child);
      if (first?.child.exitCode === null) await stop(first.child);
      if (second?.child.exitCode === null) await stop(second.child);
      if (third?.child.exitCode === null) await stop(third.child);
      fs.rmSync(f.dir, { recursive: true, force: true });
    }
  });
  await t.test("same-inode lock replacement at stale takeover rename fails closed before provider retry", async () => {
    const f = fixture();
    let crashed;
    let second;
    const swapped = path.join(f.dir, "claim-swapped");
    try {
      crashed = await startServer(f.dir, { FAKE_PROVIDER_MODE: "crash-after-upload" });
      try { await move(f.dir, crashed.port); } catch {}
      await waitFor(() => readJournal(f.dir)?.cloud?.state === "destination_upload_uncertain");
      await stop(crashed.child);
      const journal = readJournal(f.dir);
      const lockPath = path.join(f.dir, "temp", ".incoming", "rootark-webdav-move-" + journal.transactionId + ".lock");
      const evidencePath = lockPath + ".takeover" + path.sep + "evidence";
      const original = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      const stale = { ...original, pid: findAbsentPid(), processStartIdentity: null, claimedAt: new Date(Date.now() - 5000).toISOString() };
      fs.writeFileSync(lockPath, JSON.stringify(stale));
      fs.utimesSync(lockPath, new Date(0), new Date(0));
      const replacement = JSON.stringify({ ...stale, token: "raced-replacement-token", pid: process.pid, claimedAt: new Date().toISOString() });
      const verified = path.join(f.dir, "claim-verification-complete");
      const timerSignal = path.join(f.dir, "reconciliation-timer-entered");
      second = await startServer(f.dir, { CLAIM_SWAP_LOCK_PATH: lockPath, CLAIM_SWAP_EVIDENCE_PATH: evidencePath, CLAIM_SWAP_CONTENTS: replacement, CLAIM_SWAP_OBSERVED: swapped, CLAIM_SWAP_COMPLETED: verified, CLAIM_TIMER_DELAY_MS: "1200", CLAIM_TIMER_SIGNAL: timerSignal, WEBDAV_MOVE_RECONCILIATION_INTERVAL_MS: "1200", CLOUD_TEMP_RECONCILIATION_INTERVAL_MS: "30000", CLOUD_UPLOAD_RECONCILIATION_INTERVAL_MS: "30000" });
      await waitFor(() => fs.existsSync(swapped)).catch((error) => {
        const pendingJournal = journalPaths(f.dir);
        const stderrTail = second.stderr().slice(-4_000);
        let journalState = null;
        try { if (pendingJournal) journalState = JSON.parse(fs.readFileSync(pendingJournal, "utf8")); } catch (journalError) { journalState = { readError: journalError.message }; }
        throw new Error(`${error.message}; childExitCode=${second.child.exitCode}; stderrTail=${stderrTail}; swapped=${fs.existsSync(swapped)}; verified=${fs.existsSync(verified)}; timerSignal=${fs.existsSync(timerSignal)}; lockExists=${fs.existsSync(lockPath)}; evidenceExists=${fs.existsSync(evidencePath)}; journalPath=${pendingJournal}; journal=${JSON.stringify(journalState)}; providerCalls=${JSON.stringify(calls(f.dir))}`);
      });
      await waitFor(() => fs.existsSync(verified));
      await waitFor(() => fs.existsSync(timerSignal));
      assert.equal(calls(f.dir).filter((entry) => entry.operation === "upload").length, 1, "a path replacement after identity validation must not trigger a provider retry");
      assert.ok(journalPaths(f.dir), "ambiguous takeover must remain pending for operator recovery");
      assert.equal(fs.readFileSync(evidencePath, "utf8"), replacement);
    } finally {
      if (crashed?.child.exitCode === null) await stop(crashed.child);
      if (second?.child.exitCode === null) await stop(second.child);
      fs.rmSync(f.dir, { recursive: true, force: true });
    }
  });
});
