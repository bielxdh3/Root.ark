const assert = require("node:assert/strict");
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
    const cloudPath=${JSON.stringify(CLOUD)};
    const logPath=process.env.FAKE_PROVIDER_LOG;
    const statePath=process.env.FAKE_PROVIDER_STATE;
    const readState=()=>{try{return JSON.parse(fs.readFileSync(statePath,"utf8"))}catch{return {destination:false,source:true}}};
    const writeState=(value)=>fs.writeFileSync(statePath,JSON.stringify(value));
    const call=(operation,folderId,fileName)=>{const values=fs.existsSync(logPath)?JSON.parse(fs.readFileSync(logPath,"utf8")):[]; values.push({operation,folderId,fileName,identity:operation+":"+folderId+":"+fileName}); fs.writeFileSync(logPath,JSON.stringify(values));};
    const waitFor=(file)=>{const signal=new Int32Array(new SharedArrayBuffer(4)); while(!fs.existsSync(file)) Atomics.wait(signal,0,0,20);};
    let installPause=null; if(process.env.CLAIM_PAUSE_LOCK_PATH){let installed=false; installPause=()=>{if(installed)return; installed=true; let paused=false; const pause=()=>{if(paused)return; paused=true; fs.writeFileSync(process.env.CLAIM_PAUSE_OBSERVED,"observed"); waitFor(process.env.CLAIM_PAUSE_RESUME);}; const originalMkdir=fs.mkdirSync; const originalOpen=fs.openSync; fs.mkdirSync=(target,options)=>{if(path.resolve(String(target))===path.resolve(process.env.CLAIM_PAUSE_LOCK_PATH+".takeover")) pause(); return originalMkdir(target,options);}; fs.openSync=(target,flags,...args)=>{if(String(target).startsWith(process.env.CLAIM_PAUSE_LOCK_PATH+".takeover-")) pause(); return originalOpen(target,flags,...args);};};}
    const fake={
      enabled:()=>process.env.FAKE_PROVIDER_DISABLED!=="true",
      status:()=>({provider:"fake",enabled:process.env.FAKE_PROVIDER_DISABLED!=="true"}),
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
    require(${JSON.stringify(SERVER)});
    if(process.env.CLAIM_PAUSE_POST_START) setImmediate(installPause); else if(installPause) installPause();
  `;
}

function serverEnv(dir, port, extra = {}) {
  return {
    ...process.env,
    PORT: String(port),
    DB_ENABLED: "false",
    WEBDAV_ENABLED: "true",
    WEBDAV_ALLOW_MOVE: "true",
    UPLOAD_SCAN_ENABLED: "false",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    CLOUD_STORAGE_PROVIDER: "s3",
    WEBDAV_MOVE_RECONCILIATION_LEASE_MS: "1000",
    WEBDAV_MOVE_RECONCILIATION_INTERVAL_MS: "1000",
    FAKE_PROVIDER_LOG: path.join(dir, "provider-calls.json"),
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

function stop(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    let finished = false;
    const done = (code) => { if (finished) return; finished = true; resolve(code); };
    child.once("exit", done);
    if (process.platform === "win32") spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else child.kill("SIGKILL");
    setTimeout(() => done(child.exitCode), 1_000);
  });
}

function fixture({ versioned = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-crash-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 }]));
  fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source bytes");
  fs.writeFileSync(path.join(dir, "uploads", "target.txt"), "old destination");
  if (versioned) {
    fs.writeFileSync(path.join(dir, "uploads", "source.txt.v1"), "source archive bytes");
    fs.writeFileSync(path.join(dir, "data", "file-versions.json"), JSON.stringify({
      "root/source.txt": { currentVersion: 2, versions: [
        { version: 1, storedAs: "source.txt.v1", size: Buffer.byteLength("source archive bytes") },
        { version: 2, storedAs: "source.txt", size: Buffer.byteLength("source bytes") },
      ] },
    }));
  }
  fs.writeFileSync(path.join(dir, "provider-state.json"), JSON.stringify({ destination: false, source: true }));
  fs.writeFileSync(path.join(dir, "provider-calls.json"), "[]");
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

function calls(dir) { return JSON.parse(fs.readFileSync(path.join(dir, "provider-calls.json"), "utf8")); }

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

  await t.test("versioned MOVE restart uploads every archive before deleting source keys", async () => {
    const f = fixture({ versioned: true });
    let crashed;
    let recovered;
    try {
      crashed = await startServer(f.dir, { FAKE_PROVIDER_MODE: "crash-after-upload" });
      try { await move(f.dir, crashed.port); } catch {}
      await waitFor(() => readJournal(f.dir)?.cloud?.state === "destination_upload_uncertain");
      await stop(crashed.child);

      recovered = await startServer(f.dir);
      await waitFor(() => !journalPaths(f.dir)).catch((error) => { throw new Error(`${error.message}; stderr=${recovered.stderr()}`); });

      assert.equal(fs.existsSync(path.join(f.dir, "uploads", "source.txt")), false);
      assert.equal(fs.existsSync(path.join(f.dir, "uploads", "source.txt.v1")), false);
      assert.equal(fs.readFileSync(f.target, "utf8"), "source bytes");
      assert.equal(fs.readFileSync(path.join(f.dir, "uploads", "target.txt.v1"), "utf8"), "source archive bytes");
      const history = JSON.parse(fs.readFileSync(path.join(f.dir, "data", "file-versions.json"), "utf8"));
      assert.equal(history["root/source.txt"], undefined);
      assert.deepEqual(history["root/target.txt"].versions.map((entry) => entry.storedAs), ["target.txt.v1", "target.txt"]);

      const values = calls(f.dir);
      const destinationUploads = values.filter((entry) => entry.operation === "upload");
      assert.deepEqual(new Set(destinationUploads.map((entry) => entry.fileName)), new Set(["target.txt", "target.txt.v1"]));
      const firstSourceDelete = values.findIndex((entry) => entry.operation === "remove");
      assert.ok(firstSourceDelete > -1);
      assert.ok(values.slice(0, firstSourceDelete).every((entry) => entry.operation === "upload"), "all destination versions are present before any source version is removed");
      assert.deepEqual(new Set(values.filter((entry) => entry.operation === "remove").map((entry) => entry.fileName)), new Set(["source.txt", "source.txt.v1"]));
    } finally {
      if (crashed?.child.exitCode === null) await stop(crashed.child);
      if (recovered?.child.exitCode === null) await stop(recovered.child);
      fs.rmSync(f.dir, { recursive: true, force: true });
    }
  });

  await t.test("pending MOVE waits for its original provider to return after restart", async () => {
    const f = fixture();
    let crashed;
    let mismatched;
    let disabled;
    let recovered;
    try {
      crashed = await startServer(f.dir, { FAKE_PROVIDER_MODE: "crash-after-upload" });
      try { await move(f.dir, crashed.port); } catch {}
      await waitFor(() => readJournal(f.dir)?.cloud?.state === "destination_upload_uncertain");
      await stop(crashed.child);

      mismatched = await startServer(f.dir, { CLOUD_STORAGE_PROVIDER: "gdrive" });
      await waitFor(() => readJournal(f.dir)?.cloud?.failureCategory === "provider_mismatch");
      assert.ok(journalPaths(f.dir), "provider mismatch retains the pending transaction");
      assert.equal(calls(f.dir).length, 1, "a different provider is not asked to reconcile recorded effects");
      await stop(mismatched.child);

      disabled = await startServer(f.dir, { CLOUD_STORAGE_PROVIDER: "s3", FAKE_PROVIDER_DISABLED: "true" });
      await waitFor(() => readJournal(f.dir)?.cloud?.failureCategory === "provider_unavailable");
      assert.ok(journalPaths(f.dir), "temporarily disabled provider does not finalize the journal");
      assert.equal(calls(f.dir).length, 1, "disabled provider causes no upload or deletion");
      await stop(disabled.child);

      recovered = await startServer(f.dir, { CLOUD_STORAGE_PROVIDER: "s3" });
      await waitFor(() => !journalPaths(f.dir)).catch((error) => { throw new Error(`${error.message}; stderr=${recovered.stderr()}`); });
      assert.equal(calls(f.dir).filter((entry) => entry.operation === "upload").length, 2, "the original provider idempotently retries the uncertain upload");
      assert.equal(calls(f.dir).filter((entry) => entry.operation === "remove").length, 1, "source removal runs only after provider recovery");
      assert.equal(fs.readFileSync(f.target, "utf8"), "source bytes");
    } finally {
      if (crashed?.child.exitCode === null) await stop(crashed.child);
      if (mismatched?.child.exitCode === null) await stop(mismatched.child);
      if (disabled?.child.exitCode === null) await stop(disabled.child);
      if (recovered?.child.exitCode === null) await stop(recovered.child);
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
      await waitFor(() => calls(f.dir).filter((entry) => entry.operation === "upload").length >= 2, 30_000);
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
});
