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

function freePort() {
  return new Promise((resolve, reject) => {
    const listener = net.createServer();
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const value = listener.address().port;
      listener.close(() => resolve(value));
    });
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

async function ready(port) {
  for (let index = 0; index < 120; index += 1) {
    try { await request(port, "/login.html"); return; } catch { await new Promise((resolve) => setTimeout(resolve, 40)); }
  }
  throw new Error("server did not start");
}

function serverEnv(port) {
  return { ...process.env, PORT: String(port), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
}

function createFixture({ phase = "cloud_complete", state = "completed", absent = [], terminal = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-completed-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 }]));
  const id = crypto.randomUUID();
  const incoming = path.join(dir, "temp", ".incoming");
  const transactionDirectory = path.join(incoming, `rootark-webdav-move-${id}`);
  const metadataDirectory = path.join(transactionDirectory, "metadata");
  fs.mkdirSync(metadataDirectory, { recursive: true });
  const sourcePath = path.join(dir, "uploads", "source.txt");
  const destinationPath = path.join(dir, "uploads", "target.txt");
  const stagePath = path.join(dir, "uploads", `.rootark-move-${id}.source`);
  const destinationBackupPath = path.join(dir, "uploads", `.rootark-move-${id}.destination`);
  const journalPath = path.join(incoming, `rootark-webdav-move-${id}.json`);
  const claimPath = path.join(incoming, `rootark-webdav-move-${id}.lock`);
  fs.writeFileSync(destinationPath, "destination");
  if (!absent.includes("destinationBackup")) fs.writeFileSync(destinationBackupPath, "old destination");
  if (!absent.includes("stage")) fs.writeFileSync(stagePath, "staged source");
  const metadataFiles = {};
  for (const [index, file] of ["public-links.json", "file-permissions.json", "file-expirations.json", "file-versions.json", "encrypted-files.json"].entries()) {
    const snapshotPath = path.join(metadataDirectory, `${index}-${file}.snapshot`);
    const present = !absent.includes(`metadata:${file}`);
    if (present) fs.writeFileSync(snapshotPath, `snapshot-${file}`);
    metadataFiles[`./data/${file}`] = { present, path: snapshotPath, checksum: present ? crypto.createHash("sha256").update(`snapshot-${file}`).digest("hex") : null };
  }
  if (absent.includes("metadataDirectory")) fs.rmSync(metadataDirectory, { recursive: true, force: true });
  if (!absent.includes("claim")) fs.writeFileSync(claimPath, "stale-claim");
  const journal = {
    version: 1,
    transactionId: id,
    phase: terminal ? "terminal_reconciliation_failure" : phase,
    journalPath,
    sourcePath,
    destinationPath,
    stagePath,
    destinationBackupPath,
    destinationExisted: true,
    replacementInstalled: true,
    completedOperations: ["source.stage", "replacement.install", "cloud.destination.upload"],
    startedAt: new Date().toISOString(),
    metadata: { directory: metadataDirectory, files: metadataFiles },
    cloud: { state: terminal ? "terminal_reconciliation_failure" : state, destinationUploaded: true, sourceRemoved: terminal ? false : true, nextAttemptAt: state === "retry_wait" ? new Date(Date.now() + 60_000).toISOString() : null, attempts: 1, maxAttempts: 5, failureCategory: terminal ? "provider_error" : null, transitions: [] },
  };
  fs.writeFileSync(journalPath, JSON.stringify(journal));
  return { dir, id, journalPath, transactionDirectory, metadataDirectory, sourcePath, destinationPath, stagePath, destinationBackupPath, claimPath };
}

async function startServer(dir) {
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: serverEnv(port), stdio: "ignore", windowsHide: true });
  await ready(port);
  return { child, port };
}

function stop(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    let finished = false;
    let timer;
    const finish = (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve(code);
    };
    child.once("exit", finish);
    child.once("error", () => finish(child.exitCode));
    if (process.platform === "win32") spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else child.kill("SIGKILL");
    // A SIGKILLed child can fail to emit its exit event when the test runner
    // has already reaped the process; the kernel has still released the port.
    timer = setTimeout(() => finish(child.exitCode), 1_000);
  });
}

function assertConverged(fixture) {
  assert.equal(fs.readFileSync(fixture.destinationPath, "utf8"), "destination");
  assert.equal(fs.existsSync(fixture.sourcePath), false);
  assert.equal(fs.existsSync(fixture.destinationBackupPath), false);
  assert.equal(fs.existsSync(fixture.stagePath), false);
  assert.equal(fs.existsSync(fixture.journalPath), false);
  assert.equal(fs.existsSync(fixture.metadataDirectory), false);
  assert.equal(fs.existsSync(fixture.transactionDirectory), false);
  assert.equal(fs.existsSync(fixture.claimPath), false);
}

test("completed WebDAV journals finalize idempotently across restart boundaries", { timeout: 60_000 }, async (t) => {
  const variants = [
    ["all artifacts", []],
    ["destination backup already absent", ["destinationBackup"]],
    ["source stage already absent", ["stage"]],
    ["metadata directory already absent", ["metadataDirectory"]],
    ["stale claim already absent", ["claim"]],
    ["completed cloud state with legacy phase", ["destinationBackup"]],
  ];
  for (const [name, absent] of variants) {
    await t.test(name, async (t2) => {
      const fixture = createFixture({ absent, phase: name.includes("legacy") ? "metadata_installed" : "cloud_complete" });
      const children = [];
      t2.after(async () => { for (const child of children) await stop(child); fs.rmSync(fixture.dir, { recursive: true, force: true }); });
      const first = await startServer(fixture.dir);
      children.push(first.child);
      assertConverged(fixture);
      await stop(first.child);
      const second = await startServer(fixture.dir);
      children.push(second.child);
      assertConverged(fixture);
      await stop(second.child);
    });
  }
});

test("completed cleanup retries EPERM/EBUSY without rollback", { timeout: 30_000 }, async () => {
  for (const code of ["EPERM", "EBUSY"]) {
    const fixture = createFixture();
    const script = `const fs=require("fs"); const path=require("path"); const target=path.resolve(${JSON.stringify(fixture.destinationBackupPath)}); const original=fs.rmSync; let failed=false; fs.rmSync=(value, options)=>{ if(path.resolve(value)===target&&!failed){failed=true; throw Object.assign(new Error("busy"),{code:${JSON.stringify(code)}});} return original(value, options); }; require(${JSON.stringify(path.join(ROOT, "server.js"))});`;
    const failed = spawnSync(process.execPath, ["-e", script], { cwd: fixture.dir, env: serverEnv(0), encoding: "utf8", timeout: 10_000, windowsHide: true });
    assert.notEqual(failed.status, 0, `${code} cleanup unexpectedly completed`);
    assert.equal(fs.readFileSync(fixture.destinationPath, "utf8"), "destination");
    const second = await startServer(fixture.dir);
    assertConverged(fixture);
    await stop(second.child);
    fs.rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("persistent cleanup failure remains visible and retryable", { timeout: 30_000 }, async () => {
  const fixture = createFixture();
  const script = `const fs=require("fs"); const path=require("path"); const target=path.resolve(${JSON.stringify(fixture.destinationBackupPath)}); const original=fs.rmSync; fs.rmSync=(value, options)=>{ if(path.resolve(value)===target) throw Object.assign(new Error("permission denied"),{code:"EPERM"}); return original(value, options); }; require(${JSON.stringify(path.join(ROOT, "server.js"))});`;
  const failed = spawnSync(process.execPath, ["-e", script], { cwd: fixture.dir, env: serverEnv(0), encoding: "utf8", timeout: 10_000, windowsHide: true });
  assert.notEqual(failed.status, 0);
  assert.equal(fs.existsSync(fixture.journalPath), true);
  assert.equal(fs.readFileSync(fixture.destinationPath, "utf8"), "destination");
  fs.rmSync(fixture.dir, { recursive: true, force: true });
});

test("terminal, retry-wait, and uncertain journals are preserved without rollback", { timeout: 40_000 }, async (t) => {
  for (const [name, options] of [
    ["terminal", { terminal: true }],
    ["retry-wait", { phase: "cloud_source_removal_pending", state: "retry_wait" }],
    ["uncertain upload", { phase: "cloud_destination_uploaded", state: "uploaded" }],
    ["uncertain delete", { phase: "cloud_source_removal_pending", state: "uncertain" }],
  ]) {
    await t.test(name, async (t2) => {
      const fixture = createFixture(options);
      const { child, port } = await startServer(fixture.dir);
      t2.after(async () => { await stop(child); fs.rmSync(fixture.dir, { recursive: true, force: true }); });
      assert.equal(fs.existsSync(fixture.journalPath), true);
      assert.equal(fs.readFileSync(fixture.destinationPath, "utf8"), "destination");
      assert.equal(fs.existsSync(fixture.destinationBackupPath), true);
      if (name === "terminal") {
        const body = JSON.stringify({ username: "agent", password: "password" });
        const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
        const cookie = login.headers["set-cookie"].map((item) => item.split(";", 1)[0]).join("; ");
        const status = await request(port, `/webdav/moves/${fixture.id}/status`, { headers: { cookie } });
        assert.equal(status.status, 200);
        assert.equal(JSON.parse(status.body).state, "terminal_reconciliation_failure");
        assert.equal(status.body.includes(fixture.dir), false);
      }
      await stop(child);
      fs.rmSync(fixture.dir, { recursive: true, force: true });
    });
  }
});

test("WebDAV MOVE status rejects non-canonical transaction UUIDs", { timeout: 20_000 }, async (t) => {
  const fixture = createFixture();
  const originalJournal = JSON.parse(fs.readFileSync(fixture.journalPath, "utf8"));
  const { child, port } = await startServer(fixture.dir);
  t.after(async () => { await stop(child); fs.rmSync(fixture.dir, { recursive: true, force: true }); });

  const transactionId = "00000000-0000-0000-0000-000000000000";
  const journalPath = path.join(path.dirname(fixture.journalPath), `rootark-webdav-move-${transactionId}.json`);
  fs.writeFileSync(journalPath, JSON.stringify({ ...originalJournal, transactionId, journalPath }));

  const body = JSON.stringify({ username: "agent", password: "password" });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  const cookie = login.headers["set-cookie"].map((item) => item.split(";", 1)[0]).join("; ");
  const status = await request(port, `/webdav/moves/${transactionId}/status`, { headers: { cookie } });

  assert.equal(status.status, 404);
  assert.equal(status.body.includes(fixture.dir), false);
});

test("orphan transaction directory after journal deletion is cleaned without touching destination", { timeout: 20_000 }, async () => {
  const fixture = createFixture({ absent: ["destinationBackup", "stage"] });
  fs.rmSync(fixture.journalPath, { force: true });
  fs.writeFileSync(path.join(fixture.transactionDirectory, "orphan.snapshot"), "orphan");
  const { child } = await startServer(fixture.dir);
  assert.equal(fs.readFileSync(fixture.destinationPath, "utf8"), "destination");
  assert.equal(fs.existsSync(fixture.transactionDirectory), false);
  await stop(child);
  fs.rmSync(fixture.dir, { recursive: true, force: true });
});
