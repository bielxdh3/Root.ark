const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-public-link-quota-"));
const databasePath = path.join(directory, "rootark.sqlite");
process.env.DATABASE_URL = databasePath;
process.env.DB_ENABLED = "true";

const { closeDb, getDb } = require("../db");
const { runMigrations } = require("../db/migrations");

function startQuotaWorker(repositoryPath, token, barrierPath, workerId, kind) {
  const startedPath = path.join(barrierPath, `started-${workerId}`);
    const attemptingPath = path.join(barrierPath, `attempting-${workerId}`);
  const checkedPath = path.join(barrierPath, `checked-${workerId}`);
  const goPath = path.join(barrierPath, "go");
  const releasePath = path.join(barrierPath, "release");
  const script = `
    const fs = require("node:fs");
    const repository = require(${JSON.stringify(repositoryPath)});
    const delay = new Int32Array(new SharedArrayBuffer(4));
    fs.writeFileSync(${JSON.stringify(startedPath)}, "started");
    if (${workerId} === 1) while (!fs.existsSync(${JSON.stringify(goPath)})) Atomics.wait(delay, 0, 0, 10);
    fs.writeFileSync(${JSON.stringify(attemptingPath)}, "attempting");
    const result = repository.consumePublicLinkQuota(${JSON.stringify(token)}, {
      kind: ${JSON.stringify(kind)},
      expectedFileName: "quota.txt",
      expectedFolderId: "root",
      expectedPasswordHash: null,
      afterQuotaRead() {
        fs.writeFileSync(${JSON.stringify(checkedPath)}, "checked");
        while (!fs.existsSync(${JSON.stringify(releasePath)})) Atomics.wait(delay, 0, 0, 10);
      },
    });
    require(${JSON.stringify(path.join(__dirname, "..", "db", "index.js"))}).closeDb();
    process.stdout.write(JSON.stringify(result));
  `;
  const child = spawn(process.execPath, ["-e", script], {
    cwd: path.resolve(__dirname, ".."),
    env: { ...process.env, NODE_ENV: "test", DATABASE_URL: databasePath, DB_ENABLED: "true" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let output = "";
  let errors = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { errors += chunk; });
  const result = new Promise((resolve, reject) => {
    child.once("close", (code) => {
      if (code !== 0) return reject(new Error(`Quota worker exited ${code}: ${errors}`));
      if (!output) return reject(new Error(`Quota worker returned no result: ${errors}`));
      resolve(JSON.parse(output));
    });
    child.once("error", reject);
  });

  return { child, startedPath, attemptingPath, checkedPath, result };
}

test("SQLite enforces public share view and download limits across concurrent processes", async (t) => {
  t.after(() => {
    closeDb();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  runMigrations({ backup: false });

  const repositoryPath = path.join(__dirname, "..", "repositories", "publicLinksRepository.js");
  const repository = require("../repositories/publicLinksRepository");
  const viewerToken = "a".repeat(48);
  const viewerId = "b".repeat(32);
  const viewerNow = new Date().toISOString();
  repository.savePublicLinks({ [viewerToken]: {
    fileName: "viewer-quota.txt",
    folderId: "root",
    createdAt: viewerNow,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    maxViews: 0,
    views: 0,
    maxDownloads: 2,
    downloads: 0,
    activeViewers: {},
  } });
  repository.consumePublicLinkQuota(viewerToken, {
    kind: "view",
    expectedFileName: "viewer-quota.txt",
    expectedFolderId: "root",
    expectedPasswordHash: null,
    viewer: { id: viewerId, createdAt: viewerNow, expiresAt: new Date(Date.now() + 60_000).toISOString() },
  });
  const viewerSnapshot = repository.loadPublicLinks();
  const firstViewerDownload = repository.consumePublicLinkQuota(viewerToken, {
    kind: "download",
    expectedFileName: "viewer-quota.txt",
    expectedFolderId: "root",
    expectedPasswordHash: null,
    downloadViewerId: viewerId,
  });
  assert.equal(firstViewerDownload.status, "ok");
  repository.savePublicLinks(viewerSnapshot);
  const repeatedViewerDownload = repository.consumePublicLinkQuota(viewerToken, {
    kind: "download",
    expectedFileName: "viewer-quota.txt",
    expectedFolderId: "root",
    expectedPasswordHash: null,
    downloadViewerId: viewerId,
  });
  assert.equal(repeatedViewerDownload.status, "ok");
  assert.equal(repeatedViewerDownload.alreadyConsumed, true, "a stale snapshot cannot clear the per-viewer download marker");
  assert.equal(repeatedViewerDownload.link.downloads, 1, "retries by the same viewer do not consume quota twice");

  for (const kind of ["view", "download"]) {
    const token = kind === "view" ? "d".repeat(48) : "e".repeat(48);
    const now = new Date().toISOString();
    repository.savePublicLinks({ [token]: {
      fileName: "quota.txt",
      folderId: "root",
      createdAt: now,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      maxViews: kind === "view" ? 1 : 0,
      views: 0,
      maxDownloads: kind === "download" ? 1 : 0,
      downloads: 0,
    } });
    const staleSnapshot = repository.loadPublicLinks();

    const barrierPath = path.join(directory, `barrier-${kind}`);
    fs.mkdirSync(barrierPath);
    const releasePath = path.join(barrierPath, "release");
    const workers = [];
    let outcomes;
    let secondReadOverlapped;
    try {
      workers.push(startQuotaWorker(repositoryPath, token, barrierPath, 0, kind));
      const firstCheckDeadline = Date.now() + 5000;
      while (!fs.existsSync(workers[0].checkedPath) && Date.now() < firstCheckDeadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.ok(fs.existsSync(workers[0].checkedPath), "first process should pause after reading the quota and before updating it");
      workers.push(startQuotaWorker(repositoryPath, token, barrierPath, 1, kind));
      const secondStartDeadline = Date.now() + 5000;
      while (!fs.existsSync(workers[1].startedPath) && Date.now() < secondStartDeadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.ok(fs.existsSync(workers[1].startedPath), "second process should start while the first holds the quota transaction");
      fs.writeFileSync(path.join(barrierPath, "go"), "go");
      const attemptDeadline = Date.now() + 5000;
      while (!fs.existsSync(workers[1].attemptingPath) && Date.now() < attemptDeadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.ok(fs.existsSync(workers[1].attemptingPath), "second process should enter the quota call while the first transaction is paused");
      const secondReadDeadline = Date.now() + 1000;
      while (!fs.existsSync(workers[1].checkedPath) && Date.now() < secondReadDeadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      secondReadOverlapped = fs.existsSync(workers[1].checkedPath);
      fs.writeFileSync(releasePath, "release");
      outcomes = await Promise.all(workers.map((worker) => worker.result));
    } finally {
      fs.writeFileSync(releasePath, "release");
      await Promise.all(workers.map((worker) => worker.result.catch(() => undefined)));
    }
    assert.equal(secondReadOverlapped, false, "another process cannot read the quota before the first read-update transaction commits");
    assert.deepEqual(outcomes.map((outcome) => outcome.status).sort(), ["limit", "ok"]);
    repository.savePublicLinks(staleSnapshot);
    const row = getDb().prepare("SELECT views, metadata_json FROM public_links WHERE token = ?").get(token);
    const stored = JSON.parse(row.metadata_json);
    assert.equal(row.views, kind === "view" ? 1 : 0);
    assert.equal(stored.downloads, kind === "download" ? 1 : 0);
    repository.savePublicLinks({});
    assert.equal(repository.loadPublicLinks()[token], undefined, "omitting a token still removes the public link");
    assert.equal(repository.getRecordedPublicLinkTokens([token]).has(token), true, "removed shares retain a tombstone against stale JSON fallback");
    repository.savePublicLinks(staleSnapshot);
    assert.equal(repository.loadPublicLinks()[token], undefined, "a stale active snapshot cannot reactivate a revoked share");
  }

  const prototypeToken = "f".repeat(48);
  const prototypeNow = new Date().toISOString();
  repository.savePublicLinks({ [prototypeToken]: {
    fileName: "prototype-viewer.txt",
    folderId: "root",
    createdAt: prototypeNow,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    maxViews: 0,
    views: 0,
    maxDownloads: 0,
    downloads: 0,
    activeViewers: {},
  } });
  const invalidViewer = repository.consumePublicLinkQuota(prototypeToken, {
    kind: "view",
    expectedFileName: "prototype-viewer.txt",
    expectedFolderId: "root",
    expectedPasswordHash: null,
    viewer: { id: "__proto__", createdAt: prototypeNow, expiresAt: new Date(Date.now() + 60_000).toISOString() },
  });
  assert.equal(invalidViewer.status, "ok");
  assert.equal(Object.getPrototypeOf(invalidViewer.link.activeViewers), Object.prototype, "invalid viewer identifiers cannot replace the viewer map prototype");
  assert.equal(Object.prototype.hasOwnProperty.call(invalidViewer.link.activeViewers, "__proto__"), false);
});
