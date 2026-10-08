const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");

function unusedPort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const port = probe.address().port;
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function request(port, requestPath, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

function multipartUpload(filename, bytes) {
  const boundary = `----rootark-${crypto.randomBytes(12).toString("hex")}`;
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`),
    Buffer.from(bytes),
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}

function multipartFields(fields, fileField, filename, bytes) {
  const boundary = `----rootark-${crypto.randomBytes(12).toString("hex")}`;
  const parts = [];
  for (const [name, value] of Object.entries(fields)) {
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
  }
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${fileField}"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`));
  parts.push(Buffer.from(bytes), Buffer.from(`\r\n--${boundary}--\r\n`));
  return { body: Buffer.concat(parts), contentType: `multipart/form-data; boundary=${boundary}` };
}

function decodeAwsChunkedBody(body) {
  const input = Buffer.from(body).toString("latin1");
  let offset = 0;
  const chunks = [];
  while (offset < input.length) {
    const lineEnd = input.indexOf("\r\n", offset);
    if (lineEnd < 0) break;
    const length = Number.parseInt(input.slice(offset, lineEnd).split(";", 1)[0], 16);
    if (!Number.isFinite(length) || length <= 0) break;
    const start = lineEnd + 2;
    chunks.push(Buffer.from(input.slice(start, start + length), "latin1"));
    offset = start + length + 2;
  }
  return chunks.length ? Buffer.concat(chunks) : Buffer.from(body);
}

function makeS3Fixture(objects) {
  const mutationLog = [];
  const getGates = new Map();
  const deleteGates = new Map();
  const deleteFailures = new Map();
  const deleteAttempts = new Map();
  const uploadFailures = new Map();
  const uploadAttempts = new Map();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://fixture.invalid");
    const key = decodeURIComponent(url.pathname).replace(/^\/fixture-bucket\//, "");
    if (req.method === "GET" && url.searchParams.has("list-type")) {
      const prefix = url.searchParams.get("prefix") || "";
      const entries = [...objects.entries()].filter(([name]) => name.startsWith(prefix));
      const contents = entries.map(([name, value]) => `<Contents><Key>${name}</Key><LastModified>2026-10-07T00:00:00.000Z</LastModified><ETag>&quot;fixture&quot;</ETag><Size>${value.length}</Size></Contents>`).join("");
      res.writeHead(200, { "content-type": "application/xml" });
      return res.end(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture-bucket</Name><KeyCount>${entries.length}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>${contents}</ListBucketResult>`);
    }
    if (req.method === "GET") {
      const send = () => { const body = objects.get(key); res.writeHead(200, { "content-length": body.length }); res.end(body); };
      const gate = getGates.get(key)?.shift();
      if (gate) {
        gate.markStarted();
        return gate.released.then(() => {
          if (objects.has(key)) return send();
          res.writeHead(404, { "content-type": "application/xml" });
          res.end("<Error><Code>NoSuchKey</Code></Error>");
        });
      }
      if (objects.has(key)) return send();
    }
    if (req.method === "PUT") {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const body = decodeAwsChunkedBody(Buffer.concat(chunks));
        uploadAttempts.set(key, (uploadAttempts.get(key) || 0) + 1);
        const remainingFailures = uploadFailures.get(key) || 0;
        if (remainingFailures > 0) {
          uploadFailures.set(key, remainingFailures - 1);
          res.writeHead(500);
          return res.end();
        }
        objects.set(key, body);
        mutationLog.push({ method: "PUT", key, body: body.toString() });
        res.writeHead(200);
        res.end();
      });
      return;
    }
    if (req.method === "DELETE") {
      const finish = () => {
        deleteAttempts.set(key, (deleteAttempts.get(key) || 0) + 1);
        const remainingFailures = deleteFailures.get(key) || 0;
        if (remainingFailures > 0) {
          deleteFailures.set(key, remainingFailures - 1);
          res.writeHead(500);
          return res.end();
        }
        objects.delete(key); mutationLog.push({ method: "DELETE", key }); res.writeHead(204); res.end();
      };
      const gate = deleteGates.get(key)?.shift();
      if (gate) { gate.markStarted(); return gate.released.then(finish); }
      return finish();
    }
    res.writeHead(404, { "content-type": "application/xml" });
    res.end("<Error><Code>NoSuchKey</Code></Error>");
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({
      server,
      port: server.address().port,
      block(map, key) {
        let started;
        let release;
        const state = { started: new Promise((resolveStarted) => { started = resolveStarted; }), released: new Promise((resolveRelease) => { release = resolveRelease; }) };
        state.markStarted = started;
        state.release = release;
        const queue = map.get(key) || [];
        queue.push(state);
        map.set(key, queue);
        return state;
      },
      blockGet(key) { return this.block(getGates, key); },
      blockDelete(key) { return this.block(deleteGates, key); },
      failNextDeletes(key, count) { deleteFailures.set(key, count); },
      clearDeleteFailures(key) { deleteFailures.delete(key); },
      clearUploadFailures(key) { uploadFailures.delete(key); },
      deleteAttemptCount(key) { return deleteAttempts.get(key) || 0; },
      failNextUploads(key, count) { uploadFailures.set(key, count); },
      uploadAttemptCount(key) { return uploadAttempts.get(key) || 0; },
      mutationsFor(key) { return mutationLog.filter((mutation) => mutation.key === key); },
    }));
  });
}

async function waitForServer(port, child) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited");
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error("disposable server did not start");
}

function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  child.kill();
  return new Promise((resolve) => child.once("exit", resolve));
}

test("version and pending mutations serialize with cache hydration", { timeout: 60_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-lifecycle-mutation-"));
  const dataDir = path.join(directory, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");

  const restoreName = "version-restore-race.txt";
  const queueRestoreName = "version-restore-queue-failure.txt";
  const deleteName = "version-delete-race.txt";
  const rejectedName = "rejected-pending-race.txt";
  const uploadRejectName = "upload-reject-race.txt";
  const reuseName = "reused-pending-name.txt";
  const failedDeleteName = "failed-pending-delete.txt";
  const revokedDeleteName = "revoked-during-delete-wait.txt";
  const aclRevokedRestoreName = "acl-revoked-during-restore-wait.txt";
  const failedRestoreName = "version-copy-failure.txt";
  const failedPruneSaveName = "version-prune-save-failure.txt";
  const approveSaveFailureName = "approve-history-save-failure.txt";
  const approveInitialSaveFailureName = "approve-initial-history-save-failure.txt";
  const approveTrashRecoveryName = "approve-trash-cancellation-failure.txt";
  const approveTrashRecoveryId = "6c3b9d5b-ef0a-45d9-86d8-7dd7785a0014";
  const approvePruneQueueFailureName = "approve-pruned-queue-write-failure.txt";
  const restorePruneRetryName = "restore-pruned-queue-retry.txt";
  const approveCloudQueueFailureName = "approve-cloud-queue-write-failure.txt";
  const approveRevokedName = "approve-revoked-during-cache-recovery.txt";
  const rejectRevokedName = "reject-revoked-during-cache-recovery.txt";
  const orphanReplacementName = "orphan-replacement.txt";
  const failedUploadName = "queue-write-failed.txt";
  const revokedWebDavMoveName = "revoked-during-webdav-move-cache.txt";
  const revokedWebDavMoveDestination = "revoked-webdav-move-target.txt";
  const objects = new Map();
  for (const name of [restoreName, queueRestoreName, deleteName, revokedDeleteName, aclRevokedRestoreName, failedRestoreName]) {
    objects.set(`rootark/uploads/root/${name}`, Buffer.from(`current v3 ${name}`));
    objects.set(`rootark/uploads/root/${name}.v1`, Buffer.from(`version v1 ${name}`));
    objects.set(`rootark/uploads/root/${name}.v2`, Buffer.from(`version v2 ${name}`));
  }
  objects.set(`rootark/uploads/root/${approveSaveFailureName}`, Buffer.from(`prior current ${approveSaveFailureName}`));
  objects.set(`rootark/uploads/root/${orphanReplacementName}`, Buffer.from("stale provider replacement"));
  for (const name of [approveSaveFailureName, approveInitialSaveFailureName]) objects.set(`rootark/temp/root/${name}`, Buffer.from(`pending replacement ${name}`));
  objects.set(`rootark/temp/root/${approveCloudQueueFailureName}`, Buffer.from(`pending replacement ${approveCloudQueueFailureName}`));
  for (let version = 1; version <= 10; version += 1) {
    const storedAs = version === 10 ? failedPruneSaveName : `${failedPruneSaveName}.v${version}`;
    objects.set(`rootark/uploads/root/${storedAs}`, Buffer.from(version === 10 ? `current v10 ${failedPruneSaveName}` : `version v${version} ${failedPruneSaveName}`));
  }
  for (const name of [approvePruneQueueFailureName, restorePruneRetryName]) {
    for (let version = 1; version <= 10; version += 1) {
      const storedAs = version === 10 ? name : `${name}.v${version}`;
      const bytes = Buffer.from(`${name} version ${version}`);
      objects.set(`rootark/uploads/root/${storedAs}`, bytes);
      fs.writeFileSync(path.join(directory, "uploads", storedAs), bytes);
    }
  }
  objects.set(`rootark/temp/root/${rejectedName}`, Buffer.from(`rejected ${rejectedName}`));
  objects.set(`rootark/temp/root/${uploadRejectName}`, Buffer.from(`old ${uploadRejectName}`));
  objects.set(`rootark/temp/root/${reuseName}`, Buffer.from(`old ${reuseName}`));
  objects.set(`rootark/temp/root/${failedDeleteName}`, Buffer.from(`failed delete ${failedDeleteName}`));
  objects.set(`rootark/temp/root/${approveRevokedName}`, Buffer.from(`pending ${approveRevokedName}`));
  objects.set(`rootark/temp/root/${rejectRevokedName}`, Buffer.from(`pending ${rejectRevokedName}`));
  const revokedWebDavMoveBytes = Buffer.from("remote WebDAV MOVE source");
  objects.set(`rootark/uploads/root/${revokedWebDavMoveName}`, revokedWebDavMoveBytes);
  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 10), role: "admin", permissions: { listFiles: true, upload: true, approve: true, delete: true }, sessionVersion: 0 },
    { username: "limited", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, upload: true, approve: true, delete: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
  ]));
  const initialPermissions = Object.fromEntries([restoreName, queueRestoreName, deleteName, revokedDeleteName, revokedWebDavMoveName, failedRestoreName, failedPruneSaveName, approveSaveFailureName, approveInitialSaveFailureName, approveCloudQueueFailureName, approvePruneQueueFailureName, restorePruneRetryName].map((name) => [`root/${name}`, { public: false, owner: "tester", users: {} }]));
  initialPermissions[`root/${orphanReplacementName}`] = { public: false, owner: "tester", users: { limited: { read: true, edit: false } } };
  initialPermissions[`root/${aclRevokedRestoreName}`] = { public: false, owner: null, users: { limited: { read: true, edit: true } } };
  initialPermissions["root/" + approveTrashRecoveryName] = { public: false, owner: "tester", users: {} };
  const filePermissionsPath = path.join(dataDir, "file-permissions.json");
  fs.writeFileSync(filePermissionsPath, JSON.stringify(initialPermissions));
  const initialHistory = Object.fromEntries([restoreName, queueRestoreName, deleteName, revokedDeleteName, aclRevokedRestoreName, failedRestoreName].map((name) => [`root/${name}`, {
    currentVersion: 3,
    versions: [
      { version: 1, storedAs: `${name}.v1`, size: objects.get(`rootark/uploads/root/${name}.v1`).length },
      { version: 2, storedAs: `${name}.v2`, size: objects.get(`rootark/uploads/root/${name}.v2`).length },
      { version: 3, storedAs: name, size: objects.get(`rootark/uploads/root/${name}`).length },
    ],
  }]));
  initialHistory[`root/${failedPruneSaveName}`] = {
    currentVersion: 10,
    versions: Array.from({ length: 10 }, (_, index) => ({
      version: index + 1,
      storedAs: index === 9 ? failedPruneSaveName : `${failedPruneSaveName}.v${index + 1}`,
      size: objects.get(`rootark/uploads/root/${index === 9 ? failedPruneSaveName : `${failedPruneSaveName}.v${index + 1}`}`).length,
    })),
  };
  initialHistory[`root/${approveSaveFailureName}`] = {
    currentVersion: 1,
    versions: [{ version: 1, storedAs: approveSaveFailureName, size: Buffer.byteLength(`prior current ${approveSaveFailureName}`) }],
  };
  for (const name of [approvePruneQueueFailureName, restorePruneRetryName]) {
    initialHistory[`root/${name}`] = {
      currentVersion: 10,
      versions: Array.from({ length: 10 }, (_, index) => ({
        version: index + 1,
        storedAs: index === 9 ? name : `${name}.v${index + 1}`,
        size: Buffer.byteLength(`${name} version ${index + 1}`),
      })),
    };
  }
  const versionHistoryPath = path.join(dataDir, "file-versions.json");
  const versionReadMarker = path.join(directory, "version-history-reads.txt");
  const unlinkStarted = path.join(directory, "pending-unlink-started");
  const releaseUnlink = path.join(directory, "release-pending-unlink");
  const failQueueWrites = path.join(directory, "fail-cloud-temp-queue-writes");
  const failUploadQueueWrites = path.join(directory, "fail-cloud-upload-queue-writes");
  const failUploadQueueAfterWrites = path.join(directory, "fail-cloud-upload-queue-after-writes.json");
  const failPolicyClearAfterRename = path.join(directory, "fail-policy-clear-after-rename");
  const failVersionCopy = path.join(directory, "fail-version-copy-once");
  const failVersionHistorySave = path.join(directory, "fail-version-history-save-once");
  const failApprovalHistorySave = path.join(directory, "fail-approval-history-save-once");
  const failTrashCancellationSave = path.join(directory, "fail-trash-cancellation-save-once");
  const failPrunedQueueWrite = path.join(directory, "fail-pruned-upload-queue-write-once");
  const trashItemsPath = path.join(dataDir, "trash-items.json");
  const evictPendingConfig = path.join(directory, "evict-pending-cache.json");
  const cloudQueueDirectory = path.join(dataDir, ".rootark-cloud-temp-mutations");
  const cloudUploadQueueDirectory = path.join(dataDir, ".rootark-cloud-upload-mutations");
  const prunedQueueRecordPath = path.join(cloudUploadQueueDirectory, `${crypto.createHash("sha256").update(`root\0${approvePruneQueueFailureName}.v1`).digest("hex")}.json`);
  const restorePrunedQueueRecordPath = path.join(cloudUploadQueueDirectory, `${crypto.createHash("sha256").update(`root\0${restorePruneRetryName}.v1`).digest("hex")}.json`);
  const orphanPolicyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
  const rollbackPolicyUploadName = "rollback-policy-clear.txt";
  const pendingRegistryPath = path.join(dataDir, "pending-uploads.json");
  const orphanReplacementPending = { fileName: orphanReplacementName, folderId: "root", uploadedBy: "limited", uploadedAt: "2026-10-01T00:00:00.000Z" };
  const priorFailedUploadPending = { fileName: failedUploadName, folderId: "root", uploadedBy: "tester", uploadedAt: "2026-10-01T00:00:00.000Z", versionComment: "preserve pending" };
  const priorFailedUploadEncryption = { originalFilename: "prior-encrypted-name.txt", fileName: failedUploadName, folderId: "root", encryptionLevel: "server-key", marker: "preserve encrypted metadata" };
  fs.writeFileSync(versionHistoryPath, JSON.stringify(initialHistory));
  fs.writeFileSync(versionReadMarker, "");
  fs.writeFileSync(path.join(dataDir, "pending-uploads.json"), JSON.stringify({
    [`root/${rejectedName}`]: { fileName: rejectedName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    [`root/${uploadRejectName}`]: { fileName: uploadRejectName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    [`root/${reuseName}`]: { fileName: reuseName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    [`root/${failedDeleteName}`]: { fileName: failedDeleteName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    [`root/${failedUploadName}`]: priorFailedUploadPending,
    [`root/${approveSaveFailureName}`]: { fileName: approveSaveFailureName, folderId: "root", uploadedBy: "limited", uploadedAt: new Date().toISOString() },
    [`root/${approveInitialSaveFailureName}`]: { fileName: approveInitialSaveFailureName, folderId: "root", uploadedBy: "limited", uploadedAt: new Date().toISOString() },
    [`root/${approveCloudQueueFailureName}`]: { fileName: approveCloudQueueFailureName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    [`root/${approvePruneQueueFailureName}`]: { fileName: approvePruneQueueFailureName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    [`root/${approveRevokedName}`]: { fileName: approveRevokedName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    [`root/${rejectRevokedName}`]: { fileName: rejectRevokedName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    [`root/${orphanReplacementName}`]: orphanReplacementPending,
  }));
  fs.writeFileSync(orphanPolicyPath, JSON.stringify({ version: 1, providerInventory: { state: "known" }, objects: [
    { area: "temp", folderId: "root", name: rollbackPolicyUploadName },
    { area: "uploads", folderId: "root", name: orphanReplacementName },
  ] }));
  fs.writeFileSync(path.join(dataDir, ".rootark-restore-provider-orphans-state.json"), JSON.stringify({ version: 1, providerInventory: { state: "known" } }));
  fs.writeFileSync(path.join(directory, "temp", orphanReplacementName), "approved replacement bytes");
  fs.writeFileSync(path.join(directory, "temp", approveRevokedName), `pending ${approveRevokedName}`);
  fs.writeFileSync(path.join(directory, "temp", rejectRevokedName), `pending ${rejectRevokedName}`);
  fs.writeFileSync(path.join(directory, "uploads", approveSaveFailureName), `prior current ${approveSaveFailureName}`);
  fs.writeFileSync(path.join(directory, "temp", approveSaveFailureName), `pending replacement ${approveSaveFailureName}`);
  fs.writeFileSync(path.join(directory, "temp", approveInitialSaveFailureName), `pending replacement ${approveInitialSaveFailureName}`);
  fs.writeFileSync(path.join(directory, "temp", approveCloudQueueFailureName), `pending replacement ${approveCloudQueueFailureName}`);
  fs.writeFileSync(path.join(directory, "temp", approvePruneQueueFailureName), "approved bytes after queue-write failure");
  const approveQueueFailureEncryption = { originalFilename: "encrypted-pending.txt", fileName: approveCloudQueueFailureName, folderId: "root", encryptionLevel: "server-key", marker: "preserve encrypted approval metadata" };
  fs.writeFileSync(path.join(dataDir, "encrypted-files.json"), JSON.stringify({ [`root/${failedUploadName}`]: priorFailedUploadEncryption, [`root/${approveCloudQueueFailureName}`]: approveQueueFailureEncryption }));
  fs.writeFileSync(path.join(dataDir, "trash-items.json"), "[]");
  const cloud = await makeS3Fixture(objects);
  const port = await unusedPort();
  const preloadFile = path.join(directory, "lifecycle-test-preload.cjs");
  fs.writeFileSync(preloadFile, [
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const history = ${JSON.stringify(versionHistoryPath)};`,
    `const marker = ${JSON.stringify(versionReadMarker)};`,
    `const pending = ${JSON.stringify(path.join(directory, "temp", rejectedName))};`,
    `const unlinkStarted = ${JSON.stringify(unlinkStarted)};`,
    `const releaseUnlink = ${JSON.stringify(releaseUnlink)};`,
    `const failQueueWrites = ${JSON.stringify(failQueueWrites)};`,
    `const failUploadQueueWrites = ${JSON.stringify(failUploadQueueWrites)};`,
    `const failUploadQueueAfterWrites = ${JSON.stringify(failUploadQueueAfterWrites)};`,
    `const failPolicyClearAfterRename = ${JSON.stringify(failPolicyClearAfterRename)};`,
    `const restoreOrphanPolicy = ${JSON.stringify(orphanPolicyPath)};`,
    `const failVersionCopy = ${JSON.stringify(failVersionCopy)};`,
    `const failVersionHistorySave = ${JSON.stringify(failVersionHistorySave)};`,
    `const failApprovalHistorySave = ${JSON.stringify(failApprovalHistorySave)};`,
    `const failTrashCancellationSave = ${JSON.stringify(failTrashCancellationSave)};`,
    `const failPrunedQueueWrite = ${JSON.stringify(failPrunedQueueWrite)};`,
    `const prunedQueueRecordFile = ${JSON.stringify(prunedQueueRecordPath)};`,
    `const trashItemsFile = ${JSON.stringify(trashItemsPath)};`,
    `const failedTrashId = ${JSON.stringify(approveTrashRecoveryId)};`,
    `const versionHistoryFile = ${JSON.stringify(versionHistoryPath)};`,
    `const failedRestoreTarget = ${JSON.stringify(path.join(directory, "uploads", `${failedRestoreName}.v1`))};`,
    `const evictPendingConfig = ${JSON.stringify(evictPendingConfig)};`,
    `const cloudQueueDirectory = ${JSON.stringify(cloudQueueDirectory)};`,
    `const cloudUploadQueueDirectory = ${JSON.stringify(cloudUploadQueueDirectory)};`,
    'const original = fs.readFileSync;',
    'fs.readFileSync = function (file, ...args) { if (typeof file === "string" && path.resolve(file) === history) fs.appendFileSync(marker, "1\\n"); return original.call(this, file, ...args); };',
    'const originalStatSync = fs.statSync; const originalUnlinkSync = fs.unlinkSync.bind(fs); fs.statSync = function (file, ...args) { const stat = originalStatSync.call(this, file, ...args); if (typeof file === "string" && fs.existsSync(evictPendingConfig)) { try { const config = JSON.parse(fs.readFileSync(evictPendingConfig, "utf8")); if (path.resolve(file) === path.resolve(config.path)) { config.count += 1; fs.writeFileSync(evictPendingConfig, JSON.stringify(config)); if (config.count === 2) { originalUnlinkSync(file); originalUnlinkSync(evictPendingConfig); } } } catch {} } return stat; };',
    'const waitForRelease = async () => { fs.writeFileSync(unlinkStarted, "started"); while (!fs.existsSync(releaseUnlink)) await new Promise((resolve) => setTimeout(resolve, 10)); };',
    'const originalUnlink = fs.unlink;',
    'fs.unlink = function (file, ...args) { if (typeof file === "string" && path.resolve(file) === path.resolve(pending)) { waitForRelease().then(() => originalUnlink.call(this, file, ...args)); return; } return originalUnlink.call(this, file, ...args); };',
    'const originalPromiseUnlink = fs.promises.unlink.bind(fs.promises);',
    'fs.promises.unlink = async function (file) { if (typeof file === "string" && path.resolve(file) === path.resolve(pending)) await waitForRelease(); return originalPromiseUnlink(file); };',
    'const originalCopyFileSync = fs.copyFileSync; fs.copyFileSync = function (source, destination, ...args) { if (fs.existsSync(failVersionCopy) && typeof source === "string" && path.resolve(source) === path.resolve(failedRestoreTarget)) { fs.unlinkSync(failVersionCopy); const error = new Error("injected version copy failure"); error.code = "EIO"; throw error; } return originalCopyFileSync.call(this, source, destination, ...args); };',
    'const originalWriteFileSync = fs.writeFileSync; fs.writeFileSync = function (file, ...args) { if ((fs.existsSync(failVersionHistorySave) || fs.existsSync(failApprovalHistorySave)) && typeof file === "string" && path.resolve(file) === path.resolve(versionHistoryFile)) { if (fs.existsSync(failVersionHistorySave)) fs.unlinkSync(failVersionHistorySave); if (fs.existsSync(failApprovalHistorySave)) fs.unlinkSync(failApprovalHistorySave); const error = new Error("injected version history save failure"); error.code = "EIO"; throw error; } if (fs.existsSync(failTrashCancellationSave) && typeof file === "string" && path.resolve(file) === path.resolve(trashItemsFile)) { const items = JSON.parse(String(args[0])); if (items.some((item) => item.id === failedTrashId && item.status === "permanently_deleted" && item.metadata?.remoteDeletion?.state === "cancelled")) { fs.unlinkSync(failTrashCancellationSave); const error = new Error("injected trash cancellation save failure"); error.code = "EIO"; throw error; } } return originalWriteFileSync.call(this, file, ...args); };',
    'const originalOpen = fs.openSync; fs.openSync = function (file, flags, ...args) { const inTempQueue = typeof file === "string" && path.resolve(file).startsWith(path.resolve(cloudQueueDirectory) + path.sep); const inUploadQueue = typeof file === "string" && path.resolve(file).startsWith(path.resolve(cloudUploadQueueDirectory) + path.sep); if (flags === "wx" && fs.existsSync(failPrunedQueueWrite) && typeof file === "string" && path.resolve(file).startsWith(path.resolve(prunedQueueRecordFile) + ".")) { fs.unlinkSync(failPrunedQueueWrite); const error = new Error("injected pruned upload queue write failure"); error.code = "EIO"; throw error; } if (flags === "wx" && ((fs.existsSync(failQueueWrites) && inTempQueue) || (fs.existsSync(failUploadQueueWrites) && inUploadQueue))) { const error = new Error("injected cloud queue write failure"); error.code = "EIO"; throw error; } if (flags === "wx" && inUploadQueue && fs.existsSync(failUploadQueueAfterWrites)) { const config = JSON.parse(fs.readFileSync(failUploadQueueAfterWrites, "utf8")); config.remaining -= 1; if (config.remaining <= 0) { fs.unlinkSync(failUploadQueueAfterWrites); const error = new Error("injected later cloud upload queue write failure"); error.code = "EIO"; throw error; } fs.writeFileSync(failUploadQueueAfterWrites, JSON.stringify(config)); } return originalOpen.call(this, file, flags, ...args); };',
    'const originalRename = fs.renameSync; fs.renameSync = function (source, destination, ...args) { if (fs.existsSync(failPolicyClearAfterRename) && typeof destination === "string" && path.resolve(destination) === path.resolve(restoreOrphanPolicy)) { fs.unlinkSync(failPolicyClearAfterRename); originalRename.call(this, source, destination, ...args); const error = new Error("injected policy directory-sync failure after rename"); error.code = "EIO"; throw error; } return originalRename.call(this, source, destination, ...args); };',
  ].join("\n"));
  const env = {
    ...process.env,
    PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    TOTP_POLICY: "optional", CLOUD_STORAGE_PROVIDER: "s3", AWS_S3_BUCKET: "fixture-bucket", AWS_REGION: "us-east-1",
    AWS_ENDPOINT_URL: `http://127.0.0.1:${cloud.port}`, AWS_FORCE_PATH_STYLE: "true", AWS_ACCESS_KEY_ID: "fixture-access-key",
    AWS_S3_PRINCIPAL_ID: "fixture-account",
    AWS_SECRET_ACCESS_KEY: "fixture-secret-key", TRASH_ENABLED: "true", TRASH_AUTO_CLEANUP_ENABLED: "false", CLOUD_TEMP_RECONCILIATION_INTERVAL_MS: "1000", CLOUD_UPLOAD_RECONCILIATION_INTERVAL_MS: "1000",
    WEBDAV_ENABLED: "true",
    WEBDAV_ALLOW_MOVE: "true",
    NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${preloadFile}`].filter(Boolean).join(" "),
  };
  for (const key of Object.keys(env)) if (/^GOOGLE_DRIVE_/.test(key)) delete env[key];
  delete env.TRUSTED_PROXIES;
  let child;
  const gates = [];
  t.after(async () => {
    fs.writeFileSync(releaseUnlink, "release");
    for (const gate of gates) gate.release();
    if (child) await stop(child);
    await new Promise((resolve) => cloud.server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const startChild = () => spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
  child = startChild();
  let childErrors = "";
  child.stderr?.on("data", (chunk) => { childErrors += chunk.toString(); });
  assert.equal((await waitForServer(port, child)).status, 200);
  const loginBody = JSON.stringify({ username: "tester", password });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) }, body: loginBody });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const mutate = (url, method) => request(port, url, {
    method,
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": 2 },
    body: "{}",
  });
  const limitedLoginBody = JSON.stringify({ username: "limited", password });
  const limitedLogin = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(limitedLoginBody) }, body: limitedLoginBody });
  assert.equal(limitedLogin.status, 200, limitedLogin.body);
  const limitedCookies = limitedLogin.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const limitedCookie = limitedCookies.join("; ");
  const limitedCsrf = limitedCookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const mutateAsLimited = (url, method) => request(port, url, {
    method,
    headers: { cookie: limitedCookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": limitedCsrf, "content-type": "application/json", "content-length": 2 },
    body: "{}",
  });
  const readCount = () => fs.readFileSync(versionReadMarker, "utf8").trim().split(/\r?\n/).filter(Boolean).length;
  const results = [];

  const approvalProviderKey = `rootark/uploads/root/${approveTrashRecoveryName}`;
  const approvalQueuePath = path.join(cloudUploadQueueDirectory, `${crypto.createHash("sha256").update(`root\0${approveTrashRecoveryName}`).digest("hex")}.json`);
  const approvalTrashRecord = {
    id: approveTrashRecoveryId,
    itemType: "file",
    originalFolderId: "root",
    originalFileName: approveTrashRecoveryName,
    trashPath: `files/${approveTrashRecoveryId}/${approveTrashRecoveryName}`,
    deletedAt: new Date().toISOString(),
    status: "remote_delete_pending",
    metadata: { remoteDeletion: { operationId: "approval-recovery-delete", provider: "s3", state: "pending", attempts: 0, maxAttempts: 25, nextAttemptAt: new Date().toISOString(), transitions: [{ state: "pending", at: new Date().toISOString() }] } },
    restoreMetadata: { versions: { versions: [] } },
  };
  const trashItems = JSON.parse(fs.readFileSync(trashItemsPath, "utf8"));
  trashItems.push(approvalTrashRecord);
  fs.writeFileSync(trashItemsPath, JSON.stringify(trashItems));
  const approvalPending = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"));
  approvalPending[`root/${approveTrashRecoveryName}`] = { fileName: approveTrashRecoveryName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() };
  fs.writeFileSync(pendingRegistryPath, JSON.stringify(approvalPending));
  fs.writeFileSync(path.join(directory, "temp", approveTrashRecoveryName), "replacement bytes after cancellation failure");
  objects.set(approvalProviderKey, Buffer.from("old remote bytes"));
  fs.writeFileSync(failTrashCancellationSave, "fail once");
  const approvalDeleteAttempts = cloud.deleteAttemptCount(approvalProviderKey);
  cloud.failNextUploads(approvalProviderKey, 100);
  const cancellationFailureResponse = await mutate(`/approve/${approveTrashRecoveryName}?folderId=root`, "POST");
  assert.equal(cancellationFailureResponse.status, 202, cancellationFailureResponse.body);
  assert.equal(JSON.parse(cancellationFailureResponse.body).trashCancellationPending, true);
  assert.equal(fs.readFileSync(path.join(directory, "uploads", approveTrashRecoveryName), "utf8"), "replacement bytes after cancellation failure");
  assert.equal(fs.existsSync(path.join(directory, "temp", approveTrashRecoveryName)), false);
  assert.equal(Object.hasOwn(JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8")), `root/${approveTrashRecoveryName}`), false);
  assert.equal(JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${approveTrashRecoveryName}`].currentVersion, 1);
  assert.equal(JSON.parse(fs.readFileSync(approvalQueuePath, "utf8")).desired, "present");
  const trashAfterApprovalFailure = JSON.parse(fs.readFileSync(trashItemsPath, "utf8")).find((item) => item.id === approveTrashRecoveryId);
  assert.equal(trashAfterApprovalFailure.status, "remote_delete_pending");
  assert.equal(trashAfterApprovalFailure.metadata.remoteDeletion.state, "pending");
  assert.equal(cloud.deleteAttemptCount(approvalProviderKey), approvalDeleteAttempts, "approval does not delete the provider replacement while trash cancellation is pending");
  const replacementRead = await request(port, `/files/${encodeURIComponent(approveTrashRecoveryName)}?folderId=root`, { headers: { cookie } });
  assert.equal(replacementRead.status, 200, replacementRead.body);
  assert.equal(replacementRead.body, "replacement bytes after cancellation failure");
  const replacementReadPath = "/files/" + encodeURIComponent(approveTrashRecoveryName) + "?folderId=root";
  const unauthorizedReplacementRead = await request(port, replacementReadPath, { headers: { cookie: limitedCookie } });
  assert.equal(unauthorizedReplacementRead.status, 403, unauthorizedReplacementRead.body);
  const firstUploadDeadline = Date.now() + 5000;
  while (cloud.uploadAttemptCount(approvalProviderKey) === 0 && Date.now() < firstUploadDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(cloud.uploadAttemptCount(approvalProviderKey) > 0, "the approval upload reconciliation was attempted");
  const approvalLifecycleLockDirectory = path.join(dataDir, ".rootark-cloud-file-locks");
  const approvalLifecycleLockPaths = ["folder:root", `root\0${approveTrashRecoveryName}`].map((identity) =>
    path.join(approvalLifecycleLockDirectory, `${crypto.createHash("sha256").update(identity).digest("hex")}.lock`));
  const approvalLockReleaseDeadline = Date.now() + 5000;
  while (approvalLifecycleLockPaths.some((lockPath) => fs.existsSync(lockPath)) && Date.now() < approvalLockReleaseDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.ok(approvalLifecycleLockPaths.every((lockPath) => !fs.existsSync(lockPath)),
    "the failed approval upload must release its folder and file lifecycle locks before child restart");
  assert.ok(fs.existsSync(approvalQueuePath), "the failed approval upload intent remains queued before restart");
  assert.equal(JSON.parse(fs.readFileSync(approvalQueuePath, "utf8")).desired, "present");
  assert.equal(objects.get(approvalProviderKey)?.toString(), "old remote bytes",
    "the provider replacement remains unchanged while upload failures are active");
  await stop(child);
  cloud.clearUploadFailures(approvalProviderKey);
  child = startChild();
  childErrors = "";
  child.stderr?.on("data", (chunk) => { childErrors += chunk.toString(); });
  assert.equal((await waitForServer(port, child)).status, 200);
  const approvalRecoveryDeadline = Date.now() + 30_000;
  let recoveredApprovalTrash;
  while (Date.now() < approvalRecoveryDeadline) {
    recoveredApprovalTrash = JSON.parse(fs.readFileSync(trashItemsPath, "utf8")).find((item) => item.id === approveTrashRecoveryId);
    if (recoveredApprovalTrash.status === "permanently_deleted" && recoveredApprovalTrash.metadata.remoteDeletion.state === "cancelled"
      && !fs.existsSync(approvalQueuePath) && objects.get(approvalProviderKey)?.toString() === "replacement bytes after cancellation failure") break;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(recoveredApprovalTrash.status, "permanently_deleted");
  assert.equal(recoveredApprovalTrash.metadata.remoteDeletion.state, "cancelled");
  assert.equal(fs.existsSync(approvalQueuePath), false, "restart reconciles the durable approval upload intent");
  assert.equal(objects.get(approvalProviderKey)?.toString(), "replacement bytes after cancellation failure");
  assert.equal(cloud.deleteAttemptCount(approvalProviderKey), approvalDeleteAttempts, "restart cancellation detects the local replacement before provider deletion");

  fs.writeFileSync(failApprovalHistorySave, "fail once");
  const failedReplacementApproval = await mutate(`/approve/${approveSaveFailureName}?folderId=root`, "POST");
  const replacementPending = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"))[`root/${approveSaveFailureName}`];
  const replacementHistory = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${approveSaveFailureName}`];
  assert.equal(failedReplacementApproval.status, 500);
  assert.equal(fs.readFileSync(path.join(directory, "uploads", approveSaveFailureName), "utf8"), `prior current ${approveSaveFailureName}`);
  assert.equal(fs.existsSync(path.join(directory, "uploads", `${approveSaveFailureName}.v1`)), false);
  assert.equal(fs.readFileSync(path.join(directory, "temp", approveSaveFailureName), "utf8"), `pending replacement ${approveSaveFailureName}`);
  assert.ok(replacementPending, "failed approval preserves pending registry");
  assert.deepEqual(replacementHistory, initialHistory[`root/${approveSaveFailureName}`]);

  fs.writeFileSync(failApprovalHistorySave, "fail once");
  const failedInitialApproval = await mutate(`/approve/${approveInitialSaveFailureName}?folderId=root`, "POST");
  const initialPending = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"))[`root/${approveInitialSaveFailureName}`];
  const historyAfterInitialApproval = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"));
  assert.equal(failedInitialApproval.status, 500);
  assert.equal(fs.existsSync(path.join(directory, "uploads", approveInitialSaveFailureName)), false);
  assert.equal(fs.readFileSync(path.join(directory, "temp", approveInitialSaveFailureName), "utf8"), `pending replacement ${approveInitialSaveFailureName}`);
  assert.ok(initialPending, "failed initial approval preserves pending registry");
  assert.equal(Object.hasOwn(historyAfterInitialApproval, `root/${approveInitialSaveFailureName}`), false);

  const approveQueueFailureKey = `rootark/uploads/root/${approveCloudQueueFailureName}`;
  const approveQueueFailureRecord = path.join(cloudUploadQueueDirectory, `${crypto.createHash("sha256").update(`root\0${approveCloudQueueFailureName}`).digest("hex")}.json`);
  fs.writeFileSync(failUploadQueueWrites, "fail once");
  const failedCloudQueueApproval = await mutate(`/approve/${approveCloudQueueFailureName}?folderId=root`, "POST");
  fs.rmSync(failUploadQueueWrites, { force: true });
  const approvalPendingAfterQueueFailure = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"))[`root/${approveCloudQueueFailureName}`];
  const approvalHistoryAfterQueueFailure = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"));
  const encryptionAfterApprovalQueueFailure = JSON.parse(fs.readFileSync(path.join(dataDir, "encrypted-files.json"), "utf8"))[`root/${approveCloudQueueFailureName}`];
  results.push({
    case: "approval-cloud-queue-write-failure-happens-before-promoting-local-state",
    actual: {
      status: failedCloudQueueApproval.status,
      uploadExists: fs.existsSync(path.join(directory, "uploads", approveCloudQueueFailureName)),
      tempBytes: fs.existsSync(path.join(directory, "temp", approveCloudQueueFailureName)) ? fs.readFileSync(path.join(directory, "temp", approveCloudQueueFailureName), "utf8") : null,
      pendingMetadataExists: Boolean(approvalPendingAfterQueueFailure),
      historyExists: Object.hasOwn(approvalHistoryAfterQueueFailure, `root/${approveCloudQueueFailureName}`),
      encryptionMetadata: encryptionAfterApprovalQueueFailure,
      providerIntentExists: fs.existsSync(approveQueueFailureRecord),
      providerObjectUnchanged: objects.get(approveQueueFailureKey)?.toString() === undefined,
    },
    expected: {
      status: 500,
      uploadExists: false,
      tempBytes: `pending replacement ${approveCloudQueueFailureName}`,
      pendingMetadataExists: true,
      historyExists: false,
      encryptionMetadata: approveQueueFailureEncryption,
      providerIntentExists: false,
      providerObjectUnchanged: true,
    },
  });

  fs.mkdirSync(cloudUploadQueueDirectory, { recursive: true });
  fs.writeFileSync(prunedQueueRecordPath, JSON.stringify({
    version: 1,
    folderId: "root",
    fileName: `${approvePruneQueueFailureName}.v1`,
    area: "uploads",
    desired: "present",
    generation: crypto.randomUUID(),
    updatedAt: new Date().toISOString(),
  }));
  const prunedQueueProviderKey = `rootark/uploads/root/${approvePruneQueueFailureName}.v1`;
  objects.delete(prunedQueueProviderKey);
  cloud.failNextUploads(prunedQueueProviderKey, 100);
  const pruneQueueFailureHistory = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${approvePruneQueueFailureName}`];
  fs.writeFileSync(failPrunedQueueWrite, "fail once");
  const failedPruneQueueApproval = await mutate(`/approve/${approvePruneQueueFailureName}?folderId=root`, "POST");
  assert.equal(failedPruneQueueApproval.status, 500);
  assert.equal(fs.readFileSync(path.join(directory, "uploads", approvePruneQueueFailureName), "utf8"), `${approvePruneQueueFailureName} version 10`);
  assert.equal(fs.readFileSync(path.join(directory, "uploads", `${approvePruneQueueFailureName}.v1`), "utf8"), `${approvePruneQueueFailureName} version 1`);
  assert.equal(fs.readFileSync(path.join(directory, "temp", approvePruneQueueFailureName), "utf8"), "approved bytes after queue-write failure");
  assert.equal(Object.hasOwn(JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8")), `root/${approvePruneQueueFailureName}`), true);
  assert.deepEqual(JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${approvePruneQueueFailureName}`], pruneQueueFailureHistory);
  assert.equal(JSON.parse(fs.readFileSync(prunedQueueRecordPath, "utf8")).desired, "present", "failed absent-intent persistence leaves the still-present local version queued as present");
  cloud.clearUploadFailures(prunedQueueProviderKey);

  fs.writeFileSync(restorePrunedQueueRecordPath, JSON.stringify({ version: 1, folderId: "root", fileName: restorePruneRetryName + ".v1", area: "uploads", desired: "present", generation: crypto.randomUUID(), updatedAt: new Date().toISOString() }));
  const restorePrunedCloudKey = "rootark/uploads/root/" + restorePruneRetryName + ".v1";
  const restorePrunedDeleteAttempts = cloud.deleteAttemptCount(restorePrunedCloudKey);
  cloud.failNextDeletes(restorePrunedCloudKey, 100);
  const prunedVersionRestore = await mutate(`/restore/${restorePruneRetryName}/v/1?folderId=root`, "POST");
  assert.equal(prunedVersionRestore.status, 200, prunedVersionRestore.body);
  const prunedDeleteDeadline = Date.now() + 5000;
  while (cloud.deleteAttemptCount(restorePrunedCloudKey) === restorePrunedDeleteAttempts && Date.now() < prunedDeleteDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(cloud.deleteAttemptCount(restorePrunedCloudKey) > restorePrunedDeleteAttempts, "pruned remote version deletion was attempted");
  assert.equal(JSON.parse(fs.readFileSync(restorePrunedQueueRecordPath, "utf8")).desired, "absent", "pruned version has a durable absent intent instead of its previous present intent");
  assert.equal(fs.existsSync(path.join(directory, "uploads", restorePruneRetryName + ".v1")), false, "pruned local version is removed only after the absent intent is durable");
  assert.equal(objects.has(restorePrunedCloudKey), true, "failed provider deletion retains remote bytes while the absent intent remains pending");
  cloud.clearDeleteFailures(restorePrunedCloudKey);
  await stop(child);
  child = startChild();
  childErrors = "";
  child.stderr?.on("data", (chunk) => { childErrors += chunk.toString(); });
  assert.equal((await waitForServer(port, child)).status, 200);
  const pruneRetryDeadline = Date.now() + 5000;
  while ((objects.has(restorePrunedCloudKey) || fs.existsSync(restorePrunedQueueRecordPath)) && Date.now() < pruneRetryDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(objects.has(restorePrunedCloudKey), false, "restart retries and completes the durable absent intent");
  assert.equal(fs.existsSync(restorePrunedQueueRecordPath), false, "completed absent intent is removed after provider success");

  const failedReplacementQueuePath = path.join(cloudUploadQueueDirectory, `${crypto.createHash("sha256").update(`root\0${approveSaveFailureName}`).digest("hex")}.json`);
  assert.equal(fs.existsSync(failedReplacementQueuePath), false, "a failed local version transaction removes the staged provider intent");
  const successfulReplacementApproval = await mutate(`/approve/${approveSaveFailureName}?folderId=root`, "POST");
  assert.equal(successfulReplacementApproval.status, 202, successfulReplacementApproval.body);
  assert.equal(JSON.parse(successfulReplacementApproval.body).cloudSyncPending, true);
  const replacementProviderDeadline = Date.now() + 5000;
  while ((objects.get(`rootark/uploads/root/${approveSaveFailureName}`)?.toString() !== `pending replacement ${approveSaveFailureName}`
    || objects.get(`rootark/uploads/root/${approveSaveFailureName}.v1`)?.toString() !== `prior current ${approveSaveFailureName}`) && Date.now() < replacementProviderDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.equal(objects.get(`rootark/uploads/root/${approveSaveFailureName}`)?.toString(), `pending replacement ${approveSaveFailureName}`);
  assert.equal(objects.get(`rootark/uploads/root/${approveSaveFailureName}.v1`)?.toString(), `prior current ${approveSaveFailureName}`);

  const orphanReplacementKey = `rootark/uploads/root/${orphanReplacementName}`;
  const orphanReplacementQueuePath = path.join(cloudUploadQueueDirectory, `${crypto.createHash("sha256").update(`root\0${orphanReplacementName}`).digest("hex")}.json`);
  cloud.failNextUploads(orphanReplacementKey, 1);
  const orphanReplacementApproval = await mutate(`/approve/${orphanReplacementName}?folderId=root`, "POST");
  assert.equal(orphanReplacementApproval.status, 202, orphanReplacementApproval.body);
  assert.equal(JSON.parse(orphanReplacementApproval.body).cloudSyncPending, true, "approval reports its durable provider reconciliation");
  assert.equal(fs.existsSync(orphanReplacementQueuePath), true, "provider intent is durable before approval responds");
  assert.equal(fs.readFileSync(path.join(directory, "uploads", orphanReplacementName), "utf8"), "approved replacement bytes");
  const limitedOrphanBeforeProviderRetry = await request(port, `/files/${orphanReplacementName}`, { headers: { cookie: limitedCookie } });
  assert.notEqual(limitedOrphanBeforeProviderRetry.status, 200, "ordinary readers cannot receive stale provider bytes while replacement is pending");
  const providerRetryDeadline = Date.now() + 5000;
  while (cloud.uploadAttemptCount(orphanReplacementKey) < 2 && Date.now() < providerRetryDeadline) await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(cloud.uploadAttemptCount(orphanReplacementKey), 2, "startup-style reconciliation retries a failed provider upload");
  assert.equal(objects.get(orphanReplacementKey)?.toString(), "approved replacement bytes", "retry converges the provider to the approved local content");
  const providerQueueRemovalDeadline = Date.now() + 2000;
  while (fs.existsSync(orphanReplacementQueuePath) && Date.now() < providerQueueRemovalDeadline) await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(fs.existsSync(orphanReplacementQueuePath), false, "completed provider intent is removed only after success");
  const limitedOrphanAfterProviderRetry = await request(port, `/files/${orphanReplacementName}`, { headers: { cookie: limitedCookie } });
  assert.equal(limitedOrphanAfterProviderRetry.status, 200, limitedOrphanAfterProviderRetry.body);
  assert.equal(limitedOrphanAfterProviderRetry.body, "approved replacement bytes");

  const revokedDeleteGate = cloud.blockGet(`rootark/uploads/root/${revokedDeleteName}.v1`);
  gates.push(revokedDeleteGate);
  const restoreWhileDeleteWaits = mutate(`/restore/${revokedDeleteName}/v/1?folderId=root`, "POST");
  await revokedDeleteGate.started;
  const deleteAfterSessionRevocation = mutate(`/delete/${revokedDeleteName}?folderId=root`, "POST");
  let deleteSettledBeforeLockRelease = false;
  deleteAfterSessionRevocation.then(() => { deleteSettledBeforeLockRelease = true; });
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(deleteSettledBeforeLockRelease, false, "delete waits behind the restore lifecycle lock");
  const usersPath = path.join(dataDir, "users.local.json");
  const usersWhileDeleteWaits = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  usersWhileDeleteWaits[0].sessionVersion += 1;
  fs.writeFileSync(usersPath, JSON.stringify(usersWhileDeleteWaits));
  assert.equal(JSON.parse(fs.readFileSync(usersPath, "utf8"))[0].sessionVersion, 1, "session revocation is persisted while the mutation waits");
  const revokedSessionCheck = await request(port, "/auth/2fa/status", { headers: { cookie } });
  assert.equal(revokedSessionCheck.status, 401, "the stored session version invalidates a new request");
  revokedDeleteGate.release();
  const restoreResponseBeforeDelete = await restoreWhileDeleteWaits;
  const revokedDeleteResponse = await deleteAfterSessionRevocation;
  const revokedRestoreHistory = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${revokedDeleteName}`];
  const revokedRestoreBytes = fs.readFileSync(path.join(directory, "uploads", revokedDeleteName), "utf8");
  results.push({
    case: "version-restore-and-delete-revalidate-session-after-lifecycle-waits",
    actual: { restoreStatus: restoreResponseBeforeDelete.status, status: revokedDeleteResponse.status, fileStillExists: fs.existsSync(path.join(directory, "uploads", revokedDeleteName)), trashed: JSON.parse(fs.readFileSync(path.join(dataDir, "trash-items.json"), "utf8")).some((item) => item.fileName === revokedDeleteName), restoredBytes: revokedRestoreBytes, currentVersion: revokedRestoreHistory.currentVersion },
    expected: { restoreStatus: 401, status: 401, fileStillExists: true, trashed: false, restoredBytes: `current v3 ${revokedDeleteName}`, currentVersion: 3 },
  });
  usersWhileDeleteWaits[0].sessionVersion -= 1;
  fs.writeFileSync(usersPath, JSON.stringify(usersWhileDeleteWaits));

  const aclRestoreGate = cloud.blockGet(`rootark/uploads/root/${aclRevokedRestoreName}.v1`);
  gates.push(aclRestoreGate);
  const restoreWhileAclRevoked = mutateAsLimited(`/restore/${aclRevokedRestoreName}/v/1?folderId=root`, "POST");
  await aclRestoreGate.started;
  const permissionsDuringRestore = JSON.parse(fs.readFileSync(filePermissionsPath, "utf8"));
  permissionsDuringRestore[`root/${aclRevokedRestoreName}`] = { public: false, owner: "tester", users: {} };
  fs.writeFileSync(filePermissionsPath, JSON.stringify(permissionsDuringRestore));
  aclRestoreGate.release();
  const aclRestoreResponse = await restoreWhileAclRevoked;
  const aclRestoreHistory = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${aclRevokedRestoreName}`];
  results.push({
    case: "version-restore-rechecks-file-access-after-provider-wait",
    actual: { status: aclRestoreResponse.status, bytes: fs.readFileSync(path.join(directory, "uploads", aclRevokedRestoreName), "utf8"), currentVersion: aclRestoreHistory.currentVersion },
    expected: { status: 403, bytes: `current v3 ${aclRevokedRestoreName}`, currentVersion: 3 },
  });
  permissionsDuringRestore[`root/${aclRevokedRestoreName}`] = { public: false, owner: null, users: { limited: { read: true, edit: true } } };
  fs.writeFileSync(filePermissionsPath, JSON.stringify(permissionsDuringRestore));

  fs.writeFileSync(failVersionCopy, "fail once");
  const failedRestoreResponse = await mutate(`/restore/${failedRestoreName}/v/1?folderId=root`, "POST");
  const failedRestoreHistory = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${failedRestoreName}`];
  const failedRestoreCurrentPath = path.join(directory, "uploads", failedRestoreName);
  const failedRestoreQueueRecord = path.join(cloudUploadQueueDirectory, `${crypto.createHash("sha256").update(`root\0${failedRestoreName}`).digest("hex")}.json`);
  results.push({
    case: "version-restore-copy-failure-preserves-current-file",
    actual: {
      status: failedRestoreResponse.status,
      currentExists: fs.existsSync(failedRestoreCurrentPath),
      currentBytes: fs.existsSync(failedRestoreCurrentPath) ? fs.readFileSync(failedRestoreCurrentPath, "utf8") : null,
      currentVersion: failedRestoreHistory.currentVersion,
      providerIntentExists: fs.existsSync(failedRestoreQueueRecord),
    },
    expected: { status: 500, currentExists: true, currentBytes: `current v3 ${failedRestoreName}`, currentVersion: 3, providerIntentExists: false },
  });

  fs.writeFileSync(failVersionHistorySave, "fail once");
  const failedPruneSaveResponse = await mutate(`/restore/${failedPruneSaveName}/v/1?folderId=root`, "POST");
  await new Promise((resolve) => setTimeout(resolve, 100));
  const failedPruneHistory = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${failedPruneSaveName}`];
  const failedPruneCurrentPath = path.join(directory, "uploads", failedPruneSaveName);
  const failedPruneOldVersionPath = path.join(directory, "uploads", `${failedPruneSaveName}.v1`);
  const failedPruneCloudKey = `rootark/uploads/root/${failedPruneSaveName}.v1`;
  const failedPruneQueueRecord = path.join(cloudUploadQueueDirectory, `${crypto.createHash("sha256").update(`root\0${failedPruneSaveName}.v1`).digest("hex")}.json`);
  results.push({
    case: "version-restore-save-failure-preserves-pruned-history",
    actual: {
      status: failedPruneSaveResponse.status,
      currentBytes: fs.existsSync(failedPruneCurrentPath) ? fs.readFileSync(failedPruneCurrentPath, "utf8") : null,
      currentVersion: failedPruneHistory.currentVersion,
      oldVersionExists: fs.existsSync(failedPruneOldVersionPath),
      oldCloudVersionExists: objects.has(failedPruneCloudKey),
      absentIntentRolledBack: !fs.existsSync(failedPruneQueueRecord),
      oldVersionDeleteScheduled: cloud.mutationsFor(failedPruneCloudKey).some((mutation) => mutation.method === "DELETE"),
    },
    expected: {
      status: 500,
      currentBytes: `current v10 ${failedPruneSaveName}`,
      currentVersion: 10,
      oldVersionExists: true,
      oldCloudVersionExists: true,
      absentIntentRolledBack: true,
      oldVersionDeleteScheduled: false,
    },
  });

  for (const [name, route] of [[approveRevokedName, "approve"], [rejectRevokedName, "reject"]]) {
    fs.writeFileSync(evictPendingConfig, JSON.stringify({ path: path.join(directory, "temp", name), count: 0 }));
    const cacheGate = cloud.blockGet(`rootark/temp/root/${name}`);
    gates.push(cacheGate);
    const mutation = mutate(`/${route}/${name}?folderId=root`, "POST");
    await cacheGate.started;
    const usersDuringPendingMutation = JSON.parse(fs.readFileSync(usersPath, "utf8"));
    usersDuringPendingMutation[0].sessionVersion += 1;
    fs.writeFileSync(usersPath, JSON.stringify(usersDuringPendingMutation));
    cacheGate.release();
    const response = await mutation;
    const pendingAfter = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"));
    results.push({
      case: `${route}-rechecks-session-after-pending-cache-recovery`,
      actual: {
        status: response.status,
        pendingRegistered: Boolean(pendingAfter[`root/${name}`]),
        tempExists: fs.existsSync(path.join(directory, "temp", name)),
        promoted: fs.existsSync(path.join(directory, "uploads", name)),
      },
      expected: { status: 401, pendingRegistered: true, tempExists: true, promoted: false },
    });
    usersDuringPendingMutation[0].sessionVersion -= 1;
    fs.writeFileSync(usersPath, JSON.stringify(usersDuringPendingMutation));
  }

  fs.writeFileSync(failUploadQueueAfterWrites, JSON.stringify({ remaining: 2 }));
  const failedVersionQueueRestore = await mutate(`/restore/${queueRestoreName}/v/1?folderId=root`, "POST");
  const failedVersionQueueRestoreHistory = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${queueRestoreName}`];
  const failedVersionQueueRestoreRecords = fs.existsSync(cloudUploadQueueDirectory)
    ? fs.readdirSync(cloudUploadQueueDirectory).filter((entry) => entry.endsWith(".json"))
    : [];
  assert.equal(failedVersionQueueRestore.status, 500);
  assert.equal(fs.readFileSync(path.join(directory, "uploads", queueRestoreName), "utf8"), `current v3 ${queueRestoreName}`);
  assert.deepEqual(failedVersionQueueRestoreHistory, initialHistory[`root/${queueRestoreName}`]);
  assert.deepEqual(failedVersionQueueRestoreRecords, [], "failed precommit queue staging rolls back earlier queue records");

  const restoreGate = cloud.blockGet(`rootark/uploads/root/${restoreName}.v1`);
  gates.push(restoreGate);
  const initialReads = readCount();
  const restoreV1 = mutate(`/restore/${restoreName}/v/1?folderId=root`, "POST");
  await restoreGate.started;
  const firstRead = readCount() === initialReads + 1;
  const restoreV2 = mutate(`/restore/${restoreName}/v/2?folderId=root`, "POST");
  await new Promise((resolve) => setTimeout(resolve, 150));
  const secondReadBeforeFirstCommit = readCount() !== initialReads + 1;
  restoreGate.release();
  const restoreResponses = await Promise.all([restoreV1, restoreV2]);
  const restoredHistory = JSON.parse(fs.readFileSync(versionHistoryPath, "utf8"))[`root/${restoreName}`];
  const v3Name = restoredHistory.versions.find((version) => version.version === 3)?.storedAs;
  const originalCurrentPreserved = Boolean(v3Name) && fs.existsSync(path.join(directory, "uploads", v3Name)) && fs.readFileSync(path.join(directory, "uploads", v3Name), "utf8") === `current v3 ${restoreName}`;
  results.push({
    case: "concurrent-version-restores",
    actual: { firstRead, secondReadBeforeFirstCommit, statuses: restoreResponses.map((response) => response.status), originalCurrentPreserved, currentVersion: restoredHistory.currentVersion },
    expected: { firstRead: true, secondReadBeforeFirstCommit: false, statuses: [200, 200], originalCurrentPreserved: true, currentVersion: 5 },
  });

  const deleteGate = cloud.blockGet(`rootark/uploads/root/${deleteName}.v1`);
  gates.push(deleteGate);
  const restoreForDelete = mutate(`/restore/${deleteName}/v/1?folderId=root`, "POST");
  await deleteGate.started;
  let deletionSettled = false;
  const deletingVersion = mutate(`/versions/${deleteName}/v/2?folderId=root`, "DELETE").then((response) => { deletionSettled = true; return response; });
  await new Promise((resolve) => setTimeout(resolve, 150));
  const deletionWaited = !deletionSettled;
  deleteGate.release();
  const [restoreResponse, deleteResponse] = await Promise.all([restoreForDelete, deletingVersion]);
  results.push({ case: "version-delete-waits-for-restore", actual: { deletionWaited, restoreStatus: restoreResponse.status, deleteStatus: deleteResponse.status }, expected: { deletionWaited: true, restoreStatus: 200, deleteStatus: 200 } });

  const pendingHydrationGate = cloud.blockGet(`rootark/temp/root/${rejectedName}`);
  gates.push(pendingHydrationGate);
  const rejectedPromise = mutate(`/reject/${rejectedName}?folderId=root`, "POST");
  await pendingHydrationGate.started;
  const approvalPromise = mutate(`/approve/${rejectedName}?folderId=root`, "POST");
  pendingHydrationGate.release();
  const unlinkDeadline = Date.now() + 5000;
  while (!fs.existsSync(unlinkStarted) && Date.now() < unlinkDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(fs.existsSync(unlinkStarted), true, "rejection reaches the deterministic unlink boundary");
  let approvalSettled = false;
  approvalPromise.then(() => { approvalSettled = true; });
  await new Promise((resolve) => setTimeout(resolve, 150));
  const approvalWaitedForRejection = !approvalSettled;
  fs.writeFileSync(releaseUnlink, "release");
  const [rejected, approval] = await Promise.all([rejectedPromise, approvalPromise]);
  results.push({
    case: "rejected-pending-object-not-republished",
    actual: { approvalWaitedForRejection, rejectStatus: rejected.status, approveStatus: approval.status, tempExists: fs.existsSync(path.join(directory, "temp", rejectedName)), promoted: fs.existsSync(path.join(directory, "uploads", rejectedName)) },
    expected: { approvalWaitedForRejection: true, rejectStatus: 200, approveStatus: 404, tempExists: false, promoted: false },
  });
  const rejectedDeleteGate = cloud.blockDelete(`rootark/temp/root/${reuseName}`);
  gates.push(rejectedDeleteGate);
  const reuseReject = mutate(`/reject/${reuseName}?folderId=root`, "POST");
  await rejectedDeleteGate.started;
  const replacement = Buffer.from(`replacement ${reuseName}`);
  const payload = multipartUpload(reuseName, replacement);
  let uploadSettledBeforeDelete = false;
  const uploadedPromise = request(port, `/upload?folderId=root`, {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": payload.contentType, "content-length": payload.body.length },
    body: payload.body,
  });
  uploadedPromise.then(() => { uploadSettledBeforeDelete = true; });
  await new Promise((resolve) => setTimeout(resolve, 100));
  const uploadWaitedForDelete = !uploadSettledBeforeDelete;
  rejectedDeleteGate.release();
  const uploaded = await uploadedPromise;
  const replacementKey = `rootark/temp/root/${reuseName}`;
  const localReplacement = path.join(directory, "temp", reuseName);
  assert.equal(fs.readFileSync(localReplacement, "utf8"), replacement.toString(), "same-name replacement is locally registered while provider delete is blocked");
  const reuseRejectResponse = await reuseReject;
  const pendingAfterReplacement = JSON.parse(fs.readFileSync(path.join(dataDir, "pending-uploads.json"), "utf8"))[`root/${reuseName}`];
  const localReplacementPreserved = fs.existsSync(localReplacement) && fs.readFileSync(localReplacement, "utf8") === replacement.toString();
  const putDeadline = Date.now() + 5000;
  while (!objects.get(replacementKey)?.equals(replacement) && Date.now() < putDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  const replacementDeadline = Date.now() + 1500;
  while (!objects.get(replacementKey)?.equals(replacement) && Date.now() < replacementDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  results.push({ case: "old-temp-delete-cannot-remove-replacement", actual: { uploadWaitedForDelete, rejectStatus: reuseRejectResponse.status, uploadStatus: uploaded.status, localReplacementPreserved: fs.readFileSync(localReplacement, "utf8") === replacement.toString(), replacementPreserved: Boolean(objects.get(replacementKey)?.equals(replacement)), pendingRegistration: Boolean(JSON.parse(fs.readFileSync(path.join(dataDir, "pending-uploads.json"), "utf8"))[`root/${reuseName}`]), mutations: cloud.mutationsFor(replacementKey) }, expected: { uploadWaitedForDelete: true, rejectStatus: 200, uploadStatus: 200, localReplacementPreserved: true, replacementPreserved: true, pendingRegistration: true, mutations: [{ method: "DELETE", key: replacementKey }, { method: "PUT", key: replacementKey, body: replacement.toString() }] } });

  const uploadRejectGet = cloud.blockGet(`rootark/temp/root/${uploadRejectName}`);
  gates.push(uploadRejectGet);
  const rejectDuringUpload = mutate(`/reject/${uploadRejectName}?folderId=root`, "POST");
  await uploadRejectGet.started;
  const newUploadBytes = Buffer.from(`new ${uploadRejectName}`);
  const newUpload = multipartUpload(uploadRejectName, newUploadBytes);
  let newUploadSettledBeforeReject = false;
  const newUploadPromise = request(port, "/upload?folderId=root", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": newUpload.contentType, "content-length": newUpload.body.length },
    body: newUpload.body,
  });
  newUploadPromise.then(() => { newUploadSettledBeforeReject = true; });
  await new Promise((resolve) => setTimeout(resolve, 100));
  const uploadWaitedForReject = !newUploadSettledBeforeReject;
  uploadRejectGet.release();
  const newUploadResponse = await newUploadPromise;
  const rejectDuringUploadResponse = await rejectDuringUpload;
  const uploadRejectPath = path.join(directory, "temp", uploadRejectName);
  const uploadRejectPending = JSON.parse(fs.readFileSync(path.join(dataDir, "pending-uploads.json"), "utf8"))[`root/${uploadRejectName}`];
  results.push({
    case: "single-upload-publication-serializes-with-rejection",
    actual: { uploadWaitedForReject, uploadStatus: newUploadResponse.status, rejectStatus: rejectDuringUploadResponse.status, replacementBytesPreserved: fs.existsSync(uploadRejectPath) && fs.readFileSync(uploadRejectPath).equals(newUploadBytes), pendingRegistrationPreserved: Boolean(uploadRejectPending) },
    expected: { uploadWaitedForReject: true, uploadStatus: 200, rejectStatus: 200, replacementBytesPreserved: true, pendingRegistrationPreserved: true },
  });

  fs.writeFileSync(failQueueWrites, "fail");
  const queueFailurePayload = multipartFields({ encryptionLevel: "server-key" }, "file", failedUploadName, Buffer.from("queue failure fixture"));
  const queueFailureResponse = await request(port, "/upload?folderId=root", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": queueFailurePayload.contentType, "content-length": queueFailurePayload.body.length },
    body: queueFailurePayload.body,
  });
  fs.rmSync(failQueueWrites, { force: true });
  const pendingAfterQueueFailure = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"));
  const encryptedAfterQueueFailure = JSON.parse(fs.readFileSync(path.join(dataDir, "encrypted-files.json"), "utf8"));
  results.push({
    case: "failed-cloud-queue-write-rolls-back-upload-metadata",
    actual: { status: queueFailureResponse.status, localTempExists: fs.existsSync(path.join(directory, "temp", failedUploadName)), pendingMetadata: pendingAfterQueueFailure[`root/${failedUploadName}`], encryptedMetadata: encryptedAfterQueueFailure[`root/${failedUploadName}`] },
    expected: { status: 500, localTempExists: false, pendingMetadata: priorFailedUploadPending, encryptedMetadata: priorFailedUploadEncryption },
  });

  fs.writeFileSync(failPolicyClearAfterRename, "fail");
  const policyRollbackPayload = multipartFields({ encryptionLevel: "server-key" }, "file", rollbackPolicyUploadName, Buffer.from("policy clear rollback fixture"));
  const policyRollbackResponse = await request(port, "/upload?folderId=root", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": policyRollbackPayload.contentType, "content-length": policyRollbackPayload.body.length },
    body: policyRollbackPayload.body,
  });
  fs.rmSync(failPolicyClearAfterRename, { force: true });
  const pendingAfterPolicyRollback = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"));
  const encryptedAfterPolicyRollback = JSON.parse(fs.readFileSync(path.join(dataDir, "encrypted-files.json"), "utf8"));
  const policyAfterRollback = JSON.parse(fs.readFileSync(orphanPolicyPath, "utf8"));
  const policyRollbackQueuePath = path.join(cloudQueueDirectory, `${crypto.createHash("sha256").update(`root\0${rollbackPolicyUploadName}`).digest("hex")}.json`);
  results.push({
    case: "suppression-clear-failure-rolls-back-all-upload-state-and-restores-visibility-barrier",
    actual: {
      status: policyRollbackResponse.status,
      localTempExists: fs.existsSync(path.join(directory, "temp", rollbackPolicyUploadName)),
      pendingMetadataExists: Boolean(pendingAfterPolicyRollback[`root/${rollbackPolicyUploadName}`]),
      encryptedMetadataExists: Boolean(encryptedAfterPolicyRollback[`root/${rollbackPolicyUploadName}`]),
      queueIntentExists: fs.existsSync(policyRollbackQueuePath),
      stillSuppressed: policyAfterRollback.objects.some((entry) => entry.area === "temp" && entry.folderId === "root" && entry.name === rollbackPolicyUploadName),
    },
    expected: {
      status: 500,
      localTempExists: false,
      pendingMetadataExists: false,
      encryptedMetadataExists: false,
      queueIntentExists: false,
      stillSuppressed: true,
    },
  });

  const failedChunkName = "chunk-queue-write-failed.txt";
  fs.writeFileSync(failQueueWrites, "fail");
  const chunkPayload = multipartFields({ uploadId: "queue-failure-chunk", originalName: failedChunkName, chunkIndex: 0, totalChunks: 1, encryptionLevel: "password", password: "disposable-password" }, "chunk", failedChunkName, Buffer.from("chunk queue failure fixture"));
  const chunkFailureResponse = await request(port, "/upload-chunk?folderId=root", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": chunkPayload.contentType, "content-length": chunkPayload.body.length },
    body: chunkPayload.body,
  });
  fs.rmSync(failQueueWrites, { force: true });
  const pendingAfterChunkFailure = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"));
  const encryptedAfterChunkFailure = JSON.parse(fs.readFileSync(path.join(dataDir, "encrypted-files.json"), "utf8"));
  results.push({
    case: "failed-cloud-queue-write-rolls-back-chunk-upload-metadata",
    actual: { status: chunkFailureResponse.status, localTempExists: fs.existsSync(path.join(directory, "temp", failedChunkName)), pendingMetadataExists: Boolean(pendingAfterChunkFailure[`root/${failedChunkName}`]), encryptedMetadataExists: Boolean(encryptedAfterChunkFailure[`root/${failedChunkName}`]) },
    expected: { status: 400, localTempExists: false, pendingMetadataExists: false, encryptedMetadataExists: false },
  });

  const failedWebDavName = "webdav-queue-write-failed.txt";
  fs.writeFileSync(failQueueWrites, "fail");
  const webDavAuth = `Basic ${Buffer.from(`tester:${password}`).toString("base64")}`;
  const webDavFailureResponse = await request(port, `/dav/${failedWebDavName}`, {
    method: "PUT",
    headers: { authorization: webDavAuth, "content-length": Buffer.byteLength("webdav queue failure fixture") },
    body: "webdav queue failure fixture",
  });
  fs.rmSync(failQueueWrites, { force: true });
  const pendingAfterWebDavFailure = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"));
  const encryptedAfterWebDavFailure = JSON.parse(fs.readFileSync(path.join(dataDir, "encrypted-files.json"), "utf8"));
  results.push({
    case: "failed-cloud-queue-write-rolls-back-webdav-upload-metadata",
    actual: { status: webDavFailureResponse.status, localTempExists: fs.existsSync(path.join(directory, "temp", failedWebDavName)), pendingMetadataExists: Boolean(pendingAfterWebDavFailure[`root/${failedWebDavName}`]), encryptedMetadataExists: Boolean(encryptedAfterWebDavFailure[`root/${failedWebDavName}`]) },
    expected: { status: 500, localTempExists: false, pendingMetadataExists: false, encryptedMetadataExists: false },
  });

  const webDavMoveGate = cloud.blockGet(`rootark/uploads/root/${revokedWebDavMoveName}`);
  gates.push(webDavMoveGate);
  const webDavMoveSourcePath = path.join(directory, "uploads", revokedWebDavMoveName);
  const webDavMoveMetadataPath = path.join(dataDir, "file-permissions.json");
  const webDavMoveMetadataBefore = fs.readFileSync(webDavMoveMetadataPath, "utf8");
  const webDavMoveAuth = `Basic ${Buffer.from(`tester:${password}`).toString("base64")}`;
  const webDavMoveResponsePromise = request(port, `/dav/${revokedWebDavMoveName}`, {
    method: "MOVE",
    headers: {
      authorization: webDavMoveAuth,
      destination: `http://127.0.0.1:${port}/dav/${revokedWebDavMoveDestination}`,
      overwrite: "F",
    },
  });
  await webDavMoveGate.started;
  const usersWhileWebDavMoveWaits = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  usersWhileWebDavMoveWaits[0].sessionVersion += 1;
  fs.writeFileSync(usersPath, JSON.stringify(usersWhileWebDavMoveWaits));
  webDavMoveGate.release();
  const webDavMoveResponse = await webDavMoveResponsePromise;
  const usersAfterWebDavMove = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  usersAfterWebDavMove[0].sessionVersion -= 1;
  fs.writeFileSync(usersPath, JSON.stringify(usersAfterWebDavMove));
  const webDavMoveJournals = fs.existsSync(path.join(directory, "temp", ".incoming"))
    ? fs.readdirSync(path.join(directory, "temp", ".incoming")).filter((name) => name.startsWith("rootark-webdav-move-"))
    : [];
  results.push({
    case: "webdav-move-rejects-revoked-session-after-cloud-cache-wait",
    actual: {
      status: webDavMoveResponse.status,
      sourceProviderBytesPreserved: objects.get(`rootark/uploads/root/${revokedWebDavMoveName}`)?.equals(revokedWebDavMoveBytes),
      sourceCacheBytesPreserved: fs.existsSync(webDavMoveSourcePath) && fs.readFileSync(webDavMoveSourcePath).equals(revokedWebDavMoveBytes),
      targetProviderAbsent: !objects.has(`rootark/uploads/root/${revokedWebDavMoveDestination}`),
      targetLocalAbsent: !fs.existsSync(path.join(directory, "uploads", revokedWebDavMoveDestination)),
      metadataUnchanged: fs.readFileSync(webDavMoveMetadataPath, "utf8") === webDavMoveMetadataBefore,
      moveJournalCount: webDavMoveJournals.length,
    },
    expected: {
      status: 401,
      sourceProviderBytesPreserved: true,
      sourceCacheBytesPreserved: true,
      targetProviderAbsent: true,
      targetLocalAbsent: true,
      metadataUnchanged: true,
      moveJournalCount: 0,
    },
  });

  const failedDeleteKey = `rootark/temp/root/${failedDeleteName}`;
  const priorDeleteAttempts = cloud.deleteAttemptCount(failedDeleteKey);
  cloud.failNextDeletes(failedDeleteKey, 10);
  const failedDeleteResponse = await mutate(`/reject/${failedDeleteName}?folderId=root`, "POST");
  const failedDeleteDeadline = Date.now() + 5000;
  while (cloud.deleteAttemptCount(failedDeleteKey) === priorDeleteAttempts && Date.now() < failedDeleteDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(cloud.deleteAttemptCount(failedDeleteKey) > priorDeleteAttempts, "provider delete failure is injected");
  const attemptsBeforeRestart = cloud.deleteAttemptCount(failedDeleteKey);
  const stalePendingPath = path.join(directory, "temp", failedDeleteName);
  fs.writeFileSync(stalePendingPath, "stale rejected bytes");
  const pendingRegistry = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"));
  pendingRegistry[`root/${failedDeleteName}`] = { uploadedBy: "tester", folderId: "root", uploadedAt: new Date().toISOString() };
  fs.writeFileSync(pendingRegistryPath, JSON.stringify(pendingRegistry));
  cloud.clearDeleteFailures(failedDeleteKey);
  await stop(child);
  child = startChild();
  childErrors = "";
  child.stderr?.on("data", (chunk) => { childErrors += chunk.toString(); });
  assert.equal((await waitForServer(port, child)).status, 200);
  const recoveryDeadline = Date.now() + 5000;
  while (objects.has(failedDeleteKey) && Date.now() < recoveryDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  const restartRecoveryDiagnostics = {
    cloudTempErrors: childErrors.split(/\r?\n/)
      .filter((line) => line.includes("[cloud-temp]"))
      .map((line) => line.replaceAll(directory, "<fixture>")),
    cloudTempQueueEntries: fs.existsSync(cloudQueueDirectory)
      ? fs.readdirSync(cloudQueueDirectory).map((name) => {
        try {
          const record = JSON.parse(fs.readFileSync(path.join(cloudQueueDirectory, name), "utf8"));
          return { name, parses: true, folderId: record.folderId, fileName: record.fileName, area: record.area || "temp", desired: record.desired };
        } catch (error) {
          return { name, parses: false, error: error.code || error.name };
        }
      })
      : [],
  };
  results.push({
    case: "failed-temp-delete-retries-after-restart",
    actual: { rejectStatus: failedDeleteResponse.status, providerObjectRemains: objects.has(failedDeleteKey), attemptsBeforeRestart, attemptsAfterRestart: cloud.deleteAttemptCount(failedDeleteKey), staleLocalBytesRemain: fs.existsSync(stalePendingPath), stalePendingRegistrationRemains: Boolean(JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"))[`root/${failedDeleteName}`]) },
    expected: { rejectStatus: 202, providerObjectRemains: false, attemptsBeforeRestart, attemptsAfterRestart: attemptsBeforeRestart + 1, staleLocalBytesRemain: true, stalePendingRegistrationRemains: true },
  });

  const folderMetadataPath = path.join(dataDir, "folders.json");
  fs.writeFileSync(folderMetadataPath, JSON.stringify([
    { id: "root", name: "Root", createdBy: "tester", allowedUsers: [], isRoot: true },
    { id: "folder-a", name: "Folder A", createdBy: "tester", allowedUsers: [] },
    { id: "folder-b", name: "Folder B", createdBy: "tester", allowedUsers: [] },
  ]));
  const duplicateName = "cross-folder-lock-race.txt";
  const pendingAfterRestart = JSON.parse(fs.readFileSync(pendingRegistryPath, "utf8"));
  for (const folderId of ["folder-a", "folder-b"]) {
    pendingAfterRestart[`${folderId}/${duplicateName}`] = { fileName: duplicateName, folderId, uploadedBy: "tester", uploadedAt: new Date().toISOString() };
  }
  fs.writeFileSync(pendingRegistryPath, JSON.stringify(pendingAfterRestart));
  const folderAGet = cloud.blockGet(`rootark/temp/folder-a/${duplicateName}`);
  const folderBGet = cloud.blockGet(`rootark/temp/folder-b/${duplicateName}`);
  gates.push(folderAGet, folderBGet);
  const approveFromA = mutate(`/approve/${duplicateName}?folderId=folder-a`, "POST");
  const approveFromB = mutate(`/approve/${duplicateName}?folderId=folder-b`, "POST");
  await Promise.all([folderAGet.started, folderBGet.started]);
  folderAGet.release();
  folderBGet.release();
  const resolvedApprovals = await Promise.race([
    Promise.all([approveFromA, approveFromB]),
    new Promise((resolve) => setTimeout(() => resolve(null), 4000)),
  ]);
  assert.ok(resolvedApprovals, "cross-folder approval lookup completes without waiting on the other request's folder lock");
  assert.deepEqual(resolvedApprovals.map((response) => response.status), [404, 404]);
  assert.deepEqual(results.map(({ actual }) => actual), results.map(({ expected }) => expected), JSON.stringify({
    results,
    restartRecovery: restartRecoveryDiagnostics,
  }, null, 2));
});
