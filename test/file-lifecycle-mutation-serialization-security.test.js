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
      req.on("end", () => { const body = decodeAwsChunkedBody(Buffer.concat(chunks)); objects.set(key, body); mutationLog.push({ method: "PUT", key, body: body.toString() }); res.writeHead(200); res.end(); });
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
      deleteAttemptCount(key) { return deleteAttempts.get(key) || 0; },
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

test("version and pending mutations serialize with cache hydration", { timeout: 45_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-lifecycle-mutation-"));
  const dataDir = path.join(directory, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");

  const restoreName = "version-restore-race.txt";
  const deleteName = "version-delete-race.txt";
  const rejectedName = "rejected-pending-race.txt";
  const uploadRejectName = "upload-reject-race.txt";
  const reuseName = "reused-pending-name.txt";
  const failedDeleteName = "failed-pending-delete.txt";
  const revokedDeleteName = "revoked-during-delete-wait.txt";
  const failedUploadName = "queue-write-failed.txt";
  const revokedWebDavMoveName = "revoked-during-webdav-move-cache.txt";
  const revokedWebDavMoveDestination = "revoked-webdav-move-target.txt";
  const objects = new Map();
  for (const name of [restoreName, deleteName, revokedDeleteName]) {
    objects.set(`rootark/uploads/root/${name}`, Buffer.from(`current v3 ${name}`));
    objects.set(`rootark/uploads/root/${name}.v1`, Buffer.from(`version v1 ${name}`));
    objects.set(`rootark/uploads/root/${name}.v2`, Buffer.from(`version v2 ${name}`));
  }
  objects.set(`rootark/temp/root/${rejectedName}`, Buffer.from(`rejected ${rejectedName}`));
  objects.set(`rootark/temp/root/${uploadRejectName}`, Buffer.from(`old ${uploadRejectName}`));
  objects.set(`rootark/temp/root/${reuseName}`, Buffer.from(`old ${reuseName}`));
  objects.set(`rootark/temp/root/${failedDeleteName}`, Buffer.from(`failed delete ${failedDeleteName}`));
  const revokedWebDavMoveBytes = Buffer.from("remote WebDAV MOVE source");
  objects.set(`rootark/uploads/root/${revokedWebDavMoveName}`, revokedWebDavMoveBytes);
  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 10), role: "admin", permissions: { listFiles: true, upload: true, approve: true, delete: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(Object.fromEntries([restoreName, deleteName, revokedDeleteName, revokedWebDavMoveName].map((name) => [`root/${name}`, { public: false, owner: "tester", users: {} }]))));
  const initialHistory = Object.fromEntries([restoreName, deleteName, revokedDeleteName].map((name) => [`root/${name}`, {
    currentVersion: 3,
    versions: [
      { version: 1, storedAs: `${name}.v1`, size: objects.get(`rootark/uploads/root/${name}.v1`).length },
      { version: 2, storedAs: `${name}.v2`, size: objects.get(`rootark/uploads/root/${name}.v2`).length },
      { version: 3, storedAs: name, size: objects.get(`rootark/uploads/root/${name}`).length },
    ],
  }]));
  const versionHistoryPath = path.join(dataDir, "file-versions.json");
  const versionReadMarker = path.join(directory, "version-history-reads.txt");
  const unlinkStarted = path.join(directory, "pending-unlink-started");
  const releaseUnlink = path.join(directory, "release-pending-unlink");
  const failQueueWrites = path.join(directory, "fail-cloud-temp-queue-writes");
  const cloudQueueDirectory = path.join(dataDir, ".rootark-cloud-temp-mutations");
  const pendingRegistryPath = path.join(dataDir, "pending-uploads.json");
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
  }));
  fs.writeFileSync(path.join(dataDir, "encrypted-files.json"), JSON.stringify({ [`root/${failedUploadName}`]: priorFailedUploadEncryption }));
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
    `const cloudQueueDirectory = ${JSON.stringify(cloudQueueDirectory)};`,
    'const original = fs.readFileSync;',
    'fs.readFileSync = function (file, ...args) { if (typeof file === "string" && path.resolve(file) === history) fs.appendFileSync(marker, "1\\n"); return original.call(this, file, ...args); };',
    'const waitForRelease = async () => { fs.writeFileSync(unlinkStarted, "started"); while (!fs.existsSync(releaseUnlink)) await new Promise((resolve) => setTimeout(resolve, 10)); };',
    'const originalUnlink = fs.unlink;',
    'fs.unlink = function (file, ...args) { if (typeof file === "string" && path.resolve(file) === path.resolve(pending)) { waitForRelease().then(() => originalUnlink.call(this, file, ...args)); return; } return originalUnlink.call(this, file, ...args); };',
    'const originalPromiseUnlink = fs.promises.unlink.bind(fs.promises);',
    'fs.promises.unlink = async function (file) { if (typeof file === "string" && path.resolve(file) === path.resolve(pending)) await waitForRelease(); return originalPromiseUnlink(file); };',
    'const originalOpen = fs.openSync; fs.openSync = function (file, flags, ...args) { if (fs.existsSync(failQueueWrites) && typeof file === "string" && path.resolve(file).startsWith(path.resolve(cloudQueueDirectory) + path.sep) && flags === "wx") { const error = new Error("injected cloud queue write failure"); error.code = "EIO"; throw error; } return originalOpen.call(this, file, flags, ...args); };',
  ].join("\n"));
  const env = {
    ...process.env,
    PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    TOTP_POLICY: "optional", CLOUD_STORAGE_PROVIDER: "s3", AWS_S3_BUCKET: "fixture-bucket", AWS_REGION: "us-east-1",
    AWS_ENDPOINT_URL: `http://127.0.0.1:${cloud.port}`, AWS_FORCE_PATH_STYLE: "true", AWS_ACCESS_KEY_ID: "fixture-access-key",
    AWS_SECRET_ACCESS_KEY: "fixture-secret-key", TRASH_ENABLED: "true", TRASH_AUTO_CLEANUP_ENABLED: "false", CLOUD_TEMP_RECONCILIATION_INTERVAL_MS: "1000",
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
  const readCount = () => fs.readFileSync(versionReadMarker, "utf8").trim().split(/\r?\n/).filter(Boolean).length;
  const results = [];

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
  results.push({
    case: "delete-revalidates-session-after-lifecycle-lock-wait",
    actual: { restoreStatus: restoreResponseBeforeDelete.status, status: revokedDeleteResponse.status, fileStillExists: fs.existsSync(path.join(directory, "uploads", revokedDeleteName)), trashed: JSON.parse(fs.readFileSync(path.join(dataDir, "trash-items.json"), "utf8")).some((item) => item.fileName === revokedDeleteName) },
    expected: { restoreStatus: 200, status: 401, fileStillExists: true, trashed: false },
  });
  usersWhileDeleteWaits[0].sessionVersion -= 1;
  fs.writeFileSync(usersPath, JSON.stringify(usersWhileDeleteWaits));

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
  assert.deepEqual(results.map(({ actual }) => actual), results.map(({ expected }) => expected), JSON.stringify(results, null, 2));
});
