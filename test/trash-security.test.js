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
const PUBLIC = path.join(ROOT, "public");
const TIMEOUT_MS = 10_000;
const FOLDER_ID = "trash-security";

function getUnusedPort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function request(port, requestPath, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let responseBody = "";
      res.on("data", (chunk) => { responseBody += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: responseBody }));
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end(body);
  });
}

async function waitForServer(port) {
  const deadline = Date.now() + TIMEOUT_MS;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await request(port, "/login.html");
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw lastError;
}

async function login(port, username, password) {
  const body = JSON.stringify({ username, password });
  const response = await request(port, "/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    body,
  });
  assert.equal(response.status, 200, response.body);
  const cookies = response.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
  return {
    cookie: cookies.join("; "),
    csrf: cookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1],
  };
}

function state(target) {
  try {
    const stat = fs.statSync(target);
    return { exists: true, size: stat.size, hash: stat.isFile() ? crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex") : null };
  } catch (error) {
    if (error.code === "ENOENT") return { exists: false };
    throw error;
  }
}

function isContained(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function json(file) {
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : [];
}

function writeFile(dir, name, bytes) {
  const target = path.join(dir, "uploads", FOLDER_ID, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, bytes);
  return target;
}

function headers(port, session) {
  return { cookie: session.cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": session.csrf };
}

test("file trash lifecycle keeps authorization and paths inside a disposable runtime root", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-security-"));
  const checkoutJson = path.join(ROOT, "data", "trash-items.json");
  const checkoutBefore = state(checkoutJson);
  const sandboxJson = path.join(sandbox, "data", "trash-items.json");
  const trashRoot = path.join(sandbox, "data", "trash");
  fs.mkdirSync(path.join(sandbox, "data"), { recursive: true });
  fs.cpSync(PUBLIC, path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "data", "users.json"), JSON.stringify([
    { username: "deleter", password: bcrypt.hashSync(password, 10), role: "user", permissions: { delete: true, listFiles: true }, sessionVersion: 0 },
    { username: "viewer", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
    { username: "manager", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, manageTrash: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(sandbox, "data", "folders.json"), JSON.stringify([
    { id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true },
    { id: FOLDER_ID, name: "Trash security", createdBy: "deleter", users: { viewer: { read: true }, manager: { read: true } }, allowedUsers: ["viewer", "manager"] },
  ]));
  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd: sandbox,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", CLOUD_STORAGE_PROVIDER: "local", TRASH_ENABLED: "true", TRASH_AUTO_CLEANUP_ENABLED: "false", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: "ignore",
    windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, TIMEOUT_MS);
        child.once("exit", () => { clearTimeout(timer); resolve(); });
        child.kill();
      });
    }
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const deleter = await login(port, "deleter", password);
  const viewer = await login(port, "viewer", password);
  const manager = await login(port, "manager", password);

  const bytes = Buffer.from("authorized trash\n");
  const source = writeFile(sandbox, "authorized.txt", bytes);
  const moved = await request(port, `/delete/authorized.txt?folderId=${FOLDER_ID}`, { method: "POST", headers: headers(port, deleter) });
  const movedResult = JSON.parse(moved.body);
  assert.equal(moved.status, 200, moved.body);
  assert.equal(movedResult.message, "Movido para lixeira");
  const item = json(sandboxJson).find((entry) => entry.id === movedResult.trashItem.id);
  assert.match(item.id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i);
  assert.equal(item.itemType, "file");
  assert.equal(item.originalFolderId, FOLDER_ID);
  assert.equal(item.originalFileName, "authorized.txt");
  assert.equal(item.deletedBy, "deleter");
  assert.equal(item.status, "trashed");
  assert.equal(path.isAbsolute(item.trashPath), false);
  const physical = path.resolve(trashRoot, item.trashPath);
  assert.equal(fs.existsSync(source), false);
  assert.equal(isContained(path.join(trashRoot, "files", item.id), physical), true);
  assert.deepEqual(fs.readFileSync(physical), bytes);
  assert.equal(item.status, "trashed");
  assert.deepEqual(state(checkoutJson), checkoutBefore);
  assert.equal(fs.existsSync(path.join(ROOT, "data", "trash", "files", item.id, "authorized.txt")), false);

  const deniedSource = writeFile(sandbox, "denied.txt", Buffer.from("must stay live\n"));
  const deniedBefore = { source: state(deniedSource), json: state(sandboxJson), trash: fs.existsSync(trashRoot) ? fs.readdirSync(trashRoot).sort() : [] };
  const denied = await request(port, `/delete/denied.txt?folderId=${FOLDER_ID}`, { method: "POST", headers: headers(port, viewer) });
  assert.equal(denied.status, 403);
  assert.equal(JSON.parse(denied.body).error, "Permissao negada: delete");
  assert.deepEqual(state(deniedSource), deniedBefore.source);
  assert.deepEqual(state(sandboxJson), deniedBefore.json);
  assert.deepEqual(fs.existsSync(trashRoot) ? fs.readdirSync(trashRoot).sort() : [], deniedBefore.trash);
  assert.deepEqual(state(checkoutJson), checkoutBefore);

  const deleterList = JSON.parse((await request(port, "/trash", { headers: { cookie: deleter.cookie } })).body);
  const viewerList = JSON.parse((await request(port, "/trash", { headers: { cookie: viewer.cookie } })).body);
  const managerList = JSON.parse((await request(port, "/trash", { headers: { cookie: manager.cookie } })).body);
  assert.equal(deleterList.items.some((entry) => entry.id === item.id), true);
  assert.equal(viewerList.items.some((entry) => entry.id === item.id), false);
  assert.equal(managerList.items.some((entry) => entry.id === item.id), true);
  assert.equal(JSON.parse((await request(port, "/trash/summary", { headers: { cookie: deleter.cookie } })).body).sizeBytes, bytes.length);
  assert.equal(JSON.parse((await request(port, "/trash/summary", { headers: { cookie: viewer.cookie } })).body).count, 0);
  assert.equal(JSON.parse((await request(port, "/trash/summary", { headers: { cookie: manager.cookie } })).body).sizeBytes, bytes.length);

  const restored = await request(port, `/trash/${item.id}/restore`, { method: "POST", headers: headers(port, deleter) });
  assert.equal(restored.status, 200, restored.body);
  assert.equal(JSON.parse(restored.body).message, "Item restaurado");
  assert.deepEqual(fs.readFileSync(source), bytes);
  assert.equal(fs.existsSync(physical), false);
  assert.equal(json(sandboxJson).find((entry) => entry.id === item.id)?.status, "restored");
  assert.equal(isContained(path.join(sandbox, "uploads", FOLDER_ID), source), true);

  const permanentBytes = Buffer.from("permanent deletion\n");
  writeFile(sandbox, "permanent.txt", permanentBytes);
  const permanentResponse = JSON.parse((await request(port, `/delete/permanent.txt?folderId=${FOLDER_ID}`, { method: "POST", headers: headers(port, deleter) })).body).trashItem;
  const permanentMove = json(sandboxJson).find((entry) => entry.id === permanentResponse.id);
  const permanentPath = path.resolve(trashRoot, permanentMove.trashPath);
  const permanentDenied = await request(port, `/trash/${permanentMove.id}`, { method: "DELETE", headers: headers(port, viewer) });
  assert.equal(permanentDenied.status, 403);
  assert.equal(JSON.parse(permanentDenied.body).error, "Permissao negada: manageTrash");
  assert.equal(fs.existsSync(permanentPath), true);
  assert.equal(json(sandboxJson).find((entry) => entry.id === permanentMove.id)?.status, "trashed");
  const permanentDeleted = await request(port, `/trash/${permanentMove.id}`, { method: "DELETE", headers: headers(port, manager) });
  assert.equal(permanentDeleted.status, 200, permanentDeleted.body);
  assert.equal(JSON.parse(permanentDeleted.body).message, "Item excluido permanentemente");
  assert.equal(fs.existsSync(permanentPath), false);
  assert.equal(json(sandboxJson).find((entry) => entry.id === permanentMove.id)?.status, "permanently_deleted");

  const sentinel = path.join(sandbox, "data", "sentinel.txt");
  const sentinelBytes = Buffer.from("outside trash sentinel\n");
  fs.writeFileSync(sentinel, sentinelBytes);
  const tamperedId = crypto.randomUUID();
  const items = json(sandboxJson);
  items.push({ id: tamperedId, itemType: "file", originalFolderId: FOLDER_ID, originalFileName: "tampered.txt", storedFileName: "tampered.txt", deletedBy: "deleter", deletedAt: new Date().toISOString(), sizeBytes: sentinelBytes.length, trashPath: "../sentinel.txt", metadata: {}, restoreMetadata: {}, status: "trashed" });
  fs.writeFileSync(sandboxJson, JSON.stringify(items, null, 2));
  const sentinelBefore = state(sentinel);
  const tamperedRestore = await request(port, `/trash/${tamperedId}/restore`, { method: "POST", headers: headers(port, deleter) });
  assert.equal(tamperedRestore.status, 500);
  assert.equal(JSON.parse(tamperedRestore.body).error, "Erro ao restaurar item");
  assert.deepEqual(state(sentinel), sentinelBefore);
  assert.equal(fs.existsSync(path.join(sandbox, "uploads", FOLDER_ID, "tampered.txt")), false);
  assert.equal(json(sandboxJson).find((entry) => entry.id === tamperedId)?.status, "trashed");
  const tamperedDelete = await request(port, `/trash/${tamperedId}`, { method: "DELETE", headers: headers(port, manager) });
  assert.equal(tamperedDelete.status, 500);
  assert.equal(JSON.parse(tamperedDelete.body).error, "Erro ao excluir permanentemente");
  assert.deepEqual(state(sentinel), sentinelBefore);
  assert.equal(json(sandboxJson).find((entry) => entry.id === tamperedId)?.status, "trashed");
  assert.deepEqual(state(checkoutJson), checkoutBefore);
});
