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

function request(port, requestPath, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end(body);
  });
}

function unusedPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function waitForServer(port) {
  const deadline = Date.now() + TIMEOUT_MS;
  while (Date.now() < deadline) {
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  throw new Error("server did not start");
}

async function login(port, username, password) {
  const body = JSON.stringify({ username, password });
  const response = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(response.status, 200, response.body);
  const cookies = response.headers?.["set-cookie"] || [];
  const cookieValues = cookies.map((cookie) => cookie.split(";", 1)[0]);
  return { cookie: cookieValues.join("; "), csrf: cookieValues.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1] };
}

function sessionHeaders(port, session, body) {
  return {
    cookie: session.cookie,
    origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": session.csrf,
    ...(body === undefined ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(body) }),
  };
}

function write(target, bytes) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, bytes);
  return target;
}

function readJson(target) {
  return fs.existsSync(target) ? JSON.parse(fs.readFileSync(target, "utf8")) : [];
}

function state(target) {
  if (!fs.existsSync(target)) return { type: "absent" };
  const stat = fs.lstatSync(target);
  if (stat.isFile()) return { type: "file", hash: crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex") };
  const entries = [];
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      const relative = path.relative(target, absolute);
      entries.push(entry.isDirectory() ? `d:${relative}` : `f:${relative}:${crypto.createHash("sha256").update(fs.readFileSync(absolute)).digest("hex")}`);
      if (entry.isDirectory()) visit(absolute);
    }
  };
  visit(target);
  return { type: "directory", entries: entries.sort() };
}

async function createHarness(t, { folders = [], items = [], autoCleanup = false, beforeStart } = {}) {
  const password = crypto.randomBytes(24).toString("base64url");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-local-"));
  fs.mkdirSync(path.join(dir, "data"), { recursive: true });
  fs.cpSync(PUBLIC, path.join(dir, "public"), { recursive: true });
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "owner", password: bcrypt.hashSync(password, 10), role: "user", permissions: { delete: true, listFiles: true }, sessionVersion: 0 },
    { username: "ordinary", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
    { username: "manager", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, manageTrash: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dir, "data", "folders.json"), JSON.stringify([{ id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true }, ...folders]));
  if (items.length) fs.writeFileSync(path.join(dir, "data", "trash-items.json"), JSON.stringify(items, null, 2));
  if (beforeStart) beforeStart(dir);
  const port = await unusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd: dir,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", TRASH_ENABLED: "true", TRASH_AUTO_CLEANUP_ENABLED: String(autoCleanup), TRASH_RETENTION_DAYS: "30", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: "ignore",
    windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null) await new Promise((resolve) => {
      const timer = setTimeout(resolve, TIMEOUT_MS);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
      child.kill();
    });
    fs.rmSync(dir, { recursive: true, force: true });
    assert.equal(fs.existsSync(dir), false);
  });
  assert.equal((await waitForServer(port)).status, 200);
  return { dir, port, password };
}

test("folder trash lifecycle preserves bytes, authorization, restore, and containment", { timeout: 30_000 }, async (t) => {
  const folder = (id, owner = "owner") => ({ id, name: id, createdBy: owner, users: { manager: { read: true } }, allowedUsers: ["manager"] });
  const harness = await createHarness(t, { folders: [folder("folder-life"), folder("folder-permanent"), folder("folder-denied", "ordinary")] });
  const { dir, port, password } = harness;
  const owner = await login(port, "owner", password);
  const ordinary = await login(port, "ordinary", password);
  const manager = await login(port, "manager", password);
  const trashJson = path.join(dir, "data", "trash-items.json");
  const trashRoot = path.join(dir, "data", "trash");
  const checkout = [path.join(ROOT, "data", "trash"), path.join(ROOT, "data", "trash-items.json")];
  const checkoutBefore = checkout.map(state);

  const nestedBytes = Buffer.from([0, 1, 2, 255, 13, 10]);
  const source = write(path.join(dir, "uploads", "folder-life", "nested", "bytes.bin"), nestedBytes);
  const pending = write(path.join(dir, "temp", "folder-life", "pending.txt"), "pending");
  const moved = await request(port, "/folders/folder-life", { method: "DELETE", headers: sessionHeaders(port, owner) });
  assert.equal(moved.status, 200, moved.body);
  const movedItem = readJson(trashJson).find((item) => item.id === JSON.parse(moved.body).trashItem.id);
  const physical = path.resolve(trashRoot, movedItem.trashPath);
  assert.equal(fs.existsSync(source), false);
  assert.equal(fs.existsSync(pending), false);
  assert.deepEqual(fs.readFileSync(path.join(physical, "uploads", "nested", "bytes.bin")), nestedBytes);
  assert.deepEqual(fs.readFileSync(path.join(physical, "temp", "pending.txt")), Buffer.from("pending"));
  assert.equal(readJson(path.join(dir, "data", "folders.json")).some((entry) => entry.id === "folder-life"), false);

  const ownerItems = JSON.parse((await request(port, "/trash", { headers: { cookie: owner.cookie } })).body).items;
  const managerItems = JSON.parse((await request(port, "/trash", { headers: { cookie: manager.cookie } })).body).items;
  assert.equal(ownerItems.some((item) => item.id === movedItem.id), true);
  assert.equal(managerItems.some((item) => item.id === movedItem.id), true);

  const deniedSource = write(path.join(dir, "uploads", "folder-denied", "keep.txt"), "keep");
  const deniedBefore = [state(deniedSource), state(trashJson), state(trashRoot), state(path.join(dir, "data", "folders.json"))];
  const denied = await request(port, "/folders/folder-denied", { method: "DELETE", headers: sessionHeaders(port, ordinary) });
  assert.equal(denied.status, 403);
  assert.equal(JSON.parse(denied.body).error, "Permissao negada: delete");
  assert.deepEqual([state(deniedSource), state(trashJson), state(trashRoot), state(path.join(dir, "data", "folders.json"))], deniedBefore);

  const restored = await request(port, `/trash/${movedItem.id}/restore`, { method: "POST", headers: sessionHeaders(port, owner) });
  assert.equal(restored.status, 200, restored.body);
  assert.deepEqual(fs.readFileSync(path.join(dir, "uploads", "folder-life", "nested", "bytes.bin")), nestedBytes);
  assert.equal(readJson(trashJson).find((item) => item.id === movedItem.id).status, "restored");

  write(path.join(dir, "uploads", "folder-permanent", "delete.txt"), "delete");
  const permanentMove = JSON.parse((await request(port, "/folders/folder-permanent", { method: "DELETE", headers: sessionHeaders(port, owner) })).body).trashItem;
  const permanentPath = path.resolve(trashRoot, readJson(trashJson).find((item) => item.id === permanentMove.id).trashPath);
  const permanentDenied = await request(port, `/trash/${permanentMove.id}`, { method: "DELETE", headers: sessionHeaders(port, owner) });
  assert.equal(permanentDenied.status, 403);
  assert.equal(JSON.parse(permanentDenied.body).error, "Permissao negada: manageTrash");
  assert.equal(fs.existsSync(permanentPath), true);
  const permanentDeleted = await request(port, `/trash/${permanentMove.id}`, { method: "DELETE", headers: sessionHeaders(port, manager) });
  assert.equal(permanentDeleted.status, 200, permanentDeleted.body);
  assert.equal(fs.existsSync(permanentPath), false);
  assert.equal(readJson(trashJson).find((item) => item.id === permanentMove.id).status, "permanently_deleted");

  const sentinel = write(path.join(dir, "data", "outside-folder-sentinel.txt"), "outside");
  const tamperedId = crypto.randomUUID();
  const entries = readJson(trashJson);
  entries.push({ id: tamperedId, itemType: "folder", originalFolderId: "tampered-folder", originalFolderName: "tampered", originalFileName: "tampered", deletedBy: "owner", deletedAt: new Date().toISOString(), sizeBytes: 7, trashPath: "../outside-folder-sentinel.txt", metadata: {}, restoreMetadata: { folder: folder("tampered-folder") }, status: "trashed" });
  fs.writeFileSync(trashJson, JSON.stringify(entries, null, 2));
  const sentinelBefore = state(sentinel);
  const foldersBefore = state(path.join(dir, "data", "folders.json"));
  const tamperedRestore = await request(port, `/trash/${tamperedId}/restore`, { method: "POST", headers: sessionHeaders(port, owner) });
  assert.equal(tamperedRestore.status, 500);
  assert.deepEqual(state(sentinel), sentinelBefore);
  assert.deepEqual(state(path.join(dir, "data", "folders.json")), foldersBefore);
  const tamperedDelete = await request(port, `/trash/${tamperedId}`, { method: "DELETE", headers: sessionHeaders(port, manager) });
  assert.equal(tamperedDelete.status, 500);
  assert.deepEqual(state(sentinel), sentinelBefore);
  assert.equal(readJson(trashJson).find((item) => item.id === tamperedId).status, "trashed");
  assert.deepEqual(checkout.map(state), checkoutBefore);
});

test("empty trash enforces manageTrash and keeps failed or completed states consistent", { timeout: 30_000 }, async (t) => {
  const eligibleId = crypto.randomUUID();
  const failedId = crypto.randomUUID();
  const restoredId = crypto.randomUUID();
  const deletedId = crypto.randomUUID();
  const item = (id, status, trashPath) => ({ id, itemType: "file", originalFolderId: "root", originalFileName: `${id}.txt`, storedFileName: `${id}.txt`, deletedBy: "owner", deletedAt: new Date(0).toISOString(), sizeBytes: 1, trashPath, metadata: {}, restoreMetadata: {}, status });
  const items = [item(eligibleId, "trashed", `files/${eligibleId}/eligible.txt`), item(failedId, "trashed", "../outside.txt"), item(restoredId, "restored", `files/${restoredId}/restored.txt`), item(deletedId, "permanently_deleted", `files/${deletedId}/deleted.txt`)];
  const harness = await createHarness(t, { items });
  const { dir, port, password } = harness;
  const ordinary = await login(port, "ordinary", password);
  const manager = await login(port, "manager", password);
  const trashJson = path.join(dir, "data", "trash-items.json");
  const trashRoot = path.join(dir, "data", "trash");
  const eligible = write(path.join(trashRoot, "files", eligibleId, "eligible.txt"), "e");
  const restored = write(path.join(trashRoot, "files", restoredId, "restored.txt"), "r");
  const deleted = write(path.join(trashRoot, "files", deletedId, "deleted.txt"), "d");
  const sentinel = write(path.join(dir, "data", "outside.txt"), "outside");
  const before = [state(trashJson), state(trashRoot), state(sentinel)];
  const body = JSON.stringify({ confirmation: "DELETE" });

  const denied = await request(port, "/trash", { method: "DELETE", headers: sessionHeaders(port, ordinary, body), body });
  assert.equal(denied.status, 403);
  assert.equal(JSON.parse(denied.body).error, "Permissao negada: manageTrash");
  assert.deepEqual([state(trashJson), state(trashRoot), state(sentinel)], before);

  const emptied = await request(port, "/trash", { method: "DELETE", headers: sessionHeaders(port, manager, body), body });
  assert.equal(emptied.status, 200, emptied.body);
  assert.equal(JSON.parse(emptied.body).deletedCount, 1);
  const after = readJson(trashJson);
  assert.equal(after.find((entry) => entry.id === eligibleId).status, "permanently_deleted");
  assert.equal(after.find((entry) => entry.id === failedId).status, "trashed");
  assert.equal(after.find((entry) => entry.id === restoredId).status, "restored");
  assert.equal(after.find((entry) => entry.id === deletedId).status, "permanently_deleted");
  assert.equal(fs.existsSync(eligible), false);
  assert.equal(fs.existsSync(restored), true);
  assert.equal(fs.existsSync(deleted), true);
  assert.deepEqual(state(sentinel), before[2]);
});

test("startup cleanup deterministically removes only expired safe trashed items", { timeout: 30_000 }, async (t) => {
  const ids = Object.fromEntries(["expired", "recent", "restored", "deleted", "traversal", "malformed"].map((name) => [name, crypto.randomUUID()]));
  const old = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
  const recent = new Date().toISOString();
  const item = (name, status, deletedAt, trashPath = `files/${ids[name]}/${name}.txt`) => ({ id: ids[name], itemType: "file", originalFolderId: "root", originalFileName: `${name}.txt`, storedFileName: `${name}.txt`, deletedBy: "owner", deletedAt, sizeBytes: 1, trashPath, metadata: {}, restoreMetadata: {}, status });
  const items = [item("expired", "trashed", old), item("recent", "trashed", recent), item("restored", "restored", old), item("deleted", "permanently_deleted", old), item("traversal", "trashed", old, "../outside-cleanup.txt"), item("malformed", "trashed", "not-a-date")];
  let paths;
  const harness = await createHarness(t, {
    items,
    autoCleanup: true,
    beforeStart(dir) {
      const trashRoot = path.join(dir, "data", "trash");
      paths = {
        expired: write(path.join(trashRoot, items[0].trashPath), "e"),
        recent: write(path.join(trashRoot, items[1].trashPath), "n"),
        restored: write(path.join(trashRoot, items[2].trashPath), "r"),
        deleted: write(path.join(trashRoot, items[3].trashPath), "d"),
        malformed: write(path.join(trashRoot, items[5].trashPath), "m"),
        sentinel: write(path.join(dir, "data", "outside-cleanup.txt"), "outside"),
      };
    },
  });
  const after = readJson(path.join(harness.dir, "data", "trash-items.json"));
  assert.equal(after.find((entry) => entry.id === ids.expired).status, "permanently_deleted");
  assert.equal(after.find((entry) => entry.id === ids.recent).status, "trashed");
  assert.equal(after.find((entry) => entry.id === ids.restored).status, "restored");
  assert.equal(after.find((entry) => entry.id === ids.deleted).status, "permanently_deleted");
  assert.equal(after.find((entry) => entry.id === ids.traversal).status, "trashed");
  assert.equal(after.find((entry) => entry.id === ids.malformed).status, "trashed");
  assert.equal(fs.existsSync(paths.expired), false);
  for (const name of ["recent", "restored", "deleted", "malformed", "sentinel"]) assert.equal(fs.existsSync(paths[name]), true, name);
  assert.deepEqual(fs.readFileSync(paths.sentinel), Buffer.from("outside"));
});
