const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-route-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";

const trashRepository = require("../repositories/trashRepository");
const trashService = require("../services/trashService");
const registerTrashRoutes = require("../src/routes/trash");

const routes = {};
const audits = [];
const broadcasts = [];
let trashManagerStillAuthorized = true;
let restoreSession = { username: "tester", role: "admin", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 1 };
let nextLifecycleGate = null;
const app = {
  get(route, ...handlers) { routes[`GET ${route}`] = handlers.at(-1); },
  post(route, ...handlers) { routes[`POST ${route}`] = handlers.at(-1); },
  delete(route, ...handlers) { routes[`DELETE ${route}`] = handlers.at(-1); },
};

registerTrashRoutes(app, {
  addActionHistory() {},
  auditLog(...event) { audits.push(event); },
  authenticate() {},
  broadcastDataChanged(...event) { broadcasts.push(event); },
  canManageTrash() { return true; },
  revalidateTrashManageAccess(_req, res) {
    if (trashManagerStillAuthorized) return true;
    res.status(403).json({ error: "Permissao negada: manageTrash" });
    return false;
  },
  refreshAuthenticatedUser(req, res) {
    if (!restoreSession || restoreSession.sessionVersion !== req.user?.sessionVersion) {
      res.status(401).json({ error: "Sessao invalida ou expirada" });
      return false;
    }
    req.user = { ...req.user, ...restoreSession };
    return true;
  },
  canRestoreTrashItem(req, trashItem) {
    return Boolean(req.user?.permissions?.manageTrash) || trashItem.deletedBy === req.user?.username;
  },
  deleteCloudTrashItem: async () => true,
  deleteCloudTrashItemLater() {},
  ensureFolderDirectories() { return {}; },
  getAuditActor() { return { username: "tester", role: "admin" }; },
  getCloudStorageStatus() { return { provider: "s3" }; },
  getFolderById(id) { return { id }; },
  getTrashLoaders() { return {}; },
  isTrashEnabled() { return true; },
  isCloudStorageEnabled() { return true; },
  requirePermission() {},
  requireTrashManageAccess() {},
  runCloudFileLifecycleMutation(_folderId, _fileName, work) {
    if (!nextLifecycleGate) return work();
    const gate = nextLifecycleGate;
    nextLifecycleGate = null;
    gate.markQueued();
    return gate.released.then(work);
  },
  runCloudFolderLifecycleMutation(_folderId, work) {
    if (!nextLifecycleGate) return work();
    const gate = nextLifecycleGate;
    nextLifecycleGate = null;
    gate.markQueued();
    return gate.released.then(work);
  },
  rootFolderId: "root",
  serializeTrashItemForUser(item) { return item; },
  trashRepository,
  trashService,
});

function item(id, { deletedBy = "tester" } = {}) {
  const trashPath = path.join("files", id, "item.txt");
  const absolute = path.join(runtime, "data", "trash", trashPath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, "disposable");
  const value = {
    id,
    itemType: "file",
    originalFolderId: "root",
    originalFileName: "item.txt",
    trashPath,
    deletedBy,
    deletedAt: new Date().toISOString(),
    metadata: {},
    restoreMetadata: { versions: { versions: [] } },
    status: "trashed",
  };
  return trashRepository.saveTrashItem(value);
}

function response() {
  const result = {};
  return {
    result,
    get headersSent() { return Object.hasOwn(result, "body"); },
    status(code) { result.status = code; return this; },
    json(body) { result.body = body; return this; },
  };
}

function request(id) {
  return { params: { id }, user: { username: "tester", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 1 } };
}

test("DELETE /trash/:id reports the reloaded retry state after provider failure", async () => {
  const id = "11111111-1111-4111-8111-111111111111";
  item(id);
  const original = trashService.processRemoteDeletion;
  trashService.processRemoteDeletion = async ({ item: queued }) => trashService.failRemoteDeletion(queued, new Error("provider"));
  const res = response();
  try { await routes[`DELETE /trash/:id`](request(id), res); } finally { trashService.processRemoteDeletion = original; }
  assert.equal(res.result.status, undefined);
  assert.equal(res.result.body.remoteDeletion, "retry_wait");
  assert.equal(trashRepository.getTrashItem(id).metadata.remoteDeletion.state, "retry_wait");
  assert.equal(audits.some((event) => event[0] === "trash.remote_delete.failed"), false);
  assert.equal(broadcasts.at(-1)[1].action, "remote_delete_pending");
});

test("DELETE /trash/:id never reports completion when completion persistence fails", async () => {
  const id = "22222222-2222-4222-8222-222222222222";
  item(id);
  const originalSave = trashRepository.saveTrashItem;
  trashRepository.saveTrashItem = (value) => {
    if (value.metadata?.remoteDeletion?.state === "completed") throw new Error("completion persistence");
    return originalSave(value);
  };
  const res = response();
  try { await routes[`DELETE /trash/:id`](request(id), res); } finally { trashRepository.saveTrashItem = originalSave; }
  assert.equal(res.result.status, undefined);
  assert.equal(res.result.body.remoteDeletion, "retry_wait");
  assert.notEqual(res.result.body.remoteDeletion, "completed");
  assert.equal(broadcasts.at(-1)[1].action, "remote_delete_pending");
  assert.equal(audits.some((event) => event[0] === "trash.remote_delete.completed"), false);
});

test("DELETE /trash/:id returns generic 500 when persisted state cannot be reloaded", async () => {
  const id = "33333333-3333-4333-8333-333333333333";
  item(id);
  const originalGet = trashRepository.getTrashItem;
  let reads = 0;
  trashRepository.getTrashItem = (...args) => {
    reads += 1;
    if (reads > 1) throw new Error("repository unavailable");
    return originalGet(...args);
  };
  const res = response();
  try { await routes[`DELETE /trash/:id`](request(id), res); } finally { trashRepository.getTrashItem = originalGet; }
  assert.equal(res.result.status, 500);
  assert.deepEqual(res.result.body, { error: "Erro de persistencia da lixeira" });
  assert.equal(audits.some((event) => event[0] === "trash.remote_delete.completed"), false);
});

function lifecycleGate() {
  let markQueued;
  let release;
  return {
    queued: new Promise((resolve) => { markQueued = resolve; }),
    released: new Promise((resolve) => { release = resolve; }),
    markQueued,
    release,
  };
}

test("DELETE /trash/:id rechecks manager authorization after waiting for the lifecycle lock", async () => {
  const id = "44444444-4444-4444-8444-444444444444";
  item(id);
  trashManagerStillAuthorized = true;
  const gate = lifecycleGate();
  nextLifecycleGate = gate;
  const res = response();
  const deleting = routes["DELETE /trash/:id"](request(id), res);
  await gate.queued;
  trashManagerStillAuthorized = false;
  gate.release();
  await deleting;
  assert.equal(res.result.status, 403);
  assert.equal(trashRepository.getTrashItem(id).status, "trashed");
});

test("DELETE /trash stops its batch when manager authorization is revoked while waiting", async () => {
  const firstId = "55555555-5555-4555-8555-555555555555";
  const secondId = "66666666-6666-4666-8666-666666666666";
  item(firstId);
  item(secondId);
  trashManagerStillAuthorized = true;
  const gate = lifecycleGate();
  nextLifecycleGate = gate;
  const req = { body: { confirmation: "DELETE" }, user: { username: "tester" } };
  const res = response();
  const deleting = routes["DELETE /trash"](req, res);
  await gate.queued;
  trashManagerStillAuthorized = false;
  gate.release();
  await deleting;
  assert.equal(res.result.status, 403);
  assert.equal(trashRepository.getTrashItem(firstId).status, "trashed");
  assert.equal(trashRepository.getTrashItem(secondId).status, "trashed");
});

test("POST /trash/:id/restore uses current permissions after waiting for the lifecycle lock", async () => {
  const id = "77777777-7777-4777-8777-777777777777";
  item(id, { deletedBy: "former-manager" });
  restoreSession = { username: "tester", role: "admin", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 1 };
  const gate = lifecycleGate();
  nextLifecycleGate = gate;
  let restoreCalls = 0;
  const originalRestoreFile = trashService.restoreFile;
  trashService.restoreFile = (input) => { restoreCalls += 1; return input.item; };
  const res = response();
  const req = request(id);
  try {
    const restoring = routes["POST /trash/:id/restore"](req, res);
    await gate.queued;
    restoreSession = { username: "tester", role: "user", permissions: { manageTrash: false, listFiles: true }, sessionVersion: 1 };
    gate.release();
    await restoring;
    assert.equal(res.result.status, 403);
    assert.equal(restoreCalls, 0);
    assert.equal(trashRepository.getTrashItem(id).status, "trashed");
  } finally {
    trashService.restoreFile = originalRestoreFile;
    restoreSession = { username: "tester", role: "admin", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 1 };
    if (!res.result.body) gate.release();
  }
});

test("POST /trash/:id/restore rechecks listFiles after waiting even when the user owns the item", async () => {
  const id = "99999999-9999-4999-8999-999999999999";
  item(id);
  restoreSession = { username: "tester", role: "admin", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 1 };
  const gate = lifecycleGate();
  nextLifecycleGate = gate;
  let restoreCalls = 0;
  const originalRestoreFile = trashService.restoreFile;
  trashService.restoreFile = (input) => { restoreCalls += 1; return input.item; };
  const res = response();
  try {
    const restoring = routes["POST /trash/:id/restore"](request(id), res);
    await gate.queued;
    restoreSession = { username: "tester", role: "user", permissions: { manageTrash: false, listFiles: false }, sessionVersion: 1 };
    gate.release();
    await restoring;
    assert.equal(res.result.status, 403);
    assert.equal(res.result.body.error, "Permissao negada: listFiles");
    assert.equal(restoreCalls, 0);
    assert.equal(trashRepository.getTrashItem(id).status, "trashed");
  } finally {
    trashService.restoreFile = originalRestoreFile;
    restoreSession = { username: "tester", role: "admin", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 1 };
    if (!res.result.body) gate.release();
  }
});
test("POST /trash/:id/restore rejects a session revoked while waiting for the lifecycle lock", async () => {
  const id = "88888888-8888-4888-8888-888888888888";
  item(id, { deletedBy: "former-manager" });
  restoreSession = { username: "tester", role: "admin", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 1 };
  const gate = lifecycleGate();
  nextLifecycleGate = gate;
  let restoreCalls = 0;
  const originalRestoreFile = trashService.restoreFile;
  trashService.restoreFile = (input) => { restoreCalls += 1; return input.item; };
  const res = response();
  try {
    const restoring = routes["POST /trash/:id/restore"](request(id), res);
    await gate.queued;
    restoreSession = { username: "tester", role: "admin", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 2 };
    gate.release();
    await restoring;
    assert.equal(res.result.status, 401);
    assert.equal(restoreCalls, 0);
    assert.equal(trashRepository.getTrashItem(id).status, "trashed");
  } finally {
    trashService.restoreFile = originalRestoreFile;
    restoreSession = { username: "tester", role: "admin", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 1 };
    if (!res.result.body) gate.release();
  }
});
test.after(() => {
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
