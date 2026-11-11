"use strict";

// NON-CANONICAL security RED laboratory. This file deliberately shows the
// existing vulnerabilities, not that the product is fixed. Run with --test.
// Unlike w21-races.cjs, the competing FS namespace writer is a DIFFERENT
// operating-system process, with independently opened file handles.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const Module = require("node:module");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../../sync-client/rootark-sync-engine");
const { createPrivateAuthorityFixture } =
  require("../../test/support/issue-65-private-authority-fixture");

const childPath = path.join(__dirname, "w21-process-attacker.cjs");
const enginePath = require.resolve("../../sync-client/rootark-sync-engine.js");

function principal() {
  if (process.platform !== "win32") return `uid:${process.getuid()}`;
  const output = childProcess.execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"],
    { encoding: "utf8", windowsHide: true });
  const sid = output.match(/S-1-\d+(?:-\d+)+/i)?.[0];
  if (!sid) throw Error("Cannot attest same Windows SID");
  return sid;
}

function statId(stat) { return [String(stat.dev), String(stat.ino)]; }
function childId(data) { return [String(data.dev), String(data.ino)]; }

async function createAttacker(root) {
  const child = childProcess.fork(childPath, [], {
    execPath: process.execPath, env: { ...process.env }, windowsHide: true,
    stdio: ["ignore", "ignore", "pipe", "ipc"],
  });
  const pending = new Map();
  let nextId = 1;
  const stderr = [];
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 8) stderr.push(String(chunk).slice(0, 512));
  });
  const failPending = (error) => {
    for (const { reject, timer } of pending.values()) {
      clearTimeout(timer);
      reject(error);
    }
    pending.clear();
  };
  child.on("exit", (code) => failPending(new Error(`attacker exited unexpectedly: ${code} ${stderr.join("")}`)));
  child.on("error", failPending);
  child.on("message", (response) => {
    const request = pending.get(response?.id);
    if (!request) return;
    pending.delete(response.id);
    clearTimeout(request.timer);
    if (response.ok) request.resolve(response.result);
    else request.reject(new Error(`attacker error: ${response.error}`));
  });
  const send = (data) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("second-process attacker IPC timeout"));
    }, 20000);
    pending.set(id, { resolve, reject, timer });
    child.send({ id, data }, (error) => {
      if (!error || !pending.has(id)) return;
      const request = pending.get(id);
      pending.delete(id);
      clearTimeout(request.timer);
      reject(error);
    });
  });
  const hello = await send({ command: "hello", root });
  assert.notEqual(hello.pid, process.pid, "real independent child PID is required");
  assert.equal(hello.principal, principal(), "child must have exactly the parent's UID or Windows SID");
  const labels = new Set();
  return {
    pid: hello.pid,
    principal: hello.principal,
    async swap({ from, retained, bytes, label }) {
      const result = await send({ command: "swap", from, retained, bytes, label });
      assert.equal(result.pid, child.pid);
      assert.equal(result.principal, hello.principal);
      labels.add(label);
      return result;
    },
    inspect: (label) => send({ command: "inspect", label }),
    async close() {
      for (const label of labels) {
        try { await send({ command: "release", label }); } catch { /* child may have exited */ }
      }
      if (child.connected) child.disconnect();
      if (child.exitCode == null) child.kill();
    },
  };
}

function disposableRoot(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function originalProgressPublisher() {
  // Expose a private function in a fresh in-memory Module without production
  // file modifications; this is the exact current branch implementation.
  const compiled = new Module(enginePath, module);
  compiled.filename = enginePath;
  compiled.paths = Module._nodeModulePaths(path.dirname(enginePath));
  compiled._compile(fs.readFileSync(enginePath, "utf8")
    + "\nmodule.exports.__w21Lab = createDurableRestoreProgress;\n", enginePath);
  return compiled.exports.__w21Lab;
}

test("POSITIVE second-process: intact fsynced progress publishes its own inode", async (t) => {
  const root = disposableRoot("rootark67-w21-2process-positive-");
  const attacker = await createAttacker(root);
  t.after(async () => { await attacker.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const file = path.join(root, ".rootark-recovery-execution-" + "a".repeat(64) + ".json");
  const payload = { version: 1, planDigest: "a".repeat(64), scope: { test: "positive" }, items: [] };
  await originalProgressPublisher()(file, payload);
  const aliasName = (await fsp.readdir(root)).find((name) => name.startsWith(path.basename(file) + ".tmp-"));
  assert.ok(aliasName);
  assert.deepEqual(statId(await fsp.lstat(file, { bigint: true })),
    statId(await fsp.lstat(path.join(root, aliasName), { bigint: true })));
  assert.equal(await fsp.readFile(file, "utf8"), JSON.stringify(payload) + "\n");
});

test("SECURITY RED independent child: progress publication links foreign inode, not retained fsynced FD", async (t) => {
  const root = disposableRoot("rootark67-w21-2process-progress-");
  const attacker = await createAttacker(root);
  t.after(async () => { await attacker.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const file = path.join(root, ".rootark-recovery-execution-" + "b".repeat(64) + ".json");
  const realLink = fsp.link;
  let chosenFd, retained, entered = false, attested;
  fsp.link = async (from, to, ...rest) => {
    if (to !== file) return realLink(from, to, ...rest);
    entered = true;
    retained = from + ".retained-original";
    chosenFd = await fsp.open(from, "r");
    attested = await attacker.swap({ from, retained, label: "progress",
      bytes: "SYNTHETIC FOREIGN PROGRESS INODE" });
    return realLink(from, to, ...rest); // REAL NTFS/ext4 syscall after child ACK
  };
  try {
    await originalProgressPublisher()(file, {
      version: 1, planDigest: "b".repeat(64), scope: { test: "evil" }, items: [],
    });
  } finally { fsp.link = realLink; }
  try {
    assert.equal(entered, true);
    const original = await chosenFd.stat({ bigint: true });
    const published = await fsp.lstat(file, { bigint: true });
    const foreign = await attacker.inspect("progress");
    assert.notDeepEqual(statId(published), statId(original));
    assert.deepEqual(statId(published), childId(attested));
    assert.deepEqual(statId(published), childId(foreign));
    assert.deepEqual(await chosenFd.readFile(), await fsp.readFile(retained));
    assert.equal(await fsp.readFile(file, "utf8"), foreign.bytes);
    assert.equal(foreign.bytes, "SYNTHETIC FOREIGN PROGRESS INODE");
    console.log("EXPECTED_SECURITY_RED SECOND_PROCESS_PROGRESS_LINK childPidDifferent=true");
  } finally { if (chosenFd) await chosenFd.close(); }
});

test("POSITIVE second-process: stageExisting moves an uncontested original file", async (t) => {
  const root = disposableRoot("rootark67-w21-2process-stage-ok-");
  const attacker = await createAttacker(root);
  t.after(async () => { await attacker.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const engine = Object.create(SyncEngine.prototype);
  engine.rootDir = root;
  const file = path.join(root, "tracked.txt");
  await fsp.writeFile(file, "ORIGINAL CLEAN FILE");
  const original = await fsp.lstat(file, { bigint: true });
  const staged = await engine.stageExisting(file);
  assert.deepEqual(statId(await fsp.lstat(staged, { bigint: true })), statId(original));
  assert.equal(await fsp.readFile(staged, "utf8"), "ORIGINAL CLEAN FILE");
  assert.equal(fs.existsSync(file), false);
});

test("SECURITY RED independent child: stageExisting renames foreign inode, not original selected FD", async (t) => {
  const root = disposableRoot("rootark67-w21-2process-stage-");
  const attacker = await createAttacker(root);
  t.after(async () => { await attacker.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const engine = Object.create(SyncEngine.prototype);
  engine.rootDir = root;
  const file = path.join(root, "tracked.txt");
  await fsp.writeFile(file, "OWNER CLEAN SOURCE");
  const realRename = fsp.rename;
  let ownerFd, retained, attested, entered = false;
  fsp.rename = async (from, to, ...rest) => {
    if (from !== file || !to.includes(".rootark-trash")) return realRename(from, to, ...rest);
    entered = true;
    retained = path.join(root, "owner-source.retained");
    ownerFd = await fsp.open(file, "r");
    attested = await attacker.swap({ from, retained, label: "stage", bytes: "SYNTHETIC FOREIGN STAGED INODE" });
    return realRename(from, to, ...rest);
  };
  let staged;
  try { staged = await engine.stageExisting(file); }
  finally { fsp.rename = realRename; }
  try {
    assert.equal(entered, true);
    const original = await ownerFd.stat({ bigint: true });
    const actual = await fsp.lstat(staged, { bigint: true });
    const foreign = await attacker.inspect("stage");
    assert.notDeepEqual(statId(actual), statId(original));
    assert.deepEqual(statId(actual), childId(attested));
    assert.deepEqual(statId(actual), childId(foreign));
    assert.equal(foreign.bytes, "SYNTHETIC FOREIGN STAGED INODE");
    assert.equal(await fsp.readFile(staged, "utf8"), foreign.bytes);
    assert.deepEqual(await ownerFd.readFile(), await fsp.readFile(retained));
    console.log("EXPECTED_SECURITY_RED SECOND_PROCESS_STAGE_RENAME childPidDifferent=true");
  } finally { if (ownerFd) await ownerFd.close(); }
});

async function signedRestoreFixture() {
  const root = createPrivateAuthorityFixture("rootark67-w21-2process-signed-");
  const local = path.join(root, "client");
  await fsp.mkdir(local);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicSpki = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const fileKey = crypto.randomBytes(32);
  const policy = { username: "alice", trustedDevicePublicKeys: { "device-a": publicSpki },
    revokedDeviceIds: [] };
  const signed = async (input) => {
    const op = protocol.createOperation({ objectId: "file-1", fileId: "file-1",
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      fileKey, ...input });
    return { ...op, authorization: await createAuthorizationProof(op,
      { username: "alice", publicKey: publicSpki, privateKey }) };
  };
  const original = await signed({ operation: "create", versionId: "first",
    operationId: "first-op", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "document.txt" }, plaintext: Buffer.from("SIGNED AUTHENTIC RESTORED BYTES") });
  const deleted = await signed({ operation: "delete", versionId: "deleted",
    operationId: "delete-op", revision: { counter: 2, deviceId: "device-a" },
    baseRevision: original.revision, metadata: { path: "document.txt" } });
  let head = deleted, pushes = 0;
  const adapter = {
    history: async () => ({ protocolVersion: 2, versions: structuredClone([original, deleted]) }),
    list: async () => structuredClone(head),
    push: async (op) => {
      pushes++;
      assert.equal(await verifyAuthorizationProof(op.authorization, op, policy), true);
      head = structuredClone(op);
      return structuredClone(head);
    },
  };
  const engine = await new SyncEngine({
    rootDir: local, adapter, deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => fileKey,
    requireAuthorization: true, authorize: () => true, authorizeOutgoing: () => true,
    verifyIncoming: (op) => verifyAuthorizationProof(op.authorization, op, policy),
    authorizationFactory: (op) => createAuthorizationProof(op,
      { username: "alice", privateKey, publicKey: publicSpki }),
  }).open();
  return { root, local, engine, pushes: () => pushes };
}

test("POSITIVE second-process: genuine signed history restores and pushes authenticated bytes", async (t) => {
  const f = await signedRestoreFixture();
  const attacker = await createAttacker(f.root);
  t.after(async () => { await attacker.close(); fs.rmSync(f.root, { recursive: true, force: true }); });
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.restored, true);
  assert.equal(result.pushed, true);
  assert.equal(f.pushes(), 1);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
    "SIGNED AUTHENTIC RESTORED BYTES");
});

test("SECURITY RED independent child: _apply publishes swapped inode locally but NEVER pushes remotely", async (t) => {
  const f = await signedRestoreFixture();
  const attacker = await createAttacker(f.root);
  t.after(async () => { await attacker.close(); fs.rmSync(f.root, { recursive: true, force: true }); });
  const final = path.join(f.local, "document.txt");
  const realLink = fsp.link;
  let cleanFd, retained, attested, entered = false;
  fsp.link = async (from, to, ...rest) => {
    if (to !== final || !from.includes(".tmp-")) return realLink(from, to, ...rest);
    entered = true;
    retained = from + ".retained-owner";
    cleanFd = await fsp.open(from, "r");
    attested = await attacker.swap({ from, retained, label: "apply",
      bytes: "SYNTHETIC FOREIGN RESTORE CONTENT" });
    return realLink(from, to, ...rest);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_materialization_missing");
  } finally { fsp.link = realLink; }
  try {
    assert.equal(entered, true);
    const local = await fsp.lstat(final, { bigint: true });
    const real = await cleanFd.stat({ bigint: true });
    const foreign = await attacker.inspect("apply");
    assert.deepEqual(statId(local), childId(foreign));
    assert.deepEqual(statId(local), childId(attested));
    assert.notDeepEqual(statId(local), statId(real));
    assert.equal(await fsp.readFile(final, "utf8"), foreign.bytes);
    assert.equal(foreign.bytes, "SYNTHETIC FOREIGN RESTORE CONTENT");
    assert.equal(await fsp.readFile(retained, "utf8"), "SIGNED AUTHENTIC RESTORED BYTES");
    assert.equal(f.pushes(), 0, "existing outbound signed SHA gate must block remote dispatch");
    console.log("EXPECTED_SECURITY_RED SECOND_PROCESS_APPLY_LINK_REMOTE_BLOCKED childPidDifferent=true");
  } finally { if (cleanFd) await cleanFd.close(); }
});
