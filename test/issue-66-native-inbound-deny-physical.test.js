"use strict";

// Opt-in physical negative test: native-required inbound writes must stop
// before any path-based publication. This is NOT a positive RootSession test.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");

const physical = process.env.ROOTARK_ISSUE66_S0_NATIVE_DENY_PHYSICAL === "1"
  && ["win32", "linux"].includes(process.platform);

async function checkPhysicalFilesystem(root) {
  assert.match(process.version, /^v22\./, "physical gate requires Node 22");
  if (process.platform === "linux") {
    assert.equal((await fs.statfs(root)).type, 0xef53,
      "positive physical evidence must use ext4, not DrvFS or another mount");
    return;
  }
  const drive = path.parse(root).root[0];
  assert.match(drive, /^[A-Za-z]$/);
  const inspected = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
    `(Get-Volume -DriveLetter ${drive}).FileSystem`], { windowsHide: true, encoding: "utf8", timeout: 10000 });
  assert.equal(inspected.status, 0, "Windows volume interrogation failed");
  assert.equal(inspected.stdout.trim().toUpperCase(), "NTFS",
    "positive physical evidence must use a real NTFS volume");
}

async function signedCreate(relativePath = "docs/restore.txt") {
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const body = Buffer.from("SIGNED_REMOTE_RECOVERY_PAYLOAD");
  const operation = protocol.createOperation({
    operation: "create", objectId: `object-${crypto.randomUUID()}`,
    fileId: `file-${crypto.randomUUID()}`, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    baseRevision: null, metadata: { path: relativePath, name: path.posix.basename(relativePath),
      size: body.length }, plaintext: body, fileKey: key,
  });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 60_000,
  });
  const { ciphertext, nonce, tag, aad, authorization, ...metadataOnly } = operation;
  return { operation, key, trusted, metadataOnly, body };
}

function syncOptions(rootDir, adapter, signed, extra = {}) {
  return {
    rootDir, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => signed.key,
    selectedPaths: ["docs"], requireAuthorization: true,
    verifyIncoming: (op) => verifyAuthorizationProof(op.authorization, op, signed.trusted),
    ...extra,
  };
}

async function optionalFileBytes(filename) {
  try { return await fs.readFile(filename); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
}

test("#66 S0 physical: signed FOD inbound apply denies late same-principal foreign inode before JS publication",
  { skip: !physical, timeout: 30000 }, async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-s0-deny-"));
    await checkPhysicalFilesystem(root);
    const docs = path.join(root, "docs");
    await fs.mkdir(docs);
    const target = path.join(docs, "restore.txt");
    const signed = await signedCreate();
    const foreignBytes = Buffer.from("FOREIGN_SAME_PRINCIPAL_CANARY_DO_NOT_REPLACE");
    let foreignHandle = null;
    let listReads = 0;
    let signedChecks = 0;
    let pushes = 0;
    let nativeSpoofTraps = 0;
    const forgedNativeRoot = new Proxy({}, {
      get() { nativeSpoofTraps++; throw Error("FORGED_NATIVE_ROOT_READ"); },
      ownKeys() { nativeSpoofTraps++; throw Error("FORGED_NATIVE_ROOT_ENUM"); },
    });
    const adapter = {
      async listInventory() {
        return { protocolVersion: 2, view: "metadata", objects: [signed.metadataOnly], nextCursor: null };
      },
      async list(objectId) {
        listReads++;
        assert.equal(objectId, signed.operation.objectId);
        return signed.operation;
      },
      async push() { pushes++; throw Error("OUTBOUND_WRITE_NOT_AUTHORIZED"); },
    };
    const client = await new SyncEngine(syncOptions(root, adapter, signed, {
      filesOnDemand: true, nativeRootSession: forgedNativeRoot,
      verifyIncoming: async (operation) => {
        signedChecks++;
        const verified = await verifyAuthorizationProof(operation.authorization, operation, signed.trusted);
        // After authentic Ed25519 verification but before journal admission,
        // a second real OS process of the same principal creates and fsyncs
        // the foreign leaf. Retain its opened inode in the parent process.
        if (verified && !foreignHandle) {
          const injector = String.raw`
            const fs = require('node:fs');
            const dest = process.argv[1];
            const content = Buffer.from(process.argv[2], 'base64');
            const fd = fs.openSync(dest, 'wx', 0o600);
            try { fs.writeSync(fd, content); fs.fsyncSync(fd); }
            finally { fs.closeSync(fd); }
          `;
          const planted = spawnSync(process.execPath,
            ["-e", injector, target, foreignBytes.toString("base64")],
            { windowsHide: true, encoding: "utf8", timeout: 10000 });
          assert.equal(planted.status, 0, planted.stderr ||
            "independent same-principal writer failed to fsync the foreign inode");
          foreignHandle = await fs.open(target, "r");
        }
        return verified;
      },
    })).open();
    assert.equal(client.requireNativeRootRecovery, true);
    const browse = await client.browseRemoteInventory();
    assert.equal(browse.objects.length, 1);
    assert.equal(browse.objects[0].selectedOnDevice, true);
    const beforeSnapshot = await fs.readFile(client.snapshotPath);
    const beforeJournal = await optionalFileBytes(client.journal.filePath);
    const originalRename = fs.rename;
    const originalLink = fs.link;
    const originalOpen = fs.open;
    let unsafeMutationAttempts = 0;
    let tempCreates = 0;
    const sameTarget = (value) => process.platform === "win32"
      ? path.resolve(String(value)).toLowerCase() === target.toLowerCase()
      : path.resolve(String(value)) === target;
    fs.rename = async (source, destination, ...rest) => {
      if (sameTarget(source) || sameTarget(destination)) {
        unsafeMutationAttempts++;
        throw Object.assign(Error("Disallowed legacy rename with foreign inode"),
          { code: "INSECURE_RENAME_INTERCEPTED" });
      }
      return originalRename(source, destination, ...rest);
    };
    fs.link = async (source, destination, ...rest) => {
      if (sameTarget(destination)) {
        unsafeMutationAttempts++;
        throw Object.assign(Error("Disallowed JS link to mutable foreign destination"),
          { code: "INSECURE_LINK_INTERCEPTED" });
      }
      return originalLink(source, destination, ...rest);
    };
    fs.open = async (filename, flags, ...rest) => {
      if (String(filename).includes(".tmp-inbound-")) tempCreates++;
      return originalOpen(filename, flags, ...rest);
    };
    let error;
    const downloaded = await adapter.list(signed.operation.objectId);
    try { await client.apply(downloaded); }
    catch (caught) { error = caught; }
    finally {
      fs.rename = originalRename;
      fs.link = originalLink;
      fs.open = originalOpen;
    }
    assert.equal(listReads, 1, "the signed remote envelope must actually be fetched");
    assert.equal(signedChecks, 1, "the genuine Ed25519 proof must be checked");
    assert.ok(foreignHandle, "the late foreign file must have been created physically");
    try {
      const opened = await foreignHandle.stat({ bigint: true });
      const named = await fs.lstat(target, { bigint: true });
      assert.equal(opened.ino, named.ino, "the same physical foreign inode must remain named");
      assert.equal(opened.dev, named.dev);
      // Consume the canary only through the SAME retained foreign descriptor.
      // A fresh pathname read after lstat could follow a substituted inode.
      const originalCanary = Buffer.alloc(foreignBytes.length + 1);
      const { bytesRead } = await foreignHandle.read(
        originalCanary, 0, originalCanary.length, 0);
      assert.equal(bytesRead, foreignBytes.length);
      assert.deepEqual(originalCanary.subarray(0, bytesRead), foreignBytes);
      assert.equal(unsafeMutationAttempts, 0,
        "the S0 denial must occur before ANY legacy rename/link, including stageExisting");
      assert.equal(tempCreates, 0, "S0 denial must not create a speculative inbound temp");
      assert.equal(error?.code, "root_session_native_unavailable",
        "no native owner custody exists; signed hydration must fail closed");
      assert.deepEqual(await fs.readdir(docs), ["restore.txt"]);
      assert.deepEqual(await fs.readFile(client.snapshotPath), beforeSnapshot);
      assert.deepEqual(await optionalFileBytes(client.journal.filePath), beforeJournal,
        "S0 denial must precede journal.observeAdmission");
      assert.equal(pushes, 0);
      assert.equal(nativeSpoofTraps, 0, "caller-supplied fake native objects must stay inert");
      assert.equal((await client.browseRemoteInventory()).objects.length, 1,
        "advisory browsing stays available after a failed hydration");
    } finally { await foreignHandle.close(); }
    // The disposable scratch and its foreign canary are intentionally retained
    // for physical review. A mutable-path rm would be unsafe under a real race.
  });

test("#66 S0 physical: signed legacy non-FOD inbound CREATE remains operational",
  { skip: !physical, timeout: 30000 }, async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-s0-legacy-"));
    await checkPhysicalFilesystem(root);
    const signed = await signedCreate("docs/legacy.txt");
    let pushes = 0;
    const adapter = {
      async list() { return []; },
      async push() { pushes++; throw Error("OUTBOUND_WRITE_NOT_AUTHORIZED"); },
    };
    const client = await new SyncEngine(syncOptions(root, adapter, signed)).open();
    assert.equal(client.requireNativeRootRecovery, false);
    await client.apply(signed.operation);
    assert.deepEqual(await fs.readFile(path.join(root, "docs", "legacy.txt")), signed.body);
    assert.equal(pushes, 0);
  });

test("#66 S0 physical: signed full-envelope FOD materializeRemote still reads, then denies before mutation",
  { skip: !physical, timeout: 30000 }, async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-s0-hydrate-"));
    await checkPhysicalFilesystem(root);
    await fs.mkdir(path.join(root, "docs"));
    const signed = await signedCreate();
    const { ciphertext, nonce, tag, aad, authorization, ...metadataOnly } = signed.operation;
    let fullReads = 0;
    let signaturesVerified = 0;
    let pushes = 0;
    const adapter = {
      async listInventory() {
        return { protocolVersion: 2, view: "metadata", objects: [metadataOnly], nextCursor: null };
      },
      async list(objectId) {
        fullReads++;
        assert.equal(objectId, signed.operation.objectId);
        return signed.operation;
      },
      async push() { pushes++; throw Error("OUTBOUND_WRITE_NOT_AUTHORIZED"); },
    };
    const client = await new SyncEngine(syncOptions(root, adapter, signed, {
      filesOnDemand: true,
      verifyIncoming: async (operation) => {
        const valid = await verifyAuthorizationProof(operation.authorization, operation, signed.trusted);
        if (valid) signaturesVerified++;
        return valid;
      },
    })).open();
    const snapshotBefore = await fs.readFile(client.snapshotPath);
    const journalBefore = await optionalFileBytes(client.journal.filePath);
    await assert.rejects(client.materializeRemote("docs/restore.txt"),
      { code: "root_session_native_unavailable" });
    assert.equal(fullReads, 1, "the real full signed envelope must be fetched by the hydration API");
    assert.equal(signaturesVerified, 1, "native denial follows actual Ed25519 verification");
    assert.deepEqual(await fs.readdir(path.join(root, "docs")), [],
      "there must be no inbound payload or reserved temporary file");
    assert.deepEqual(await fs.readFile(client.snapshotPath), snapshotBefore);
    assert.deepEqual(await optionalFileBytes(client.journal.filePath), journalBefore);
    assert.equal(pushes, 0);
    assert.equal((await client.browseRemoteInventory()).objects.length, 1,
      "the read-only advisory picker remains available");
  });

test("#66 S0 physical: explicit native-required mode denies signed ingress without the FOD toggle",
  { skip: !physical, timeout: 30000 }, async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-s0-explicit-"));
    await checkPhysicalFilesystem(root);
    const signed = await signedCreate();
    const adapter = { async list() { return []; }, async push() { throw Error("PUSH_NOT_ALLOWED"); } };
    const client = await new SyncEngine(syncOptions(root, adapter, signed,
      { requireNativeRootRecovery: true })).open();
    assert.equal(client.filesOnDemand, false);
    assert.equal(client.requireNativeRootRecovery, true);
    const snapshotBefore = await fs.readFile(client.snapshotPath);
    const journalBefore = await optionalFileBytes(client.journal.filePath);
    await assert.rejects(client.apply(signed.operation), { code: "root_session_native_unavailable" });
    assert.equal(await optionalFileBytes(path.join(root, "docs", "restore.txt")), null);
    assert.deepEqual(await fs.readFile(client.snapshotPath), snapshotBefore);
    assert.deepEqual(await optionalFileBytes(client.journal.filePath), journalBefore);
  });
