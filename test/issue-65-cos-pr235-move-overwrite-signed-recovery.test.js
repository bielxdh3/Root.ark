"use strict";

// TEST_UNRUN: NODE_COUNT=61, exclusive Node22 window CLOSED.
// W217 deliberately separates two very different boundaries:
// (1) REAL protected HTTP overwriting MOVE fails closed with 503 BEFORE
//     translation, local physical mutation, or journal admission because the
//     remote SyncEngine sends DELETE and MOVE in separate transactions.
// (2) DIRECT enqueueProtocol() and deliberately constructed physical recovery
//     fixtures test LOCAL fsync-backed batch/receipt and historical replay
//     invariants. These do NOT establish remote atomic DELETE+MOVE CAS.
// No power-loss, remote transaction, or real HTTP overwrite is simulated.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-move-overwrite-only";
const SOURCE_BYTES = Buffer.from("SIGNED_MOVE_SOURCE_PAYLOAD_".repeat(21));
const OLD_DESTINATION = Buffer.from("DIFFERENT_PREEXISTING_DESTINATION_BYTES".repeat(12));
const TIMEOUT = 150_000;
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const exact = (value) => JSON.parse(protocol.canonicalJson(value));

function idFor(event, verb, destination = "target.txt") {
  return "webdav-" + event.operationId + "-" +
    sha(verb + ":" + destination).slice(0, 24);
}

async function request(port, method, pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1", port, method, path: pathname, agent: false,
      headers: { authorization: "Bearer " + TOKEN, ...headers },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.once("error", reject);
      res.once("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.setTimeout(45_000, () => req.destroy(new Error("real WebDAV HTTP timeout")));
    req.once("error", reject);
    req.end();
  });
}

function inode(stat) {
  assert.ok(stat.ino > 0n && stat.dev >= 0n);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.nlink, 1n);
  return { dev: String(stat.dev), ino: String(stat.ino), type: "file" };
}

async function fixture(t, mode = "atomic", sourceBytes = SOURCE_BYTES) {
  const parent = createPrivateAuthorityFixture("cos-pr235-overwrite-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const source = path.join(root, "source.txt");
  const destination = path.join(root, "target.txt");
  await fsp.writeFile(source, sourceBytes, { flag: "wx", mode: 0o600 });
  await fsp.writeFile(destination, OLD_DESTINATION, { flag: "wx", mode: 0o600 });
  const sourceWitness = inode(await fsp.lstat(source, { bigint: true }));
  const oldDestinationWitness = inode(await fsp.lstat(destination, { bigint: true }));
  const localPath = path.join(parent, "local.json");
  const outboxPath = path.join(parent, "outbox.json");
  const key = crypto.randomBytes(32);
  const signing = crypto.generateKeyPairSync("ed25519");
  const publicKey = signing.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const events = [];
  const operations = [];
  const state = { mode, current: null, mutation: null, outbox: null,
    revoked: false, policyChecks: 0, translations: 0, keyResolutions: 0,
    ignoreTranslation: false };
  t.after(async () => {
    if (state.current) await state.current.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });

  async function sign(event, verb, { id = idFor(event, verb), sourcePath = "source.txt",
    destinationPath = "target.txt", plaintext = sourceBytes } = {}) {
    assert.equal(event.kind, "move");
    assert.equal(event.journalType, "webdav-mutation");
    assert.match(event.operationId, /^[0-9a-f-]{36}$/i,
      "signature must be bound to the exact generated fixture mutation ID");
    const op = protocol.createOperation({
      operation: verb, operationId: id,
      objectId: "overwrite-" + verb, fileId: "overwrite-" + verb,
      versionId: crypto.randomUUID(), deviceId: "device-a",
      keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: verb === "delete" ? 2 : 3, deviceId: "device-a" },
      metadata: { path: destinationPath, ...(verb === "move" ? { sourcePath } : {}) },
      plaintext: verb === "move" ? protocol.encodeMovePayload(plaintext, key) : Buffer.alloc(0),
      fileKey: key,
    });
    op.authorization = await createAuthorizationProof(op, {
      username: "alice", privateKey: signing.privateKey, publicKey,
      expiresAt: Date.now() + 180_000,
    });
    assert.equal(await verifyAuthorizationProof(op.authorization, op, {
      username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: [],
    }), true, "each tested envelope must have authentic pinned Ed25519 authorization");
    return op;
  }

  async function translate(event) {
    state.translations += 1;
    events.push(exact(event));
    const move = await sign(event, "move");
    const del = await sign(event, "delete");
    operations.push({ move, del });
    if (state.mode === "lone") return move;
    if (state.mode === "missing") return [move];
    if (state.mode === "reverse") return [move, del];
    // Preserve the correct DELETE->MOVE prefix: only the third, independently
    // signed extra tombstone should cause cardinality rejection.
    if (state.mode === "extra") return [del, move, await sign(event, "delete")];
    if (state.mode === "wrong-id") return [move, await sign(event, "delete", {
      id: "unrelated-" + crypto.randomUUID(),
    })];
    if (state.mode === "wrong-path") return [move, await sign(event, "delete", {
      destinationPath: "other.txt", id: idFor(event, "delete", "other.txt"),
    })];
    return [del, move];
  }
  const policy = () => {
    state.policyChecks += 1;
    return {
      username: "alice",
      trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: state.revoked ? ["device-a"] : [],
    };
  };
  async function newBridge(local, outbox) {
    return new LocalSyncWebDavBridge({
      rootDir: root, token: TOKEN, journal: local, protocolJournal: outbox,
      requireSignedProtocolIngress: true,
      trustedProtocolPolicy: policy,
      resolveProtectedFileKey: async (op) => {
        state.keyResolutions += 1;
        assert.equal(op.fileId, "overwrite-move");
        return key;
      },
      toProtocolOperation: async (event) => {
        if (state.ignoreTranslation) throw new Error("recovery must not mint a new signed batch");
        return translate(event);
      },
    });
  }
  async function start() {
    assert.equal(state.current, null, "must stop previous owner before cold reopen");
    state.mutation = await new SyncJournal(localPath).open();
    state.outbox = await new SyncJournal(outboxPath).open();
    const bridge = await newBridge(state.mutation, state.outbox);
    await bridge.start();
    state.current = bridge;
    return bridge.address().port;
  }
  async function stop() {
    if (state.current) await state.current.stop();
    state.current = null;
  }
  async function reopen() {
    return {
      local: await new SyncJournal(localPath).open(),
      outbox: await new SyncJournal(outboxPath).open(),
    };
  }
  async function moveRequest(port) {
    return request(port, "MOVE", "/source.txt", {
      destination: "http://127.0.0.1:" + port + "/target.txt",
      overwrite: "T",
    });
  }
  async function physical() {
    const snapshot = {};
    for (const [name, filename] of Object.entries({ source, destination })) {
      const stat = await fsp.lstat(filename, { bigint: true }).catch((error) => {
        if (error.code === "ENOENT") return null;
        throw error;
      });
      snapshot[name] = stat ? { identity: inode(stat), bytes: await fsp.readFile(filename) } : null;
    }
    return snapshot;
  }
  return { parent, root, source, destination, sourceBytes,
    sourceWitness, oldDestinationWitness,
    localPath, outboxPath, events, operations, state,
    start, stop, reopen, moveRequest, newBridge, physical, key, publicKey, sign };
}

async function assertAuthenticOutbox(f, pending, signed) {
  assert.equal(pending.length, 2, "LOCAL atomic journal batch must contain precisely two entries");
  assert.equal(signed.length, 2);
  const ids = [idFor(f.events[0], "move"), idFor(f.events[0], "delete")];
  assert.deepEqual(new Set(pending.map((x) => x.operationId)), new Set(ids));
  for (const op of pending) {
    assert.equal(await verifyAuthorizationProof(op.authorization, op, {
      username: "alice", trustedDevicePublicKeys: { "device-a": f.publicKey },
      revokedDeviceIds: [],
    }), true, "disk outbox must retain valid independently verified signature");
    const original = signed.find((value) => value.operationId === op.operationId);
    assert.ok(original, "outbox envelope must be exactly from original signed translation");
    assert.equal(protocol.canonicalJson(op), protocol.canonicalJson(original),
      "further encryption or a different signature cannot silently replace the original");
  }
  const move = pending.find((op) => op.operation === "move");
  assert.ok(move);
  assert.equal(pending[0].operation, "delete",
    "local ordering must place displaced-destination DELETE before MOVE");
  assert.equal(pending[1].operation, "move",
    "a reverse local order is invalid even though remote atomicity remains unavailable");
  assert.deepEqual(protocol.decodeMovePayload(protocol.decryptPayload(move, f.key), f.key),
    f.sourceBytes, "signed MOVE payload must match actual physical source bytes");
  const companion = pending.find((op) => op.operation === "delete");
  assert.ok(companion);
  assert.equal(companion.metadata.path, "target.txt");
  return { ids, move, companion };
}

// Setup intentionally bypasses the HTTP protected-overwrite prohibition ONLY
// in a private TEST fixture. The independently generated mutation journal
// operation is persisted BEFORE staging source/destination physical inodes.
// This is not a request, remote CAS, production entrypoint, or committed
// end-to-end overwrite. It exercises the local receipt/recovery state machine.
async function constructInstalledMoveFixture(f) {
  const operationId = crypto.randomUUID();
  const oldBackup = path.join(f.root, ".rootark-trash",
    ".rootark-move-" + operationId + "-target.txt");
  const event = {
    operationId, kind: "move", journalType: "webdav-mutation",
    source: "/source.txt", destination: "/target.txt",
    trash: path.relative(f.root, oldBackup),
    sourceIdentity: f.sourceWitness,
    previousDestinationIdentity: f.oldDestinationWitness,
    phase: "prepared",
  };
  assert.deepEqual(await f.physical(), {
    source: { identity: f.sourceWitness, bytes: f.sourceBytes },
    destination: { identity: f.oldDestinationWitness, bytes: OLD_DESTINATION },
  });
  await f.state.mutation.enqueue(event); // real fsync-backed prepared record
  const onDiskPrepared = (await f.reopen()).local.pending();
  assert.equal(onDiskPrepared.length, 1);
  assert.equal(onDiskPrepared[0].phase, "prepared");
  await fsp.rename(f.destination, oldBackup);
  await fsp.link(f.source, f.destination);
  await fsp.unlink(f.source);
  await f.state.mutation.update(operationId, { phase: "source-moved" });
  const installed = await f.physical();
  assert.equal(installed.source, null);
  assert.deepEqual(installed.destination.identity, f.sourceWitness);
  assert.deepEqual(installed.destination.bytes, f.sourceBytes);
  assert.deepEqual(await fsp.readFile(oldBackup), OLD_DESTINATION);
  assert.deepEqual(inode(await fsp.lstat(oldBackup, { bigint: true })),
    f.oldDestinationWitness);
  assert.equal((await f.reopen()).local.pending()[0].phase, "source-moved");
  return { event, oldBackup };
}

for (const mode of ["atomic", "lone", "missing", "reverse", "extra", "wrong-id", "wrong-path"]) {
  test("real protected HTTP overwrite fails closed BEFORE " + mode + " translator is called", {
    timeout: TIMEOUT,
  }, async (t) => {
    const f = await fixture(t, mode);
    const beforePhysical = await f.physical();
    const port = await f.start();
    const beforeLocal = await fsp.readFile(f.localPath);
    const beforeOutbox = await fsp.readFile(f.outboxPath);
    const beforePolicyChecks = f.state.policyChecks;
    const reply = await f.moveRequest(port);
    assert.equal(reply.status, 503,
      "remote split DELETE+MOVE cannot be authorized as one HTTP overwrite");
    assert.equal(reply.body.toString(), "Protected overwrite requires atomic remote DELETE+MOVE admission",
      "must reject for the specific remote atomicity barrier, not an unrelated 503");
    assert.equal(f.events.length, 0,
      "HTTP must NOT construct or pass a signed MOVE event to the translator");
    assert.equal(f.operations.length, 0);
    assert.equal(f.state.translations, 0);
    assert.equal(f.state.keyResolutions, 0);
    assert.equal(f.state.policyChecks, beforePolicyChecks);
    assert.deepEqual(await f.physical(), beforePhysical,
      "original source and destination bytes and inodes must remain untouched");
    assert.deepEqual(await fsp.readFile(f.localPath), beforeLocal,
      "HTTP fail-closed gate must not mutate physical journal bytes");
    assert.deepEqual(await fsp.readFile(f.outboxPath), beforeOutbox,
      "HTTP fail-closed gate must not admit ANY signed DELETE or MOVE");
    const { local, outbox } = await f.reopen();
    assert.deepEqual(local.pending(), []);
    assert.deepEqual(outbox.pending(), []);
    assert.deepEqual(await fsp.readdir(path.join(f.root, ".rootark-trash")), []);
    assert.equal((await request(port, "GET", "/source.txt")).status, 200,
      "positive GET controls verify original source remains accessible");
    assert.equal((await request(port, "GET", "/target.txt")).status, 200,
      "positive GET controls verify old destination remains accessible");
  });
}

test("real HTTP Overwrite:F retains normal 412 precondition without translator or filesystem mutation", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  const port = await f.start();
  const physical = await f.physical();
  const local = await fsp.readFile(f.localPath);
  const outbox = await fsp.readFile(f.outboxPath);
  const defaultOverwrite = await request(port, "MOVE", "/source.txt", {
    destination: "http://127.0.0.1:" + port + "/target.txt",
  });
  assert.equal(defaultOverwrite.status, 503,
    "omitted Overwrite header defaults to T but cannot bypass remote atomic gate");
  assert.equal(defaultOverwrite.body.toString(),
    "Protected overwrite requires atomic remote DELETE+MOVE admission");
  const reply = await request(port, "MOVE", "/source.txt", {
    destination: "http://127.0.0.1:" + port + "/target.txt", overwrite: "F",
  });
  assert.equal(reply.status, 412);
  assert.equal(reply.body.toString(), "Destination exists");
  assert.equal(f.state.translations, 0);
  assert.equal(f.state.keyResolutions, 0);
  assert.deepEqual(await f.physical(), physical);
  assert.deepEqual(await fsp.readFile(f.localPath), local);
  assert.deepEqual(await fsp.readFile(f.outboxPath), outbox);
});

for (const mode of ["lone", "missing", "reverse", "extra", "wrong-id", "wrong-path"]) {
  test("DIRECT local enqueueProtocol rejects " + mode + " signed DELETE+MOVE batch without partial outbox", {
    timeout: TIMEOUT,
  }, async (t) => {
    const f = await fixture(t, mode);
    await f.start();
    const { event, oldBackup } = await constructInstalledMoveFixture(f);
    const afterConstructedPhysical = await f.physical();
    const untouchedLocal = (await f.reopen()).local.pending();
    assert.equal(untouchedLocal[0].phase, "source-moved");
    assert.equal((await f.reopen()).outbox.pending().length, 0);
    const noOutbox = await fsp.readFile(f.outboxPath);
    await assert.rejects(f.state.current.enqueueProtocol(event), (error) => {
      assert.equal(error?.code, "authorization_rejected",
        "malformed or incomplete signed LOCAL batch must fail at authorization binding");
      assert.match(error.message,
        /(?:signed|MOVE|atomic|batch|destination|authorization|operation)/i,
        "failure must arise at genuine signed local batch validation");
      return true;
    });
    assert.equal(f.state.translations, 1,
      "DIRECT call must reach actual Ed25519 envelope translator");
    assert.ok(f.operations[0]?.move?.authorization.signature,
      "adversarial batch must contain a real independently signed MOVE");
    assert.deepEqual(await f.physical(), afterConstructedPhysical,
      "DIRECT enqueue failure is not permission to alter constructed physical evidence");
    assert.deepEqual(await fsp.readFile(f.outboxPath), noOutbox,
      "no partial signed DELETE or MOVE must be persisted locally");
    const { local, outbox } = await f.reopen();
    assert.deepEqual(local.pending(), untouchedLocal,
      "source-moved fixture must remain pending, not silently ACKed");
    assert.deepEqual(outbox.pending(), []);
    assert.deepEqual(await fsp.readFile(oldBackup), OLD_DESTINATION);
  });
}

test("DIRECT local enqueueProtocol commits genuine signed DELETE + MOVE as one fsynced local batch, NOT remotely", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t, "atomic");
  await f.start();
  const { event } = await constructInstalledMoveFixture(f);
  assert.equal(await f.state.current.enqueueProtocol(event), true);
  await f.state.mutation.update(event.operationId, { phase: "protocol-queued" });
  assert.equal(f.events.length, 1);
  const after = await f.physical();
  assert.equal(after.source, null);
  assert.deepEqual(after.destination.bytes, f.sourceBytes);
  assert.deepEqual(after.destination.identity, f.sourceWitness,
    "installed MOVE must retain physical source inode");
  const { local, outbox } = await f.reopen();
  assert.equal(local.pending().length, 1,
    "DIRECT enqueue does not ACK the local mutation on its own");
  assert.equal(local.pending()[0].phase, "protocol-queued");
  const { ids } = await assertAuthenticOutbox(f, outbox.pending(),
    Object.values(f.operations[0]));
  assert.deepEqual(new Set(Object.keys(outbox.state.committedSigned)), new Set(ids));
  for (const id of ids) {
    const op = outbox.pending().find((item) => item.operationId === id);
    assert.equal(outbox.durableSignedReceiptDigest(id),
      sha(protocol.canonicalJson(op)));
  }
  await f.stop();
  f.state.revoked = true;
  f.state.ignoreTranslation = true;
  const secondPort = await f.start();
  assert.equal((await request(secondPort, "GET", "/target.txt")).status, 200);
  const restored = await f.reopen();
  assert.deepEqual(restored.local.pending(), []);
  assert.equal(restored.local.hasSeen(event.operationId), true);
  assert.deepEqual(restored.outbox.pending(), outbox.pending(),
    "local replay may ACK its existing batch but MUST NOT claim remote atomicity");
});

async function committedButUnacknowledgedMove(t, phase, sourceBytes = SOURCE_BYTES) {
  const f = await fixture(t, "atomic", sourceBytes);
  await f.start();
  const constructed = await constructInstalledMoveFixture(f);
  assert.equal(await f.state.current.enqueueProtocol(constructed.event), true,
    "DIRECT local admission must fsync both independently signed envelopes");
  // These are deliberately constructed durable recovery phases. No actual
  // protected HTTP overwrite is executed, no remote split transaction is
  // authorized, and no process crash or missing-ACK injection is claimed.
  if (phase === "protocol-queued") {
    await f.state.mutation.update(constructed.event.operationId,
      { phase: "protocol-queued" });
  } else {
    assert.equal(phase, "source-moved");
  }
  assert.equal(f.events.length, 1);
  const current = await f.reopen();
  const entry = current.local.pending()[0];
  assert.ok(entry);
  assert.equal(entry.phase, phase);
  assert.equal(entry.kind, "move");
  assert.deepEqual(entry.sourceIdentity, f.sourceWitness);
  assert.deepEqual(entry.previousDestinationIdentity, f.oldDestinationWitness);
  assert.equal(entry.moveBytes, f.sourceBytes.length,
    "verified signed MOVE plaintext must become a durable recovery length witness");
  assert.equal(entry.moveSha256, sha(f.sourceBytes),
    "verified signed MOVE plaintext must become a durable recovery digest");
  assert.ok(entry.trash);
  const oldBackup = path.resolve(f.root, entry.trash);
  assert.equal(oldBackup, constructed.oldBackup);
  assert.deepEqual(await fsp.readFile(oldBackup), OLD_DESTINATION,
    "successful overwrite must retain genuine displaced destination in private trash");
  assert.deepEqual(inode(await fsp.lstat(oldBackup, { bigint: true })),
    f.oldDestinationWitness);
  assert.equal(fs.existsSync(f.source), false);
  assert.deepEqual(await fsp.readFile(f.destination), f.sourceBytes);
  await assertAuthenticOutbox(f, current.outbox.pending(),
    Object.values(f.operations[0]));
  const pinned = entry.signedOutboxReceipts;
  assert.equal(pinned.length, 2);
  for (const saved of pinned) {
    const signed = current.outbox.pending().find((op) => op.operationId === saved.operationId);
    assert.ok(signed, "both independent signed witness operation IDs must be in outbox");
    assert.equal(saved.digest, sha(protocol.canonicalJson(signed)));
    assert.equal(current.outbox.durableSignedReceiptDigest(saved.operationId),
      saved.digest);
  }
  await f.stop();
  return { f, entry, oldBackup };
}

for (const phase of ["source-moved", "protocol-queued"]) {
  test("DIRECT physical fixture: cold signed local batch " + phase + " replays same-inode bytes once", {
    timeout: TIMEOUT,
  }, async (t) => {
    const { f, entry, oldBackup } = await committedButUnacknowledgedMove(t, phase);
    f.state.revoked = true;
    f.state.ignoreTranslation = true;
    const policyBefore = f.state.policyChecks;
    const translatedBefore = f.state.translations;
    const startedPort = await f.start();
    assert.ok(Number.isInteger(startedPort));
    assert.equal(f.state.policyChecks, policyBefore,
      "historically committed TWO-receipt LOCAL outbox must not reauthorize revoked device");
    assert.equal(f.state.translations, translatedBefore,
      "replay must not re-encrypt, re-sign or enqueue a duplicate");
    const recovered = await f.reopen();
    assert.deepEqual(recovered.local.pending(), []);
    assert.equal(recovered.local.hasSeen(entry.operationId), true);
    assert.equal(recovered.outbox.pending().length, 2);
    assert.deepEqual(await fsp.readFile(f.destination), f.sourceBytes);
    assert.deepEqual(inode(await fsp.lstat(f.destination, { bigint: true })),
      f.sourceWitness);
    assert.deepEqual(await fsp.readFile(oldBackup), OLD_DESTINATION,
      "recovery must not destroy original overwritten target's archived inode");
    await f.stop();
    await f.start();
    const again = await f.reopen();
    assert.deepEqual(again.outbox.pending(), recovered.outbox.pending());
    assert.deepEqual(again.local.pending(), []);
  });

  test("DIRECT physical fixture: signed local batch " + phase + " rejects same-inode content mutation", {
    timeout: TIMEOUT,
  }, async (t) => {
    const { f, entry, oldBackup } = await committedButUnacknowledgedMove(t, phase);
    const beforeStat = await fsp.lstat(f.destination, { bigint: true });
    const changed = Buffer.from(f.sourceBytes);
    changed[0] ^= 0x5a;
    assert.equal(changed.length, f.sourceBytes.length);
    await fsp.writeFile(f.destination, changed);
    const afterStat = await fsp.lstat(f.destination, { bigint: true });
    assert.equal(afterStat.dev, beforeStat.dev);
    assert.equal(afterStat.ino, beforeStat.ino,
      "fault must mutate the SAME inode: rejection cannot be due to inode replacement");
    assert.equal(afterStat.size, beforeStat.size);
    assert.deepEqual(inode(afterStat), f.sourceWitness);
    assert.notEqual(sha(changed), entry.moveSha256);
    assert.deepEqual(await fsp.readFile(f.destination), changed);
    const frozenLocal = await fsp.readFile(f.localPath);
    const frozenOutbox = await fsp.readFile(f.outboxPath);
    const frozenBackup = await fsp.readFile(oldBackup);
    f.state.revoked = true;
    f.state.ignoreTranslation = true;
    const policyBefore = f.state.policyChecks;
    const translatedBefore = f.state.translations;
    await assert.rejects(() => f.start(), {
      code: "WEBDAV_RECOVERY_INDETERMINATE",
    }, "valid inode and signed receipts must NOT conceal changed physical MOVE payload");
    assert.equal(f.state.current, null,
      "failed cold start must not leave an active HTTP listener");
    assert.equal(f.state.policyChecks, policyBefore);
    assert.equal(f.state.translations, translatedBefore);
    assert.deepEqual(await fsp.readFile(f.localPath), frozenLocal,
      "rejected recovery cannot claim a fresh protocol-queued/seen mutation");
    assert.deepEqual(await fsp.readFile(f.outboxPath), frozenOutbox,
      "rejected recovery cannot alter either signed envelope or receipt");
    assert.deepEqual(await fsp.readFile(f.destination), changed,
      "rejected recovery preserves the suspect physical bytes for investigation");
    assert.deepEqual(await fsp.readFile(oldBackup), frozenBackup,
      "rejected recovery preserves the original overwritten destination");
    const reopened = await f.reopen();
    assert.equal(reopened.local.pending()[0].operationId, entry.operationId);
    assert.equal(reopened.local.pending()[0].phase, phase);
    assert.equal(reopened.outbox.pending().length, 2);
  });
}

test("LOCAL-ONLY direct recovery >8 MiB: signed MOVE witness is NOT remote-sync-capable", {
  timeout: TIMEOUT,
}, async (t) => {
  // Contract ONLY: large locally fsynced MOVE evidence can be recovered by
  // the local WebDAV journal implementation. NO protected overwrite HTTP
  // request or remote request is made, and NO remote DELETE+MOVE atomicity,
  // transportability, or sync success is implied by a successful local replay.
  // src/routes/sync.js currently limits request bodies to 9 MiB and decoded
  // ciphertext to 8 MiB. MOVE framing/AES-GCM add overhead and a base64 JSON
  // envelope further enlarges this payload. This fixture deliberately
  // EXCEEDS those limits: it is not presently admissible via that remote API
  // even if a separate atomic remote batch operation becomes available.
  const large = Buffer.alloc(8 * 1024 * 1024 + 257, 0x4d);
  large.set(Buffer.from("AUTHENTICATED_LARGE_MOVE_HEADER"), 0);
  large.set(Buffer.from("AUTHENTICATED_LARGE_MOVE_TAIL"), large.length - 29);
  const { f, entry, oldBackup } =
    await committedButUnacknowledgedMove(t, "protocol-queued", large);
  assert.ok(entry.moveBytes > 8 * 1024 * 1024);
  assert.equal(entry.moveSha256, sha(large));
  const localOutbox = (await f.reopen()).outbox.pending();
  const signedMove = localOutbox.find((operation) => operation.operation === "move");
  assert.ok(signedMove, "locally durable Ed25519 MOVE must be present");
  assert.ok(Buffer.byteLength(signedMove.ciphertext, "base64url") > 8 * 1024 * 1024,
    "signed MOVE exceeds current server MAX_CIPHERTEXT_BYTES; do NOT claim remote sync");
  assert.ok(Buffer.byteLength(JSON.stringify(signedMove), "utf8") > 9 * 1024 * 1024,
    "encoded MOVE alone exceeds current server MAX_REQUEST_BYTES");
  f.state.revoked = true;
  f.state.ignoreTranslation = true;
  const beforePolicy = f.state.policyChecks;
  const beforeTranslation = f.state.translations;
  const port = await f.start();
  assert.ok(Number.isInteger(port));
  assert.equal(f.state.policyChecks, beforePolicy,
    "only existing committed exact-envelope receipts permit replay");
  assert.equal(f.state.translations, beforeTranslation);
  const reopened = await f.reopen();
  assert.deepEqual(reopened.local.pending(), []);
  assert.equal(reopened.local.hasSeen(entry.operationId), true);
  assert.equal(reopened.outbox.pending().length, 2);
  assert.deepEqual(reopened.outbox.pending(), localOutbox,
    "local-only recovery may ACK but must not re-sign or alter outbox evidence");
  assert.equal((await fsp.stat(f.destination)).size, large.length);
  assert.equal(sha(await fsp.readFile(f.destination)), sha(large));
  assert.deepEqual(inode(await fsp.lstat(f.destination, { bigint: true })),
    f.sourceWitness);
  assert.deepEqual(await fsp.readFile(oldBackup), OLD_DESTINATION);
});
