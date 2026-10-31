"use strict";

// TEST_UNRUN: exclusive Node22 gate remains closed while NODE_COUNT > 0.
// This tests an explicitly configured, opt-in protected LocalSyncWebDavBridge.
// It does NOT prove that any production entrypoint enables protected WebDAV
// or that remote device revocation is atomically fenced.
// Each real HTTP event gets its own Ed25519-signed, AES-GCM-encrypted operation
// derived from the ACTUAL mutation ID/path. Authorized bytes come from an
// independent test manifest, never the caller's incoming HTTP body.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-signed-http-durable-e2e-only";
const BYTES = Buffer.from("AUTHORIZED_HTTP_PAYLOAD_".repeat(32));
const TIMEOUT = 120_000;
function sha(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function boundId(event, verb, relative) {
  const prefix = (event.kind === "delete" && verb === "delete")
    || (event.kind === "move" && verb === "move" && !event.previousDestinationIdentity)
    ? "webdavsolo" : "webdav";
  return prefix + "-" + event.operationId + "-" + sha(verb + ":" + relative).slice(0, 24);
}
function relative(value) {
  assert.match(value, /^\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/);
  assert.ok(!value.slice(1).split("/").some((part) => !part || part === "." || part === ".."));
  return value.slice(1);
}
function request(port, method, pathname, body = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const bytes = body === null ? null : Buffer.from(body);
    const req = http.request({
      host: "127.0.0.1", port, method, path: pathname, agent: false,
      headers: {
        authorization: "Bearer " + TOKEN,
        ...(bytes === null ? {} : { "content-length": bytes.length }),
        ...extraHeaders,
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.once("error", reject);
      res.once("end", () => resolve({
        status: res.statusCode, body: Buffer.concat(chunks),
      }));
    });
    req.setTimeout(20_000, () => req.destroy(new Error("HTTP request timed out")));
    req.once("error", reject);
    req.end(bytes ?? undefined);
  });
}
function deadline(promise, ms = 20_000) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("Protected test barrier timed out")), ms);
  })]).finally(() => clearTimeout(timer));
}

async function fixture(t) {
  const parent = createPrivateAuthorityFixture("cos-pr235-signed-http-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const localPath = path.join(parent, "mutation.json");
  const outboxPath = path.join(parent, "outbox.json");
  const fileKey = crypto.randomBytes(32);
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const approved = new Map();
  const events = [];
  const signed = [];
  const state = {
    bridge: null, journal: null, outbox: null, revoked: false,
    policyReads: 0, resolverReads: 0,
    mutateSigned: null, beforeReturn: null, duringResolver: null,
    replayFromDurableOutbox: false,
  };
  t.after(async () => {
    if (state.bridge) await state.bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });

  function manifestKey(kind, source, destination) {
    return kind === "put" ? "put:" + destination
      : kind === "move" ? "move:" + source + "->" + destination
        : "delete:" + source;
  }
  function authorize(kind, source, destination, bytes = Buffer.alloc(0)) {
    approved.set(manifestKey(kind, source, destination), Buffer.from(bytes));
  }
  async function signActualEvent(event) {
    assert.equal(event.journalType, "webdav-mutation");
    assert.match(event.operationId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      "test must use the random identifier from a real WebDAV HTTP mutation");
    const key = manifestKey(event.kind, event.source, event.destination);
    assert.ok(approved.has(key), "No independently authorized mutation: " + key);
    const plaintext = approved.get(key);
    const verb = event.kind === "put" ? (event.existed ? "update" : "create")
      : event.kind === "move" ? "move" : "delete";
    const pathname = relative(event.kind === "delete" ? event.source : event.destination);
    const metadata = { path: pathname };
    if (event.kind === "put") metadata.size = event.putBytes;
    if (event.kind === "move") metadata.sourcePath = relative(event.source);
    const bytes = verb === "move"
      ? protocol.encodeMovePayload(plaintext, fileKey) : plaintext;
    const canonicalId = boundId(event, verb, pathname);
    // If a test requests an unrelated ID, make it the genuine encrypted
    // operation's ID BEFORE AES-GCM AAD and Ed25519 signature are computed.
    // Mutating it afterward would fail an unrelated AAD check: false GREEN.
    const requestedId = state.mutateSigned
      ? state.mutateSigned(canonicalId, event) : canonicalId;
    const operation = protocol.createOperation({
      operation: verb, operationId: requestedId,
      objectId: "cos-e2e-object", fileId: "cos-e2e-file",
      versionId: crypto.randomUUID(), deviceId: "device-a",
      keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: signed.length + 1, deviceId: "device-a" },
      metadata, plaintext: bytes, fileKey,
    });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey: pair.privateKey, publicKey,
      expiresAt: Date.now() + 120_000,
    });
    return operation;
  }
  async function translateActualEvent(event) {
    events.push(JSON.parse(protocol.canonicalJson(event)));
    if (state.replayFromDurableOutbox) {
      // On a real reopened protocol-queued replay, the ORIGINAL Ed25519
      // envelope must come from real durable outbox bytes. Encrypting again
      // would generate a different signed envelope with the same canonical
      // operationId and correctly trigger journal collision.
      assert.ok(approved.has(manifestKey(event.kind, event.source, event.destination)));
      const verb = event.kind === "put" ? (event.existed ? "update" : "create")
        : event.kind === "move" ? "move" : "delete";
      const target = relative(event.kind === "delete" ? event.source : event.destination);
      const expectedId = boundId(event, verb, target);
      const persisted = state.outbox.pending().find((item) => item.operationId === expectedId);
      assert.ok(persisted, "replay must find exact signed entry in independently reopened outbox");
      signed.push(persisted);
      return persisted;
    }
    const operation = await signActualEvent(event);
    signed.push(operation);
    if (state.beforeReturn) await state.beforeReturn(event, operation);
    return operation;
  }
  function currentPolicy() {
    state.policyReads += 1;
    return {
      username: "alice",
      trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: state.revoked ? ["device-a"] : [],
    };
  }
  async function resolveFileKey(operation) {
    state.resolverReads += 1;
    assert.equal(operation.fileId, "cos-e2e-file");
    if (state.duringResolver) await state.duringResolver();
    return fileKey;
  }
  async function start() {
    assert.equal(state.bridge, null, "stop the current listener first");
    state.journal = await new SyncJournal(localPath).open();
    state.outbox = await new SyncJournal(outboxPath).open();
    const bridge = new LocalSyncWebDavBridge({
      rootDir: root, token: TOKEN, journal: state.journal,
      protocolJournal: state.outbox, requireSignedProtocolIngress: true,
      toProtocolOperation: translateActualEvent,
      trustedProtocolPolicy: currentPolicy,
      resolveProtectedFileKey: resolveFileKey,
    });
    assert.equal(bridge.requireSignedProtocolIngress, true);
    await bridge.start();
    state.bridge = bridge;
    return bridge.address().port;
  }
  async function stop() {
    if (state.bridge) await state.bridge.stop();
    state.bridge = null;
  }
  async function reopen() {
    return {
      local: await new SyncJournal(localPath).open(),
      outbox: await new SyncJournal(outboxPath).open(),
    };
  }
  return {
    parent, root, localPath, outboxPath, fileKey, events, signed, state,
    authorize, signActualEvent, translateActualEvent, currentPolicy,
    resolveFileKey, start, stop, reopen,
  };
}

test("strict HTTP PUT/MOVE/DELETE persists genuinely signed envelopes and survives restart", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  f.authorize("put", "/document.txt", "/document.txt", BYTES);
  f.authorize("move", "/document.txt", "/moved.txt", BYTES);
  f.authorize("delete", "/moved.txt", null);
  let port = await f.start();
  assert.equal((await request(port, "PUT", "/document.txt", BYTES)).status, 201);
  assert.deepEqual((await request(port, "GET", "/document.txt")).body, BYTES);
  assert.equal(f.events[0].kind, "put");
  assert.equal(f.events[0].putSha256, sha(BYTES));
  assert.equal(f.events[0].putBytes, BYTES.length);
  assert.equal(f.signed[0].operationId, boundId(f.events[0], "create", "document.txt"));
  assert.equal(f.state.policyReads, 3,
    "outbox admission rechecks current policy after awaiting durable local signed receipt");
  assert.equal(f.state.resolverReads, 1);
  let disk = await f.reopen();
  assert.deepEqual(await disk.local.recover(), []);
  assert.equal(disk.local.hasSeen(f.events[0].operationId), true);
  assert.deepEqual((await disk.outbox.recover()).map((entry) => entry.operation), ["create"]);
  assert.deepEqual(protocol.decryptPayload((await disk.outbox.recover())[0], f.fileKey), BYTES);

  const move = await request(port, "MOVE", "/document.txt", null, {
    destination: "http://127.0.0.1:" + port + "/moved.txt",
  });
  assert.equal(move.status, 201, move.body.toString());
  assert.deepEqual((await request(port, "GET", "/moved.txt")).body, BYTES);
  assert.equal((await request(port, "GET", "/document.txt")).status, 404);
  assert.equal(f.events[1].kind, "move");
  assert.equal(f.events[1].source, "/document.txt");
  assert.equal(f.events[1].destination, "/moved.txt");
  disk = await f.reopen();
  const moved = (await disk.outbox.recover())[1];
  assert.equal(moved.operation, "move");
  assert.deepEqual(protocol.decodeMovePayload(
    protocol.decryptPayload(moved, f.fileKey), f.fileKey,
  ), BYTES);
  assert.equal(disk.local.hasSeen(f.events[1].operationId), true);
  await f.stop();

  port = await f.start();
  assert.deepEqual((await request(port, "GET", "/moved.txt")).body, BYTES);
  disk = await f.reopen();
  assert.deepEqual(await disk.local.recover(), []);
  assert.equal((await disk.outbox.recover()).length, 2,
    "restart must not queue an already admitted signed operation again");
  assert.equal((await request(port, "DELETE", "/moved.txt")).status, 204);
  assert.equal((await request(port, "GET", "/moved.txt")).status, 404);
  disk = await f.reopen();
  assert.deepEqual(await disk.local.recover(), []);
  assert.equal(disk.local.hasSeen(f.events[2].operationId), true);
  assert.deepEqual((await disk.outbox.recover()).map((entry) => entry.operation),
    ["create", "move", "delete"]);
  assert.equal(f.events.length, 3);
  assert.equal(f.signed.length, 3);
  for (const [index, operation] of f.signed.entries()) {
    assert.equal(operation.operationId,
      boundId(f.events[index], operation.operation, operation.metadata.path));
    assert.equal((await disk.outbox.recover())[index].authorization.signature,
      operation.authorization.signature, "durable outbox retains exact Ed25519 proof");
  }
});

test("actual HTTP rejects Ed25519-valid but unrelated signed operation ID", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  f.authorize("put", "/wrong-id.txt", "/wrong-id.txt", BYTES);
  f.state.mutateSigned = () => crypto.randomUUID();
  const port = await f.start();
  const response = await request(port, "PUT", "/wrong-id.txt", BYTES);
  assert.equal(response.status, 500, response.body.toString());
  assert.equal(f.signed.length, 1, "must reach the actual HTTP translator");
  assert.notEqual(f.signed[0].operationId,
    boundId(f.events[0], "create", "wrong-id.txt"));
  assert.equal((await request(port, "GET", "/wrong-id.txt")).status, 404);
  const disk = await f.reopen();
  assert.deepEqual(await disk.outbox.recover(), [], "unrelated signed event may not persist");
  assert.deepEqual(await disk.local.recover(), [], "failed PUT must be rolled back");
});

test("real protocol-queued PUT reopens physical journal and idempotently replays its durable signed envelope", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  f.authorize("put", "/replay.txt", "/replay.txt", BYTES);
  const port = await f.start();
  const originalMarkSeen = f.state.journal.markSeen;
  let interrupted = 0;
  f.state.journal.markSeen = async (operationId, ...args) => {
    interrupted += 1;
    assert.match(operationId, /^[0-9a-f-]{36}$/i);
    assert.equal(interrupted, 1);
    throw new Error("injected interruption AFTER durable signed enqueue");
  };
  try {
    const response = await request(port, "PUT", "/replay.txt", BYTES);
    assert.equal(response.status, 201, response.body.toString());
  } finally {
    f.state.journal.markSeen = originalMarkSeen;
  }
  assert.equal(interrupted, 1, "fault must reach the actual HTTP markSeen boundary");
  assert.deepEqual((await request(port, "GET", "/replay.txt")).body, BYTES);
  let disk = await f.reopen();
  const pending = await disk.local.recover();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].phase, "protocol-queued",
    "real persisted mutation receipt must survive interrupted acknowledgement");
  assert.equal(pending[0].putSha256, sha(BYTES));
  assert.equal(pending[0].operationId, f.events[0].operationId);
  const firstSigned = (await disk.outbox.recover())[0];
  assert.equal(firstSigned.authorization.signature, f.signed[0].authorization.signature);
  const pinned = pending[0].signedOutboxReceipts;
  assert.equal(pinned.length, 1, "physically admitted signed ingress must persist its verified batch receipt");
  assert.equal(pinned[0].operationId, firstSigned.operationId);
  assert.equal(pinned[0].digest, sha(protocol.canonicalJson(firstSigned)));
  assert.equal(disk.outbox.durableSignedReceiptDigest(firstSigned.operationId), pinned[0].digest);
  await f.stop();

  // Restart opens TWO fresh real journals. A previously authenticated,
  // outbox-fsynced identical envelope must be recovered WITHOUT invoking a
  // translator or current policy and therefore without re-authorizing an
  // expired/revoked device. The only permission is to acknowledge the exact
  // previous physical mutation, not to create any new remote operation.
  f.state.replayFromDurableOutbox = true;
  f.state.revoked = true;
  const restartedPort = await f.start();
  assert.deepEqual((await request(restartedPort, "GET", "/replay.txt")).body, BYTES);
  assert.equal(f.events.length, 1, "exact previously durable signed receipt must not re-sign or retranslate");
  disk = await f.reopen();
  assert.deepEqual(await disk.local.recover(), [],
    "verified already-queued replay must be acknowledged after restart");
  assert.equal(disk.local.hasSeen(pending[0].operationId), true);
  assert.deepEqual(await disk.outbox.recover(), [firstSigned],
    "a durable replay must never duplicate or rewrite signed outbox evidence");
});

test("previously committed local digest rejects an outbox with the same operation ID but substituted bytes", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  f.authorize("put", "/substituted-replay.txt", "/substituted-replay.txt", BYTES);
  const port = await f.start();
  const originalMarkSeen = f.state.journal.markSeen;
  f.state.journal.markSeen = async () => {
    throw new Error("injected interruption after signed envelope fsync");
  };
  try {
    assert.equal((await request(port, "PUT", "/substituted-replay.txt", BYTES)).status, 201);
  } finally {
    f.state.journal.markSeen = originalMarkSeen;
  }
  const original = await f.reopen();
  const pending = (await original.local.recover())[0];
  assert.equal(pending.phase, "protocol-queued");
  assert.equal(pending.signedOutboxReceipts.length, 1);
  const pinnedDigest = pending.signedOutboxReceipts[0].digest;
  const id = pending.signedOutboxReceipts[0].operationId;
  assert.equal(original.outbox.durableSignedReceiptDigest(id), pinnedDigest);
  await f.stop();

  // Replace the actual fsync-backed JSON outbox with another internally
  // consistent receipt for the SAME ID. This simulates a compromised/stale
  // outbox: its local digest validates against its own bytes but not against
  // the independent signed ingress digest stored in the mutation journal.
  const poisoned = JSON.parse(await fsp.readFile(f.outboxPath, "utf8"));
  assert.equal(poisoned.pending.length, 1);
  poisoned.pending[0].ciphertext = "POISONED_SIGNED_BYTES_SAME_OPERATION_ID";
  const poisonedDigest = sha(protocol.canonicalJson(poisoned.pending[0]));
  assert.notEqual(poisonedDigest, pinnedDigest);
  poisoned.committedSigned[id] = poisonedDigest;
  const poisonedHandle = await fsp.open(f.outboxPath, "r+");
  try {
    await poisonedHandle.truncate(0);
    await poisonedHandle.writeFile(JSON.stringify(poisoned) + "\n", "utf8");
    await poisonedHandle.sync();
  } finally { await poisonedHandle.close(); }
  const onDiskPoison = await fsp.readFile(f.outboxPath);
  const selfConsistentOutbox = await new SyncJournal(f.outboxPath).open();
  assert.equal(selfConsistentOutbox.durableSignedReceiptDigest(id), poisonedDigest,
    "the attack must reach a real self-consistent durable signed receipt");

  await assert.rejects(f.start(), /Committed WebDAV protocol outbox receipt missing/i);
  assert.deepEqual(await fsp.readFile(f.outboxPath), onDiskPoison,
    "rejected recovery must not rewrite or silently cleanse foreign outbox bytes");
  const after = await f.reopen();
  assert.deepEqual((await after.local.recover())[0], pending,
    "a mismatched outbox must never authorize acknowledgement of the physical mutation");
  assert.deepEqual(await fsp.readFile(path.join(f.root, "substituted-replay.txt")), BYTES);
  assert.equal(after.outbox.durableSignedReceiptDigest(id), poisonedDigest);
});

test("actual HTTP rejects valid signature for DIFFERENT plaintext of the same length", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  f.authorize("put", "/wrong-bytes.txt", "/wrong-bytes.txt", BYTES);
  const uploaded = Buffer.from(BYTES);
  uploaded[0] ^= 1;
  const port = await f.start();
  const response = await request(port, "PUT", "/wrong-bytes.txt", uploaded);
  assert.equal(response.status, 500, response.body.toString());
  assert.equal(f.events.length, 1);
  assert.equal(f.events[0].putSha256, sha(uploaded));
  assert.equal(f.state.resolverReads, 1,
    "must reach actual decrypted-byte comparison, not a fake earlier rejection");
  assert.equal((await request(port, "GET", "/wrong-bytes.txt")).status, 404);
  const disk = await f.reopen();
  assert.deepEqual(await disk.outbox.recover(), []);
  assert.deepEqual(await disk.local.recover(), []);
});

test("live revocation during resolver barrier rejects HTTP request before journal ingress", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  f.authorize("put", "/revocation.txt", "/revocation.txt", BYTES);
  let arrived;
  const reached = new Promise((resolve) => { arrived = resolve; });
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  f.state.duringResolver = async () => {
    arrived();
    await held;
  };
  const port = await f.start();
  let pending;
  try {
    pending = request(port, "PUT", "/revocation.txt", BYTES);
    await deadline(reached);
    assert.equal(f.state.policyReads, 1,
      "must cross the first genuine Ed25519-policy check before revoking");
    f.state.revoked = true;
  } finally {
    release(); // Prevent an orphaned HTTP handler even if the assertion fails.
  }
  const response = await deadline(pending);
  assert.equal(response.status, 500, response.body.toString());
  assert.equal(f.state.policyReads, 2,
    "the second live policy check must observe newly revoked device");
  assert.equal((await request(port, "GET", "/revocation.txt")).status, 404);
  const disk = await f.reopen();
  assert.deepEqual(await disk.outbox.recover(), []);
  assert.deepEqual(await disk.local.recover(), []);
});

test("protected bridge refuses startup without real local journal, outbox or policy", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  const local = await new SyncJournal(f.localPath).open();
  const outbox = await new SyncJournal(f.outboxPath).open();
  const config = {
    rootDir: f.root, token: TOKEN, requireSignedProtocolIngress: true,
    toProtocolOperation: f.translateActualEvent,
    trustedProtocolPolicy: f.currentPolicy,
    resolveProtectedFileKey: f.resolveFileKey,
  };
  assert.throws(() => new LocalSyncWebDavBridge({
    ...config, journal: local,
  }), /trusted current device policy/, "missing durable protocol outbox must fail");
  assert.throws(() => new LocalSyncWebDavBridge({
    ...config, journal: local, protocolJournal: outbox,
    trustedProtocolPolicy: null,
  }), /trusted current device policy/, "missing independent policy must fail");
  const withoutLocal = new LocalSyncWebDavBridge({
    ...config, protocolJournal: outbox,
  });
  await assert.rejects(withoutLocal.start(), /durable local mutation journal/);
  assert.equal(withoutLocal.server.listening, false);
  await withoutLocal.stop();

  const withoutFileKey = new LocalSyncWebDavBridge({
    ...config, journal: local, protocolJournal: outbox,
    resolveProtectedFileKey: null,
  });
  await assert.rejects(withoutFileKey.start(), /trusted file-key resolver/);
  assert.equal(withoutFileKey.server.listening, false);
  await withoutFileKey.stop();
  const disk = await f.reopen();
  assert.deepEqual(await disk.local.recover(), []);
  assert.deepEqual(await disk.outbox.recover(), []);
});

test("real HTTP rejects different signed envelope reusing canonical durable operationId", {
  timeout: TIMEOUT,
}, async (t) => {
  const f = await fixture(t);
  f.authorize("put", "/collision.txt", "/collision.txt", BYTES);
  let seeded = null;
  f.state.beforeReturn = async (event, operation) => {
    assert.equal(seeded, null);
    // A second real Ed25519/AES-GCM envelope for the same HTTP event ID is
    // independently encrypted, creating genuinely different canonical bytes.
    // Preseed the REAL SyncJournal, then exercise collision through actual HTTP.
    seeded = await f.signActualEvent(event);
    assert.equal(seeded.operationId, operation.operationId);
    assert.notEqual(protocol.canonicalJson(seeded), protocol.canonicalJson(operation));
    await f.state.outbox.enqueue(seeded);
  };
  const port = await f.start();
  const response = await request(port, "PUT", "/collision.txt", BYTES);
  assert.equal(response.status, 500, response.body.toString());
  assert.ok(seeded?.authorization?.signature);
  assert.equal(f.events.length, 1);
  assert.equal(f.state.resolverReads, 1,
    "must verify valid authenticated bytes before reaching durable duplicate ID");
  assert.equal((await request(port, "GET", "/collision.txt")).status, 404);
  let disk = await f.reopen();
  assert.deepEqual(await disk.outbox.recover(), JSON.parse(JSON.stringify([seeded])),
    "conflict cannot replace previously persisted signed envelope");
  assert.deepEqual(await disk.local.recover(), []);
  await f.stop();
  disk = await f.reopen();
  await assert.rejects(disk.outbox.enqueue(f.signed[0]),
    { code: "sync_journal_operation_conflict" });
  assert.deepEqual((await f.reopen()).outbox.pending(), JSON.parse(JSON.stringify([seeded])));
});

for (const verb of ["PUT", "MOVE"]) {
  test("protected HTTP " + verb + " rejects a physically admissible file exceeding bounded remote JSON wire budget BEFORE mutation", {
    timeout: TIMEOUT,
  }, async (t) => {
    // The protected server's JSON request cap is 9 MiB, but binary signed
    // ciphertext expands via base64url and adds authorization metadata.
    // Accepting the full legacy 8 MiB locally would create an outbox entry
    // that the remote server can never admit. Keep legacy caps unchanged.
    const f = await fixture(t);
    const overBudget = Buffer.alloc(6 * 1024 * 1024 + 1, 0x51);
    const original = path.join(f.root, "too-large.txt");
    if (verb === "MOVE") {
      await fsp.writeFile(original, overBudget, { flag: "wx", mode: 0o600 });
    }
    const originalStat = verb === "MOVE"
      ? await fsp.lstat(original, { bigint: true }) : null;
    const port = await f.start();
    const response = verb === "PUT"
      ? await request(port, "PUT", "/too-large.txt", overBudget)
      : await request(port, "MOVE", "/too-large.txt", null,
        { destination: "http://127.0.0.1:" + port + "/not-admitted.txt" });
    assert.equal(response.status, 413, response.body.toString());
    assert.match(response.body.toString(), /bounded remote sync wire budget/);
    assert.equal(f.events.length, 0, "inadmissible wire payload may not reach translator");
    assert.equal(f.signed.length, 0);
    assert.equal(f.state.policyReads, 0);
    assert.equal(f.state.resolverReads, 0);
    const disk = await f.reopen();
    assert.deepEqual(disk.local.pending(), []);
    assert.deepEqual(disk.outbox.pending(), []);
    if (verb === "PUT") {
      await assert.rejects(fsp.lstat(original), { code: "ENOENT" });
    } else {
      const after = await fsp.lstat(original, { bigint: true });
      assert.equal(after.dev, originalStat.dev);
      assert.equal(after.ino, originalStat.ino);
      assert.deepEqual(await fsp.readFile(original), overBudget);
      await assert.rejects(fsp.lstat(path.join(f.root, "not-admitted.txt")), { code: "ENOENT" });
    }
  });
}
