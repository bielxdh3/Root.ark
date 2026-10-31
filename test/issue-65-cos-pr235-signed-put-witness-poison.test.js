"use strict";

// TEST_UNRUN (exclusive Node22 gate closed, NODE_COUNT=61).
// This suite tests the W217 independent signed PUT content witness: a signed
// local filesystem PUT and genuine fsynced two-journal outbox must never be
// acknowledged after the installed inode AND its mutable local hash are
// jointly poisoned. Test-only protected activation is not production wiring.
// Interrupted ACKs are deliberate fault injection, not an actual power cut.
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
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-signed-put-witness-poison-only";
const ORIGINAL = Buffer.from("AUTHENTIC_SIGNED_PUT_PAYLOAD_".repeat(19));
const TIMEOUT_MS = 120_000;
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const clone = (value) => JSON.parse(protocol.canonicalJson(value));

function receipt(signed) {
  return { operationId: signed.operationId,
    digest: sha(protocol.canonicalJson(signed)) };
}

function identity(stat) {
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.ok(stat.ino > 0n && stat.dev >= 0n);
  assert.equal(stat.nlink, 1n);
  return { dev: String(stat.dev), ino: String(stat.ino), type: "file" };
}

function send(port, method, pathname, bytes = null) {
  return new Promise((resolve, reject) => {
    const body = bytes === null ? null : Buffer.from(bytes);
    const req = http.request({
      host: "127.0.0.1", port, path: pathname, method, agent: false,
      headers: {
        authorization: "Bearer " + TOKEN,
        ...(body === null ? {} : { "content-length": body.length }),
      },
    }, (response) => {
      const data = [];
      response.on("data", (chunk) => data.push(chunk));
      response.once("error", reject);
      response.once("end", () => resolve({
        status: response.statusCode, body: Buffer.concat(data),
      }));
    });
    req.setTimeout(25_000, () => req.destroy(new Error("real PUT HTTP timeout")));
    req.once("error", reject);
    req.end(body ?? undefined);
  });
}

async function fixture(t) {
  const parent = createPrivateAuthorityFixture("cos-pr235-put-poison-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const target = path.join(root, "signed.txt");
  const localPath = path.join(parent, "mutation.json");
  const outboxPath = path.join(parent, "signed-outbox.json");
  const key = crypto.randomBytes(32);
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const events = [];
  const signed = [];
  const state = { bridge: null, journal: null, outbox: null,
    revoked: false, policyReads: 0, keyReads: 0, translations: 0,
    noNewTranslation: false };
  t.after(async () => {
    if (state.bridge) await state.bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });

  function policy() {
    state.policyReads += 1;
    return { username: "alice",
      trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: state.revoked ? ["device-a"] : [] };
  }
  async function keyResolver(operation) {
    state.keyReads += 1;
    assert.equal(operation.fileId, "put-witness-file");
    assert.equal(operation.keyEpoch, "epoch-1");
    return key;
  }
  async function translate(event) {
    if (state.noNewTranslation) {
      throw new Error("no new encryption/signing on committed signed replay");
    }
    state.translations += 1;
    events.push(clone(event));
    assert.equal(event.kind, "put");
    assert.equal(event.journalType, "webdav-mutation");
    assert.equal(event.existed, false);
    assert.equal(event.source, "/signed.txt");
    assert.equal(event.destination, "/signed.txt");
    assert.match(event.operationId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    const expectedId = "webdav-" + event.operationId + "-" +
      sha("create:signed.txt").slice(0, 24);
    // Authorization is based on an independently pinned original manifest,
    // not on the potentially poisoned current HTTP file or journal hash.
    const operation = protocol.createOperation({
      operation: "create", operationId: expectedId,
      objectId: "put-witness-object", fileId: "put-witness-file",
      versionId: crypto.randomUUID(), deviceId: "device-a",
      keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: "signed.txt", size: ORIGINAL.length },
      plaintext: ORIGINAL, fileKey: key,
    });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey: pair.privateKey, publicKey,
      expiresAt: Date.now() + 180_000,
    });
    assert.equal(await verifyAuthorizationProof(operation.authorization, operation,
      { username: "alice",
        trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] }), true,
    "the outbox must be derived from an authentic signed envelope");
    signed.push(operation);
    return operation;
  }
  async function reopen() {
    return {
      local: await new SyncJournal(localPath).open(),
      outbox: await new SyncJournal(outboxPath).open(),
    };
  }
  async function start() {
    assert.equal(state.bridge, null, "real cold restart must stop prior listener");
    state.journal = await new SyncJournal(localPath).open();
    state.outbox = await new SyncJournal(outboxPath).open();
    const bridge = new LocalSyncWebDavBridge({
      rootDir: root, token: TOKEN,
      requireSignedProtocolIngress: true,
      journal: state.journal, protocolJournal: state.outbox,
      toProtocolOperation: translate, trustedProtocolPolicy: policy,
      resolveProtectedFileKey: keyResolver,
    });
    await bridge.start();
    state.bridge = bridge;
    return bridge.address().port;
  }
  async function stop() {
    if (state.bridge) await state.bridge.stop();
    state.bridge = null;
  }
  async function frozen() {
    return {
      local: await fsp.readFile(localPath),
      outbox: await fsp.readFile(outboxPath),
      bytes: await fsp.readFile(target),
      inode: identity(await fsp.lstat(target, { bigint: true })),
    };
  }
  return { parent, root, target, key, localPath, outboxPath,
    publicKey, events, signed, state, start, stop, reopen, frozen };
}

async function realSignedUnacknowledgedPut(t, phase) {
  const f = await fixture(t);
  const port = await f.start();
  const oldSeen = f.state.journal.markSeen;
  const oldUpdate = f.state.journal.update;
  let boundaryHits = 0;
  if (phase === "protocol-queued") {
    f.state.journal.markSeen = async (id) => {
      assert.match(id, /^[0-9a-f-]{36}$/i);
      boundaryHits += 1;
      throw new Error("injected interruption AFTER real signed outbox commit");
    };
  } else {
    f.state.journal.update = async (id, patch) => {
      if (patch.phase === "protocol-queued") {
        boundaryHits += 1;
        const proof = await f.reopen();
        assert.equal(proof.local.pending()[0].phase, "source-moved");
        assert.equal(proof.outbox.pending().length, 1,
          "source-moved injection happens ONLY after signed outbox durable write");
        throw new Error("injected interruption BEFORE local phase ACK");
      }
      return oldUpdate.call(f.state.journal, id, patch);
    };
  }
  let reply;
  try {
    reply = await send(port, "PUT", "/signed.txt", ORIGINAL);
  } finally {
    f.state.journal.markSeen = oldSeen;
    f.state.journal.update = oldUpdate;
  }
  assert.equal(reply.status, 201, reply.body.toString());
  assert.equal(boundaryHits, 1, "must reach exact outbox-durable interrupt boundary");
  assert.equal(f.state.translations, 1, "must reach real authenticated PUT translation");
  assert.equal(f.events.length, 1);
  assert.equal(f.signed.length, 1);
  const proof = await f.reopen();
  const records = proof.local.pending();
  assert.equal(records.length, 1);
  const event = records[0];
  assert.equal(event.phase, phase);
  assert.equal(event.journalType, "webdav-mutation");
  assert.equal(event.kind, "put");
  assert.equal(event.putBytes, ORIGINAL.length);
  assert.equal(event.putSha256, sha(ORIGINAL));
  assert.deepEqual(event.installedIdentity,
    identity(await fsp.lstat(f.target, { bigint: true })));
  assert.deepEqual(await fsp.readFile(f.target), ORIGINAL);
  assert.deepEqual(proof.outbox.pending(), JSON.parse(JSON.stringify(f.signed)),
    "the outbox must actually survive an independent on-disk journal reopen");
  const originalSigned = proof.outbox.pending()[0];
  assert.equal(await verifyAuthorizationProof(originalSigned.authorization, originalSigned,
    { username: "alice", trustedDevicePublicKeys: { "device-a": f.publicKey },
      revokedDeviceIds: [] }), true);
  assert.deepEqual(protocol.decryptPayload(originalSigned, f.key), ORIGINAL,
    "the original AES-GCM ciphertext must independently prove unmodified original content");
  assert.deepEqual(event.signedOutboxReceipts, [receipt(originalSigned)]);
  assert.equal(proof.outbox.durableSignedReceiptDigest(originalSigned.operationId),
    receipt(originalSigned).digest);
  await f.stop();
  return { f, event, originalSigned };
}

for (const phase of ["source-moved", "protocol-queued"]) {
  test("signed PUT cold recovery " + phase +
    " accepts unpoisoned original AES-GCM bytes under revoked policy without new admission", {
    timeout: TIMEOUT_MS,
  }, async (t) => {
    const { f, event, originalSigned } = await realSignedUnacknowledgedPut(t, phase);
    const beforePolicy = f.state.policyReads;
    const beforeKey = f.state.keyReads;
    const beforeTranslations = f.state.translations;
    f.state.revoked = true;
    f.state.noNewTranslation = true;
    const port = await f.start();
    assert.ok(Number.isInteger(port));
    assert.equal(f.state.policyReads, beforePolicy,
      "already committed exact receipt must not reauthorize revoked signer");
    assert.equal(f.state.translations, beforeTranslations,
      "must not mint a new signed envelope with same operation ID");
    assert.ok(f.state.keyReads > beforeKey,
      "independent historical signed plaintext MUST be decrypted and compared");
    assert.deepEqual((await send(port, "GET", "/signed.txt")).body, ORIGINAL);
    const recovered = await f.reopen();
    assert.deepEqual(recovered.local.pending(), []);
    assert.equal(recovered.local.hasSeen(event.operationId), true);
    assert.deepEqual(recovered.outbox.pending(), [originalSigned]);
    assert.equal(recovered.outbox.durableSignedReceiptDigest(originalSigned.operationId),
      receipt(originalSigned).digest);
    await f.stop();
    await f.start();
    assert.deepEqual((await f.reopen()).outbox.pending(), [originalSigned],
      "second cold restart must not duplicate outbox or re-sign");
  });

  for (const poisonStyle of ["same-size", "length-change"]) {
    test("signed PUT cold recovery " + phase + " rejects " + poisonStyle +
      " SAME-inode poison plus forged LOCAL putBytes and putSha256", {
    timeout: TIMEOUT_MS,
  }, async (t) => {
    const { f, event, originalSigned } = await realSignedUnacknowledgedPut(t, phase);
    const before = await f.frozen();
    const corrupted = Buffer.from(ORIGINAL);
    corrupted[0] ^= 0x51;
    corrupted[1] ^= 0x22;
    const attackerBytes = poisonStyle === "length-change"
      ? Buffer.concat([corrupted, Buffer.from("_ATTACKER_EXTRA_UNAUTHORIZED_BYTES_")])
      : corrupted;
    assert.notEqual(sha(attackerBytes), sha(ORIGINAL));
    assert.equal(attackerBytes.length === ORIGINAL.length, poisonStyle === "same-size",
      "test must distinguish same-size byte substitution from forged length");
    await fsp.writeFile(f.target, attackerBytes);
    assert.deepEqual(identity(await fsp.lstat(f.target, { bigint: true })),
      before.inode, "attack must keep EXACT physical inode; not a replaced path");
    assert.deepEqual(await fsp.readFile(f.target), attackerBytes);
    const local = await new SyncJournal(f.localPath).open();
    await local.update(event.operationId, {
      putBytes: attackerBytes.length, putSha256: sha(attackerBytes),
    });
    const doctored = await f.reopen();
    assert.equal(doctored.local.pending()[0].putBytes, attackerBytes.length);
    assert.equal(doctored.local.pending()[0].putSha256, sha(attackerBytes));
    assert.deepEqual(doctored.local.pending()[0].installedIdentity, before.inode);
    assert.deepEqual(doctored.local.pending()[0].signedOutboxReceipts, [receipt(originalSigned)]);
    assert.deepEqual(doctored.outbox.pending(), [originalSigned]);
    assert.deepEqual(await fsp.readFile(f.outboxPath), before.outbox,
      "attacker may poison ONLY local mutation journal and physical inode");
    const poisoned = await f.frozen();
    f.state.revoked = true;
    f.state.noNewTranslation = true;
    const policyBefore = f.state.policyReads;
    const translationBefore = f.state.translations;
    const keyBefore = f.state.keyReads;
    await assert.rejects(() => f.start(), { code: "WEBDAV_RECOVERY_INDETERMINATE" },
      "independently signed AES-GCM plaintext MUST defeat matched local-only SHA and bytes");
    assert.equal(f.state.bridge, null, "a failed cold boot must not expose an HTTP listener");
    assert.equal(f.state.policyReads, policyBefore);
    assert.equal(f.state.translations, translationBefore);
    assert.ok(f.state.keyReads > keyBefore,
      "rejection must reach original signed ciphertext decrypt, not unrelated startup error");
    assert.deepEqual(await f.frozen(), poisoned,
      "rejection must preserve both journals, original signed outbox and suspect bytes");
    const pending = (await f.reopen()).local.pending();
    assert.equal(pending.length, 1);
    assert.equal(pending[0].phase, phase);
    assert.equal(pending[0].operationId, event.operationId);
    assert.equal((await f.reopen()).local.hasSeen(event.operationId), false);
  });
  }
}

test("signed PUT with only seen signed digest but PURGED original encrypted envelope fails closed", {
  timeout: TIMEOUT_MS,
}, async (t) => {
  const { f, event, originalSigned } =
    await realSignedUnacknowledgedPut(t, "protocol-queued");
  const outbox = await new SyncJournal(f.outboxPath).open();
  await outbox.markSeen(originalSigned.operationId);
  const seen = await f.reopen();
  assert.deepEqual(seen.outbox.pending(), [],
    "original AES-GCM bytes must genuinely be absent, not just hidden by an assertion");
  assert.equal(seen.outbox.hasSeen(originalSigned.operationId), true);
  assert.equal(seen.outbox.durableSignedReceiptDigest(originalSigned.operationId),
    receipt(originalSigned).digest,
    "historical digest remains present and CORRECT but cannot decrypt original bytes");
  assert.deepEqual(seen.local.pending()[0].signedOutboxReceipts, [receipt(originalSigned)]);
  const before = await f.frozen();
  f.state.revoked = true;
  f.state.noNewTranslation = true;
  const policyBefore = f.state.policyReads;
  const translationBefore = f.state.translations;
  await assert.rejects(() => f.start(), { code: "WEBDAV_RECOVERY_INDETERMINATE" },
    "signed digest without retained ORIGINAL encrypted envelope is insufficient for cold ACK");
  assert.equal(f.state.bridge, null);
  assert.equal(f.state.policyReads, policyBefore);
  assert.equal(f.state.translations, translationBefore);
  assert.deepEqual(await f.frozen(), before,
    "missing signed ciphertext must never erase or acknowledge local physical evidence");
  const pending = (await f.reopen()).local.pending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].operationId, event.operationId);
  assert.equal(pending[0].phase, "protocol-queued");
  assert.equal((await f.reopen()).local.hasSeen(event.operationId), false);
});
