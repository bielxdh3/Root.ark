"use strict";

// TEST_UNRUN: exclusive Node22 gate is closed. This is a genuine signed
// WebDAV HTTP→local-fsync journal→Ed25519 encrypted outbox→recovery flow.
// The attacker changes ONLY the physical same-inode file and local mutation
// journal. The independent outbox, signing key and file key remain untouched.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-move-poison-private-only";
const ORIGINAL = Buffer.from("REAL_ED25519_AUTHORIZED_MOVE_BYTES_".repeat(16));
const SOURCE = "/source.txt";
const DESTINATION = "/moved.txt";
const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const clone = (value) => JSON.parse(protocol.canonicalJson(value));

function httpRequest(port, method, route, body = null, extra = {}) {
  return new Promise((resolve, reject) => {
    const bytes = body === null ? null : Buffer.from(body);
    const req = http.request({
      host: "127.0.0.1", port, method, path: route, agent: false,
      headers: { authorization: "Bearer " + TOKEN,
        ...(bytes === null ? {} : { "content-length": bytes.length }), ...extra },
    }, (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode, body: Buffer.concat(parts),
      }));
    });
    req.setTimeout(30000, () => req.destroy(Error("Real signed WebDAV request timed out")));
    req.on("error", reject);
    req.end(bytes ?? undefined);
  });
}

function exactInode(filename) {
  const stat = fs.lstatSync(filename, { bigint: true });
  assert.equal(stat.isFile(), true);
  assert.equal(stat.nlink, 1n);
  return { dev: stat.dev, ino: stat.ino };
}
function sameInode(actual, expected) {
  assert.equal(actual.dev, expected.dev);
  assert.equal(actual.ino, expected.ino,
    "attacker must modify content in SAME physical inode, never replace pathname");
}

async function setup(t) {
  const parent = createPrivateAuthorityFixture("cos-pr235-signed-poison-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const localPath = path.join(parent, "mutation.json");
  const outboxPath = path.join(parent, "outbox.json");
  const fileKey = crypto.randomBytes(32);
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const state = { revoked: false, translatorReads: 0, policyReads: 0,
    forbidTranslation: false, events: [], signed: [], active: null, bridges: [],
    journal: null, outbox: null };
  const policy = () => {
    state.policyReads++;
    return { username: "alice",
      trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: state.revoked ? ["device-a"] : [] };
  };
  const translate = async (event) => {
    state.translatorReads++;
    assert.equal(state.forbidTranslation, false,
      "replay must reuse exact independently durable signed outbox, not sign again");
    assert.equal(event.journalType, "webdav-mutation");
    assert.ok(["put", "move"].includes(event.kind));
    if (event.kind === "put") {
      assert.equal(event.destination, SOURCE);
      assert.equal(event.existed, false);
    } else {
      assert.equal(event.source, SOURCE);
      assert.equal(event.destination, DESTINATION);
    }
    const verb = event.kind === "put" ? "create" : "move";
    const relative = event.kind === "put" ? SOURCE.slice(1) : DESTINATION.slice(1);
    const operationId = (verb === "move" ? "webdavsolo-" : "webdav-") + event.operationId + "-" +
      digest(verb + ":" + relative).slice(0, 24);
    const metadata = { path: relative };
    if (verb === "create") metadata.size = ORIGINAL.length;
    else metadata.sourcePath = SOURCE.slice(1);
    const signed = protocol.createOperation({
      operation: verb, operationId,
      objectId: "poison-object", fileId: "poison-file",
      versionId: crypto.randomUUID(), deviceId: "device-a",
      keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: state.signed.length + 1, deviceId: "device-a" },
      metadata,
      plaintext: verb === "move"
        ? protocol.encodeMovePayload(ORIGINAL, fileKey) : ORIGINAL,
      fileKey,
    });
    signed.authorization = await createAuthorizationProof(signed, {
      username: "alice", privateKey: keys.privateKey, publicKey,
      expiresAt: Date.now() + 120000,
    });
    state.events.push(clone(event));
    state.signed.push(clone(signed));
    return signed;
  };
  async function start() {
    const journal = await new SyncJournal(localPath).open();
    const outbox = await new SyncJournal(outboxPath).open();
    const bridge = new LocalSyncWebDavBridge({
      rootDir: root, port: 0, token: TOKEN,
      journal, protocolJournal: outbox, requireSignedProtocolIngress: true,
      toProtocolOperation: translate, trustedProtocolPolicy: policy,
      resolveProtectedFileKey: async (operation) => {
        assert.equal(operation.fileId, "poison-file");
        return fileKey;
      },
    });
    state.bridges.push(bridge);
    await bridge.start();
    state.active = bridge;
    state.journal = journal;
    state.outbox = outbox;
    return bridge;
  }
  async function stop() {
    if (!state.active) return;
    await state.active.stop();
    state.active = null;
  }
  t.after(async () => {
    await Promise.allSettled(state.bridges.map((bridge) => bridge.stop()));
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  return { parent, root, localPath, outboxPath, fileKey, state,
    start, stop, policy };
}

async function prepareRealDurableMove(f) {
  const bridge = await f.start();
  const port = bridge.address().port;
  const created = await httpRequest(port, "PUT", SOURCE, ORIGINAL);
  assert.equal(created.status, 201, created.body.toString("utf8"));
  const source = path.join(f.root, SOURCE.slice(1));
  const sourceIdentity = exactInode(source);
  assert.deepEqual(fs.readFileSync(source), ORIGINAL);
  // Induce only a lost final local ACK. Outbox persistence, encryption,
  // Ed25519 verification and physical MOVE must all run normally.
  const originalMarkSeen = f.state.journal.markSeen.bind(f.state.journal);
  let interrupted = 0;
  f.state.journal.markSeen = async (id, ...args) => {
    if (f.state.events.some((event) => event.kind === "move" && event.operationId === id)) {
      interrupted++;
      throw Error("intentional lost ACK AFTER signed outbox fsync");
    }
    return originalMarkSeen(id, ...args);
  };
  try {
    const moved = await httpRequest(port, "MOVE", SOURCE, null, {
      destination: "http://127.0.0.1:" + port + DESTINATION, overwrite: "F",
    });
    assert.equal(moved.status, 201, moved.body.toString("utf8"));
  } finally {
    f.state.journal.markSeen = originalMarkSeen;
  }
  assert.equal(interrupted, 1, "real HTTP MOVE must reach the lost-ACK boundary");
  assert.deepEqual(f.state.events.map((event) => event.kind), ["put", "move"]);
  assert.equal(f.state.signed.length, 2);
  const target = path.join(f.root, DESTINATION.slice(1));
  assert.equal(fs.existsSync(source), false);
  sameInode(exactInode(target), sourceIdentity);
  assert.deepEqual(fs.readFileSync(target), ORIGINAL);
  const local = await new SyncJournal(f.localPath).open();
  const outbox = await new SyncJournal(f.outboxPath).open();
  const pending = await local.recover();
  assert.equal(pending.length, 1);
  const move = pending[0];
  assert.equal(move.kind, "move");
  assert.equal(move.phase, "protocol-queued");
  assert.deepEqual(move.sourceIdentity, { dev: String(sourceIdentity.dev),
    ino: String(sourceIdentity.ino), type: "file" });
  assert.equal(move.moveBytes, ORIGINAL.length);
  assert.equal(move.moveSha256, digest(ORIGINAL));
  assert.equal(move.signedOutboxReceipts.length, 1);
  const signed = (await outbox.recover()).find((event) => event.operation === "move");
  assert.ok(signed, "independent durable outbox must contain the real signed MOVE");
  assert.deepEqual(signed, f.state.signed[1]);
  const receipt = move.signedOutboxReceipts[0];
  assert.equal(receipt.operationId, signed.operationId);
  assert.equal(receipt.digest, digest(protocol.canonicalJson(signed)));
  assert.equal(outbox.durableSignedReceiptDigest(signed.operationId), receipt.digest);
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.policy()), true,
    "signature must verify against independently pinned Ed25519 device key");
  const signedBytes = protocol.decodeMovePayload(
    protocol.decryptPayload(signed, f.fileKey), f.fileKey);
  assert.deepEqual(signedBytes, ORIGINAL,
    "independent signed ciphertext must authenticate ORIGINAL MOVE content");
  await f.stop();
  return { target, sourceIdentity, move, signed, signedBytes,
    outboxBytes: await fsp.readFile(f.outboxPath) };
}

test("RED: same-inode MOVE content and local-only hash witness poisoned; signed outbox must reject recovery", {
  timeout: 120000,
}, async (t) => {
  const f = await setup(t);
  const proof = await prepareRealDurableMove(f);
  const poison = Buffer.from(ORIGINAL);
  poison[0] ^= 0x5a;
  assert.equal(poison.length, ORIGINAL.length);
  assert.notDeepEqual(poison, proof.signedBytes);
  const handle = await fsp.open(proof.target, "r+");
  try {
    const written = await handle.write(poison, 0, poison.length, 0);
    assert.equal(written.bytesWritten, poison.length);
    await handle.sync();
  } finally { await handle.close(); }
  sameInode(exactInode(proof.target), proof.sourceIdentity);
  assert.deepEqual(fs.readFileSync(proof.target), poison);

  // Independent stolen local-only journal control, committed through the
  // normal fsync-backed SyncJournal transaction machinery. Neither receipt
  // IDs/digests nor immutable Ed25519 ciphertext/outbox are modified.
  const attackerJournal = await new SyncJournal(f.localPath).open();
  await attackerJournal.update(proof.move.operationId, {
    moveBytes: poison.length, moveSha256: digest(poison),
  });
  const poisonedLocal = await new SyncJournal(f.localPath).open();
  const poisonedPending = (await poisonedLocal.recover())[0];
  assert.equal(poisonedPending.phase, "protocol-queued");
  assert.equal(poisonedPending.moveBytes, poison.length);
  assert.equal(poisonedPending.moveSha256, digest(poison));
  assert.deepEqual(poisonedPending.sourceIdentity, proof.move.sourceIdentity);
  assert.deepEqual(poisonedPending.signedOutboxReceipts, proof.move.signedOutboxReceipts);
  assert.notEqual(digest(poison), digest(proof.signedBytes),
    "forged local witness is self-consistent but disagrees with signed decrypted MOVE");
  assert.equal((await fsp.readFile(f.outboxPath)).equals(proof.outboxBytes), true);
  const localBeforeRestart = await fsp.readFile(f.localPath);

  f.state.revoked = true;
  f.state.forbidTranslation = true;
  const translationsBefore = f.state.translatorReads;
  // Source under review currently checks attacker-controlled moveSha256
  // against the changed inode, then treats the unrelated signed receipt as
  // sufficient. Expected RED until recovery independently decrypts the
  // durable MOVE envelope and compares its exact plaintext witness.
  await assert.rejects(f.start(), (error) => {
    assert.equal(error?.code, "WEBDAV_RECOVERY_INDETERMINATE",
      "must fail for SIGNED content mismatch, not unrelated HTTP/startup errors");
    assert.match(error.message, /(?:move|signed|content|outbox|witness)/i);
    return true;
  });
  assert.equal(f.state.translatorReads, translationsBefore,
    "revoked recovery must not create a fresh signature or protocol operation");
  const diskAfter = await new SyncJournal(f.localPath).open();
  assert.equal(diskAfter.hasSeen(proof.move.operationId), false);
  assert.deepEqual(await diskAfter.recover(), [poisonedPending],
    "failed recovery must retain exact attacker-local evidence for investigation");
  assert.equal((await fsp.readFile(f.localPath)).equals(localBeforeRestart), true);
  assert.equal((await fsp.readFile(f.outboxPath)).equals(proof.outboxBytes), true);
  sameInode(exactInode(proof.target), proof.sourceIdentity);
  assert.deepEqual(fs.readFileSync(proof.target), poison);
});

test("positive revoked replay: valid signed MOVE preserves original inode, exactly once, without reauthorization", {
  timeout: 120000,
}, async (t) => {
  const f = await setup(t);
  const proof = await prepareRealDurableMove(f);
  const translationsBefore = f.state.translatorReads;
  const policyBefore = f.state.policyReads;
  f.state.revoked = true;
  f.state.forbidTranslation = true;
  const restarted = await f.start();
  assert.ok(restarted.address()?.port > 0);
  assert.equal(f.state.translatorReads, translationsBefore,
    "replay must not mint a second signed operation");
  assert.equal(f.state.policyReads, policyBefore + 1,
    "historical MOVE requires read-only pinned key verification, never a fresh grant");
  sameInode(exactInode(proof.target), proof.sourceIdentity);
  assert.deepEqual(fs.readFileSync(proof.target), ORIGINAL);
  const local = await new SyncJournal(f.localPath).open();
  assert.deepEqual(await local.recover(), []);
  assert.equal(local.hasSeen(proof.move.operationId), true);
  const outbox = await new SyncJournal(f.outboxPath).open();
  assert.deepEqual((await outbox.recover()).find((item) =>
    item.operation === "move"), proof.signed);
  assert.equal((await fsp.readFile(f.outboxPath)).equals(proof.outboxBytes), true,
    "replaying a revoked historical receipt must not rewrite signed bytes");
  const response = await httpRequest(restarted.address().port, "GET", DESTINATION);
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, ORIGINAL);
});
