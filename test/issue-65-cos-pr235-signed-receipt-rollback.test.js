"use strict";

// Signed cross-journal recovery. TEST_UNRUN: exclusive Node22 gate closed.
// These tests use genuine Ed25519/AES-GCM envelopes, physical PUT publication,
// and two fsync-backed journals. Deliberate phase/receipt fault injection is
// identified as such; it is not an assertion that a power failure occurred.
// This test does not prove production enables strict ingress, or that a remote
// authority atomically fences revocations.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const BYTES = Buffer.from("AUTHORIZED_PHYSICAL_PUT_SAME_DEVICE_SIGNED_RECEIPT");
const LIMIT = 45_000;
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const receipt = (signed) => ({
  operationId: signed.operationId, digest: sha(protocol.canonicalJson(signed)),
});
const disk = (file) => new SyncJournal(file).open();

function physicalIdentity(stat) {
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.nlink, 1n);
  assert.ok(stat.ino > 0n);
  return { dev: String(stat.dev), ino: String(stat.ino), type: "file" };
}

async function fixture(t) {
  const parent = createPrivateAuthorityFixture("cos-pr235-receipt-");
  const root = path.join(parent, "private");
  fs.mkdirSync(root, { mode: 0o700 });
  t.after(async () => {
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  const mutationPath = path.join(parent, "mutation.json");
  const outboxPath = path.join(parent, "outbox.json");
  const mutation = await disk(mutationPath);
  const outbox = await disk(outboxPath);
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const fileKey = crypto.randomBytes(32);
  const pathname = "/physical.txt";
  const target = path.join(root, "physical.txt");
  const operationId = "receipt-" + crypto.randomUUID();
  const event = {
    journalType: "webdav-mutation", operationId, kind: "put",
    path: pathname, source: pathname, destination: pathname,
    existed: false, trash: null, previousIdentity: null,
    putBytes: BYTES.length, putSha256: sha(BYTES), phase: "prepared",
  };
  await mutation.enqueue(event);
  assert.deepEqual((await disk(mutationPath)).pending(), [event]);
  const staging = path.join(root, ".rootark-put-receipt-prepared");
  const handle = await fsp.open(staging, "wx", 0o600);
  try { await handle.writeFile(BYTES); await handle.sync(); }
  finally { await handle.close(); }
  const physicalStaged = await fsp.lstat(staging, { bigint: true });
  await fsp.link(staging, target);
  await fsp.unlink(staging);
  const installed = await fsp.lstat(target, { bigint: true });
  assert.equal(installed.dev, physicalStaged.dev);
  assert.equal(installed.ino, physicalStaged.ino);
  assert.deepEqual(await fsp.readFile(target), BYTES);
  const installedIdentity = physicalIdentity(installed);
  await mutation.update(operationId, { phase: "source-moved", installedIdentity });
  const onDiskEvent = (await disk(mutationPath)).pending()[0];
  assert.equal(onDiskEvent.phase, "source-moved");
  assert.deepEqual(onDiskEvent.installedIdentity, installedIdentity);
  const signedId = "webdav-" + operationId + "-" + sha("create:physical.txt").slice(0, 24);

  async function sign(plaintext = BYTES, expiresAt = Date.now() + 120_000) {
    const operation = protocol.createOperation({
      operation: "create", operationId: signedId,
      objectId: "receipt-object", fileId: "receipt-file",
      versionId: crypto.randomUUID(), deviceId: "device-a",
      keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: "physical.txt", size: BYTES.length },
      plaintext, fileKey,
    });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", publicKey, privateKey: pair.privateKey, expiresAt,
    });
    return operation;
  }
  const signed = await sign();
  async function verifySigned(operation) {
    return verifyAuthorizationProof(operation.authorization, operation, {
      username: "alice",
      trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: [],
    });
  }
  assert.equal(await verifySigned(signed), true,
    "fixture must use real Ed25519 authorization, not decorative signature fields");
  const state = { revoked: false, policyReads: 0, translations: 0 };
  function policy() {
    state.policyReads += 1;
    return { username: "alice",
      trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: state.revoked ? ["device-a"] : [] };
  }
  function bridge(journal, protocolJournal, translate = async () => signed) {
    return new LocalSyncWebDavBridge({
      rootDir: root, token: "signed-receipt-test-private-only",
      journal, protocolJournal, requireSignedProtocolIngress: true,
      trustedProtocolPolicy: policy, resolveProtectedFileKey: async () => fileKey,
      toProtocolOperation: async (eventRecord) => {
        state.translations += 1;
        return translate(eventRecord);
      },
    });
  }
  async function reopen() {
    return { mutation: await disk(mutationPath), outbox: await disk(outboxPath) };
  }
  async function evidence() {
    return { mutationBytes: await fsp.readFile(mutationPath),
      outboxBytes: await fsp.readFile(outboxPath),
      content: await fsp.readFile(target),
      installed: physicalIdentity(await fsp.lstat(target, { bigint: true })) };
  }
  return { parent, root, target, mutationPath, outboxPath, mutation, outbox,
    event: onDiskEvent, signed, signedId, sign, verifySigned,
    state, bridge, reopen, evidence };
}

async function exactAdmission(f) {
  const incoming = f.bridge(f.mutation, f.outbox);
  assert.equal(await incoming.enqueueProtocol(f.event), true);
  const pair = await f.reopen();
  const pending = pair.mutation.pending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].phase, "source-moved",
    "a real outbox ACK can precede the physical journal's protocol-queued write");
  assert.deepEqual(pending[0].signedOutboxReceipts, [receipt(f.signed)],
    "local receipt must derive from the exact verified signature and ciphertext");
  assert.equal(pair.outbox.durableSignedReceiptDigest(f.signedId), receipt(f.signed).digest);
  assert.deepEqual(pair.outbox.pending(), [f.signed],
    "signed envelope must survive a distinct disk journal reopen");
  return pair;
}

async function assertDeniedUnchanged(f, action, match) {
  const before = await f.evidence();
  const phase = (await disk(f.mutationPath)).pending()[0];
  await assert.rejects(action, match);
  const after = await f.evidence();
  assert.deepEqual(after, before,
    "denial must preserve signed outbox, mutation journal and physical bytes");
  assert.deepEqual((await disk(f.mutationPath)).pending(), [phase]);
}

test("genuine signed outbox fsync with lost local ACK safely recovers under revoked policy", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await exactAdmission(f);
  // This is the precise post-outbox/pre-mutation-ACK fault boundary, with
  // genuine signed outbox bytes persisted, not a fabricated seen-only flag.
  await f.mutation.update(f.event.operationId, { phase: "protocol-queued" });
  const first = await f.reopen();
  assert.equal(first.mutation.pending()[0].phase, "protocol-queued");
  f.state.revoked = true;
  const reads = f.state.policyReads;
  const translations = f.state.translations;
  const restarted = f.bridge(first.mutation, first.outbox,
    async () => { throw new Error("no fresh signing allowed for durable replay"); });
  await restarted.recoverPending();
  assert.equal(f.state.policyReads, reads,
    "only identical prior committed envelope bypasses the fresh policy lookup");
  assert.equal(f.state.translations, translations);
  const after = await f.reopen();
  assert.deepEqual(after.mutation.pending(), []);
  assert.equal(after.mutation.hasSeen(f.event.operationId), true);
  assert.deepEqual(after.outbox.pending(), [f.signed]);
  assert.deepEqual(await fsp.readFile(f.target), BYTES);
  await f.bridge(after.mutation, after.outbox).recoverPending();
  assert.deepEqual((await disk(f.outboxPath)).pending(), [f.signed],
    "later recovery cannot replay an already acknowledged signed envelope");
});

test("source-moved with genuine persisted outbox and receipt is recovered without claiming protocol-queued", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await exactAdmission(f);
  f.state.revoked = true;
  const priorReads = f.state.policyReads;
  await f.bridge((await f.reopen()).mutation, (await f.reopen()).outbox,
    () => { throw new Error("never translate already signed outbox"); }).recoverPending();
  const after = await f.reopen();
  assert.equal(f.state.policyReads, priorReads);
  assert.deepEqual(after.mutation.pending(), []);
  assert.equal(after.mutation.hasSeen(f.event.operationId), true);
  assert.deepEqual(after.outbox.pending(), [f.signed]);
});

test("protocol-queued claim with no durable signed outbox cannot be promoted by a stale policy", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await f.mutation.update(f.event.operationId, { phase: "protocol-queued" });
  const pair = await f.reopen();
  f.state.revoked = true;
  const reads = f.state.policyReads;
  await assertDeniedUnchanged(f, () => f.bridge(pair.mutation, pair.outbox).recoverPending(),
    { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.equal(f.state.policyReads, reads,
    "asserted committed phase without receipt must fail before translator/policy");
  assert.equal(f.state.translations, 0);
  assert.deepEqual((await disk(f.outboxPath)).pending(), []);
});

test("stale revocation after durable local receipt but before outbox commit denies and leaves recoverable evidence", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  const originalUpdate = f.mutation.update.bind(f.mutation);
  let crossedReceiptBoundary = 0;
  f.mutation.update = async (id, patch) => {
    await originalUpdate(id, patch);
    if (Object.hasOwn(patch, "signedOutboxReceipts")) {
      crossedReceiptBoundary += 1;
      assert.deepEqual((await disk(f.mutationPath)).pending()[0].signedOutboxReceipts,
        [receipt(f.signed)], "local receipt must really hit disk before revocation");
      f.state.revoked = true;
    }
  };
  const started = f.bridge(f.mutation, f.outbox);
  await assert.rejects(() => started.enqueueProtocol(f.event), { code: "authorization_rejected" });
  assert.equal(crossedReceiptBoundary, 1);
  const pair = await f.reopen();
  assert.deepEqual(pair.mutation.pending()[0].signedOutboxReceipts, [receipt(f.signed)]);
  assert.deepEqual(pair.outbox.pending(), [], "no unapproved outbox after fresh revocation");
  assert.equal(pair.outbox.hasDurableSignedReceipt(f.signedId), false);
  assert.deepEqual(await fsp.readFile(f.target), BYTES);
  // Still revoked: no false ACK or unverified fresh re-authorization.
  await assertDeniedUnchanged(f, () => f.bridge(pair.mutation, pair.outbox).recoverPending(),
    { code: "authorization_rejected" });
  assert.equal((await disk(f.mutationPath)).pending().length, 1);
});

test("same signed operationId with a second valid Ed25519 envelope cannot replace a pending or seen outbox", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await exactAdmission(f);
  const alternate = await f.sign();
  assert.equal(await f.verifySigned(alternate), true,
    "colliding envelope must be independently VALID before journal rejects it");
  assert.equal(alternate.operationId, f.signedId);
  assert.notEqual(receipt(alternate).digest, receipt(f.signed).digest,
    "the second fully signed encryption must contain different canonical bytes");
  await assertDeniedUnchanged(f, () => f.outbox.enqueue(alternate),
    { code: "sync_journal_operation_conflict" });
  assert.deepEqual((await disk(f.outboxPath)).pending(), [f.signed]);
  await f.outbox.markSeen(f.signedId);
  const acknowledged = await disk(f.outboxPath);
  assert.deepEqual(acknowledged.pending(), []);
  assert.equal(acknowledged.durableSignedReceiptDigest(f.signedId), receipt(f.signed).digest,
    "committed signed envelope digest survives pending-to-seen");
  const before = await f.evidence();
  await assert.rejects(() => acknowledged.enqueue(alternate),
    { code: "sync_journal_operation_conflict" });
  await assert.rejects(() => acknowledged.enqueue({
    operationId: f.signedId, operation: "create", metadata: { path: "physical.txt" },
  }), { code: "sync_journal_operation_conflict" });
  assert.deepEqual(await f.evidence(), before,
    "signed operation cannot be replaced by valid alternative or unsigned collision");
  f.state.revoked = true;
  const pair = await f.reopen();
  await f.bridge(pair.mutation, pair.outbox, () => {
    throw new Error("seen exact signed outbox must not be retranslated");
  }).recoverPending();
  assert.deepEqual((await disk(f.mutationPath)).pending(), []);
  assert.equal((await disk(f.outboxPath)).durableSignedReceiptDigest(f.signedId),
    receipt(f.signed).digest);
});

test("outbox replaced by internally consistent different VALID signed envelope with same ID must not ACK original mutation", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await exactAdmission(f);
  const alternate = await f.sign();
  assert.equal(await f.verifySigned(alternate), true,
    "attack must present a valid Ed25519 envelope, not an invalid signature");
  assert.equal(alternate.operationId, f.signedId);
  assert.notEqual(receipt(alternate).digest, receipt(f.signed).digest);
  const raw = JSON.parse(await fsp.readFile(f.outboxPath, "utf8"));
  assert.equal(raw.pending.length, 1);
  assert.deepEqual(raw.pending[0], f.signed);
  assert.equal(raw.committedSigned[f.signedId], receipt(f.signed).digest);
  // Deliberate hostile disk rollback/substitution, not an authorized second
  // enqueue. Both the signed envelope AND its local outbox digest are changed
  // together, so an outbox-only integrity check would produce a false GREEN.
  raw.pending[0] = alternate;
  raw.committedSigned[f.signedId] = receipt(alternate).digest;
  const handle = await fsp.open(f.outboxPath, "r+");
  try {
    await handle.truncate(0);
    await handle.writeFile(JSON.stringify(raw) + "\n", "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  const outbox = await disk(f.outboxPath);
  assert.deepEqual(outbox.pending(), [alternate]);
  assert.equal(outbox.durableSignedReceiptDigest(f.signedId), receipt(alternate).digest,
    "attacker's outbox must be internally self-consistent, not rejected at parse");
  const pair = await f.reopen();
  f.state.revoked = true;
  const reads = f.state.policyReads;
  await assertDeniedUnchanged(f, () => f.bridge(pair.mutation, pair.outbox).recoverPending(),
    { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.equal(f.state.policyReads, reads,
    "a mismatched committed phase cannot ask stale policy to reauthorize");
  assert.equal(f.state.translations, 1,
    "only original admission may have translated, recovery must not retry");
  assert.deepEqual((await disk(f.mutationPath)).pending()[0].signedOutboxReceipts,
    [receipt(f.signed)], "independent local witness must not be overwritten");
});

for (const poison of [
  { label: "different valid SHA digest", change: (f) => [{
    operationId: f.signedId, digest: sha("SAME_OPERATION_ID_DIFFERENT_AUTHORIZED_BYTES"),
  }] },
  { label: "different signed operationId", change: (f) => [{
    operationId: "other-accepted-looking-operation", digest: receipt(f.signed).digest,
  }] },
]) {
  test("protocol-queued recovery refuses " + poison.label + " even with real signed outbox", {
    timeout: LIMIT,
  }, async (t) => {
    const f = await fixture(t);
    await exactAdmission(f);
    await f.mutation.update(f.event.operationId, { phase: "protocol-queued",
      signedOutboxReceipts: poison.change(f) });
    const pair = await f.reopen();
    f.state.revoked = true;
    const observations = f.state.policyReads;
    await assertDeniedUnchanged(f, () => f.bridge(pair.mutation, pair.outbox).recoverPending(),
      { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    assert.equal(f.state.policyReads, observations);
    assert.deepEqual((await disk(f.outboxPath)).pending(), [f.signed],
      "bad local witness must never erase signed outbox evidence");
  });
}

test("legacy local mutation with no signedOutboxReceipts cannot claim prior signed outbox commit", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await exactAdmission(f);
  const original = (await disk(f.mutationPath)).pending()[0];
  const { signedOutboxReceipts: _removed, ...legacy } = original;
  await f.mutation.replace(f.event.operationId, {
    ...legacy, phase: "protocol-queued",
  });
  const pair = await f.reopen();
  assert.equal(Object.hasOwn(pair.mutation.pending()[0], "signedOutboxReceipts"), false);
  f.state.revoked = true;
  const reads = f.state.policyReads;
  await assertDeniedUnchanged(f, () => f.bridge(pair.mutation, pair.outbox).recoverPending(),
    { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.equal(f.state.policyReads, reads);
  assert.deepEqual((await disk(f.outboxPath)).pending(), [f.signed]);
});

test("SyncJournal refuses malformed cross-journal receipt lists before durable mutation", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await exactAdmission(f);
  const original = await f.evidence();
  for (const malformed of [null, [], [receipt(f.signed), receipt(f.signed)],
    [{ operationId: f.signedId, digest: "INVALID_SHA256" }],
    Array.from({ length: 5 }, (_, index) => ({
      operationId: "unexpected-" + index, digest: sha("receipt-" + index),
    })),
  ]) {
    await assert.rejects(
      () => f.mutation.update(f.event.operationId, { signedOutboxReceipts: malformed }),
      /Invalid protected WebDAV signed receipt binding/);
    assert.deepEqual(await f.evidence(), original,
      "invalid receipt format must never alter durable journal or physical bytes");
  }
});

test("outbox-only historical seen ID with no signed digest cannot authorize protocol-queued recovery", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await f.mutation.update(f.event.operationId, {
    phase: "protocol-queued", signedOutboxReceipts: [receipt(f.signed)],
  });
  await f.outbox.markSeen(f.signedId);
  const historical = await disk(f.outboxPath);
  assert.equal(historical.hasSeen(f.signedId), true);
  assert.equal(historical.hasDurableSignedReceipt(f.signedId), false,
    "historical ID-only ACK is not a cryptographic envelope receipt");
  const pair = await f.reopen();
  f.state.revoked = true;
  await assertDeniedUnchanged(f, () => f.bridge(pair.mutation, pair.outbox).recoverPending(),
    { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.deepEqual((await disk(f.mutationPath)).pending().map((entry) => entry.operationId),
    [f.event.operationId]);
});

test("prepared crash without physical installation cannot acquire an outbox receipt from stale signature", {
  timeout: LIMIT,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-prepared-");
  t.after(() => fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 }));
  const root = path.join(parent, "private");
  fs.mkdirSync(root, { mode: 0o700 });
  const localPath = path.join(parent, "local.json");
  const outboxPath = path.join(parent, "outbox.json");
  const local = await disk(localPath);
  const outbox = await disk(outboxPath);
  const event = {
    operationId: "prepared-" + crypto.randomUUID(), journalType: "webdav-mutation",
    kind: "put", source: "/not-installed.txt", destination: "/not-installed.txt",
    path: "/not-installed.txt", existed: false, trash: null, phase: "prepared",
    putBytes: BYTES.length, putSha256: sha(BYTES),
  };
  await local.enqueue(event);
  assert.equal(fs.existsSync(path.join(root, "not-installed.txt")), false);
  let translations = 0;
  const b = new LocalSyncWebDavBridge({
    rootDir: root, token: "prepared-receipt-test-only",
    journal: await disk(localPath), protocolJournal: await disk(outboxPath),
    requireSignedProtocolIngress: true,
    trustedProtocolPolicy: () => { throw new Error("stale policy must not be invoked"); },
    resolveProtectedFileKey: async () => { throw new Error("no protected bytes installed"); },
    toProtocolOperation: () => { translations += 1; throw new Error("no protocol enqueue"); },
  });
  await b.recoverPending();
  assert.equal(translations, 0);
  const after = await disk(localPath);
  assert.deepEqual(after.pending(), []);
  assert.equal(after.hasSeen(event.operationId), true,
    "non-applied prepared mutation is an aborted local operation, not a remote ACK");
  assert.deepEqual((await disk(outboxPath)).pending(), []);
  assert.equal(fs.existsSync(path.join(root, "not-installed.txt")), false);
});

test("prepared phase relabelled after physical installation is indeterminate despite byte and inode match", {
  timeout: LIMIT,
}, async (t) => {
  const f = await fixture(t);
  await f.mutation.update(f.event.operationId, { phase: "prepared" });
  const pair = await f.reopen();
  f.state.revoked = true;
  await assertDeniedUnchanged(f, () => f.bridge(pair.mutation, pair.outbox).recoverPending(),
    { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.equal(f.state.translations, 0);
  assert.deepEqual((await disk(f.outboxPath)).pending(), []);
});
