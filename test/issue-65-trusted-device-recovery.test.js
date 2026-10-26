"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const fileCrypto = require("../public/client/rootark-dev-vault-crypto");
const recovery = require("../public/client/rootark-dev-vault-trusted-device");

test("an enrolled trusted browser independently authorizes a new browser without password or server KDF", async () => {
  const existing = await fileCrypto.generateRecoveryKey();
  const keyId = await fileCrypto.keyCommitment(existing.recoveryKey, "alice");
  const enrolled = await recovery.enrollTrustedDevice({
    username: "alice", recoveryKey: existing.recoveryKey, keyId,
  });
  assert.equal(enrolled.wrappingKey.extractable, false);
  assert.equal(enrolled.wrappingKey.algorithm.name, "AES-GCM");
  assert.ok(!JSON.stringify({ ...enrolled, wrappingKey: null }).includes(existing.recoveryKey));

  const pending = await recovery.createRecoveryRequest({ username: "alice" });
  assert.equal(pending.privateKey.extractable, false);
  const answer = await recovery.approveRecoveryRequest({
    username: "alice", record: enrolled, request: pending.request,
  });
  assert.equal(answer.keyId, keyId);
  assert.ok(!JSON.stringify(answer).includes(existing.recoveryKey));
  const restored = await recovery.completeRecoveryRequest({
    username: "alice", privateKey: pending.privateKey, request: pending.request, answer,
  });
  assert.equal(restored.keyId, keyId);
  assert.equal(await fileCrypto.keyCommitment(restored.recoveryKey, "alice"), keyId);
  const openedKey = await fileCrypto.importRecoveryKey(restored.recoveryKey);
  const id = crypto.randomBytes(16).toString("base64url");
  const envelope = await fileCrypto.encryptFile({
    key: existing.key, username: "alice", id, name: "opaque.txt",
    mediaType: "text/plain", data: new TextEncoder().encode("saved"),
  });
  const opened = await fileCrypto.decryptFile({
    key: openedKey, username: "alice", id, envelope,
  });
  assert.equal(new TextDecoder().decode(opened.data), "saved");
});

test("device response is bound to exact request, account, ephemeral secret and ciphertext", async () => {
  const existing = await fileCrypto.generateRecoveryKey();
  const keyId = await fileCrypto.keyCommitment(existing.recoveryKey, "alice");
  const record = await recovery.enrollTrustedDevice({
    username: "alice", recoveryKey: existing.recoveryKey, keyId,
  });
  const pending = await recovery.createRecoveryRequest({ username: "alice" });
  const other = await recovery.createRecoveryRequest({ username: "alice" });
  const answer = await recovery.approveRecoveryRequest({
    username: "alice", record, request: pending.request,
  });
  for (const attempt of [
    { username: "bob" },
    { request: other.request },
    { privateKey: other.privateKey },
    { answer: { ...answer, requestId: other.request.requestId } },
    { answer: { ...answer, keyId: crypto.randomBytes(32).toString("base64url") } },
    { answer: { ...answer, ciphertext: crypto.randomBytes(48).toString("base64url") } },
    { answer: { ...answer, extra: "forbidden" } },
  ]) {
    await assert.rejects(recovery.completeRecoveryRequest({
      username: "alice", request: pending.request, privateKey: pending.privateKey,
      answer, ...attempt,
    }));
  }
  await assert.rejects(recovery.approveRecoveryRequest({
    username: "bob", record, request: pending.request,
  }));
  await assert.rejects(recovery.approveRecoveryRequest({
    username: "alice", record, request: { ...pending.request, expiresAt: 1 },
  }));
});

test("device recovery request expires and record cannot silently be rebound to another account", async () => {
  const existing = await fileCrypto.generateRecoveryKey();
  const keyId = await fileCrypto.keyCommitment(existing.recoveryKey, "alice");
  const record = await recovery.enrollTrustedDevice({
    username: "alice", recoveryKey: existing.recoveryKey, keyId,
  });
  const pending = await recovery.createRecoveryRequest({ username: "alice" });
  await assert.rejects(recovery.approveRecoveryRequest({
    username: "alice", record: { ...record, username: "bob" }, request: pending.request,
  }));
  const answer = await recovery.approveRecoveryRequest({
    username: "alice", record, request: pending.request,
  });
  await assert.rejects(recovery.completeRecoveryRequest({
    username: "alice", privateKey: pending.privateKey, request: pending.request, answer,
    now: pending.request.expiresAt + 1,
  }));
});

test("human pairing fingerprint authenticates recipient public key, scope and expiry", async () => {
  const victim = await recovery.createRecoveryRequest({ username: "alice" });
  const attacker = await recovery.createRecoveryRequest({ username: "alice" });
  const authentic = await recovery.requestFingerprint({
    username: "alice", request: victim.request,
  });
  assert.match(authentic, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(authentic, await recovery.requestFingerprint({
    username: "alice", request: { ...victim.request },
  }));
  const substitution = { ...victim.request, publicKey: attacker.request.publicKey };
  const changed = await recovery.requestFingerprint({
    username: "alice", request: substitution,
  });
  assert.notEqual(changed, authentic,
    "substituted ECDH public key must change the out-of-band code even when request ID is preserved");
  assert.equal(recovery.confirmRequestFingerprint(changed, authentic), false);
  assert.equal(recovery.confirmRequestFingerprint(authentic, authentic), true);
  assert.equal(recovery.confirmRequestFingerprint("", authentic), false);
});
