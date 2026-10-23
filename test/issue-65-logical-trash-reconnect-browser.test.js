"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const file = require("../public/client/rootark-zk1-file-content");
const trash = require("../public/client/rootark-zk1-client-logical-trash");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest();
const enc = new TextEncoder();

test("browser reconnect rejects stale CAS, wrong archived CEK, changed session and leaves journal intact", async () => {
  const scope = { account_id: b64(crypto.randomBytes(16)),
    compartment_id: b64(Buffer.from("private")), keyring_id: b64(crypto.randomBytes(16)) };
  const objectId = b64(crypto.randomBytes(16));
  const source = { ...scope, object_id: objectId, version_id: b64(crypto.randomBytes(16)),
    parent_version_id: null, epoch: 1, kind: "file" };
  const target = { ...source, version_id: b64(crypto.randomBytes(16)),
    parent_version_id: source.version_id };
  const secret = async () => crypto.webcrypto.subtle.importKey("raw", crypto.randomBytes(32),
    "AES-GCM", false, ["encrypt", "decrypt"]);
  const sourceCek = await secret(), targetCek = await secret();
  const sourceBytes = new Uint8Array(await file.encryptFile({ cek: sourceCek,
    metadata: source, name: "private.bin", mediaType: "application/octet-stream",
    data: enc.encode("source plaintext must never enter the journal") }));
  const prior = { revision: 1, ciphertextDigest: b64(hash(sourceBytes)),
    versionId: source.version_id };
  const iv = crypto.randomBytes(12);
  const encrypted = await crypto.webcrypto.subtle.encrypt({ name: "AES-GCM", iv,
    additionalData: enc.encode("Root.ark/zk-1/logical-trash-aead/v1\0"
      + JSON.stringify(target) + "\0" + JSON.stringify(prior)), tagLength: 128,
  }, targetCek, enc.encode('{"state":"trashed","retention":"unknown"}'));
  const targetBytes = enc.encode(JSON.stringify({ format: "rootark-zk1-logical-trash/v1",
    metadata: target, predecessor: prior, nonce: b64(iv), ciphertext: b64(encrypted) }));
  const digest = crypto.randomBytes(32), journalId = b64(crypto.randomBytes(32));
  const snapshot = { head: { sequence: 2, digest }, rows: [
    { object_id: objectId, revision: 1, epoch: 1, ciphertext_digest: hash(sourceBytes) },
    { object_id: objectId, revision: 2, epoch: 1, ciphertext_digest: hash(targetBytes) },
  ] };
  let session = true, clears = 0, signedGets = 0, puts = 0;
  const catalogWriter = {
    async readAll() { return snapshot; },
    async readVerifiedCiphertext(_snapshot, id, revision) {
      signedGets++;
      assert.equal(_snapshot, snapshot);
      assert.equal(id, objectId);
      return { objectId, revision, epoch: 1,
        ciphertextBase64: b64(revision === 1 ? sourceBytes : targetBytes) };
    },
    async confirmPendingIntent(id) { assert.equal(id, journalId); clears++; return true; },
    async commit() { puts++; throw Error("MUST_NOT_REPLAY"); },
  };
  const readArchivedCek = async ({ objectId: id, revision, nonce, versionId }) => {
    assert.equal(id, objectId);
    if (nonce !== journalId || versionId !== (revision === 1 ? source : target).version_id)
      throw Error("UNVERIFIED_ARCHIVE_NONCE");
    return revision === 1 ? sourceCek : targetCek;
  };
  const input = () => ({ catalogWriter, journalId,
    pinnedCatalogHead: { sequence: 2, digest: b64(digest) },
    sourceMetadata: source, destinationMetadata: target,
    sourceRevision: 1, destinationRevision: 2, readArchivedCek,
    assertLive: () => { if (!session) throw Error("LOGOUT"); } });
  await assert.rejects(trash.reconcileCommittedTrash({ ...input(),
    pinnedCatalogHead: { sequence: 1, digest: b64(crypto.randomBytes(32)) } }),
  /ZK_LOGICAL_TRASH_DENIED/);
  await assert.rejects(trash.reconcileCommittedTrash({ ...input(),
    readArchivedCek: async ({ revision }) => revision === 2 ? secret() : sourceCek }),
  /ZK_LOGICAL_TRASH_DENIED/);
  session = false;
  await assert.rejects(trash.reconcileCommittedTrash(input()), /ZK_LOGICAL_TRASH_DENIED/);
  assert.equal(clears, 0, "unverified or logged-out reconnection retains the signed journal");
  session = true;
  await assert.rejects(trash.reconcileCommittedTrash({ ...input(),
    catalogWriter: { ...catalogWriter,
      async readVerifiedCiphertext(...args) {
        const result = await catalogWriter.readVerifiedCiphertext(...args);
        if (args[2] === 2) session = false;
        return result;
      },
    },
  }), /ZK_LOGICAL_TRASH_DENIED/,
  "session revoked after signed GET cannot clear pending journal");
  assert.equal(clears, 0);
  session = true;
  const verified = await trash.reconcileCommittedTrash(input());
  assert.equal(verified.state, "trashed");
  assert.equal(verified.signedCatalogCommitVerified, true);
  assert.equal(verified.productionDurabilityProven, false);
  assert.equal(clears, 1);
  assert.ok(signedGets >= 2);
  assert.equal(puts, 0, "reconnection cannot issue another PUT or CAS");
});
