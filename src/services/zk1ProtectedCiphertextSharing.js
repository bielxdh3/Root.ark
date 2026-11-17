"use strict";

// DEV-only: an owner-device-signed, recipient-account + recipient-device bound
// ciphertext grant. Key distribution is deliberately outside this API.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");

const DOMAIN = Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0", "ascii");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const ID = /^[A-Za-z0-9_-]{43}$/;
const USER = /^[A-Za-z0-9_.@-]{1,128}$/;
const DEVICE = /^[^\x00-\x1f\x7f]{1,64}$/;
const FIELDS = ["type", "grant_id", "account_id", "compartment_id", "keyring_id",
  "object_id", "object_revision", "ciphertext_digest", "epoch", "manifest_revision",
  "manifest_digest", "issuer_device_id", "request_nonce", "issued_at", "expires_at",
  "recipient_username", "recipient_device_id"];

function deny(code = "ZK_SHARE_DENIED") {
  throw Object.assign(new Error(code), { code });
}
function canonicalId(value) {
  if (typeof value !== "string" || !ID.test(value)) deny();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) deny();
  return value;
}
function bytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < min || value.length > max) deny();
  return Buffer.from(value);
}
function scopeKey(scope) {
  return bytes(scope.account_id, 16).toString("hex") + ":"
    + bytes(scope.compartment_id, 1, 128).toString("hex") + ":"
    + bytes(scope.keyring_id, 16).toString("hex");
}
function shareStatement(input) {
  const a = input.authorization;
  if (!a || typeof a !== "object" || a.operation !== "get"
    || typeof a.object_id !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(a.object_id)
    || Buffer.from(a.object_id, "base64url").toString("base64url") !== a.object_id
    || !Number.isSafeInteger(a.expected_object_revision) || a.expected_object_revision < 1
    || !Number.isSafeInteger(a.epoch) || a.epoch < 1
    || !Number.isSafeInteger(a.manifest_revision) || a.manifest_revision < 1
    || !Number.isSafeInteger(a.issued_at) || a.issued_at < 0
    || !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= a.issued_at
    || input.expiresAt > a.issued_at + 86400
    || !DEVICE.test(a.device_id) || !DEVICE.test(input.recipientDeviceId)
    || !USER.test(input.recipientUsername)) deny();
  return {
    type: "rootark-zk1-protected-ciphertext-share/v1",
    grant_id: Buffer.from(canonicalId(input.grantId), "base64url"),
    account_id: bytes(a.account_id, 16),
    compartment_id: bytes(a.compartment_id, 1, 128),
    keyring_id: bytes(a.keyring_id, 16),
    object_id: a.object_id,
    object_revision: a.expected_object_revision,
    ciphertext_digest: bytes(a.ciphertext_digest, 32),
    epoch: a.epoch,
    manifest_revision: a.manifest_revision,
    manifest_digest: bytes(a.manifest_digest, 32),
    issuer_device_id: a.device_id,
    request_nonce: bytes(a.nonce, 32),
    issued_at: a.issued_at,
    expires_at: input.expiresAt,
    recipient_username: input.recipientUsername,
    recipient_device_id: input.recipientDeviceId,
  };
}
async function shareGrantMessageV1(input) {
  return Buffer.concat([DOMAIN, Buffer.from(await z.encodeDeterministic(shareStatement(input)))]);
}
function verifySignature(publicKeyBytes, message, signature) {
  const key = crypto.createPublicKey({ key: Buffer.concat([
    ED25519_SPKI, bytes(publicKeyBytes, 32)]), format: "der", type: "spki" });
  if (!crypto.verify(null, message, key, bytes(signature, 64))) deny();
}
function activeDevice(manifest, deviceId) {
  const device = manifest?.devices?.find((entry) => entry.device_id === deviceId);
  if (!device || device.revoked_at_epoch !== null
    || Number(device.enrolled_epoch) > Number(manifest.current_epoch)) deny();
  return device;
}

class Zk1ProtectedCiphertextSharing {
  constructor(store) {
    if (!store?.signedHistoryRequired || !store?.admissionRequired || !store.db?.open
      || typeof store.runWithAdmission !== "function") deny("ZK_SHARE_UNAVAILABLE");
    this.store = store;
    // Reuse the privately pinned content store, including its durable WAL,
    // scope identity, replay ledger and crash/restart behavior.
    store.db.exec(`CREATE TABLE IF NOT EXISTS zk_content_share (
      grant_id TEXT PRIMARY KEY,
      scope TEXT NOT NULL,
      statement BLOB NOT NULL,
      signature BLOB NOT NULL CHECK(length(signature)=64),
      owner_username TEXT NOT NULL,
      recipient_username TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1))
    )`);
    this.insert = store.db.prepare(`INSERT INTO zk_content_share
      (grant_id,scope,statement,signature,owner_username,recipient_username,expires_at)
      VALUES(?,?,?,?,?,?,?)`);
    this.find = store.db.prepare("SELECT * FROM zk_content_share WHERE grant_id=? AND scope=?");
    this.revokeRow = store.db.prepare(`UPDATE zk_content_share SET revoked=1
      WHERE grant_id=? AND scope=? AND owner_username=?`);
  }

  async issue({ scope, authorization, signature, grantId, recipientUsername,
    recipientDeviceId, expiresAt, shareSignature, ownerUsername, guard }) {
    const statement = shareStatement({ authorization, grantId, recipientUsername,
      recipientDeviceId, expiresAt });
    const signedBytes = Buffer.from(await z.encodeDeterministic(statement));
    const message = Buffer.concat([DOMAIN, signedBytes]);
    const expectedScope = scopeKey(scope);
    if (scopeKey(statement) !== expectedScope || !USER.test(ownerUsername)
      || typeof guard !== "function") deny();
    const now = this.store.nowSeconds();
    if (!Number.isSafeInteger(now) || expiresAt <= now || expiresAt > now + 86400) deny();
    return this.store.runWithAdmission({ scope, authorization, signature }, "get",
      (result) => {
        if (result.id !== statement.object_id || result.revision !== statement.object_revision
          || result.epoch !== statement.epoch
          || !crypto.createHash("sha256").update(result.ciphertext).digest()
            .equals(statement.ciphertext_digest)) deny();
        try {
          this.insert.run(grantId, expectedScope, signedBytes,
            bytes(shareSignature, 64), ownerUsername, recipientUsername, expiresAt);
        } catch (error) {
          if (error?.code === "SQLITE_CONSTRAINT_PRIMARYKEY"
            || error?.code === "SQLITE_CONSTRAINT_UNIQUE") deny("ZK_SHARE_CONFLICT");
          deny("ZK_SHARE_UNAVAILABLE");
        }
        return { grantId, expiresAt };
      }, (approval) => {
        guard();
        activeDevice(approval.verifiedHeadManifest, recipientDeviceId);
        verifySignature(approval.deviceAuthorizationPublicKey, message, shareSignature);
        const current = this.store.nowSeconds();
        if (!Number.isSafeInteger(current) || current >= expiresAt) deny();
      });
  }

  getGrant(scope, grantId, recipientUsername) {
    const row = this.find.get(canonicalId(grantId), scopeKey(scope));
    if (!row || row.revoked !== 0 || row.recipient_username !== recipientUsername
      || this.store.nowSeconds() >= row.expires_at) deny();
    return row;
  }

  async read({ scope, grantId, recipientUsername, authorization, signature,
    guard, emit }) {
    const row = this.getGrant(scope, grantId, recipientUsername);
    if (typeof guard !== "function" || typeof emit !== "function") deny();
    return this.store.runWithAdmission({ scope, authorization, signature }, "get",
      async (result, approval) => {
        guard();
        const current = this.getGrant(scope, grantId, recipientUsername);
        if (!current.statement.equals(row.statement)
          || !current.signature.equals(row.signature)) deny();
        let statement;
        try { statement = await z.decodeDeterministic(current.statement); }
        catch (_) { deny(); }
        if (Reflect.ownKeys(statement).length !== FIELDS.length
          || FIELDS.some((field) => !Object.hasOwn(statement, field))) deny();
        const canonical = shareStatement({ grantId, recipientUsername,
          recipientDeviceId: statement.recipient_device_id,
          expiresAt: statement.expires_at,
          authorization: {
            ...authorization, device_id: statement.issuer_device_id,
            object_id: statement.object_id,
            expected_object_revision: statement.object_revision,
            ciphertext_digest: statement.ciphertext_digest,
            epoch: statement.epoch,
            manifest_revision: statement.manifest_revision,
            manifest_digest: statement.manifest_digest,
            nonce: statement.request_nonce,
            issued_at: statement.issued_at,
          } });
        if (!Buffer.from(await z.encodeDeterministic(canonical)).equals(row.statement)
          || statement.type !== canonical.type
          || statement.issuer_device_id !== canonical.issuer_device_id
          || current.expires_at !== statement.expires_at
          || !row.scope || scopeKey(statement) !== row.scope
          || statement.recipient_username !== recipientUsername
          || statement.recipient_device_id !== authorization.device_id
          || statement.object_id !== result.id
          || statement.object_revision !== result.revision
          || statement.epoch !== result.epoch
          || statement.epoch !== authorization.epoch
          || statement.manifest_revision !== authorization.manifest_revision
          || !Buffer.from(statement.manifest_digest).equals(authorization.manifest_digest)
          || !Buffer.from(statement.ciphertext_digest).equals(authorization.ciphertext_digest)
          || !crypto.createHash("sha256").update(result.ciphertext).digest()
            .equals(Buffer.from(statement.ciphertext_digest))) deny();
        const issuer = activeDevice(approval.verifiedHeadManifest, statement.issuer_device_id);
        verifySignature(issuer.authorization_public_key,
          Buffer.concat([DOMAIN, current.statement]), current.signature);
        guard();
        // There must be no await between this final fence and res.json():
        // SQLite's mutable expiry must never outlive the owner-signed expiry,
        // even if the witness admission or CBOR verification awaited earlier.
        const final = this.getGrant(scope, grantId, recipientUsername);
        const now = this.store.nowSeconds();
        if (!final.statement.equals(current.statement)
          || !final.signature.equals(current.signature)
          || final.expires_at !== statement.expires_at
          || !Number.isSafeInteger(now) || now >= statement.expires_at) deny();
        return emit({ id: result.id, revision: result.revision, epoch: result.epoch,
          ciphertextBase64: result.ciphertext.toString("base64url"),
          shareStatementBase64: current.statement.toString("base64url"),
          shareSignatureBase64: current.signature.toString("base64url") });
      });
  }

  revoke(scope, grantId, ownerUsername) {
    if (!USER.test(ownerUsername)) deny();
    const result = this.revokeRow.run(canonicalId(grantId), scopeKey(scope), ownerUsername);
    if (result.changes !== 1) deny();
    return { revoked: true };
  }
}

module.exports = { Zk1ProtectedCiphertextSharing, shareGrantMessageV1 };
