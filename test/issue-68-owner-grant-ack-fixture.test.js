"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { shareGrantMessageV1 } =
  require("../src/services/zk1ProtectedCiphertextSharing");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { assertAuthenticOwnerGrantAck } =
  require("./support/issue-68-owner-grant-ack-fixture");

const b64 = (value) => Buffer.from(value).toString("base64url");
const DOMAIN = Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0");
async function fixture() {
  const signer = crypto.generateKeyPairSync("ed25519");
  const ownerInput = {
    authorization: {
      account_id: crypto.randomBytes(16),
      compartment_id: crypto.randomBytes(16),
      keyring_id: crypto.randomBytes(16),
      device_id: "trusted-owner-device",
      operation: "get",
      object_id: b64(crypto.randomBytes(16)),
      expected_object_revision: 1,
      manifest_revision: 3,
      manifest_digest: crypto.randomBytes(32),
      epoch: 2,
      nonce: crypto.randomBytes(32),
      issued_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 120,
      ciphertext_digest: crypto.randomBytes(32),
    },
    grantId: b64(crypto.randomBytes(32)),
    recipientUsername: "recipient",
    recipientDeviceId: "trusted-recipient-device",
    expiresAt: Math.floor(Date.now() / 1000) + 120,
  };
  const signedMessage = await shareGrantMessageV1(ownerInput);
  assert.deepEqual(signedMessage.subarray(0, DOMAIN.length), DOMAIN);
  const expected = {
    grantId: ownerInput.grantId,
    expiresAt: ownerInput.expiresAt,
    shareStatementBase64: b64(signedMessage.subarray(DOMAIN.length)),
    shareSignatureBase64: b64(crypto.sign(null, signedMessage, signer.privateKey)),
  };
  return { signer, expected, signedMessage };
}

test("#294 CodeQL: exact owner-signed grant ACK is authentic and cannot inject arbitrary local files", async (t) => {
  const { signer, expected, signedMessage } = await fixture();
  const dir = createPrivateAuthorityFixture("rootark-codeql-grant-ack-w4-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const output = path.join(dir, "grant-ack.json");
  const persistAfterApproval = (candidate) => {
    assertAuthenticOwnerGrantAck(candidate, expected, signedMessage, signer.publicKey);
    // No candidate value, property or filename reaches the owner-only O_EXCL write.
    fs.writeFileSync(output, JSON.stringify(expected), { mode: 0o600, flag: "wx" });
  };
  assert.equal(assertAuthenticOwnerGrantAck(JSON.parse(JSON.stringify(expected)), expected,
    signedMessage, signer.publicKey), undefined);
  for (const [label, candidate] of [
    ["HTML/script in signed wire", { ...expected, shareStatementBase64: "<script>alert(1)</script>" }],
    ["path traversal in ID", { ...expected, grantId: "../../trusted-share.js" }],
    ["oversized HTTP property", { ...expected, shareStatementBase64: "a".repeat(2 ** 20) }],
    ["spoofed signature", { ...expected, shareSignatureBase64: b64(crypto.randomBytes(64)) }],
    ["forged expiry", { ...expected, expiresAt: expected.expiresAt + 60 }],
    ["unexpected file path", { ...expected, output: "../../escape.js" }],
    ["prototype pollution attempt", JSON.parse('{"__proto__":{"admin":true}}')],
    ["unexpected getter", Object.defineProperty({ ...expected }, "shareStatementBase64",
      { enumerable: true, get() { throw Error("PRIVATE_MARKER_MUST_NOT_RUN"); } })],
  ]) {
    assert.throws(() => persistAfterApproval(candidate), error => {
      assert.equal(error.message, "ZK_SHARE_GRANT_ACK_UNVERIFIED", label);
      assert.equal(error.message.includes("PRIVATE_MARKER"), false);
      return true;
    }, label);
    assert.equal(fs.existsSync(output), false, label + " cannot create a fixture");
  }
  const secondSigner = crypto.generateKeyPairSync("ed25519");
  assert.throws(() => assertAuthenticOwnerGrantAck(expected, expected,
    signedMessage, secondSigner.publicKey), /ZK_SHARE_GRANT_ACK_UNVERIFIED/);
  assert.throws(() => assertAuthenticOwnerGrantAck(expected, expected,
    Buffer.from("forged-signed-body"), signer.publicKey), /ZK_SHARE_GRANT_ACK_UNVERIFIED/);
  persistAfterApproval(JSON.parse(JSON.stringify(expected)));
  assert.deepEqual(fs.readFileSync(output), Buffer.from(JSON.stringify(expected)));
  assert.throws(() => persistAfterApproval(expected), /EEXIST/,
    "existing owner-only fixture cannot be overwritten");
});
