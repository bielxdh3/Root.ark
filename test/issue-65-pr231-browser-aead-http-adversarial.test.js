"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const nodeHttp = require("node:http");
const files = require("../public/client/rootark-zk1-file-content");
const roots = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const http = require("../public/client/rootark-zk1-protected-http-client");
const normal = require("../public/client/rootark-zk1-normal-browser-content");

const subtle = crypto.webcrypto.subtle;
const b64 = (value) => Buffer.from(value).toString("base64url");
const rand = (length) => crypto.randomBytes(length);
const text = (value) => new TextEncoder().encode(value);
const scope = () => ({ account_id: b64(rand(16)), compartment_id: b64(rand(9)),
  keyring_id: b64(rand(16)) });
const metadataFor = (identity) => ({ ...identity, object_id: b64(rand(16)),
  version_id: b64(rand(16)), parent_version_id: null, epoch: 2, kind: "file" });
const seal = (cek, metadata) => files.encryptFile({ cek, metadata, name: "receipt.txt",
  mediaType: "text/plain", data: text("authentic content") });

async function localHttp(t, handler) {
  const requests = [];
  const server = nodeHttp.createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      requests.push({ method: req.method, url: req.url, body });
      const result = await handler(req, body);
      res.writeHead(result.status ?? 200, { "content-type": "application/json" });
      res.end(JSON.stringify(result.body ?? {}));
    } catch (_) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end("{}");
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { origin: `http://127.0.0.1:${server.address().port}/`, requests };
}

test("real AES-GCM AAD binds content, exact object/version/scope/epoch and V1/V2 format", async () => {
  const cek = await files.generateFileCek();
  const metadata = metadataFor(scope());
  const wire = await seal(cek, metadata);
  const baseline = await files.decryptFile({ cek, metadata, envelopeBytes: wire });
  assert.equal(baseline.name, "receipt.txt");
  assert.deepEqual(Buffer.from(baseline.data), Buffer.from("authentic content"));
  const original = JSON.parse(Buffer.from(wire).toString("utf8"));
  const decrypt = (envelope, expected = metadata) => files.decryptFile({
    cek, metadata: expected, envelopeBytes: text(JSON.stringify(envelope)),
  });
  for (const field of ["ciphertext", "nonce"]) {
    const broken = Buffer.from(original[field], "base64url");
    broken[0] ^= 1;
    await assert.rejects(decrypt({ ...original, [field]: b64(broken) }), /ZK_FILE_INVALID/,
      `modified ${field} must fail AEAD authentication`);
  }
  // WebCrypto appends the 128-bit GCM tag to the ciphertext, rather than
  // exposing a separate wire field. A last-byte mutation tests tag integrity
  // independently of an initial payload-byte bitflip.
  const badTag = Buffer.from(original.ciphertext, "base64url");
  assert.ok(badTag.length >= 16, "actual encrypted wire must include a GCM tag");
  badTag[badTag.length - 1] ^= 1;
  await assert.rejects(decrypt({ ...original, ciphertext: b64(badTag) }),
    /ZK_FILE_INVALID/, "an altered final GCM tag byte must fail authentic decryption");
  for (const [field, replacement] of [
    ["account_id", b64(rand(16))], ["compartment_id", b64(rand(9))],
    ["keyring_id", b64(rand(16))], ["object_id", b64(rand(16))],
    ["version_id", b64(rand(16))], ["parent_version_id", b64(rand(16))],
    ["epoch", 1], ["kind", "derived-data"],
  ]) {
    const altered = { ...metadata, [field]: replacement };
    await assert.rejects(decrypt({ ...original, metadata: altered }, altered),
      /ZK_FILE_INVALID/, `same CEK under changed ${field} must not authenticate`);
  }
  await assert.rejects(decrypt({ ...original, format: "rootark-zk1-file-v2" }),
    /ZK_FILE_INVALID/, "cross-format domain substitution must fail");

  // The simple V1->V2 field mutation above can fail the V2 payload schema
  // rather than the AEAD domain. Prove the real V2 payload is well-formed,
  // then deliberately encrypt those SAME valid V2 fields under the V1 AAD
  // domain. Only the cryptographic domain mismatch can explain the rejection.
  const parentFolderId = b64(rand(16));
  const validV2Wire = await files.encryptFileWithParent({ cek, metadata,
    name: "receipt.txt", mediaType: "text/plain", data: text("authentic content"),
    parentFolderId });
  assert.equal((await files.decryptFile({ cek, metadata,
    envelopeBytes: validV2Wire })).parentFolderId, parentFolderId,
    "positive control proves the V2 parent-folder schema is valid");
  const validV2Envelope = JSON.parse(Buffer.from(validV2Wire).toString("utf8"));
  const v2Payload = text(JSON.stringify({ name: "receipt.txt", mediaType: "text/plain",
    length: "authentic content".length, content: b64(text("authentic content")),
    parentFolderId }));
  const wrongDomainNonce = rand(12);
  const wrongDomainCiphertext = await subtle.encrypt({ name: "AES-GCM",
    iv: wrongDomainNonce, tagLength: 128,
    additionalData: text("Root.ark/zk-1/content-aead/v1\0"
      + JSON.stringify(validV2Envelope.metadata)),
  }, cek, v2Payload);
  await assert.rejects(decrypt({ ...validV2Envelope,
    nonce: b64(wrongDomainNonce), ciphertext: b64(wrongDomainCiphertext) }),
  /ZK_FILE_INVALID/,
  "valid V2 payload encrypted under the V1 AEAD domain must not decrypt as V2");
});

test("signed browser HTTP GET/PUT binds ciphertext root, digest, revision, epoch and ACK", async (t) => {
  const identity = scope();
  const metadata = metadataFor(identity);
  const cek = await files.generateFileCek();
  const ciphertext = await seal(cek, metadata);
  const root = await roots.computeCiphertextRoot([ciphertext]);
  const signer = await subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const common = { signerKey: signer.privateKey, scope: identity, deviceId: "device-a",
    objectId: metadata.object_id, manifestRevision: 7, manifestDigest: rand(32),
    epoch: metadata.epoch, nowSeconds: Math.floor(Date.now() / 1000) };
  const signGet = () => http.signProtectedContentOperation({ ...common, operation: "get",
    expectedObjectRevision: 1, expectedCiphertextDigest:
      crypto.createHash("sha256").update(ciphertext).digest(), ciphertext: null });
  const get = await signGet();
  const put = await http.signProtectedContentOperation({ ...common, operation: "put",
    expectedObjectRevision: null, ciphertext });
  let responseMode = "valid";
  const transport = await localHttp(t, (_req, body) => {
    if (body.authorization.operation === "put") {
      return { body: { id: metadata.object_id,
        revision: responseMode === "wrong-put-revision" ? 2 : 1 } };
    }
    const result = { id: metadata.object_id, revision: 1, epoch: metadata.epoch,
      ciphertextBase64: b64(ciphertext) };
    if (responseMode === "ciphertext-bitflip") {
      const altered = Buffer.from(ciphertext);
      altered[altered.length - 1] ^= 1;
      result.ciphertextBase64 = b64(altered);
    }
    if (responseMode === "foreign-id") result.id = b64(rand(16));
    if (responseMode === "stale-revision") result.revision = 0;
    if (responseMode === "stale-epoch") result.epoch = metadata.epoch - 1;
    if (responseMode === "denied") return { status: 403, body: { error: "forbidden" } };
    return { body: result };
  });
  const read = (request) => http.postProtectedCiphertextRead({ origin: transport.origin,
    request, expectedObjectRevision: 1, expectedRoot: root, cek, metadata });
  const baseline = await read(get);
  assert.deepEqual(Buffer.from(baseline.data), Buffer.from("authentic content"));
  assert.equal(baseline.authorizesRelease, false);
  assert.deepEqual(await http.postProtectedCiphertextPut({ origin: transport.origin,
    request: put }), { id: metadata.object_id, revision: 1 });
  assert.equal(transport.requests[0].url, "/zk-1/v1/content/read");
  assert.equal(transport.requests[1].url, "/zk-1/v1/content/put");
  assert.equal(transport.requests[0].body.authorization.epoch, metadata.epoch);
  assert.equal(typeof transport.requests[0].body.signatureBase64, "string");
  const nextGet = await signGet();
  assert.notEqual(nextGet.authorization.nonce, get.authorization.nonce,
    "each independent signed GET must have a fresh nonce");
  assert.equal((await read(nextGet)).authorizesRelease, false);
  for (const scenario of ["ciphertext-bitflip", "foreign-id", "stale-revision",
    "stale-epoch", "denied"]) {
    responseMode = scenario;
    await assert.rejects(read(await signGet()), /ZK_BROWSER_CONTENT_UNAVAILABLE/, scenario);
  }
  responseMode = "valid";
  const staleGet = await http.signProtectedContentOperation({ ...common, operation: "get",
    expectedObjectRevision: 2, expectedCiphertextDigest:
      crypto.createHash("sha256").update(ciphertext).digest(), ciphertext: null });
  await assert.rejects(http.postProtectedCiphertextRead({ origin: transport.origin,
    request: staleGet, expectedObjectRevision: 2, expectedRoot: root, cek, metadata }),
  /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "a previously captured revision-1 HTTP response cannot satisfy a new revision-2 read");
  responseMode = "wrong-put-revision";
  await assert.rejects(http.postProtectedCiphertextPut({ origin: transport.origin,
    request: put }), /ZK_BROWSER_CONTENT_UNAVAILABLE/,
  "a mismatched revision ACK cannot advance the browser's expected revision");
  const sent = transport.requests.length;
  await assert.rejects(http.postProtectedCiphertextRead({ origin: transport.origin,
    request: { ...get }, expectedObjectRevision: 1, expectedRoot: root, cek, metadata }),
  /ZK_BROWSER_CONTENT_UNAVAILABLE/, "a cloned unsigned HTTP request is not signer-branded");
  assert.equal(transport.requests.length, sent, "unbranded request must not reach HTTP");
});

test("normal browser upload requires a real owner-signed active device grant and pinned head", async (t) => {
  const owner = await subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const device = await subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const identity = scope();
  const metadata = metadataFor(identity);
  const pin = { revision: 7, digest: rand(32), epoch: metadata.epoch };
  const ownerRaw = await subtle.exportKey("raw", owner.publicKey);
  const deviceRaw = await subtle.exportKey("raw", device.publicKey);
  const grant = { schema: "rootark-zk1-browser-owner-device-grant/v1",
    ...identity, device_id: "device-a", authorization_key_id: b64(rand(16)),
    authorization_public_key: b64(deviceRaw), manifest_revision: pin.revision,
    manifest_digest: b64(pin.digest), current_epoch: pin.epoch,
    enrolled_epoch: 1, revoked_at_epoch: null };
  const domain = text("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const message = Buffer.concat([domain, text(JSON.stringify(grant))]);
  const signedDeviceGrant = { ...grant,
    signature: b64(await subtle.sign("Ed25519", owner.privateKey, message)) };
  // A valid owner-signed revocation is materially different from tampering
  // with the old grant (which fails only signature verification).
  const revokedGrant = { ...grant, revoked_at_epoch: pin.epoch };
  const signedRevokedGrant = { ...revokedGrant,
    signature: b64(await subtle.sign("Ed25519", owner.privateKey,
      Buffer.concat([domain, text(JSON.stringify(revokedGrant))]))) };
  const enrollment = { ownerPublicKey: owner.publicKey,
    pinnedOwnerKeyHash: crypto.createHash("sha256").update(Buffer.from(ownerRaw)).digest(),
    pinnedCurrentHead: pin, signedDeviceGrant,
    devicePublicKey: device.publicKey, devicePrivateKey: device.privateKey };
  assert.equal((await normal.verifyOwnerGrant(enrollment)).ownerGrantSignatureVerified, true);
  let committed;
  const transport = await localHttp(t, (req, body) => {
    if (req.url === "/zk-1/v1/content/put") {
      committed = body.ciphertextBase64;
      return { body: { id: metadata.object_id, revision: 1 } };
    }
    return { body: { id: metadata.object_id, revision: 1,
      epoch: metadata.epoch, ciphertextBase64: committed } };
  });
  const input = { ...enrollment, metadata, fileName: "receipt.txt",
    mediaType: "text/plain", data: text("authentic content"),
    nowSeconds: Math.floor(Date.now() / 1000),
    origin: transport.origin, fetchImpl: fetch };
  const verified = await normal.uploadAndVerify(input);
  assert.equal(verified.protectedHttpReadbackVerified, true);
  assert.equal(verified.authorizesProductionIo, false);
  assert.equal(transport.requests.length, 2);
  for (const [scenario, overrides] of [
    ["missing grant", { signedDeviceGrant: null }],
    ["forged signature", { signedDeviceGrant: { ...signedDeviceGrant,
      signature: b64(rand(64)) } }],
    ["stale epoch", { pinnedCurrentHead: { ...pin, epoch: pin.epoch + 1 } }],
    ["foreign scope", { metadata: { ...metadata, keyring_id: b64(rand(16)) } }],
    ["valid owner-signed revoked device", { signedDeviceGrant: signedRevokedGrant }],
  ]) {
    const before = transport.requests.length;
    await assert.rejects(normal.uploadAndVerify({ ...input, ...overrides }),
      /ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED/, scenario);
    assert.equal(transport.requests.length, before,
      `${scenario} must fail before protected HTTP I/O`);
  }
});
