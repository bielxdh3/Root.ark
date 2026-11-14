"use strict";
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const b64 = (value) => Buffer.from(value).toString("base64url");
const hash = (value) => b64(crypto.createHash("sha256").update(value).digest());
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
};
const domain = (type) => Buffer.from("Root.ark/android/" + type + "/v1\0");
function sign(key, kind, payload) {
  return { ...payload, signature: b64(crypto.sign(null,
    Buffer.concat([domain(kind), Buffer.from(JSON.stringify(canonical(payload)))]), key)) };
}
function verify(key, kind, signed) {
  const { signature, ...body } = signed;
  return crypto.verify(null, Buffer.concat([
    domain(kind), Buffer.from(JSON.stringify(canonical(body))) ]),
  key, Buffer.from(signature, "base64url"));
}
function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicDer = owner.publicKey.export({ type: "spki", format: "der" });
  const issuerDer = signer.publicKey.export({ type: "spki", format: "der" });
  const fixed = {
    origin: "https://rootark.test", username: "offline-owner",
    readerDeviceId: "reader-android-001", ownerRevision: 15,
    ownerDigest: hash(Buffer.from("owner-current-15")),
  };
  const time = 1700000000000;
  const head = sign(owner.privateKey, "owner-head", {
    schema: "rootark-android-owner-head/v1", ...fixed, revokedDeviceIds: [],
    issuedAtMillis: time, expiresAtMillis: time + 120000,
  });
  const read = sign(owner.privateKey, "cek-read", {
    schema: "rootark-android-cek-read/v1", ...fixed,
    objectId: "item-id-001", fileId: "file-id-001", versionId: "version-id-001",
    compartmentId: "compartment-1", keyEpoch: "epoch-2",
    signerDeviceId: "issuer-001", signerPublicKeySpki: b64(issuerDer),
    cekSha256: hash(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1))),
    nonce: b64(Buffer.alloc(16, 9)),
    issuedAtMillis: time, expiresAtMillis: time + 90000,
  });
  const revoked = sign(owner.privateKey, "owner-head", {
    ...head, ownerRevision: 16, ownerDigest: hash(Buffer.from("owner-revoked-16")),
    revokedDeviceIds: ["issuer-001", "reader-android-001"],
    signature: undefined,
  });
  const revokedGrant = sign(owner.privateKey, "cek-read", {
    ...read, ownerRevision: revoked.ownerRevision, ownerDigest: revoked.ownerDigest,
    signature: undefined,
  });
  return {
    anchor: { ...fixed, ownerPublicSpki: b64(publicDer),
      ownerPublicSpkiSha256: hash(publicDer) },
    head, grant: read, revoked, revokedGrant,
  };
}
async function main() {
  const f = fixture();
  if (process.argv.includes("--write")) {
    const destination = path.join(__dirname, "../android/core/src/test/resources/owner-pinned-grant.json");
    fs.writeFileSync(destination, JSON.stringify(f, null, 2) + "\n");
    return;
  }
  const assert = require("node:assert/strict");
  const key = crypto.createPublicKey({ key: Buffer.from(f.anchor.ownerPublicSpki, "base64url"),
    format: "der", type: "spki" });
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push(req.url);
    if (req.url !== "/signed-head" && req.url !== "/signed-grant"
      && req.url !== "/revoked-head") return res.writeHead(404).end();
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify(req.url === "/signed-head" ? f.head
      : req.url === "/signed-grant" ? f.grant : f.revoked));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const base = "http://127.0.0.1:" + server.address().port;
    for (const [route, kind] of [["signed-head", "owner-head"],
      ["signed-grant", "cek-read"], ["revoked-head", "owner-head"]]) {
      const response = await fetch(base + "/" + route);
      assert.equal(response.status, 200);
      const signed = await response.json();
      assert.equal(verify(key, kind, signed), true);
      const changed = { ...signed, readerDeviceId: "attacker-reader" };
      assert.equal(verify(key, kind, changed), false);
    }
    assert.deepEqual(requests, ["/signed-head", "/signed-grant", "/revoked-head"]);
    // A network reply is not a trust anchor. The pin is supplied separately.
    assert.ok(!requests.some((request) => request.includes(f.anchor.ownerPublicSpki)));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}
if (require.main === module) main().catch((error) => {
  process.stderr.write(error.message + "\n");
  process.exitCode = 1;
});
module.exports = { fixture, verify };
