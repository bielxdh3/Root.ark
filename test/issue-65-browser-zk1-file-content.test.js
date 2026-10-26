"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const file = require("../public/client/rootark-zk1-file-content.js");

test("client-only versioned CEK encrypts filename, type and binary; never exposes plaintext via opaque file wire", async () => {
  const cek = await file.generateFileCek();
  assert.equal(cek.extractable, false);
  const scope = {
    account_id: crypto.randomBytes(16).toString("base64url"),
    compartment_id: Buffer.from("encrypted-content", "ascii").toString("base64url"),
    keyring_id: crypto.randomBytes(16).toString("base64url"),
  };
  const metadata = {
    ...scope, object_id: crypto.randomBytes(16).toString("base64url"),
    version_id: crypto.randomBytes(16).toString("base64url"),
    parent_version_id: null, epoch: 2, kind: "file",
  };
  const data = crypto.randomBytes(1024);
  const encrypted = await file.encryptFile({ cek, metadata, name: "private-生活.pdf",
    mediaType: "application/pdf", data });
  assert.ok(encrypted instanceof Uint8Array);
  const wire = Buffer.from(encrypted).toString("utf8");
  assert.equal(wire.includes("private-"), false);
  assert.equal(wire.includes("application/pdf"), false);
  const decrypted = await file.decryptFile({ cek, metadata, envelopeBytes: encrypted });
  assert.equal(decrypted.name, "private-生活.pdf");
  assert.equal(decrypted.mediaType, "application/pdf");
  assert.deepEqual(Buffer.from(decrypted.data), data);
  decrypted.data.fill(0);

  const mutations = [
    { compartment_id: crypto.randomBytes(16).toString("base64url") },
    { object_id: crypto.randomBytes(16).toString("base64url") },
    { version_id: crypto.randomBytes(16).toString("base64url") },
    { parent_version_id: crypto.randomBytes(16).toString("base64url") },
    { epoch: 1 }, { kind: "derived-data" },
  ];
  for (const changed of mutations) {
    await assert.rejects(file.decryptFile({ cek, metadata: { ...metadata, ...changed },
      envelopeBytes: encrypted }), /ZK_FILE_INVALID/, JSON.stringify(changed));
  }
  const anotherCek = await file.generateFileCek();
  await assert.rejects(file.decryptFile({ cek: anotherCek, metadata,
    envelopeBytes: encrypted }), /ZK_FILE_INVALID/);
  const corrupt = Buffer.from(encrypted);
  corrupt[corrupt.length - 10] ^= 1;
  await assert.rejects(file.decryptFile({ cek, metadata, envelopeBytes: corrupt }), /ZK_FILE_INVALID/);
  await assert.rejects(file.encryptFile({ cek, metadata, name: "x/../y", mediaType: "text/plain",
    data }), /ZK_FILE_INVALID/);
  const emptyWire = await file.encryptFile({ cek, metadata: { ...metadata,
    object_id: crypto.randomBytes(16).toString("base64url") },
    name: "empty.txt", mediaType: "text/plain", data: Buffer.alloc(0) });
  const openedEmpty = await file.decryptFile({ cek, metadata: { ...metadata,
    object_id: JSON.parse(Buffer.from(emptyWire).toString()).metadata.object_id },
    envelopeBytes: emptyWire });
  assert.equal(openedEmpty.data.byteLength, 0);
});
