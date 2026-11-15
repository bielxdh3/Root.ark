"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");
const fileContent = require("../public/client/rootark-zk1-file-content");
const preview = require("../public/client/rootark-zk1-selected-local-preview");
const b64 = (data) => Buffer.from(data).toString("base64url");
const sha = (data) => b64(nodeCrypto.createHash("sha256").update(data).digest());
const id = () => b64(nodeCrypto.randomBytes(16));

async function setup() {
  const scope = { account_id: id(), compartment_id: id(), keyring_id: id() };
  const selected = { objectId: id(), revision: 3, epoch: 2 };
  const metadata = { ...scope, object_id: selected.objectId, version_id: id(),
    parent_version_id: id(), epoch: 2, kind: "file" };
  const raw = nodeCrypto.randomBytes(32);
  const cek = await fileContent.importFileCek(raw);
  const content = new TextEncoder().encode("<script>no HTML</script> relatório confidencial");
  const sealed = await fileContent.encryptFile({ cek, metadata,
    name: "relatorio.txt", mediaType: "text/plain", data: content });
  const ciphertextDigestBase64 = sha(sealed);
  const entry = { ...selected, ciphertextDigestBase64 };
  const checked = { ...selected, ciphertextDigestBase64,
    ciphertextBase64: b64(sealed), verifiedCiphertext: true,
    plaintextAvailable: false, authorizesMutation: false };
  const ownerDigest = b64(nodeCrypto.randomBytes(32));
  const grant = { ...scope, device_id: "device-valid", current_epoch: 2,
    manifest_revision: 8, manifest_digest: ownerDigest, revoked_at_epoch: null };
  const ownerHead = { revision: 8, epoch: 2, digest: ownerDigest };
  const baseline = { head: { sequence: 11, digest: b64(nodeCrypto.randomBytes(32)) },
    entries: [entry] };
  let active = true;
  const input = { checked, selected: entry, metadata, rawCek: raw, cekSha256Pin: sha(raw),
    grant, ownerHead, baseline, assertLive() { if (!active) throw Error("LOGGED_OUT"); } };
  return { input, selected, scope, raw, sealed,
    logout() { active = false; } };
}

test("offline-pinned CEK opens only an exact signed selection as bounded plain text", async () => {
  const f = await setup();
  const result = await preview.open(f.input);
  assert.equal(result.text, "<script>no HTML</script> relatório confidencial");
  assert.equal(result.name, "relatorio.txt");
  assert.equal(result.mediaType, "text/plain");
  assert.equal(result.objectId, f.selected.objectId);
  assert.equal(result.revision, 3);
  assert.equal(result.epoch, 2);
  assert.equal(result.plaintextSentToServer, false);
  assert.equal(Object.hasOwn(result, "cek"), false);
});

test("wrong offline CEK pin, wrong AEAD key, selected revision, epoch, scope and ciphertext deny all content", async () => {
  const f = await setup();
  const bad = [
    { cekSha256Pin: sha(nodeCrypto.randomBytes(32)) },
    { rawCek: nodeCrypto.randomBytes(32) },
    { selected: { ...f.input.selected, revision: 2 } },
    { selected: { ...f.input.selected, epoch: 1 } },
    { grant: { ...f.input.grant, keyring_id: id() } },
    { grant: { ...f.input.grant, revoked_at_epoch: 2 } },
    { ownerHead: { ...f.input.ownerHead, epoch: 3 } },
    { checked: { ...f.input.checked, ciphertextBase64: b64(nodeCrypto.randomBytes(f.sealed.length)) } },
    { metadata: { ...f.input.metadata, version_id: id() } },
    { metadata: { ...f.input.metadata, object_id: id() } },
    { checked: { ...f.input.checked, verifiedCiphertext: false } },
  ];
  for (const change of bad) {
    await assert.rejects(preview.open({ ...f.input, ...change }),
      /ZK_SELECTED_PREVIEW_DENIED/, JSON.stringify(Object.keys(change)));
  }
});

test("stale session on crypto completion denies preview; source CEK is not modified", async () => {
  const f = await setup();
  const before = Buffer.from(f.raw);
  f.logout();
  await assert.rejects(preview.open(f.input), /ZK_SELECTED_PREVIEW_DENIED/);
  assert.deepEqual(f.raw, before);
});
