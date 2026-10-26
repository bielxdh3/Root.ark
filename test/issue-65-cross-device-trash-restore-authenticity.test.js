"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const file = require("../public/client/rootark-zk1-file-content");

const b64 = (value) => Buffer.from(value).toString("base64url");
const digest = (value) => crypto.createHash("sha256").update(value).digest();
const utf8 = new TextEncoder();

async function secret() {
  return crypto.webcrypto.subtle.importKey("raw", crypto.randomBytes(32),
    "AES-GCM", false, ["encrypt", "decrypt"]);
}

// Real file/tombstone AEADs; only the already independently authenticated
// catalog/GET boundary is replaced by a deterministic fixture. The HTTP CAS
// and independent-device positive path live in issue-65-zk1-client-logical-trash-http.
async function inspectReplacement({ replacementName = "before.txt",
  replacementParent = null, replacementData = "original contents" }) {
  const scope = { account_id: b64(crypto.randomBytes(16)),
    compartment_id: b64(Buffer.from("private")),
    keyring_id: b64(crypto.randomBytes(16)) };
  const objectId = b64(crypto.randomBytes(16));
  const version = (parent) => ({ ...scope, object_id: objectId,
    version_id: b64(crypto.randomBytes(16)), parent_version_id: parent,
    epoch: 3, kind: "file" });
  const initial = version(null);
  const tombstone = version(initial.version_id);
  const candidate = version(tombstone.version_id);
  const keys = [await secret(), await secret(), await secret()];
  const originalBytes = await file.encryptFileWithParent({ cek: keys[0],
    metadata: initial, name: "before.txt", parentFolderId: null,
    mediaType: "text/plain", data: utf8.encode("original contents") });
  const predecessor = { revision: 1, ciphertextDigest: b64(digest(originalBytes)),
    versionId: initial.version_id };
  const nonce = crypto.randomBytes(12);
  const sealed = await crypto.webcrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce,
    tagLength: 128, additionalData: utf8.encode(
      "Root.ark/zk-1/logical-trash-aead/v1\0" + JSON.stringify(tombstone)
      + "\0" + JSON.stringify(predecessor)) }, keys[1],
  utf8.encode('{"state":"trashed","retention":"unknown"}'));
  const tombstoneBytes = utf8.encode(JSON.stringify({
    format: "rootark-zk1-logical-trash/v1", metadata: tombstone,
    predecessor, nonce: b64(nonce), ciphertext: b64(sealed) }));
  const candidateBytes = await file.encryptFileWithParent({ cek: keys[2],
    metadata: candidate, name: replacementName,
    parentFolderId: replacementParent, mediaType: "text/plain",
    data: utf8.encode(replacementData) });
  const versions = [originalBytes, tombstoneBytes, candidateBytes];
  const snapshot = { sequence: 3, catalogDigest: b64(crypto.randomBytes(32)),
    entries: versions.map((ciphertext, i) => ({ objectId,
      revision: i + 1, epoch: 3, ciphertextDigestBase64: b64(digest(ciphertext)) })) };
  let reads = 0;
  const fakeCatalog = {
    async openCatalog() { reads++; return snapshot; },
    async getCatalogCiphertext(_snapshot, index) {
      assert.equal(_snapshot, snapshot);
      return { objectId, revision: index + 1,
        ciphertextBase64: b64(versions[index]) };
    },
  };
  const browser = { crypto: crypto.webcrypto, TextEncoder, TextDecoder,
    btoa, atob, RootarkZk1BrowserCatalog: fakeCatalog };
  vm.createContext(browser);
  for (const name of ["rootark-zk1-file-content",
    "rootark-zk1-cross-device-trash-observer"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname,
      "../public/client/" + name + ".js"), "utf8"), browser);
  }
  const realm = vm.runInContext("(json) => JSON.parse(json)", browser);
  const copy = (value) => realm(JSON.stringify(value));
  const trust = copy({ signedDeviceGrant: scope,
    pinnedCurrentHead: { revision: 1 } });
  trust.independentOwnerSpkiSha256 = crypto.randomBytes(32);
  trust.pinnedCurrentHead.digest = crypto.randomBytes(32);
  const input = Object.assign(copy({}), {
    catalogRead: Object.assign(copy({}), {
      trust, signerGrant: copy({}),
      independentAuthoritySpkiHash: crypto.randomBytes(32),
      pinnedCatalogHead: copy({ sequence: 3, digest: snapshot.catalogDigest }),
    }),
    objectId,
    versionMetadata: copy([initial, tombstone, candidate]),
    readArchivedCek: async ({ revision, versionId }) => {
      assert.equal(versionId, [initial, tombstone, candidate][revision - 1].version_id);
      return keys[revision - 1];
    },
    assertLive: () => {},
  });
  try {
    const result = await browser.RootarkZk1CrossDeviceTrashObserver.inspect(input);
    return { result, reads };
  } finally {
    for (const value of versions) value.fill(0);
  }
}

test("independent device verifies an exact restore after an authenticated trash", async () => {
  const { result, reads } = await inspectReplacement({});
  assert.equal(result.state, "file");
  assert.equal(result.restoredAfterTombstone, true);
  assert.equal(result.revision, 3);
  assert.equal(result.authorizesProductionRestore, false);
  assert.equal(reads, 2, "second catalog read confirms the pinned head");
});

for (const [label, replacement] of [
  ["new plaintext", { replacementData: "substituted contents" }],
  ["new filename", { replacementName: "different.txt" }],
  ["new parent folder", { replacementParent: b64(crypto.randomBytes(16)) }],
]) test("independent device cannot call an authenticated " + label + " a restore", async () => {
  await assert.rejects(inspectReplacement(replacement), /ZK_CROSS_DEVICE_TRASH_UNVERIFIED/);
});
