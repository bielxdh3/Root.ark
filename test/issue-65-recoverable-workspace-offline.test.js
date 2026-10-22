"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const recoveryWorkspace = require("../public/client/rootark-zk1-recoverable-workspace");

const opaque = () => crypto.randomBytes(16).toString("base64url");
const metadata = () => ({ account_id: opaque(),
  compartment_id: Buffer.from("fresh-client-test").toString("base64url"),
  keyring_id: opaque(), object_id: opaque(), version_id: opaque(),
  parent_version_id: null, epoch: 1, kind: "file" });

test("portable sealed CEK survives independent client reload while forged external roots and wrong holder secrets fail closed", async () => {
  const a = portable;
  const holder = crypto.randomBytes(32);
  const plain = Buffer.from("owner-approved offline holder secret; not server plaintext");
  const meta = metadata();
  const bundle = await a.sealForUserHeldSecret({
    recoverySecret: holder, metadata: meta,
    name: "recover.txt", mediaType: "text/plain", data: plain,
  });
  const serialized = JSON.stringify(bundle);
  assert.equal(serialized.includes(plain.toString()), false);
  assert.equal(serialized.includes(holder.toString("base64url")), false);
  assert.equal(bundle.wrap.format, "HKDF-SHA256/AES-256-GCM");

  // Model the fresh profile: no in-memory CryptoKey from the old profile,
  // only the exported bundle, separately held secret and independently pinned root.
  const freshBundle = JSON.parse(serialized);
  const freshHolder = Buffer.from(holder);
  const trustedRoot = Buffer.from(bundle.ciphertextRoot, "base64url");
  const output = await portable.openWithIndependentRoot({
    recoverySecret: freshHolder, bundle: freshBundle, expectedMetadata: meta,
    independentlyPinnedCiphertextRoot: trustedRoot,
  });
  assert.deepEqual(Buffer.from(output.data), plain);
  assert.equal(output.ownerPinProvenanceVerifiedByModule, false,
    "a holder secret alone never manufactures trusted owner provenance");
  output.data.fill(0);
  const invalid = (override) => assert.rejects(portable.openWithIndependentRoot({
    recoverySecret: freshHolder, bundle: freshBundle, expectedMetadata: meta,
    independentlyPinnedCiphertextRoot: trustedRoot, ...override,
  }), /ZK_PORTABLE_FILE_RECOVERY_DENIED/);
  await invalid({ recoverySecret: crypto.randomBytes(32) });
  await invalid({ independentlyPinnedCiphertextRoot: crypto.randomBytes(32) });
  await invalid({ bundle: { ...freshBundle, objectRevision: 2 } });
  await invalid({ expectedMetadata: { ...meta, epoch: 2 } });
  assert.equal(typeof recoveryWorkspace.restoreOnNewDevice, "function");
  assert.equal(typeof recoveryWorkspace.createRecoverableProtectedFile, "function");
  holder.fill(0);
  freshHolder.fill(0);
});
