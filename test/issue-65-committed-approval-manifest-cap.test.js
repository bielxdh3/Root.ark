"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");

const RECEIPT_FIELDS = ["schema", "status", "account_id", "compartment_id", "keyring_id",
  "revision", "digest", "epoch", "previous_revision", "previous_digest",
  "operation_id", "pop_challenge_id", "request_nonce", "commit_nonce",
  "sequence", "previous_receipt_sha256", "issued_at", "expires_at"];
const RECEIPT_DOMAIN = Buffer.from("Root.ark/zk-1/offline-commitment-receipt/v1\0");
const MANIFEST_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-manifest-digest/v1\0");
const b64 = (value) => Buffer.from(value).toString("base64url");
const sha = (value) => crypto.createHash("sha256").update(value).digest();

// Isolate the manifest-consumer boundary from device-enrollment dependencies.
// Witness receipts and both signatures are still verified by real WebCrypto.
function committedApprovalWithVerifiedOwner() {
  const filename = path.join(__dirname, "../public/client/rootark-zk1-v2-committed-approval.js");
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.paths = Module._nodeModulePaths(path.dirname(filename));
  const defaultRequire = loaded.require.bind(loaded);
  loaded.require = (id) => {
    if (id === "./rootark-zk1-v2-device-approval") return {
      verifyImportedApproval: async () => ({ verifiedOwnerOfflineApproval: true,
        authorizesProductionIo: false }),
    };
    if (id === "./rootark-zk1-v2-browser-pop") return {
      targetDigest: async () => "bound-target",
    };
    if (id === "./rootark-zk1-normal-browser-trust-floor") return {};
    return defaultRequire(id);
  };
  loaded._compile(fs.readFileSync(filename, "utf8"), filename);
  return loaded.exports;
}

function signedReceipt(data, privateKey) {
  const body = Object.fromEntries(RECEIPT_FIELDS.map((key) => [key, data[key]]));
  const wire = Buffer.concat([RECEIPT_DOMAIN, Buffer.from(JSON.stringify(body))]);
  const signature = crypto.sign(null, wire, privateKey);
  return { receipt: { ...body, signature: b64(signature) },
    hash: sha(Buffer.concat([wire, signature])) };
}

test("committed approval consumes 3,284,324-byte manifest with valid witness signatures and rejects over 8 MiB", async () => {
  const verify = committedApprovalWithVerifiedOwner().verifyCommittedApproval;
  const witness = crypto.generateKeyPairSync("ed25519");
  const owner = crypto.generateKeyPairSync("ed25519");
  const subtle = crypto.webcrypto.subtle;
  const witnessSpki = witness.publicKey.export({ format: "der", type: "spki" });
  const witnessPublicKey = await subtle.importKey("spki", witnessSpki,
    "Ed25519", true, ["verify"]);
  const ownerPublicKey = await subtle.importKey("spki",
    owner.publicKey.export({ format: "der", type: "spki" }),
    "Ed25519", true, ["verify"]);
  const scope = { account_id: b64(Buffer.alloc(16, 1)),
    compartment_id: b64(Buffer.alloc(8, 2)), keyring_id: b64(Buffer.alloc(16, 3)) };
  const now = 1_800_000_000;
  const manifest = Buffer.alloc(3_284_324, 0x5a);
  const manifestDigest = sha(Buffer.concat([MANIFEST_DOMAIN, manifest]));
  const operation = b64(Buffer.alloc(16, 4));
  const challenge = b64(Buffer.alloc(16, 5));
  const nonce = b64(Buffer.alloc(32, 6));
  const common = { schema: "rootark-zk1-offline-commitment-receipt/v1",
    status: "committed", ...scope, epoch: 1, previous_revision: null,
    previous_digest: null, operation_id: null, pop_challenge_id: null,
    request_nonce: null, commit_nonce: null, previous_receipt_sha256: null,
    issued_at: now, expires_at: now + 300 };
  const prior = signedReceipt({ ...common, revision: 1,
    digest: b64(Buffer.alloc(32, 7)), sequence: 1 }, witness.privateKey);
  const current = signedReceipt({ ...common, revision: 2,
    digest: b64(manifestDigest), previous_revision: 1,
    previous_digest: prior.receipt.digest, sequence: 2,
    operation_id: operation, pop_challenge_id: challenge,
    request_nonce: nonce, previous_receipt_sha256: b64(prior.hash),
  }, witness.privateKey);
  const input = {
    request: { challenge: nonce }, approval: { operation_id: operation,
      pop_challenge_id: challenge, target_device_key_digest: "bound-target",
      issued_at: now, expires_at: now + 300 },
    signedDeviceGrant: { ...scope }, ownerPublicKey,
    independentOwnerSpkiSha256: Buffer.alloc(32),
    pinnedOwnerKeyHash: Buffer.alloc(32),
    pinnedCurrentHead: { revision: 2, digest: manifestDigest, epoch: 1 },
    devicePublicKey: ownerPublicKey, devicePrivateKey: null,
    nowSeconds: now, committedReceipt: current.receipt,
    previousReceipt: prior.receipt, witnessPublicKey,
    independentWitnessSpkiSha256: sha(witnessSpki),
    independentlyPinnedPreviousReceiptSha256: prior.hash,
    signedV2Manifest: b64(manifest),
  };
  assert.equal((await verify(input)).committedV2ManifestDigestMatched, true);

  const tampered = Buffer.from(manifest);
  tampered[123] ^= 1;
  await assert.rejects(verify({ ...input, signedV2Manifest: b64(tampered) }),
    /ZK_V2_COMMITTED_APPROVAL_DENIED/, "same-size manifest with wrong digest");
  await assert.rejects(verify({ ...input,
    signedV2Manifest: b64(Buffer.alloc(8 * 1024 * 1024 + 1)) }),
  /ZK_V2_COMMITTED_APPROVAL_DENIED/, "manifest larger than 8 MiB");
});
