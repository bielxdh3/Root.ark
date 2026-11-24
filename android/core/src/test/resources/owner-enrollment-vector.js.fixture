"use strict";

// Test-only Node -> Kotlin HPKE vector builder. Private keys and the CEK arrive
// through stdin from the test process, stay in memory, and are never emitted.
const crypto = require("node:crypto");

const b64u = (value) => Buffer.from(value).toString("base64url");
const fromB64u = (value) => Buffer.from(value, "base64url");
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
const sha256 = (value) => crypto.createHash("sha256").update(value).digest();
const i2osp = (value, length) => {
  const output = Buffer.alloc(length);
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = value & 0xff;
    value >>>= 8;
  }
  return output;
};
const hmac = (key, value) => crypto.createHmac("sha256", key).update(value).digest();
const hkdfExtract = (salt, ikm) => hmac(salt.length ? salt : Buffer.alloc(32), ikm);
const hkdfExpand = (prk, info, length) => {
  const output = [];
  let previous = Buffer.alloc(0);
  for (let counter = 1; Buffer.concat(output).length < length; counter += 1) {
    previous = hmac(prk, Buffer.concat([previous, info, Buffer.from([counter])]));
    output.push(previous);
  }
  return Buffer.concat(output).subarray(0, length);
};
const labeledExtract = (salt, label, ikm, suite) => hkdfExtract(
  salt, Buffer.concat([Buffer.from("HPKE-v1"), suite, Buffer.from(label), ikm]),
);
const labeledExpand = (prk, label, info, length, suite) => hkdfExpand(
  prk, Buffer.concat([i2osp(length, 2), Buffer.from("HPKE-v1"), suite, Buffer.from(label), info]), length,
);
const sign = (privateKey, domain, fields) => b64u(crypto.sign(
  null, Buffer.from(domain + canonical(fields), "utf8"), privateKey,
));
const ed25519SpkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

function seal(cek, recipientPublicKey, ownerPublicSpki, contextFields) {
  const seed = sha256(Buffer.concat([
    Buffer.from("Root.ark/android/test-hpke-ephemeral/v2\0"),
    recipientPublicKey, cek, ownerPublicSpki,
  ]));
  const scalar = (BigInt(`0x${seed.toString("hex")}`) % (P256_ORDER - 1n)) + 1n;
  const ephemeralPrivate = Buffer.from(scalar.toString(16).padStart(64, "0"), "hex");
  const ephemeral = crypto.createECDH("prime256v1");
  ephemeral.setPrivateKey(ephemeralPrivate);
  const enc = ephemeral.getPublicKey(undefined, "uncompressed");
  const dh = ephemeral.computeSecret(recipientPublicKey);
  const kemSuite = Buffer.concat([Buffer.from("KEM"), i2osp(0x0010, 2)]);
  const hpkeSuite = Buffer.concat([Buffer.from("HPKE"), i2osp(0x0010, 2), i2osp(0x0001, 2), i2osp(0x0002, 2)]);
  const eaePrk = labeledExtract(Buffer.alloc(0), "eae_prk", dh, kemSuite);
  const sharedSecret = labeledExpand(eaePrk, "shared_secret", Buffer.concat([enc, recipientPublicKey]), 32, kemSuite);
  const pskIdHash = labeledExtract(Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0), hpkeSuite);
  const infoHash = labeledExtract(Buffer.alloc(0), "info_hash", Buffer.from(
    "Root.ark/android/cek-read-hpke/v2/info\0" + canonical({ ...contextFields, enc: b64u(enc) }), "utf8",
  ), hpkeSuite);
  const keyScheduleContext = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(sharedSecret, "secret", Buffer.alloc(0), hpkeSuite);
  const key = labeledExpand(secret, "key", keyScheduleContext, 32, hpkeSuite);
  const nonce = labeledExpand(secret, "base_nonce", keyScheduleContext, 12, hpkeSuite);
  const aad = Buffer.from(
    "Root.ark/android/cek-read-hpke/v2/aad\0" + canonical({ ...contextFields, enc: b64u(enc) }), "utf8",
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(cek), cipher.final(), cipher.getAuthTag()]);
  for (const value of [seed, ephemeralPrivate, dh, eaePrk, sharedSecret, pskIdHash,
    infoHash, keyScheduleContext, secret, key, nonce, aad]) value.fill(0);
  return { enc: b64u(enc), wrappedCek: b64u(encrypted) };
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const inputBytes = Buffer.concat(chunks);
  let ownerPrivateBytes;
  let signerPrivateBytes;
  let cek;
  try {
    const input = JSON.parse(inputBytes.toString("utf8"));
    ownerPrivateBytes = fromB64u(input.ownerPrivatePkcs8);
    signerPrivateBytes = fromB64u(input.signerPrivatePkcs8);
    cek = fromB64u(input.cek);
    const ownerPrivate = crypto.createPrivateKey({ key: ownerPrivateBytes, format: "der", type: "pkcs8" });
    const signerPrivate = crypto.createPrivateKey({ key: signerPrivateBytes, format: "der", type: "pkcs8" });
    const ownerPublicSpki = crypto.createPublicKey(ownerPrivate).export({ format: "der", type: "spki" });
    const signerPublicSpki = crypto.createPublicKey(signerPrivate).export({ format: "der", type: "spki" });
    if (!signerPublicSpki.subarray(0, 12).equals(ed25519SpkiPrefix)) throw new Error("unexpected signer key type");

    const recipientPublicKey = fromB64u(input.readerPublicKey);
    const derivedReaderId = `p256:${sha256(recipientPublicKey).toString("hex")}`;
    if (derivedReaderId !== input.readerDeviceId || cek.length !== 32) throw new Error("reader identity or CEK invalid");
    const now = input.nowMillis;
    const revision = input.ownerRevision || 1;
    const revokedDeviceIds = input.revokedDeviceIds || [];
    const headDigestFields = {
      origin: input.origin,
      username: input.username,
      readerDeviceId: derivedReaderId,
      ownerRevision: revision,
      revokedDeviceIds,
      issuedAtMillis: now,
      expiresAtMillis: now + 300000,
    };
    const ownerDigest = b64u(sha256(Buffer.from(
      "Root.ark/android/owner-head-digest/v2\0" + canonical(headDigestFields), "utf8",
    )));
    const headFields = {
      schema: "rootark-android-owner-head/v2",
      ...headDigestFields,
      ownerDigest,
    };
    const head = {
      ...headFields,
      signature: sign(ownerPrivate, "Root.ark/android/owner-head-v2\0", headFields),
    };

    const cekSha256 = b64u(sha256(cek));
    const nonce = b64u(sha256(Buffer.concat([
      Buffer.from("Root.ark/android/test-grant-nonce/v2\0"), cek, recipientPublicKey,
    ])).subarray(0, 16));
    const contextFields = {
      schema: "rootark-android-cek-read-hpke/v2",
      origin: input.origin,
      username: input.username,
      readerDeviceId: derivedReaderId,
      ownerRevision: revision,
      ownerDigest,
      objectId: input.objectId || "object-1",
      fileId: input.fileId || "file-1",
      versionId: input.versionId || "version-1",
      compartmentId: input.compartmentId || "compartment-1",
      keyEpoch: input.keyEpoch || "epoch-1",
      signerDeviceId: input.signerDeviceId || "signer-device-1",
      signerPublicKeySpki: b64u(signerPublicSpki),
      cekSha256,
      nonce,
      issuedAtMillis: now,
      expiresAtMillis: now + 240000,
      hpkeSuite: "DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM",
    };
    const wrapped = seal(cek, recipientPublicKey, ownerPublicSpki, contextFields);
    const grantFields = { ...contextFields, ...wrapped };
    const grant = {
      ...grantFields,
      signature: sign(ownerPrivate, "Root.ark/android/cek-read-hpke-v2\0", grantFields),
    };
    process.stdout.write(JSON.stringify({
      schema: "rootark-android-enrollment-package/v2",
      ownerPublicSpki: b64u(ownerPublicSpki),
      head,
      grant,
    }));
  } finally {
    inputBytes.fill(0);
    ownerPrivateBytes?.fill(0);
    signerPrivateBytes?.fill(0);
    cek?.fill(0);
  }
}

main().catch(() => {
  process.stderr.write("owner enrollment vector generation failed\n");
  process.exitCode = 1;
});
