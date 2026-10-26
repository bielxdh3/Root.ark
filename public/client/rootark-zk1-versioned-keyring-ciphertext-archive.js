"use strict";

// Node/WebCrypto offline adapter. Its sealed v2 records preserve the ORIGINAL
// ciphertext and user-held CEK for every owner-inventoried version. No cloud
// custody, global discovery, or production restore authority is implied.
const keyring = require("./rootark-zk1-keyring-portable-archive");
const FORMAT = "rootark-zk1-versioned-ciphertext-cek/v1";
const MAX_VERSIONS = 12;
function deny() { throw new Error("ZK_VERSIONED_KEYRING_ARCHIVE_DENIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((name) => !Object.hasOwn(value, name))) deny();
}
function copyBytes(value, min, max = min) {
  if (!(value instanceof Uint8Array) || value.byteLength < min
    || value.byteLength > max || value.buffer instanceof SharedArrayBuffer) deny();
  return Buffer.from(value);
}
async function createVersionedArchive(input) {
  let files = [];
  try {
    exact(input, ["archiveInput", "versions", "verifiedAuthority"]);
    if (!Array.isArray(input.versions) || input.versions.length < 1
      || input.versions.length > MAX_VERSIONS
      || Reflect.ownKeys(input.versions).length !== input.versions.length + 1) deny();
    for (const entry of input.versions) {
      exact(entry, ["metadata", "objectRevision", "ciphertext", "cek"]);
      const ciphertext = copyBytes(entry.ciphertext, 16, 1536 * 1024);
      const cek = copyBytes(entry.cek, 32);
      try {
        const packet = { format: FORMAT, ciphertextBase64: ciphertext.toString("base64url"),
          cekBase64: cek.toString("base64url") };
        const data = Buffer.from(JSON.stringify(packet), "utf8");
        if (data.length > 2 * 1024 * 1024) deny();
        files.push({ metadata: entry.metadata, objectRevision: entry.objectRevision,
          name: "opaque-ciphertext-version", mediaType: "application/octet-stream", data });
      } finally { ciphertext.fill(0); cek.fill(0); }
    }
    const options = { ...input.archiveInput, files,
      versionedAuthority: input.verifiedAuthority };
    return await keyring.createArchive(options);
  } catch (_) { deny(); }
  finally { for (const file of files) file.data.fill(0); }
}
async function recoverVersionedArchive(input) {
  try {
    exact(input, ["recoveryInput", "verifiedAuthority"]);
    return await keyring.recoverArchive({
      ...input.recoveryInput, versionedAuthority: input.verifiedAuthority });
  } catch (_) { deny(); }
}
module.exports = Object.freeze({
  verifyVersionedAuthority: keyring.verifyVersionedAuthority,
  createVersionedArchive, recoverVersionedArchive,
});
