"use strict";

// Optional legacy S3/Drive copy-reference observation, not a migration or a
// complete provider listing. Owner-signed scope + independently signed
// generation fence must agree before and after bounded, read-only inventory.
// The caller pins separate owner and generation Ed25519 public keys. Scope is
// lower-case hex for account_id, compartment_id and keyring_id; both signed
// statements use the exact declared field order below. Generation callbacks
// sign the fresh caller nonce with GENERATION_DOMAIN, not cached old receipts.
const crypto = require("node:crypto");
const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/legacy-remote-copy-scan/owner/v1\0");
const GENERATION_DOMAIN = Buffer.from("Root.ark/zk-1/legacy-remote-copy-scan/generation/v1\0");
const MAX_ITEMS = 5000;
const MAX_PAGES = 8;

function deny() {
  const error = new Error("ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![null, Object.prototype].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length) deny();
  const copy = {};
  for (const name of fields) {
    const prop = Object.getOwnPropertyDescriptor(value, name);
    if (!prop || !Object.hasOwn(prop, "value")) deny();
    copy[name] = prop.value;
  }
  return copy;
}
function fingerprintKey(value) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function scopeOf(raw) {
  const values = exact(raw, ["account_id", "compartment_id", "keyring_id"]);
  for (const [name, value] of Object.entries(values)) {
    if (typeof value !== "string" || !/^(?:[a-f0-9]{2})+$/.test(value)
      || (name === "compartment_id" ? value.length > 256
        : value.length !== 32)) deny();
  }
  return values;
}
function component(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= 255
    && !/[\\/\x00-\x1f<>:"|?*]/.test(value) && value !== "." && value !== ".."
    && !value.endsWith(".") && !value.endsWith(" ");
}
function signed(raw, fields, key, domain) {
  const pair = exact(raw, ["statement", "signature"]);
  const body = exact(pair.statement, fields);
  if (typeof pair.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(pair.signature)) deny();
  const signature = Buffer.from(pair.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== pair.signature
    || !crypto.verify(null, Buffer.concat([domain,
      Buffer.from(JSON.stringify(body))]), fingerprintKey(key), signature)) deny();
  return body;
}
const OWNER_FIELDS = ["type", "scope", "provider", "namespaceIdentity",
  "readerContext", "folderIds", "generation", "issuedAt", "expiresAt"];
const GENERATION_FIELDS = ["type", "scope", "provider", "namespaceIdentity",
  "readerContext", "generation", "nonce"];
const hex64 = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

function checkGeneration(raw, nonce, key, expected) {
  const body = signed(raw, GENERATION_FIELDS, key, GENERATION_DOMAIN);
  if (body.type !== "rootark-zk1-legacy-remote-copy-generation/v1"
    || JSON.stringify(scopeOf(body.scope)) !== JSON.stringify(expected.scope)
    || body.provider !== expected.provider
    || body.namespaceIdentity !== expected.namespaceIdentity
    || body.readerContext !== expected.readerContext
    || body.generation !== expected.generation || body.nonce !== nonce) deny();
}

async function inspectZk1LiveLegacyRemoteCopyEvidence({ optIn, cloudStorage, scope,
  authorization, pinnedOwnerPublicKey, pinnedGenerationPublicKey,
  readSignedGeneration } = {}) {
  if (optIn !== true || !cloudStorage || typeof cloudStorage !== "object"
    || ["status", "enabled", "zk1StorageNamespace", "resolveInventoryContext", "inventory"]
      .some((name) => typeof cloudStorage[name] !== "function")
    || typeof readSignedGeneration !== "function") deny();
  const ownerKey = fingerprintKey(pinnedOwnerPublicKey);
  const generationKey = fingerprintKey(pinnedGenerationPublicKey);
  if (ownerKey.export({ format: "der", type: "spki" }).equals(
    generationKey.export({ format: "der", type: "spki" }))) deny();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  // An uncooperative read-only inventory may retain a network request after
  // abort. Never wait indefinitely or grant a positive observation from it.
  const bounded = async (work) => {
    if (controller.signal.aborted) deny();
    let cancel;
    const expired = new Promise((_, reject) => {
      cancel = () => reject(new Error("READ_ONLY_SCAN_TIMEOUT"));
      controller.signal.addEventListener("abort", cancel, { once: true });
    });
    try { return await Promise.race([Promise.resolve().then(work), expired]); }
    finally { controller.signal.removeEventListener("abort", cancel); }
  };
  try {
    const owner = signed(authorization, OWNER_FIELDS, pinnedOwnerPublicKey, OWNER_DOMAIN);
    const scoped = scopeOf(scope);
    if (JSON.stringify(scoped) !== JSON.stringify(scopeOf(owner.scope))) deny();
    const status = cloudStorage.status();
    const provider = status?.provider;
    const namespaceIdentity = cloudStorage.zk1StorageNamespace();
    if (!["s3", "gdrive"].includes(provider) || status.enabled !== true
      || cloudStorage.enabled() !== true || !hex64(namespaceIdentity)
      || owner.type !== "rootark-zk1-legacy-remote-copy-owner/v1"
      || owner.provider !== provider || owner.namespaceIdentity !== namespaceIdentity
      || !Number.isSafeInteger(owner.generation) || owner.generation < 1
      || !Number.isSafeInteger(owner.issuedAt) || !Number.isSafeInteger(owner.expiresAt)
      || owner.issuedAt > Math.floor(Date.now() / 1000)
      || owner.expiresAt <= Math.floor(Date.now() / 1000)
      || owner.expiresAt - owner.issuedAt > 300
      || !Array.isArray(owner.folderIds) || owner.folderIds.length < 1
      || owner.folderIds.length > 256
      || Reflect.ownKeys(owner.folderIds).length !== owner.folderIds.length + 1
      || owner.folderIds.some((folder) => !component(folder))
      || new Set(owner.folderIds).size !== owner.folderIds.length
      || [...owner.folderIds].sort().some((folder, i) => folder !== owner.folderIds[i])) deny();
    const allowed = new Set(owner.folderIds);
    const readerContext = await bounded(() => cloudStorage.resolveInventoryContext());
    if (!hex64(readerContext) || readerContext !== owner.readerContext
      || controller.signal.aborted) deny();
    const expected = { scope: scoped, provider, namespaceIdentity,
      readerContext, generation: owner.generation };
    const probe = async () => {
      const nonce = crypto.randomBytes(32).toString("base64url");
      checkGeneration(await bounded(() => readSignedGeneration(nonce)), nonce,
        pinnedGenerationPublicKey, expected);
      if (controller.signal.aborted) deny();
    };
    await probe();
    const items = await bounded(() => cloudStorage.inventory({ maxEntries: MAX_ITEMS,
      maxPages: MAX_PAGES, abortSignal: controller.signal }));
    if (!Array.isArray(items) || items.length > MAX_ITEMS
      || Reflect.ownKeys(items).length !== items.length + 1
      || controller.signal.aborted) deny();
    const names = new Set(), identities = new Set();
    const records = [];
    for (const raw of items) {
      const entry = exact(raw, ["provider", "providerIdentity", "key", "area", "folderId", "name",
        ...(provider === "gdrive" ? ["id"] : [])]);
      if (entry.provider !== provider || !["uploads", "temp"].includes(entry.area)
        || !component(entry.folderId) || !allowed.has(entry.folderId)
        || !component(entry.name) || typeof entry.key !== "string"
        || entry.key.length > 3072 || entry.key.startsWith("/")
        || entry.key.includes("\\") || entry.key.includes("//")
        || !entry.key.endsWith(`/${entry.area}/${entry.folderId}/${entry.name}`)
        || entry.key.split("/").some((segment) => !component(segment))
        || typeof entry.providerIdentity !== "string" || entry.providerIdentity.length > 1024
        || entry.providerIdentity.length < 1
        || (provider === "s3" && entry.providerIdentity !== entry.key)
        || (provider === "gdrive" && (entry.id !== entry.providerIdentity
          || !/^[A-Za-z0-9_-]{1,256}$/.test(entry.id)))
        || names.has(entry.key) || identities.has(entry.providerIdentity)) deny();
      names.add(entry.key);
      identities.add(entry.providerIdentity);
      records.push([entry.area, entry.folderId, entry.name, entry.key, entry.providerIdentity]);
    }
    records.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    await probe();
    if (await bounded(() => cloudStorage.resolveInventoryContext()) !== readerContext
      || cloudStorage.zk1StorageNamespace() !== namespaceIdentity || controller.signal.aborted
      || Math.floor(Date.now() / 1000) >= owner.expiresAt) deny();
    const ephemeralFingerprint = crypto.createHmac("sha256", crypto.randomBytes(32))
      .update("rootark-zk1-legacy-remote-copy-observation/v1\0")
      .update(JSON.stringify(records)).digest("base64url");
    return Object.freeze({ observation: "partial-owner-scoped-remote-provider-references-only",
      provider, observedCopies: records.length, readOnly: true, globallyComplete: false,
      authorizesCutover: false, providerDurabilityProven: false,
      generationStableInSignedProbes: true, inventorySnapshotAtomic: false,
      providerObjectVersionVerified: false, legacySqlJoinVerified: false,
      ephemeralFingerprint });
  } catch (_) { deny(); }
  finally { clearTimeout(timeout); controller.abort(); }
}
module.exports = { inspectZk1LiveLegacyRemoteCopyEvidence };
