"use strict";

// Read-only, explicitly opt-in CloudStorage inventory preflight. This does NOT
// authorize migration, materialize cloud objects, enumerate local files or
// expose private filenames/provider IDs. Live mutation needs a separate
// provider-neutral ZK data-plane fence and owner-approved rollback contract.
const crypto = require("node:crypto");
const BLOCKERS = Object.freeze([
  "missing-version-history",
  "missing-backup-inventory",
  "missing-trash-sync-webdav-inventory",
  "missing-content-integrity-proof",
  "missing-authorized-key-recovery",
  "missing-physical-migration-fence",
]);

function refuse() {
  const error = new Error("ZK_MIGRATION_PREFLIGHT_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function component(v) {
  return typeof v === "string" && v.length > 0 && v.length <= 1024
    && !v.includes("\\") && !v.includes("\u0000") && !v.includes("/")
    && v !== "." && v !== "..";
}
function scoped(entry, provider) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)
    || entry.provider !== provider
    || !["uploads", "temp"].includes(entry.area)
    || !component(entry.folderId) || !component(entry.name)
    || typeof entry.providerIdentity !== "string"
    || entry.providerIdentity.length < 1 || entry.providerIdentity.length > 1024
    || typeof entry.key !== "string" || entry.key.length > 3072
    || entry.key.includes("\\") || entry.key.includes("\u0000")) refuse();
  const suffix = `/${entry.area}/${entry.folderId}/${entry.name}`;
  if (!entry.key.endsWith(suffix) || entry.key.length <= suffix.length
    || entry.key.startsWith("/") || entry.key.includes("//")) refuse();
  const prefix = entry.key.slice(0, -suffix.length);
  if (prefix.split("/").some((p) => !component(p))) refuse();
  return entry;
}

async function inspectZk1CloudMigrationReadiness({ cloudStorage } = {}) {
  if (!cloudStorage || typeof cloudStorage !== "object"
    || ["status", "enabled", "resolveInventoryContext", "inventory"]
      .some((name) => typeof cloudStorage[name] !== "function")) refuse();
  try {
    const status = cloudStorage.status();
    const provider = status?.provider;
    if (!["s3", "gdrive"].includes(provider)
      || status.enabled !== true || cloudStorage.enabled() !== true) refuse();
    const identity = await cloudStorage.resolveInventoryContext();
    if (typeof identity !== "string" || !/^[a-f0-9]{64}$/.test(identity)) refuse();
    const items = await cloudStorage.inventory();
    const after = await cloudStorage.resolveInventoryContext();
    if (after !== identity || !Array.isArray(items) || items.length > 10000) refuse();
    // The report is not a stable migration catalogue. These opaque references
    // deliberately rotate on each invocation to prevent cross-run tracking.
    const runSecret = crypto.randomBytes(32);
    const ids = new Set();
    const keys = new Set();
    const objects = [];
    for (const raw of items) {
      const item = scoped(raw, provider);
      const id = `${provider}:${item.providerIdentity}`;
      if (ids.has(id) || keys.has(item.key)) refuse();
      ids.add(id);
      keys.add(item.key);
      objects.push({ area: item.area,
        reference: crypto.createHmac("sha256", runSecret)
          .update(JSON.stringify([id, item.key])).digest("base64url") });
    }
    objects.sort((a, b) => a.reference.localeCompare(b.reference));
    return Object.freeze({
      schema: "rootark-zk1-cloud-migration-readiness/v1",
      provider,
      readOnly: true,
      canMigrate: false,
      rollbackReady: false,
      consistency: "two-provider-identity-probes-not-atomic-inventory",
      inspectedAreas: ["uploads", "temp"],
      objects,
      blockers: [...BLOCKERS],
    });
  } catch (_) { refuse(); }
}

module.exports = { inspectZk1CloudMigrationReadiness };
