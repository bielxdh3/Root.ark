(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(require("../../sync-client/rootark-sync-paths"));
  else root.RootarkSyncAdapter = factory(root.RootarkSyncPaths);
}(typeof globalThis === "object" ? globalThis : this, function (sharedPaths) {
  "use strict";

  class SyncConflictError extends Error {
    constructor(payload = {}) {
      super(payload.error || "Sync conflict");
      this.name = "SyncConflictError";
      this.code = "sync_conflict";
      this.status = 409;
      this.current = payload.current || null;
      this.currentRevision = payload.currentRevision || this.current?.revision || null;
      this.payload = payload;
    }
  }

  const PROTOCOL_VERSION = 2;
  const OPERATION_FIELDS = ["protocolVersion", "operationId", "objectId", "fileId", "versionId", "operation", "revision", "baseRevision", "keyEpoch", "compartmentId", "deviceId", "metadata", "tombstone", "ciphertext", "nonce", "tag", "aad", "authorization"];
  const OPTIONAL_FIELDS = new Set(["authorization"]);
  const AUTHORIZATION_FIELDS = ["schemaVersion", "type", "suite", "protocolVersion", "username", "deviceId", "operationId", "objectId", "fileId", "versionId", "operation", "revision", "baseRevision", "keyEpoch", "compartmentId", "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest", "expiresAt", "replayId", "idempotencyKey", "publicKey", "signature"];
  const METADATA = {
    create: new Set(["fileId", "versionId", "path", "parentId", "name", "contentType", "size", "keyEpoch", "compartmentId", "deviceId"]),
    update: new Set(["fileId", "versionId", "path", "parentId", "name", "contentType", "size", "keyEpoch", "compartmentId", "deviceId"]),
    move: new Set(["fileId", "versionId", "path", "sourcePath", "keyEpoch", "compartmentId", "deviceId"]),
    delete: new Set(["fileId", "versionId", "path", "keyEpoch", "compartmentId", "deviceId"]),
  };
  const RESERVED = new Set([".rootark-trash", ".rootark-sync", ".rootark-sync-state.json", ".rootark-sync.json", ".rootark-sync-journal.json", ".rootark-sync-index.json", ".rootark-sync.lock"]);
  const RESERVED_PREFIXES = [".rootark-sync-lock-init-"];

  function fail(message) { throw new Error(message); }

  function canonicalize(value) {
    if (value === null || typeof value !== "object") return value;
    if (Array.isArray(value)) return value.map(canonicalize);
    return Object.keys(value).sort().reduce((result, key) => { result[key] = canonicalize(value[key]); return result; }, {});
  }

  function canonicalJson(value) { return JSON.stringify(canonicalize(value)); }

  function exact(value, keys, name) {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(`Invalid ${name}`);
    const allowed = new Set(keys);
    Object.keys(value).forEach((key) => { if (!allowed.has(key)) fail(`Unknown ${name} field`); });
    keys.forEach((key) => { if (!OPTIONAL_FIELDS.has(key) && !Object.hasOwn(value, key)) fail(`Missing ${name} field`); });
  }

  function allowedOnly(value, keys, name) {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(`Invalid ${name}`);
    const allowed = new Set(keys);
    Object.keys(value).forEach((key) => { if (!allowed.has(key)) fail(`Unknown ${name} field`); });
  }

  function portablePath(value) {
    if (sharedPaths?.validatePortableRelativePath) return sharedPaths.validatePortableRelativePath(value, "path");
    const text = String(value || "");
    if (!text || text.includes("%") || text.includes("\\") || text.includes(":") || text.startsWith("/") || /[\u0000-\u001f\u007f]/.test(text)) fail("Invalid metadata path");
    const dos = /^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$/i;
    if (text.split("/").some((part) => !part || part === "." || part === ".." || RESERVED.has(part.toLowerCase()) || RESERVED_PREFIXES.some((prefix) => part.toLowerCase().startsWith(prefix)) || dos.test(part) || /[. ]$/.test(part))) fail("Invalid metadata path");
    return text;
  }

  function id(value) {
    const text = String(value || "");
    if (!text || text.length > 160 || !/^[A-Za-z0-9._:-]+$/.test(text)) fail("Invalid sync id");
    return text;
  }

  function revision(value, optional) {
    if (value === null && optional) return null;
    exact(value, ["counter", "deviceId"], "revision");
    if (!Number.isSafeInteger(value.counter) || value.counter < 0) fail("Invalid revision");
    return { counter: value.counter, deviceId: id(value.deviceId) };
  }

  function decoded(value, field) {
    if (typeof value !== "string" || (field !== "ciphertext" && !value) || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) fail("Invalid encrypted field");
    let binary;
    try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch { fail("Invalid encrypted field"); }
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    let roundTrip = "";
    bytes.forEach((byte) => { roundTrip += String.fromCharCode(byte); });
    if (btoa(roundTrip).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "") !== value) fail("Non-canonical encrypted field");
    if (field === "nonce" && bytes.length !== 12 || field === "tag" && bytes.length !== 16) fail("Invalid encrypted field length");
    return new TextDecoder().decode(bytes);
  }

  function metadata(value, operation) {
    allowedOnly(value, [...METADATA[operation]], "metadata");
    const result = {};
    for (const key of Object.keys(value)) {
      const item = value[key];
      if (key === "size") { if (!Number.isSafeInteger(item) || item < 0) fail("Invalid metadata size"); result[key] = item; }
      else if (["path", "sourcePath"].includes(key)) {
        result[key] = portablePath(item);
      } else if (["name", "contentType"].includes(key)) {
        const text = String(item || "");
        if (!text || text.length > 512 || /[\u0000-\u001f\u007f]/.test(text)) fail("Invalid metadata text");
        result[key] = text;
      } else result[key] = id(item);
    }
    if (!result.path || (operation === "move" && !result.sourcePath)) fail("Operation path is required");
    return canonicalize(result);
  }

  function authorization(value) {
    exact(value, AUTHORIZATION_FIELDS, "authorization");
    if (value.schemaVersion !== 1 || value.type !== "rootark-sync-device-authorization-v1" || value.suite !== "rootark-zk-1") fail("Invalid device authorization");
    for (const field of ["aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest", "replayId", "idempotencyKey", "publicKey", "signature"]) decoded(value[field], "authorization");
    if (!Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) fail("Expired device authorization");
    return canonicalize(value);
  }

  function aadFor(operation) {
    return canonicalJson({ protocolVersion: PROTOCOL_VERSION, objectId: operation.objectId, fileId: operation.fileId, versionId: operation.versionId, operation: operation.operation, revision: operation.revision, baseRevision: operation.baseRevision, keyEpoch: operation.keyEpoch, compartmentId: operation.compartmentId, deviceId: operation.deviceId, metadata: operation.metadata, tombstone: operation.tombstone });
  }

  function assertOpaqueEnvelope(input) {
    exact(input, OPERATION_FIELDS, "operation");
    if (input.protocolVersion !== PROTOCOL_VERSION || !["create", "update", "move", "delete"].includes(input.operation)) fail("Unsupported sync operation");
    const operation = { ...input, objectId: id(input.objectId), fileId: id(input.fileId), versionId: id(input.versionId), operationId: id(input.operationId), keyEpoch: id(input.keyEpoch), compartmentId: id(input.compartmentId), deviceId: id(input.deviceId), revision: revision(input.revision), baseRevision: revision(input.baseRevision, true), metadata: metadata(input.metadata, input.operation), tombstone: input.operation === "delete" };
    if (input.authorization !== undefined) operation.authorization = authorization(input.authorization);
    if (input.tombstone !== operation.tombstone) fail("Invalid tombstone flag");
    const aad = decoded(input.aad, "aad");
    decoded(input.ciphertext, "ciphertext");
    decoded(input.nonce, "nonce");
    decoded(input.tag, "tag");
    if (aad !== aadFor(operation)) fail("AAD binding mismatch");
    return { ...operation, ciphertext: input.ciphertext, nonce: input.nonce, tag: input.tag, aad: input.aad };
  }

  function createOpaqueSyncAdapter({ fetchImpl = fetch, baseUrl = "" } = {}) {
    const request = async (url, options = {}) => {
      const response = await fetchImpl(`${baseUrl}${url}`, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
      const payload = await response.json().catch(() => ({}));
      if (response.status === 409) throw new SyncConflictError(payload);
      if (!response.ok) throw Object.assign(new Error(payload.error || "Falha de sincronizacao"), { status: response.status, payload });
      return payload;
    };
    return {
      list: async (objectId = "") => {
        const payload = await request(`/sync/v1/objects${objectId ? `/${encodeURIComponent(objectId)}` : ""}`);
        if (Array.isArray(payload.objects)) return { ...payload, protocolVersion: PROTOCOL_VERSION, objects: payload.objects.map(assertOpaqueEnvelope) };
        return assertOpaqueEnvelope(payload);
      },
      push: (envelope) => {
        const normalized = assertOpaqueEnvelope(envelope);
        const deleteRequest = normalized.operation === "delete";
        return request(`/sync/v1/objects${deleteRequest ? `/${encodeURIComponent(normalized.objectId)}` : ""}`, { method: deleteRequest ? "DELETE" : "POST", body: JSON.stringify(normalized) });
      },
      validate: assertOpaqueEnvelope,
      normalize: assertOpaqueEnvelope,
      protocolVersion: PROTOCOL_VERSION,
    };
  }

  return { PROTOCOL_VERSION, OPERATION_FIELDS, SyncConflictError, assertOpaqueEnvelope, createOpaqueSyncAdapter, normalizeOpaqueEnvelope: assertOpaqueEnvelope };
}));
