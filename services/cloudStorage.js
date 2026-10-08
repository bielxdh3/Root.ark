const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { pipeline } = require("stream/promises");
const { normalizeProviderError } = require("../src/services/deploymentResilience");

function createCloudStorage(options = {}) {
  const provider = String(options.provider || "local").toLowerCase();
  const prefix = normalizePrefix(options.prefix || "rootark");
  const rootFolderId = String(options.rootFolderId || "root");
  const createS3Client = options.createS3Client || defaultS3Client(options.s3 || {});
  const createGoogleDriveClient = options.createGoogleDriveClient || defaultGoogleDriveClient(options.gdrive || {});
  let s3Client;
  let driveClient;
  let resolvedInventoryContext = null;

  function enabled() { return provider === "s3" || provider === "gdrive"; }
  function status() {
    return {
      provider,
      enabled: enabled(),
      prefix,
      s3: { bucketConfigured: Boolean(options.s3?.bucket), region: options.s3?.region || "", endpointConfigured: Boolean(options.s3?.endpoint) },
      gdrive: { folderConfigured: Boolean(options.gdrive?.folderId), credentialsConfigured: Boolean(options.gdrive?.credentials || options.gdrive?.credentialsPath) },
    };
  }
  function inventoryContext() {
    if (!resolvedInventoryContext) throw new Error("Cloud provider identity has not been resolved; cloud access remains blocked");
    return resolvedInventoryContext;
  }
  async function resolveInventoryContext() {
    if (resolvedInventoryContext) return resolvedInventoryContext;
    try {
      const principal = typeof options.resolvePrincipalIdentity === "function"
        ? await options.resolvePrincipalIdentity({ provider, s3: options.s3 || {}, gdrive: options.gdrive || {} })
        : await resolvePrincipalIdentity();
      if (typeof principal !== "string" || !principal.trim()) throw new Error("missing provider identity");
      const namespace = provider === "s3"
        ? [provider, prefix, rootFolderId, options.s3?.bucket || "", options.s3?.region || "", options.s3?.endpoint || "", Boolean(options.s3?.forcePathStyle)]
        : provider === "gdrive"
          ? [provider, prefix, rootFolderId, options.gdrive?.folderId || ""]
          : [provider, prefix];
      resolvedInventoryContext = crypto.createHash("sha256").update(JSON.stringify([...namespace, principal.trim()])).digest("hex");
      return resolvedInventoryContext;
    } catch {
      throw new Error("Cloud provider identity could not be resolved; cloud access remains blocked");
    }
  }
  async function resolvePrincipalIdentity() {
    if (provider === "s3") {
      const s3Provider = await s3();
      if (options.s3?.endpoint) {
        const principalId = String(options.s3?.principalId || "").trim();
        if (!principalId) throw new Error("missing custom S3 principal identifier");
        return `s3-compatible:${principalId}`;
      }
      const { STSClient, GetCallerIdentityCommand } = require("@aws-sdk/client-sts");
      const sts = options.createStsClient
        ? await options.createStsClient(s3Provider)
        : new STSClient({ region: options.s3?.region || "us-east-1", credentials: s3Provider.config.credentials });
      try {
        const identity = await sts.send(new GetCallerIdentityCommand({}));
        if (!identity.Account || !identity.Arn) throw new Error("missing identity fields");
        return `${identity.Account}:${stableAwsPrincipal(identity.Arn)}`;
      } finally { sts.destroy(); }
    }
    if (provider === "gdrive") {
      const response = await (await drive()).about.get({ fields: "user(permissionId,emailAddress)" });
      const user = response?.data?.user;
      const identity = String(user?.permissionId || "").trim();
      if (!identity) throw new Error("missing Google Drive identity");
      return `gdrive:${identity}`;
    }
    return "local";
  }
  function key(folderId = rootFolderId, fileName = "", area = "uploads") {
    const segment = (value, name) => {
      const raw = String(value || "").replace(/\\/g, "/");
      if (raw.startsWith("/")) throw cloudError("invalid_path", `Invalid ${name}`);
      const clean = raw.replace(/^\/+|\/+$/g, "");
      if (!clean || clean.split("/").some((part) => !part || part === "." || part === "..")) throw cloudError("invalid_path", `Invalid ${name}`);
      return clean;
    };
    const safeArea = segment(area, "area");
    const safeFolder = segment(folderId || rootFolderId, "folder");
    if (!fileName) return path.posix.join(prefix, safeArea, safeFolder);
    const normalized = String(fileName).replace(/\\/g, "/");
    if (normalized.includes("/") || normalized === "." || normalized === "..") throw cloudError("invalid_path", "Invalid filename");
    return path.posix.join(prefix, safeArea, safeFolder, normalized);
  }
  function objectKey(folderId, fileName, area) {
    if (!fileName) throw cloudError("invalid_path", "Invalid filename");
    return key(folderId, fileName, area);
  }
  async function s3() { if (!s3Client) s3Client = await createS3Client(); return s3Client; }
  async function drive() { if (!driveClient) driveClient = await createGoogleDriveClient(); return driveClient; }
  function assertProvider() { if (!["local", "s3", "gdrive"].includes(provider)) throw cloudError("unsupported_provider", "Unsupported cloud provider"); }
  function bucket() { if (!options.s3?.bucket) throw cloudError("configuration", "S3 bucket is not configured"); return options.s3.bucket; }
  function folder() { if (!options.gdrive?.folderId) throw cloudError("configuration", "Google Drive folder is not configured"); return options.gdrive.folderId; }
  function escapeQuery(value) { return String(value).replace(/'/g, "\\'"); }
  async function findDriveFile(cloudKey, folderId, area) {
    const result = await (await drive()).files.list({
      q: `appProperties has { key='rootArkKey' and value='${escapeQuery(cloudKey)}' } and trashed=false`,
      fields: "files(id,name,parents,appProperties)",
      spaces: "drive",
      pageSize: 100,
    });
    const files = result.data.files || [];
    for (const file of files) assertDriveFileOwnership(file, cloudKey, folderId, area);
    return files.sort((a, b) => String(a.id).localeCompare(String(b.id)))[0] || null;
  }
  async function resolveUploadId(folderId, fileName, area = "uploads") {
    assertProvider();
    if (provider !== "gdrive") throw cloudError("unsupported_provider", "Stable upload IDs are supported only by Google Drive");
    const cloudKey = objectKey(folderId, fileName, area);
    const existing = await findDriveFile(cloudKey, folderId, area);
    if (existing) {
      const file = await getDriveFile(existing.id);
      assertDriveFileOwnership(file, cloudKey, folderId, area);
      return String(file.id);
    }
    const result = await (await drive()).files.generateIds({ count: 1, space: "drive", fields: "ids" });
    const id = String(result.data.ids?.[0] || "");
    if (!isDriveFileId(id)) throw cloudError("provider_error", "Google Drive did not reserve a valid file ID");
    return id;
  }
  async function getDriveFile(fileId) {
    return (await (await drive()).files.get({ fileId, fields: "id,parents,appProperties" })).data;
  }
  function assertDriveFileOwnership(file, cloudKey, folderId, area) {
    const properties = file?.appProperties || {};
    if (!file?.id || properties.rootArkKey !== cloudKey
      || String(properties.rootArkFolderId || "") !== String(folderId || rootFolderId)
      || String(properties.rootArkArea || "") !== String(area)
      || !Array.isArray(file.parents) || !file.parents.includes(folder())) {
      throw cloudError("provider_error", "Google Drive file does not belong to this object");
    }
  }
  function driveRequestBody(folderId, fileName, area, cloudKey) {
    return {
      name: fileName,
      appProperties: { rootArkKey: cloudKey, rootArkFolderId: String(folderId || rootFolderId), rootArkArea: area },
    };
  }
  async function uploadToPinnedDriveId(localPath, fileId, requestBody, cloudKey, folderId, area) {
    const client = await drive();
    let existing;
    try { existing = await getDriveFile(fileId); }
    catch (error) { if (!isDriveStatus(error, 404)) throw error; }
    if (existing) {
      assertDriveFileOwnership(existing, cloudKey, folderId, area);
      await client.files.update({ fileId, requestBody, media: { body: fs.createReadStream(localPath) }, fields: "id" });
      return { provider, key: cloudKey, id: fileId };
    }
    try {
      const result = await client.files.create({ requestBody: { ...requestBody, id: fileId, parents: [folder()] }, media: { body: fs.createReadStream(localPath) }, fields: "id" });
      return { provider, key: cloudKey, id: String(result.data.id || fileId) };
    } catch (error) {
      if (!isDriveStatus(error, 409)) throw error;
      const raced = await getDriveFile(fileId);
      assertDriveFileOwnership(raced, cloudKey, folderId, area);
      await client.files.update({ fileId, requestBody, media: { body: fs.createReadStream(localPath) }, fields: "id" });
      return { provider, key: cloudKey, id: fileId };
    }
  }
  function parseInventoryKey(value) {
    const clean = String(value || "").replace(/\\/g, "/");
    const root = `${prefix}/`;
    if (!clean.startsWith(root)) throw cloudError("foreign_prefix", "Cloud object is outside the configured prefix");
    const parts = clean.slice(root.length).split("/");
    if (parts.length !== 3 || !["uploads", "temp"].includes(parts[0]) || !parts[1] || !parts[2]) {
      throw cloudError("invalid_inventory_key", "Cloud object key is malformed");
    }
    if (parts.some((part) => !part || part === "." || part === "..")) throw cloudError("invalid_inventory_key", "Cloud object key is unsafe");
    return { area: parts[0], folderId: parts[1], name: parts[2], key: clean };
  }
  async function inventory() {
    assertProvider();
    if (!enabled()) return [];
    const objects = [];
    const identities = new Set();
    const add = (entry) => {
      const identity = `${entry.provider}:${entry.providerIdentity || entry.key}`;
      if (identities.has(identity)) throw cloudError("duplicate_inventory_identity", "Cloud inventory contains a duplicate identity");
      identities.add(identity);
      objects.push(entry);
    };
    if (provider === "s3") {
      const bucketName = bucket();
      let token;
      do {
        const page = await (await s3()).send(new (require("@aws-sdk/client-s3").ListObjectsV2Command)({ Bucket: bucketName, Prefix: `${prefix}/`, ContinuationToken: token }));
        for (const object of page.Contents || []) {
          const parsed = parseInventoryKey(object.Key);
          add({ provider, providerIdentity: parsed.key, ...parsed });
        }
        token = page.NextContinuationToken;
      } while (token);
      return objects;
    }
    let token;
    do {
      const page = await (await drive()).files.list({
        q: "appProperties has { key='rootArkKey' } and trashed=false",
        fields: "nextPageToken,files(id,name,parents,appProperties)",
        spaces: "drive",
        pageToken: token,
        pageSize: 100,
      });
      for (const file of page.data.files || []) {
        if (!Array.isArray(file.parents) || !file.parents.includes(folder())) {
          throw cloudError("outside_configured_parent", "Drive object is outside the configured parent folder");
        }
        const properties = file.appProperties || {};
        const parsed = parseInventoryKey(properties.rootArkKey);
        if (String(properties.rootArkFolderId || "") !== parsed.folderId || String(properties.rootArkArea || "") !== parsed.area) {
          throw cloudError("invalid_inventory_metadata", "Drive metadata does not match rootArkKey");
        }
        if (!file.id) throw cloudError("invalid_inventory_identity", "Drive object is missing its identity");
        add({ provider, providerIdentity: String(file.id), id: String(file.id), ...parsed });
      }
      token = page.data.nextPageToken;
    } while (token);
    return objects;
  }
  async function upload(localPath, folderId, fileName, area = "uploads", uploadOptions = {}) {
    assertProvider(); if (!enabled() || !fs.statSync(localPath, { throwIfNoEntry: false })?.isFile()) return null;
    const cloudKey = objectKey(folderId, fileName, area);
    if (provider === "s3") { const bucketName = bucket(); await (await s3()).send(new (require("@aws-sdk/client-s3").PutObjectCommand)({ Bucket: bucketName, Key: cloudKey, Body: fs.createReadStream(localPath) })); return { provider, key: cloudKey }; }
    const providerFileId = String(uploadOptions?.providerFileId || "").trim();
    if (providerFileId) {
      if (!isDriveFileId(providerFileId)) throw cloudError("invalid_path", "Google Drive file ID is invalid");
      return uploadToPinnedDriveId(localPath, providerFileId, driveRequestBody(folderId, fileName, area, cloudKey), cloudKey, folderId, area);
    }
    const existing = await findDriveFile(cloudKey, folderId, area);
    const requestBody = driveRequestBody(folderId, fileName, area, cloudKey);
    const media = { body: fs.createReadStream(localPath) };
    if (existing) {
      const current = await getDriveFile(existing.id);
      assertDriveFileOwnership(current, cloudKey, folderId, area);
      await (await drive()).files.update({ fileId: existing.id, requestBody, media, fields: "id" });
      return { provider, key: cloudKey, id: existing.id };
    }
    const result = await (await drive()).files.create({ requestBody: { ...requestBody, parents: [folder()] }, media, fields: "id" }); return { provider, key: cloudKey, id: result.data.id };
  }
  async function download(folderId, fileName, localPath, area = "uploads", canPublish = () => true) {
    assertProvider(); if (!enabled() || fs.existsSync(localPath)) return false;
    const cloudKey = objectKey(folderId, fileName, area);
    const parentPath = path.dirname(localPath);
    fs.mkdirSync(parentPath, { recursive: true });
    const stagingDirectory = fs.mkdtempSync(path.join(parentPath, ".rootark-cloud-cache-"));
    const stagedPath = path.join(stagingDirectory, path.basename(localPath));
    try {
      let input;
      if (provider === "s3") { const bucketName = bucket(); input = (await (await s3()).send(new (require("@aws-sdk/client-s3").GetObjectCommand)({ Bucket: bucketName, Key: cloudKey }))).Body; }
      else {
        const existing = await findDriveFile(cloudKey, folderId, area);
        if (!existing) return false;
        const current = await getDriveFile(existing.id);
        assertDriveFileOwnership(current, cloudKey, folderId, area);
        input = (await (await drive()).files.get({ fileId: existing.id, alt: "media" }, { responseType: "stream" })).data;
      }
      await pipeline(input, fs.createWriteStream(stagedPath));
      if (typeof canPublish === "function" && !canPublish()) return false;
      if (fs.existsSync(localPath)) return true;
      fs.renameSync(stagedPath, localPath);
      return true;
    } catch (error) { throw classify(error); }
    finally { fs.rmSync(stagingDirectory, { recursive: true, force: true }); }
  }
  async function remove(folderId, fileName, area = "uploads") {
    assertProvider(); if (!enabled()) return false; const cloudKey = objectKey(folderId, fileName, area);
    if (provider === "s3") { const bucketName = bucket(); await (await s3()).send(new (require("@aws-sdk/client-s3").DeleteObjectCommand)({ Bucket: bucketName, Key: cloudKey })); return true; }
    const existing = await findDriveFile(cloudKey, folderId, area);
    if (!existing) return false;
    const current = await getDriveFile(existing.id);
    assertDriveFileOwnership(current, cloudKey, folderId, area);
    await (await drive()).files.delete({ fileId: existing.id });
    return true;
  }
  async function removePrefix(value) {
    assertProvider(); if (!enabled()) return false;
    const clean = normalizePrefix(value); if (clean !== prefix && !clean.startsWith(`${prefix}/`)) throw cloudError("invalid_prefix", "Prefix is outside cloud root");
    if (provider === "s3") { const bucketName = bucket(); let token; do { const page = await (await s3()).send(new (require("@aws-sdk/client-s3").ListObjectsV2Command)({ Bucket: bucketName, Prefix: `${clean}/`, ContinuationToken: token })); const objects = (page.Contents || []).map(({ Key }) => ({ Key })).filter(({ Key }) => Key); if (objects.length) { const deleted = await (await s3()).send(new (require("@aws-sdk/client-s3").DeleteObjectsCommand)({ Bucket: bucketName, Delete: { Objects: objects } })); if (deleted.Errors?.length) throw cloudError("partial_delete", "Cloud prefix deletion was incomplete"); } token = page.NextContinuationToken; } while (token); return true; }
    const relative = clean.startsWith(`${prefix}/`) ? clean.slice(prefix.length + 1) : "";
    const [area, ...folderSegments] = relative.split("/");
    const folderId = folderSegments.join("/");
    if (!folderId || !["uploads", "temp"].includes(area)) throw cloudError("invalid_prefix", "Invalid cloud prefix");
    const files = await list(folderId, area);
    for (const file of files) {
      const current = await getDriveFile(file.id);
      assertDriveFileOwnership(current, file.key, folderId, area);
      await (await drive()).files.delete({ fileId: file.id });
    }
    return true;
  }
  async function list(folderId, area = "uploads") {
    assertProvider(); if (!enabled()) return []; const prefixKey = `${key(folderId, "", area)}/`; const files = [];
    if (provider === "s3") {
      const bucketName = bucket(); let token;
      do {
        const page = await (await s3()).send(new (require("@aws-sdk/client-s3").ListObjectsV2Command)({ Bucket: bucketName, Prefix: prefixKey, ContinuationToken: token }));
        for (const item of page.Contents || []) {
          const objectKey = String(item.Key || "");
          if (!objectKey.startsWith(prefixKey)) continue;
          const name = objectKey.slice(prefixKey.length);
          if (!name || name.includes("/") || name === "." || name === "..") continue;
          const entry = { name, key: objectKey };
          if (Number.isFinite(item.Size)) entry.size = item.Size;
          if (item.LastModified instanceof Date && Number.isFinite(item.LastModified.getTime())) {
            entry.modifiedAt = item.LastModified.toISOString();
            entry.uploadedAt = entry.modifiedAt;
          }
          files.push(entry);
        }
        token = page.NextContinuationToken;
      } while (token);
      return files;
    }
    let token;
    do {
      const page = await (await drive()).files.list({
        q: `appProperties has { key='rootArkFolderId' and value='${escapeQuery(folderId || rootFolderId)}' } and appProperties has { key='rootArkArea' and value='${escapeQuery(area)}' } and trashed=false`,
        fields: "nextPageToken,files(id,name,size,createdTime,modifiedTime,parents,appProperties)",
        spaces: "drive",
        pageToken: token,
        pageSize: 100,
      });
      for (const file of page.data.files || []) {
        const properties = file.appProperties || {};
        const cloudKey = String(properties.rootArkKey || "");
        const name = path.posix.basename(cloudKey);
        if (!name || cloudKey !== key(folderId, name, area)
          || String(properties.rootArkFolderId || "") !== String(folderId || rootFolderId)
          || String(properties.rootArkArea || "") !== String(area)
          || !file.id || !Array.isArray(file.parents) || !file.parents.includes(folder())) continue;
        const entry = { name, id: file.id, key: cloudKey };
        const size = Number(file.size);
        if (Number.isFinite(size)) entry.size = size;
        if (typeof file.createdTime === "string") entry.uploadedAt = file.createdTime;
        if (typeof file.modifiedTime === "string") entry.modifiedAt = file.modifiedTime;
        files.push(entry);
      }
      token = page.data.nextPageToken;
    } while (token);
    return files;
  }
  const run = async (operation, ...args) => {
    try { return await operation(...args); } catch (error) { throw classify(error); }
  };
  return { provider, enabled, status, inventoryContext, resolveInventoryContext, key, inventory: (...args) => run(inventory, ...args), resolveUploadId: (...args) => run(resolveUploadId, ...args), upload: (...args) => run(upload, ...args), download: (...args) => run(download, ...args), remove: (...args) => run(remove, ...args), removePrefix: (...args) => run(removePrefix, ...args), list: (...args) => run(list, ...args) };
}

function normalizePrefix(value) { const clean = String(value || "").replace(/\\/g, "/").replace(/^\/+|\/+$/g, ""); if (!clean || clean.split("/").some((part) => !part || part === "." || part === "..")) throw cloudError("invalid_prefix", "Invalid cloud prefix"); return clean; }
function cloudError(code, message) { const error = new Error(message); error.code = code; return error; }
function isDriveFileId(value) { return /^[A-Za-z0-9_-]{1,256}$/.test(String(value || "")); }
function isDriveStatus(error, status) { return Number(error?.response?.status || error?.response?.data?.error?.code || error?.status || error?.code) === status; }
function classify(error) { return normalizeProviderError(error); }
function stableAwsPrincipal(arn) {
  const value = String(arn || "");
  const assumedRole = value.match(/^arn:([^:]+):sts::([^:]+):assumed-role\/(.+)\/[^/]+$/);
  if (assumedRole) return `arn:${assumedRole[1]}:iam::${assumedRole[2]}:role/${assumedRole[3]}`;
  return value;
}
function defaultS3Client(config) { return async () => { const { S3Client } = require("@aws-sdk/client-s3"); return new S3Client({ region: config.region || "us-east-1", ...(config.endpoint ? { endpoint: config.endpoint } : {}), ...(config.forcePathStyle ? { forcePathStyle: true } : {}) }); }; }
function defaultGoogleDriveClient(config) { return async () => { const { google } = require("googleapis"); const auth = new google.auth.GoogleAuth({ ...(config.credentials ? { credentials: JSON.parse(config.credentials) } : {}), scopes: ["https://www.googleapis.com/auth/drive"] }); return google.drive({ version: "v3", auth }); }; }

module.exports = { createCloudStorage, stableAwsPrincipal };
