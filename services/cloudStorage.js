const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { pipeline } = require("stream/promises");
const { Transform, Readable } = require("stream");
const { normalizeProviderError } = require("../src/services/deploymentResilience");
const { checkWindowsPrivateCloudDirectory } = require("../src/services/zk1WindowsPrivateCloudAcl");

async function abortableProviderRead(action, signal) {
  if (signal?.aborted) throw cloudError("provider_error", "Bounded cloud readback deadline exceeded");
  // SDK transport receives AbortSignal from the caller. Await its ACTUAL
  // settlement so a slow/misbehaving SDK cannot outlive witness admission,
  // provider staging cleanup, or a supposedly finished remote I/O effect.
  const result = await action();
  if (signal?.aborted) throw cloudError("provider_error", "Bounded cloud readback deadline exceeded");
  return result;
}

// A matching digest of the received bytes does not prove a complete remote
// object GET: a 206 response can contain exactly those bytes while the object
// has additional content outside the returned range. Reject partial/encoded
// representations before a bounded ZK readback can be reconciled as a copy.
function assertFullCiphertextGet(response, provider, expectedBytes, boundedLengthOnly = false) {
  const status = provider === "s3" ? response?.$metadata?.httpStatusCode : response?.status;
  const headers = provider === "s3" ? null : response?.headers;
  const header = (key) => {
    if (provider === "s3") return response?.[{
      "content-range": "ContentRange", "content-encoding": "ContentEncoding",
      "content-length": "ContentLength",
    }[key]];
    if (typeof headers?.get === "function") return headers.get(key);
    if (!headers || typeof headers !== "object") return undefined;
    const actual = Object.keys(headers).find((name) => name.toLowerCase() === key);
    return actual === undefined ? undefined : headers[actual];
  };
  const range = header("content-range");
  const encoding = header("content-encoding");
  const length = header("content-length");
  if ((status !== undefined && status !== 200)
    || (range !== undefined && range !== null)
    || (encoding !== undefined && encoding !== null && encoding !== "identity")
    || (length !== undefined && length !== null
      && (!/^(0|[1-9][0-9]*)$/.test(String(length))
        || (boundedLengthOnly
          ? Number(length) < 1 || Number(length) > expectedBytes
          : Number(length) !== expectedBytes)))) {
    throw cloudError("provider_error", "Bounded ZK ciphertext GET was not a complete object representation");
  }
}

// S3 version IDs are opaque. Restrict pinned identifiers to a bounded ASCII
// subset; an unversioned "null" object cannot prove historical identity.
function validZk1S3VersionId(value) {
  return typeof value === "string" && value !== "null"
    && /^[A-Za-z0-9_.+\-=/]{1,1024}$/.test(value);
}

// A bounded ZK GET is a security assertion about the *selected* destination,
// not permission to follow a local junction/symlink into an unrelated tree.
// The caller creates a private cache directory first; unlike legacy downloads,
// missing parents are refused rather than implicitly created through links.
function assertTrustedBoundedPosixParent(stat, finalParent) {
  if (process.platform === "win32") return;
  const owner = BigInt(process.getuid());
  const rootOwned = stat.uid === 0n;
  const foreignWritable = (stat.mode & 0o022n) !== 0n;
  // A foreign UID can chmod/rename its directory even if it is 0755 today.
  // Root-owned sticky ancestors (e.g. /tmp) cannot rename our owned child;
  // the actual destination parent must be owned by this process and not
  // writable by any other UID. Owner-owned 0755 parents remain supported.
  if ((stat.uid !== owner && !rootOwned)
    || (finalParent && (stat.uid !== owner || foreignWritable))
    || (!finalParent && foreignWritable
      && !(rootOwned && (stat.mode & 0o1000n) !== 0n))) {
    throw cloudError("provider_error", "Bounded ciphertext destination has an unsafe owner or mode");
  }
}
function pinBoundedDownloadParent(localPath) {
  if (typeof localPath !== "string" || !path.isAbsolute(localPath)) {
    throw cloudError("provider_error", "Bounded ciphertext destination must be absolute");
  }
  const parent = path.dirname(path.resolve(localPath));
  const root = path.parse(parent).root;
  const segments = path.relative(root, parent).split(path.sep).filter(Boolean);
  const pinned = [];
  let current = root;
  for (const segment of ["", ...segments]) {
    if (segment) current = path.join(current, segment);
    const stat = fs.lstatSync(current, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw cloudError("provider_error", "Bounded ciphertext destination has a redirected parent");
    }
    assertTrustedBoundedPosixParent(stat, current === parent);
    pinned.push({ current, dev: stat.dev, ino: stat.ino });
  }
  const guard = () => {
    for (const item of pinned) {
      const stat = fs.lstatSync(item.current, { bigint: true });
      if (!stat.isDirectory() || stat.isSymbolicLink()
        || stat.dev !== item.dev || stat.ino !== item.ino) {
        throw cloudError("provider_error", "Bounded ciphertext destination parent changed");
      }
      assertTrustedBoundedPosixParent(stat, item.current === parent);
    }
  };
  guard();
  return guard;
}

function pinUploadSourceParent(localPath) {
  try {
    // Check every ancestor BEFORE the first stat can follow a junction. The
    // returned guard also detects subsequent renames across provider awaits.
    return pinBoundedDownloadParent(path.resolve(localPath));
  } catch (error) {
    // Preserve the ordinary absent-source result. There is no path to read
    // or publish when an ancestor does not exist.
    if (error?.code === "ENOENT") return null;
    throw cloudError("invalid_path", "Cloud upload source has an unsafe parent");
  }
}

function sameUploadSource(left, right) {
  return left.isFile() && right.isFile() && !left.isSymbolicLink()
    && !right.isSymbolicLink() && left.nlink === 1n && right.nlink === 1n
    && left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

// Legacy uploads may be larger than the bounded ZK staging contract. Keep
// streaming them, but never allow a provider SDK to reopen a mutable pathname
// after an asynchronous credential/metadata lookup. The bytes must come from
// the exact regular inode authorized before the first await.
function openVerifiedLegacyUpload(localPath, expectedIdentity = null) {
  let fd;
  try {
    const named = fs.lstatSync(localPath, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n) {
      throw new Error("unsafe upload source");
    }
    fd = fs.openSync(localPath, fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0));
    const opened = fs.fstatSync(fd, { bigint: true });
    const same = (a, b) => a.isFile() && !a.isSymbolicLink() && a.nlink === 1n
      && a.dev === b.dev && a.ino === b.ino && a.size === b.size
      && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
    if (!same(opened, named) || (expectedIdentity && !same(opened, expectedIdentity))
      || !same(fs.lstatSync(localPath, { bigint: true }), opened)) {
      throw new Error("upload source replaced");
    }
    // A null path + explicit FD is essential: fs.createReadStream(localPath)
    // would perform another path resolution at its first asynchronous read.
    const stream = fs.createReadStream(null, { fd, autoClose: true, start: 0 });
    const verifyName = () => {
      try {
        if (!same(fs.fstatSync(fd, { bigint: true }), opened)
          || !same(fs.lstatSync(localPath, { bigint: true }), opened)) {
          throw new Error("upload source replaced");
        }
      } catch (_) { throw cloudError("invalid_path", "Cloud upload source was replaced"); }
    };
    return { stream, identity: opened, verifyName };
  } catch (_) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (_) { /* already closed */ }
    }
    throw cloudError("invalid_path", "Cloud upload source was replaced or is unsafe");
  }
}

function createCloudStorage(options = {}) {
  const provider = String(options.provider || "local").toLowerCase();
  const prefix = normalizePrefix(options.prefix || "rootark");
  const rootFolderId = String(options.rootFolderId || "root");
  // Stable physical namespace without including the authenticated principal:
  // a writer and separately credentialed reader may share the same bucket or
  // Drive root, while two different remote stores cannot be paired by key.
  const zk1StorageNamespace = crypto.createHash("sha256").update(JSON.stringify(
    provider === "s3" ? ["rootark-zk1/s3-namespace/v1", prefix, rootFolderId,
      options.s3?.bucket || "", options.s3?.region || "", options.s3?.endpoint || "",
      Boolean(options.s3?.forcePathStyle)]
      : ["rootark-zk1/gdrive-namespace/v1", prefix, rootFolderId,
        options.gdrive?.folderId || ""])).digest("hex");
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
    // Refresh the authenticated identity at every operation boundary. Keep the
    // last context unavailable if the identity probe itself fails.
    resolvedInventoryContext = null;
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
  function escapeQuery(value) { return String(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'"); }
  async function findDriveFile(cloudKey, folderId, area, signal = undefined) {
    const result = await (await drive()).files.list({
      q: `appProperties has { key='rootArkKey' and value='${escapeQuery(cloudKey)}' } and trashed=false`,
      fields: "files(id,name,parents,appProperties)",
      spaces: "drive",
      pageSize: 100,
    }, signal ? { signal } : undefined);
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
  async function getDriveFile(fileId, signal = undefined) {
    const current = (await (await drive()).files.get({ fileId, fields: "id,parents,appProperties" },
      signal ? { signal } : undefined)).data;
    // A provider adapter must not answer a pinned ID lookup with metadata
    // belonging to a different physical file that shares the same app key.
    // This is required before either an immutable-ID update or a ZK GET.
    if (!isDriveFileId(fileId) || current?.id !== fileId) {
      throw cloudError("provider_error", "Drive returned metadata for a different file ID");
    }
    return current;
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
  async function uploadToPinnedDriveId(localPath, fileId, requestBody, cloudKey, folderId, area,
    signal = undefined, boundedBytes = null, legacyBody = null) {
    const client = await drive();
    // The bounded writer owns a detached byte buffer. Never leave a lazy
    // file-descriptor stream that may open AFTER its private staging path is
    // removed by the caller (for example after a lying provider's early ACK).
    const media = () => ({ body: boundedBytes === null
      ? legacyBody() : Readable.from([boundedBytes]) });
    let existing;
    try { existing = await abortableProviderRead(() => getDriveFile(fileId, signal), signal); }
    catch (error) { if (!isDriveStatus(error, 404)) throw error; }
    if (existing) {
      assertDriveFileOwnership(existing, cloudKey, folderId, area);
      const result = await abortableProviderRead(() => client.files.update({ fileId, requestBody,
        media: media(), fields: "id" },
      signal ? { signal } : undefined), signal);
      if (result?.data?.id !== fileId) {
        throw cloudError("provider_error", "Drive update receipt returned a different physical file ID");
      }
      return { provider, key: cloudKey, id: fileId };
    }
    try {
      const result = await abortableProviderRead(() => client.files.create({
        requestBody: { ...requestBody, id: fileId, parents: [folder()] },
        media: media(), fields: "id" },
      signal ? { signal } : undefined), signal);
      if (result?.data?.id !== fileId) {
        throw cloudError("provider_error", "Drive create receipt returned a different physical file ID");
      }
      return { provider, key: cloudKey, id: fileId };
    } catch (error) {
      if (!isDriveStatus(error, 409)) throw error;
      const raced = await abortableProviderRead(() => getDriveFile(fileId, signal), signal);
      assertDriveFileOwnership(raced, cloudKey, folderId, area);
      const result = await abortableProviderRead(() => client.files.update({ fileId, requestBody,
        media: media(), fields: "id" },
      signal ? { signal } : undefined), signal);
      if (result?.data?.id !== fileId) {
        throw cloudError("provider_error", "Drive retry receipt returned a different physical file ID");
      }
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
  async function inventory(readOnlyBounds = undefined) {
    assertProvider();
    if (!enabled()) return [];
    // The opt-in owner-scoped migration probe MUST bound remote pages before
    // accumulating provider metadata; normal historical callers are unchanged.
    const bounded = readOnlyBounds !== undefined;
    if (bounded && (!readOnlyBounds || typeof readOnlyBounds !== "object"
      || Array.isArray(readOnlyBounds)
      || Reflect.ownKeys(readOnlyBounds).length !== 3
      || !["maxEntries", "maxPages", "abortSignal"]
        .every((name) => Object.hasOwn(readOnlyBounds, name))
      || !Number.isSafeInteger(readOnlyBounds.maxEntries)
      || readOnlyBounds.maxEntries < 1 || readOnlyBounds.maxEntries > 5000
      || !Number.isSafeInteger(readOnlyBounds.maxPages)
      || readOnlyBounds.maxPages < 1 || readOnlyBounds.maxPages > 8
      || !(readOnlyBounds.abortSignal instanceof AbortSignal))) {
      throw cloudError("configuration", "Invalid read-only inventory bounds");
    }
    const fence = () => {
      if (bounded && readOnlyBounds.abortSignal.aborted) {
        throw cloudError("provider_error", "Read-only inventory deadline expired");
      }
    };
    const objects = [];
    const identities = new Set();
    const add = (entry) => {
      fence();
      if (bounded && objects.length >= readOnlyBounds.maxEntries) {
        throw cloudError("provider_error", "Read-only inventory entry limit exceeded");
      }
      const identity = `${entry.provider}:${entry.providerIdentity || entry.key}`;
      if (identities.has(identity)) throw cloudError("duplicate_inventory_identity", "Cloud inventory contains a duplicate identity");
      identities.add(identity);
      objects.push(entry);
    };
    if (provider === "s3") {
      const bucketName = bucket();
      let token;
      const visited = new Set();
      let pages = 0;
      do {
        fence();
        if (bounded && ++pages > readOnlyBounds.maxPages) throw cloudError("provider_error", "Read-only inventory page limit exceeded");
        const page = await (await s3()).send(new (require("@aws-sdk/client-s3").ListObjectsV2Command)({ Bucket: bucketName,
          Prefix: `${prefix}/`, ContinuationToken: token,
          ...(bounded ? { MaxKeys: 1000 } : {}) }),
        bounded ? { abortSignal: readOnlyBounds.abortSignal } : undefined);
        fence();
        if (bounded && (!page || (page.Contents !== undefined && !Array.isArray(page.Contents))
          || (page.Contents || []).length > 1000
          || typeof page.IsTruncated !== "boolean"
          || (page.IsTruncated !== Boolean(page.NextContinuationToken)))) {
          throw cloudError("provider_error", "Incomplete S3 inventory page");
        }
        for (const object of page.Contents || []) {
          const parsed = parseInventoryKey(object.Key);
          add({ provider, providerIdentity: parsed.key, ...parsed });
        }
        token = page.NextContinuationToken;
        if (bounded && token && (typeof token !== "string" || token.length > 4096
          || visited.has(token))) throw cloudError("provider_error", "Repeated S3 inventory token");
        if (bounded && token) visited.add(token);
      } while (token);
      return objects;
    }
    let token;
    const visited = new Set();
    let pages = 0;
    do {
      fence();
      if (bounded && ++pages > readOnlyBounds.maxPages) throw cloudError("provider_error", "Read-only inventory page limit exceeded");
      const page = await (await drive()).files.list({
        q: `'${escapeQuery(folder())}' in parents and appProperties has { key='rootArkKey' } and trashed=false`,
        fields: "nextPageToken,files(id,name,parents,appProperties)",
        spaces: "drive",
        pageToken: token,
        pageSize: 100,
      }, bounded ? { signal: readOnlyBounds.abortSignal } : undefined);
      fence();
      if (bounded && (!Array.isArray(page?.data?.files) || page.data.files.length > 100)) {
        throw cloudError("provider_error", "Incomplete Google Drive inventory page");
      }
      for (const file of page.data.files || []) {
        if (!Array.isArray(file.parents)) {
          throw cloudError("invalid_inventory_identity", "Drive object is missing its parent metadata");
        }
        if (!file.parents.includes(folder())) {
          if (bounded) throw cloudError("provider_error", "Foreign Drive parent in bounded inventory");
          continue;
        }
        const properties = file.appProperties || {};
        if (typeof properties.rootArkKey !== "string" || !properties.rootArkKey) {
          throw cloudError("invalid_inventory_key", "Drive object is missing its inventory key");
        }
        const normalizedKey = properties.rootArkKey.replace(/\\/g, "/");
        if ((bounded && normalizedKey !== properties.rootArkKey)
          || !normalizedKey.startsWith(`${prefix}/`)) {
          if (bounded) throw cloudError("provider_error", "Foreign Drive namespace in bounded inventory");
          continue;
        }
        const parsed = parseInventoryKey(normalizedKey);
        if (String(properties.rootArkFolderId || "") !== parsed.folderId || String(properties.rootArkArea || "") !== parsed.area) {
          throw cloudError("invalid_inventory_metadata", "Drive metadata does not match rootArkKey");
        }
        if (!file.id) throw cloudError("invalid_inventory_identity", "Drive object is missing its identity");
        add({ provider, providerIdentity: String(file.id), id: String(file.id), ...parsed });
      }
      token = page.data.nextPageToken;
      if (bounded && token && (typeof token !== "string" || token.length > 4096
        || visited.has(token))) throw cloudError("provider_error", "Repeated Drive inventory token");
      if (bounded && token) visited.add(token);
    } while (token);
    return objects;
  }
  async function upload(localPath, folderId, fileName, area = "uploads", uploadOptions = {}) {
    assertProvider(); if (!enabled()) return null;
    const bound = uploadOptions?.zk1BoundedBytes;
    // The legacy path is intentionally still supported, but must never
    // silently accept a partial ZK/verified-integrity opt-in. The hash comes
    // from the caller's independent ciphertext commitment, not this live FD.
    const zk1Selected = bound !== undefined
      || uploadOptions?.zk1ExpectedSha256 !== undefined
      || (uploadOptions && typeof uploadOptions === "object"
        && Reflect.ownKeys(uploadOptions).some((name) =>
          typeof name === "string" && name.startsWith("zk1")));
    if (zk1Selected && (!uploadOptions
      || typeof uploadOptions !== "object" || Array.isArray(uploadOptions)
      || !Object.hasOwn(uploadOptions, "zk1BoundedBytes")
      || !Object.hasOwn(uploadOptions, "zk1ExpectedSha256")
      || !Number.isSafeInteger(bound) || bound < 1 || bound > 16 * 1024 * 1024
      || Reflect.ownKeys(uploadOptions).some((key) => ![
        "providerFileId", "zk1BoundedBytes", "zk1ExpectedSha256",
      ].includes(key))
      || typeof uploadOptions.zk1ExpectedSha256 !== "string"
      || !/^[a-f0-9]{64}$/.test(uploadOptions.zk1ExpectedSha256))) {
      throw cloudError("configuration", "Invalid bounded ZK ciphertext upload");
    }
    // Preserve the historical POSIX legacy stream behavior; bounded ZK copies
    // and Windows uploads require ancestor validation before the first stat.
    const guardSourceParent = process.platform === "win32" || bound !== undefined
      ? pinUploadSourceParent(localPath) : () => {};
    if (!guardSourceParent) return null;
    if (bound !== undefined && process.platform === "win32") {
      // A caller-created staging directory is not trusted just because its
      // filename is random. Verify native owner, DACL and all ancestors before
      // reading anything that may become a remote ciphertext PUT.
      try {
        await checkWindowsPrivateCloudDirectory(path.dirname(path.resolve(localPath)), "verify");
      } catch (_) {
        throw cloudError("invalid_path", "Cloud upload source staging ACL is unsafe");
      }
    }
    guardSourceParent();
    // The initial path check is an authorization boundary, not just an
    // existence probe. An attacker can rename a parent directory after this
    // stat and before the upload's later FD open. Retain the original inode
    // instead of silently authorizing whichever file now occupies the name.
    const initialSource = fs.statSync(localPath, { throwIfNoEntry: false, bigint: true });
    if (!initialSource?.isFile()) return null;
    const cloudKey = objectKey(folderId, fileName, area);
    let boundedBytes = null;
    if (bound !== undefined) {
      const stat = fs.lstatSync(localPath, { bigint: true });
      if (stat.size !== BigInt(bound) || !sameUploadSource(stat, initialSource)) {
        throw cloudError("configuration", "Ciphertext staging file is not an exact private upload");
      }
      guardSourceParent();
      const fd = fs.openSync(localPath,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      try {
        const opened = fs.fstatSync(fd, { bigint: true });
        if (opened.size !== BigInt(bound) || !sameUploadSource(opened, stat)
          || !sameUploadSource(opened, initialSource)) {
          throw cloudError("configuration", "Bounded ciphertext staging file changed identity");
        }
        // The source may grow after fstat while another process still holds
        // the inode. readFileSync(fd) can then allocate/read beyond the
        // trusted ZK byte budget before the later identity check rejects it.
        boundedBytes = Buffer.alloc(bound);
        let offset = 0;
        while (offset < bound) {
          const count = fs.readSync(fd, boundedBytes, offset,
            Math.min(64 * 1024, bound - offset), offset);
          if (count <= 0 || count > bound - offset) {
            throw cloudError("configuration", "Bounded ciphertext staging file truncated during capture");
          }
          offset += count;
        }
        const ended = fs.fstatSync(fd, { bigint: true });
        if (boundedBytes.length !== bound || !sameUploadSource(ended, opened)
          || !sameUploadSource(fs.lstatSync(localPath, { bigint: true }), opened)) {
          throw cloudError("configuration", "Bounded ciphertext staging file changed during capture");
        }
        guardSourceParent();
        // The publisher already authenticated the exact ciphertext against
        // its signed root. Compare that trusted digest with the detached bytes
        // before either SDK can receive the body.
        if (crypto.createHash("sha256").update(boundedBytes).digest("hex")
            !== uploadOptions.zk1ExpectedSha256) {
          throw cloudError("configuration", "Bounded ciphertext digest mismatch");
        }
      } finally { fs.closeSync(fd); }
    }
    const legacyStreams = [];
    let initialLegacy = null;
    let firstLegacyBody = false;
    if (boundedBytes === null) {
      initialLegacy = openVerifiedLegacyUpload(localPath, initialSource);
      legacyStreams.push(initialLegacy.stream);
    }
    const legacyBody = () => {
      if (!initialLegacy) throw cloudError("invalid_path", "Missing verified upload source");
      guardSourceParent();
      if (!firstLegacyBody) {
        initialLegacy.verifyName();
        firstLegacyBody = true;
        return initialLegacy.stream;
      }
      // A pinned Drive create may receive 409 and retry as an update. Reopen
      // only when the same authorized inode still occupies the original name.
      const retry = openVerifiedLegacyUpload(localPath, initialLegacy.identity);
      legacyStreams.push(retry.stream);
      return retry.stream;
    };
    const controller = bound !== undefined ? new AbortController() : null;
    const timeout = controller ? setTimeout(() => controller.abort(), 15000) : null;
    const signal = controller?.signal;
    try {
    if (provider === "s3") {
      const bucketName = bucket();
      const s3Put = await abortableProviderRead(async () => {
        const client = await s3();
        // Path-less streams cannot use the SDK's path/stat length inference.
        // Sign the byte count of the pinned file instead of rereading a name.
        if (initialLegacy && initialLegacy.identity.size > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw cloudError("invalid_path", "Cloud upload source size is unsupported");
        }
        guardSourceParent();
        return client.send(new (require("@aws-sdk/client-s3").PutObjectCommand)({ Bucket: bucketName,
          Key: cloudKey, Body: boundedBytes === null ? legacyBody() : boundedBytes,
          ContentLength: bound || Number(initialLegacy.identity.size) }),
        signal ? { abortSignal: signal } : undefined);
      }, signal);
      if (signal?.aborted) throw cloudError("provider_error", "Bounded ciphertext upload deadline exceeded");
      // A returned version ID is a provider assertion only. It can be pinned
      // for subsequent exact GETs, but never proves independent durability.
      if (s3Put?.VersionId !== undefined && s3Put.VersionId !== "null"
        && !validZk1S3VersionId(s3Put.VersionId)) {
        throw cloudError("provider_error", "Invalid S3 ciphertext version identity");
      }
      // S3 versioning-suspended buckets can acknowledge VersionId="null":
      // preserve the unversioned copy, but never expose a pinnable version.
      const versionId = s3Put?.VersionId === "null" ? undefined : s3Put?.VersionId;
      return { provider, key: cloudKey,
        ...(versionId === undefined ? {} : { versionId }) };
    }
    const providerFileId = String(uploadOptions?.providerFileId || "").trim();
    if (providerFileId) {
      if (!isDriveFileId(providerFileId)) throw cloudError("invalid_path", "Google Drive file ID is invalid");
      guardSourceParent();
      const result = await abortableProviderRead(() => uploadToPinnedDriveId(localPath,
        providerFileId, driveRequestBody(folderId, fileName, area, cloudKey),
        cloudKey, folderId, area, signal, boundedBytes, legacyBody), signal);
      if (signal?.aborted) throw cloudError("provider_error", "Bounded ciphertext upload deadline exceeded");
      return result;
    }
    if (bound !== undefined) throw cloudError("configuration", "Bounded Drive copy requires an immutable pinned file ID");
    const existing = await findDriveFile(cloudKey, folderId, area);
    const requestBody = driveRequestBody(folderId, fileName, area, cloudKey);
    const media = { body: legacyBody() };
    if (existing) {
      const current = await getDriveFile(existing.id);
      assertDriveFileOwnership(current, cloudKey, folderId, area);
      await (await drive()).files.update({ fileId: existing.id, requestBody, media, fields: "id" });
      return { provider, key: cloudKey, id: existing.id };
    }
    const result = await (await drive()).files.create({ requestBody: { ...requestBody, parents: [folder()] }, media, fields: "id" }); return { provider, key: cloudKey, id: result.data.id };
    } catch (error) {
      if (controller) controller.abort();
      throw error;
    } finally {
      if (timeout) clearTimeout(timeout);
      for (const stream of legacyStreams) stream.destroy();
    }
  }
  async function download(folderId, fileName, localPath, area = "uploads", canPublish = () => true,
    constraints = undefined) {
    assertProvider(); if (!enabled() || fs.existsSync(localPath)) return false;
    const pinId = constraints && Object.hasOwn(constraints, "providerFileId")
      ? constraints.providerFileId : null;
    const externalSignal = constraints && Object.hasOwn(constraints, "abortSignal")
      ? constraints.abortSignal : undefined;
    const pinnedVersion = constraints && Object.hasOwn(constraints, "providerVersionId")
      ? constraints.providerVersionId : null;
    // Signed catalog sidecars have a cryptographically authenticated payload
    // length *below* their maximum. All regular ciphertext copies still demand
    // an exact Content-Length and byte count, never this upper-bound-only mode.
    const boundedLengthOnly = constraints?.boundedLengthOnly === true;
    if (constraints !== undefined && (!constraints || typeof constraints !== "object"
      || Array.isArray(constraints)
      || Reflect.ownKeys(constraints).length !== (pinId === null ? 1 : 2)
        + (externalSignal === undefined ? 0 : 1) + (pinnedVersion === null ? 0 : 1)
        + (boundedLengthOnly ? 1 : 0)
      || !Object.hasOwn(constraints, "maxBytes")
      || !Number.isSafeInteger(constraints.maxBytes)
      || constraints.maxBytes < 1 || constraints.maxBytes > 16 * 1024 * 1024
      || (externalSignal !== undefined && !(externalSignal instanceof AbortSignal))
      || (provider === "gdrive" && !isDriveFileId(pinId))
      || (provider === "s3" && pinId !== null)
      || (pinnedVersion !== null && (provider !== "s3"
        || !validZk1S3VersionId(pinnedVersion))))) {
      throw cloudError("invalid_path", "Invalid bounded ciphertext download");
    }
    const cloudKey = objectKey(folderId, fileName, area);
    const parentPath = path.dirname(localPath);
    const guardParent = constraints ? pinBoundedDownloadParent(localPath) : null;
    if (constraints && process.platform === "win32") {
      // The destination's inode alone is not enough. A shared temp ancestor
      // may rename the disposable staging directory while an SDK GET awaits,
      // making a later createWriteStream(path) overwrite a foreign file.
      try { await checkWindowsPrivateCloudDirectory(parentPath, "verify"); }
      catch (_) {
        throw cloudError("provider_error", "Bounded ciphertext destination is not private");
      }
      guardParent();
    }
    if (!constraints) fs.mkdirSync(parentPath, { recursive: true });
    const stagingDirectory = fs.mkdtempSync(path.join(parentPath, ".rootark-cloud-cache-"));
    const stagedPath = path.join(stagingDirectory, path.basename(localPath));
    // All bounded GETs must pin their stage and file descriptor before the
    // provider await. POSIX permits renaming an open staging directory, so a
    // later pathname-based stream would still overwrite a foreign symlink.
    const secureBoundedStage = Boolean(constraints);
    const pinnedStage = secureBoundedStage ? fs.lstatSync(stagingDirectory, { bigint: true }) : null;
    const guardStage = secureBoundedStage ? () => {
      guardParent();
      const named = fs.lstatSync(stagingDirectory, { bigint: true });
      if (!pinnedStage.isDirectory() || pinnedStage.isSymbolicLink()
        || !named.isDirectory() || named.isSymbolicLink()
        || named.dev !== pinnedStage.dev || named.ino !== pinnedStage.ino) {
        throw cloudError("provider_error", "Bounded ciphertext staging directory changed");
      }
    } : null;
    let stagedFd = null;
    let pinnedFile = null;
    const boundedController = constraints ? new AbortController() : null;
    const boundedDeadline = boundedController ? setTimeout(() => boundedController.abort(), 15000) : null;
    const signal = boundedController?.signal;
    const cancel = () => boundedController?.abort();
    if (externalSignal) {
      if (externalSignal.aborted) cancel();
      else externalSignal.addEventListener("abort", cancel, { once: true });
    }
    try {
      if (signal?.aborted) throw cloudError("provider_error", "Cancelled bounded cloud readback");
      if (secureBoundedStage) {
        // Pin the actual output file BEFORE awaiting a remote provider. All
        // streamed bytes go to this FD, never to a pathname resolved after a
        // junction/symlink swap. O_EXCL refuses a preexisting foreign leaf.
        guardStage();
        stagedFd = fs.openSync(stagedPath, fs.constants.O_WRONLY | fs.constants.O_CREAT
          | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
        pinnedFile = fs.fstatSync(stagedFd, { bigint: true });
        guardStage();
        if (!pinnedFile.isFile() || pinnedFile.nlink !== 1n || pinnedFile.size !== 0n) {
          throw cloudError("provider_error", "Bounded ciphertext staging file is unsafe");
        }
      }
      let input;
      if (provider === "s3") {
        const bucketName = bucket();
        const response = await abortableProviderRead(async () => (await s3()).send(
          new (require("@aws-sdk/client-s3").GetObjectCommand)({ Bucket: bucketName,
            Key: cloudKey, ...(pinnedVersion === null ? {} : { VersionId: pinnedVersion }) }),
          signal ? { abortSignal: signal } : undefined), signal);
        if (constraints) assertFullCiphertextGet(response, provider,
          constraints.maxBytes, boundedLengthOnly);
        if (pinnedVersion !== null && response?.VersionId !== pinnedVersion) {
          throw cloudError("provider_error", "S3 returned a different ciphertext version");
        }
        input = response.Body;
      }
      else {
        const existing = pinId === null
          ? await abortableProviderRead(() => findDriveFile(cloudKey, folderId, area, signal), signal)
          : { id: pinId };
        if (!existing) return false;
        const current = await abortableProviderRead(() => getDriveFile(existing.id, signal), signal);
        assertDriveFileOwnership(current, cloudKey, folderId, area);
        const response = await abortableProviderRead(async () => (await drive()).files.get(
          { fileId: existing.id, alt: "media" },
          { responseType: "stream", ...(signal ? { signal } : {}) }), signal);
        if (constraints) assertFullCiphertextGet(response, provider,
          constraints.maxBytes, boundedLengthOnly);
        input = response.data;
      }
      if (constraints) {
        let size = 0;
        const bounded = new Transform({ transform(chunk, _encoding, next) {
          size += chunk.length;
          if (size > constraints.maxBytes) next(cloudError("provider_error", "Ciphertext copy exceeds bounded readback size"));
          else next(null, chunk);
        } });
        if (secureBoundedStage) {
          guardStage();
          await pipeline(input, bounded, fs.createWriteStream(null,
            { fd: stagedFd, autoClose: false }), { signal });
          const written = fs.fstatSync(stagedFd, { bigint: true });
          guardStage();
          const named = fs.lstatSync(stagedPath, { bigint: true });
          if (!written.isFile() || written.nlink !== 1n
            || written.dev !== pinnedFile.dev || written.ino !== pinnedFile.ino
            || written.size !== BigInt(size)
            || !named.isFile() || named.isSymbolicLink() || named.nlink !== 1n
            || named.dev !== pinnedFile.dev || named.ino !== pinnedFile.ino
            || named.size !== BigInt(size)) {
            throw cloudError("provider_error", "Bounded ciphertext staging file changed");
          }
          fs.closeSync(stagedFd);
          stagedFd = null;
        }
        if (boundedLengthOnly && size === 0) {
          throw cloudError("provider_error", "Empty signed catalog object");
        }
      } else {
        await pipeline(input, fs.createWriteStream(stagedPath));
      }
      if (signal?.aborted) throw cloudError("provider_error", "Bounded cloud readback deadline exceeded");
      if (guardParent) guardParent();
      if (typeof canPublish === "function" && !canPublish()) return false;
      if (constraints) {
        // For a ZK verification readback the target MUST be exactly the bytes
        // just streamed from the provider. A different local writer must not
        // be able to win an exists/rename race and have its own bytes falsely
        // attributed to this GET. Hardlink publication is atomic NO_REPLACE
        // on the same filesystem (staging is under the destination parent).
        if (guardStage) guardStage();
        else guardParent();
        const stage = fs.lstatSync(stagedPath, { bigint: true });
        if (!stage.isFile() || stage.isSymbolicLink() || stage.nlink !== 1n
          || (pinnedFile && (stage.dev !== pinnedFile.dev || stage.ino !== pinnedFile.ino))) {
          throw cloudError("provider_error", "Bounded ciphertext staging is not a private file");
        }
        fs.linkSync(stagedPath, localPath);
        if (pinnedFile) {
          const published = fs.lstatSync(localPath, { bigint: true });
          if (!published.isFile() || published.dev !== pinnedFile.dev
            || published.ino !== pinnedFile.ino) {
            throw cloudError("provider_error", "Bounded ciphertext published unexpected inode");
          }
        }
      } else {
        if (fs.existsSync(localPath)) return true;
        fs.renameSync(stagedPath, localPath);
      }
      return true;
    } catch (error) {
      if (boundedController) boundedController.abort();
      throw classify(error);
    } finally {
      if (stagedFd !== null) {
        try { fs.closeSync(stagedFd); } catch (_) { /* descriptor already closed */ }
      }
      if (boundedDeadline) clearTimeout(boundedDeadline);
      if (externalSignal) externalSignal.removeEventListener("abort", cancel);
      // A parent replaced by a junction after the provider call must not turn
      // cache cleanup into a recursive delete of an unrelated directory.
      // Leave the original disposable stage inert if its parent moved.
      let cleanupSafe = true;
      if (guardParent) {
        try { guardParent(); } catch (_) { cleanupSafe = false; }
      }
      if (guardStage) {
        try { guardStage(); } catch (_) { cleanupSafe = false; }
      }
      if (cleanupSafe) fs.rmSync(stagingDirectory, { recursive: true, force: true });
    }
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
  return { provider, enabled, status, inventoryContext, resolveInventoryContext,
    zk1StorageNamespace: () => zk1StorageNamespace,
    key, inventory: (...args) => run(inventory, ...args), resolveUploadId: (...args) => run(resolveUploadId, ...args), upload: (...args) => run(upload, ...args), download: (...args) => run(download, ...args), remove: (...args) => run(remove, ...args), removePrefix: (...args) => run(removePrefix, ...args), list: (...args) => run(list, ...args) };
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
