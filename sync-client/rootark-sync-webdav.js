"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { validatePortableRelativePath } = require("./rootark-sync-paths");
const { SyncJournal } = require("./rootark-sync-journal");
const protocol = require("./rootark-sync-protocol");
const { verifyAuthorizationProof } = require("./rootark-sync-authorization");
const { verifyWindowsLocalWebDavTree, createWindowsLocalWebDavAclVerifier } =
  require("../services/chunkUploadWindowsAcl");

const MAX_BODY_BYTES = 8 * 1024 * 1024;
// The remote Sync v2 HTTP route limits the *JSON request* to 9 MiB and raw
// ciphertext to 8 MiB. Base64url expands binary by ~4/3, and MOVE adds a
// keyed 61-byte content envelope before encryption. A local 8 MiB protected
// mutation could otherwise ACK as durable but be impossible to remote-push.
// Keep a conservative positive budget for auth metadata and JSON framing.
// Legacy unauthenticated WebDAV retains its historical 8 MiB PUT body cap.
const MAX_PROTECTED_REMOTE_SOURCE_BYTES = 6 * 1024 * 1024;
function isLoopback(host) {
  const value = String(host || "").toLowerCase();
  return value === "localhost" || value === "127.0.0.1" || value === "::1" || (net.isIP(value) === 6 && value === "0:0:0:0:0:0:0:1");
}

function safeSegments(urlPath) {
  let decoded;
  try { decoded = decodeURIComponent(urlPath); } catch { throw Object.assign(new Error("Invalid path"), { statusCode: 400 }); }
  if (decoded.includes("\0") || decoded.includes("\\")) throw Object.assign(new Error("Unsafe path"), { statusCode: 400 });
  const segments = decoded.split("/").filter(Boolean);
  // PUT staging entries can survive a crash. They are recovery evidence, not
  // user documents: never expose or mutate them through the WebDAV surface.
  if (segments.some((segment) => {
    const name = process.platform === "win32" ? segment.toLowerCase() : segment;
    return name.startsWith(".rootark-put-") || name === ".rootark-webdav-owner.lock";
  })) {
    throw Object.assign(new Error("Reserved internal staging path"), { statusCode: 400 });
  }
  if (segments.length) {
    try { validatePortableRelativePath(segments.join("/"), "path"); } catch { throw Object.assign(new Error("Unsafe path"), { statusCode: 400 }); }
  }
  return segments;
}

function sameOrBelow(candidate, parent) {
  const left = path.resolve(candidate);
  const right = path.resolve(parent);
  const compare = process.platform === "win32" ? (value) => value.toLowerCase() : (value) => value;
  const a = compare(left);
  const b = compare(right);
  return a === b || a.startsWith(`${b}${path.sep}`);
}

function sameLocalEntry(actual, expected) {
  // Local fallback for failed operations; never restore over a pathname
  // which visibly changed identity. Parent directory ACLs/ownership remain a
  // separate prerequisite. This is not an atomic unlinkat2/renameat2 fence.
  return Boolean(actual && expected && !actual.isSymbolicLink()
    && !expected.isSymbolicLink()
    && actual.dev === expected.dev && actual.ino === expected.ino
    && actual.isFile() === expected.isFile()
    && actual.isDirectory() === expected.isDirectory());
}

function sameExclusiveSourceEntry(actual, expected) {
  // Original document file witnesses MUST still have exactly one link at the
  // moment they are first linked or removed. Otherwise a local actor can
  // create a foreign hardlink after the earlier admission lstat(), turning
  // the bridge's authorized path mutation into an untracked alias mutation.
  // Temporary publication/rollback deliberately permits nlink2 at their
  // intermediate verification points and must not use this helper.
  return sameLocalEntry(actual, expected)
    && (!expected.isFile() || (expected.nlink === 1n && actual.nlink === 1n));
}

function durableEntryIdentity(stat) {
  // JSON-safe filesystem identity, persisted in the private mutation journal.
  // Zero/unknown inode values are not recovery proof.
  if (!stat || typeof stat.dev !== "bigint" || typeof stat.ino !== "bigint"
    || stat.dev < 0n || stat.ino <= 0n || stat.isSymbolicLink()
    || (stat.isFile() && stat.nlink !== 1n)
    || (!stat.isFile() && !stat.isDirectory())) {
    throw uncertainRollback("WebDAV filesystem identity cannot be witnessed");
  }
  return { dev: String(stat.dev), ino: String(stat.ino),
    type: stat.isFile() ? "file" : "directory" };
}

function matchesDurableIdentity(stat, proof, expectedFileLinks = 1n) {
  return Boolean(stat && proof && typeof proof === "object"
    && typeof proof.dev === "string" && /^(0|[1-9][0-9]*)$/.test(proof.dev)
    && typeof proof.ino === "string" && /^[1-9][0-9]*$/.test(proof.ino)
    && !stat.isSymbolicLink() && stat.dev === BigInt(proof.dev)
    && stat.ino === BigInt(proof.ino)
    && ((proof.type === "file" && stat.isFile() && stat.nlink === expectedFileLinks)
      || (proof.type === "directory" && stat.isDirectory())));
}

async function syncBridgeNamespace(...paths) {
  // A synced file does not durably publish its new directory entry. A journal
  // phase/outbox ACK must not outrun POSIX namespace metadata after link,
  // unlink or rename. Windows directory-handle flushing is not provided by
  // Node's portable fs API; do not mistake a skipped platform operation for
  // an independently verified NTFS power-loss durability guarantee.
  if (process.platform === "win32") return;
  const parents = new Set(paths.filter(Boolean).map((name) => path.dirname(name)));
  for (const directory of parents) {
    const handle = await fsp.open(directory, "r");
    try { await handle.sync(); }
    finally { await handle.close(); }
  }
}

async function localEntryOrNull(filename) {
  try { return await fsp.lstat(filename, { bigint: true }); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
}

function uncertainRollback(reason) {
  return Object.assign(new Error(reason), { code: "WEBDAV_ROLLBACK_INDETERMINATE" });
}

function assertPosixTrustedBridgePath(rootDir, targetPath, allowMissingLeaf = true,
  createMissingDirectories = false) {
  // Deny directory replacement by a different local UID before a pathname
  // open or journal rename. The bridge owner and root remain trusted actors;
  // this is an ownership/mode gate, not descriptor-relative openat2.
  if (process.platform === "win32") return;
  const uid = process.getuid?.();
  if (!Number.isSafeInteger(uid)) throw new Error("POSIX bridge owner unavailable");
  const trusted = (owner) => owner === BigInt(uid) || owner === 0n;
  const root = path.resolve(rootDir);
  const target = path.resolve(targetPath);
  if (!sameOrBelow(target, root)) throw new Error("Untrusted bridge path");
  const filesystemRoot = path.parse(target).root;
  const segments = path.relative(filesystemRoot, target).split(path.sep).filter(Boolean);
  let current = filesystemRoot;
  for (let index = -1; index < segments.length; index += 1) {
    if (index >= 0) current = path.join(current, segments[index]);
    let stat;
    try { stat = fs.lstatSync(current, { bigint: true }); }
    catch (error) {
      if (error.code !== "ENOENT") throw error;
      if (createMissingDirectories) {
        // Only the immediate component is created after its parent passed the
        // owner/mode gate. Recursive mkdir can follow an untrusted ancestor.
        fs.mkdirSync(current, { mode: 0o700 });
        stat = fs.lstatSync(current, { bigint: true });
      } else {
        if (allowMissingLeaf && index === segments.length - 1) return;
        throw error;
      }
    }
    if (stat.isSymbolicLink() || !trusted(stat.uid)) throw new Error("Untrusted POSIX bridge owner or link");
    if (!stat.isDirectory()) {
      if (createMissingDirectories || index !== segments.length - 1 || !stat.isFile()) {
        throw new Error("Untrusted POSIX bridge path type");
      }
      // An owner-trusted file can still be modified by a different UID when
      // its group/other write bits are set. Verify the existing leaf as well
      // as its ancestors before HTTP I/O or journal recovery.
      if ((stat.mode & 0o022n) !== 0n) throw new Error("Untrusted POSIX bridge file mode");
      return;
    }
    if ((stat.mode & 0o022n) === 0n) continue;
    // /tmp-style sticky ancestors can host a private bridge directory. A
    // different UID cannot rename that trusted-owned child under sticky rules.
    // The exception never applies to the bridge root or its descendants.
    const aboveRoot = current !== root && sameOrBelow(root, current);
    const next = index + 1 < segments.length ? path.join(current, segments[index + 1]) : null;
    if (!aboveRoot || stat.uid !== 0n || (stat.mode & 0o1000n) === 0n || !next) {
      throw new Error("Untrusted writable POSIX bridge ancestor");
    }
    let child;
    try { child = fs.lstatSync(next, { bigint: true }); }
    catch (error) {
      if (!createMissingDirectories || error.code !== "ENOENT") throw error;
      // Sticky root-owned /tmp protects only an owner-owned entry. Create the
      // immediate missing entry with O_EXCL-equivalent mkdir before proceeding.
      fs.mkdirSync(next, { mode: 0o700 });
      child = fs.lstatSync(next, { bigint: true });
    }
    if (child.isSymbolicLink() || !trusted(child.uid)) {
      throw new Error("Untrusted POSIX sticky ancestor child");
    }
  }
}

function createPosixTrustedBridgeDirectory(rootDir, directory) {
  assertPosixTrustedBridgePath(rootDir, directory, false, true);
}

async function rejectSymlinks(rootDir, targetPath, allowMissing = true) {
  const root = path.resolve(rootDir);
  const resolved = path.resolve(targetPath);
  if (!(resolved === root || resolved.startsWith(`${root}${path.sep}`))) throw Object.assign(new Error("Path outside bridge root"), { statusCode: 400 });
  const rootStats = await fsp.lstat(root);
  if (rootStats.isSymbolicLink()) throw Object.assign(new Error("Symlink bridge root is not supported"), { statusCode: 400 });
  const relative = path.relative(root, resolved);
  let current = root;
  for (const segment of relative ? relative.split(path.sep) : []) {
    current = path.join(current, segment);
    let stats;
    try { stats = await fsp.lstat(current); } catch (error) {
      if (allowMissing && error.code === "ENOENT") break;
      throw error;
    }
    if (stats.isSymbolicLink()) throw Object.assign(new Error("Symlink paths are not supported"), { statusCode: 400 });
  }
  return resolved;
}

async function canonicalPath(rootDir, targetPath, allowMissing = true) {
  const checked = await rejectSymlinks(rootDir, targetPath, allowMissing);
  if (process.platform !== "win32") return checked;

  const root = path.resolve(rootDir);
  await rejectSymlinks(root, root, false);
  let current = root;
  const segments = path.relative(root, checked).split(path.sep).filter(Boolean);
  for (let index = 0; index < segments.length; index += 1) {
    const requestedName = segments[index];
    const names = await fsp.readdir(current);
    const matches = names.filter((entry) => entry.toLowerCase() === requestedName.toLowerCase());
    const name = names.includes(requestedName) ? requestedName : matches.length === 1 ? matches[0] : null;
    if (!name) {
      if (matches.length > 1) throw Object.assign(new Error("Ambiguous case-insensitive path"), { statusCode: 400 });
      current = path.join(current, ...segments.slice(index));
      break;
    }
    current = path.join(current, name);
    const stats = await fsp.lstat(current);
    if (stats.isSymbolicLink()) throw Object.assign(new Error("Symlink paths are not supported"), { statusCode: 400 });
  }
  return rejectSymlinks(root, current, allowMissing);
}

async function canonicalExistingPath(rootDir, targetPath) {
  return canonicalPath(rootDir, targetPath, false);
}

function encodedWebDavPath(rootDir, targetPath) {
  const relative = path.relative(path.resolve(rootDir), path.resolve(targetPath)).split(path.sep).join("/");
  validatePortableRelativePath(relative, "path");
  return `/${relative.split("/").map((segment) => encodeURIComponent(segment)).join("/")}`;
}

function boundWebDavRelativePath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.includes("?")) {
    throw Object.assign(new Error("Protected WebDAV event has no canonical path"),
      { code: "authorization_rejected" });
  }
  const segments = safeSegments(value);
  if (!segments.length) throw Object.assign(new Error("Protected WebDAV root mutation refused"),
    { code: "authorization_rejected" });
  return segments.join("/");
}

function assertSignedWebDavEventBinding(event, signed) {
  // A valid Ed25519 envelope from the right device is still insufficient:
  // it may authorize a completely different object, path or operation.
  if (!event || event.journalType !== "webdav-mutation"
    || typeof event.operationId !== "string"
    || !/^[A-Za-z0-9._:-]{1,100}$/.test(event.operationId)
    || !["put", "move", "delete"].includes(event.kind)) {
    throw Object.assign(new Error("Unbound protected WebDAV event"),
      { code: "authorization_rejected" });
  }
  const source = boundWebDavRelativePath(event.source || event.path);
  const destination = event.kind === "delete" ? source
    : boundWebDavRelativePath(event.destination || event.path);
  const metadataPath = signed.metadata?.path;
  const allowed = event.kind === "put"
    ? typeof event.existed === "boolean"
      && signed.operation === (event.existed ? "update" : "create")
      && metadataPath === destination
    : event.kind === "delete"
      ? signed.operation === "delete" && metadataPath === source
      : ["move", "delete"].includes(signed.operation)
        && metadataPath === destination;
  const solo = (event.kind === "delete" && signed.operation === "delete")
    || (event.kind === "move" && signed.operation === "move"
      && !event.previousDestinationIdentity);
  const expectedId = `${solo ? "webdavsolo" : "webdav"}-${event.operationId}-${crypto.createHash("sha256")
    .update(`${signed.operation}:${metadataPath}`).digest("hex").slice(0, 24)}`;
  if (!allowed || signed.operationId !== expectedId
    || (signed.operation === "move" && signed.metadata.sourcePath !== source)
    || (event.kind === "put" && (!Number.isSafeInteger(event.putBytes)
      || event.putBytes < 0 || typeof event.putSha256 !== "string"
      || !/^[0-9a-f]{64}$/.test(event.putSha256)
      || signed.metadata.size !== event.putBytes))) {
    throw Object.assign(new Error("Signed WebDAV translation does not match local mutation"),
      { code: "authorization_rejected" });
  }
}

function xml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[character]));
}

function writeResponse(res, status, body = "", headers = {}) {
  // A WebDAV error can contain a rejected caller-controlled path. Browsers
  // must not treat that text as HTML via MIME sniffing. Successful PROPFIND
  // explicitly overrides this default with the required XML media type.
  res.writeHead(status, {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Type": "text/plain; charset=utf-8",
    ...headers,
  });
  res.end(body);
}

class LocalSyncWebDavBridge {
  constructor(options = {}) {
    this.rootDir = path.resolve(options.rootDir || process.cwd());
    this.trashDir = path.resolve(options.trashDir || path.join(this.rootDir, ".rootark-trash"));
    this.token = String(options.token || "");
    this.host = options.host || "127.0.0.1";
    this.port = Number(options.port || 0);
    this.maxBodyBytes = options.maxBodyBytes === undefined
      ? MAX_BODY_BYTES : Number(options.maxBodyBytes);
    // A malformed override (NaN/Infinity/negative/fractional) must not
    // disable both Content-Length and streamed-size checks, turning PUT
    // bodies into unbounded in-memory buffers. The hard server cap remains
    // 8 MiB even when an embedder supplies a larger configuration value.
    if (!Number.isSafeInteger(this.maxBodyBytes)
      || this.maxBodyBytes < 1 || this.maxBodyBytes > MAX_BODY_BYTES) {
      throw new Error("Invalid bounded WebDAV PUT body limit");
    }
    this.journal = options.journal || null;
    this.protocolJournal = options.protocolJournal || null;
    this.toProtocolOperation = options.toProtocolOperation || null;
    // Legacy bridges may queue unsigned V2 operations. A protected bridge
    // MUST be configured explicitly with a fresh trusted device-policy
    // provider: its direct journal path bypasses SyncEngine.buildOperation().
    this.requireSignedProtocolIngress = options.requireSignedProtocolIngress === true;
    this.trustedProtocolPolicy = options.trustedProtocolPolicy || null;
    // A trusted device key only proves who signed the ciphertext. Decrypting
    // through an independently provisioned file key also proves WHICH bytes
    // that device authorized for this particular physical WebDAV mutation.
    this.resolveProtectedFileKey = options.resolveProtectedFileKey || null;
    if (this.requireSignedProtocolIngress && (!this.protocolJournal
      || typeof this.toProtocolOperation !== "function"
      || typeof this.trustedProtocolPolicy !== "function")) {
      throw new Error("Protected WebDAV protocol ingress requires a trusted current device policy");
    }
    this.onOperation = options.onOperation || (options.journal ? (operation) => options.journal.enqueue(operation) : null);
    // An inherited hook is still a hook: checking only own properties lets a
    // prototype-supplied no-op silently bypass the protected write-ahead
    // admission journal before any physical mutation is recorded.
    this.hasCustomMutationJournalHook = "onOperation" in options;
    this.windowsAclVerifier = null;
    this.starting = false;
    this.startSettled = null;
    this.listenPending = false;
    this.stopRequested = false;
    this.stopping = false;
    this.stopSettled = null;
    // Per-instance local mutation critical section. Journal admission can
    // proceed concurrently, but file staging, rename/link/unlink, rollback
    // and outbox admission must not race another authenticated HTTP mutation.
    // This is NOT a cross-process or malicious-owner filesystem lock.
    this.localMutationTail = Promise.resolve();
    // Lifetime exclusivity is filesystem-backed, not merely a per-instance
    // Promise. A second bridge serving this root must fail before journal
    // reopen, even when it has its own in-memory SyncJournal instance.
    this.rootOwnerLockPath = path.join(this.rootDir, ".rootark-webdav-owner.lock");
    this.rootOwnerIdentity = null;
    // Two bridges may serve different roots but be configured to use the same
    // journal path. Root ownership alone cannot prevent lost JSON updates in
    // that case: also claim each on-disk journal for the bridge lifetime.
    this.journalOwnerClaims = [];
    // A PUT holds an in-memory body of up to 8 MiB while awaiting the local
    // lock or a signed translator. Bound total concurrent admissions.
    this.inflightMutations = 0;
    this.maxInflightMutations = 8;
    // A renamed but un-fsynced protocol outbox is not a durable ACK. Stop
    // admitting subsequent mutations until independent journal recovery;
    // another write could otherwise build on an uncertain signed outbox.
    this.protocolDurabilityUncertain = false;
    if (!this.token) throw new Error("Local WebDAV bridge bearer token is required");
    if (!isLoopback(this.host)) throw new Error("Local WebDAV bridge must bind to loopback");
    this.server = http.createServer((req, res) => this.handle(req, res));
  }

  async start() {
    // Reject repeated and concurrent starts BEFORE any await or replacement
    // of the bridge's long-lived native ACL subprocess.
    if (this.starting || this.stopping || this.server.listening) {
      throw new Error("Local WebDAV bridge is already starting or listening");
    }
    if (this.protocolDurabilityUncertain) {
      throw new Error("WebDAV outbox durability uncertain; use independently reconciled journals");
    }
    this.starting = true;
    this.stopRequested = false;
    let settleStart;
    this.startSettled = new Promise((resolve) => { settleStart = resolve; });
    try {
      if (this.requireSignedProtocolIngress) {
        if (this.hasCustomMutationJournalHook
          || typeof this.resolveProtectedFileKey !== "function") {
          throw new Error("Protected WebDAV requires a trusted file-key resolver and durable admission hook");
        }
        // A signed outbox alone is not a write-ahead mutation journal. Without
        // a genuine persisted journal, a crash after physical rename and
        // before signed enqueue loses its recovery witness forever.
        if (!(this.protocolJournal instanceof SyncJournal)
          || !this.protocolJournal.filePath
          || typeof this.protocolJournal.hasDurableSignedReceipt !== "function") {
          throw new Error("Protected WebDAV requires a persistent signed protocol outbox");
        }
        if (!(this.journal instanceof SyncJournal)
          || !this.journal.filePath || typeof this.journal.enqueue !== "function"
          || typeof this.journal.update !== "function"
          || typeof this.journal.markSeen !== "function"
          || typeof this.journal.recover !== "function") {
          throw new Error("Protected WebDAV requires a durable local mutation journal");
        }
        // Mutation phases and signed protocol envelopes are independent
        // durability domains. Pointing both journals at the same pathname
        // lets a later enqueue replace the other's pending evidence.
        const localJournalPath = path.resolve(this.journal.filePath);
        const signedOutboxPath = path.resolve(this.protocolJournal.filePath);
        if (process.platform === "win32"
          ? localJournalPath.toLowerCase() === signedOutboxPath.toLowerCase()
          : localJournalPath === signedOutboxPath) {
          throw new Error("Protected WebDAV requires distinct mutation and signed outbox journals");
        }
      }
      // The bearer authorizes ordinary document access, NEVER permission to
      // read, PUT, MOVE or DELETE the bridge's private write-ahead evidence.
      // Even an unprotected legacy bridge must not expose a journal under
      // its served root; reserved-name filtering alone cannot cover a
      // caller-selected SyncJournal filename.
      for (const journal of [this.journal, this.protocolJournal]) {
        if (journal instanceof SyncJournal && sameOrBelow(journal.filePath, this.rootDir)) {
          throw new Error("WebDAV journals must reside outside the served document root");
        }
      }
      if (process.platform === "win32") {
        if (!sameOrBelow(this.trashDir, this.rootDir) || this.trashDir === this.rootDir) {
          throw Object.assign(new Error("Trash directory must be below bridge root"), { statusCode: 400 });
        }
        await fsp.mkdir(this.rootDir, { recursive: true });
      } else {
        if (!sameOrBelow(this.trashDir, this.rootDir) || this.trashDir === this.rootDir) {
          throw Object.assign(new Error("Trash directory must be below bridge root"), { statusCode: 400 });
        }
        createPosixTrustedBridgeDirectory(this.rootDir, this.rootDir);
      }
      await rejectSymlinks(this.rootDir, this.rootDir, false);
      assertPosixTrustedBridgePath(this.rootDir, this.rootDir, false);
      // Reject an unsafe root before creating trash/journal state or replaying
      // pending mutations. Runtime requests repeat this check because a trusted
      // actor might later introduce a subtree with a permissive inherited ACL.
      if (process.platform === "win32") verifyWindowsLocalWebDavTree(this.rootDir);
      await this.claimRootOwnership();
      if (this.stopRequested) throw new Error("Local WebDAV bridge start cancelled by stop");
      // Read the latest durable bytes ONLY AFTER gaining exclusive ownership.
      // Pre-opened SyncJournal instances can otherwise overwrite a predecessor's
      // new pending events with stale in-memory snapshots. Strict and legacy
      // bridges both need this fence, not only protected signed ingress.
      const openedJournalStats = [];
      const physicalRoot = await fsp.realpath(this.rootDir);
      for (const journal of [this.journal, this.protocolJournal]) {
        if (!(journal instanceof SyncJournal)) continue;
        const journalParent = path.dirname(journal.filePath);
        // Detect an outside-looking symlink/junction parent before open()
        // could create a fresh private journal *inside* the served root.
        // Previously existing journal-file aliases need the same pre-open
        // check, not only a post-open assertion.
        for (const toResolve of [journalParent, journal.filePath]) {
          let physical;
          try { physical = await fsp.realpath(toResolve); }
          catch (error) {
            if (error.code !== "ENOENT") throw error;
            continue;
          }
          if (sameOrBelow(physical, physicalRoot)) {
            throw new Error("WebDAV journal resolves inside the served document root");
          }
        }
        if (!this.requireSignedProtocolIngress) {
          // Legacy SyncJournal.open() used to create a missing parent before
          // its first durable write. The cross-process claim now runs first:
          // preserve that bootstrap behavior WITHOUT letting an alias of
          // this missing directory resolve into the HTTP-served tree.
          await fsp.mkdir(journalParent, { recursive: true, mode: 0o700 });
          if (sameOrBelow(await fsp.realpath(journalParent), physicalRoot)) {
            throw new Error("WebDAV journal resolves inside the served document root");
          }
        }
        if (this.requireSignedProtocolIngress) {
          if (process.platform === "win32") verifyWindowsLocalWebDavTree(journalParent);
          else assertPosixTrustedBridgePath(journalParent, journalParent, false);
        }
        await this.claimJournalOwnership(journal);
        await journal.open();
        // A lexical path outside root may be a junction/symlink alias for an
        // inode INSIDE the HTTP-served document tree. Resolving it after
        // opening protects legacy journals as well as strict signed outboxes.
        // Strict mode additionally verifies every trusted ancestor and the
        // single-link regular-file inode below.
        if (sameOrBelow(await fsp.realpath(journal.filePath), physicalRoot)) {
          throw new Error("WebDAV journal resolves inside the served document root");
        }
        const journalStat = await fsp.lstat(journal.filePath, { bigint: true });
        if (!journalStat.isFile() || journalStat.isSymbolicLink()
          || journalStat.nlink !== 1n || journalStat.ino <= 0n) {
          // A second hardlink outside root could bypass pathname-based
          // lifetime locks even when both bridges serve distinct roots.
          throw new Error(this.requireSignedProtocolIngress
            ? "Untrusted protected WebDAV journal inode or link count"
            : "Untrusted WebDAV journal inode or link count");
        }
        if (this.requireSignedProtocolIngress) {
          if (process.platform === "win32") verifyWindowsLocalWebDavTree(journalParent);
          else assertPosixTrustedBridgePath(journalParent, journal.filePath, false);
          openedJournalStats.push(journalStat);
        }
      }
      if (openedJournalStats.length === 2 && openedJournalStats.every((stat) =>
        stat.ino > 0n && stat.dev === openedJournalStats[0].dev
        && stat.ino === openedJournalStats[0].ino)) {
        throw new Error("Protected WebDAV journals share one physical inode");
      }
      if (process.platform === "win32") await fsp.mkdir(this.trashDir, { recursive: true });
      else createPosixTrustedBridgeDirectory(this.rootDir, this.trashDir);
      await rejectSymlinks(this.rootDir, this.trashDir, false);
      assertPosixTrustedBridgePath(this.rootDir, this.trashDir, false);
      if (process.platform === "win32") verifyWindowsLocalWebDavTree(this.rootDir);
      if (this.trashDir === this.rootDir) throw Object.assign(new Error("Trash directory must be below bridge root"), { statusCode: 400 });
      if (this.stopRequested) throw new Error("Local WebDAV bridge start cancelled by stop");
      await this.recoverPending();
      if (this.stopRequested) throw new Error("Local WebDAV bridge start cancelled by stop");
      if (process.platform === "win32") {
        this.windowsAclVerifier = createWindowsLocalWebDavAclVerifier();
        // Compile/prime the long-lived native ACL worker before accepting
        // HTTP. Its first use otherwise puts variable PowerShell Add-Type
        // startup latency on the first authenticated request. This is a
        // FRESH native check, not a cached ACL approval for later requests.
        await this.windowsAclVerifier.verify(this.rootDir);
      }
      // stop() may cancel the async native warm-up without waiting for it;
      // prohibit a late listener after such a cancellation. No await occurs
      // between this cancellation fence and issuing listen.
      if (this.stopRequested) throw new Error("Local WebDAV bridge start cancelled by stop");
      this.listenPending = true;
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          this.server.off("error", onError);
          reject(error);
        };
        this.server.once("error", onError);
        try {
          this.server.listen(this.port, this.host, () => {
            this.server.off("error", onError);
            resolve();
          });
        } catch (error) {
          this.server.off("error", onError);
          reject(error);
        }
      });
      if (this.stopRequested) throw new Error("Local WebDAV bridge start cancelled by stop");
      return this.address();
    } catch (error) {
      // Failed listen/start must not retain a verifier that a caller has no
      // reason to stop, including when the underlying server throws.
      this.windowsAclVerifier?.stop();
      this.windowsAclVerifier = null;
      // A stop request may arrive after listen() committed, but before
      // start() returns its address. The startup catch must close that
      // listener BEFORE releasing the cross-process root ownership claim;
      // otherwise a second bridge can acquire the same root while the first
      // is still accepting authenticated HTTP requests.
      if (this.server.listening) {
        await new Promise((resolve, reject) => this.server.close((closeError) =>
          closeError ? reject(closeError) : resolve()));
      }
      await this.releaseJournalOwnership();
      await this.releaseRootOwnership();
      throw error;
    } finally {
      this.listenPending = false;
      this.starting = false;
      settleStart();
      this.startSettled = null;
    }
  }

  address() { return this.server.address(); }

  async claimRootOwnership() {
    if (this.rootOwnerIdentity) throw new Error("WebDAV root ownership already held");
    // mkdir is atomic on both Windows and POSIX. A lock left by a dead process
    // is deliberately NO-GO until an operator independently reconciles it;
    // a PID-only stale-lock steal would allow two live owners after PID reuse.
    await fsp.mkdir(this.rootOwnerLockPath, { mode: 0o700 });
    const stat = await fsp.lstat(this.rootOwnerLockPath, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error("Untrusted WebDAV lifetime lock type");
    }
    this.rootOwnerIdentity = durableEntryIdentity(stat);
    if (process.platform === "win32") verifyWindowsLocalWebDavTree(this.rootDir);
    else assertPosixTrustedBridgePath(this.rootDir, this.rootOwnerLockPath, false);
  }

  async releaseRootOwnership() {
    if (!this.rootOwnerIdentity) return;
    const actual = await localEntryOrNull(this.rootOwnerLockPath);
    if (!matchesDurableIdentity(actual, this.rootOwnerIdentity)) {
      throw new Error("WebDAV lifetime lock was replaced; preserving foreign evidence");
    }
    await fsp.rmdir(this.rootOwnerLockPath);
    this.rootOwnerIdentity = null;
  }

  async claimJournalOwnership(journal) {
    const filename = path.resolve(journal.filePath);
    const key = process.platform === "win32" ? filename.toLowerCase() : filename;
    if (this.journalOwnerClaims.some((claim) => claim.key === key)) return;
    const lockPath = filename + ".webdav-owner.lock";
    // The lock is a sibling of the durable journal, not inside the public
    // document namespace. Atomic mkdir works across independent OS processes.
    // A crash leaves the claim for deliberate manual reconciliation; never
    // steal it based on a potentially reused PID.
    await fsp.mkdir(lockPath, { mode: 0o700 });
    const stat = await fsp.lstat(lockPath, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.ino <= 0n) {
      throw new Error("Untrusted WebDAV journal ownership lock");
    }
    this.journalOwnerClaims.push({
      key, lockPath, identity: durableEntryIdentity(stat),
    });
  }

  async releaseJournalOwnership() {
    while (this.journalOwnerClaims.length) {
      const claim = this.journalOwnerClaims[this.journalOwnerClaims.length - 1];
      const actual = await localEntryOrNull(claim.lockPath);
      if (!matchesDurableIdentity(actual, claim.identity)) {
        throw new Error("WebDAV journal ownership lock changed; preserving foreign evidence");
      }
      await fsp.rmdir(claim.lockPath);
      this.journalOwnerClaims.pop();
    }
  }

  async withLocalMutationLock(callback) {
    const predecessor = this.localMutationTail;
    let release;
    this.localMutationTail = new Promise((resolve) => { release = resolve; });
    await predecessor;
    try {
      // HTTP admission can precede another request's outbox fsync failure.
      // A queued request must recheck the durability fence AFTER acquiring
      // the serialized physical mutation lock, not only at HTTP entry.
      if (this.protocolDurabilityUncertain) {
        throw Object.assign(new Error("WebDAV protocol durability unverified; recovery required"),
          { statusCode: 503 });
      }
      return await callback();
    }
    finally { release(); }
  }

  async verifyRecoveredPutBytes(filename, operation, maxBytes = this.maxBodyBytes) {
    // A prepared journal record does NOT prove that its PUT happened. In
    // particular, preexisting/unrelated destination bytes must never be
    // reported as an authenticated completed PUT after a crash. Older records
    // missing this immutable payload witness fail closed for manual recovery.
    if (!Number.isSafeInteger(operation.putBytes) || operation.putBytes < 0
      || operation.putBytes > maxBytes
      || typeof operation.putSha256 !== "string"
      || !/^[0-9a-f]{64}$/.test(operation.putSha256)) {
      throw Object.assign(new Error("WebDAV PUT recovery lacks durable payload evidence"),
        { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    }
    const handle = await fsp.open(filename, fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    try {
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
        || before.size !== BigInt(operation.putBytes)) {
        throw new Error("Recovered PUT has an unexpected inode or size");
      }
      const hash = crypto.createHash("sha256");
      const chunk = Buffer.allocUnsafe(64 * 1024);
      let offset = 0;
      while (offset < operation.putBytes) {
        const length = Math.min(chunk.length, operation.putBytes - offset);
        const { bytesRead } = await handle.read(chunk, 0, length, offset);
        if (bytesRead === 0) throw new Error("Recovered PUT file truncated");
        hash.update(chunk.subarray(0, bytesRead));
        offset += bytesRead;
      }
      const after = await handle.stat({ bigint: true });
      const named = await fsp.lstat(filename, { bigint: true });
      if (!matchesDurableIdentity(before, operation.installedIdentity)) {
        throw new Error("Recovered PUT inode is not the admitted installed inode");
      }
      const stable = [after, named].every((stat) => stat.isFile()
        && !stat.isSymbolicLink() && stat.nlink === 1n
        && stat.dev === before.dev && stat.ino === before.ino
        && stat.size === before.size && stat.mtimeNs === before.mtimeNs
        && stat.ctimeNs === before.ctimeNs);
      if (!stable || hash.digest("hex") !== operation.putSha256) {
        throw new Error("Recovered PUT content or inode changed");
      }
      return true;
    } catch (_) {
      throw Object.assign(new Error("WebDAV PUT recovery content unverified"),
        { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    } finally { await handle.close(); }
  }

  async verifyRecoveredMoveBytes(filename, operation) {
    // Unlike PUT, MOVE keeps the preexisting inode. A matching dev/ino alone
    // does not prove its original authenticated content survived a crash and
    // subsequent same-inode modification. The signed MOVE destination bytes
    // were verified and bound to this local journal BEFORE outbox admission.
    if (!Number.isSafeInteger(operation.moveBytes) || operation.moveBytes < 0
      || typeof operation.moveSha256 !== "string"
      || !/^[0-9a-f]{64}$/.test(operation.moveSha256)) {
      throw Object.assign(new Error("WebDAV MOVE recovery lacks authenticated content witness"),
        { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    }
    try {
      return await this.verifyRecoveredPutBytes(filename, {
        putBytes: operation.moveBytes,
        putSha256: operation.moveSha256,
        installedIdentity: operation.sourceIdentity,
      }, Number.MAX_SAFE_INTEGER);
    } catch {
      throw Object.assign(new Error("WebDAV MOVE recovery content unverified"),
        { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    }
  }

  async verifyRecoveredSignedMoveContent(filename, operation) {
    // A local mutation journal is NOT independent cryptographic custody of
    // the file bytes. An actor able to rewrite this journal AND the same
    // installed inode could forge moveSha256/moveBytes while leaving the
    // legitimate, immutable Ed25519 outbox untouched. Reconstruct the bytes
    // from the exact separately committed signed MOVE envelope instead.
    // A seen-only digest with no retained envelope cannot prove those bytes:
    // intentionally require manual reconciliation rather than false ACK.
    try {
      // Signed ID namespace also proves the overwrite distinction: solo
      // MOVE uses webdavsolo-, displaced destination requires webdav- and
      // a distinct DELETE. A mismatched backup/identity fails closed.
      const overwritten = Boolean(operation.previousDestinationIdentity);
      if (overwritten !== Boolean(operation.trash)) {
        throw new Error("MOVE recovery overwrite identity and backup disagree");
      }
      const relative = boundWebDavRelativePath(operation.destination);
      const signedId = `${overwritten ? "webdav" : "webdavsolo"}-${operation.operationId}-${crypto.createHash("sha256")
        .update(`move:${relative}`).digest("hex").slice(0, 24)}`;
      const witness = operation.signedOutboxReceipts?.find((item) =>
        item.operationId === signedId);
      const entries = this.protocolJournal?.pending?.();
      const matching = Array.isArray(entries)
        ? entries.filter((item) => item.operationId === signedId) : [];
      if (!witness || matching.length !== 1
        || crypto.createHash("sha256").update(protocol.canonicalJson(matching[0]))
          .digest("hex") !== witness.digest) {
        throw new Error("Original signed MOVE envelope unavailable");
      }
      const signed = protocol.validateStoredOperation(matching[0]);
      assertSignedWebDavEventBinding(operation, signed);
      if (signed.operation !== "move" || typeof this.resolveProtectedFileKey !== "function") {
        throw new Error("Original signed MOVE key unavailable");
      }
      // This is historical authenticated-content verification, NOT a new
      // device authorization. No current grant or revocation decision is
      // issued here; replay may only ACK previously signed exact outbox bytes.
      const key = await this.resolveProtectedFileKey(signed);
      const plaintext = protocol.decodeMovePayload(protocol.decryptPayload(signed, key), key);
      if (!plaintext || plaintext.length !== operation.moveBytes
        || crypto.createHash("sha256").update(plaintext).digest("hex") !== operation.moveSha256) {
        throw new Error("Local MOVE witness differs from independently signed ciphertext");
      }
    } catch {
      throw Object.assign(new Error("WebDAV MOVE recovery lacks independently signed content proof"),
        { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    }
    await this.verifyRecoveredMoveBytes(filename, operation);
  }

  async verifyRecoveredSignedPutContent(filename, operation) {
    // PUT has the same independent-custody boundary as MOVE: mutating the
    // physical inode and its local SHA in tandem must not turn a genuine
    // signed envelope for OTHER bytes into a cold-recovery acknowledgement.
    try {
      const relative = boundWebDavRelativePath(operation.destination || operation.path);
      const verb = operation.existed === true ? "update" : "create";
      const signedId = `webdav-${operation.operationId}-${crypto.createHash("sha256")
        .update(`${verb}:${relative}`).digest("hex").slice(0, 24)}`;
      const witness = operation.signedOutboxReceipts?.find((item) =>
        item.operationId === signedId);
      const entries = this.protocolJournal?.pending?.();
      const matching = Array.isArray(entries)
        ? entries.filter((item) => item.operationId === signedId) : [];
      if (!witness || matching.length !== 1
        || crypto.createHash("sha256").update(protocol.canonicalJson(matching[0]))
          .digest("hex") !== witness.digest) {
        throw new Error("Original signed PUT envelope unavailable");
      }
      const signed = protocol.validateStoredOperation(matching[0]);
      assertSignedWebDavEventBinding(operation, signed);
      if (signed.operation !== verb || typeof this.resolveProtectedFileKey !== "function") {
        throw new Error("Original signed PUT key unavailable");
      }
      const key = await this.resolveProtectedFileKey(signed);
      const plaintext = protocol.decryptPayload(signed, key);
      if (!plaintext || plaintext.length !== operation.putBytes
        || crypto.createHash("sha256").update(plaintext).digest("hex") !== operation.putSha256) {
        throw new Error("Local PUT witness differs from independently signed ciphertext");
      }
    } catch {
      throw Object.assign(new Error("WebDAV PUT recovery lacks independently signed content proof"),
        { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    }
    await this.verifyRecoveredPutBytes(filename, operation);
  }

  async recoverPending() {
    if (!this.journal?.recover) return;
    for (const operation of await this.journal.recover()) {
      // A phase label alone is not an authenticated durability witness, even
      // when it claims that the remote protocol outbox was already queued.
      if (operation.phase === "protocol-queued" && !this.protocolJournal) {
        throw Object.assign(new Error("WebDAV protocol-queued recovery lacks durable outbox"),
          { code: "WEBDAV_RECOVERY_INDETERMINATE" });
      }
      if (!["move", "put", "delete"].includes(operation.kind)) {
        throw Object.assign(new Error("Unknown pending WebDAV journal mutation kind"),
          { code: "WEBDAV_RECOVERY_INDETERMINATE" });
      }
      if (!["prepared", "staged", "source-moved", "protocol-queued"].includes(operation.phase)
        || (this.requireSignedProtocolIngress && operation.journalType !== "webdav-mutation")) {
        throw Object.assign(new Error("Unknown WebDAV mutation journal phase or type"),
          { code: "WEBDAV_RECOVERY_INDETERMINATE" });
      }
      const sourcePath = operation.source || operation.path;
      const destinationPath = operation.kind === "delete" ? sourcePath : (operation.destination || operation.path || operation.source);
      if (!destinationPath) {
        throw Object.assign(new Error("Pending WebDAV mutation has no destination"),
          { code: "WEBDAV_RECOVERY_INDETERMINATE" });
      }
      const destination = await this.target(destinationPath);
      const source = sourcePath ? await this.target(sourcePath) : null;
      const backup = operation.trash ? path.resolve(this.rootDir, operation.trash) : null;
      // Journal replay can rename files before the HTTP request guard runs.
      // The same POSIX ancestry boundary must hold during recovery.
      assertPosixTrustedBridgePath(this.rootDir, destination);
      if (source) assertPosixTrustedBridgePath(this.rootDir, source);
      if (backup) assertPosixTrustedBridgePath(this.rootDir, backup);
      if (backup) await rejectSymlinks(this.rootDir, backup, true);
      const backupStat = backup ? await localEntryOrNull(backup) : null;
      const destinationStat = await localEntryOrNull(destination);
      const sourceStat = source ? await localEntryOrNull(source) : null;
      const backupExists = Boolean(backupStat);
      const destinationExists = Boolean(destinationStat);
      const sourceExists = Boolean(sourceStat);
      // A crash before the first physical rename leaves the original source
      // and (when replacing) the original destination at their old inodes.
      // This is evidence of NO application, not permission to enqueue a
      // completed operation or to overwrite either pathname on recovery.
      if (operation.phase === "prepared" && operation.kind === "move"
        && !matchesDurableIdentity(sourceStat, operation.sourceIdentity)) {
        throw Object.assign(new Error("Prepared MOVE lacks original source inode witness"),
          { code: "WEBDAV_RECOVERY_INDETERMINATE" });
      }
      if (operation.phase === "prepared" && !backupExists
        && ((operation.kind === "put" && operation.existed === false
          && !destinationExists)
          || (operation.kind === "put" && operation.existed === true
          && matchesDurableIdentity(destinationStat, operation.previousIdentity))
          || (operation.kind === "delete" && sourceExists
          && matchesDurableIdentity(sourceStat, operation.sourceIdentity))
          || (operation.kind === "move" && sourceExists
            && matchesDurableIdentity(sourceStat, operation.sourceIdentity)
            && (operation.trash
              ? matchesDurableIdentity(destinationStat, operation.previousDestinationIdentity)
              : !destinationExists)))) {
        if (this.journal.markSeen) await this.journal.markSeen(operation.operationId);
        continue;
      }
      let applied = false;
      if (operation.kind === "move") {
        if (["source-moved", "protocol-queued"].includes(operation.phase)) {
          if (sourceExists || !destinationExists
            || !matchesDurableIdentity(destinationStat, operation.sourceIdentity)
            || (operation.trash && !matchesDurableIdentity(backupStat, operation.previousDestinationIdentity))) {
            throw Object.assign(new Error("MOVE recovery cannot prove installed source identity"),
              { code: "WEBDAV_RECOVERY_INDETERMINATE" });
          }
          applied = true;
        }
      }
      else if (operation.kind === "put") {
        // A prepared PUT can point to a file that existed long before the
        // request or was created by another actor. A staged PUT has not yet
        // durably acknowledged its install. Neither is proof of application.
        if (["source-moved", "protocol-queued"].includes(operation.phase)) {
          if (!destinationExists || (operation.existed
            && (!backupExists || !matchesDurableIdentity(backupStat, operation.previousIdentity)))) {
            throw Object.assign(new Error("WebDAV PUT recovery installation is ambiguous"),
              { code: "WEBDAV_RECOVERY_INDETERMINATE" });
          }
          applied = await this.verifyRecoveredPutBytes(destination, operation);
        } else if (operation.phase === "prepared" && destinationExists) {
          throw Object.assign(new Error("WebDAV prepared PUT cannot prove installation"),
            { code: "WEBDAV_RECOVERY_INDETERMINATE" });
        } else if (operation.phase === "staged" && destinationExists && backupExists) {
          throw Object.assign(new Error("WebDAV staged PUT installation is ambiguous"),
            { code: "WEBDAV_RECOVERY_INDETERMINATE" });
        }
      }
      else if (["source-moved", "protocol-queued"].includes(operation.phase)) {
        if (sourceExists || !matchesDurableIdentity(backupStat, operation.sourceIdentity)) {
          throw Object.assign(new Error("DELETE recovery cannot prove original trash inode"),
            { code: "WEBDAV_RECOVERY_INDETERMINATE" });
        }
        applied = true;
      }

      if (applied) {
        if (this.requireSignedProtocolIngress) {
          if (this.hasPreviouslyCommittedSignedOutbox(operation)) {
            if (operation.kind === "put") {
              await this.verifyRecoveredSignedPutContent(destination, operation);
            } else if (operation.kind === "move") {
              await this.verifyRecoveredSignedMoveContent(destination, operation);
            }
            // The outbox already durably contains (or has durably acknowledged)
            // the exact signed operation ID and envelope fingerprint. Do not
            // demand a NEW unexpired signature or re-admit a revoked device
            // merely because the physical mutation's local ACK was lost.
            if (this.journal.markSeen) await this.journal.markSeen(operation.operationId);
            continue;
          }
          if (operation.phase === "protocol-queued") {
            // An asserted committed phase without a matching prior signed
            // outbox receipt is not evidence of a successful admission.
            throw Object.assign(new Error("Committed WebDAV protocol outbox receipt missing"),
              { code: "WEBDAV_RECOVERY_INDETERMINATE" });
          }
        }
        const protocolQueued = await this.enqueueProtocol(operation);
        if (protocolQueued) await this.updateJournal(operation.operationId, { phase: "protocol-queued" });
        if (this.journal.markSeen) await this.journal.markSeen(operation.operationId);
        continue;
      }

      const rolledBack = operation.phase === "staged" && !backupExists
        && ((operation.kind === "put" && operation.existed
          && matchesDurableIdentity(destinationStat, operation.previousIdentity))
          || (operation.kind === "move" && operation.trash
            && matchesDurableIdentity(destinationStat, operation.previousDestinationIdentity)
            && matchesDurableIdentity(sourceStat, operation.sourceIdentity)));
      if (rolledBack) {
        if (this.journal.markSeen) await this.journal.markSeen(operation.operationId);
        continue;
      }

      if (backupExists && !destinationExists && operation.kind !== "delete") {
        const originalIdentity = operation.kind === "put"
          ? operation.previousIdentity : operation.previousDestinationIdentity;
        if ((operation.kind === "move"
          && !matchesDurableIdentity(sourceStat, operation.sourceIdentity))
          || (operation.kind === "put" && !operation.existed)
          || !matchesDurableIdentity(backupStat, originalIdentity) || !backupStat.isFile()) {
          throw Object.assign(new Error("Staged WebDAV backup has no trusted restorable identity"),
            { code: "WEBDAV_RECOVERY_INDETERMINATE" });
        }
        // Exclusive file restoration: a newly created destination MUST not
        // be replaced between existence inspection and recovery.
        await fsp.link(backup, destination);
        // The two names MUST temporarily witness the very same inode, each
        // with nlink2, before removing the staged backup. Ordinary completed
        // MOVE/DELETE replay still requires nlink1 and refuses hardlink aliases.
        if (!matchesDurableIdentity(await localEntryOrNull(destination), originalIdentity, 2n)
          || !matchesDurableIdentity(await localEntryOrNull(backup), originalIdentity, 2n)) {
          throw Object.assign(new Error("Staged WebDAV restored a substituted inode"),
            { code: "WEBDAV_RECOVERY_INDETERMINATE" });
        }
        await fsp.unlink(backup);
        await syncBridgeNamespace(backup, destination);
      } else if ((backupExists || destinationExists || !sourceExists)
        && ["prepared", "staged", "protocol-queued"].includes(operation.phase)) {
        throw Object.assign(new Error("WebDAV recovery state is ambiguous"),
          { code: "WEBDAV_RECOVERY_INDETERMINATE" });
      }
      if (this.journal.markSeen) await this.journal.markSeen(operation.operationId);
    }
  }

  async updateJournal(operationId, patch) {
    if (this.journal?.update) await this.journal.update(operationId, patch);
  }

  async markJournalSeen(operationId) {
    if (this.journal?.markSeen) await this.journal.markSeen(operationId);
  }

  hasPreviouslyCommittedSignedOutbox(event) {
    if (!this.requireSignedProtocolIngress
      || typeof this.protocolJournal?.durableSignedReceiptDigest !== "function") {
      return false;
    }
    if (!event || !["put", "move", "delete"].includes(event.kind)
      || typeof event.operationId !== "string"
      || !/^[A-Za-z0-9._:-]{1,100}$/.test(event.operationId)) return false;
    const opcode = event.kind === "put" ? (event.existed === true ? "update" : "create")
      : event.kind;
    const pathToBind = event.kind === "delete" ? (event.source || event.path)
      : (event.destination || event.path);
    const relativePath = boundWebDavRelativePath(pathToBind);
    const solo = event.kind === "delete"
      || (event.kind === "move" && !event.previousDestinationIdentity);
    const expectedId = `${solo ? "webdavsolo" : "webdav"}-${event.operationId}-${crypto.createHash("sha256")
      .update(`${opcode}:${relativePath}`).digest("hex").slice(0, 24)}`;
    const overwrittenMove = event.kind === "move" && Boolean(event.previousDestinationIdentity);
    // An overwriting MOVE destroys the old destination inode as well as
    // installing the source. Both effects require distinct signed envelopes
    // and a complete cross-journal batch receipt, even on restart.
    const companionId = overwrittenMove ? `webdav-${event.operationId}-${crypto.createHash("sha256")
      .update(`delete:${relativePath}`).digest("hex").slice(0, 24)}` : null;
    // An outbox entry's ID is not proof that it contains the exact Ed25519
    // envelope authenticated BEFORE the original mutation's signed ingress.
    // Recovery must compare independent durable local evidence of the
    // authenticated complete batch to the exact persisted outbox digests.
    // A local missing/legacy witness fails closed, even if the outbox says
    // this ID is "seen". No new signature or expired device is authorized.
    const receipts = event.signedOutboxReceipts;
    if (!Array.isArray(receipts) || receipts.length !== (overwrittenMove ? 2 : 1)
      || (event.kind === "move"
        && Boolean(event.previousDestinationIdentity) !== Boolean(event.trash))) {
      return false;
    }
    const ids = new Set();
    for (const receipt of receipts) {
      if (!receipt || typeof receipt !== "object"
        || typeof receipt.operationId !== "string"
        || !/^[A-Za-z0-9._:-]{1,160}$/.test(receipt.operationId)
        || typeof receipt.digest !== "string" || !/^[0-9a-f]{64}$/.test(receipt.digest)
        || ids.has(receipt.operationId)
        || this.protocolJournal.durableSignedReceiptDigest(receipt.operationId) !== receipt.digest) {
        return false;
      }
      ids.add(receipt.operationId);
    }
    return ids.has(expectedId) && (!overwrittenMove || ids.has(companionId));
  }

  async enqueueProtocol(operation) {
    if (!this.protocolJournal) return false;
    if (!this.toProtocolOperation) throw new Error("WebDAV protocol translation required");
    const translated = await this.toProtocolOperation(operation);
    if (!translated) throw new Error("WebDAV mutation translation failed");
    let admitted = translated;
    // A signed translator cannot silently fall through to the historical
    // unauthenticated path simply because the embedding process forgot the
    // strict-mode option. Mixed signed/unsigned batches must also fail.
    const translatedEntries = Array.isArray(translated) ? translated : [translated];
    const containsSigned = translatedEntries.some((entry) => entry
      && typeof entry === "object" && Object.hasOwn(entry, "authorization"));
    if (this.requireSignedProtocolIngress || containsSigned) {
      // Verify the actual Ed25519 signature against a PINNED device key and
      // explicit current revocation state before touching the outbox. A
      // structural authorization field or caller-supplied key is not trust.
      // Verify the ENTIRE batch before one atomic enqueueMany; detached
      // copies prevent translator/policy callbacks from swapping the bytes.
      if (typeof this.trustedProtocolPolicy !== "function") {
        throw new Error("Protected WebDAV current device policy required");
      }
      const operations = translatedEntries;
      if (!operations.length) throw new Error("Protected WebDAV mutation cannot be unsigned or empty");
      const candidates = [];
      let moveContentWitness = null;
      const boundEvent = Object.freeze(JSON.parse(protocol.canonicalJson(operation)));
      const freezeSignedEnvelope = (value) => {
        if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
        for (const nested of Object.values(value)) freezeSignedEnvelope(nested);
        return Object.freeze(value);
      };
      const currentPolicyOrDeny = (signed) => {
        const current = this.trustedProtocolPolicy(signed);
        const keys = current?.trustedDevicePublicKeys;
        if (!current || typeof current !== "object"
          || typeof current.then === "function"
          || current.username !== signed.authorization.username
          || !keys || typeof keys !== "object" || Array.isArray(keys)
          || !Object.hasOwn(keys, signed.deviceId)
          || keys[signed.deviceId] !== signed.authorization.publicKey
          || !Array.isArray(current.revokedDeviceIds)
          || current.revokedDeviceIds.includes(signed.deviceId)
          || signed.authorization.expiresAt <= Date.now()) {
          throw Object.assign(new Error("Protected WebDAV current device authorization rejected"),
            { code: "authorization_rejected" });
        }
        return current;
      };
      for (const source of operations) {
        const candidate = JSON.parse(protocol.canonicalJson(source));
        // Policy callbacks are not allowed to change the exact operation
        // already checked for signature/digest and later written to journal.
        const signed = freezeSignedEnvelope(protocol.validateFreshSignedOperation(candidate));
        assertSignedWebDavEventBinding(boundEvent, signed);
        // The trusted policy is supplied by the embedding process, never by
        // the HTTP mutation or its translator. Require explicit revocation
        // data; a missing list cannot be interpreted as no revocations.
        const policy = currentPolicyOrDeny(signed);
        if (await verifyAuthorizationProof(signed.authorization, signed, policy) !== true) {
          throw new Error("Protected WebDAV device authorization rejected");
        }
        if (signed.operation !== "delete") {
          if (typeof this.resolveProtectedFileKey !== "function") {
            throw Object.assign(new Error("Protected WebDAV file key resolver required"),
              { code: "authorization_rejected" });
          }
          const fileKey = await this.resolveProtectedFileKey(signed);
          const decrypted = protocol.decryptPayload(signed, fileKey);
          const payload = signed.operation === "move"
            ? protocol.decodeMovePayload(decrypted, fileKey) : decrypted;
          if (!payload) throw Object.assign(new Error("Protected MOVE has invalid authenticated payload"),
            { code: "authorization_rejected" });
          if (boundEvent.kind === "put") {
            const digest = crypto.createHash("sha256").update(payload).digest("hex");
            if (payload.length !== boundEvent.putBytes || digest !== boundEvent.putSha256) {
              throw Object.assign(new Error("Protected PUT ciphertext does not bind uploaded bytes"),
                { code: "authorization_rejected" });
            }
          } else if (boundEvent.kind === "move") {
            if (signed.operation === "move") {
              moveContentWitness = {
                moveBytes: payload.length,
                moveSha256: crypto.createHash("sha256").update(payload).digest("hex"),
              };
            }
            // Physical MOVE has already happened, so compare a pinned
            // destination descriptor against the signed decrypted content.
            const target = await this.target(boundEvent.destination);
            const handle = await fsp.open(target, fs.constants.O_RDONLY
              | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
            try {
              const before = await handle.stat({ bigint: true });
              if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(payload.length)) {
                throw new Error("Protected MOVE file identity or size mismatch");
              }
              const digest = crypto.createHash("sha256");
              const buffer = Buffer.allocUnsafe(64 * 1024);
              for (let offset = 0; offset < payload.length;) {
                const { bytesRead } = await handle.read(buffer, 0,
                  Math.min(buffer.length, payload.length - offset), offset);
                if (!bytesRead) throw new Error("Protected MOVE file truncated");
                digest.update(buffer.subarray(0, bytesRead));
                offset += bytesRead;
              }
              const named = await fsp.lstat(target, { bigint: true });
              const after = await handle.stat({ bigint: true });
              if (![named, after].every((stat) => sameLocalEntry(stat, before)
                && stat.size === before.size && stat.mtimeNs === before.mtimeNs
                && stat.ctimeNs === before.ctimeNs)
                || digest.digest("hex") !== crypto.createHash("sha256").update(payload).digest("hex")) {
                throw new Error("Protected MOVE signed content changed after install");
              }
            } finally { await handle.close(); }
          }
        }
        candidates.push(signed);
      }
      if (boundEvent.kind === "put" && candidates.length !== 1) {
        throw Object.assign(new Error("Protected PUT must authorize exactly one ciphertext mutation"),
          { code: "authorization_rejected" });
      }
      if (boundEvent.kind === "move" && candidates.filter((entry) =>
        entry.operation === "move").length !== 1) {
        throw Object.assign(new Error("Protected MOVE lacks an authorized destination mutation"),
          { code: "authorization_rejected" });
      }
      if (boundEvent.kind === "move") {
        const overwrite = Boolean(boundEvent.previousDestinationIdentity);
        if (overwrite !== Boolean(boundEvent.trash)
          || candidates.length !== (overwrite ? 2 : 1)
          || candidates.filter((entry) => entry.operation === "delete").length !== (overwrite ? 1 : 0)
          // An old destination tombstone MUST precede installing the MOVE;
          // the reverse order could delete the newly moved ciphertext.
          || (overwrite && (candidates[0].operation !== "delete"
            || candidates[1].operation !== "move"))
          || new Set(candidates.map((entry) => entry.operationId)).size !== candidates.length) {
          throw Object.assign(new Error("Protected MOVE overwrite requires an atomic signed destination tombstone"),
            { code: "authorization_rejected" });
        }
      }
      if (boundEvent.kind === "delete" && candidates.length !== 1) {
        throw Object.assign(new Error("Protected file DELETE requires exactly one signed tombstone"),
          { code: "authorization_rejected" });
      }
      // The crypto checks above may yield and a batch may take several
      // iterations. This final recheck is synchronous for ALL operations,
      // without an await between it and starting durable journal enqueue.
      // It narrows the local window, but is NOT a distributed transaction:
      // the remote atomic store must still fence concurrent revocation.
      for (const signed of candidates) currentPolicyOrDeny(signed);
      // Bind the exact verified signed-envelope bytes, including every
      // companion MOVE/delete operation, to the already durable local
      // physical mutation record BEFORE writing the signed outbox. A crash
      // after outbox fsync but before protocol-queued/markSeen may then
      // reconcile ONLY the same authenticated bytes, never an ID collision.
      if (this.requireSignedProtocolIngress) {
        const signedOutboxReceipts = candidates.map((signed) => ({
          operationId: signed.operationId,
          digest: crypto.createHash("sha256")
            .update(protocol.canonicalJson(signed)).digest("hex"),
        }));
        if (signedOutboxReceipts.length > 4) {
          throw Object.assign(new Error("Protected WebDAV signed batch exceeds receipt limit"),
            { code: "authorization_rejected" });
        }
        if (boundEvent.kind === "move" && !moveContentWitness) {
          throw Object.assign(new Error("Protected MOVE lacks signed content witness"),
            { code: "authorization_rejected" });
        }
        const witness = { signedOutboxReceipts,
          ...(moveContentWitness || {}) };
        await this.updateJournal(operation.operationId, witness);
        if (!this.journal.pending().some((entry) =>
          entry.operationId === operation.operationId
            && Object.entries(witness).every(([key, value]) =>
              protocol.canonicalJson(entry[key]) === protocol.canonicalJson(value)))) {
          throw new Error("Protected WebDAV cannot prove durable signed admission binding");
        }
        // The digest commit above awaited filesystem durability. Recheck live
        // revocation immediately afterward, before starting outbox enqueue.
        for (const signed of candidates) currentPolicyOrDeny(signed);
      }
      admitted = Array.isArray(translated) ? candidates : candidates[0];
    }
    try {
      if (Array.isArray(admitted)) {
        if (!admitted.length) return false;
        if (typeof this.protocolJournal.enqueueMany !== "function") throw new Error("WebDAV mutation batch cannot be committed atomically");
        await this.protocolJournal.enqueueMany(admitted);
      } else {
        await this.protocolJournal.enqueue(admitted);
      }
    } catch (error) {
      if (error.journalCommitted) {
        error.protocolQueueUncertain = true;
        this.protocolDurabilityUncertain = true;
      }
      throw error;
    }
    return true;
  }

  async stop() {
    if (this.stopping) return this.stopSettled;
    this.stopping = true;
    this.stopRequested = true;
    let settleStop;
    this.stopSettled = new Promise((resolve) => { settleStop = resolve; });
    try {
      // Pre-listen recovery may be unbounded, or may itself await stop().
      // Cancel immediately in that phase; the start's post-recovery guard
      // prevents a later listener or native worker. Once listen was issued,
      // wait for its outcome so stop cannot return with a late HTTP listener.
      if (this.listenPending && this.startSettled) await this.startSettled;
      this.windowsAclVerifier?.stop();
      this.windowsAclVerifier = null;
      if (this.server.listening) await new Promise((resolve) => this.server.close(resolve));
      await this.localMutationTail;
      // During pre-listen startup, recovery may still be reading or
      // restoring physically durable entries. stop() intentionally does not
      // await that potentially reentrant work, but MUST also not release its
      // cross-process ownership claim while it is active. The cancelled
      // start() observes stopRequested, fails closed and releases the claim
      // from its catch path after recovery has stopped touching the tree.
      if (!this.starting || this.listenPending) {
        await this.releaseJournalOwnership();
        await this.releaseRootOwnership();
      }
    } finally {
      this.stopping = false;
      settleStop();
      this.stopSettled = null;
    }
  }

  authorized(req) {
    const header = String(req.headers.authorization || "");
    const supplied = header.startsWith("Bearer ") ? header.slice(7) : "";
    const expected = Buffer.from(this.token);
    const actual = Buffer.from(supplied);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  }

  async target(urlPath) {
    const target = await canonicalPath(this.rootDir, path.join(this.rootDir, ...safeSegments(urlPath)), true);
    if (target === this.rootDir) return target;
    if (sameOrBelow(target, this.trashDir)) throw Object.assign(new Error("Internal trash path is not accessible"), { statusCode: 400 });
    const parent = await canonicalPath(this.rootDir, path.dirname(target), false);
    return path.join(parent, path.basename(target));
  }

  async verifyWindowsItem(target) {
    // One framed native check verifies the selected leaf (if present) and
    // its private parent. A missing leaf still needs a trusted parent before
    // PUT/MKCOL. Pin inode identity across the asynchronous ACL lookup.
    const original = await fsp.lstat(target, { bigint: true }).catch((error) =>
      error.code === "ENOENT" ? null : Promise.reject(error));
    if (original?.isFile()) await this.windowsAclVerifier.verifyFile(target);
    else await this.windowsAclVerifier.verify(original ? target : path.dirname(target));
    if (original) {
      const current = await fsp.lstat(target, { bigint: true });
      if (current.dev !== original.dev || current.ino !== original.ino
        || current.isDirectory() !== original.isDirectory()
        || current.isFile() !== original.isFile()) {
        throw new Error("Bridge item identity changed during ACL verification");
      }
    }
  }

  async body(req) {
    const declared = Number(req.headers["content-length"]);
    if (Number.isSafeInteger(declared) && declared > this.maxBodyBytes) throw Object.assign(new Error("Payload too large"), { statusCode: 413 });
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > this.maxBodyBytes) throw Object.assign(new Error("Payload too large"), { statusCode: 413 });
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }

  async properties(target, requestPath) {
    const stats = await fsp.lstat(target);
    if (stats.isSymbolicLink()) throw Object.assign(new Error("Symlink paths are not supported"), { statusCode: 400 });
    const collection = stats.isDirectory();
    return `<d:response><d:href>${xml(requestPath)}${collection ? "/" : ""}</d:href><d:propstat><d:prop><d:resourcetype>${collection ? "<d:collection/>" : ""}</d:resourcetype><d:getcontentlength>${collection ? 0 : stats.size}</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
  }

  async handle(req, res) {
    if (!this.authorized(req)) return writeResponse(res, 401, "Unauthorized", { "WWW-Authenticate": "Bearer" });
    const mutation = ["PUT", "MOVE", "DELETE", "MKCOL"].includes(req.method);
    if (mutation && this.protocolDurabilityUncertain) {
      return writeResponse(res, 503, "WebDAV protocol durability unverified; recovery required");
    }
    if (mutation && this.inflightMutations >= this.maxInflightMutations) {
      return writeResponse(res, 503, "Too many pending WebDAV mutations", { "Retry-After": "1" });
    }
    if (mutation) this.inflightMutations++;
    try {
      // Validate the raw request target before WHATWG URL normalizes dot segments.
      safeSegments(String(req.url || "/").split("?", 1)[0]);
      const parsed = new URL(req.url, "http://localhost");
      const target = await this.target(parsed.pathname);
      if (process.platform !== "win32") {
        try { assertPosixTrustedBridgePath(this.rootDir, target); }
        catch { return writeResponse(res, 503, "Untrusted bridge storage"); }
      }
      if (process.platform === "win32") {
        // NTFS O_NOFOLLOW protects the leaf but not an ancestor junction.
        // A transient swap can open an outside-root inode, restore the safe
        // pathname, then pass every later lstat/fstat comparison. An untrusted
        // local SID with Modify/DELETE_CHILD on ANY ancestor or descendant
        // could race an authenticated request. Startup proves the full tree;
        // each request revalidates the selected leaf (if present), its parent,
        // and ALL ancestors without rescanning unrelated data.
        // This excludes actors
        // with trusted owner/admin privileges; no pathname recheck solves that.
        try {
          await this.verifyWindowsItem(target);
        }
        catch { return writeResponse(res, 503, "Untrusted bridge storage"); }
      }
      if (req.method === "OPTIONS") return writeResponse(res, 204, "", { DAV: "1", Allow: "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, MOVE, DELETE" });
      if (req.method === "PROPFIND") {
        const depth = String(req.headers.depth || "0");
        if (!["0", "1"].includes(depth)) return writeResponse(res, 400, "Invalid depth");
        const results = [await this.properties(target, parsed.pathname)];
        if (depth === "1" && (await fsp.lstat(target)).isDirectory()) {
          for (const entry of await fsp.readdir(target, { withFileTypes: true })) {
            if (entry.isSymbolicLink()) continue;
            const child = path.join(target, entry.name);
            const internalName = process.platform === "win32"
              ? entry.name.toLowerCase() : entry.name;
            if (internalName.startsWith(".rootark-put-")
              || internalName === ".rootark-webdav-owner.lock"
              || sameOrBelow(child, this.trashDir)) continue;
            if (process.platform !== "win32") {
              try { assertPosixTrustedBridgePath(this.rootDir, child, false); }
              catch { return writeResponse(res, 503, "Untrusted bridge storage"); }
            }
            results.push(await this.properties(child, `${parsed.pathname.replace(/\/$/, "")}/${entry.name}`));
          }
        }
        return writeResponse(res, 207, `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">${results.join("")}</d:multistatus>`, { "Content-Type": "application/xml; charset=utf-8" });
      }
      if (["GET", "HEAD"].includes(req.method)) {
        // Opening a pathname only when the stream begins would let a local
        // rename/symlink swap serve a different file than the one authorized.
        // Pin a regular, single-link inode before emitting success headers;
        // close only that descriptor, never reopen the mutable pathname.
        let fd;
        try {
          // A pathname can be swapped for a FIFO between admission checks
          // and open. Blocking O_RDONLY would freeze this HTTP event loop.
          // Pin a nonblocking FD *before* trusting any pathname stat, then
          // authorize only the same regular inode after its identity recheck.
          fd = fs.openSync(target, fs.constants.O_RDONLY
            | (fs.constants.O_NONBLOCK || 0)
            | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0));
          const opened = fs.fstatSync(fd, { bigint: true });
          if (!opened.isFile() || opened.isSymbolicLink() || opened.nlink !== 1n) {
            return writeResponse(res, 405, "Not a regular file");
          }
          const named = fs.lstatSync(target, { bigint: true });
          const again = fs.lstatSync(target, { bigint: true });
          const same = (a, b) => a.isFile() && !a.isSymbolicLink() && a.nlink === 1n
            && a.dev === b.dev && a.ino === b.ino && a.size === b.size
            && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
          if (!same(named, opened) || !same(opened, again)
            || opened.size > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw Object.assign(new Error("WebDAV source identity changed"), { statusCode: 409 });
          }
          await rejectSymlinks(this.rootDir, target, false);
          res.writeHead(200, {
            "Content-Length": Number(opened.size), "Cache-Control": "no-store",
            "Content-Type": "application/octet-stream", "X-Content-Type-Options": "nosniff",
          });
          if (req.method === "HEAD") {
            fs.closeSync(fd);
            fd = undefined;
            return res.end();
          }
          if (opened.size === 0n) {
            fs.closeSync(fd);
            fd = undefined;
            return res.end();
          }
          // A foreign UID may retain an old writable descriptor even after
          // the owner makes this inode read-only. A later append must never
          // overrun the already advertised HTTP Content-Length and corrupt
          // the framing of a subsequent response on this connection.
          const stream = fs.createReadStream(null, {
            fd, autoClose: true, start: 0, end: Number(opened.size) - 1,
          });
          fd = undefined;
          let sent = 0;
          stream.on("data", (chunk) => { sent += chunk.length; });
          stream.once("end", () => {
            // Shrinking the same inode is the dual of append: pipe() would
            // finish a short Content-Length body and leave keep-alive waiting
            // for attacker-controlled bytes from a subsequent HTTP response.
            if (sent !== Number(opened.size)) res.destroy();
          });
          // pipe() only unpipes on client abort; it does not guarantee the
          // source ReadStream closes its pinned FD before end-of-file.
          res.once("close", () => stream.destroy());
          stream.once("error", () => res.destroy());
          return stream.pipe(res);
        } finally {
          if (fd !== undefined) fs.closeSync(fd);
        }
      }
      if (req.method === "PUT") {
        if (target === this.rootDir) return writeResponse(res, 400, "Invalid target");
        const data = await this.body(req);
        if (this.requireSignedProtocolIngress
          && data.length > MAX_PROTECTED_REMOTE_SOURCE_BYTES) {
          return writeResponse(res, 413, "Protected ciphertext exceeds bounded remote sync wire budget");
        }
        const parent = path.dirname(target);
        await fsp.mkdir(parent, { recursive: false }).catch((error) => { if (error.code !== "EEXIST") throw error; });
        await rejectSymlinks(this.rootDir, parent, false);
        const existing = await fsp.lstat(target, { bigint: true }).catch((error) =>
          error.code === "ENOENT" ? null : Promise.reject(error));
        if (existing?.isSymbolicLink() || existing?.isDirectory()) return writeResponse(res, 409, "Invalid target");
        const operationId = crypto.randomUUID();
        const backup = existing ? path.join(this.trashDir, `.rootark-put-${operationId}-${path.basename(target)}`) : null;
        const operation = {
          operationId,
          kind: "put",
          journalType: "webdav-mutation",
          path: process.platform === "win32" ? encodedWebDavPath(this.rootDir, target) : parsed.pathname,
          source: process.platform === "win32" ? encodedWebDavPath(this.rootDir, target) : parsed.pathname,
          destination: process.platform === "win32" ? encodedWebDavPath(this.rootDir, target) : parsed.pathname,
          existed: Boolean(existing),
          // Persist only an exact payload fingerprint and byte count in the
          // private mutation journal. A restart must re-read the same pinned
          // file and verify both before it may enqueue a completed PUT.
          putBytes: data.length,
          putSha256: crypto.createHash("sha256").update(data).digest("hex"),
          previousIdentity: existing ? durableEntryIdentity(existing) : null,
          trash: backup ? path.relative(this.rootDir, backup) : null,
          phase: "prepared",
        };
        if (this.onOperation) await this.onOperation(operation);
        return await this.withLocalMutationLock(async () => {
        const temporary = path.join(parent, `.rootark-put-${process.pid}-${crypto.randomUUID()}`);
        let staged = false;
        let backupLinked = false;
        let installed = false;
        let installedIdentity = null;
        let protocolQueued = false;
        let ownedTemporary = null;
        const matchesIdentity = (named, identity) => identity && named.isFile()
          && !named.isSymbolicLink() && named.nlink === 1n
          && named.dev === identity.dev && named.ino === identity.ino;
        const stillOwned = (named) => matchesIdentity(named, ownedTemporary);
        try {
          // O_EXCL is essential even with a random basename: a preexisting
          // collision must never be truncated, and its owner never becomes us.
          const handle = await fsp.open(temporary, "wx", 0o600);
          try {
            const created = await handle.stat({ bigint: true });
            if (!created.isFile() || created.nlink !== 1n) throw new Error("Unsafe PUT staging file");
            ownedTemporary = { dev: created.dev, ino: created.ino };
            await handle.writeFile(data);
            // The content must reach durable file storage before publishing
            // its pathname or recording a completed mutation phase.
            await handle.sync();
            const written = await handle.stat({ bigint: true });
            if (!stillOwned(written) || written.size !== BigInt(data.length)) {
              throw new Error("PUT staging file identity changed");
            }
          } finally { await handle.close(); }
          if (!stillOwned(await fsp.lstat(temporary, { bigint: true }))) {
            throw new Error("PUT staging pathname changed");
          }
          if (backup) {
            await rejectSymlinks(this.rootDir, backup, true);
            if (!sameExclusiveSourceEntry(await localEntryOrNull(target), existing)) {
              throw uncertainRollback("WebDAV PUT original destination changed before backup");
            }
            // The private trash name is still an untrusted pathname. Link
            // exclusively before unlinking the original so a planted backup
            // can never be silently replaced by rename().
            await fsp.link(target, backup);
            backupLinked = true;
            await fsp.unlink(target);
            staged = true;
            backupLinked = false;
            await syncBridgeNamespace(target, backup);
            await this.updateJournal(operationId, { phase: "staged" });
          }
          if (!stillOwned(await fsp.lstat(temporary, { bigint: true }))) {
            throw new Error("PUT staging pathname changed");
          }
          // rename() unconditionally replaces an entry created by another
          // client after the earlier lstat/journal await. Since staging and
          // target share a filesystem, link() is an atomic NO-REPLACE
          // publication for regular files. The original staging link is
          // unlinked only after the destination has been exclusively won.
          await fsp.link(temporary, target);
          installedIdentity = ownedTemporary;
          installed = true;
          await fsp.unlink(temporary);
          ownedTemporary = null;
          if (!matchesIdentity(await fsp.lstat(target, { bigint: true }), installedIdentity)) {
            throw uncertainRollback("WebDAV PUT published pathname changed");
          }
          await syncBridgeNamespace(temporary, target);
          await this.updateJournal(operationId, { phase: "source-moved",
            installedIdentity: durableEntryIdentity(await fsp.lstat(target, { bigint: true })) });
          protocolQueued = await this.enqueueProtocol(operation);
          if (protocolQueued) await this.updateJournal(operationId, { phase: "protocol-queued" });
          try { await this.markJournalSeen(operationId); } catch (error) { if (!protocolQueued) throw error; }
        } catch (error) {
          // A failed O_EXCL open or replaced pathname is not ours to remove.
          // Check the opened inode, not merely the predictable temporary name.
          if (ownedTemporary) {
            try {
              if (stillOwned(await fsp.lstat(temporary, { bigint: true }))) {
                await fsp.unlink(temporary);
              }
            } catch (_) { /* missing or inaccessible: never delete an unverified name */ }
          }
          if (error.protocolQueueUncertain) {
            // rename() may have made outbox bytes visible, but the directory
            // fsync FAILED: those bytes are not proven power-loss durable.
            // Preserve the completed physical mutation and its prepared
            // journal for recovery; never report HTTP success without ACK.
            return writeResponse(res, 503, "WebDAV protocol durability unverified; recovery required");
          }
          if (protocolQueued) return writeResponse(res, existing ? 204 : 201);
          if (backupLinked) {
            const original = await localEntryOrNull(target);
            const duplicate = await localEntryOrNull(backup);
            if (!sameLocalEntry(original, existing) || !sameLocalEntry(duplicate, existing)) {
              throw uncertainRollback("WebDAV PUT backup link partially staged; manual recovery required");
            }
            await fsp.unlink(backup);
          }
          if (installed) {
            // NEVER unlink an unverified post-install pathname. An adversary
            // can replace the entry between rename() and a failed journal
            // update; recursive rm would delete unrelated files or folders.
            let named;
            try { named = await fsp.lstat(target, { bigint: true }); }
            catch (_) { /* Missing/replaced target is not safe to remove. */ }
            if (!named || !matchesIdentity(named, installedIdentity)) {
              // Keep the original in trash for manual recovery. Restoring it
              // by rename would itself overwrite the foreign replacement.
              throw Object.assign(new Error("WebDAV PUT target changed before rollback"),
                { code: "unsafe_path" });
            }
            await fsp.unlink(target);
          }
          if (staged) {
            if (!sameLocalEntry(await localEntryOrNull(backup), existing)) {
              throw uncertainRollback("WebDAV PUT original backup changed before restoration");
            }
            // Atomic exclusive restoration, never rename over a reoccupied
            // target after a stale lstat. Restrict restoration to files.
            await fsp.link(backup, target);
            await fsp.unlink(backup);
          }
          // The failed HTTP mutation has been wholly aborted or its original
          // inode restored. Retaining `prepared` would turn an ordinary
          // concurrent EEXIST into an unrecoverable startup false positive.
          await syncBridgeNamespace(temporary, target, backup);
          await this.markJournalSeen(operationId);
          throw error;
        }
        return writeResponse(res, existing ? 204 : 201);
        });
      }
      if (req.method === "MKCOL") {
        if (this.requireSignedProtocolIngress) {
          // An unsigned MKCOL has no protocol journal translation. Refuse to
          // mutate a protected tree without a signed directory grant.
          return writeResponse(res, 503, "Protected WebDAV collection authorization unavailable");
        }
        return await this.withLocalMutationLock(async () => {
        if (target === this.rootDir) return writeResponse(res, 405, "Already exists");
        // MKCOL must never inherit a permissive process umask (including
        // umask 000): otherwise another local UID can write under this
        // authenticated WebDAV collection without presenting the bearer.
        await fsp.mkdir(target, { recursive: false, mode: 0o700 });
        await rejectSymlinks(this.rootDir, target, false);
        if (process.platform !== "win32") {
          assertPosixTrustedBridgePath(this.rootDir, target, false);
          const created = await fsp.lstat(target, { bigint: true });
          if (!created.isDirectory() || created.isSymbolicLink()
            || created.uid !== BigInt(process.getuid())
            || (created.mode & 0o777n) !== 0o700n) {
            throw Object.assign(new Error("Untrusted POSIX MKCOL owner or mode"), { statusCode: 503 });
          }
        }
        return writeResponse(res, 201);
        });
      }
      if (req.method === "MOVE") return await this.move(req, res, target, parsed);
      if (req.method === "DELETE") return await this.remove(req, res, target, parsed);
      return writeResponse(res, 405, "Method not allowed");
    } catch (error) {
      const status = error.statusCode || (error.code === "ENOENT" ? 404 : error.code === "EEXIST" ? 405 : 500);
      return writeResponse(res, status, status === 500 ? "Bridge operation failed" : error.message);
    } finally {
      if (mutation) this.inflightMutations--;
    }
  }

  async destination(req) {
    const value = String(req.headers.destination || "");
    if (!value) throw Object.assign(new Error("Destination required"), { statusCode: 400 });
    // The WHATWG URL parser removes literal and percent-encoded dot segments.
    // Validate the Destination header's ORIGINAL path just as we validate the
    // request target: otherwise a syntactically forbidden traversal could be
    // transformed into a permitted path before the WebDAV admission check.
    const rawPathAndQuery = value.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/, "");
    const rawPath = rawPathAndQuery.split(/[?#]/, 1)[0] || "/";
    if (!rawPath.startsWith("/")) {
      throw Object.assign(new Error("Invalid WebDAV Destination path"), { statusCode: 400 });
    }
    safeSegments(rawPath);
    const parsed = new URL(value, `http://${this.host}`);
    if (parsed.hostname !== this.host && !isLoopback(parsed.hostname)) throw Object.assign(new Error("Destination outside bridge"), { statusCode: 400 });
    return { parsed, target: await this.target(parsed.pathname) };
  }

  async move(req, res, source, parsed) {
    if (source === this.rootDir) return writeResponse(res, 400, "Cannot move root");
    const destination = await this.destination(req);
    if (process.platform !== "win32") {
      try { assertPosixTrustedBridgePath(this.rootDir, destination.target); }
      catch { return writeResponse(res, 503, "Untrusted bridge storage"); }
    }
    if (destination.target === source) return writeResponse(res, 400, "Source and destination are identical");
    let existingTarget = destination.target;
    let destinationTarget = destination.target;
    let destinationPath = destination.parsed.pathname;
    let existingStats = await fsp.lstat(destination.target, { bigint: true }).catch((error) => error.code === "ENOENT" ? null : Promise.reject(error));
    let canonicalSource = null;
    if (process.platform === "win32") {
      canonicalSource = await canonicalExistingPath(this.rootDir, source);
      const canonicalParent = await canonicalExistingPath(this.rootDir, path.dirname(destination.target));
      if (existingStats) {
        existingTarget = await canonicalExistingPath(this.rootDir, destination.target);
        if (canonicalSource.toLowerCase() === existingTarget.toLowerCase()) {
          return writeResponse(res, 400, "Source and destination are identical");
        }
        destinationTarget = existingTarget;
      } else {
        destinationTarget = path.join(canonicalParent, path.basename(destination.target));
      }
      destinationPath = encodedWebDavPath(this.rootDir, destinationTarget);
      // The Destination header can select a different directory than the
      // authenticated source; its ancestry must be independently trusted.
      try { await this.verifyWindowsItem(destinationTarget); }
      catch { return writeResponse(res, 503, "Untrusted bridge storage"); }
    }
    if (existingStats && String(req.headers.overwrite || "T").toUpperCase() !== "T") return writeResponse(res, 412, "Destination exists");
    // A two-entry DELETE+MOVE signed batch can be fsynced atomically in the
    // local outbox, but SyncEngine._pushPending currently sends each entry as
    // a separate HTTP write/remote CAS. Remote DELETE could succeed and its
    // MOVE fail (revocation, conflict, network partition), irreversibly
    // tombstoning the previous destination after an apparent WebDAV 204.
    // Refuse protected overwrites BEFORE moving either physical inode until
    // the server exposes a genuine single-transaction multi-op CAS endpoint.
    // Never claim that SyncJournal.enqueueMany is a remote atomic commit.
    if (this.requireSignedProtocolIngress && existingStats) {
      return writeResponse(res, 503, "Protected overwrite requires atomic remote DELETE+MOVE admission");
    }
    const sourceIdentity = await fsp.lstat(source, { bigint: true });
    if (existingStats && sourceIdentity.isDirectory() !== existingStats.isDirectory()) return writeResponse(res, 409, "Cannot overwrite a file with a collection or vice versa");
    // Node's rename() offers no cross-platform NOREPLACE flag. Until a native
    // atomic directory-move primitive is supplied, never risk destroying an
    // independently created directory after an asynchronous journal await.
    if (sourceIdentity.isDirectory() && this.requireSignedProtocolIngress) {
      return writeResponse(res, 503, "Atomic directory MOVE is unavailable");
    }
    if (this.requireSignedProtocolIngress && sourceIdentity.isFile()
      && sourceIdentity.size > BigInt(MAX_PROTECTED_REMOTE_SOURCE_BYTES)) {
      return writeResponse(res, 413, "Protected ciphertext exceeds bounded remote sync wire budget");
    }
    const sourceForTranslation = process.platform === "win32"
      ? encodedWebDavPath(this.rootDir, canonicalSource)
      : parsed.pathname;
    await rejectSymlinks(this.rootDir, path.dirname(destinationTarget), false);
    const operationId = crypto.randomUUID();
    const backup = existingStats ? path.join(this.trashDir, `.rootark-move-${operationId}-${path.basename(destinationTarget)}`) : null;
    const operation = {
      operationId,
      kind: "move",
      journalType: "webdav-mutation",
      source: sourceForTranslation,
      destination: destinationPath,
      trash: backup ? path.relative(this.rootDir, backup) : null,
      sourceIdentity: durableEntryIdentity(sourceIdentity),
      previousDestinationIdentity: existingStats ? durableEntryIdentity(existingStats) : null,
      phase: "prepared",
    };
    if (this.onOperation) await this.onOperation(operation);
    return this.withLocalMutationLock(async () => {
    const previousDestinationIdentity = existingStats
      ? existingStats : null;
    let staged = false;
    let backupLinked = false;
    let moved = false;
    let publishedLinked = false;
    let protocolQueued = false;
    const directoryMove = sourceIdentity.isDirectory();
    try {
      if (backup) {
        await rejectSymlinks(this.rootDir, backup, true);
        if (!sameExclusiveSourceEntry(await localEntryOrNull(existingTarget), previousDestinationIdentity)) {
          throw uncertainRollback("WebDAV MOVE destination changed before backup");
        }
        if (directoryMove) {
          // Legacy compatibility only: collection renames are serialized
          // within this trusted-owner bridge. Protected mode never reaches
          // this path without signed subtree/atomic-move authorization.
          await fsp.rename(existingTarget, backup);
        } else {
          await fsp.link(existingTarget, backup);
          backupLinked = true;
          await fsp.unlink(existingTarget);
        }
        staged = true;
        backupLinked = false;
        await syncBridgeNamespace(existingTarget, backup);
        await this.updateJournal(operationId, { phase: "staged" });
      }
      if (!sameExclusiveSourceEntry(await localEntryOrNull(source), sourceIdentity)) {
        throw uncertainRollback("WebDAV MOVE source changed before publication");
      }
      if (directoryMove && await localEntryOrNull(destinationTarget)) {
        // Directory rename replaces an empty existing directory on POSIX.
        // Initial Overwrite:F/ENOENT detection happens before onOperation;
        // revalidate UNDER the local mutation lock before legacy rename.
        throw uncertainRollback("WebDAV directory MOVE destination was reoccupied");
      }
      // Exclusive hard-link publication never clobbers a destination created
      // during the journal await, including with Overwrite:F. Files only.
      if (directoryMove) {
        await fsp.rename(source, destinationTarget);
      } else {
        await fsp.link(source, destinationTarget);
        publishedLinked = true;
        if (!sameLocalEntry(await localEntryOrNull(destinationTarget), sourceIdentity)) {
          throw uncertainRollback("WebDAV MOVE published unexpected inode");
        }
        await fsp.unlink(source);
      }
      moved = true;
      await syncBridgeNamespace(source, destinationTarget);
      await this.updateJournal(operationId, { phase: "source-moved" });
      protocolQueued = await this.enqueueProtocol(operation);
      if (protocolQueued) await this.updateJournal(operationId, { phase: "protocol-queued" });
      try { await this.markJournalSeen(operationId); } catch (error) { if (!protocolQueued) throw error; }
    } catch (error) {
      if (error.protocolQueueUncertain) {
        return writeResponse(res, 503, "WebDAV protocol durability unverified; recovery required");
      }
      if (protocolQueued) return writeResponse(res, existingStats ? 204 : 201);
      if (backupLinked) {
        const original = await localEntryOrNull(existingTarget);
        const duplicate = await localEntryOrNull(backup);
        if (!sameLocalEntry(original, previousDestinationIdentity)
          || !sameLocalEntry(duplicate, previousDestinationIdentity)) {
          throw uncertainRollback("WebDAV MOVE backup link partially staged; manual recovery required");
        }
        await fsp.unlink(backup);
      }
      if (publishedLinked && !moved) {
        // A failed unlink may leave two names for the same inode. Never
        // rename an unverified entry or discard the staged original.
        throw uncertainRollback("WebDAV MOVE linked publication needs manual recovery");
      }
      if (moved) {
        const installed = await localEntryOrNull(destinationTarget);
        const reoccupiedSource = await localEntryOrNull(source);
        if (!sameLocalEntry(installed, sourceIdentity) || reoccupiedSource) {
          // An adversary or racing client replaced an entry after MOVE.
          // Preserve backup and both foreign paths for manual recovery.
          throw uncertainRollback("WebDAV MOVE cannot restore replaced source/destination");
        }
        // Source recreation must be exclusive. A racing client that inserts
        // the old source pathname receives priority instead of being erased.
        if (directoryMove) await fsp.rename(destinationTarget, source);
        else {
          await fsp.link(destinationTarget, source);
          await fsp.unlink(destinationTarget);
        }
      }
      if (staged) {
        const oldBackup = await localEntryOrNull(backup);
        const occupied = await localEntryOrNull(existingTarget);
        if (!sameLocalEntry(oldBackup, previousDestinationIdentity) || occupied) {
          throw uncertainRollback("WebDAV MOVE cannot restore replaced backup/destination");
        }
        if (directoryMove) await fsp.rename(backup, existingTarget);
        else {
          await fsp.link(backup, existingTarget);
          await fsp.unlink(backup);
        }
      }
      await syncBridgeNamespace(source, destinationTarget, backup, existingTarget);
      await this.markJournalSeen(operationId);
      throw error;
    }
    return writeResponse(res, existingStats ? 204 : 201);
    });
  }

  async remove(req, res, target, parsed) {
    if (target === this.rootDir) return writeResponse(res, 400, "Cannot delete root");
    const stats = await fsp.lstat(target, { bigint: true });
    if (stats.isSymbolicLink()) return writeResponse(res, 400, "Symlink paths are not supported");
    // A directory delete moves the entire subtree. A single signed file
    // tombstone is not authorization for unenumerated descendant bytes.
    if (stats.isDirectory() && this.requireSignedProtocolIngress) return writeResponse(res, 503,
      "Atomic authorized directory DELETE is unavailable");
    await fsp.mkdir(this.trashDir, { recursive: true });
    const trashTarget = path.join(this.trashDir, `${Date.now()}-${crypto.randomUUID()}-${path.basename(target)}`);
    await rejectSymlinks(this.rootDir, trashTarget, true);
    const sourcePath = process.platform === "win32" ? encodedWebDavPath(this.rootDir, target) : parsed.pathname;
    const operation = { operationId: crypto.randomUUID(), kind: "delete", journalType: "webdav-mutation", source: sourcePath, trash: path.relative(this.rootDir, trashTarget),
      sourceIdentity: durableEntryIdentity(stats), phase: "prepared" };
    if (this.onOperation) await this.onOperation(operation);
    return this.withLocalMutationLock(async () => {
    const sourceIdentity = await fsp.lstat(target, { bigint: true });
    if (!sameExclusiveSourceEntry(sourceIdentity, stats)) {
      await this.markJournalSeen(operation.operationId);
      throw uncertainRollback("WebDAV DELETE source changed during journal admission");
    }
    const directoryDelete = sourceIdentity.isDirectory();
    let trashLinked = false;
    try {
      if (directoryDelete) {
        await fsp.rename(target, trashTarget);
      } else {
        await fsp.link(target, trashTarget);
        trashLinked = true;
        if (!sameLocalEntry(await localEntryOrNull(trashTarget), sourceIdentity)
          || !sameLocalEntry(await localEntryOrNull(target), sourceIdentity)) {
          throw uncertainRollback("WebDAV DELETE staging source changed identity");
        }
        await fsp.unlink(target);
        trashLinked = false;
      }
    } catch (error) {
      if (trashLinked) {
        const original = await localEntryOrNull(target);
        const duplicate = await localEntryOrNull(trashTarget);
        if (!sameLocalEntry(original, sourceIdentity)
          || !sameLocalEntry(duplicate, sourceIdentity)) {
          throw uncertainRollback("WebDAV DELETE has an uncertain partial trash link");
        }
        await fsp.unlink(trashTarget);
      }
      await syncBridgeNamespace(target, trashTarget);
      await this.markJournalSeen(operation.operationId);
      throw error;
    }
    let protocolQueued = false;
    try {
      await syncBridgeNamespace(target, trashTarget);
      await this.updateJournal(operation.operationId, { phase: "source-moved" });
      protocolQueued = await this.enqueueProtocol(operation);
      if (protocolQueued) await this.updateJournal(operation.operationId, { phase: "protocol-queued" });
      try { await this.markJournalSeen(operation.operationId); } catch (error) { if (!protocolQueued) throw error; }
    } catch (error) {
      if (error.protocolQueueUncertain) {
        return writeResponse(res, 503, "WebDAV protocol durability unverified; recovery required");
      }
      if (protocolQueued) return writeResponse(res, 204);
      const originalInTrash = await localEntryOrNull(trashTarget);
      const replacedTarget = await localEntryOrNull(target);
      if (!sameLocalEntry(originalInTrash, sourceIdentity) || replacedTarget) {
        throw uncertainRollback("WebDAV DELETE cannot restore replaced trash/target");
      }
      if (directoryDelete) await fsp.rename(trashTarget, target);
      else {
        await fsp.link(trashTarget, target);
        await fsp.unlink(trashTarget);
      }
      await syncBridgeNamespace(target, trashTarget);
      await this.markJournalSeen(operation.operationId);
      throw error;
    }
    return writeResponse(res, 204);
    });
  }
}

module.exports = { LocalSyncWebDavBridge, isLoopback, rejectSymlinks, safeSegments };
