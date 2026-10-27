"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

test("CAS anchor refuses a foreign-owned 0755 ancestor on restart before any journal IO", {
  skip: process.platform === "win32",
}, (t) => {
  const root = createPrivateAuthorityFixture("rootark-cas-foreign-owner-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const ancestor = path.join(root, "operator-parent");
  const owned = path.join(ancestor, "private-anchor");
  fs.mkdirSync(owned, { recursive: true, mode: 0o700 });
  fs.chmodSync(ancestor, 0o755);
  const filename = path.join(owned, "anchor.log");
  const options = { statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey };
  new Zk1CasTerminalAnchor(filename, { ...options, bootstrapNew: true });
  assert.equal(new Zk1CasTerminalAnchor(filename, {
    ...options, bootstrapNew: false }).sequence, 0,
  "private owner-controlled 0755 ancestors remain valid");
  const initial = fs.readFileSync(filename);
  const initialNames = fs.readdirSync(owned);
  const nativeLstat = fs.lstatSync;
  let observed = false;
  try {
    // Simulate the same host-observed stat as a foreign UID 0755 parent.
    // The parent owner can rename its 0700 child without entering that child.
    fs.lstatSync = function (target, ...args) {
      const stat = nativeLstat.call(this, target, ...args);
      if (String(target) === ancestor && args[0]?.bigint === true) {
        observed = true;
        return Object.assign(Object.create(stat), {
          uid: BigInt(process.getuid()) + 100000n,
        });
      }
      return stat;
    };
    assert.throws(() => new Zk1CasTerminalAnchor(filename, {
      ...options, bootstrapNew: false }), /CAS_ANCHOR_INVALID/,
    "an existing signed journal must not excuse a foreign-controlled ancestor");
  } finally { fs.lstatSync = nativeLstat; }
  assert.equal(observed, true, "the attempted restart inspected the foreign ancestor");
  assert.deepEqual(fs.readFileSync(filename), initial,
    "rejection neither truncates nor rewrites a signed journal");
  assert.deepEqual(fs.readdirSync(owned), initialNames,
    "rejection cannot leave a lock or a new file in the foreign path");
  assert.equal(new Zk1CasTerminalAnchor(filename, {
    ...options, bootstrapNew: false }).sequence, 0,
  "the original trusted journal remains usable after denial");
  fs.chmodSync(ancestor, 0o1777);
  assert.equal(new Zk1CasTerminalAnchor(filename, {
    ...options, bootstrapNew: false }).sequence, 0,
  "a sticky writable ancestor owned by the service retains its existing exception");
  try {
    fs.lstatSync = function (target, ...args) {
      const stat = nativeLstat.call(this, target, ...args);
      return String(target) === ancestor && args[0]?.bigint === true
        ? Object.assign(Object.create(stat), { uid: 0n }) : stat;
    };
    assert.equal(new Zk1CasTerminalAnchor(filename, {
      ...options, bootstrapNew: false }).sequence, 0,
    "root-owned sticky directories retain the existing exception");
  } finally { fs.lstatSync = nativeLstat; }
});

test("CAS signed anchor reload cannot allocate inode bytes appended after pinned fstat", (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-anchor-growth-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const filename = path.join(dir, "anchor.log");
  const anchor = new Zk1CasTerminalAnchor(filename, {
    bootstrapNew: true, statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
  });
  const realOpen = fs.openSync;
  const realFstat = fs.fstatSync;
  const realReadFile = fs.readFileSync;
  let selectedFd;
  let attacked = false;
  const readLengths = [];
  fs.openSync = function (name, ...args) {
    const fd = realOpen.call(fs, name, ...args);
    if (name === filename && selectedFd === undefined) selectedFd = fd;
    return fd;
  };
  fs.fstatSync = function (fd, ...args) {
    const opened = realFstat.call(fs, fd, ...args);
    if (fd === selectedFd && !attacked) {
      attacked = true;
      fs.truncateSync(filename, Number(opened.size) + 65 * 1024 * 1024);
    }
    return opened;
  };
  fs.readFileSync = function (source, ...args) {
    const bytes = realReadFile.call(fs, source, ...args);
    if (typeof source === "number") readLengths.push(bytes.length);
    return bytes;
  };
  try {
    assert.throws(() => anchor.reload(true), /CAS_ANCHOR_INVALID/);
  } finally {
    fs.openSync = realOpen;
    fs.fstatSync = realFstat;
    fs.readFileSync = realReadFile;
  }
  assert.equal(attacked, true, "race the signed anchor after validated descriptor fstat");
  assert.deepEqual(readLengths, [], "CAS authority must not allocate more than the pinned 64 MiB cap");
});

test("two CAS handles cannot append a duplicate sequence or permanently corrupt continuity on restart", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-anchor-lock-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const file = path.join(dir, "anchor.log");
  const statusPrivateKey = crypto.generateKeyPairSync("ed25519").privateKey;
  const statusKeyId = crypto.randomBytes(16);
  const first = new Zk1CasTerminalAnchor(file, {
    statusPrivateKey, statusKeyId, bootstrapNew: true,
  });
  const second = new Zk1CasTerminalAnchor(file, {
    statusPrivateKey, statusKeyId, bootstrapNew: false,
  });
  const scope = {
    account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16),
  };
  const q1 = { ...scope, reservation_id: crypto.randomBytes(16) };
  const q2 = { ...scope, reservation_id: crypto.randomBytes(16) };
  const firstSeal = crypto.randomBytes(64);
  const secondSeal = crypto.randomBytes(64);
  const receipt1 = crypto.randomBytes(100);
  const receipt2 = crypto.randomBytes(100);
  const manifest1 = crypto.randomBytes(200);
  first.prepare(q1, receipt1, "committed", manifest1);
  await first.append(q1, receipt1, "committed", manifest1, firstSeal);
  second.prepare(q2, receipt2, "not-committed-final", null);
  await second.append(q2, receipt2, "not-committed-final", null, secondSeal);
  const reopened = new Zk1CasTerminalAnchor(file, {
    statusPrivateKey, statusKeyId, bootstrapNew: false,
  });
  assert.equal(reopened.sequence, 2);
  assert.ok(reopened.get(q1.reservation_id));
  assert.ok(reopened.get(q2.reservation_id));
  assert.ok(first.get(q2.reservation_id), "stale reader refreshes from signed disk journal");
  assert.equal(first.sequence, 2, "a stale first handle must refresh its durable head");
});

test("CAS append cannot unlink another writer's replacement lock during release", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-lock-replaced-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const filename = path.join(dir, "anchor.log");
  const lockPath = filename + ".append.lock";
  const displaced = path.join(dir, "displaced-owned-lock");
  const anchor = new Zk1CasTerminalAnchor(filename, {
    bootstrapNew: true, statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
  });
  const query = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("main"), keyring_id: crypto.randomBytes(16),
    reservation_id: crypto.randomBytes(16) };
  const ticket = crypto.randomBytes(64);
  const manifest = crypto.randomBytes(64);
  anchor.prepare(query, ticket, "committed", manifest);
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  let ownedLockFd;
  let replaced = false;
  try {
    fs.openSync = function (pathname, flags) {
      const fd = originalOpen.apply(this, arguments);
      if (pathname === lockPath && flags === "wx") ownedLockFd = fd;
      return fd;
    };
    fs.closeSync = function (fd) {
      const result = originalClose.apply(this, arguments);
      if (fd === ownedLockFd && !replaced) {
        replaced = true;
        fs.renameSync(lockPath, displaced);
        fs.writeFileSync(lockPath, "another writer owns this lock", { flag: "wx", mode: 0o600 });
      }
      return result;
    };
    await assert.rejects(anchor.append(query, ticket, "committed", manifest,
      crypto.randomBytes(64)), /CAS_ANCHOR_INVALID/,
    "a replaced lock must abort release rather than removing another writer's exclusive lock");
  } finally {
    fs.openSync = originalOpen;
    fs.closeSync = originalClose;
  }
  assert.equal(replaced, true);
  assert.equal(fs.readFileSync(lockPath, "utf8"), "another writer owns this lock",
    "a competing writer's lock must remain intact after our release fails");
});

test("incomplete staging file from a crashed intent writer is not an authoritative intent", (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-intent-stage-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const pathname = path.join(dir, "anchor.log");
  const statusPrivateKey = crypto.generateKeyPairSync("ed25519").privateKey;
  const statusKeyId = crypto.randomBytes(16);
  const first = new Zk1CasTerminalAnchor(pathname, {
    bootstrapNew: true, statusPrivateKey, statusKeyId,
  });
  const query = {
    account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16), reservation_id: crypto.randomBytes(16),
  };
  const staged = first.intentPath(query) + ".stage-crashed-writer";
  fs.writeFileSync(staged, "{uncommitted", { mode: 0o600 });
  const receipt = crypto.randomBytes(100);
  const manifest = crypto.randomBytes(100);
  assert.equal(first.getIntent(query), null);
  assert.equal(first.prepare(query, receipt, "committed", manifest), true);
  assert.ok(first.getIntent(query), "only a complete signed intent becomes authoritative");
  const restarted = new Zk1CasTerminalAnchor(pathname, {
    bootstrapNew: false, statusPrivateKey, statusKeyId,
  });
  assert.equal(restarted.assertIntent(query, receipt, "committed", manifest), true);
});

test("trusted externally retained CAS anchor floor refuses signed rollback and valid signer fork", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-floor-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const filename = path.join(dir, "anchor.log");
  const statusPrivateKey = crypto.generateKeyPairSync("ed25519").privateKey;
  const statusKeyId = crypto.randomBytes(16);
  const opts = { statusPrivateKey, statusKeyId };
  const original = new Zk1CasTerminalAnchor(filename, { ...opts, bootstrapNew: true });
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("main"), keyring_id: crypto.randomBytes(16) };
  const terminal = async (anchor, reservation_id) => {
    const query = { ...scope, reservation_id };
    const ticket = crypto.randomBytes(80);
    const manifest = crypto.randomBytes(64);
    const seal = crypto.randomBytes(64);
    anchor.prepare(query, ticket, "committed", manifest);
    await anchor.append(query, ticket, "committed", manifest, seal);
    return query;
  };
  await terminal(original, crypto.randomBytes(16));
  const firstSnapshot = fs.readFileSync(filename);
  const altFile = path.join(dir, "alternate.log");
  fs.copyFileSync(filename, altFile);
  await terminal(original, crypto.randomBytes(16));
  const realHead = original.headCheckpoint();
  assert.equal(realHead.sequence, 2);
  assert.match(realHead.lastHash, /^[0-9a-f]{64}$/);
  const externallyKept = { ...realHead };
  const trusted = new Zk1CasTerminalAnchor(filename, {
    ...opts, bootstrapNew: false, trustedMinimumHead: externallyKept,
  });
  assert.equal(trusted.headCheckpoint().lastHash, realHead.lastHash);
  externallyKept.sequence = 0;
  externallyKept.lastHash = "0".repeat(64);
  const latest = fs.readFileSync(filename);
  fs.writeFileSync(filename, firstSnapshot);
  assert.throws(() => trusted.hasScope(scope), /CAS_ANCHOR_INVALID/,
    "a valid earlier signed prefix must not become trusted by mutating the caller's floor");
  assert.throws(() => new Zk1CasTerminalAnchor(filename, {
    ...opts, bootstrapNew: false, trustedMinimumHead: realHead,
  }), /CAS_ANCHOR_INVALID/);
  fs.writeFileSync(filename, latest);
  assert.equal(trusted.headCheckpoint().lastHash, realHead.lastHash);
  const alternate = new Zk1CasTerminalAnchor(altFile, {
    ...opts, bootstrapNew: false,
  });
  await terminal(alternate, crypto.randomBytes(16));
  assert.equal(fs.statSync(altFile).size, latest.length,
    "both valid forks use exactly the same fixed-length wire structure");
  assert.notEqual(alternate.headCheckpoint().lastHash, realHead.lastHash);
  fs.copyFileSync(altFile, filename);
  assert.throws(() => trusted.get(crypto.randomBytes(16)), /CAS_ANCHOR_INVALID/,
    "a different Ed25519-signed fork at the same sequence cannot replace the pinned head");
  assert.throws(() => trusted.headCheckpoint(), /CAS_ANCHOR_INVALID/);
});

test("cached CAS lookup rechecks signatures when equal size and timestamp conceal in-place tampering", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-tamper-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const filename = path.join(dir, "anchor.log");
  const privateKey = crypto.generateKeyPairSync("ed25519").privateKey;
  const anchor = new Zk1CasTerminalAnchor(filename, { bootstrapNew: true,
    statusKeyId: crypto.randomBytes(16), statusPrivateKey: privateKey });
  const q = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16), reservation_id: crypto.randomBytes(16) };
  const ticket = crypto.randomBytes(64);
  const manifest = crypto.randomBytes(64);
  const seal = crypto.randomBytes(64);
  anchor.prepare(q, ticket, "committed", manifest);
  await anchor.append(q, ticket, "committed", manifest, seal);
  assert.ok(anchor.get(q.reservation_id));
  const stat = fs.statSync(filename);
  const original = fs.readFileSync(filename, "utf8");
  const lines = original.trimEnd().split("\n");
  const event = JSON.parse(lines[1]);
  event.signature = (event.signature[0] === "A" ? "B" : "A") + event.signature.slice(1);
  lines[1] = JSON.stringify(event);
  fs.writeFileSync(filename, lines.join("\n") + "\n");
  assert.equal(fs.statSync(filename).size, stat.size);
  const nativeStat = fs.statSync;
  try {
    fs.statSync = (target, ...args) => {
      const result = nativeStat(target, ...args);
      return path.resolve(String(target)) === filename
        ? { ...result, mtimeMs: stat.mtimeMs } : result;
    };
    assert.throws(() => anchor.get(q.reservation_id), /CAS_ANCHOR_INVALID/,
      "metadata-only cache must never mask a modified signed receipt");
    assert.throws(() => anchor.hasScope(q), /CAS_ANCHOR_INVALID/);
  } finally { fs.statSync = nativeStat; }
});

test("CAS reload refuses a signed old prefix substituted during FD read of a pinned head", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-fd-swap-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const filename = path.join(dir, "anchor.log");
  const privateKey = crypto.generateKeyPairSync("ed25519").privateKey;
  const opts = { statusKeyId: crypto.randomBytes(16), statusPrivateKey: privateKey };
  const first = new Zk1CasTerminalAnchor(filename, { ...opts, bootstrapNew: true });
  const scope = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16) };
  const append = async () => {
    const query = { ...scope, reservation_id: crypto.randomBytes(16) };
    const ticket = crypto.randomBytes(64);
    const manifest = crypto.randomBytes(64);
    first.prepare(query, ticket, "committed", manifest);
    await first.append(query, ticket, "committed", manifest, crypto.randomBytes(64));
    return query;
  };
  await append();
  const oldSigned = fs.readFileSync(filename);
  const newQuery = await append();
  const floor = first.headCheckpoint();
  const trusted = new Zk1CasTerminalAnchor(filename, { ...opts,
    bootstrapNew: false, trustedMinimumHead: floor });
  const originalRead = fs.readSync;
  let attacked = false;
  try {
    fs.readSync = function (fd) {
      const count = originalRead.apply(this, arguments);
      if (!attacked && typeof fd === "number") {
        attacked = true;
        fs.writeFileSync(filename, oldSigned);
      }
      return count;
    };
    assert.throws(() => trusted.get(newQuery.reservation_id), /CAS_ANCHOR_INVALID/,
      "signed new bytes do not prove the live disk file still has the pinned history");
  } finally { fs.readSync = originalRead; }
  assert.equal(attacked, true);
  assert.throws(() => trusted.headCheckpoint(), /CAS_ANCHOR_INVALID/);
});

test("CAS append cannot write into a path replaced after its signed reload", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-append-swap-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const filename = path.join(dir, "anchor.log");
  const detached = path.join(dir, "detached-anchor.log");
  const anchor = new Zk1CasTerminalAnchor(filename, { bootstrapNew: true,
    statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey });
  const q = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16), reservation_id: crypto.randomBytes(16) };
  const ticket = crypto.randomBytes(64);
  const manifest = crypto.randomBytes(64);
  const seal = crypto.randomBytes(64);
  anchor.prepare(q, ticket, "committed", manifest);
  const nativeOpen = fs.openSync;
  let swapped = false;
  try {
    fs.openSync = function (name, flags) {
      if (name === filename && !swapped && (flags === "a"
        || (typeof flags === "number" && (flags & fs.constants.O_APPEND)))) {
        swapped = true;
        fs.renameSync(filename, detached);
        fs.copyFileSync(detached, filename);
      }
      return nativeOpen.apply(this, arguments);
    };
    await assert.rejects(anchor.append(q, ticket, "committed", manifest, seal),
      /CAS_ANCHOR_INVALID/,
      "same signed prefix on different inode is not the verified append target");
  } finally { fs.openSync = nativeOpen; }
  assert.equal(swapped, true);
  const actual = fs.readFileSync(filename).toString("utf8");
  assert.equal(actual.trimEnd().split("\n").length, 1,
    "substituted anchor did not receive a forged successful terminal append");
});

test("cached CAS reads hash current FD bytes but do not redo signature verification for identical content", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-cas-cache-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const filename = path.join(dir, "anchor.log");
  const anchor = new Zk1CasTerminalAnchor(filename, { bootstrapNew: true,
    statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey });
  const q = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16), reservation_id: crypto.randomBytes(16) };
  const ticket = crypto.randomBytes(64);
  const manifest = crypto.randomBytes(64);
  anchor.prepare(q, ticket, "committed", manifest);
  await anchor.append(q, ticket, "committed", manifest, crypto.randomBytes(64));
  const nativeVerify = crypto.verify;
  let validations = 0;
  try {
    crypto.verify = function () {
      validations++;
      return nativeVerify.apply(this, arguments);
    };
    for (let i = 0; i < 25; ++i) assert.equal(anchor.get(q.reservation_id).status, "committed");
    assert.equal(validations, 0,
      "a previously verified byte-identical private snapshot does not rescan every Ed25519 signature per GET");
    // A tampered in-place record MUST miss the digest cache even if the
    // attacker preserves size, external timestamps and the public records.
    const bytes = fs.readFileSync(filename, "utf8");
    const lines = bytes.trimEnd().split("\n");
    const item = JSON.parse(lines[1]);
    item.signature = (item.signature[0] === "A" ? "B" : "A") + item.signature.slice(1);
    lines[1] = JSON.stringify(item);
    fs.writeFileSync(filename, lines.join("\n") + "\n");
    assert.throws(() => anchor.get(q.reservation_id), /CAS_ANCHOR_INVALID/);
    assert.ok(validations > 0, "any byte change forces a fresh signed cryptographic check");
  } finally { crypto.verify = nativeVerify; }
});
