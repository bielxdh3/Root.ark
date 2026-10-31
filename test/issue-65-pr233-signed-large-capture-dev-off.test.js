"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { verifyDevOffSignedLargeCapture } =
  require("../src/services/zk1DevOffSignedLargeCloudCapture");
const FIELDS = ["format", "account_id", "object_id", "revision", "epoch",
  "operation_id", "ciphertext_sha256", "byte_length", "owner_head_revision",
  "owner_head_digest", "owner_head_epoch", "provider", "namespace_sha256",
  "principal_context_sha256", "provider_object_key", "provider_file_id",
  "issued_at", "expires_at"];
const DOMAIN = Buffer.from("Root.ark/zk-1/dev-off-signed-large-capture/v1\0");
const sha = (data) => crypto.createHash("sha256").update(data).digest("hex");

function fixture(t, bytes = Buffer.from("AAAA-signed-original")) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-signed-large-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
  const sourcePath = path.join(directory, "ciphertext.ct");
  fs.writeFileSync(sourcePath, bytes, { flag: "wx", mode: 0o600 });
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const issued = Math.floor(Date.now() / 1000) - 1;
  const claim = {
    format: "rootark-zk1-dev-off-signed-large-capture/v1",
    account_id: "a".repeat(32), object_id: "b".repeat(32),
    revision: 2, epoch: 3, operation_id: crypto.randomBytes(16).toString("hex"),
    ciphertext_sha256: sha(bytes), byte_length: bytes.length,
    owner_head_revision: 7, owner_head_digest: "d".repeat(64),
    owner_head_epoch: 3, provider: "gdrive",
    namespace_sha256: "e".repeat(64), principal_context_sha256: "f".repeat(64),
    provider_object_key: "rootark/uploads/folder/ciphertext.ct",
    provider_file_id: "pinnedFileId", issued_at: issued, expires_at: issued + 30,
  };
  const sign = (fields, key = privateKey) => {
    const canonical = Object.fromEntries(FIELDS.map((field) => [field, fields[field]]));
    const bytes = Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(canonical))]);
    return { ...fields, signature: crypto.sign(null, bytes, key).toString("base64url") };
  };
  const signedClaim = sign(claim);
  const expected = Object.fromEntries(FIELDS.filter((field) =>
    !["format", "ciphertext_sha256", "byte_length", "issued_at", "expires_at"].includes(field))
    .map((field) => [field, claim[field]]));
  const run = (extra = {}) => verifyDevOffSignedLargeCapture({
    sourcePath, signedClaim, pinnedOwnerPublicKey: publicKey, expected,
    ...extra,
  });
  return { sourcePath, claim, signedClaim, expected, publicKey, privateKey,
    sign, run };
}

test("DEV-OFF captures >16MiB signed original with bounded memory, authenticates encrypted spool, NEVER authorizes cloud PUT", async (t) => {
  const original = Buffer.alloc(16 * 1024 * 1024 + 4097, 0x41);
  const f = fixture(t, original);
  const result = await f.run();
  assert.equal(result.byteLength, original.length);
  assert.equal(result.sha256, sha(original));
  assert.equal(result.signedPreimageMatched, true);
  assert.equal(result.encryptedSpoolRereadMatched, true);
  assert.equal(result.authorizesCloudUpload, false);
  assert.equal(result.externalOwnerCustodyVerified, false);
  assert.equal(result.providerVersionedReadbackVerified, false);
  assert.equal(result.ioChunkBytes <= 65536, true);
});

test("actual held writable FD A→B→A mutation during pinned capture cannot fake a signed original", async (t) => {
  const original = Buffer.alloc(128 * 1024, 0x41);
  const injected = Buffer.alloc(original.length, 0x42);
  const f = fixture(t, original);
  const held = fs.openSync(f.sourcePath, "r+");
  t.after(() => fs.closeSync(held));
  const native = fs.readSync;
  let attacked = false;
  const inode = fs.statSync(f.sourcePath, { bigint: true }).ino;
  fs.readSync = function (fd, buffer, offset, length, position) {
    if (!attacked && fs.fstatSync(fd, { bigint: true }).ino === inode) {
      attacked = true;
      fs.writeSync(held, injected, 0, injected.length, 0);
      fs.fsyncSync(held);
      try { return native.call(fs, fd, buffer, offset, length, position); }
      finally {
        fs.writeSync(held, original, 0, original.length, 0);
        fs.fsyncSync(held);
      }
    }
    return native.call(fs, fd, buffer, offset, length, position);
  };
  try {
    await assert.rejects(f.run(), /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
  } finally { fs.readSync = native; }
  assert.equal(attacked, true);
  assert.deepEqual(fs.readFileSync(f.sourcePath), original);
  assert.equal(fs.statSync(f.sourcePath, { bigint: true }).ino, inode);
});

test("source swapped for a real FIFO at open is denied without blocking the server", (t) => {
  if (process.platform !== "linux") return t.skip("requires native Linux FIFO");
  const f = fixture(t);
  const fifoPath = f.sourcePath + ".fifo";
  const mkfifo = spawnSync("mkfifo", [fifoPath], { encoding: "utf8", timeout: 2000 });
  assert.equal(mkfifo.status, 0, mkfifo.stderr);
  const child = [
    'const fs = require("node:fs"); const crypto = require("node:crypto");',
    'const [sourcePath, fifo, pub, signed, expected, modulePath] = process.argv.slice(1);',
    'let swapped = false; const originalOpen = fs.openSync;',
    'fs.openSync = function (target, ...args) {',
    '  if (target === sourcePath && !swapped) {',
    '    fs.renameSync(sourcePath, sourcePath + ".original");',
    '    fs.renameSync(fifo, sourcePath); swapped = true;',
    '  }',
    '  return originalOpen.call(fs, target, ...args);',
    '};',
    'const { verifyDevOffSignedLargeCapture } = require(modulePath);',
    'verifyDevOffSignedLargeCapture({ sourcePath, signedClaim: JSON.parse(signed),',
    '  expected: JSON.parse(expected), pinnedOwnerPublicKey: crypto.createPublicKey(',
    '    Buffer.from(pub, "base64").toString("utf8")),',
    '}).then(() => { process.stderr.write("BAD_SUCCESS"); process.exitCode = 2; },',
    '  (e) => { if (swapped && e.message === "ZK_DEV_OFF_CAPTURE_UNAVAILABLE")',
    '    process.stdout.write("FIFO_REFUSED_WITHOUT_BLOCKING");',
    '    else { process.stderr.write("BAD_REFUSAL " + e); process.exitCode = 3; } });',
  ].join("\n");
  const result = spawnSync(process.execPath, ["-e", child, f.sourcePath, fifoPath,
    Buffer.from(f.publicKey.export({ type: "spki", format: "pem" })).toString("base64"),
    JSON.stringify(f.signedClaim), JSON.stringify(f.expected),
    require.resolve("../src/services/zk1DevOffSignedLargeCloudCapture")],
  { encoding: "utf8", timeout: 2500 });
  assert.equal(result.status, 0,
    "capture must not block on FIFO swap: " + result.error + " " + result.stderr);
  assert.match(result.stdout, /FIFO_REFUSED_WITHOUT_BLOCKING/);
});

test("signature, independently expected scope/object/revision, replay-floor mismatch and expiry all deny before capture", async (t) => {
  const f = fixture(t);
  const other = crypto.generateKeyPairSync("ed25519");
  const read = fs.readSync;
  let reads = 0;
  fs.readSync = function (...args) { reads++; return read.apply(fs, args); };
  try {
    await assert.rejects(f.run({ pinnedOwnerPublicKey: other.publicKey }),
      /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
    await assert.rejects(f.run({ expected: { ...f.expected, object_id: "1".repeat(32) } }),
      /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
    await assert.rejects(f.run({ expected: { ...f.expected, revision: 3 } }),
      /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
    await assert.rejects(f.run({ expected: { ...f.expected, operation_id: "2".repeat(32) } }),
      /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
    const expired = { ...f.claim, issued_at: 10, expires_at: 11 };
    await assert.rejects(f.run({ signedClaim: f.sign(expired) }),
      /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
    const accessor = { ...f.signedClaim };
    Object.defineProperty(accessor, "ciphertext_sha256", { enumerable: true,
      get: () => { throw new Error("GETTER_EXECUTED"); } });
    await assert.rejects(f.run({ signedClaim: accessor }), /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
  } finally { fs.readSync = read; }
  assert.equal(reads, 0, "invalid signed claims cannot trigger source capture");
});

test("mutated source B cannot be certified by historical signature of A even when size unchanged", async (t) => {
  const f = fixture(t);
  fs.writeFileSync(f.sourcePath, Buffer.alloc(f.claim.byte_length, 0x42));
  await assert.rejects(f.run(), /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
});

test("local operation-id replay fails closed, but does not claim an off-host durable fence", async (t) => {
  const f = fixture(t);
  const first = await f.run();
  assert.equal(first.durableReplayFenceVerified, false);
  await assert.rejects(f.run(), /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
});

test("same signed content with adversary-chosen signer does not become authorized external owner custody", async (t) => {
  const f = fixture(t);
  const attacker = crypto.generateKeyPairSync("ed25519");
  const result = await f.run({ signedClaim: f.sign(f.claim, attacker.privateKey),
    pinnedOwnerPublicKey: attacker.publicKey });
  assert.equal(result.signedPreimageMatched, true);
  assert.equal(result.externalOwnerCustodyVerified, false);
  assert.equal(result.authorizesCloudUpload, false);
});

test("post-require crypto.verify monkeypatch cannot admit a wrong-domain Ed25519 signature", async (t) => {
  const f = fixture(t);
  const forged = { ...f.signedClaim,
    signature: crypto.sign(null, Buffer.from("different-domain-without-owner-consent"),
      f.privateKey).toString("base64url") };
  assert.equal(crypto.verify(null, Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(
    Object.fromEntries(FIELDS.map((field) => [field, f.claim[field]]))))]),
  f.publicKey, Buffer.from(forged.signature, "base64url")), false);
  const nativeVerify = crypto.verify;
  let monkeypatchCalls = 0;
  crypto.verify = () => { monkeypatchCalls++; return true; };
  try {
    await assert.rejects(f.run({ signedClaim: forged }),
      /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
  } finally { crypto.verify = nativeVerify; }
  assert.equal(monkeypatchCalls, 0, "verification must not consult mutated crypto exports");
});

test("post-require crypto.createHash monkeypatch cannot disguise original-byte mismatch", async (t) => {
  const original = Buffer.alloc(128 * 1024, 0x41);
  const f = fixture(t, original);
  fs.writeFileSync(f.sourcePath, Buffer.alloc(original.length, 0x42));
  const nativeCreateHash = crypto.createHash;
  let monkeypatchCalls = 0;
  crypto.createHash = () => {
    monkeypatchCalls++;
    return { update() { return this; }, digest() { return f.claim.ciphertext_sha256; } };
  };
  try {
    await assert.rejects(f.run(), /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
  } finally { crypto.createHash = nativeCreateHash; }
  assert.equal(monkeypatchCalls, 0, "digest checks must not consult mutable crypto exports");
});

test("post-require crypto export tampering cannot authorize cloud I/O or bypass captured primitives", async (t) => {
  const names = ["randomBytes", "createCipheriv", "createDecipheriv",
    "timingSafeEqual", "KeyObject", "verify", "createHash"];
  for (const name of names) {
    await t.test(name, async (sub) => {
      const f = fixture(sub, Buffer.alloc(128 * 1024, 0x41));
      const original = crypto[name];
      let calls = 0;
      crypto[name] = () => { calls++; throw new Error("MUTATED_CRYPTO_EXPORT_" + name); };
      try {
        let result;
        try { result = await f.run(); }
        catch (error) {
          // The separate Windows ACL worker may call the shared crypto RNG;
          // denying operation entirely is safe. Never mask a different error.
          assert.match(String(error.message), /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
        }
        if (result) {
          assert.equal(result.signedPreimageMatched, true);
          assert.equal(result.encryptedSpoolRereadMatched, true);
          assert.equal(result.authorizesCloudUpload, false);
          assert.equal(calls, 0, "successful capture must use pinned crypto " + name);
        }
      } finally { crypto[name] = original; }
    });
  }
});

test("authentic encrypted stage becomes unavailable if on-disk ciphertext is corrupted after capture", async (t) => {
  const f = fixture(t, Buffer.alloc(64 * 1024 + 127, 0x41));
  const fsync = fs.fsyncSync;
  const fdPath = new Map();
  const open = fs.openSync;
  let corrupted = false;
  fs.openSync = function (pathname, ...args) {
    const fd = open.call(fs, pathname, ...args);
    if (typeof pathname === "string" && pathname.endsWith("sealed.enc"))
      fdPath.set(fd, pathname);
    return fd;
  };
  fs.fsyncSync = function (fd) {
    const ret = fsync.call(fs, fd);
    if (!corrupted && fdPath.has(fd)) {
      corrupted = true;
      fs.writeSync(fd, Buffer.from([0x7e]), 0, 1, 0);
      fsync.call(fs, fd);
    }
    return ret;
  };
  try { await assert.rejects(f.run(), /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/); }
  finally { fs.fsyncSync = fsync; fs.openSync = open; }
  assert.equal(corrupted, true);
});

test("untrusted accessor at the outer request boundary is refused before source read", async (t) => {
  const f = fixture(t);
  const options = { signedClaim: f.signedClaim, pinnedOwnerPublicKey: f.publicKey,
    expected: f.expected };
  Object.defineProperty(options, "sourcePath", { enumerable: true,
    get() { throw new Error("UNTRUSTED_PATH_GETTER"); } });
  await assert.rejects(verifyDevOffSignedLargeCapture(options),
    /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/);
});

test("native Linux other-UID retained writable FD A→B→A is denied against owner-signed original", async (t) => {
  if (process.platform !== "linux" || process.getuid?.() !== 0)
    return t.skip("requires native Linux root/runuser to open a second-UID FD");
  const original = Buffer.alloc(128 * 1024, 0x41);
  const f = fixture(t, original);
  const directory = path.dirname(f.sourcePath);
  fs.chmodSync(directory, 0o755);
  fs.chmodSync(f.sourcePath, 0o666);
  const trigger = path.join(directory, "trigger.txt");
  const status = path.join(directory, "status.txt");
  fs.writeFileSync(trigger, "idle", { flag: "wx", mode: 0o644 });
  fs.writeFileSync(status, "starting", { flag: "wx", mode: 0o666 });
  fs.chmodSync(status, 0o666);
  const childScript = String.raw`
    const fs = require("node:fs");
    const [source, trigger, status] = process.argv.slice(1);
    const fd = fs.openSync(source, "r+");
    const size = fs.statSync(source).size;
    fs.writeFileSync(status, "ready");
    let last = "";
    const poll = setInterval(() => {
      const cmd = fs.readFileSync(trigger, "utf8").trim();
      if (cmd === last) return;
      last = cmd;
      if (cmd === "mutate" || cmd === "restore") {
        const data = Buffer.alloc(size, cmd === "mutate" ? 0x42 : 0x41);
        fs.writeSync(fd, data, 0, data.length, 0);
        fs.fsyncSync(fd);
        fs.writeFileSync(status, cmd === "mutate" ? "mutated" : "restored");
      }
    }, 2);
    poll.unref?.();
    process.stdin.resume();
  `;
  const child = spawn("runuser", ["-u", "nobody", "--", process.execPath,
    "-e", childScript, f.sourcePath, trigger, status],
  { stdio: ["pipe", "ignore", "pipe"] });
  t.after(() => { child.kill(); child.stdin.destroy(); });
  const nap = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  let ready = false;
  for (let i = 0; i < 200; i += 1) {
    if (fs.readFileSync(status, "utf8") === "ready") { ready = true; break; }
    if (child.exitCode !== null) break;
    await nap(10);
  }
  assert.equal(ready, true, "unprivileged writer must obtain real FD before chmod");
  fs.chmodSync(f.sourcePath, 0o644);
  const read = fs.readSync;
  const inode = fs.statSync(f.sourcePath, { bigint: true }).ino;
  let attacked = false;
  const waitStatus = (expect) => {
    const atom = new Int32Array(new SharedArrayBuffer(4));
    for (let i = 0; i < 400; i += 1) {
      if (fs.readFileSync(status, "utf8") === expect) return;
      Atomics.wait(atom, 0, 0, 10);
    }
    throw new Error("foreign-UID writer did not acknowledge " + expect);
  };
  fs.readSync = function (fd, ...args) {
    if (!attacked && fs.fstatSync(fd, { bigint: true }).ino === inode) {
      attacked = true;
      fs.writeFileSync(trigger, "mutate");
      waitStatus("mutated");
      try { return read.call(fs, fd, ...args); }
      finally {
        fs.writeFileSync(trigger, "restore");
        waitStatus("restored");
      }
    }
    return read.call(fs, fd, ...args);
  };
  try { await assert.rejects(f.run(), /ZK_DEV_OFF_CAPTURE_UNAVAILABLE/); }
  finally { fs.readSync = read; }
  assert.equal(attacked, true);
  assert.deepEqual(fs.readFileSync(f.sourcePath), original);
  assert.equal(fs.statSync(f.sourcePath, { bigint: true }).ino, inode);
});
