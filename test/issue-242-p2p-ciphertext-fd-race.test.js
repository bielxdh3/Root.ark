"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const crypto = require("node:crypto");
const path = require("node:path");
const os = require("node:os");
const vm = require("node:vm");

// Exercise the exact server.js closure without starting production services.
const server = fs.readFileSync(path.resolve(__dirname, "../server.js"), "utf8");
const start = server.indexOf("  async function currentP2pCiphertext(");
const end = server.indexOf("\n  // This gate deliberately", start);
assert.ok(start >= 0 && end > start, "P2P source extraction must remain exact");
const source = server.slice(start, end);

async function setup(t, platform = process.platform, overrides = {}) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-p2p-fd-peer-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const directory = path.join(root, "uploads");
  await fsp.mkdir(directory);
  const bytes = Buffer.from(Array.from({ length: 4096 }, (_, i) => i % 251));
  const file = path.join(directory, "signed-ciphertext.bin");
  await fsp.writeFile(file, bytes);
  const promises = Object.assign(Object.create(fsp), overrides);
  const context = {
    fs: { promises, constants: fs.constants }, path, crypto, Buffer,
    process: { platform },
    MAX_P2P_CIPHERTEXT: 32 * 1024 * 1024,
    getFolderStoragePath: () => directory,
    isSafeChildPath: () => true,
    isSafeFolderChildPath: (_folder, value) => value === file,
  };
  const current = vm.runInNewContext(source + "\ncurrentP2pCiphertext", context);
  return { root, directory, file, bytes, current };
}
function pinnedHandle(handle, overrides) {
  return new Proxy(handle, { get(target, key) {
    if (Object.hasOwn(overrides, key)) return overrides[key](target);
    const value = Reflect.get(target, key, target);
    return typeof value === "function" ? value.bind(target) : value;
  } });
}

test("ciphertext hashes only unchanged locally retained bounded bytes", async t => {
  const f = await setup(t);
  const result = await f.current("root", "signed-ciphertext.bin", f.bytes.length);
  assert.ok(result);
  assert.equal(result.bytes, f.bytes.length);
  assert.equal(result.sha256, crypto.createHash("sha256").update(f.bytes).digest("hex"));
  assert.equal(await f.current("root", "signed-ciphertext.bin", f.bytes.length + 1), null);
});

test("CodeQL POSIX: open with O_NOFOLLOW and O_NONBLOCK then fstat before pathname lstat", async t => {
  if (process.platform === "win32") return t.skip("POSIX FD-first ordering");
  const order = [];
  const f = await setup(t, "linux", {
    open: async (...args) => {
      order.push(["open", args[1]]);
      return pinnedHandle(await fsp.open(...args), {
        stat: target => async (...stats) => {
          order.push(["fstat"]);
          return target.stat(...stats);
        },
      });
    },
    lstat: async (...args) => {
      order.push(["lstat"]);
      return fsp.lstat(...args);
    },
  });
  assert.ok(await f.current("root", "signed-ciphertext.bin", f.bytes.length));
  assert.deepEqual(order.slice(0, 3).map(x => x[0]), ["open", "fstat", "lstat"]);
  assert.ok((order[0][1] & fs.constants.O_NOFOLLOW) !== 0);
  assert.ok((order[0][1] & fs.constants.O_NONBLOCK) !== 0);
});

test("CodeQL Windows: reparse pathname denies BEFORE open", async t => {
  let opens = 0;
  const f = await setup(t, "win32", {
    open: async (...args) => { opens++; return fsp.open(...args); },
    lstat: async (...args) => pinnedHandle(await fsp.lstat(...args), {
      isSymbolicLink: () => () => true,
    }),
  });
  assert.equal(await f.current("root", "signed-ciphertext.bin", f.bytes.length), null);
  assert.equal(opens, 0);
});

test("CodeQL Windows: reparse replacement after opening the FD denies before ciphertext read", async t => {
  let opens = 0, stats = 0, reads = 0;
  const f = await setup(t, "win32", {
    open: async (...args) => {
      opens++;
      return pinnedHandle(await fsp.open(...args), {
        read: target => async (...data) => { reads++; return target.read(...data); },
      });
    },
    lstat: async (...args) => {
      const value = await fsp.lstat(...args);
      stats++;
      return stats === 2 ? pinnedHandle(value, { isSymbolicLink: () => () => true }) : value;
    },
  });
  assert.equal(await f.current("root", "signed-ciphertext.bin", f.bytes.length), null);
  assert.equal(opens, 1);
  assert.equal(stats, 2);
  assert.equal(reads, 0);
});

test("POSIX: pathname swapped after pinned fstat is denied before reading bytes", async t => {
  if (process.platform === "win32") return t.skip("POSIX inode rename while FD open");
  let swapped = false, reads = 0;
  const f = await setup(t, "linux", {
    open: async (...args) => pinnedHandle(await fsp.open(...args), {
      stat: target => async (...stats) => {
        const result = await target.stat(...stats);
        if (!swapped) {
          swapped = true;
          await fsp.rename(args[0], args[0] + ".old");
          await fsp.writeFile(args[0], Buffer.alloc(4096, 0x66));
        }
        return result;
      },
      read: target => async (...data) => { reads++; return target.read(...data); },
    }),
  });
  assert.equal(await f.current("root", "signed-ciphertext.bin", f.bytes.length), null);
  assert.equal(swapped, true);
  assert.equal(reads, 0, "replaced pathname must deny before ciphertext read");
});

test("mutation during pinned hashing cannot inherit signed object fingerprint", async t => {
  let changed = false;
  const f = await setup(t, process.platform, {
    open: async (...args) => pinnedHandle(await fsp.open(...args), {
      read: target => async (...data) => {
        const result = await target.read(...data);
        if (!changed) {
          changed = true;
          await fsp.writeFile(args[0], Buffer.alloc(4096, 0x55));
        }
        return result;
      },
    }),
  });
  assert.equal(await f.current("root", "signed-ciphertext.bin", f.bytes.length), null);
  assert.equal(changed, true);
});

test("same-tick overwrite without stat timestamp delta cannot inherit signed object fingerprint", async t => {
  let changed = false;
  let frozen = null;
  const f = await setup(t, process.platform, {
    lstat: async (...args) => {
      const value = await fsp.lstat(...args);
      if (!frozen) frozen = value;
      return frozen;
    },
    open: async (...args) => pinnedHandle(await fsp.open(...args), {
      stat: () => async () => frozen,
      read: target => async (...data) => {
        const result = await target.read(...data);
        if (!changed) {
          changed = true;
          await fsp.writeFile(args[0], Buffer.alloc(4096, 0x55));
        }
        return result;
      },
    }),
  });
  assert.equal(await f.current("root", "signed-ciphertext.bin", f.bytes.length), null);
  assert.equal(changed, true);
});

test("symlink and extra hardlink do not prove signed ciphertext", async t => {
  const f = await setup(t);
  const alias = path.join(f.directory, "foreign-hardlink.bin");
  await fsp.link(f.file, alias);
  assert.equal(await f.current("root", "signed-ciphertext.bin", f.bytes.length), null);
  await fsp.unlink(alias);
  const foreign = path.join(f.root, "foreign-target.bin");
  await fsp.writeFile(foreign, f.bytes);
  await fsp.unlink(f.file);
  try { await fsp.symlink(foreign, f.file, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code))
      return t.skip("native Windows symlink creation requires developer rights");
    throw error;
  }
  assert.equal(await f.current("root", "signed-ciphertext.bin", f.bytes.length), null);
});
