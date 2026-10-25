"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { Readable } = require("node:stream");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../sync-client/rootark-sync.js"), "utf8");
const original = Buffer.from("same bytes on both inode identities");
const inodeA = (1n << 53n) + 4n;
const inodeB = inodeA + 1n;

async function harness(t, { tamperPathStream = false } = {}) {
  const localFolder = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-exact-inode-"));
  const filePath = path.join(localFolder, "payload.txt");
  await fsp.writeFile(filePath, original);
  t.after(() => fsp.rm(localFolder, { recursive: true, force: true }));

  let phase = "A";
  let lstatCalls = 0;
  let postOpenSwap = false;
  let alternatingStability = false;
  let fdChangedAfterRead = false;
  let fdStatCalls = 0;

  function simulatedStat(stat, bigint, inode, changedCtime = false) {
    const copy = Object.create(stat);
    Object.defineProperties(copy, {
      dev: { value: bigint ? (1n << 53n) + 10n : Number((1n << 53n) + 10n) },
      ino: { value: bigint ? inode : Number(inode) },
      ...(changedCtime && bigint ? {
        ctimeNs: { value: stat.ctimeNs + 1000000n },
      } : {}),
    });
    return copy;
  }

  const mockFsp = Object.create(fsp);
  mockFsp.lstat = async (target, options) => {
    const bigint = options?.bigint === true;
    const stat = await fsp.lstat(target, options);
    lstatCalls += 1;
    let inode = phase === "B" ? inodeB : inodeA;
    if (alternatingStability && lstatCalls === 2) inode = inodeB;
    if (postOpenSwap && lstatCalls >= 2) inode = inodeB;
    return simulatedStat(stat, bigint, inode);
  };
  mockFsp.open = async (target, flags) => {
    const handle = await fsp.open(target, flags);
    return {
      read: (...args) => handle.read(...args),
      close: () => handle.close(),
      stat: async (options) => {
        const stat = await handle.stat(options);
        fdStatCalls += 1;
        return simulatedStat(stat, options?.bigint === true, inodeA, fdChangedAfterRead && fdStatCalls > 1);
      },
    };
  };
  const mockFs = Object.create(fs);
  if (tamperPathStream) mockFs.createReadStream = () => Readable.from(["attacker-supplied path bytes"]);
  const context = vm.createContext({
    require(id) {
      if (id === "fs") return mockFs;
      if (id === "fs/promises") return mockFsp;
      if (id === "./rootark-sync-transport-policy")
        return require("../sync-client/rootark-sync-transport-policy");
      return require(id);
    },
    process: { argv: ["node", "rootark-sync", "help"], cwd: () => localFolder, env: {} },
    console: { log() {}, error() {} },
    Buffer, setTimeout, clearTimeout,
  });
  vm.runInContext(`${source}\n;globalThis.helpers = { getStableFileInfo, readVerifiedUpload };`, context, {
    filename: "rootark-sync.js",
  });
  return {
    config: { localFolder }, filePath,
    ...context.helpers,
    setPhase(next) { phase = next; lstatCalls = 0; fdStatCalls = 0; },
    setAlternatingStability() { alternatingStability = true; },
    setPostOpenSwap() { postOpenSwap = true; },
    setFdChangedAfterRead() { fdChangedAfterRead = true; },
  };
}

test("stability scan rejects different 64-bit inodes colliding as Number", async (t) => {
  const h = await harness(t);
  h.setAlternatingStability();
  assert.equal(await h.getStableFileInfo(h.filePath, 0, h.config), null);
});

test("upload rejects changed 64-bit inode despite unchanged content, size and timestamps", async (t) => {
  const h = await harness(t);
  const expected = await h.getStableFileInfo(h.filePath, 0, h.config);
  assert.ok(expected);
  h.setPhase("B");
  await assert.rejects(h.readVerifiedUpload(h.config, h.filePath, expected), /alterado/);
});

test("upload rejects pathname replacement after FD was opened", async (t) => {
  const h = await harness(t);
  const expected = await h.getStableFileInfo(h.filePath, 0, h.config);
  assert.ok(expected);
  h.setPhase("A");
  h.setPostOpenSwap();
  await assert.rejects(h.readVerifiedUpload(h.config, h.filePath, expected), /alterado/);
});

test("stable file digest is read from the verified FD, never a fresh path stream", async (t) => {
  const h = await harness(t, { tamperPathStream: true });
  const expected = await h.getStableFileInfo(h.filePath, 0, h.config);
  assert.equal(expected.hash, crypto.createHash("sha256").update(original).digest("hex"));
});

test("upload rejects in-place metadata mutation even when size and mtime match", async (t) => {
  const h = await harness(t);
  const expected = await h.getStableFileInfo(h.filePath, 0, h.config);
  assert.ok(expected);
  h.setPhase("A");
  h.setFdChangedAfterRead();
  await assert.rejects(h.readVerifiedUpload(h.config, h.filePath, expected), /alterado/);
});
