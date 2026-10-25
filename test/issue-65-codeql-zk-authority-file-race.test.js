"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const helper = path.resolve(__dirname, "../src/services/zk1AuthorityPinnedFile");
const b64 = (value) => Buffer.from(value).toString("base64url");

function fixture(t) {
  let dir;
  if (process.platform === "win32") {
    // Windows TMP may grant unrelated accounts Modify. Tests must provision
    // operator-private roots just as a real CAS/witness operator must.
    const { ensureWindowsChunkUploadRoot } =
      require("../services/chunkUploadWindowsAcl");
    dir = path.join(process.env.LOCALAPPDATA,
      "zk65-authority-file-" + crypto.randomBytes(8).toString("hex"));
    ensureWindowsChunkUploadRoot(dir);
  } else {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-authority-file-"));
  }
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const a = path.join(dir, "authority.pem");
  const b = path.join(dir, "alternate.pem");
  const first = crypto.generateKeyPairSync("ed25519").privateKey.export({
    type: "pkcs8", format: "pem" });
  const second = crypto.generateKeyPairSync("ed25519").privateKey.export({
    type: "pkcs8", format: "pem" });
  assert.equal(Buffer.byteLength(first), Buffer.byteLength(second));
  fs.writeFileSync(a, first, { flag: "wx", mode: 0o600 });
  fs.writeFileSync(b, second, { flag: "wx", mode: 0o600 });
  return { dir, a, b, first: Buffer.from(first), second: Buffer.from(second) };
}

function childProbe(file, attack, extra) {
  const source = `
    "use strict";
    const fs=require("node:fs");
    const { readAuthorityPinnedFile }=require(process.argv[1]);
    const name=process.argv[2], foreign=process.argv[3], attack=process.argv[4];
    const originalOpen=fs.openSync, originalRead=fs.readSync;
    let used=false;
    function replace() {
      if(used) return;
      used=true;
      fs.renameSync(name, name+".detached");
      fs.renameSync(foreign, name);
    }
    if(attack==="open") {
      fs.openSync=function(target,...args) {
        if(target===name) replace();
        return originalOpen.call(fs,target,...args);
      };
    }
    if(attack==="read") {
      fs.readSync=function(fd,...args) {
        if(!used) replace();
        return originalRead.call(fs,fd,...args);
      };
    }
    if(attack==="growth") {
      fs.readSync=function(fd,...args) {
        if(!used) { used=true; fs.appendFileSync(name,Buffer.alloc(65536)); }
        return originalRead.call(fs,fd,...args);
      };
    }
    try {
      const bytes=readAuthorityPinnedFile(name);
      process.stdout.write("ACCEPT:"+bytes.toString("base64url"));
    } catch(error) {
      process.stdout.write("DENIED:"+error.code);
    }
  `;
  return spawnSync(process.execPath, ["-e", source, helper, file, extra, attack], {
    encoding: "utf8", windowsHide: true, timeout: 10000, env: {
      ...process.env, NODE_OPTIONS: "",
      ...(attack === "path-poison" ? {
        PATH: path.dirname(file) + path.delimiter + (process.env.PATH || ""),
      } : {}),
    },
  });
}

test("trusted ZK authority PEM read succeeds with one stable private file", (t) => {
  const f = fixture(t);
  const child = childProbe(f.a, "none", f.b);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, "ACCEPT:" + b64(f.first));
});

test("separate Node process rejects a replaced authority PEM between lstat and open", (t) => {
  const f = fixture(t);
  const child = childProbe(f.a, "open", f.b);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, "DENIED:ZK_AUTHORITY_FILE_UNTRUSTED",
    "replacement must never authorize attacker-selected Ed25519 signer key");
});

test("separate Node process rejects replacement after open but before read", (t) => {
  const f = fixture(t);
  const child = childProbe(f.a, "read", f.b);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, "DENIED:ZK_AUTHORITY_FILE_UNTRUSTED");
});

test("file growth cannot evade bounded snapshot or become a trusted authority key", (t) => {
  const f = fixture(t);
  const child = childProbe(f.a, "growth", f.b);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, "DENIED:ZK_AUTHORITY_FILE_UNTRUSTED");
});

test("ancestor junction/symlink cannot select a replacement authority key", (t) => {
  const f = fixture(t);
  const alias = path.join(f.dir, "authority-alias");
  const privateDir = path.join(f.dir, "authority-folder");
  fs.mkdirSync(privateDir, { mode: 0o700 });
  fs.copyFileSync(f.b, path.join(privateDir, "authority.pem"));
  fs.chmodSync(path.join(privateDir, "authority.pem"), 0o600);
  fs.symlinkSync(privateDir, alias, process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => require(helper).readAuthorityPinnedFile(
    path.join(alias, "authority.pem")), { code: "ZK_AUTHORITY_FILE_UNTRUSTED" });
  assert.deepEqual(require(helper).readAuthorityPinnedFile(f.a), f.first);
});

test("ancestor replacement during file open refuses the substituted key", (t) => {
  const f = fixture(t);
  const trusted = path.join(f.dir, "trusted-parent");
  const other = path.join(f.dir, "other-parent");
  fs.mkdirSync(trusted, { mode: 0o700 });
  fs.mkdirSync(other, { mode: 0o700 });
  const firstPath = path.join(trusted, "authority.pem");
  fs.copyFileSync(f.a, firstPath);
  fs.copyFileSync(f.b, path.join(other, "authority.pem"));
  fs.chmodSync(firstPath, 0o600);
  fs.chmodSync(path.join(other, "authority.pem"), 0o600);
  const realOpen = fs.openSync;
  let replaced = false;
  fs.openSync = function (name, ...args) {
    if (name === firstPath && !replaced) {
      replaced = true;
      fs.renameSync(trusted, trusted + ".original");
      fs.renameSync(other, trusted);
    }
    return realOpen.call(fs, name, ...args);
  };
  try {
    assert.throws(() => require(helper).readAuthorityPinnedFile(firstPath),
      { code: "ZK_AUTHORITY_FILE_UNTRUSTED" });
  } finally { fs.openSync = realOpen; }
  assert.equal(replaced, true);
});

test("Windows permissive authority key DACL is rejected", {
  skip: process.platform !== "win32",
}, (t) => {
  const { execFileSync } = require("node:child_process");
  const f = fixture(t);
  execFileSync("C:\\Windows\\System32\\icacls.exe", [
    f.a, "/grant", "*S-1-5-11:(M)",
  ], { stdio: "ignore", windowsHide: true });
  assert.throws(() => require(helper).readAuthorityPinnedFile(f.a),
    { code: "ZK_AUTHORITY_FILE_UNTRUSTED" });
});

test("Windows permissive ancestor DACL is rejected before signing key load", {
  skip: process.platform !== "win32",
}, (t) => {
  const { execFileSync } = require("node:child_process");
  const f = fixture(t);
  execFileSync("C:\\Windows\\System32\\icacls.exe", [
    f.dir, "/grant", "*S-1-5-11:(OI)(CI)M",
  ], { stdio: "ignore", windowsHide: true });
  assert.throws(() => require(helper).readAuthorityPinnedFile(f.a),
    { code: "ZK_AUTHORITY_FILE_UNTRUSTED" });
});

test("Windows native DACL verification never resolves an executable from mutable PATH", {
  skip: process.platform !== "win32",
}, (t) => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.dir, "powershell.exe"),
    "NOT_A_EXECUTABLE", { mode: 0o600 });
  const child = childProbe(f.a, "path-poison", f.b);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, "ACCEPT:" + b64(f.first));
});
