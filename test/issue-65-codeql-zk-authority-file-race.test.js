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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-authority-file-"));
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
