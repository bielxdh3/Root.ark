"use strict";

const assert = require("node:assert/strict");
const { spawnSync, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

test("physical cloud readback cannot block opening a FIFO swapped after a file check", {
  skip: process.platform !== "linux",
}, (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-readback-fifo-"));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true, maxRetries: 5 }));
  const fifo = path.join(fixture, "replacement");
  execFileSync("mkfifo", [fifo]);
  const child = String.raw`
    const fs = require('node:fs');
    const crypto = require('node:crypto');
    const fifo = process.argv[1];
    const { Zk1CloudCiphertextReadbackVerifier } =
      require('./src/services/zk1CloudCiphertextReadbackVerifier');
    const { computeZk1CiphertextRoot } = require('./src/crypto/rootark-zk-chunk-root-v1');
    const bytes = Buffer.from('private opaque ciphertext');
    const scope = {account_id: crypto.randomBytes(16),
      compartment_id: crypto.randomBytes(6), keyring_id: crypto.randomBytes(16)};
    const operationId = crypto.randomBytes(16);
    const reader = { enabled:()=>true, status:()=>({provider:'s3'}),
      resolveInventoryContext:async()=> 'a'.repeat(64),
      key:(folder,name)=> 'fixture/uploads/' + folder + '/' + name,
      download:async(_f,_n,destination)=> {
        fs.writeFileSync(destination, bytes, {flag:'wx',mode:0o600});
        return true;
      } };
    const verifier = new Zk1CloudCiphertextReadbackVerifier({
      cloudReader:reader, expectedProvider:'s3', expectedReaderContext:'a'.repeat(64) });
    // Attack with an already-prepared FIFO on the same Linux filesystem.
    // The critical lstat-to-open race performs only atomic rename operations.
    const original = fs.lstatSync;
    let attacked = false;
    fs.lstatSync = function(filename,...args) {
      const stat = original.call(this,filename,...args);
      if (!attacked && typeof filename==='string' && filename.endsWith('/ciphertext.ct')) {
        attacked = true;
        fs.renameSync(filename, filename + '.held');
        fs.renameSync(fifo, filename);
      }
      return stat;
    };
    verifier.verifyExact({scope,operationId,
      ciphertextSha256:crypto.createHash('sha256').update(bytes).digest(),
      expectedRootHash:computeZk1CiphertextRoot([bytes]),
      chunkLengths:[bytes.length]}).then(
      ()=>process.exit(3), ()=>process.exit(attacked?0:4));
  `;
  const outcome = spawnSync(process.execPath, ["-e", child, fifo], {
    cwd: path.resolve(__dirname, ".."),
    timeout: 8000, windowsHide: true, encoding: "utf8",
  });
  assert.equal(outcome.status, 0,
    `swapped FIFO must not stall the physical readback (signal=${outcome.signal}, error=${outcome.error?.code}, stderr=${outcome.stderr})`);
});
