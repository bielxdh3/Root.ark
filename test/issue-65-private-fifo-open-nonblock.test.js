"use strict";

const assert = require("node:assert/strict");
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

for (const kind of ["pinned", "sqlite", "cas", "cas-intent", "cas-append"]) {
  test(`protected ${kind} file refuses a FIFO swapped at the exact open boundary`, {
    skip: process.platform !== "linux",
  }, (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `zk65-${kind}-fifo-`));
    t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
    const staging = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-fifo-staging-"));
    t.after(() => fs.rmSync(staging, { recursive: true, force: true, maxRetries: 5 }));
    const target = path.join(root, "protected.bin");
    // Stage the FIFO outside the trusted private-authority directory: its
    // bootstrap/tree checks must not see malicious siblings before our race.
    const substitute = path.join(staging, "prepared-fifo");
    if (!kind.startsWith("cas")) {
      fs.writeFileSync(target, Buffer.from("opaque signed test fixture"), {
        mode: 0o600, flag: "wx",
      });
    }
    execFileSync("mkfifo", [substitute]);
    const child = String.raw`
      "use strict";
      const fs = require('node:fs');
      const crypto = require('node:crypto');
      const [kind,target,substitute] = process.argv.slice(1);
      const isCas = kind.startsWith('cas');
      let key, keyId, anchor, query, ticket, manifest;
      if (isCas) {
        key = crypto.generateKeyPairSync('ed25519').privateKey;
        keyId = crypto.randomBytes(16);
        const {Zk1CasTerminalAnchor} = require('./src/services/zk1CasTerminalAnchor');
        anchor = new Zk1CasTerminalAnchor(target,{bootstrapNew:true,
          statusKeyId:keyId,statusPrivateKey:key});
        if (kind === 'cas-intent' || kind === 'cas-append') {
          query = { account_id:crypto.randomBytes(16),
            compartment_id:Buffer.from('main'),keyring_id:crypto.randomBytes(16),
            reservation_id:crypto.randomBytes(16) };
          ticket=crypto.randomBytes(64);
          manifest=crypto.randomBytes(64);
          anchor.prepare(query,ticket,'committed',manifest);
        }
      }
      const attackTarget = kind === 'cas-intent' ? anchor.intentPath(query) : target;
      const expected = kind === 'pinned' ? 'ZK_AUTHORITY_FILE_UNTRUSTED'
        : kind === 'sqlite' ? 'UNTRUSTED_SQLITE_PATH' : 'CAS_ANCHOR_INVALID';
      const open = fs.openSync;
      let swapped = false;
      fs.openSync = function(filename, flags, ...rest) {
        if (!swapped && filename === attackTarget
          && (kind !== 'cas-append'
            || (typeof flags === 'number' && (flags & fs.constants.O_APPEND) !== 0))) {
          fs.renameSync(attackTarget,attackTarget+'.held');
          fs.renameSync(substitute,attackTarget);
          if (!fs.lstatSync(attackTarget).isFIFO()) process.exit(8);
          // Record success only AFTER both atomic filesystem renames completed.
          swapped = true;
        }
        return open.apply(this,arguments);
      };
      (async () => { try {
        if (kind === 'pinned') {
          require('./src/services/zk1AuthorityPinnedFile')
            .readAuthorityPinnedFile(target,4096);
        } else if (kind === 'sqlite') {
          require('./src/services/zk1PrivateSqlitePath')
            .assertPrivateSqliteFile(target);
        } else if (kind === 'cas') {
          const {Zk1CasTerminalAnchor} = require('./src/services/zk1CasTerminalAnchor');
          new Zk1CasTerminalAnchor(target,{bootstrapNew:false,
            statusKeyId:keyId,statusPrivateKey:key});
        } else if (kind === 'cas-intent') {
          anchor.getIntent(query);
        } else if (kind === 'cas-append') {
          await anchor.append(query,ticket,'committed',manifest,crypto.randomBytes(64));
        } else {
          process.exit(10);
        }
        process.exit(3);
      } catch (error) {
        const denied = error && (error.code === expected || error.message === expected);
        const realFifo = swapped && fs.lstatSync(attackTarget).isFIFO();
        process.exit(denied && realFifo ? 0 : 4);
      } })().catch(()=>process.exit(5));
    `;
    const outcome = spawnSync(process.execPath, ["-e", child, kind, target, substitute], {
      cwd: path.resolve(__dirname, ".."),
      timeout: 7000, windowsHide: true, encoding: "utf8",
    });
    assert.equal(outcome.status, 0,
      `${kind} must deny the swapped FIFO without blocking open() `
        + `(signal=${outcome.signal}, error=${outcome.error?.code}, stderr=${outcome.stderr})`);
  });
}
