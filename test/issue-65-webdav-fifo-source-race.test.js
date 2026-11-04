"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

test("WebDAV GET refuses a FIFO source substitution without blocking the HTTP event loop", {
  skip: process.platform !== "linux", timeout: 10_000,
}, () => {
  const child = String.raw`
    "use strict";
    const fs = require("node:fs");
    const os = require("node:os");
    const path = require("node:path");
    const http = require("node:http");
    const { execFileSync } = require("node:child_process");
    const { LocalSyncWebDavBridge } = require("./sync-client/rootark-sync-webdav");
    const { createPrivateAuthorityFixture } = require("./test/support/issue-65-private-authority-fixture");
    (async () => {
      const root = createPrivateAuthorityFixture("zk65-webdav-fifo-race-");
      const outside = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-webdav-fifo-outside-"));
      const source = path.join(root, "opaque.ct");
      const fifo = path.join(outside, "malicious.fifo");
      fs.writeFileSync(source, "REAL_CIPHERTEXT", { flag: "wx", mode: 0o600 });
      execFileSync("mkfifo", [fifo], { stdio: "ignore" });
      const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "fifo-race", port: 0 });
      let originalOpen;
      try {
        await bridge.start();
        originalOpen = fs.openSync;
        let substituted = false;
        fs.openSync = function (filename, ...rest) {
          if (filename === source && !substituted) {
            substituted = true;
            fs.renameSync(source, source + ".parked");
            fs.renameSync(fifo, source);
          }
          return originalOpen.call(fs, filename, ...rest);
        };
        const status = await new Promise((resolve, reject) => {
          const req = http.get({ hostname: "127.0.0.1", port: bridge.address().port,
            path: "/opaque.ct", agent: false,
            headers: { authorization: "Bearer fifo-race" } }, (res) => {
            res.resume();
            res.once("end", () => resolve(res.statusCode));
          });
          req.once("error", reject);
          req.setTimeout(1500, () => req.destroy(Error("HTTP_GET_TIMEOUT")));
        });
        if (!substituted || status === 200) throw Error("UNVERIFIED_FIFO_READ");
        process.stdout.write("FIFO_DENIED:" + status);
      } finally {
        if (originalOpen) fs.openSync = originalOpen;
        await bridge.stop();
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(outside, { recursive: true, force: true });
      }
    })().catch((error) => { console.error(error.message); process.exitCode = 1; });
  `;
  const result = spawnSync(process.execPath, ["-e", child], {
    cwd: require("node:path").resolve(__dirname, ".."), encoding: "utf8",
    timeout: 3000, maxBuffer: 64 * 1024,
  });
  assert.notEqual(result.error?.code, "ETIMEDOUT",
    "native FIFO swapped at fs.openSync must never block the Node process");
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.match(result.stdout, /FIFO_DENIED:(?!200)\d+/);
});
