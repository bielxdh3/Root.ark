"use strict";

const assert = require("node:assert/strict");
const { createRequire } = require("node:module");
const Module = require("node:module");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");

function loadClassWithoutStartingCli() {
  // Exercise the actual SyncClient class without invoking the module's CLI
  // entrypoint. This modifies only source bytes in the test module cache;
  // production files and public exports remain unchanged.
  const source = fs.readFileSync(cli, "utf8");
  const last = source.lastIndexOf("main().catch(");
  assert.ok(last > 0, "expected CLI entrypoint was not found");
  const loaded = new Module(cli, module);
  loaded.filename = cli;
  loaded.paths = Module._nodeModulePaths(path.dirname(cli));
  loaded.require = createRequire(cli);
  loaded._compile(`${source.slice(0, last)}\nmodule.exports = { SyncClient };\n`, cli);
  return loaded.exports.SyncClient;
}

test("a transient failed basename claim save must be retried before remote POST", {
  timeout: 90000,
}, async (t) => {
  const SyncClient = loadClassWithoutStartingCli();
  const configDir = createPrivateAuthorityFixture("rootark-claim-durable-config-");
  const selected = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-claim-durable-source-"));
  t.after(() => fsp.rm(selected, { recursive: true, force: true }));
  t.after(() => fsp.rm(configDir, { recursive: true, force: true }));
  const file = path.join(selected, "same.txt");
  await fsp.writeFile(file, "REAL_PROTECTED_UPLOAD");
  let observedClaimAtPost = false;
  let postCount = 0;
  let statePath;
  const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    } else if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        postCount++;
        // Durable owner must exist BEFORE the remote receives mutating bytes,
        // not only after a successful uploaded acknowledgement is saved.
        try {
          const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
          observedClaimAtPost = state.remoteBasenameOwners?.["same.txt"]?.localFolder
            === path.resolve(selected);
        } catch { observedClaimAtPost = false; }
        res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ fileName: "same.txt" }));
      });
    } else res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = { serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "test-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1 };
  const client = new SyncClient(path.join(configDir, "config.json"), config,
    { once: true });
  statePath = client.statePath;
  t.after(async () => {
    client.stateLock?.release();
    await fsp.rm(statePath, { force: true });
  });
  await client.init();
  const realSave = client.saveState.bind(client);
  let injectedFailures = 0;
  client.saveState = () => {
    if (injectedFailures++ === 0) return Promise.reject(new Error("INJECTED_PRIVATE_STATE_WRITE_FAIL"));
    return realSave();
  };
  await assert.rejects(client.ensureRemoteBasenameAuthority("same.txt"),
    /INJECTED_PRIVATE_STATE_WRITE_FAIL/);
  assert.equal(fs.existsSync(statePath), false, "first claim did not reach durable storage");

  // Same-process retry via real bounded snapshot and HTTP upload.
  await client.syncOneWithSlot(file, "same.txt", "retry-after-private-write-failure");
  assert.equal(postCount, 1, "upload must still be permitted after a durable claim succeeds");
  assert.equal(observedClaimAtPost, true,
    "never POST before the second, now-successful claim fsync");
  const saved = JSON.parse(await fsp.readFile(statePath, "utf8"));
  assert.equal(saved.remoteBasenameOwners["same.txt"].relativePath, "same.txt");
  assert.equal(saved.files["same.txt"].lastStatus, "uploaded");
  assert.equal(injectedFailures, 3, "failed claim, durable retry, and uploaded acknowledgement only");
  await client.ensureRemoteBasenameAuthority("same.txt");
  assert.equal(injectedFailures, 3,
    "an already fsynced trusted owner must not force a new save for each scan");
});

test("different case-exact Windows roots cannot share a basename provenance claim", async (t) => {
  if (process.platform !== "win32") { t.skip("Windows per-directory case-sensitive NTFS boundary"); return; }
  const SyncClient = loadClassWithoutStartingCli();
  // Do not change NTFS case-sensitivity flags. On a case-sensitive NTFS
  // directory, these paths can refer to different physical source trees.
  const common = { serverUrl: "http://127.0.0.1:37001", username: "fixture",
    token: "test-token", targetFolderId: "root", retryLimit: 1 };
  const a = new SyncClient("C:\\private\\first-config.json", {
    ...common, localFolder: "C:\\case-sensitive\\Source",
  });
  const b = new SyncClient("C:\\private\\second-config.json", {
    ...common, localFolder: "C:\\case-sensitive\\source",
  });
  // In-memory synthetic case-sensitive local-root model; state path is the
  // same remote authority but never written during this fixture.
  assert.equal(a.statePath, b.statePath);
  a.saveState = async () => {};
  await a.ensureRemoteBasenameAuthority("same.txt");
  b.state = a.state;
  b.saveState = async () => {};
  await assert.rejects(b.ensureRemoteBasenameAuthority("same.txt"),
    /SYNC_REMOTE_BASENAME_AUTHORITY_CONFLICT/);
});
