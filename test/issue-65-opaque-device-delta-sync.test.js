"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const http = require("node:http");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { sealZk1CatalogMetadataV1 } = require("../src/crypto/rootark-zk1-opaque-catalog-client-v1");
const sourceFile = path.join(__dirname,
  "../public/client/rootark-zk1-opaque-device-delta-sync.js");
const probeFile = path.join(__dirname, "support/issue-65-opaque-delta-browser-probe.js");
const restoreProbeFile = path.join(__dirname, "support/issue-65-opaque-restore-probe.js");

test("independently authorized opaque delta client boots without generic sync-v2", () => {
  const source = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-opaque-device-delta-sync.js"), "utf8");
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob,
    RootarkZk1BrowserOpaqueCatalogCommit: Object.freeze({ createClient() {} }),
    RootarkZk1ProtectedHttpClient: Object.freeze({}),
    RootarkZk1CiphertextRoot: Object.freeze({}) };
  context.globalThis = context;
  vm.runInNewContext(source, context);
  assert.equal(typeof context.RootarkZk1OpaqueDeviceDeltaSync.createClient, "function");
  assert.doesNotMatch(source, /sync-client\/|rootark-sync-v2|rootark-sync-adapter/);
});

test("local filename filter caps display, counts all matches, and rejects a corrupt row after the cap", async () => {
  // Controlled signed-reader contract for the display cap. Real signatures and
  // AES-GCM decryption are exercised by browser-opaque-catalog-commit.test.js.
  const rows = Array.from({ length: 105 }, (_, index) => ({
    object_id: `opaque-${String(index).padStart(3, "0")}`,
    revision: 1, epoch: 1, ciphertext_digest: new Uint8Array(32).fill(8),
    metadata_ciphertext: new Uint8Array(284).fill(9),
  }));
  const snapshot = { head: { sequence: 1, digest: new Uint8Array(32).fill(7) }, rows };
  let decrypted = 0;
  let rejectLast = false;
  const catalog = {
    createClient: () => ({ readAll: async () => snapshot }),
    openMetadata: async ({ objectId }) => {
      decrypted++;
      if (rejectLast && objectId === rows[104].object_id) throw Error("BAD_METADATA");
      if (objectId === rows[0].object_id) return "report-relato\u0301rio [2026].txt";
      return `report-${objectId}.txt`;
    },
  };
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob,
    RootarkZk1BrowserOpaqueCatalogCommit: catalog,
    RootarkZk1ProtectedHttpClient: { signProtectedContentOperation() {} },
    RootarkZk1CiphertextRoot: { computeCiphertextRoot() {} },
    RootarkZk1FileContent: {} };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(sourceFile, "utf8"), context);
  const client = vm.runInContext(`RootarkZk1OpaqueDeviceDeltaSync.createClient({
    authority: { signedDeviceGrant: {}, pinnedOwnerHead: { digest: new Uint8Array(32) },
      signerGrants: [], csrfToken: () => "fixture-csrf", isSessionCurrent: () => true },
    assertLive() {},
  })`, context);
  const baseline = await client.readCurrent();
  const key = await crypto.webcrypto.subtle.importKey("raw", crypto.randomBytes(32),
    "AES-GCM", false, ["decrypt"]);
  const result = await client.readPrivateListing(baseline, key, "REPORT-");
  assert.equal(result.totalMatches, 105);
  assert.equal(result.entries.length, 100);
  assert.equal(decrypted, 105, "the cap must never skip verification of the remaining rows");
  const normalized = await client.readPrivateListing(baseline, key, "RELATÓRIO [2026]");
  assert.equal(normalized.totalMatches, 1,
    "casefold and NFC normalization must preserve literal special characters");
  assert.equal(normalized.entries[0].objectId, rows[0].object_id);
  rejectLast = true;
  await assert.rejects(client.readPrivateListing(baseline, key, "REPORT-"),
    /ZK_OPAQUE_DELTA_SYNC_DENIED/, "a corrupt row past the cap must fail the whole listing");
});

test("cached local search requires fresh signed catalog and never decrypts on a matching head", async () => {
  const head = { sequence: 3, digest: new Uint8Array(32).fill(4) };
  let requested = 0, opened = 0;
  const rows = [{ object_id: "opaque-current", revision: 1, epoch: 2,
    ciphertext_digest: new Uint8Array(32).fill(9),
    metadata_ciphertext: new Uint8Array(284).fill(8) }];
  const snapshot = { head, rows };
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob,
    RootarkZk1BrowserOpaqueCatalogCommit: {
      createClient: () => ({ readAll: async () => { requested++; return snapshot; } }),
      openMetadata: async () => { opened++; return "private.txt"; },
    },
    RootarkZk1ProtectedHttpClient: { signProtectedContentOperation() {} },
    RootarkZk1CiphertextRoot: { computeCiphertextRoot() {} },
    RootarkZk1FileContent: {} };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(sourceFile, "utf8"), context);
  const client = vm.runInContext(`RootarkZk1OpaqueDeviceDeltaSync.createClient({
    authority: { signedDeviceGrant: { account_id: "a", compartment_id: "c", keyring_id: "k" },
      pinnedOwnerHead: { digest: new Uint8Array(32) },
      signerGrants: [], csrfToken: () => "csrf", isSessionCurrent: () => true },
    assertLive() {},
  })`, context);
  const baseline = await client.readCurrent();
  const verified = await client.verifyPrivateListingHead(baseline);
  assert.equal(verified.head.sequence, 3);
  assert.equal(verified.scope.compartment_id, "c");
  assert.equal(requested, 2);
  assert.equal(opened, 0, "ciphertext stays sealed when the local index is valid");
  snapshot.head = { ...head, sequence: 4 };
  await assert.rejects(client.verifyPrivateListingHead(baseline), /ZK_OPAQUE_DELTA_SYNC_DENIED/);
  snapshot.head = head;
  snapshot.rows = [{ ...rows[0], revision: 2 }];
  await assert.rejects(client.verifyPrivateListingHead(baseline), /ZK_OPAQUE_DELTA_SYNC_DENIED/,
    "a same-head but altered signed row must not release cached plaintext");
});

test("normal workspace routes historical restore through all three existing authorization gates", () => {
  const source = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-authenticated-workspace.js"), "utf8");
  const allowlist = source.match(/if \(!\[([\s\S]*?)\]\.includes\(action\)\) return;/)?.[1];
  const deltaGate = source.match(/if \(\[([\s\S]*?)\]\.includes\(action\)\) \{\s*if \(available\.opaqueCatalogV1/)?.[1];
  const historyGate = source.match(/if \(\["catalog-delta-trash", "catalog-delta-trash-inspect",([\s\S]*?)\]\.includes\(action\)\) \{/)?.[1];
  for (const [gate, value] of Object.entries({ allowlist, deltaGate, historyGate })) {
    assert.ok(value?.includes('"catalog-delta-restore"'),
      `historical restore must not bypass or be excluded by ${gate}`);
  }
  assert.match(source, /if \(action === "catalog-delta-restore"\) \{[\s\S]*?held\.client\.restoreVersion\(/);
});

test("Node22/24 browser VM rejects replay/logout after opaque delta with no plaintext metadata", async () => {
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob,
    RootarkZk1BrowserOpaqueCatalogCommit: { createClient() {} },
    RootarkZk1ProtectedHttpClient: { signProtectedContentOperation() {} },
    RootarkZk1CiphertextRoot: { computeCiphertextRoot() {} } };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(sourceFile, "utf8"), context);
  vm.runInContext(fs.readFileSync(probeFile, "utf8"), context);
  assert.equal(await context.runOpaqueDeltaBrowserProbe(), "PASS");
});

for (const caseName of ["valid", "rekeyValid"]) {
  test(`authorized ${caseName} historical restore re-encrypts through signed browser PUT/GET and rejects replay`,
    { timeout: 30_000 }, async (t) => {
      const scopeBytes = { account_id: crypto.randomBytes(16),
        compartment_id: crypto.randomBytes(16), keyring_id: crypto.randomBytes(16) };
      const scope = Object.fromEntries(Object.entries(scopeBytes)
        .map(([name, value]) => [name, value.toString("base64url")]));
      const objectId = crypto.randomBytes(16).toString("base64url");
      const metadataKey = crypto.randomBytes(32);
      const tombstoneKey = caseName === "rekeyValid" ? crypto.randomBytes(32) : metadataKey;
      const name = "restored-private-name.txt";
      const sourceMetadataCiphertext = await sealZk1CatalogMetadataV1({
        scope: scopeBytes, objectId, revision: 1, epoch: 1, metadataKey, name,
      });
      const tombstoneMetadataCiphertext = await sealZk1CatalogMetadataV1({
        scope: scopeBytes, objectId, revision: 2,
        epoch: caseName === "rekeyValid" ? 2 : 1,
        metadataKey: tombstoneKey, name: "\uE000rootark-zk1-logical-trash/v1",
      });
      const stored = new Map();
      const server = http.createServer(async (req, res) => {
        try {
          const parts = [];
          for await (const part of req) parts.push(part);
          const input = JSON.parse(Buffer.concat(parts).toString("utf8"));
          const key = `${input.objectId}:${input.revision}`;
          let reply;
          if (req.method !== "POST") throw Error("INVALID_METHOD");
          if (req.url === "/fixture" || req.url === "/protected-put") {
            if (stored.has(key)) throw Error("DUPLICATE_VERSION");
            stored.set(key, input.ciphertextBase64);
            reply = { accepted: true };
          } else if (req.url === "/protected-get") {
            if (!stored.has(key)) throw Error("MISSING_CIPHERTEXT");
            reply = { ciphertextBase64: stored.get(key) };
          } else throw Error("INVALID_ROUTE");
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(reply));
        } catch (_) {
          res.writeHead(409, { "content-type": "application/json" });
          res.end('{"error":"denied"}');
        }
      });
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      t.after(() => new Promise((resolve) => server.close(resolve)));
      const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob, fetch };
      context.globalThis = context;
      vm.createContext(context);
      for (const script of ["rootark-zk1-file-content",
        "rootark-zk1-ciphertext-chunk-root", "rootark-zk1-browser-opaque-catalog-commit"]) {
        vm.runInContext(fs.readFileSync(path.join(__dirname,
          `../public/client/${script}.js`), "utf8"), context);
      }
      context.installOpaqueRestoreClient = async () => {
        vm.runInContext(fs.readFileSync(sourceFile, "utf8"), context);
      };
      vm.runInContext(fs.readFileSync(restoreProbeFile, "utf8"), context);
      const result = await context.runOpaqueRestoreProbe({ caseName, scope, objectId,
        sourceMetadata: { ...scope, object_id: objectId,
          version_id: crypto.randomBytes(16).toString("base64url"),
          parent_version_id: null, epoch: 1, kind: "file" },
        metadataKeyBase64: metadataKey.toString("base64url"),
        tombstoneMetadataKeyBase64: tombstoneKey.toString("base64url"),
        cekBase64: crypto.randomBytes(32).toString("base64url"),
        sourceMetadataCiphertextBase64: sourceMetadataCiphertext.toString("base64url"),
        tombstoneMetadataCiphertextBase64: tombstoneMetadataCiphertext.toString("base64url"),
        origin: `http://127.0.0.1:${server.address().port}` });
      assert.equal(result.result, "PASS");
      assert.equal(result.puts, 1);
      assert.equal(result.gets, caseName === "rekeyValid" ? 3 : 2);
      assert.equal(stored.size, 3, "historical source, signed tombstone, and one new ciphertext version");
    });
}

test("real Edge runs opaque delta browser contract under restrictive CSP", {
  timeout: 40_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("Edge Windows unavailable");
    return;
  }
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(16), keyring_id: crypto.randomBytes(16) };
  const metadataKey = crypto.randomBytes(32);
  const objectId = crypto.randomBytes(16).toString("base64url");
  const name = "edge-local-only-filename.txt";
  const sealed = await sealZk1CatalogMetadataV1({ scope, objectId,
    revision: 1, epoch: 1, metadataKey, name });
  const trashMetadata = await sealZk1CatalogMetadataV1({ scope, objectId,
    revision: 2, epoch: 1, metadataKey,
    name: "\uE000rootark-zk1-logical-trash/v1" });
  const fixture = { scope: Object.fromEntries(Object.entries(scope)
    .map(([key, value]) => [key, value.toString("base64url")])),
  objectId, name, ciphertextBase64: sealed.toString("base64url"),
  trashMetadataBase64: trashMetadata.toString("base64url"),
  metadataKeyBase64: metadataKey.toString("base64url") };
  const startup = "window.__deltaCryptoFixture=" + JSON.stringify(fixture) + ";"
    + "window.RootarkZk1ProtectedHttpClient={signProtectedContentOperation(){}};"
    + "window.RootarkZk1CiphertextRoot={computeCiphertextRoot(){}};";
  const html = "<!doctype html><meta charset='utf-8'>"
    + "<output id='probe-result'>PENDING</output>"
    + "<script src='/bootstrap.js'></script>"
    + "<script src='/writer.js'></script><script src='/writer-bridge.js'></script>"
    + "<script src='/client.js'></script><script src='/probe.js'></script>";
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'");
    const content = request.url === "/" ? html : request.url === "/bootstrap.js" ? startup
      : request.url === "/writer-bridge.js"
        ? "window.RootarkZk1BrowserOpaqueCatalogCommit={"
          + "openMetadata:window.RootarkZk1BrowserOpaqueCatalogCommit.openMetadata,"
          + "createClient(){}};"
      : request.url === "/writer.js" ? fs.readFileSync(path.join(__dirname,
        "../public/client/rootark-zk1-browser-opaque-catalog-commit.js"), "utf8")
      : request.url === "/client.js" ? fs.readFileSync(sourceFile, "utf8")
        : request.url === "/probe.js" ? fs.readFileSync(probeFile, "utf8") : null;
    response.writeHead(content === null ? 404 : 200, {
      "Content-Type": request.url === "/" ? "text/html; charset=utf-8"
        : "text/javascript; charset=utf-8",
    });
    response.end(content ?? "");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-delta-edge-"));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  const url = "http://127.0.0.1:" + server.address().port + "/";
  const options = ["--headless=new", "--disable-gpu", "--no-first-run",
    "--no-default-browser-check", "--disable-extensions", "--virtual-time-budget=10000",
    "--user-data-dir=" + path.join(dir, "edge-profile"), "--dump-dom", url];
  const result = await promisify(execFile)(edge, options, {
    timeout: 35_000, windowsHide: true, maxBuffer: 1024 * 1024,
  });
  assert.match(result.stdout, /EDGE_OPAQUE_DELTA_PASS/);
  assert.doesNotMatch(result.stdout, /EDGE_OPAQUE_DELTA_FAIL/);
});

test("real Edge CSP exposes normal authenticated manual delta import, but no unconsented sync", {
  timeout: 40_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("Edge Windows unavailable"); return;
  }
  const source = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-authenticated-workspace.js"), "utf8");
  const dependencies = source.match(/const dependencyNames = \[([\s\S]*?)\];/)[1]
    .match(/"rootark-[^"]+"/g).map((name) => JSON.parse(name));
  const allowed = new Set(["rootark-zk1-authenticated-workspace", ...dependencies]);
  const root = path.join(__dirname, "../public/client");
  const html = "<!doctype html><meta charset='utf-8'>"
    + "<section class='protected-client-panel'><p id='protectedClientStatus'></p></section>"
    + "<output id='edge-delta-ui-result'>PENDING</output>"
    + "<script defer src='/bootstrap.js'></script>"
    + "<script defer src='/client/rootark-zk1-authenticated-workspace.js'></script>"
    + "<script defer src='/ui-probe.js'></script>";
  const bootstrap = "window.RootarkApi={get:async()=>({enabled:true,"
    + "securityVersion:2,signedHistoryRequired:true,opaqueCatalogV1:true})};";
  const probe = `window.addEventListener("load", async()=>{
    const out=document.getElementById("edge-delta-ui-result");
    const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
    try{
      window.dispatchEvent(new Event("rootark:workspace-rendered"));
      let opener=null;
      for(let i=0;i<80;i++){
        opener=document.getElementById("zk1-workspace-open");
        if(opener)break;
        await sleep(30);
      }
      if(!opener)throw Error("CAPABILITY_GATE_MISSING");
      opener.click();
      let dlg;
      for(let i=0;i<80;i++){
        dlg=document.querySelector("dialog.zk1-workspace-dialog");
        if(dlg?.open)break;
        await sleep(30);
      }
      if(!dlg?.open)throw Error("NOT_AUTHENTICATED_ENTRY");
      const names=["catalog-delta-anchor","catalog-delta-list","catalog-delta-pull",
        "catalog-delta-import","catalog-delta-publish"];
      for(const name of names){
        if(!dlg.querySelector('[data-zk1-action="'+name+'"]'))
          throw Error("MISSING_ACTION_"+name);
      }
      const localQuery=dlg.querySelector('[data-zk1-field="catalog-delta-query"]');
      if(!localQuery||localQuery.type!=="search"||localQuery.maxLength!==120)
        throw Error("MISSING_BOUNDED_LOCAL_FILENAME_QUERY");
      localQuery.value="secret-local-only-term";
      if(!dlg.querySelector('[data-zk1-field="catalog-restore-epoch-opt-in"]')
        || !dlg.querySelector('[data-zk1-field="catalog-restore-rekey-grant"]')
        || !dlg.querySelector('[data-zk1-field="catalog-restore-current-cek"]')
        || !dlg.querySelector('[data-zk1-field="catalog-restore-current-metadata"]'))
        throw Error("MISSING_CURRENT_OWNER_REKEY_PROOF");
      const consent=dlg.querySelector('[data-zk1-field="catalog-delta-opt-in"]');
      if(!consent || consent.checked)throw Error("SILENT_AUTO_SYNC");
      dlg.querySelector('[data-zk1-action="catalog-delta-import"]').click();
      for(let i=0;i<100;i++){
        if(dlg.querySelector('[data-zk1-field="status"]').textContent
          .includes("Operação recusada"))break;
        await sleep(30);
      }
      if(!dlg.querySelector('[data-zk1-field="status"]').textContent
        .includes("Operação recusada"))throw Error("UNCONSENTED_IMPORT_NOT_DENIED");
      const restore=dlg.querySelector('[data-zk1-action="catalog-delta-restore"]');
      if(!restore)throw Error("HISTORICAL_RESTORE_ACTION_MISSING");
      for(let i=0;i<100&&restore.disabled;i++)await sleep(30);
      if(restore.disabled)throw Error("HISTORICAL_RESTORE_STILL_BUSY");
      const restoreStatus=dlg.querySelector('[data-zk1-field="status"]');
      restoreStatus.textContent="RESTORE_NOT_DISPATCHED";
      restore.click();
      if(restoreStatus.textContent==="RESTORE_NOT_DISPATCHED")
        throw Error("HISTORICAL_RESTORE_SILENT_NOOP");
      for(let i=0;i<100;i++){
        if(restoreStatus.textContent.includes("Operação recusada"))break;
        await sleep(30);
      }
      if(!restoreStatus.textContent.includes("Operação recusada"))
        throw Error("UNAUTHORIZED_RESTORE_NOT_DENIED");
      out.textContent="EDGE_DELTA_UI_PASS";
    }catch(error){out.textContent="EDGE_DELTA_UI_FAIL:"+error.message;}
  });`;
  let protectedRequests = 0;
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Security-Policy",
      "default-src 'none'; script-src 'self'; connect-src 'self'");
    if (/\/zk-1\/v1\/(catalog|content)\//.test(request.url)) protectedRequests++;
    const name = /^\/client\/([a-z0-9-]+)\.js$/.exec(request.url)?.[1];
    const content = request.url === "/" ? html
      : request.url === "/bootstrap.js" ? bootstrap
        : request.url === "/ui-probe.js" ? probe
          : name && allowed.has(name)
            ? fs.readFileSync(path.join(root, name + ".js"), "utf8") : null;
    response.writeHead(content === null ? 404 : 200, {
      "Content-Type": request.url === "/" ? "text/html; charset=utf-8"
        : "text/javascript; charset=utf-8",
    });
    response.end(content ?? "");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk-delta-normal-edge-"));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
  });
  const result = await promisify(execFile)(edge, ["--headless=new", "--disable-gpu",
    "--no-first-run", "--disable-extensions", "--no-default-browser-check",
    "--virtual-time-budget=15000", "--user-data-dir=" + path.join(folder, "edge"),
    "--dump-dom", "http://127.0.0.1:" + server.address().port + "/"], {
    timeout: 35000, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
  });
  assert.match(result.stdout, /EDGE_DELTA_UI_PASS/);
  assert.doesNotMatch(result.stdout, /EDGE_DELTA_UI_FAIL/);
  assert.equal(protectedRequests, 0,
    "opening the authenticated opt-in interface must never auto-sync or issue PUT/GET");
});
