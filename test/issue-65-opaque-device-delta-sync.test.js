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
