"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { spawn, execFileSync } = require("node:child_process");

test("real Edge: two selected 128-revision UI batches never inherit destructive replacement consent", {
  timeout: 90_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("Real Windows Edge unavailable");
    return;
  }
  const root = path.join(__dirname, "../public/client");
  const html = "<!doctype html><meta charset='utf-8'>"
    + "<section class='protected-client-panel'><p id='protectedClientStatus'></p></section>"
    + "<output id='edge-result'>PENDING</output>"
    + "<script defer src='/bootstrap.js'></script>"
    + "<script defer src='/client/rootark-zk1-file-content.js'></script>"
    + "<script defer src='/client/rootark-zk1-selected-local-preview.js'></script>"
    + "<script defer src='/client/rootark-zk1-protected-text-batch.js'></script>"
    + "<script defer src='/client/rootark-zk1-protected-revision-index.js'></script>"
    + "<script defer src='/client/rootark-zk1-authenticated-workspace.js'></script>"
    + "<script defer src='/probe.js'></script>";
  const bootstrap = "window.RootarkApi={get:async()=>({enabled:true,"
    + "securityVersion:2,signedHistoryRequired:true,opaqueCatalogV1:true})};"
    + "window.RootarkZk1NormalBrowserTrustFloor={"
    + "assertCurrent:async()=>true};";
  // This fixture replaces only external owner/capability provisioning in a
  // disposable served copy. The REAL workspace action, text batch, signed
  // catalog checks, AES-GCM index, IndexedDB, DOM and CSP run unchanged.
  const source = fs.readFileSync(path.join(root,
    "rootark-zk1-authenticated-workspace.js"), "utf8");
  const injections = [
    ["async function ensureScripts() {",
      "async function ensureScripts() { if (window.__issue63Fixture) return;"],
    ["async function grantAndOwner() {",
      "async function grantAndOwner() { if (window.__issue63Fixture) return window.__issue63Fixture.trust;"],
    ["const trust = await grantAndOwner();",
      "if (window.__issue63Fixture) verifiedOpaqueDelta = window.__issue63Fixture.held;\n      const trust = await grantAndOwner();"],
  ];
  let servedWorkspace = source;
  for (const [before, after] of injections) {
    assert.equal(servedWorkspace.split(before).length, 2,
      "fixture injection must match the exact current source once");
    servedWorkspace = servedWorkspace.replace(before, after);
  }
  const probe = `window.addEventListener("load", async () => {
    const out=document.getElementById("edge-result");
    const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
    const encoder=new TextEncoder();
    const random=n=>crypto.getRandomValues(new Uint8Array(n));
    const b64=bytes=>btoa(String.fromCharCode(...bytes))
      .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"");
    const id=()=>b64(random(16));
    let phase="initial";
    try {
      const scope={account_id:id(),compartment_id:id(),keyring_id:id()};
      const ownerDigest=random(32);
      const grant={...scope,device_id:id(),current_epoch:2,
        manifest_revision:8,manifest_digest:b64(ownerDigest),revoked_at_epoch:null};
      const baseline={head:{sequence:11,digest:b64(random(32))},entries:[]};
      const signer=await crypto.subtle.generateKey("Ed25519",false,["sign","verify"]);
      const metadataRaw=random(32);
      const rawCek=random(32);
      const cek=await window.RootarkZk1FileContent.importFileCek(rawCek);
      const cekPin=b64(new Uint8Array(await crypto.subtle.digest("SHA-256",rawCek)));
      const selections=[];
      const checked=new Map();
      for(let i=0;i<129;i++){
        const oid=id();
        const metadata={...scope,object_id:oid,version_id:id(),
          parent_version_id:null,epoch:2,kind:"file"};
        const ciphertext=await window.RootarkZk1FileContent.encryptFile({
          cek,metadata,name:"owner-selected-"+(i+1)+".txt",mediaType:"text/plain",
          data:encoder.encode("selected revision "+String(i+1).padStart(4,"0")+" needle")});
        const selected={objectId:oid,revision:i+1,epoch:2,
          ciphertextDigestBase64:b64(new Uint8Array(
            await crypto.subtle.digest("SHA-256",ciphertext)))};
        baseline.entries.push(selected);
        checked.set(oid+":"+(i+1),{...selected,ciphertextBase64:b64(ciphertext),
          verifiedCiphertext:true,plaintextAvailable:false,authorizesMutation:false});
        selections.push({objectId:oid,revision:i+1,metadata,
          cekFile:"cek-"+i+".bin",cekSha256Pin:cekPin});
      }
      const serialized=encoder.encode(JSON.stringify({head:baseline.head,
        entries:baseline.entries}));
      const signature=new Uint8Array(await crypto.subtle.sign("Ed25519",
        signer.privateKey,serialized));
      let verifiedGets=0;
      const client={
        async verifyPrivateListingHead() {
          if(!await crypto.subtle.verify("Ed25519",signer.publicKey,
            signature,serialized))throw Error("SIGNED_CATALOG_BAD");
          return {scope,head:baseline.head};
        },
        async readSelectedCiphertext(_baseline,oid,rev){
          const row=checked.get(oid+":"+rev);
          if(!row||!await crypto.subtle.verify("Ed25519",signer.publicKey,
            signature,serialized))throw Error("SIGNED_GET_BAD");
          verifiedGets++;
          return row;
        },
      };
      const trust={ownerPublicKey:signer.publicKey,
        independentOwnerSpkiSha256:random(32),ownerHistoryCheckpoint:{},
        signedDeviceGrant:grant,
        pinnedCurrentHead:{revision:8,epoch:2,digest:ownerDigest}};
      document.cookie="rootark_csrf=disposable-ui-batch; SameSite=Strict";
      window.dispatchEvent(new Event("rootark:workspace-rendered"));
      let opener;
      for(let i=0;i<100;i++){
        opener=document.getElementById("zk1-workspace-open");
        if(opener)break;
        await sleep(20);
      }
      if(!opener)throw Error("NO_ENTRY");
      opener.click();
      let dialog;
      for(let i=0;i<100;i++){
        dialog=document.querySelector("dialog.zk1-workspace-dialog");
        if(dialog?.open)break;
        await sleep(20);
      }
      if(!dialog?.open)throw Error("NO_DIALOG");
      const field=name=>dialog.querySelector('[data-zk1-field="'+name+'"]');
      const action=name=>dialog.querySelector('[data-zk1-action="'+name+'"]');
      const batchButton=action("catalog-delta-text-search");
      const persisted=field("catalog-batch-persist");
      const replaced=field("catalog-batch-replace");
      const confirmed=field("catalog-batch-confirm");
      field("catalog-delta-opt-in").checked=true;
      field("catalog-write-sequence").value="11";
      field("catalog-write-digest").value=baseline.head.digest;
      field("catalog-cas-spki").value=b64(random(32));
      field("catalog-witness-spki").value=b64(random(32));
      const held={client,baseline,csrf:"disposable-ui-batch",epoch:0,
        origin:location.origin,grant:JSON.stringify(grant),
        ownerDigest:b64(ownerDigest),ownerRevision:8,ownerEpoch:2,
        minimumSequence:field("catalog-write-sequence").value,
        minimumDigest:field("catalog-write-digest").value,
        casPin:field("catalog-cas-spki").value,
        witnessPin:field("catalog-witness-spki").value,
        snapshotUrl:field("catalog-snapshot-url").value};
      window.__issue63Fixture={trust,held};
      const setFile=(name,fileList)=>{
        const dt=new DataTransfer();
        for(const file of fileList)dt.items.add(file);
        const input=field(name);
        input.files=dt.files;
        input.dispatchEvent(new Event("change",{bubbles:true}));
      };
      const selection=async(items)=>{
        const manifest=JSON.stringify({schema:"rootark-zk1-local-text-batch/v1",
          entries:items});
        const encoded=encoder.encode(manifest);
        setFile("catalog-batch-manifest",[new File([encoded],"selection.json")]);
        const pin=b64(new Uint8Array(await crypto.subtle.digest("SHA-256",encoded)));
        field("catalog-batch-manifest-pin").value=pin;
        field("catalog-batch-manifest-pin").dispatchEvent(
          new Event("input",{bubbles:true}));
        setFile("catalog-batch-ceks",items.map(item=>
          new File([rawCek],item.cekFile)));
        setFile("catalog-write-key",[new File([metadataRaw],"metadata.bin")]);
        field("catalog-batch-query").value="needle";
        field("catalog-batch-query").dispatchEvent(new Event("input",{bubbles:true}));
      };
      const clickConsent=(replace)=>{
        confirmed.click();persisted.click();
        if(replace)replaced.click();
      };
      const run=async(expected)=>{
        batchButton.click();
        const status=field("status");
        for(let i=0;i<800;i++){
          if(!batchButton.disabled && (status.textContent.includes("Busca protegida local:")
            || status.textContent.includes("Operação recusada:")))break;
          await sleep(20);
        }
        const success=status.textContent.includes("Busca protegida local:");
        if(batchButton.disabled||success!==expected)
          throw Error("UNEXPECTED_BATCH_OUTCOME_"+status.textContent);
        if(confirmed.checked||persisted.checked||replaced.checked)
          throw Error("CONSENT_NOT_ONE_SHOT");
      };
      const localIndex=window.RootarkZk1ProtectedRevisionIndex;
      const indexInput=()=>({grant,ownerHead:{revision:8,epoch:2,digest:b64(ownerDigest)},
        baseline,client,metadataRaw,indexedDBImpl:indexedDB,
        assertLive:()=>true,verifyOwnerGrant:async()=>({
          verifiedCurrent:true,grant,ownerHead:{revision:8,epoch:2,
            digest:b64(ownerDigest)}})});
      phase="owner-batch-A-succeeds";
      await selection(selections.slice(0,128));
      clickConsent(true);
      await run(true);
      if(verifiedGets!==128)throw Error("A_NOT_ALL_VERIFIED");
      const first=await localIndex.search({...indexInput(),query:"selected revision 0001"});
      if(first.indexedCount!==128||first.totalMatches!==1)
        throw Error("A_MISSING_FROM_ENCRYPTED_INDEX");
      phase="fresh-B-default-append-denied-without-replace";
      await selection(selections.slice(1,129));
      if(confirmed.checked||persisted.checked||replaced.checked)
        throw Error("B_INHERITED_CONSENT");
      clickConsent(false);
      await run(false);
      const preserved=await localIndex.search({...indexInput(),query:"selected revision 0001"});
      if(preserved.indexedCount!==128||preserved.totalMatches!==1)
        throw Error("UNAUTHORIZED_B_ERASED_A");
      phase="fresh-B-explicit-replacement-succeeds";
      await selection(selections.slice(1,129));
      clickConsent(true);
      await run(true);
      const rotated=await localIndex.search({...indexInput(),query:"selected revision 0129"});
      const removed=await localIndex.search({...indexInput(),query:"selected revision 0001"});
      if(rotated.indexedCount!==128||rotated.totalMatches!==1
        ||removed.totalMatches!==0)throw Error("FRESH_REPLACEMENT_NOT_EXACT");
      if(!await (async()=>{try{await first.readPage(0);return false;}
        catch(e){return e.message==="ZK_REVISION_INDEX_DENIED";}})())
        throw Error("OLD_ENCRYPTED_PAGE_SURVIVED_REPLACEMENT");
      metadataRaw.fill(0);rawCek.fill(0);
      out.textContent="EDGE_REPLACE_ONCE_PASS";
    }catch(error){out.textContent="EDGE_REPLACE_ONCE_FAIL:"+phase+":"+error.message;}
  });`;
  let sensitiveRequests = 0;
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Security-Policy",
      "default-src 'none'; script-src 'self'; connect-src 'self'");
    if (request.url.includes("needle") || /\/zk-1\/v1\/(catalog|content)\//.test(request.url))
      sensitiveRequests++;
    const client = /^\/client\/([a-z0-9-]+)\.js$/.exec(request.url)?.[1];
    const content = request.url === "/" ? html
      : request.url === "/bootstrap.js" ? bootstrap
        : request.url === "/probe.js" ? probe
          : client === "rootark-zk1-authenticated-workspace" ? servedWorkspace
            : ["rootark-zk1-file-content", "rootark-zk1-selected-local-preview",
              "rootark-zk1-protected-text-batch", "rootark-zk1-protected-revision-index"]
                .includes(client) ? fs.readFileSync(path.join(root, client + ".js"), "utf8") : null;
    response.writeHead(content === null ? 404 : 200, {
      "Content-Type": request.url === "/" ? "text/html; charset=utf-8"
        : "text/javascript; charset=utf-8",
    });
    response.end(content ?? "");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue63-replace-edge-"));
  const profile = path.join(folder, "edge");
  let browser, socket;
  try {
    browser = spawn(edge, ["--headless=new", "--disable-gpu", "--no-first-run",
      "--disable-extensions", "--no-default-browser-check",
      "--remote-debugging-port=0", "--user-data-dir=" + profile, "about:blank"],
    { stdio: "ignore", windowsHide: true });
    const waitFor = async (fn, timeout = 70_000) => {
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) {
        const value = await fn();
        if (value) return value;
        await new Promise((resolve) => setTimeout(resolve, 90));
      }
      throw Error("EDGE_REPLACE_ONCE_TIMEOUT");
    };
    const port = await waitFor(() => {
      const file = path.join(profile, "DevToolsActivePort");
      if (!fs.existsSync(file)) return null;
      const value = Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]);
      return Number.isSafeInteger(value) && value > 0 ? value : null;
    }, 15_000);
    const tabs = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    const tab = tabs.find((item) => item.type === "page");
    assert.ok(tab?.webSocketDebuggerUrl);
    socket = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    let sequence = 0;
    const waiting = new Map();
    socket.addEventListener("message", ({ data }) => {
      const payload = JSON.parse(data);
      const pending = waiting.get(payload.id);
      if (!pending) return;
      waiting.delete(payload.id);
      if (payload.error) pending.reject(Error(payload.error.message));
      else pending.resolve(payload.result);
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++sequence;
      waiting.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Page.navigate", {
      url: "http://127.0.0.1:" + server.address().port + "/",
    });
    const result = await waitFor(async () => {
      const evalResult = await send("Runtime.evaluate", {
        expression: "document.getElementById('edge-result')?.textContent || null",
        returnByValue: true,
      });
      const value = evalResult.result?.value;
      return typeof value === "string" && /^EDGE_REPLACE_ONCE_(PASS|FAIL)/.test(value)
        ? value : null;
    });
    assert.equal(result, "EDGE_REPLACE_ONCE_PASS");
    assert.equal(sensitiveRequests, 0);
  } finally {
    socket?.close();
    if (browser?.pid) {
      try { execFileSync("taskkill", ["/PID", String(browser.pid), "/T", "/F"],
        { stdio: "ignore", timeout: 10_000 }); }
      catch (_) { browser.kill(); }
    }
    server.closeAllConnections();
    server.close();
    server.unref();
    let removed = false;
    for (let i = 0; i < 12; i++) {
      try { fs.rmSync(folder, { recursive: true, force: true }); removed = true; break; }
      catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 150));
      }
    }
    if (!removed) t.diagnostic("EDGE_REPLACE_ONCE_CLEANUP_PENDING");
  }
});
