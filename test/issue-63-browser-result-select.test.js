"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

test("real Edge CSP: verified local results select an opaque object without HTML/network or stale session replay", {
  timeout: 40_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("Windows Edge unavailable");
    return;
  }
  const root = path.join(__dirname, "../public/client");
  const html = "<!doctype html><meta charset='utf-8'>"
    + "<section class='protected-client-panel'><p id='protectedClientStatus'></p></section>"
    + "<output id='edge-result'>PENDING</output>"
    + "<script defer src='/bootstrap.js'></script>"
    + "<script defer src='/client/rootark-zk1-authenticated-workspace.js'></script>"
    + "<script defer src='/client/rootark-zk1-protected-local-search.js'></script>"
    + "<script defer src='/client/rootark-zk1-file-content.js'></script>"
    + "<script defer src='/client/rootark-zk1-selected-local-preview.js'></script>"
    + "<script defer src='/client/rootark-zk1-protected-text-batch.js'></script>"
    + "<script defer src='/probe.js'></script>";
  const bootstrap = "window.RootarkApi={get:async()=>({enabled:true,"
    + "securityVersion:2,signedHistoryRequired:true,opaqueCatalogV1:true})};";
  const probe = `window.addEventListener("load",async()=>{
    const out=document.getElementById("edge-result");
    const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
    try {
      window.dispatchEvent(new Event("rootark:workspace-rendered"));
      let opener;
      for(let i=0;i<80;i++){
        opener=document.getElementById("zk1-workspace-open");
        if(opener)break;
        await sleep(30);
      }
      if(!opener)throw Error("NO_WORKSPACE_ENTRY");
      opener.click();
      let dialog;
      for(let i=0;i<80;i++){
        dialog=document.querySelector("dialog.zk1-workspace-dialog");
        if(dialog?.open)break;
        await sleep(30);
      }
      if(!dialog?.open)throw Error("NO_AUTH_DIALOG");
      const list=dialog.querySelector('[data-zk1-field="catalog-delta-private-list"]');
      const target=dialog.querySelector('[data-zk1-field="catalog-write-id"]');
      const revision=dialog.querySelector('[data-zk1-field="catalog-delta-read-revision"]');
      const getButton=dialog.querySelector('[data-zk1-action="catalog-delta-get"]');
      const batchButton=dialog.querySelector('[data-zk1-action="catalog-delta-text-search"]');
      const allTermsToggle=dialog.querySelector('[data-zk1-field="catalog-batch-all-terms"]');
      if(!list||!target||!revision||!getButton||getButton.type!=="button"
        ||!batchButton||batchButton.type!=="button"
        ||!allTermsToggle||allTermsToggle.type!=="checkbox"||allTermsToggle.checked)
        throw Error("MISSING_EXPLICIT_PROTECTED_GET");
      const progress=dialog.querySelector('[data-zk1-field="catalog-batch-progress"]');
      const cancel=dialog.querySelector('[data-zk1-action="catalog-delta-text-cancel"]');
      if(!progress||progress.getAttribute("role")!=="status"
        ||!cancel||cancel.textContent!=="Cancelar busca"||!cancel.disabled)
        throw Error("MISSING_ACCESSIBLE_CANCEL_PROGRESS");
      document.cookie="rootark_csrf=disposable-browser-session; SameSite=Strict";
      if(batchButton.disabled)throw Error("BATCH_BUTTON_INITIAL_DISABLED");
      batchButton.click();
      if(cancel.disabled)throw Error("CANCEL_NOT_AVAILABLE_DURING_BUSY");
      cancel.click();
      if(!progress.textContent.includes("Cancelando"))
        throw Error("CANCEL_NOT_ACKNOWLEDGED");
      for(let i=0;i<100&&batchButton.disabled;i++)await sleep(20);
      if(batchButton.disabled||!cancel.disabled)
        throw Error("CANCEL_NOT_CLEANED");
      const id="AAAAAAAAAAAAAAAAAAAAAA";
      const malicious="<img src=x onerror=alert(1)> secret-local-only";
      let active=true;
      const verify=()=>active;
      window.RootarkZk1ProtectedLocalSearch.renderVerifiedResults(
        list,[{name:malicious,objectId:id,revision:7,epoch:2,
          logicalTrashCandidate:false}],target,verify,revision);
      const button=list.querySelector("button");
      if(!button||button.type!=="button"||button.textContent!=="Selecionar objeto")
        throw Error("NOT_SELECTABLE");
      if(list.querySelector("img")||!list.textContent.includes(malicious))
        throw Error("HTML_UNSAFE");
      button.click();
      if(target.value!==id||revision.value!=="7"||document.activeElement!==target)
        throw Error("OPAQUE_SELECTION_FAILED");
      target.value="";
      revision.value="";
      active=false;
      button.click();
      if(target.value!==""||revision.value!=="")throw Error("STALE_RESULT_SELECTED");
      active=true;
      list.replaceChildren();
      button.click();
      if(target.value!==""||revision.value!=="")throw Error("DETACHED_RESULT_SELECTED");
      const pageOne={name:"history-0000",objectId:id,revision:7,epoch:2,
        logicalTrashCandidate:false};
      const pageTwo={name:"history-0100",objectId:id,revision:8,epoch:2,
        logicalTrashCandidate:false};
      let pageReads=0;
      const readPage=async(offset)=>{
        if(offset!==100)throw Error("UNEXPECTED_PAGE_OFFSET");
        pageReads++;
        return {entries:[pageTwo],offset,totalMatches:101,pageSize:100,
          hasNext:false,hasPrevious:true,plaintextSentToServer:false,
          independentlySignedCatalog:true,authorizesMutation:false};
      };
      window.RootarkZk1ProtectedLocalSearch.renderVerifiedResults(
        list,[pageOne],target,verify,revision,{offset:0,totalMatches:101,
          pageSize:100,hasNext:true,hasPrevious:false,readPage});
      const next=list.querySelector('[data-zk1-page="next"]');
      if(!next||next.type!=="button")throw Error("MISSING_NEXT_PAGE");
      next.click();
      for(let i=0;i<100&&!list.textContent.includes("history-0100");i++)await sleep(10);
      if(pageReads!==1||!list.textContent.includes("history-0100")
        ||list.textContent.includes("history-0000"))throw Error("PAGE_NAVIGATION_FAILED");
      const previous=list.querySelector('[data-zk1-page="previous"]');
      if(!previous)throw Error("MISSING_PREVIOUS_PAGE");
      active=false;
      previous.click();
      await sleep(40);
      if(pageReads!==1)throw Error("STALE_PAGE_NAVIGATION");
      active=true;
      list.replaceChildren();
      getButton.click();
      for(let i=0;i<100;i++){
        if(dialog.querySelector('[data-zk1-field="status"]').textContent
          .includes("Operação recusada"))break;
        await sleep(25);
      }
      if(!dialog.querySelector('[data-zk1-field="status"]').textContent
        .includes("Operação recusada"))throw Error("MISSING_AUTH_DENIAL");
      const b64=bytes=>btoa(String.fromCharCode(...bytes))
        .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"");
      const scope={account_id:id,compartment_id:id,keyring_id:id};
      const metadata={...scope,object_id:id,version_id:id,
        parent_version_id:null,epoch:2,kind:"file"};
      const raw=crypto.getRandomValues(new Uint8Array(32));
      const cek=await window.RootarkZk1FileContent.importFileCek(raw);
      const content=new TextEncoder().encode("<img src=x onerror=alert(1)> secret-local-only");
      const sealed=await window.RootarkZk1FileContent.encryptFile({cek,metadata,
        name:"local.txt",mediaType:"text/plain",data:content});
      const hash=b64(new Uint8Array(await crypto.subtle.digest("SHA-256",raw)));
      const ciphertextDigestBase64=b64(new Uint8Array(
        await crypto.subtle.digest("SHA-256",sealed)));
      const selected={objectId:id,revision:7,epoch:2,ciphertextDigestBase64};
      const ownerDigest=b64(crypto.getRandomValues(new Uint8Array(32)));
      const checked={...selected,ciphertextBase64:b64(sealed),
        verifiedCiphertext:true,plaintextAvailable:false,authorizesMutation:false};
      const opened=await window.RootarkZk1SelectedLocalPreview.open({
        selected,checked,metadata,rawCek:raw,cekSha256Pin:hash,
        grant:{...scope,device_id:"device",current_epoch:2,
          manifest_revision:8,manifest_digest:ownerDigest,revoked_at_epoch:null},
        ownerHead:{revision:8,epoch:2,digest:ownerDigest},
        baseline:{head:{sequence:11,digest:ownerDigest},entries:[selected]},
        assertLive:()=>true
      });
      const pane=dialog.querySelector('[data-zk1-field="catalog-delta-preview"]');
      if(!pane||!opened.text.includes("secret-local-only"))throw Error("PREVIEW_DENIED");
      pane.textContent=opened.text;
      if(pane.querySelector("img"))throw Error("PREVIEW_XSS");
      let batchGets=0;
      const found=await window.RootarkZk1ProtectedTextBatch.search({
        query:"SECRET-LOCAL-ONLY",
        items:[{selected,metadata,rawCek:raw,cekSha256Pin:hash}],
        grant:{...scope,device_id:"device",current_epoch:2,
          manifest_revision:8,manifest_digest:ownerDigest,revoked_at_epoch:null},
        ownerHead:{revision:8,epoch:2,digest:ownerDigest},
        baseline:{head:{sequence:11,digest:ownerDigest},entries:[selected]},
        assertLive:()=>true,
        getChecked:async(objectId,rev)=>{
          batchGets++;
          if(objectId!==id||rev!==7)throw Error("BATCH_ID_LEAK");
          return checked;
        }
      });
      if(found.totalSearched!==1||found.totalMatches!==1||batchGets!==1
        ||found.plaintextSentToServer!==false
        ||!found.matches[0].excerpt.includes("secret-local-only"))
        throw Error("BATCH_TEXT_SEARCH_DENIED");
      const batchPane=dialog.querySelector('[data-zk1-field="catalog-delta-text-results"]');
      if(!batchPane)throw Error("MISSING_LOCAL_BATCH_RESULTS");
      batchPane.textContent=found.matches[0].excerpt;
      if(batchPane.querySelector("img"))throw Error("BATCH_PREVIEW_XSS");
      const nine=[];
      const signed=new Map();
      for(let index=0;index<9;index++){
        const oid=b64(crypto.getRandomValues(new Uint8Array(16)));
        const rec={...metadata,object_id:oid};
        const keyRaw=crypto.getRandomValues(new Uint8Array(32));
        const key=await window.RootarkZk1FileContent.importFileCek(keyRaw);
        const cipher=await window.RootarkZk1FileContent.encryptFile({cek:key,
          metadata:rec,name:"doc-"+index+".txt",mediaType:"text/plain",
          data:new TextEncoder().encode("local-window secret-local-only "+index)});
        const exact={objectId:oid,revision:7,epoch:2,
          ciphertextDigestBase64:b64(new Uint8Array(
            await crypto.subtle.digest("SHA-256",cipher)))};
        nine.push({selected:exact,metadata:rec,cekFile:"key-"+index,
          cekSha256Pin:b64(new Uint8Array(
            await crypto.subtle.digest("SHA-256",keyRaw)))});
        signed.set("key-"+index,{keyRaw,checked:{...exact,
          ciphertextBase64:b64(cipher),verifiedCiphertext:true,
          plaintextAvailable:false,authorizesMutation:false}});
      }
      const multiple={...scope,device_id:"device",current_epoch:2,
        manifest_revision:8,manifest_digest:ownerDigest,revoked_at_epoch:null};
      const batchBaseline={head:{sequence:11,digest:ownerDigest},
        entries:nine.map(row=>row.selected)};
      const progressCalls=[];
      const completed=await window.RootarkZk1ProtectedTextBatch.search({
        query:"secret-local-only",items:nine,grant:multiple,
        ownerHead:{revision:8,epoch:2,digest:ownerDigest},
        baseline:batchBaseline,assertLive:()=>true,
        getChecked:async(oid,rev)=>signed.get(nine.find(item=>
          item.selected.objectId===oid&&item.selected.revision===rev)?.cekFile)?.checked,
        readCek:async(name)=>new Uint8Array(signed.get(name).keyRaw),
        onProgress:({completed,total})=>progressCalls.push(completed+"/"+total),
        isCancelled:()=>false
      });
      if(completed.totalSearched!==9||completed.totalMatches!==9
        ||progressCalls.join()!=="8/9,9/9")
        throw Error("EDGE_MULTI_WINDOW_WRONG");
      const allTerms=await window.RootarkZk1ProtectedTextBatch.search({
        query:"SECRET-LOCAL-ONLY local-window",matchMode:"all-terms",
        items:nine,grant:multiple,
        ownerHead:{revision:8,epoch:2,digest:ownerDigest},
        baseline:batchBaseline,assertLive:()=>true,
        getChecked:async(oid,rev)=>signed.get(nine.find(item=>
          item.selected.objectId===oid&&item.selected.revision===rev)?.cekFile)?.checked,
        readCek:async(name)=>new Uint8Array(signed.get(name).keyRaw),
        isCancelled:()=>false
      });
      if(allTerms.totalMatches!==9||allTerms.totalSearched!==9
        ||allTerms.plaintextSentToServer!==false)
        throw Error("EDGE_ALL_TERMS_FAILED");
      batchPane.textContent=completed.matches.map(item=>item.excerpt).join(String.fromCharCode(10));
      if(batchPane.querySelector("img"))throw Error("MULTI_WINDOW_HTML_LEAK");
      const abortProgress=[];
      let stopped=false, getCount=0;
      let rejected=false;
      try{
        await window.RootarkZk1ProtectedTextBatch.search({
          query:"secret-local-only",items:nine,grant:multiple,
          ownerHead:{revision:8,epoch:2,digest:ownerDigest},
          baseline:batchBaseline,assertLive:()=>true,
          getChecked:async(oid,rev)=>{
            getCount++;
            return signed.get(nine.find(item=>item.selected.objectId===oid
              &&item.selected.revision===rev)?.cekFile)?.checked;
          },
          readCek:async(name)=>new Uint8Array(signed.get(name).keyRaw),
          onProgress:({completed})=>{abortProgress.push(completed);stopped=true;},
          isCancelled:()=>stopped
        });
      }catch(error){rejected=error.message==="ZK_BATCH_TEXT_SEARCH_DENIED";}
      if(!rejected||getCount!==8||abortProgress.join()!=="8")
        throw Error("EDGE_CANCEL_RELEASED_PARTIAL");
      target.dispatchEvent(new Event("input",{bubbles:true}));
      if(pane.textContent!==""||batchPane.textContent!=="")
        throw Error("PREVIEW_NOT_ZEROED_ON_CHANGE");
      pane.textContent=opened.text;
      batchPane.textContent=found.matches[0].excerpt;
      window.dispatchEvent(new Event("rootark:logout"));
      if(pane.textContent!==""||batchPane.textContent!=="")
        throw Error("PREVIEW_NOT_ZEROED_ON_LOGOUT");
      raw.fill(0);
      out.textContent="EDGE_PROTECTED_SELECT_PASS";
    }catch(error){out.textContent="EDGE_PROTECTED_SELECT_FAIL:"+error.message;}
  });`;
  let sensitiveRequests = 0;
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Security-Policy",
      "default-src 'none'; script-src 'self'; connect-src 'self'");
    if (request.url.includes("secret-local-only")
      || /\/zk-1\/v1\/(catalog|content)\//.test(request.url)) sensitiveRequests++;
    const file = /^\/client\/([a-z0-9-]+)\.js$/.exec(request.url)?.[1];
    const content = request.url === "/" ? html
      : request.url === "/bootstrap.js" ? bootstrap
        : request.url === "/probe.js" ? probe
        : ["rootark-zk1-authenticated-workspace", "rootark-zk1-protected-local-search",
          "rootark-zk1-file-content", "rootark-zk1-selected-local-preview",
          "rootark-zk1-protected-text-batch"]
            .includes(file) ? fs.readFileSync(path.join(root, file + ".js"), "utf8") : null;
    response.writeHead(content === null ? 404 : 200, {
      "Content-Type": request.url === "/" ? "text/html; charset=utf-8"
        : "text/javascript; charset=utf-8",
    });
    response.end(content ?? "");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk63-select-edge-"));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
  });
  const response = await promisify(execFile)(edge, ["--headless=new", "--disable-gpu",
    "--no-first-run", "--disable-extensions", "--no-default-browser-check",
    "--virtual-time-budget=12000", "--user-data-dir=" + path.join(folder, "edge"),
    "--dump-dom", "http://127.0.0.1:" + server.address().port + "/"], {
    timeout: 35000, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
  });
  assert.match(response.stdout, /EDGE_PROTECTED_SELECT_PASS/);
  assert.doesNotMatch(response.stdout, /EDGE_PROTECTED_SELECT_FAIL/);
  assert.equal(sensitiveRequests, 0);
});
