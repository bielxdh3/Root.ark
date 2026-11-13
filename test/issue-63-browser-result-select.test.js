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
      if(!list||!target||!revision||!getButton||getButton.type!=="button")
        throw Error("MISSING_EXPLICIT_PROTECTED_GET");
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
      getButton.click();
      for(let i=0;i<100;i++){
        if(dialog.querySelector('[data-zk1-field="status"]').textContent
          .includes("Operação recusada"))break;
        await sleep(25);
      }
      if(!dialog.querySelector('[data-zk1-field="status"]').textContent
        .includes("Operação recusada"))throw Error("MISSING_AUTH_DENIAL");
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
          : ["rootark-zk1-authenticated-workspace", "rootark-zk1-protected-local-search"]
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
