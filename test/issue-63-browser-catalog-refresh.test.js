"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

test("real Edge: refreshing catalog results clears the old list and summary even when loading fails", {
  timeout: 40_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("Windows Edge unavailable");
    return;
  }
  const workspace = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-authenticated-workspace.js"), "utf8");
  const html = "<!doctype html><meta charset='utf-8'>"
    + "<section class='protected-client-panel'><p id='protectedClientStatus'></p></section>"
    + "<output id='edge-result'>PENDING</output>"
    + "<script defer src='/bootstrap.js'></script>"
    + "<script defer src='/client/rootark-zk1-authenticated-workspace.js'></script>"
    + "<script defer src='/probe.js'></script>";
  const bootstrap = "window.RootarkApi={get:async()=>({enabled:true,"
    + "securityVersion:2,signedHistoryRequired:true,opaqueCatalogV1:true})};";
  const probe = `window.addEventListener("load",async()=>{
    const output=document.getElementById("edge-result");
    const wait=async find=>{
      for(let i=0;i<100;i++){
        const value=find(); if(value)return value;
        await new Promise(resolve=>setTimeout(resolve,20));
      }
      throw Error("UI_TIMEOUT");
    };
    try{
      window.dispatchEvent(new Event("rootark:workspace-rendered"));
      (await wait(()=>document.getElementById("zk1-workspace-open"))).click();
      const dialog=await wait(()=>document.querySelector("dialog[open]"));
      const list=dialog.querySelector('[data-zk1-field="catalog-delta-private-list"]');
      const summary=dialog.querySelector('[data-zk1-field="catalog-delta-summary"]');
      const refresh=dialog.querySelector('[data-zk1-action="catalog-delta-list"]');
      const status=dialog.querySelector('[data-zk1-field="status"]');
      if(!list||!summary||!refresh||!status)throw Error("MISSING_CONTROLS");
      const row=document.createElement("p");
      row.textContent="Previous example result";
      list.append(row);
      summary.textContent="1 result";
      refresh.click();
      if(list.children.length!==0||summary.textContent!=="")
        throw Error("STALE_DURING_REFRESH");
      await wait(()=>!refresh.disabled&&status.textContent.includes("Operação recusada"));
      if(list.children.length!==0||summary.textContent!=="")
        throw Error("STALE_AFTER_LOAD_FAILURE");
      output.textContent="EDGE_REFRESH_PASS";
    }catch(error){output.textContent="EDGE_REFRESH_FAIL:"+error.message;}
  });`;
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'");
    const content = request.url === "/" ? html
      : request.url === "/bootstrap.js" ? bootstrap
      : request.url === "/probe.js" ? probe
      : request.url === "/client/rootark-zk1-authenticated-workspace.js" ? workspace
      : null;
    response.writeHead(content === null ? 404 : 200, {
      "Content-Type": request.url === "/" ? "text/html; charset=utf-8" : "text/javascript; charset=utf-8",
    });
    response.end(content ?? "");
  });
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk63-refresh-edge-"));
  t.after(async () => {
    if (server.listening) await new Promise(resolve => server.close(resolve));
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const response = await promisify(execFile)(edge, ["--headless=new", "--disable-gpu",
    "--no-first-run", "--disable-extensions", "--no-default-browser-check",
    "--virtual-time-budget=12000", "--user-data-dir=" + path.join(folder, "edge"),
    "--dump-dom", "http://127.0.0.1:" + server.address().port + "/"], {
    timeout: 35000, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
  });
  const result = response.stdout.match(/<output id="edge-result">([^<]*)<\/output>/)?.[1] || "MISSING";
  assert.equal(result, "EDGE_REFRESH_PASS");
});
