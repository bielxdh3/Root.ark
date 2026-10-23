"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
function findRealEdge(platform = process.platform, exists = fs.existsSync) {
  const candidates = platform === "win32"
    ? ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"]
    : platform === "linux"
      ? ["/usr/bin/microsoft-edge-stable", "/usr/bin/microsoft-edge"]
      : [];
  return candidates.find((candidate) => exists(candidate)) || null;
}

async function realEdge(t, origin) {
  const edge = findRealEdge();
  if (!edge) throw Error("REAL_EDGE_NOT_INSTALLED");
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-checkpoint-v2-edge-"));
  const proc = spawn(edge, ["--headless=new", "--disable-gpu", "--no-first-run",
    "--disable-extensions", "--disable-dev-shm-usage", "--remote-debugging-port=0",
    "--user-data-dir=" + profile, "about:blank"],
  { windowsHide: true, stdio: "ignore" });
  let socket;
  t.after(async () => {
    socket?.close();
    if (proc.pid) {
      if (process.platform === "win32") {
        try { execFileSync("taskkill", ["/PID", String(proc.pid), "/T", "/F"],
          { timeout: 10000, stdio: "ignore" }); }
        catch (_) { proc.kill(); }
      } else {
        proc.kill();
      }
    }
    for (let i = 0; i < 30; i++) {
      try { fs.rmSync(profile, { recursive: true, force: true }); break; }
      catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
  });
  async function until(check, label) {
    for (let i = 0; i < 250; i++) {
      const outcome = await check();
      if (outcome) return outcome;
      await new Promise((resolve) => setTimeout(resolve, 60));
    }
    throw Error("REAL_EDGE_CHECKPOINT_TIMEOUT_" + label);
  }
  const port = await until(() => {
    const file = path.join(profile, "DevToolsActivePort");
    return fs.existsSync(file) ? Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]) : null;
  }, "port");
  const pages = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
  socket = new WebSocket(pages.find((item) => item.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  const pending = new Map();
  let nextId = 0;
  socket.addEventListener("message", ({ data }) => {
    const reply = JSON.parse(data), outstanding = pending.get(reply.id);
    if (!outstanding) return;
    pending.delete(reply.id);
    reply.error ? outstanding.reject(Error(reply.error.message))
      : outstanding.resolve(reply.result);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await send("Page.enable");
  await send("Runtime.enable");
  const evaluate = async (source) => {
    const reply = await send("Runtime.evaluate", {
      expression: source, awaitPromise: true, returnByValue: true });
    if (reply.exceptionDetails) throw Error("REAL_EDGE_SCRIPT:"
      + reply.exceptionDetails.text + " " + JSON.stringify(reply.exceptionDetails.exception?.description));
    return reply.result?.value;
  };
  await send("Page.navigate", { url: new URL("checkpoint-v2-browser-test", origin).href });
  await until(() => evaluate("document.readyState==='complete'"), "document");
  try { await until(() => evaluate("!!window.RootarkZk1BrowserAuthorityHeadRelay"), "script"); }
  catch (error) {
    const details = await evaluate(`JSON.stringify({url:location.href,
      title:document.title,body:document.body?.innerText?.slice(0,500),
      scripts:[...document.scripts].map(s=>({src:s.src,type:s.type})),
      protected:!!window.RootarkZk1ProtectedHttpClient})`);
    throw Error(error.message + " " + details);
  }
  return { evaluate };
}

module.exports = { realEdge, findRealEdge };
