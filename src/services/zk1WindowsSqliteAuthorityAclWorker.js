"use strict";
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { NATIVE_ACL, TRUSTED_POWERSHELL } = require("../../services/chunkUploadWindowsAcl");

// The same native owner/DACL/ancestry verification used above, executed by a
// private resident PowerShell worker. A fresh Windows ACL scan occurs for
// EVERY operation; only Add-Type compilation is reused. Never cache trust.
// Unlike a fresh synchronous PowerShell launch, this cannot stall the HTTPS
// event loop long enough to trigger a healthy mTLS client's absolute deadline.
function createWindowsPrivateSqliteAclVerifier() {
  if (process.platform !== "win32") return {
    verify: async () => {}, stop() {},
  };
  const native = NATIVE_ACL.replace(/^[ \t]*\/\/[^\r\n]*\r?\n/gm, "")
    .replace(/^[ \t]*\r?\n/gm, "");
  const script = `$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
${native}
'@
` + String.raw`
[Console]::Out.WriteLine('READY')
[Console]::Out.Flush()
while ($true) {
  $line = [Console]::ReadLine()
  if ($null -eq $line) { break }
  if ($line.Length -gt 131072) { break }
  $parts = $line.Split('|')
  if ($parts.Length -ne 2 -or $parts[0] -cnotmatch '^[a-f0-9]{32}$') { break }
  $nonce = $parts[0]
  try {
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $item = $utf8.GetString([Convert]::FromBase64String($parts[1]))
    [void][RootarkChunkAclNative]::Ensure($item, 'verify')
    [Console]::Out.WriteLine($nonce + '|OK')
  } catch {
    [Console]::Out.WriteLine($nonce + '|DENY')
  }
  [Console]::Out.Flush()
}
`;
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  const MAX_WAITING = 16;
  const CHECK_MS = 12000;
  let worker = null, ready = false, closed = false, output = "", stderr = "";
  let active = null;
  const queue = [];
  const denial = () => new Error("Windows SQLite authority ACL validation failed");
  function complete(job, error) {
    if (job.finished) return;
    job.finished = true;
    clearTimeout(job.timer);
    if (error) job.reject(denial());
    else job.resolve();
  }
  function failWorker() {
    const old = worker;
    worker = null; ready = false; output = ""; stderr = "";
    if (old) {
      old.stdout.removeAllListeners("data");
      old.stderr.removeAllListeners("data");
      old.kill();
    }
    if (active) { complete(active, true); active = null; }
    while (queue.length) complete(queue.shift(), true);
  }
  function advance() {
    if (!ready || !worker || active || closed) return;
    let next;
    do { next = queue.shift(); } while (next?.finished);
    if (!next) return;
    active = next;
    next.nonce = crypto.randomBytes(16).toString("hex");
    const path64 = Buffer.from(next.path, "utf8").toString("base64");
    try { worker.stdin.write(next.nonce + "|" + path64 + "\n"); }
    catch (_) { failWorker(); }
  }
  function lineReceived(line) {
    if (!ready) {
      if (line !== "READY") return failWorker();
      ready = true;
      advance();
      return;
    }
    if (!active || (line !== active.nonce + "|OK" && line !== active.nonce + "|DENY")) {
      return failWorker();
    }
    const done = active;
    active = null;
    complete(done, line.endsWith("|DENY"));
    advance();
  }
  function start() {
    if (worker || closed) return;
    try {
      const child = spawn(TRUSTED_POWERSHELL, ["-NoLogo", "-NoProfile",
        "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", encoded], {
        windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
      });
      worker = child;
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (part) => {
        if (worker !== child) return;
        output += part;
        if (output.length > 4096) return failWorker();
        let pos;
        while (worker === child && (pos = output.indexOf("\n")) !== -1) {
          const line = output.slice(0, pos).replace(/\r$/, "");
          output = output.slice(pos + 1);
          lineReceived(line);
        }
      });
      child.stderr.on("data", (part) => {
        if (worker !== child) return;
        stderr += part.toString("utf8");
        const harmless = "#< CLIXML\r\n";
        if (!harmless.startsWith(stderr) && stderr !== harmless) failWorker();
      });
      child.stdin.on("error", () => { if (worker === child) failWorker(); });
      child.on("error", () => { if (worker === child) failWorker(); });
      child.on("exit", () => { if (worker === child) failWorker(); });
    } catch (_) { failWorker(); }
  }
  return {
    verify(directory) {
      if (closed || typeof directory !== "string" || !directory.length
        || Buffer.byteLength(directory, "utf8") > 65000
        || queue.length >= MAX_WAITING) return Promise.reject(denial());
      return new Promise((resolve, reject) => {
        const job = { path: directory, resolve, reject, finished: false };
        job.timer = setTimeout(failWorker, CHECK_MS);
        queue.push(job);
        start();
        advance();
      });
    },
    stop() { closed = true; failWorker(); },
  };
}

module.exports = { createWindowsPrivateSqliteAclVerifier };
