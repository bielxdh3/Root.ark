"use strict";

// Isolated same-user *second process*. This file is not imported by sync
// production code, and never accepts operations outside the test's own root.
const crypto = require("node:crypto");
const cp = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

function principal() {
  if (process.platform !== "win32") return `uid:${process.getuid()}`;
  const output = cp.execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"],
    { encoding: "utf8", windowsHide: true });
  const sid = output.match(/S-1-\d+(?:-\d+)+/i)?.[0];
  if (!sid) throw Error("Windows SID not available");
  return sid;
}

const owned = new Map();
const handles = new Map();
let root;
const underRoot = (item) => typeof item === "string"
  && path.isAbsolute(item)
  && path.resolve(item).startsWith(path.resolve(root) + path.sep);

async function perform(data) {
  switch (data.command) {
    case "hello": {
      if (typeof data.root !== "string" || !path.isAbsolute(data.root)) throw Error("root missing");
      root = await fsp.realpath(data.root);
      return { pid: process.pid, principal: principal(), nonce: crypto.randomBytes(8).toString("hex") };
    }
    case "swap": {
      if (!root || !underRoot(data.from) || !underRoot(data.retained)
        || typeof data.bytes !== "string" || data.bytes.length > 4096
        || handles.has(data.label)) throw Error("invalid swap instruction");
      // The original physical file moves to a *different name*. No object
      // belonging to the user or outside the test fixture can be targeted.
      await fsp.rename(data.from, data.retained);
      await fsp.writeFile(data.from, data.bytes, { flag: "wx", mode: 0o600 });
      const foreign = await fsp.open(data.from, "r");
      handles.set(data.label, foreign);
      const stat = await foreign.stat({ bigint: true });
      return { pid: process.pid, principal: principal(),
        dev: String(stat.dev), ino: String(stat.ino), nlink: String(stat.nlink) };
    }
    case "inspect": {
      const handle = handles.get(data.label);
      if (!handle) throw Error("missing retained foreign FD");
      const stat = await handle.stat({ bigint: true });
      const content = await handle.readFile({ encoding: "utf8" });
      return { pid: process.pid, principal: principal(),
        dev: String(stat.dev), ino: String(stat.ino), bytes: content };
    }
    case "release": {
      const handle = handles.get(data.label);
      if (handle) await handle.close();
      handles.delete(data.label);
      return { ok: true };
    }
    default:
      throw Error("unknown command");
  }
}

if (!process.send) throw Error("Standalone IPC child required");
process.on("message", async (message) => {
  const { id, data } = message || {};
  if (!Number.isSafeInteger(id) || id < 1) return;
  try {
    process.send({ id, ok: true, result: await perform(data) });
  } catch (error) {
    process.send({ id, ok: false, error: error?.code || error?.message || "child error" });
  }
});
process.on("disconnect", () => {
  for (const handle of handles.values()) void handle.close();
  handles.clear();
});
