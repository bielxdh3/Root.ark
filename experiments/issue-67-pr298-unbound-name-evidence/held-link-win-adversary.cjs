"use strict";

// Separate Windows process of same inherited SID. Synthetic test paths only.
const fs = require("node:fs/promises");
const { execFileSync } = require("node:child_process");

function sid() {
  const result = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"],
    { encoding: "utf8" });
  const match = result.match(/S-\d(?:-\d+)+/);
  if (!match) throw new Error("cannot read current Windows user SID");
  return match[0];
}

async function main() {
  const [source, alias, foreignBytes, directory, retainedDirectory] = process.argv.slice(2);
  if (!source || !alias || !foreignBytes) throw Error("synthetic source/alias required");
  await fs.rename(source, alias);
  const foreign = await fs.open(source, "wx", 0o600);
  try {
    await foreign.writeFile(foreignBytes);
    await foreign.sync();
  } finally { await foreign.close(); }
  if (directory && retainedDirectory) {
    await fs.rename(directory, retainedDirectory);
    await fs.mkdir(directory);
  }
  process.stdout.write(JSON.stringify({ pid: process.pid, sid: sid() }) + "\n");
}

main().catch(error => {
  process.stderr.write(String(error.stack || error) + "\n");
  process.exitCode = 1;
});
