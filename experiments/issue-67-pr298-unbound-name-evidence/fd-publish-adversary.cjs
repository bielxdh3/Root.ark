"use strict";

// Run in a DIFFERENT Linux process/UID-independent namespace actor.
// Inputs are disposable files created by the lab test; never accept real paths.
const fs = require("node:fs/promises");

async function main() {
  const [source, retained, foreignBytes, destinationDir, movedDestinationDir] = process.argv.slice(2);
  if (!source || !retained || !foreignBytes) throw new Error("synthetic args required");
  // The original opened inode moves to a new name; then an unrelated inode
  // takes the exact source pathname before either publication syscall.
  await fs.rename(source, retained);
  const foreign = await fs.open(source, "wx", 0o600);
  try {
    await foreign.writeFile(foreignBytes);
    await foreign.sync();
    if (destinationDir && movedDestinationDir) {
      // Also replace the ancestor name. Native publisher has the original
      // destination dirfd; a pathname-based publisher would follow the decoy.
      await fs.rename(destinationDir, movedDestinationDir);
      await fs.mkdir(destinationDir);
    }
    const stat = await foreign.stat({ bigint: true });
    process.stdout.write(JSON.stringify({ pid: process.pid, uid: process.getuid(),
      dev: String(stat.dev), ino: String(stat.ino) }) + "\n");
  } finally {
    await foreign.close();
  }
}

main().catch((error) => {
  process.stderr.write(String(error.stack || error) + "\n");
  process.exitCode = 1;
});
