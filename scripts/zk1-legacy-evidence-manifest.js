"use strict";

// Explicit operator opt-in. This command does not modify either the live
// legacy data or any migration, cloud, trash or backup retention state.
const path = require("node:path");
const { inspectZk1LegacyEvidenceManifest } =
  require("../src/services/zk1LegacyEvidenceManifest");

async function main(argv) {
  const allowed = new Map([
    ["--database", "databasePath"], ["--uploads", "uploadsDir"],
    ["--temp", "tempDir"], ["--trash", "trashDir"],
    ["--backups", "backupsDir"],
  ]);
  const args = { optIn: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--opt-in" && !args.optIn) {
      args.optIn = true;
      continue;
    }
    const key = allowed.get(argv[i]);
    if (!key || args[key] !== undefined || i + 1 >= argv.length
      || !path.isAbsolute(argv[i + 1]))
      throw Error("INVALID_INVENTORY_ARGUMENT");
    args[key] = argv[++i];
  }
  if (!args.optIn || !args.databasePath) throw Error("INVENTORY_REQUIRES_EXPLICIT_OPT_IN");
  const result = await inspectZk1LegacyEvidenceManifest(args);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}
main(process.argv.slice(2)).catch(() => {
  // Never print source paths, filenames, SQL data or caller-supplied arguments.
  process.stderr.write("Legacy manifest unavailable: check opt-in, paths and evidence.\n");
  process.exitCode = 2;
});
