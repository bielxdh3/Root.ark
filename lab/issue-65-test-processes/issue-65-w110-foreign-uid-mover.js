"use strict";

// Invoked as an unprivileged UNIX user solely against a disposable fixture.
const fs = require("node:fs");
const path = require("node:path");
const [stage, victim] = process.argv.slice(2);
const base = path.dirname(stage);
if (typeof stage !== "string" || typeof victim !== "string"
  || base !== path.dirname(victim)
  || !path.basename(base).startsWith("zk65-w110-unsafe-")
  || !path.basename(stage).startsWith("zk1-cloud-recovery-")
  || !path.basename(victim).startsWith("w110-private-victim-")) process.exit(9);
const parked = `${stage}-parked`;
if (fs.existsSync(parked)) process.exit(10);
fs.renameSync(stage, parked);
fs.renameSync(victim, stage);
process.stdout.write("FOREIGN_UID_RENAMED\n");
