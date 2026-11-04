"use strict";

// Operator process: node scripts/zk1-historical-recovery-operator.js --serve CONFIG [--bootstrap]
// TLS bridge process (internal): --bridge CONFIG, binary v8 protocol on stdio.
const v8 = require("node:v8");
const fs = require("node:fs");
const path = require("node:path");
const { createHistoricalRecoveryOperatorServer, invokeRemote, readConfig } =
  require("../src/services/zk1HistoricalRecoveryOperatorHttps");

async function main() {
  const [, , mode, configPath, extra] = process.argv;
  if (!configPath || !["--serve", "--bridge", "--inspect",
    "--advance-policy"].includes(mode)) throw Error("OPERATOR_ARGS");
  if (mode === "--inspect") {
    if (extra !== undefined) throw Error("OPERATOR_ARGS");
    const [ownerGeneration, head] = await Promise.all([
      invokeRemote(configPath, "loadOwnerGeneration", []),
      invokeRemote(configPath, "loadHead", []),
    ]);
    process.stdout.write(JSON.stringify({ ownerGeneration, head }) + "\n");
    return;
  }
  if (mode === "--advance-policy") {
    const [, , , , generation, policyFilename] = process.argv;
    if (process.argv.length !== 6 || !Number.isSafeInteger(Number(generation))
      || Number(generation) < 0 || !path.isAbsolute(policyFilename)) {
      throw Error("OPERATOR_ARGS");
    }
    const { assertPrivateSqliteFile, assertPrivateSqliteAuthorityDirectory } =
      require("../src/services/zk1PrivateSqlitePath");
    assertPrivateSqliteAuthorityDirectory(policyFilename);
    assertPrivateSqliteFile(policyFilename);
    const policy = JSON.parse(fs.readFileSync(policyFilename, "utf8"));
    const advanced = await invokeRemote(configPath, "advanceOwnerPolicy",
      [Number(generation), policy]);
    if (advanced !== true) throw Error("OPERATOR_POLICY_CAS_STALE");
    process.stdout.write("OPERATOR_POLICY_GENERATION_ADVANCED_AND_QUARANTINED\n");
    return;
  }
  if (mode === "--serve") {
    if (extra !== undefined && extra !== "--bootstrap") throw Error("OPERATOR_ARGS");
    const config = readConfig(configPath);
    const server = createHistoricalRecoveryOperatorServer(config,
      { bootstrapNew: extra === "--bootstrap" });
    server.listen(config.server.port, config.server.host, () => {
      // No trust material in readiness output.
      process.stdout.write(JSON.stringify({ ready: true,
        port: server.address().port }) + "\n");
    });
    return;
  }
  if (extra !== undefined) throw Error("OPERATOR_ARGS");
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 256 * 1024) throw Error("OPERATOR_BODY_LIMIT");
    chunks.push(chunk);
  }
  const input = v8.deserialize(Buffer.concat(chunks));
  if (!input || typeof input !== "object" || Array.isArray(input)
    || Reflect.ownKeys(input).length !== 2
    || typeof input.method !== "string" || !Array.isArray(input.args)) {
    throw Error("OPERATOR_BRIDGE_INPUT");
  }
  const value = await invokeRemote(configPath, input.method, input.args);
  process.stdout.write(v8.serialize({ ok: true, value }));
}
main().catch(() => { process.stderr.write("HISTORICAL_RECOVERY_OPERATOR_DENIED\n");
  process.exitCode = 1; });
