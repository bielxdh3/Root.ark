const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const modulePath = (relative) => JSON.stringify(path.join(ROOT, relative));

test("restart removes file-set pre-image temps after interrupted copy and replacement", { timeout: 60_000 }, () => {
  for (const boundary of ["copy", "delete", "rename"]) {
    const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-preimage-recovery-"));
    const env = {
      ...process.env,
      NODE_ENV: "test",
      DB_ENABLED: "false",
      BACKUP_ENABLED: "true",
      BACKUP_INCLUDE_UPLOADS: "true",
      BACKUP_INCLUDE_TEMP: "false",
      BACKUP_RETENTION_COUNT: "20",
      ROOTARK_RESTORE_INSTANCE_COUNT: "1",
      ROOTARK_INSTANCE_ID: "fixture-file-preimage",
      JWT_SECRET: "j".repeat(48),
      ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    };
    const prepare = [
      'const fs=require("node:fs");',
      "const backup=require(" + modulePath("services/backupService") + ");",
      "const restore=require(" + modulePath("services/restoreService") + ");",
      'fs.mkdirSync("data",{recursive:true});fs.mkdirSync("uploads",{recursive:true});',
      'fs.writeFileSync("data/runtime.json",JSON.stringify({state:"archived"}));',
      'fs.writeFileSync("uploads/file.txt","archived-upload");',
      "(async()=>{",
      'const saved=await backup.createBackup({createdBy:"fixture"});',
      'fs.writeFileSync("data/runtime.json",JSON.stringify({state:"live",payload:"L".repeat(2*1024*1024)}));',
      'fs.writeFileSync("uploads/file.txt","live-upload");',
      'await restore.restoreBackup(saved.id,{confirmation:"RESTORE",failureInjector(step){if(step==="restore.uploads.cleared")process.exit(86)}});',
      "process.exit(3);",
      '})().catch(error=>{console.error(error);process.exit(2)});',
    ].join("\n");
    const interruptLines = [
      'const fs=require("node:fs"),path=require("node:path");',
      "const restore=require(" + modulePath("services/restoreService") + ");",
      'const destination=path.resolve("data/runtime.json"),dataRoot=path.resolve("data")+path.sep;',
      "const originalOpen=fs.openSync,originalWrite=fs.writeSync,originalRemove=fs.rmSync,originalRename=fs.renameSync;",
      "const tempFds=new Set();let tempPath=null;",
      'fs.openSync=function(target,flags,...args){const fd=originalOpen.call(this,target,flags,...args);if(flags==="wx"&&path.resolve(String(target)).startsWith(dataRoot)&&path.basename(String(target)).startsWith("runtime.json.")&&String(target).endsWith(".restore-preimage")){tempFds.add(fd);tempPath=String(target)}return fd};',
    ];
    if (boundary === "copy") {
      interruptLines.push('fs.writeSync=function(fd,...args){const result=originalWrite.call(this,fd,...args);if(tempFds.has(fd))process.exit(87);return result};');
    } else if (boundary === "delete") {
      interruptLines.push('fs.rmSync=function(target,...args){const result=originalRemove.call(this,target,...args);if(path.resolve(String(target))===destination&&tempPath&&fs.existsSync(tempPath))process.exit(87);return result};');
    } else {
      interruptLines.push('fs.renameSync=function(source,target,...args){const result=originalRename.call(this,source,target,...args);if(tempPath&&path.resolve(String(source))===path.resolve(tempPath))process.exit(87);return result};');
    }
    interruptLines.push("restore.assertNoPendingWholeRestore();", "process.exit(4);");
    const recover = [
      'const assert=require("node:assert/strict"),fs=require("node:fs");',
      "const restore=require(" + modulePath("services/restoreService") + ");",
      'const coordinator=JSON.parse(fs.readFileSync("data/.rootark-restore-coordinator.json","utf8"));',
      "const result=restore.assertNoPendingWholeRestore();assert.equal(result.recovered,true);",
      'const live=JSON.parse(fs.readFileSync("data/runtime.json","utf8"));',
      "assert.equal(live.state,\"live\");assert.equal(live.payload.length,2*1024*1024);",
      'assert.equal(fs.readFileSync("uploads/file.txt","utf8"),"live-upload");',
      'assert.equal(fs.existsSync("data/.rootark-restore-coordinator.json"),false);',
      'const leftovers=fs.readdirSync("data").filter(name=>!name.startsWith("unlisted.")&&name.endsWith(".restore-preimage"));',
      'assert.deepEqual(leftovers,["runtime.json.aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.restore-preimage"]);',
      'assert.equal(fs.readFileSync("data/"+leftovers[0],"utf8"),"legacy transaction temp");',
      'assert.equal(fs.readFileSync("data/unlisted."+coordinator.transactionId+".restore-preimage","utf8"),"preserve unrelated file");',
    ].join("\n");
    try {
      const first = spawnSync(process.execPath, ["-e", prepare], { cwd: runtime, env, encoding: "utf8", timeout: 20_000 });
      assert.equal(first.status, 86, boundary + ": " + (first.stderr || first.stdout));
      const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      const unlistedPath = path.join(runtime, "data", "unlisted." + coordinator.transactionId + ".restore-preimage");
      fs.writeFileSync(unlistedPath, "preserve unrelated file");
      const manifestPath = path.join(runtime, "data", "backups", ".restore-preimages", coordinator.transactionId, "manifest.json");
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      const runtimeEntry = manifest.domains.find((domain) => domain.name === "data-files").files.find((entry) => path.basename(entry.destination) === "runtime.json");
      assert.ok(runtimeEntry, "runtime.json must be a journal-listed destination");
      const legacyPath = path.join(path.dirname(runtimeEntry.destination), "runtime.json.aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.restore-preimage");
      fs.writeFileSync(legacyPath, "legacy transaction temp");
      const interrupted = spawnSync(process.execPath, ["-e", interruptLines.join("\n")], { cwd: runtime, env, encoding: "utf8", timeout: 15_000 });
      assert.equal(interrupted.status, 87, boundary + ": " + (interrupted.stderr || interrupted.stdout));
      const listedTemps = fs.readdirSync(path.join(runtime, "data")).filter((name) => !name.startsWith("unlisted.") && name.endsWith(".restore-preimage"));
      assert.equal(listedTemps.filter((name) => name.includes(coordinator.transactionId)).length, boundary === "rename" ? 0 : 1, boundary + ": interruption must leave only the expected transaction temp");
      const restarted = spawnSync(process.execPath, ["-e", recover], { cwd: runtime, env, encoding: "utf8", timeout: 20_000 });
      assert.equal(restarted.status, 0, boundary + ": " + (restarted.stderr || restarted.stdout));
      assert.equal(fs.readFileSync(unlistedPath, "utf8"), "preserve unrelated file");
      assert.equal(fs.existsSync(legacyPath), true, boundary + ": restart must preserve ambiguous UUID-shaped data beside a listed destination");
      assert.equal(fs.readFileSync(legacyPath, "utf8"), "legacy transaction temp");
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  }
});
