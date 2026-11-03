"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const project = path.resolve(__dirname, "..");
const cases = ["divergent", "exact-replay", "malformed-main", "malformed-archive",
  "duplicate-archive", "giant-archive-duplicate", "giant-archive-valid"];

for (const mode of cases) test(`never-enrolled JSON archive preflight before real restore: ${mode}`,
  { timeout: 90_000 }, (t) => {
    const runtime = process.platform === "win32"
      ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-no-store-${crypto.randomBytes(10).toString("hex")}`)
      : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-no-store-"));
    if (process.platform === "win32") ensureWindowsChunkUploadRoot(runtime);
    t.after(() => fs.rmSync(runtime, { recursive: true, force: true, maxRetries: 5 }));
    const script = `
      "use strict";
      const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
      const backup=require(${JSON.stringify(path.join(project, "services", "backupService"))});
      const restore=require(${JSON.stringify(path.join(project, "services", "restoreService"))});
      const store=require(${JSON.stringify(path.join(project, "repositories", "jsonAuditArchiveStore"))});
      const mode=${JSON.stringify(mode)};
      const data=path.join(process.cwd(),'data');fs.mkdirSync(data,{recursive:true});
      const main=path.join(data,'audit-logs.json'),archive=path.join(data,'audit-logs-archive.json');
      const runtime=path.join(data,'runtime.json');
      const enrollment=path.join(data,'.rootark-json-audit-enrollment.json');
      const shared={id:'shared-evidence',eventType:'auth.login.failed',timestamp:'2026-11-03T12:00:00.000Z'};
      const giant=mode.startsWith('giant-archive');
      const archived=giant?Array.from({length:22000},(_,n)=>({id:'historic-'+n,eventType:'auth.login.success'})):[];
      if(mode==='divergent'||mode==='duplicate-archive'||mode==='giant-archive-duplicate') archived.push(shared);
      if(mode==='exact-replay')archived.push(shared);
      if(mode==='duplicate-archive'||mode==='giant-archive-duplicate')archived.push(shared);
      const selectedMain={logs:[shared]};
      fs.writeFileSync(main,mode==='malformed-main'?'{"logs":[':JSON.stringify(selectedMain));
      fs.writeFileSync(archive,mode==='malformed-archive'?'{"logs":[':JSON.stringify({logs:archived.map((row)=>
        mode==='divergent'&&row.id===shared.id?{...row,eventType:'tampered'}:row)}));
      fs.writeFileSync(runtime,'selected-state');
      async function run(){
        assert.equal(fs.existsSync(store.STORE),false);
        assert.equal(fs.existsSync(enrollment),false);
        const saved=await backup.createBackup({createdBy:'fixture'});
        assert.equal(saved.status,'success');
        assert.equal(fs.existsSync(store.STORE),false,'backup never enrolls archive index');
        fs.writeFileSync(runtime,'live-state');
        fs.writeFileSync(main,JSON.stringify({logs:[{id:'live-main',eventType:'live'}]}));
        fs.writeFileSync(archive,JSON.stringify({logs:[{id:'live-archive',eventType:'live'}]}));
        const rejected=!['exact-replay','giant-archive-valid'].includes(mode);
        let destructive=0;
        let outcome;
        try{ outcome=await restore.restoreBackup(saved.id,{confirmation:'RESTORE',
          failureInjector(step){if(step.startsWith('restore.data.'))destructive++;}}); }
        catch(e){if(!rejected)throw e;assert.match(String(e.message),/collision|Invalid JSON restore audit history|Invalid restored active JSON audit history/i);}
        if(rejected){
          assert.equal(outcome,undefined,'unsafe restore is rejected');
          assert.equal(destructive,0,'preflight rejects before any restore.data operation');
          assert.equal(fs.readFileSync(runtime,'utf8'),'live-state');
          assert.ok(JSON.parse(fs.readFileSync(main,'utf8')).logs.some(e=>e.id==='live-main'));
          assert.ok(JSON.parse(fs.readFileSync(archive,'utf8')).logs.some(e=>e.id==='live-archive'));
          assert.equal(fs.existsSync(store.STORE),false,'rejected preflight must not enroll a persistent archive');
          assert.equal(fs.existsSync(enrollment),false,'rejected preflight must not publish an enrollment marker');
        }else{
          assert.equal(outcome.restartRecommended,true);
          assert.equal(fs.readFileSync(runtime,'utf8'),'selected-state');
          assert.ok(JSON.parse(fs.readFileSync(main,'utf8')).logs.some(e=>e.id===shared.id));
          // After preflight succeeds, the restore deliberately enrolls the
          // durable archive to carry live-only records across replacement.
          assert.equal(fs.existsSync(store.STORE),true,'successful restore preserves live audit in durable archive');
          assert.equal(fs.existsSync(enrollment),true,'durable carry-forward is enrolled');
          for(const id of ['live-main','live-archive'])
            assert.equal(store.findDeltaAuditMatches(id).length,1,'lost live audit evidence: '+id);
        }
        console.log('NO_STORE_PREFLIGHT_VERIFIED');
      }
      run().catch(e=>{console.error(e.stack||e);process.exitCode=1;});`;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime, encoding: "utf8", timeout: 80_000, windowsHide: true,
      env: { ...process.env, DB_ENABLED: "false", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false",
        BACKUP_INCLUDE_TEMP: "false", ROOTARK_RESTORE_INSTANCE_COUNT: "1", ROOTARK_INSTANCE_ID: "no-store-preflight",
        UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
        NODE_PATH: [path.join(project, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter) },
    });
    assert.equal(result.status, 0, `${mode}: ${result.error?.message||''}\n${result.stderr||''}\n${result.stdout||''}`);
    assert.match(result.stdout, /NO_STORE_PREFLIGHT_VERIFIED/);
  });
