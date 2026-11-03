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

for (const mode of ["missing-enrolled-store", "backup-eviction-race", "restore-rebase-rollback",
  "actual-backup-zip", "long-escaped-legacy-id", "preflight-divergent-restore"]) {
  test(`JSON archive durable delta: ${mode}`, { timeout: 35_000 }, (t) => {
    const root = process.platform === "win32"
      ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-json-delta-${crypto.randomBytes(10).toString("hex")}`)
      : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-json-delta-"));
    if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
    t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
    const script = `
      'use strict';
      const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
      const Database=require('better-sqlite3');
      const repo=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
      const store=require(${JSON.stringify(path.join(project, "repositories", "jsonAuditArchiveStore"))});
      const data=path.join(process.cwd(),'data');fs.mkdirSync(data,{recursive:true});
      const old=path.join(data,'audit-logs-archive.json');
      const main=path.join(data,'audit-logs.json');
      const archiveSnapshot=path.join(data,'snapshot-archive.json');
      const mainSnapshot=path.join(data,'snapshot-main.json');
      const mode=${JSON.stringify(mode)};
      const a={id:'event-a',eventType:'auth.login.failed',timestamp:'2026-11-03T12:00:00Z'};
      const b={id:'event-b',eventType:'file.upload.success',timestamp:'2026-11-03T12:01:00Z'};
      const c={id:'event-c',eventType:'auth.login.success',timestamp:'2026-11-03T12:02:00Z'};
      const early={id:'prior-delta',eventType:'earlier'};
      fs.writeFileSync(old,JSON.stringify({logs:[]}));
      fs.writeFileSync(main,JSON.stringify({logs:[a]}));
      repo.appendJsonArchiveLogs([early]);
      async function run() {
        if(mode==='long-escaped-legacy-id'){
          const id='A'.repeat(180);
          const escaped=String.fromCharCode(92,117,48,48,52,49).repeat(180);
          fs.writeFileSync(old,JSON.stringify({logs:[{id,eventType:'original'}]}).replace(id,escaped));
          assert.throws(()=>repo.appendJsonArchiveLogs([{id,eventType:'divergent'}]),/collision/i);
          return;
        }
        if(mode==='preflight-divergent-restore'){
          const stage=path.join(data,'selected');fs.mkdirSync(path.join(stage,'data'),{recursive:true});
          const target=path.join(stage,'data','audit-logs-archive.json');
          fs.writeFileSync(target,JSON.stringify({logs:[{...early,eventType:'tampered'}]}));
          assert.throws(()=>store.assertJsonRestoreCompatible(stage),/collision/i);
          fs.writeFileSync(target,JSON.stringify({logs:[early]}));
          assert.doesNotThrow(()=>store.assertJsonRestoreCompatible(stage));
          const incoming={id:'selected-internal',eventType:'main-version'};
          fs.writeFileSync(path.join(stage,'data','audit-logs.json'),JSON.stringify({logs:[incoming]}));
          fs.writeFileSync(target,JSON.stringify({logs:[{...incoming,eventType:'archive-version'}]}));
          assert.throws(()=>store.assertJsonRestoreCompatible(stage),/collision/i,
            'divergent selected main/archive identity rejected before destructive restore');
          return;
        }
        if(mode==='actual-backup-zip'){
          const zip=require('unzipper');
          const backup=require(${JSON.stringify(path.join(project, "services", "backupService"))});
          repo.appendJsonArchiveLogs([a]);
          fs.writeFileSync(main,JSON.stringify({logs:[b]}));
          const saved=await backup.createBackup({createdBy:'json-archive-test'});
          assert.equal(saved.status,'success');
          const archive=await zip.Open.file(path.join(data,'backups',saved.filename));
          const read=async(name)=>{
            const member=archive.files.find(entry=>entry.path===name);
            assert.ok(member,name+' missing from backup');
            return JSON.parse((await member.buffer()).toString('utf8'));
          };
          assert.deepEqual((await read('data/audit-logs-archive.json')).logs.map(e=>e.id),
            ['prior-delta','event-a']);
          assert.deepEqual((await read('data/audit-logs.json')).logs.map(e=>e.id),['event-b']);
          assert.equal(archive.files.some(entry=>entry.path.includes('archive.sqlite')
            ||entry.path.includes('json-audit-enrollment')),false,
            'private archive authority must not leak into backup');
          return;
        }
        if(mode==='missing-enrolled-store'){
          assert.equal(fs.existsSync(store.STORE),true);
          fs.rmSync(store.STORE);
          assert.throws(()=>repo.appendJsonArchiveLogs([a]),/Enrolled JSON audit archive journal missing/);
          await assert.rejects(repo.writeJsonArchiveBackupSnapshot(archiveSnapshot,mainSnapshot),
            /Enrolled JSON audit archive journal missing/);
          assert.equal(fs.existsSync(old),true);
          return;
        }
        if(mode==='restore-rebase-rollback'){
          repo.appendJsonArchiveLogs([a]);
          fs.writeFileSync(old,JSON.stringify({logs:[a]}));
          repo.appendJsonArchiveLogs([b]);
          fs.writeFileSync(old,JSON.stringify({logs:[]}));
          repo.appendJsonArchiveLogs([c]);
          const result=await repo.writeJsonArchiveBackupSnapshot(archiveSnapshot,mainSnapshot);
          assert.ok(result.archiveSnapshotPath && result.mainSnapshotPath);
          const ids=JSON.parse(fs.readFileSync(archiveSnapshot,'utf8')).logs.map(v=>v.id);
          assert.deepEqual(ids,['prior-delta','event-a','event-b','event-c']);
          return;
        }
        const originalBackup=Database.prototype.backup;
        let intervened=false;
        Database.prototype.backup=function(destination,...args){
          if(!intervened){
            intervened=true;
            repo.appendJsonArchiveLogs([a]);
            fs.writeFileSync(main,JSON.stringify({logs:[b]}));
          }
          return originalBackup.call(this,destination,...args);
        };
        try {await repo.writeJsonArchiveBackupSnapshot(archiveSnapshot,mainSnapshot);}
        finally{Database.prototype.backup=originalBackup;}
        assert.equal(intervened,true);
        const archives=JSON.parse(fs.readFileSync(archiveSnapshot,'utf8')).logs;
        const active=JSON.parse(fs.readFileSync(mainSnapshot,'utf8')).logs;
        assert.equal(archives.filter(e=>e.id===a.id).length,1,'evicted A preserved in delta');
        assert.equal(active.filter(e=>e.id===a.id).length,0,'A not duplicated in frozen active backup');
        assert.equal(active.filter(e=>e.id===b.id).length,0,'post-t0 new active B is out of backup cutoff');
        assert.deepEqual(archives.map(e=>e.id),['prior-delta','event-a']);
      }
      run().then(()=>console.log('DELTA_BACKUP_VERIFIED'))
        .catch(error=>{console.error(error);process.exitCode=1;});`;
    const run = spawnSync(process.execPath, ["-e", script], {
      cwd: root, encoding: "utf8", timeout: 30_000, windowsHide: true,
      env: { ...process.env, DB_ENABLED: "false", BACKUP_INCLUDE_UPLOADS: "false", BACKUP_INCLUDE_TEMP: "false",
        NODE_PATH: [path.join(project, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter) },
    });
    assert.equal(run.status, 0, `${run.error?.message || ""}\n${run.stderr || ""}\n${run.stdout || ""}`);
    assert.match(run.stdout, /DELTA_BACKUP_VERIFIED/);
  });
}
