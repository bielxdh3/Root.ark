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

function fixture(mode, t) {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-carry-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-carry-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const environment = {
    ...process.env, DB_ENABLED: "false", BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "false", BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20", ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "carry-test-instance", UPLOAD_QUARANTINE_DIR: path.join(root, "quarantine"),
    NODE_PATH: [path.join(project, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter),
  };
  const main = `
    'use strict';
    const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
    const backup=require(${JSON.stringify(path.join(project, "services", "backupService"))});
    const restore=require(${JSON.stringify(path.join(project, "services", "restoreService"))});
    const repo=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
    const delta=require(${JSON.stringify(path.join(project, "repositories", "jsonAuditArchiveStore"))});
    const data=path.join(process.cwd(),'data');fs.mkdirSync(data,{recursive:true});
    const main=path.join(data,'audit-logs.json');
    const archive=path.join(data,'audit-logs-archive.json');
    const state=path.join(data,'restore-carry-test.json');
    const mode=${JSON.stringify(mode)};
    const before={id:'old-main',eventType:'file.download',timestamp:'2026-01-01T00:00:00Z'};
    const beforeArchived={id:'old-archive',eventType:'auth.login',timestamp:'2026-01-01T00:00:01Z'};
    const after={id:'current-main',eventType:'file.read',timestamp:'2026-11-01T00:00:00Z'};
    const afterArchived={id:'current-archive',eventType:'auth.login.failed',timestamp:'2026-11-01T00:00:01Z'};
    const existingDelta={id:'existing-delta',eventType:'file.deleted',timestamp:'2026-11-01T00:00:02Z'};
    fs.writeFileSync(main,JSON.stringify({logs:[before]}));
    fs.writeFileSync(archive,JSON.stringify({logs:[beforeArchived]}));
    fs.writeFileSync(state,'old');
    (async()=>{
      const selected=await backup.createBackup({createdBy:'carry-test'});
      assert.equal(selected.status,'success');
      fs.writeFileSync(main,JSON.stringify({logs:[before,after]}));
      const current=[beforeArchived,afterArchived];
      if(mode==='huge-archive') {
        for(let i=0;i<15000;i++)current.push({id:'history-'+i,eventType:'large.history',timestamp:'2026-10-01T00:00:00Z'});
      }
      fs.writeFileSync(archive,JSON.stringify({logs:current}));
      repo.appendJsonArchiveLogs([existingDelta]);
      if(mode==='malformed')fs.writeFileSync(archive,'{"logs":[{');
      if(mode==='oversized')fs.writeFileSync(archive,JSON.stringify({logs:[
        beforeArchived,afterArchived,{id:'oversized-live',eventType:'old.event',details:{note:'X'.repeat(70*1024)}}
      ]}));
      if(mode==='divergent-selected')fs.writeFileSync(main,JSON.stringify({logs:[
        {...before,eventType:'changed-after-backup'},after
      ]}));
      if(mode==='live-conflict')fs.writeFileSync(archive,JSON.stringify({logs:[
        beforeArchived,afterArchived,{...after,eventType:'divergent-current-archive'}
      ]}));
      fs.writeFileSync(state,'new');
      const inject=['rollback-after-data','interrupted-restart'].includes(mode)
        ? (phase)=>{if(phase==='restore.backup-history.reconciled')throw Error('INJECTED_ROLLBACK');}
        : ['fail-before-data','retry-exact'].includes(mode)
          ? (phase)=>{if(phase==='restore.audit.carry-forward.persisted')throw Error('INJECTED_PRECOMMIT');}
          : mode==='fault-before-commit'
            ? (phase)=>{if(phase==='restore.audit.carry-forward.before-commit')throw Error('INJECTED_DURABLE_TRANSACTION_ABORT');}
          : mode==='tampered-coordinator'
            ? (phase)=>{
              if(phase==='restore.audit.carry-forward.before-commit') {
                const marker=path.join(data,'.rootark-restore-coordinator.json');
                const current=JSON.parse(fs.readFileSync(marker,'utf8'));
                fs.writeFileSync(marker,JSON.stringify({...current,updatedAt:'TAMPERED'}));
              }
            }
          : null;
      try {
        await restore.restoreBackup(selected.id,{confirmation:'RESTORE',username:'manager',
          ...(inject?{failureInjector:inject}: {})});
        if(['malformed','oversized','divergent-selected','live-conflict','rollback-after-data','interrupted-restart',
          'fail-before-data','retry-exact','fault-before-commit','tampered-coordinator'].includes(mode))throw Error('expected restore failure');
        assert.equal(fs.readFileSync(state,'utf8'),'old');
        assert.equal(restore.getWholeRestorePhase(),'restart_required');
      }catch(error){
        if(!['malformed','oversized','divergent-selected','live-conflict','rollback-after-data','interrupted-restart',
          'fail-before-data','retry-exact','fault-before-commit','tampered-coordinator'].includes(mode))throw error;
        assert.match(error.message,mode==='tampered-coordinator'?/coordinator changed/i
          :['malformed','oversized','divergent-selected','live-conflict'].includes(mode)?/audit|restore|collision/i:/INJECTED_/);
        if(['malformed','oversized','divergent-selected','live-conflict'].includes(mode))assert.equal(fs.readFileSync(state,'utf8'),'new');
        if(['fail-before-data','retry-exact','fault-before-commit','tampered-coordinator'].includes(mode))assert.equal(fs.readFileSync(state,'utf8'),'new');
      }
      if(mode==='tampered-coordinator') {
        assert.equal(delta.findDeltaAuditMatches(after.id).length,0,'tampered coordinator cannot commit carry');
        console.log('CARRY_REJECTED_TAMPER');return;
      }
      if(mode==='fault-before-commit') {
        for(const id of [before.id,after.id,beforeArchived.id,afterArchived.id]) {
          assert.equal(delta.findDeltaAuditMatches(id).length,0,'partial carry on abort: '+id);
        }
        await restore.restoreBackup(selected.id,{confirmation:'RESTORE',username:'manager'});
        assert.equal(restore.getWholeRestorePhase(),'restart_required');
      }
      if(mode==='retry-exact') {
        for(const id of [before.id,after.id,beforeArchived.id,afterArchived.id]) {
          assert.equal(delta.findDeltaAuditMatches(id).length,1,'carry missing before retry: '+id);
        }
        await restore.restoreBackup(selected.id,{confirmation:'RESTORE',username:'manager'});
        assert.equal(restore.getWholeRestorePhase(),'restart_required');
        assert.equal(fs.readFileSync(state,'utf8'),'old');
      }
      if(['malformed','oversized','divergent-selected','live-conflict'].includes(mode)) {
        assert.equal(delta.findDeltaAuditMatches(after.id).length,
          mode==='divergent-selected'?1:0,
          'carry-forward must be atomic or leave only real live evidence on collision');
        console.log('CARRY_REJECTED_UNSAFE');return;
      }
      for(const event of [before,beforeArchived,after,afterArchived,existingDelta]) {
        const matches=delta.findDeltaAuditMatches(event.id);
        assert.equal(matches.length,1,'missing carried event '+event.id);
        assert.deepEqual(matches[0],event);
      }
      if(mode==='huge-archive') {
        for(const id of ['history-0','history-14999']) assert.equal(delta.findDeltaAuditMatches(id).length,1);
      }
      // Ordinary writers stay blocked until terminal coordinator cleanup.
      if(restore.getWholeRestorePhase()) {
        assert.throws(()=>repo.appendJsonArchiveLogs([{...after,eventType:'divergent'}]),/restore/i);
      } else {
        assert.throws(()=>repo.appendJsonArchiveLogs([{...after,eventType:'divergent'}]),/collision/i);
      }
      console.log('CARRY_DURABLE_'+restore.getWholeRestorePhase());
    })().catch(error=>{console.error(error.stack||error);process.exitCode=1;});`;
  const run = (script) => spawnSync(process.execPath, ["-e", script], {
    cwd: root, env: environment, encoding: "utf8", timeout: 60_000, windowsHide: true,
  });
  return { run, main, root };
}

for (const mode of ["success", "rollback-after-data", "interrupted-restart", "fail-before-data",
  "retry-exact", "fault-before-commit", "tampered-coordinator", "malformed", "oversized", "divergent-selected",
  "live-conflict", "huge-archive"]) {
  test(`JSON whole restore carries live audit history: ${mode}`, { timeout: 75_000 }, (t) => {
    const { run, main, root } = fixture(mode, t);
    const first = run(main);
    assert.equal(first.status, 0, `${first.error?.message || ""}\n${first.stderr || ""}\n${first.stdout || ""}`);
    assert.match(first.stdout, mode==='tampered-coordinator'?/CARRY_REJECTED_TAMPER/
      :["malformed","oversized","divergent-selected","live-conflict"].includes(mode)
      ? /CARRY_REJECTED_UNSAFE/ : /CARRY_DURABLE_/);
    if (["malformed","oversized","divergent-selected","live-conflict","tampered-coordinator"].includes(mode)) return;
    const restart = run(`
      const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
      const restore=require(${JSON.stringify(path.join(project, "services", "restoreService"))});
      const delta=require(${JSON.stringify(path.join(project, "repositories", "jsonAuditArchiveStore"))});
      const repo=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
      const backup=require(${JSON.stringify(path.join(project, "services", "backupService"))});
      const zip=require('unzipper');
      if(${JSON.stringify(mode)}==='interrupted-restart') {
        const original=fs.rmSync;
        const coordinator=path.join(process.cwd(),'data','.rootark-restore-coordinator.json');
        let interrupted=false;
        fs.rmSync=function(target,...args){
          if(!interrupted&&path.resolve(target)===coordinator){
            interrupted=true;throw Object.assign(Error('INJECTED_CLEANUP_INTERRUPTION'),{code:'EIO'});
          }
          return original.call(this,target,...args);
        };
        try{assert.throws(()=>restore.assertNoPendingWholeRestore(),/rollback failed/i);}
        finally{fs.rmSync=original;}
        assert.equal(interrupted,true);
      }
      const pending=restore.assertNoPendingWholeRestore();
      if(pending.restartRequired) {
        restore.prepareWholeRestoreStartup();
        restore.acknowledgeWholeRestoreInstance('carry-test-instance');
      }
      for(const id of ['current-main','current-archive','old-main','old-archive','existing-delta']) {
        assert.equal(delta.findDeltaAuditMatches(id).length,1,'evidence not durable after restart: '+id);
      }
      const active={id:'current-main',eventType:'file.read',timestamp:'2026-11-01T00:00:00Z'};
      assert.doesNotThrow(()=>repo.withJsonAuditLock(()=>repo.appendJsonArchiveLogs([active])));
      assert.throws(()=>repo.withJsonAuditLock(()=>repo.appendJsonArchiveLogs([{...active,eventType:'different'}])),/collision/i);
      (async()=>{
        const saved=await backup.createBackup({createdBy:'carry-post-restore'});
        const archive=await zip.Open.file(path.join(process.cwd(),'data','backups',saved.filename));
        const member=archive.files.find(e=>e.path==='data/audit-logs-archive.json');
        assert.ok(member,'post-restore canonical archive missing');
        const events=JSON.parse((await member.buffer()).toString('utf8')).logs;
        for(const id of ['current-main','current-archive','old-archive','existing-delta']) {
          assert.equal(events.filter(e=>e.id===id).length,1,'canonical evidence missing or duplicate: '+id);
        }
        console.log('CARRY_RESTART_VERIFIED');
      })().catch(e=>{console.error(e);process.exitCode=1;});`);
    assert.equal(restart.status, 0, `${restart.error?.message || ""}\n${restart.stderr || ""}\n${restart.stdout || ""}`);
    assert.match(restart.stdout, /CARRY_RESTART_VERIFIED/);
  });
}
