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
for (const { injectFailure, strictMode, beforeMutation = false } of [
  { injectFailure: false, strictMode: true },
  { injectFailure: true, strictMode: true },
  { injectFailure: false, strictMode: false },
  { injectFailure: true, strictMode: false, beforeMutation: true },
]) test(
  `HTTP/SQLite ${strictMode ? "strict" : "unenrolled"} restore ${!injectFailure ? "committed" : beforeMutation ? "cancelled before mutation" : "failed after mutation and rolled back"} retains a durable outcome`,
  { timeout: 90_000 }, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-restore-outcome-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-outcome-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const script = `
    const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http');
    // The disposable cwd has no node_modules. Resolve the real checkout's
    // dependency before spawning, rather than relying on NODE_PATH in CI.
    const express=require(${JSON.stringify(require.resolve("express"))});
    const {runMigrations}=require(${JSON.stringify(path.join(project,"db","migrations"))});
    const {createSyncSqliteAccountWriteFence}=require(${JSON.stringify(path.join(project,"src","services","syncSqliteAccountWriteFence"))});
    const backup=require(${JSON.stringify(path.join(project,"services","backupService"))});
    const restore=require(${JSON.stringify(path.join(project,"services","restoreService"))});
    const audit=require(${JSON.stringify(path.join(project,"repositories","auditRepository"))});
    const strict=require(${JSON.stringify(path.join(project,"services","strictAuditSnapshot"))});
    const register=require(${JSON.stringify(path.join(project,"src","routes","backups"))});
    const injectFailure=${JSON.stringify(injectFailure)};
    const strictMode=${JSON.stringify(strictMode)};
    const beforeMutation=${JSON.stringify(beforeMutation)};
    const actor={username:'fixture-manager',role:'admin',ip:'127.0.0.1',userAgent:null};
    let n=0;
    function auditLog(eventType,who,target,action,result,details){
      const event={id:'fixture-outcome-'+(++n),timestamp:new Date().toISOString(),eventType,
        severity:'critical',actor:who,target,action,result,details};
      const rows=audit.loadAuditLogs();rows.logs.push(event);audit.saveAuditLogs(rows);
    }
    function request(server,id){return new Promise((resolve,reject)=>{
      const body=JSON.stringify({confirmation:'RESTORE'});
      const req=http.request({host:'127.0.0.1',port:server.address().port,
        path:'/backups/'+id+'/restore',method:'POST',headers:{'content-type':'application/json','content-length':Buffer.byteLength(body)}},res=>{
        let data='';res.setEncoding('utf8');res.on('data',x=>data+=x);res.on('end',()=>resolve({status:res.statusCode,body:data}));
      });req.once('error',reject);req.end(body);
    });}
    (async()=>{
      runMigrations({backup:false});if(strictMode)createSyncSqliteAccountWriteFence();
      const saved=await backup.createBackup({createdBy:'fixture-manager'});
      const app=express();app.use(express.json());
      register(app,{auditLog,authenticate(req,res,next){req.user=actor;next();},
        requireBackupAccess(req,res,next){next();},getAuditActor(){return actor;},backupService:backup,
        revalidateBackupAccess(){return null;},waitForRequestQuiescence:async()=>true,
        restoreService:{...restore,restoreBackup(id,opts){return restore.restoreBackup(id,{
          ...opts,...(injectFailure?{failureInjector(phase){if(phase===(beforeMutation?'restore.coordinator.persisted':'restore.sqlite.committed'))throw Error('INJECTED_RESTORE');}}:{})});}}});
      const server=app.listen(0,'127.0.0.1');
      await new Promise(resolve=>server.once('listening',resolve));
      let response;
      try{response=await request(server,saved.id);}finally{await new Promise(resolve=>server.close(resolve));}
      assert.equal(response.status,injectFailure?(beforeMutation?400:503):200,response.body);
      if(strictMode)assert.throws(()=>audit.deferAuditLog({id:'unauthorized-during-restore',eventType:'auth.login.failed'}),
        /Strict audit writes blocked during whole restore/);
      if(injectFailure&&!beforeMutation){
        assert.equal(restore.getWholeRestorePhase(),'prepared');
        assert.equal(restore.assertNoPendingWholeRestore().recovered,true);
      }else if(!injectFailure) assert.equal(restore.getWholeRestorePhase(),'restart_required');
      else assert.equal(restore.getWholeRestorePhase(),null);
      const logs=[...audit.loadAuditLogs().logs,...audit.loadArchivedAuditLogs().logs];
      const matches=logs.filter(log=>log.eventType==='backup.restore.'+(injectFailure?'failed':'completed'));
      assert.equal(matches.length,1,'exactly one restore outcome must survive');
      assert.equal(matches[0].target.id,saved.id);
      assert.equal(matches[0].actor.username,'fixture-manager');
      assert.equal(strict.verifyAuditDatabase(strict.journalPath(process.env.DATABASE_URL)).pending>=1,true);
      console.log('RESTORE_HTTP_OUTCOME_OK');
    })().catch(e=>{console.error(e.stack||e);process.exitCode=1;});`;
  const childEnv = { ...process.env, DATABASE_URL: path.join(root,"data","rootark.sqlite"),
    DB_ENABLED:"true", BACKUP_ENABLED:"true", BACKUP_INCLUDE_UPLOADS:"false",BACKUP_INCLUDE_TEMP:"false",
    BACKUP_RETENTION_COUNT:"20",ROOTARK_RESTORE_INSTANCE_COUNT:"1",ROOTARK_INSTANCE_ID:"restore-outcome-test" };
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: root,
    env: childEnv,
    encoding:"utf8",timeout:75_000,windowsHide:true,
  });
  assert.equal(result.status,0,`${result.error?.message||""}\n${result.stderr||""}\n${result.stdout||""}`);
  assert.match(result.stdout,/RESTORE_HTTP_OUTCOME_OK/);
  // A different process must be able to read the acknowledged outcome even
  // before a restart_required coordinator has been cleared by instance ACKs.
  const restartRead = `
    const assert=require('node:assert/strict');
    const audit=require(${JSON.stringify(path.join(project,"repositories","auditRepository"))});
    const rows=[...audit.loadAuditLogs().logs,...audit.loadArchivedAuditLogs().logs];
    const expected='backup.restore.'+${JSON.stringify(injectFailure?"failed":"completed")};
    assert.equal(rows.filter(log=>log.eventType===expected).length,1);
    console.log('RESTORE_OUTCOME_SURVIVED_RESTART');`;
  const probe = spawnSync(process.execPath,["-e",restartRead], {
    cwd:root,env:childEnv,encoding:"utf8",timeout:15_000,windowsHide:true,
  });
  assert.equal(probe.status,0,`${probe.error?.message||""}\n${probe.stderr||""}`);
  assert.match(probe.stdout,/RESTORE_OUTCOME_SURVIVED_RESTART/);
});
