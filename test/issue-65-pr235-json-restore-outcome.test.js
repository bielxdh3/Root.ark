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

for (const { interruptCleanup, failureAt } of [
  { interruptCleanup: false, failureAt: "restore.backup-history.reconciled" },
  { interruptCleanup: true, failureAt: "restore.backup-history.reconciled" },
  { interruptCleanup: false, failureAt: "restore.preimage.completed" },
]) test(
  `HTTP JSON ${failureAt === "restore.preimage.completed" ? "cancellation" : "rollback"} keeps exactly one durable failure across restart${interruptCleanup ? " and interrupted coordinator cleanup" : ""}`,
  { timeout: 90_000 }, (t) => {
    const root = process.platform === "win32"
      ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-json-restore-outcome-${crypto.randomBytes(10).toString("hex")}`)
      : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-json-restore-outcome-"));
    if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
    t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
    const environment = {
      ...process.env, DB_ENABLED: "false", BACKUP_ENABLED: "true",
      BACKUP_INCLUDE_UPLOADS: "false", BACKUP_INCLUDE_TEMP: "false",
      BACKUP_RETENTION_COUNT: "20", ROOTARK_RESTORE_INSTANCE_COUNT: "1",
      ROOTARK_INSTANCE_ID: "json-restore-outcome-fixture",
      UPLOAD_QUARANTINE_DIR: path.join(root, "quarantine"),
      NODE_PATH: [path.join(project, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter),
    };
    const servicePath = JSON.stringify(path.join(project, "services", "restoreService"));
    const backupPath = JSON.stringify(path.join(project, "services", "backupService"));
    const initial = `
      const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
      const express=require('express');
      const backup=require(${backupPath});
      const restore=require(${servicePath});
      const register=require(${JSON.stringify(path.join(project, "src", "routes", "backups"))});
      const dataDir=path.join(process.cwd(),'data');fs.mkdirSync(dataDir,{recursive:true});
      const main=path.join(dataDir,'audit-logs.json');
      const archive=path.join(dataDir,'audit-logs-archive.json');
      const marker=path.join(dataDir,'runtime.json');
      const actor={username:'json-manager',role:'admin',ip:'127.0.0.1',userAgent:null};
      const early=${JSON.stringify(failureAt === "restore.preimage.completed")};
      const prior={id:'preexisting-audit',eventType:'auth.login.failed',timestamp:new Date().toISOString()};
      fs.writeFileSync(main,JSON.stringify({logs:[prior]}));
      fs.writeFileSync(archive,JSON.stringify({logs:[{id:'old-archived',eventType:'auth.login.failed'}]}));
      fs.writeFileSync(marker,'selected-state');
      function auditLog(eventType,who,target,action,result,details){
        const rows=JSON.parse(fs.readFileSync(main,'utf8'));
        rows.logs.push({id:'request-'+rows.logs.length,timestamp:new Date().toISOString(),eventType,
          actor:who,target,action,result,details});
        fs.writeFileSync(main,JSON.stringify(rows));
      }
      function request(server,id){return new Promise((resolve,reject)=>{
        const body=JSON.stringify({confirmation:'RESTORE'});
        const req=http.request({host:'127.0.0.1',port:server.address().port,
          path:'/backups/'+id+'/restore',method:'POST',headers:{'content-type':'application/json','content-length':Buffer.byteLength(body)}},res=>{
          let data='';res.setEncoding('utf8');res.on('data',v=>data+=v);res.on('end',()=>resolve({status:res.statusCode,body:data}));
        });req.once('error',reject);req.end(body);
      });}
      (async()=>{
        const saved=await backup.createBackup({createdBy:'json-manager'});
        fs.writeFileSync(marker,'live-state');
        const app=express();app.use(express.json());
        register(app,{auditLog,authenticate(req,res,next){req.user=actor;next();},
          requireBackupAccess(req,res,next){next();},getAuditActor(){return actor;},backupService:backup,
          revalidateBackupAccess(){return null;},waitForRequestQuiescence:async()=>true,
          restoreService:{...restore,restoreBackup(id,opts){return restore.restoreBackup(id,{
            ...opts,failureInjector(phase){if(phase===${JSON.stringify(failureAt)})throw Error('INJECTED_JSON_RESTORE_FAILURE');}});}}});
        const server=app.listen(0,'127.0.0.1');
        await new Promise(resolve=>server.once('listening',resolve));
        let response;try{response=await request(server,saved.id);}finally{await new Promise(resolve=>server.close(resolve));}
        assert.equal(response.status,early?400:503,response.body);
        assert.equal(restore.getWholeRestorePhase(),early?null:'prepared');
        assert.equal(fs.readFileSync(marker,'utf8'),early?'live-state':'selected-state',
          'the coordinator must preserve the correct pre/post-mutation state');
        assert.equal(JSON.parse(fs.readFileSync(main,'utf8')).logs.filter(e=>e.eventType==='backup.restore.failed').length,early?1:0);
        console.log('JSON_RESTORE_INTERRUPTED');
      })().catch(e=>{console.error(e.stack||e);process.exitCode=1;});`;
    const run = (script) => spawnSync(process.execPath, ["-e", script], {
      cwd: root, env: environment, encoding: "utf8", timeout: 45_000, windowsHide: true,
    });
    const first = run(initial);
    assert.equal(first.status, 0, `${first.error?.message || ""}\n${first.stderr || ""}\n${first.stdout || ""}`);
    assert.match(first.stdout, /JSON_RESTORE_INTERRUPTED/);
    const lockPath = path.join(root, "data", "backups", ".backup.lock");
    if (fs.existsSync(lockPath)) {
      // On Windows only the test operator may clear a dead fixture process's lock.
      assert.equal(process.platform, "win32");
      assert.equal(JSON.parse(fs.readFileSync(lockPath, "utf8")).pid, first.pid);
      fs.unlinkSync(lockPath);
    }
    const recovery = `
      const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
      const restore=require(${servicePath});
      const main=path.join(process.cwd(),'data','audit-logs.json');
      const archive=path.join(process.cwd(),'data','audit-logs-archive.json');
      const coordinator=path.join(process.cwd(),'data','.rootark-restore-coordinator.json');
      const interrupt=${JSON.stringify(interruptCleanup)};
      const early=${JSON.stringify(failureAt === "restore.preimage.completed")};
      const originalRm=fs.rmSync;
      if(interrupt){let once=true;fs.rmSync=function(p,...args){
        if(once&&path.resolve(p)===coordinator){once=false;throw Object.assign(Error('INJECTED_CLEANUP_INTERRUPTION'),{code:'EIO'});}
        return originalRm.call(this,p,...args);
      };}
      try{
        if(early) assert.equal(restore.assertNoPendingWholeRestore().recovered,false);
        else if(interrupt){
          assert.throws(()=>restore.assertNoPendingWholeRestore(),/rollback failed/);
          assert.equal(restore.getWholeRestorePhase(),'rollback_complete');
        }else assert.equal(restore.assertNoPendingWholeRestore().recovered,true);
      }finally{fs.rmSync=originalRm;}
      const events=[...JSON.parse(fs.readFileSync(main,'utf8')).logs,...JSON.parse(fs.readFileSync(archive,'utf8')).logs];
      assert.equal(events.filter(e=>e.eventType==='backup.restore.failed').length,1,'one durable failed outcome');
      assert.equal(events.some(e=>e.eventType==='backup.restore.completed'),false);
      assert.equal(events.some(e=>e.id==='preexisting-audit'),true,'preserve JSON audit history');
      assert.equal(events.some(e=>e.id==='old-archived'),true,'preserve JSON audit archive');
      assert.equal(fs.readFileSync(path.join(process.cwd(),'data','runtime.json'),'utf8'),'live-state');
      console.log('JSON_RECOVERY_OK');`;
    const recovered = run(recovery);
    assert.equal(recovered.status, 0, `${recovered.error?.message || ""}\n${recovered.stderr || ""}\n${recovered.stdout || ""}`);
    assert.match(recovered.stdout, /JSON_RECOVERY_OK/);
    const restart = run(`
      const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
      const restore=require(${servicePath});
      assert.equal(restore.assertNoPendingWholeRestore().recovered,${interruptCleanup ? "true" : "false"});
      const data=path.join(process.cwd(),'data');
      const events=[...JSON.parse(fs.readFileSync(path.join(data,'audit-logs.json'),'utf8')).logs,
        ...JSON.parse(fs.readFileSync(path.join(data,'audit-logs-archive.json'),'utf8')).logs];
      assert.equal(events.filter(e=>e.eventType==='backup.restore.failed').length,1);
      assert.equal(events.some(e=>e.eventType==='backup.restore.completed'),false);
      assert.equal(restore.isWholeRestoreBlocked(),false);
      console.log('JSON_RESTART_IDEMPOTENT');`);
    assert.equal(restart.status, 0, `${restart.error?.message || ""}\n${restart.stderr || ""}\n${restart.stdout || ""}`);
    assert.match(restart.stdout, /JSON_RESTART_IDEMPOTENT/);
  },
);
