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
const modes = ["large-clean", "already-archived", "divergent", "duplicate", "malformed", "truncated",
  "escaped-id-match", "escaped-id-divergent", "nested-id", "duplicate-logs", "invalid-escape", "oversized-match", "non-object-log"];

for (const mode of modes) test(`JSON whole-restore audit streaming archive: ${mode}`, { timeout: 30_000 }, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-archive-scan-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-archive-scan-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const script = `
    const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
    const data=path.join(process.cwd(),'data');fs.mkdirSync(data,{recursive:true});
    const audit=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
    const transactionId='aaaa0000-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
    const coordinator={transactionId,phase:'rollback_complete',backupId:'backup-1',
      restoreAudit:{requestedAt:'2026-11-03T12:00:00.000Z',
        actor:{username:'auditor',role:'admin',ip:null,userAgent:null}}};
    const log={id:'restore-outcome-'+transactionId,timestamp:coordinator.restoreAudit.requestedAt,
      eventType:'backup.restore.failed',severity:'error',actor:coordinator.restoreAudit.actor,
      target:{type:'backup',id:'backup-1'},action:'restore',result:'failure',
      details:{error:'restore_not_committed',phase:'rollback_complete'}};
    const mainPath=path.join(data,'audit-logs.json');
    const archivePath=path.join(data,'audit-logs-archive.json');
    const coordinatorPath=path.join(data,'.rootark-restore-coordinator.json');
    fs.writeFileSync(mainPath,JSON.stringify({logs:[{id:'preexisting',eventType:'x'}]}));
    fs.writeFileSync(coordinatorPath,JSON.stringify(coordinator));
    const mode=${JSON.stringify(mode)};
    const logs=[{id:'ordinary',eventType:'audit.event',details:{
      nested:{id:log.id},text:'\\"id\\":\\"'+log.id+'\\"'}},
      {id:'very-large-unrelated',details:{blob:'Z'.repeat(85*1024)}}];
    if(['already-archived','escaped-id-match'].includes(mode))logs.push(log);
    if(mode==='divergent')logs.push({...log,eventType:'auth.login'});
    if(mode==='escaped-id-divergent')logs.push({...log,eventType:'auth.login'});
    if(mode==='duplicate')logs.push(log,log);
    if(mode==='oversized-match')logs.push({...log,details:{blob:'X'.repeat(80*1024)}});
    if(mode==='non-object-log')logs.push(null);
    let encoded=JSON.stringify({logs});
    if(mode.startsWith('escaped-id-'))encoded=encoded.replace('"id":"'+log.id+'"','"\\\\u0069d":"'+log.id+'"');
    if(mode==='malformed')encoded=encoded.slice(0,-1)+',}';
    if(mode==='truncated')encoded=encoded.slice(0,-1);
    if(mode==='duplicate-logs')encoded=encoded.slice(0,-1)+',"logs":[]}';
    if(mode==='invalid-escape')encoded=encoded.slice(0,-1)+',"meta":"\\\\q"}';
    fs.writeFileSync(archivePath,encoded);
    const before=fs.readFileSync(archivePath);
    const LOWERED_ARCHIVE_LIMIT=80*1024;
    assert.ok(before.length>LOWERED_ARCHIVE_LIMIT &&
      before.length<LOWERED_ARCHIVE_LIMIT+(mode==='oversized-match'?100*1024:16*1024),
      'fixture crosses a controlled lowered whole-file threshold');
    const oldRead=fs.readFileSync;
    fs.readFileSync=function(target,...args){
      if(typeof target==='number'&&fs.fstatSync(target).size>LOWERED_ARCHIVE_LIMIT)
        throw Error('WHOLE_ARCHIVE_READ_FORBIDDEN');
      return oldRead.call(this,target,...args);
    };
    const rejected=['divergent','escaped-id-divergent','duplicate','malformed','truncated',
      'duplicate-logs','invalid-escape','oversized-match','non-object-log'].includes(mode);
    try{
      if(rejected)assert.throws(()=>audit.persistTerminalRestoreAudit(coordinator),
        /collision|Invalid JSON restore audit history|safe parse budget/i);
      else assert.equal(audit.persistTerminalRestoreAudit(coordinator),log.id);
    }finally{fs.readFileSync=oldRead;}
    assert.deepEqual(fs.readFileSync(archivePath),before,'original archive preserved');
    const after=JSON.parse(fs.readFileSync(mainPath,'utf8')).logs;
    assert.equal(after.filter(e=>e.id===log.id).length,
      rejected||['already-archived','escaped-id-match'].includes(mode)?0:1,
      'append exactly once only when no prior evidence');
    assert.equal(fs.existsSync(coordinatorPath),true,'coordinator remains owned by restore workflow');
    console.log('SCANNED_WITHOUT_WHOLE_ARCHIVE_READ');`;
  const run = spawnSync(process.execPath, ["-e", script], {
    cwd: root, encoding: "utf8", timeout: 25_000, windowsHide: true,
    env: { ...process.env, DB_ENABLED: "false", NODE_PATH: [path.join(project, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter) },
  });
  assert.equal(run.status, 0, `${run.error?.message || ""}\n${run.stderr || ""}\n${run.stdout || ""}`);
  assert.match(run.stdout, /SCANNED_WITHOUT_WHOLE_ARCHIVE_READ/);
});
