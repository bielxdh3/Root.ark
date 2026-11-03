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
const modes = ["large", "missing", "empty", "escaped-collision", "identical-replay",
  "long-escaped-collision", "long-escaped-replay", "boundary-escaped-collision", "divergent", "truncated", "malformed",
  "rename-failure", "sync-failure", "duplicate-input"];

for (const mode of modes) test(`JSON archive atomic streaming append: ${mode}`, { timeout: 30_000 }, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-append-archive-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-append-archive-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const script = `
    const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
    const audit=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
    const data=path.join(process.cwd(),'data');fs.mkdirSync(data,{recursive:true});
    const archive=path.join(data,'audit-logs-archive.json');
    const mode=${JSON.stringify(mode)};
    const newLog={id:mode==='boundary-escaped-collision'?'A'.repeat(512):
      mode.startsWith('long-escaped-')?'A'.repeat(180):'candidate-1',
      eventType:'new.audit',timestamp:'2026-11-03T13:00:00Z',details:{nested:'test'}};
    const extraLog={id:'candidate-2',eventType:'extra.audit'};
    const oldLogs=[{id:'earlier-1',details:{blob:'Q'.repeat(90*1024)}}, {id:'earlier-2',eventType:'old.audit'}];
    if(mode==='empty')oldLogs.length=0;
    if(['escaped-collision','long-escaped-collision','boundary-escaped-collision','divergent'].includes(mode))
      oldLogs.push({...newLog,eventType:'wrong.evidence'});
    if(mode==='identical-replay'||mode==='long-escaped-replay')oldLogs.push(newLog);
    let content=JSON.stringify({logs:oldLogs,metadata:{retention:'forever'}},null,2)+'\\n';
    if(mode==='escaped-collision')content=content.replace('"id": "candidate-1"','"\\\\u0069d": "candidate-1"');
    if(mode.startsWith('long-escaped-')||mode==='boundary-escaped-collision'){
      const encodedId=(String.fromCharCode(92)+'u0041').repeat(newLog.id.length);
      content=content.replace('"id": "'+newLog.id+'"','"id": "'+encodedId+'"');
      assert.ok(encodedId.length>1024,'encoded ID crosses old raw retention cap');
    }
    if(mode==='truncated')content=content.slice(0,-2);
    if(mode==='malformed')content=content.slice(0,-2)+',}';
    if(mode!=='missing')fs.writeFileSync(archive,content);
    const before=mode==='missing'?null:fs.readFileSync(archive);
    const LOWERED_LIMIT=80*1024;
    if(!['missing','empty'].includes(mode))assert.ok(before.length>LOWERED_LIMIT);
    const originalRead=fs.readFileSync,originalRename=fs.renameSync,originalFsync=fs.fsyncSync;
    fs.readFileSync=function(target,...args){
      if(typeof target==='number'&&fs.fstatSync(target).size>LOWERED_LIMIT)
        throw Error('UNBOUNDED_READ_FORBIDDEN');
      return originalRead.call(this,target,...args);
    };
    if(mode==='rename-failure')fs.renameSync=function(src,dst,...args){
      if(path.resolve(dst)===archive)throw Object.assign(Error('SIMULATED_RENAME_FAILURE'),{code:'EIO'});
      return originalRename.call(this,src,dst,...args);
    };
    if(mode==='sync-failure')fs.fsyncSync=function(fd,...args){
      if(fs.fstatSync(fd).isFile())throw Object.assign(Error('SIMULATED_SYNC_FAILURE'),{code:'EIO'});
      return originalFsync.call(this,fd,...args);
    };
    try {
      if(['escaped-collision','long-escaped-collision','boundary-escaped-collision','divergent','truncated','malformed','rename-failure','sync-failure','duplicate-input'].includes(mode)) {
        assert.throws(()=>audit.appendJsonArchiveLogs(mode==='duplicate-input'
          ?[newLog,{...newLog,eventType:'different'}]:[newLog,extraLog]),
          /collision|Invalid JSON restore audit history|SIMULATED_(RENAME|SYNC)_FAILURE/i);
      } else {
        const result=audit.appendJsonArchiveLogs([newLog,extraLog]);
        assert.ok(result!==false);
      }
    } finally {fs.readFileSync=originalRead;fs.renameSync=originalRename;fs.fsyncSync=originalFsync;}
    if(['escaped-collision','long-escaped-collision','boundary-escaped-collision','divergent','truncated','malformed','rename-failure','sync-failure','duplicate-input'].includes(mode)) {
      assert.deepEqual(fs.readFileSync(archive),before,'original authority unchanged');
    } else {
      const saved=JSON.parse(fs.readFileSync(archive,'utf8'));
      assert.equal(saved.logs.filter(x=>x.id===newLog.id).length,1);
      assert.equal(saved.logs.filter(x=>x.id==='candidate-2').length,1);
      assert.equal(saved.logs.filter(x=>x.id==='earlier-1').length,mode==='missing'||mode==='empty'?0:1);
      if(mode!=='missing')assert.equal(saved.metadata.retention,'forever');
      if(mode==='large')assert.equal(saved.logs[0].details.blob.length,90*1024);
      const committed=fs.readFileSync(archive);
      assert.doesNotThrow(()=>audit.appendJsonArchiveLogs([newLog,extraLog]),'idempotent append');
      assert.deepEqual(fs.readFileSync(archive),committed,'replay leaves bytes unchanged');
    }
    const leftovers=fs.readdirSync(data).filter(name=>name.includes('.tmp'));
    assert.equal(leftovers.length,0,'temporary files cleaned');
    console.log('ATOMIC_JSON_ARCHIVE_VERIFIED');`;
  const run = spawnSync(process.execPath, ["-e", script], {
    cwd: root, encoding: "utf8", timeout: 25_000, windowsHide: true,
    env: { ...process.env, DB_ENABLED: "false", NODE_PATH: [path.join(project, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter) },
  });
  assert.equal(run.status, 0, `${run.error?.message || ""}\n${run.stderr || ""}\n${run.stdout || ""}`);
  assert.match(run.stdout, /ATOMIC_JSON_ARCHIVE_VERIFIED/);
});
