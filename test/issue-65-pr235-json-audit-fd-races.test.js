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
const cases = ["enrollment-read-swap", "enrollment-symlink", "enrollment-hardlink",
  "temporary-fsync-swap", "temporary-pinned-fd", "normal-enrollment"];

for (const mode of cases) test(`JSON private audit file identity: ${mode}`, { timeout: 35_000 }, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-audit-fd-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-fd-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const script = `
    "use strict";
    const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
    const repo=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
    const store=require(${JSON.stringify(path.join(project, "repositories", "jsonAuditArchiveStore"))});
    const mode=${JSON.stringify(mode)};
    const data=path.join(process.cwd(),'data');fs.mkdirSync(data,{recursive:true});
    const enrollment=path.join(data,'.rootark-json-audit-enrollment.json');
    const example={id:'audit-fd-identity',eventType:'auth.login.failed',timestamp:'2026-11-03T15:00:00Z'};
    const originalOpen=fs.openSync,originalReadFile=fs.readFileSync,originalRead=fs.readSync;
    const originalFsync=fs.fsyncSync,originalRename=fs.renameSync;
    let openedEnrollment=-1, temporary=null, reopened=0, swapped=false;
    const archivedBefore=()=>repo.appendJsonArchiveLogs([example]);
    function replaceEnrollment(){
      if(swapped)return;
      swapped=true;
      originalRename(enrollment,enrollment+'.kept');
      fs.copyFileSync(enrollment+'.kept',enrollment);
    }
    async function run(){
      if(mode.startsWith('enrollment-')||mode==='normal-enrollment')archivedBefore();
      if(mode==='enrollment-symlink'||mode==='enrollment-hardlink'){
        const original=enrollment+'.foreign';fs.copyFileSync(enrollment,original);
        fs.rmSync(enrollment);
        if(mode==='enrollment-hardlink')fs.linkSync(original,enrollment);
        else {
          try{fs.symlinkSync(original,enrollment,'file');}
          catch(error){if(error.code==='EPERM'||error.code==='EACCES'){console.log('SYMLINK_PERMISSION_UNAVAILABLE');return;}throw error;}
        }
        assert.throws(()=>store.findDeltaAuditMatches(example.id),/Unsafe JSON audit archive enrollment marker|ELOOP/i);
        assert.equal(fs.existsSync(store.STORE),true);
        return;
      }
      if(mode==='enrollment-read-swap'){
        fs.openSync=function(filename,...args){
          const fd=originalOpen.call(this,filename,...args);
          if(filename===enrollment)openedEnrollment=fd;
          return fd;
        };
        fs.readFileSync=function(fd,...args){
          const result=originalReadFile.call(this,fd,...args);
          if(fd===openedEnrollment)replaceEnrollment();
          return result;
        };
        fs.readSync=function(fd,...args){
          const result=originalRead.call(this,fd,...args);
          if(fd===openedEnrollment)replaceEnrollment();
          return result;
        };
        try{assert.throws(()=>store.findDeltaAuditMatches(example.id),/Unsafe JSON audit archive enrollment marker|changed/i);}
        finally{fs.openSync=originalOpen;fs.readFileSync=originalReadFile;fs.readSync=originalRead;}
        assert.equal(swapped,true,'the pathname was exchanged after reading pinned enrollment bytes');
        assert.equal(fs.existsSync(store.STORE),true,'trusted private store preserved');
        return;
      }
      if(mode==='normal-enrollment'){
        assert.deepEqual(store.findDeltaAuditMatches(example.id),[example]);
        return;
      }
      fs.openSync=function(filename,...args){
        const fd=originalOpen.call(this,filename,...args);
        if(typeof filename==='string'&&filename.startsWith(store.STORE+'.')&&filename.endsWith('.tmp')){
          temporary=filename;
          if(args[0]==='r+')reopened++;
        }
        return fd;
      };
      if(mode==='temporary-fsync-swap'){
        fs.fsyncSync=function(fd,...args){
          if(temporary&&!swapped&&fs.existsSync(temporary)&&fs.fstatSync(fd).isFile()
            && fs.fstatSync(fd).size>0){
            swapped=true;
            originalRename(temporary,temporary+'.kept');
            fs.copyFileSync(temporary+'.kept',temporary);
          }
          return originalFsync.call(this,fd,...args);
        };
      }
      try{
        if(mode==='temporary-fsync-swap'){
          assert.throws(archivedBefore,/Unsafe private JSON audit archive|changed|identity/i);
          assert.equal(swapped,true,'actual post-initialization fsync boundary was swapped');
          assert.equal(fs.existsSync(store.STORE),false,'foreign inode was not published');
        }else{
          archivedBefore();
          assert.equal(reopened,0,'no pathname-based r+ reopened after SQLite initialization');
          assert.deepEqual(store.findDeltaAuditMatches(example.id),[example]);
        }
      }finally{fs.openSync=originalOpen;fs.fsyncSync=originalFsync;}
    }
    run().then(()=>console.log('AUDIT_FD_IDENTITY_VERIFIED'))
      .catch(e=>{console.error(e.stack||e);process.exitCode=1;});`;
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: root, encoding: "utf8", timeout: 30_000, windowsHide: true,
    env: { ...process.env, DB_ENABLED: "false",
      NODE_PATH: [path.join(project, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter) },
  });
  assert.equal(result.status, 0, `${mode}: ${result.error?.message || ""}\n${result.stderr || ""}\n${result.stdout || ""}`);
  if (result.stdout.includes("SYMLINK_PERMISSION_UNAVAILABLE")) {
    t.skip("OS did not grant symlink creation privilege");
    return;
  }
  assert.match(result.stdout, /AUDIT_FD_IDENTITY_VERIFIED/);
});
