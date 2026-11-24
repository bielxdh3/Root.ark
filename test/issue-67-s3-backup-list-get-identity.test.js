"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const SOURCE = path.resolve(__dirname, "..");
// The disposable child runs with cwd outside this checkout. Its direct
// `require("unzipper")` would resolve from that empty fixture directory even
// though the dependency is installed for the actual repository test process.
const UNZIPPER_MODULE = require.resolve("unzipper");
const ORIGINAL_TAG = '"inventoried-etag"';
const REPLACED_TAG = '"replacement-etag"';

function runRealBackup(mode) {
  const runtime = createPrivateAuthorityFixture("rootark-s3-listed-identity-");
  const program = `
    const fs = require("node:fs");
    const path = require("node:path");
    const { Readable } = require("node:stream");
    const { createCloudStorage } = require(${JSON.stringify(path.join(SOURCE, "services", "cloudStorage"))});
    const backup = require(${JSON.stringify(path.join(SOURCE, "services", "backupService"))});
    const unzipper = require(${JSON.stringify(UNZIPPER_MODULE)});
    const mode = ${JSON.stringify(mode)};
    const tagA = ${JSON.stringify(ORIGINAL_TAG)};
    const tagB = ${JSON.stringify(REPLACED_TAG)};
    let seenIfMatch = null, gets = 0;
    fs.mkdirSync("data", {recursive:true});
    fs.writeFileSync(path.join("data", "settings.json"), "{}");
    const storage = createCloudStorage({
      provider:"s3", prefix:"rootark", s3:{bucket:"disposable-bucket"},
      resolvePrincipalIdentity:async()=>"disposable-s3-backup-principal",
      createS3Client:async()=>({send:async(command)=>{
        if(command.constructor.name === "ListObjectsV2Command") {
          return {IsTruncated:false,Contents:[{Key:"rootark/uploads/root/remote.txt",
            ...(mode === "missing-etag" ? {} : {ETag:tagA}),
            ...(mode === "missing-size" ? {} : {Size:6})}]};
        }
        if(command.constructor.name === "GetObjectCommand") {
          gets += 1;
          seenIfMatch = command.input.IfMatch || null;
          const changed = mode === "replaced";
          const short = mode === "short-read";
          return { ETag:changed ? tagB : tagA, ContentLength:6,
            Body:Readable.from([Buffer.from(short ? "CUT" : mode === "long-read" ? "TOO-LONG" : changed ? "OTHERB" : "ORIG-A")]) };
        }
        throw new Error("unexpected S3 operation");
      }})
    });
    backup.setCloudStorage(storage);
    (async()=>{
      let created=null, error=null, cloudComplete=null, archived=null;
      try {
        created=await backup.createBackup({createdBy:"disposable-test"});
        const zip=await unzipper.Open.file(path.join("data","backups",created.filename));
        const manifest=JSON.parse((await zip.files.find(x=>x.path==="backup-manifest.json").buffer()).toString());
        cloudComplete=manifest.cloud_complete;
        const file=zip.files.find(x=>x.path==="uploads/remote.txt");
        archived=file && (await file.buffer()).toString();
      } catch(e) { error=e.message; }
      const zipDir=path.join("data","backups");
      const zips=fs.existsSync(zipDir)?fs.readdirSync(zipDir).filter(x=>x.endsWith(".zip")):[];
      const history=backup.listBackups();
      console.log(JSON.stringify({ok:!!created,error,cloudComplete,archived,seenIfMatch,gets,zips,
        successes:history.filter(x=>x.status==="success").length,
        failures:history.filter(x=>x.status==="failed").length}));
    })().catch(e=>{console.error(e.stack||e);process.exitCode=1;});
  `;
  try {
    const result = spawnSync(process.execPath, ["-e", program], {
      cwd: runtime,
      env: { ...Object.fromEntries(Object.entries(process.env).filter(([name]) =>
        !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_|ZK10_)/i.test(name))),
        NODE_ENV: "test", DB_ENABLED: "false", BACKUP_ENABLED: "true",
        BACKUP_INCLUDE_UPLOADS: "true", BACKUP_INCLUDE_TEMP: "false",
        UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine") },
      timeout: 60000, encoding: "utf8", windowsHide: true,
    });
    assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
    return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  } finally {
    fs.rmSync(runtime, {recursive:true,force:true,maxRetries:10,retryDelay:100});
  }
}

test("S3 whole ZIP pins the listed object's ETag and includes its exact bytes", () => {
  const result = runRealBackup("stable");
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.cloudComplete, true);
  assert.equal(result.archived, "ORIG-A");
  assert.equal(result.seenIfMatch, ORIGINAL_TAG);
  assert.equal(result.successes, 1);
});

for (const mode of ["replaced", "short-read", "long-read", "missing-etag", "missing-size"]) {
  test(`S3 ${mode} cannot certify a whole ZIP`, () => {
    const result = runRealBackup(mode);
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.cloudComplete, null);
    assert.deepEqual(result.zips, []);
    assert.equal(result.successes, 0);
    assert.equal(result.failures, 1);
  });
}
