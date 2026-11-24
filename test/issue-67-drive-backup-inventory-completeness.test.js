"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const ROOT = path.resolve(__dirname, "..");
const IN_SCOPE = {
  id: "expected-object",
  name: "remote.txt",
  parents: ["configured-root"],
  appProperties: {
    rootArkKey: "rootark/uploads/root/remote.txt",
    rootArkFolderId: "root",
    rootArkArea: "uploads",
  },
};

const scenarios = {
  "foreign-parent": [{ data: { files: [{ ...IN_SCOPE, parents: ["foreign-root"] }] } }],
  "missing-files": [{ data: {} }],
  "missing-data": [{}],
  "falsey-token": [{ data: { files: [], nextPageToken: 0 } }],
  "object-token": [{ data: { files: [], nextPageToken: { invalid: true } } }],
  "empty-token": [{ data: { files: [], nextPageToken: "" } }],
  "repeated-token": [
    { data: { files: [], nextPageToken: "repeat" } },
    { data: { files: [], nextPageToken: "repeat" } },
  ],
  "foreign-prefix": [{ data: { files: [{
    ...IN_SCOPE,
    id: "foreign-object",
    appProperties: { ...IN_SCOPE.appProperties, rootArkKey: "another/uploads/root/remote.txt" },
  }] } }],
  "valid-multipage": [
    { data: { files: [IN_SCOPE], nextPageToken: "second-page" } },
    { data: { files: [], nextPageToken: null } },
  ],
  // The initial inventory selected A. A concurrent Drive rename/delete can
  // make a second lookup for the same logical key resolve B instead. A ZIP
  // cannot certify it included the inventoried physical object by downloading
  // B while omitting A.
  "replaced-before-download": [
    { data: { files: [IN_SCOPE] } },
    { data: { files: [{ ...IN_SCOPE, id: "replacement-object" }] } },
  ],
  "stable-physical-id": [{ data: { files: [IN_SCOPE] } }],
};

function runFixture(mode) {
  const runtime = createPrivateAuthorityFixture("rootark-w27-drive-page-");
  const script = [
    'const fs = require("node:fs"); const path = require("node:path"); const {Readable}=require("node:stream");',
    'const source = ' + JSON.stringify(ROOT) + ';',
    'const {createCloudStorage} = require(path.join(source, "services", "cloudStorage"));',
    'const backup = require(path.join(source, "services", "backupService"));',
    'const unzipper = require(path.join(source, "node_modules", "unzipper"));',
    'const pages = ' + JSON.stringify(scenarios[mode]) + ';',
    'let calls = 0; let downloads = 0; const mediaIds = []; let archivedRemote = null;',
    'fs.mkdirSync("data", {recursive:true}); fs.writeFileSync("data/settings.json","{}");',
    'const cloud = createCloudStorage({provider:"gdrive",prefix:"rootark",gdrive:{folderId:"configured-root"},',
    '  resolvePrincipalIdentity:async()=>"disposable-drive-principal",',
    '  createGoogleDriveClient:async()=>({files:{list:async({pageToken})=>{',
    '    const i=calls++; if (i>=pages.length) throw new Error("fake-pages-exhausted");',
    '    if (i===1 && ' + JSON.stringify(mode !== "replaced-before-download") + ' && pageToken!=="repeat" && pageToken!=="second-page") throw new Error("unexpected-page-token");',
    '    return pages[i];',
    '  }, get:async({fileId,alt})=>{',
    '    if(fileId==="expected-object" && ' + JSON.stringify(mode === "replaced-before-download") + ') { const err=new Error("original physical ID disappeared"); err.status=404; throw err; }',
    '    if(fileId==="expected-object" && ' + JSON.stringify(mode === "stable-physical-id") + ') {',
    '      if(alt==="media") { mediaIds.push(fileId); return {data:Readable.from([Buffer.from("STABLE_INVENTORIED_A_BYTES")])}; }',
    '      return {data:' + JSON.stringify(IN_SCOPE) + '};',
    '    }',
    '    if(fileId!=="replacement-object") throw new Error("unexpected physical file ID");',
    '    if(alt==="media") { mediaIds.push(fileId); return {data:Readable.from([Buffer.from("WRONG_REPLACEMENT_BYTES")])}; }',
    '    return {data:{...pages[1].data.files[0]}};',
    '  }}})});',
    'backup.setCloudStorage(' + JSON.stringify(["replaced-before-download", "stable-physical-id"].includes(mode)) + ' ? cloud : {...cloud, download:async(_folder,_name,target)=>{',
    '  downloads++; fs.writeFileSync(target,"verified disposable remote bytes");return true;',
    '}});',
    '(async()=>{',
    '  let created=null,error=null,cloudComplete=null,zipEntries=[],includedFiles=[];',
    '  try { created=await backup.createBackup({createdBy:"disposable-test"});',
    '    const zip=await unzipper.Open.file(path.join("data","backups",created.filename));',
    '    zipEntries=zip.files.map((entry)=>entry.path);',
    '    const manifest=JSON.parse((await zip.files.find((entry)=>entry.path==="backup-manifest.json").buffer()).toString("utf8"));',
    '    cloudComplete=manifest.cloud_complete; includedFiles=manifest.included_files.map((entry)=>entry.path);',
    '    const archived=zip.files.find((entry)=>entry.path==="uploads/remote.txt");',
    '    if(archived) archivedRemote=(await archived.buffer()).toString("utf8");',
    '  }catch(e){error=e.message;}',
    '  const backupsDir=path.join("data","backups");',
    '  const zips=fs.existsSync(backupsDir)?fs.readdirSync(backupsDir).filter((name)=>name.endsWith(".zip")):[];',
    '  const history=backup.listBackups();',
    '  console.log(JSON.stringify({ok:!!created,error,cloudComplete,zipEntries,includedFiles,zips,calls,downloads,mediaIds,archivedRemote,',
    '    success:history.filter((entry)=>entry.status==="success").length,',
    '    failed:history.filter((entry)=>entry.status==="failed").length}));',
    '})().catch((error)=>{console.error(error.stack||error);process.exitCode=1;});',
  ].join("\n");
  try {
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: {
        ...Object.fromEntries(Object.entries(process.env).filter(([key]) =>
          !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_|ZK10_)/i.test(key))),
        NODE_ENV: "test",
        DB_ENABLED: "false",
        BACKUP_ENABLED: "true",
        BACKUP_INCLUDE_UPLOADS: "true",
        BACKUP_INCLUDE_TEMP: "false",
        UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
      },
      timeout: 60000,
      windowsHide: true,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
    return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}

for (const [mode, expected] of [
  ["foreign-parent", /outside.*configured.*parent/i],
  ["missing-files", /provider operation failed/i],
  ["missing-data", /provider operation failed/i],
  ["falsey-token", /provider operation failed/i],
  ["object-token", /provider operation failed/i],
  ["empty-token", /provider operation failed/i],
  ["repeated-token", /provider operation failed/i],
]) {
  test("Drive " + mode + " cannot certify an incomplete ZIP", () => {
    const result = runFixture(mode);
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.match(result.error, expected);
    assert.equal(result.cloudComplete, null);
    assert.deepEqual(result.zips, []);
    assert.deepEqual(result.includedFiles, []);
    assert.equal(result.success, 0);
    assert.equal(result.failed, 1);
    assert.equal(result.downloads, 0);
    if (mode === "repeated-token") assert.equal(result.calls, 2);
  });
}

test("a genuinely foreign namespace in the configured Drive folder is excluded", () => {
  const result = runFixture("foreign-prefix");
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.cloudComplete, true);
  assert.equal(result.success, 1);
  assert.equal(result.downloads, 0);
  assert.ok(!result.zipEntries.includes("uploads/remote.txt"));
  assert.ok(!result.includedFiles.includes("uploads/remote.txt"));
});

test("valid Drive pagination retains the remote object in the completed ZIP", () => {
  const result = runFixture("valid-multipage");
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.cloudComplete, true);
  assert.equal(result.success, 1);
  assert.equal(result.calls, 2);
  assert.equal(result.downloads, 1);
  assert.ok(result.zipEntries.includes("uploads/remote.txt"));
  assert.ok(result.includedFiles.includes("uploads/remote.txt"));
});

test("whole backup cannot replace an inventoried Drive physical ID with a newer same-key object", () => {
  const result = runFixture("replaced-before-download");
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.cloudComplete, null);
  assert.deepEqual(result.zips, []);
  assert.deepEqual(result.mediaIds, [], "must not download replacement B's bytes");
  assert.equal(result.success, 0);
  assert.equal(result.failed, 1);
});

test("whole backup downloads the exact stable inventoried Drive file ID", () => {
  const result = runFixture("stable-physical-id");
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.cloudComplete, true);
  assert.equal(result.success, 1);
  assert.equal(result.failed, 0);
  assert.equal(result.calls, 1, "no second same-key Drive identity lookup");
  assert.deepEqual(result.mediaIds, ["expected-object"]);
  assert.equal(result.archivedRemote, "STABLE_INVENTORIED_A_BYTES");
});
