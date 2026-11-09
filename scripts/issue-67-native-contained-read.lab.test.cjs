// Disposable lab fixtures only. Set ROOTARK_NATIVE_READ_EXE and
// ROOTARK_NATIVE_READ_TESTDIR to explicit pre-created fixture locations.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const exe = process.env.ROOTARK_NATIVE_READ_EXE;
const base = process.env.ROOTARK_NATIVE_READ_TESTDIR;
assert.ok(exe && fs.existsSync(exe), 'set compiled ROOTARK_NATIVE_READ_EXE');
assert.ok(base && fs.statSync(base).isDirectory(), 'set disposable ROOTARK_NATIVE_READ_TESTDIR');
const isWin = process.platform === 'win32';

const ownerSid = isWin ? (() => {
  const info = spawnSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8' });
  assert.equal(info.status, 0, `whoami: ${info.stderr}`);
  const sid = info.stdout.match(/S-1-5-(?:\d+-)+\d+/);
  assert.ok(sid, 'current SID');
  return sid[0];
})() : '';

function makeFixture(t) {
  const temp = fs.mkdtempSync(path.join(base, 'contained-w35-'));
  const root = path.join(temp, 'root');
  const foreign = path.join(temp, 'foreign');
  fs.mkdirSync(root);
  fs.mkdirSync(foreign);
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  return { temp, root, foreign };
}

function protect(file) {
  if (isWin) {
    const result = spawnSync('icacls.exe', [file, '/inheritance:r', '/grant:r', `*${ownerSid}:(F)`], { encoding: 'utf8' });
    assert.equal(result.status, 0, `ACL setup: ${result.stderr} ${result.stdout}`);
  } else fs.chmodSync(file, 0o600);
}

function makeFile(root, basename, contents = 'progress-safe-fixture\n') {
  const full = path.join(root, basename);
  fs.writeFileSync(full, contents);
  protect(full);
  return full;
}

function invoke(...args) {
  return spawnSync(exe, args, { encoding: 'utf8', timeout: 12000 });
}

function rootId(root) {
  const result = invoke('--fingerprint', root);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout).rootId;
}

function valid(root, relative, expected) {
  const result = invoke('--read', root, relative, expected);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const obj = JSON.parse(result.stdout);
  assert.equal(obj.ok, true);
  return Buffer.from(obj.payloadBase64, 'base64');
}

function refused(root, relative, expected, why) {
  const result = invoke('--read', root, relative, expected);
  assert.equal(result.status, 4, `${why}: ${result.stderr} ${result.stdout}`);
  assert.deepEqual(JSON.parse(result.stdout), { ok: false });
}

function signalChild(args) {
  const child = spawn(exe, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk.toString(); });
  const ready = new Promise((resolve, reject) => {
    const watchdog = setTimeout(() => reject(new Error('READY timeout')), 5000);
    child.stderr.on('data', chunk => {
      stderr += chunk.toString();
      if (/READY\r?\n/.test(stderr)) { clearTimeout(watchdog); resolve(); }
    });
    child.once('error', reject);
    child.once('exit', (code) => { clearTimeout(watchdog); reject(new Error(`exit before READY: ${code}`)); });
  });
  const done = new Promise(resolve => child.once('close', code => resolve({ code, stdout, stderr })));
  return { child, ready, done };
}

test('bounded genuine payload through the pinned leaf; empty and oversized fail-safe', t => {
  const { root } = makeFixture(t);
  const id = rootId(root);
  makeFile(root, 'progress.json', '{"version":1,"items":[]}\n');
  assert.equal(valid(root, 'progress.json', id).toString(), '{"version":1,"items":[]}\n');
  makeFile(root, 'empty.json', '');
  assert.equal(valid(root, 'empty.json', id).length, 0);
  makeFile(root, 'large.json', 'A'.repeat(65537));
  refused(root, 'large.json', id, '>64 KiB');
  refused(root, '../progress.json', id, 'traversal');
  refused(root, 'progress.json', '0'.repeat(id.length), 'wrong physical root');
});

test('leaf and ancestor reparse points cannot reach the external canary', t => {
  const { root, foreign } = makeFixture(t);
  const canary = makeFile(foreign, 'outside.txt', 'EXTERNAL_CANARY_DO_NOT_READ');
  const id = rootId(root);
  if (isWin) {
    fs.symlinkSync(foreign, path.join(root, 'junction'), 'junction');
    refused(root, path.join('junction', 'outside.txt'), id, 'NTFS junction');
    try {
      fs.symlinkSync(canary, path.join(root, 'leaf-link'), 'file');
      refused(root, 'leaf-link', id, 'NTFS leaf symlink');
    } catch (err) {
      if (err.code !== 'EPERM' && err.code !== 'EACCES') throw err;
      t.diagnostic('NTFS leaf symlink creation unavailable without privilege; junction tested');
    }
  } else {
    fs.symlinkSync(foreign, path.join(root, 'junction'));
    fs.symlinkSync(canary, path.join(root, 'leaf-link'));
    refused(root, 'junction/outside.txt', id, 'POSIX directory symlink');
    refused(root, 'leaf-link', id, 'POSIX leaf symlink');
  }
  assert.equal(fs.readFileSync(canary, 'utf8'), 'EXTERNAL_CANARY_DO_NOT_READ');
});

test('reject hardlinked leaf and alternate writer grants', t => {
  const { root } = makeFixture(t);
  const id = rootId(root);
  const leaf = makeFile(root, 'data.json');
  const twin = path.join(root, 'twin.json');
  fs.linkSync(leaf, twin);
  refused(root, 'data.json', id, 'hardlink');
  fs.unlinkSync(twin);
  assert.ok(valid(root, 'data.json', id).length);
  if (isWin) {
    const result = spawnSync('icacls.exe', [leaf, '/grant', '*S-1-5-4:(M)'], { encoding: 'utf8' });
    assert.equal(result.status, 0, `grant INTERACTIVE: ${result.stderr} ${result.stdout}`);
  } else fs.chmodSync(leaf, 0o660);
  refused(root, 'data.json', id, 'untrusted writer');
});

test('root identity binds NTFS case alias or rejects unexpected POSIX spelling', t => {
  const { root } = makeFixture(t);
  makeFile(root, 'progress.json');
  const id = rootId(root);
  if (isWin) assert.equal(valid(root.toUpperCase(), 'PROGRESS.JSON', id).toString(), 'progress-safe-fixture\n');
  else refused(root, 'PROGRESS.JSON', id, 'case-sensitive ext4');
});

test('explicit active-writer boundary shows platform limitation', async t => {
  const { root } = makeFixture(t);
  const leaf = makeFile(root, 'data.json');
  const id = rootId(root);
  const held = signalChild(['--read', root, 'data.json', id, '--hold-ms', '1500']);
  t.after(() => { if (held.child.exitCode === null) held.child.kill(); });
  await held.ready;
  if (isWin) {
    assert.throws(() => fs.openSync(leaf, 'r+'), { code: 'EBUSY' });
  } else {
    // An fd lease gives no Linux writer exclusion: demonstrate accepted new
    // data after the helper has opened but before its bounded read starts.
    fs.writeFileSync(leaf, 'owner-concurrent-write\n');
  }
  const result = await held.done;
  assert.equal(result.code, 0, result.stderr);
  const bytes = Buffer.from(JSON.parse(result.stdout).payloadBase64, 'base64');
  assert.equal(bytes.toString(), isWin ? 'progress-safe-fixture\n' : 'owner-concurrent-write\n');
});

test('ancestor replacement during held read is blocked or invalidates revalidation', async t => {
  const { temp, root } = makeFixture(t);
  const nested = path.join(root, 'folder');
  fs.mkdirSync(nested);
  makeFile(nested, 'data.json');
  const id = rootId(root);
  const held = signalChild(['--read', root, path.join('folder', 'data.json'), id, '--hold-ms', '1500']);
  t.after(() => { if (held.child.exitCode === null) held.child.kill(); });
  await held.ready;
  const relocated = path.join(temp, 'relocated');
  let renameDenied = false;
  try { fs.renameSync(nested, relocated); }
  catch (error) { if (!isWin) throw error; renameDenied = ['EPERM', 'EACCES', 'EBUSY'].includes(error.code); }
  if (isWin) assert.equal(renameDenied, true, 'Windows ancestor lease blocks rename');
  else fs.symlinkSync(path.join(temp, 'foreign'), nested);
  const result = await held.done;
  if (isWin) assert.equal(result.code, 0, result.stderr);
  else { assert.equal(result.code, 4, result.stderr); assert.deepEqual(JSON.parse(result.stdout), { ok: false }); }
});

test('hard process crash releases held leases (disposable fixture only)', async t => {
  const { temp, root } = makeFixture(t);
  const leaf = makeFile(root, 'data.json');
  const id = rootId(root);
  const held = signalChild(['--read', root, 'data.json', id, '--hold-ms', '4500']);
  await held.ready;
  held.child.kill('SIGKILL');
  await held.done;
  fs.renameSync(leaf, path.join(temp, 'post-crash.json'));
  assert.ok(fs.existsSync(path.join(temp, 'post-crash.json')));
});
