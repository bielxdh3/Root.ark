'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = __dirname;
const TEST_FILE = path.join(ROOT, 'postgres-lab.test.js');
const RED_SQL = path.join(ROOT, 'postgres-negative-control.sql');
const SCHEMA_SQL = path.join(ROOT, 'postgres-schema.sql');
const IMAGE = 'postgres:18.6-alpine3.24';
const LABELS = ['rootark.lab=issue65-packet-b', 'rootark.owner=local-feasibility'];
const RED_ONLY = process.argv.includes('--red-only');
const SCHEMA_ONLY = process.argv.includes('--schema-only');
const DOCKER = process.platform === 'win32'
  ? 'docker'
  : (fs.existsSync('/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe')
    ? '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
    : 'docker');

let containerName;
let containerId;
let volumeName;
let syntheticPassword;

function command(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    input: options.input,
    encoding: 'utf8',
    timeout: options.timeout || 30000,
    env: options.env || process.env,
    windowsHide: true,
  });
  if (result.error) throw new Error(executable + ' failed: ' + result.error.message);
  return {
    status: result.status,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
  };
}

function requireSuccess(executable, args, options = {}) {
  const result = command(executable, args, options);
  if (result.status !== 0) {
    throw new Error(executable + ' exited ' + result.status + ': ' + result.stderr + ' ' + result.stdout);
  }
  return result.stdout;
}

function docker(args, options = {}) {
  return command(DOCKER, args, options);
}

function dockerSuccess(args, options = {}) {
  const result = docker(args, options);
  if (result.status !== 0) {
    throw new Error('docker exited ' + result.status + ': ' + result.stderr + ' ' + result.stdout);
  }
  return result.stdout;
}

function psql(input, options = {}) {
  const args = [
    'exec', '-i', '--env', 'PGPASSWORD', containerName,
    'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-h', '127.0.0.1', '-d', 'p65lab',
  ];
  const env = { ...process.env, PGPASSWORD: syntheticPassword };
  const result = docker(args, { input, env, timeout: options.timeout || 30000 });
  if (result.status !== 0) {
    throw new Error('psql exited ' + result.status + ': ' + result.stderr + ' ' + result.stdout);
  }
  return result.stdout;
}

function startContainer() {
  const suffix = crypto.randomBytes(5).toString('hex');
  const prefix = 'rootark-issue65-pgb-20261020-' + suffix;
  containerName = prefix;
  volumeName = prefix + '-data';
  syntheticPassword = crypto.randomBytes(36).toString('base64url');

  const existing = docker(['container', 'inspect', containerName]);
  if (existing.status === 0) throw new Error('Refusing colliding container name: ' + containerName);
  const existingVolume = docker(['volume', 'inspect', volumeName]);
  if (existingVolume.status === 0) throw new Error('Refusing colliding volume name: ' + volumeName);

  const version = dockerSuccess(['version', '--format', '{{.Server.Version}}|{{.Server.Os}}|{{.Server.Arch}}']);
  const image = dockerSuccess(['image', 'inspect', '--format', '{{.Id}}|{{join .RepoDigests ","}}|{{.Os}}|{{.Architecture}}', IMAGE]);
  process.stdout.write('ENV docker_engine=' + version + '\n');
  process.stdout.write('ENV image=' + IMAGE + ' id-and-digest=' + image + ' pull=NOT_RUN_CACHED_OFFICIAL_IMAGE\n');

  dockerSuccess(['volume', 'create', '--label', LABELS[0], '--label', LABELS[1], volumeName]);
  const runArgs = [
    'run', '-d', '--name', containerName,
    '--label', LABELS[0], '--label', LABELS[1],
    '--network', 'none', '--memory', '1g', '--cpus', '1.0', '--pids-limit', '128', '--shm-size', '64m',
    '--mount', 'type=volume,src=' + volumeName + ',dst=/var/lib/postgresql',
    '--env', 'POSTGRES_PASSWORD', '--env', 'POSTGRES_DB=p65lab',
    '--env', 'POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256',
    IMAGE,
  ];
  containerId = dockerSuccess(runArgs, { env: { ...process.env, POSTGRES_PASSWORD: syntheticPassword } });
  if (!/^[0-9a-f]{64}$/i.test(containerId)) throw new Error('docker run did not return a full container ID');
  process.stdout.write('RESOURCE container=' + containerName + ' id=' + containerId + ' labels=' + LABELS.join(',') + '\n');
  process.stdout.write('RESOURCE volume=' + volumeName + ' labels=' + LABELS.join(',') + '\n');

  const deadline = Date.now() + 60000;
  let ready = false;
  let readyAt;
  let lastSqlProbeError = '';
  while (Date.now() < deadline) {
    const probe = docker(['exec', containerName, 'pg_isready', '-U', 'postgres', '-d', 'p65lab'], { timeout: 5000 });
    if (probe.status === 0) {
      const sqlProbe = docker([
        'exec', '-i', '--env', 'PGPASSWORD', containerName,
        'psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
        '-U', 'postgres', '-h', '127.0.0.1', '-d', 'p65lab',
      ], {
        input: 'SELECT 1;\n',
        env: { ...process.env, PGPASSWORD: syntheticPassword },
        timeout: 5000,
      });
      if (sqlProbe.status === 0 && sqlProbe.stdout === '1') {
        ready = true;
        readyAt = new Date().toISOString();
        break;
      }
      lastSqlProbeError = (sqlProbe.stderr || '').trim();
    }
    const state = docker(['inspect', '--format', '{{.State.Status}}', containerName]);
    if (state.status !== 0 || state.stdout === 'exited' || state.stdout === 'dead') {
      const logs = docker(['logs', '--tail', '60', containerName]);
      throw new Error('lab PostgreSQL container stopped before readiness; state=' + state.stdout
        + '; logs=' + (logs.stdout + ' ' + logs.stderr).trim());
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
  if (!ready) throw new Error('lab PostgreSQL did not accept authenticated SQL within 60 seconds'
    + (lastSqlProbeError ? '; last SQL probe=' + lastSqlProbeError : ''));
  process.stdout.write('ENV postgres_ready_at=' + readyAt + ' postgres_version=' + psql('SELECT version();') + '\n');
}

function runRedControl() {
  const source = fs.readFileSync(RED_SQL, 'utf8');
  psql(source);
  process.stdout.write('COMMAND docker exec -i --env PGPASSWORD ' + containerName + ' psql -X -v ON_ERROR_STOP=1 -U postgres -h 127.0.0.1 -d p65lab < postgres-negative-control.sql exit=0\n');

  const result = command(process.execPath, [
    '--test', '--test-reporter=tap',
    '--test-name-pattern=exact retry rejects a changed expected revision|no-commit seal rejects an unrelated operation after stop acknowledgement',
    TEST_FILE,
  ], {
    env: { ...process.env, PGB_MODE: 'red', PGB_CONTAINER: containerName, PGB_DATABASE: 'p65lab', PGPASSWORD: syntheticPassword },
    timeout: 60000,
  });
  process.stdout.write('RED_EXIT=' + result.status + '\n');
  process.stdout.write(result.stdout + '\n');
  if (result.stderr) process.stdout.write(result.stderr + '\n');
  if (result.status !== 1 || !result.stdout.includes('not ok 1 - exact retry rejects a changed expected revision')
      || !result.stdout.includes('not ok 2 - no-commit seal rejects an unrelated operation after stop acknowledgement')
      || !result.stdout.includes('1..2')) {
    throw new Error('negative-control RED run did not produce exactly two expected failing assertions');
  }
}

function runSchema() {
  psql(fs.readFileSync(SCHEMA_SQL, 'utf8'));
  process.stdout.write('COMMAND docker exec -i --env PGPASSWORD ' + containerName + ' psql -X -v ON_ERROR_STOP=1 -U postgres -h 127.0.0.1 -d p65lab < postgres-schema.sql exit=0\n');
  process.stdout.write('SCHEMA_TABLES=' + psql("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'p65_lab';") + '\n');
}

function testSummary(output) {
  const tests = output.match(/^# tests (\d+)$/m);
  const pass = output.match(/^# pass (\d+)$/m);
  const fail = output.match(/^# fail (\d+)$/m);
  const skip = output.match(/^# skipped (\d+)$/m);
  return {
    tests: tests ? Number(tests[1]) : null,
    pass: pass ? Number(pass[1]) : null,
    fail: fail ? Number(fail[1]) : null,
    skipped: skip ? Number(skip[1]) : null,
  };
}

function runWindowsTests() {
  const result = command(process.execPath, ['--test', '--test-reporter=tap', TEST_FILE], {
    env: {
      ...process.env,
      PGB_MODE: 'green', PGB_CONTAINER: containerName, PGB_CONTAINER_ID: containerId,
      PGB_DATABASE: 'p65lab', PGPASSWORD: syntheticPassword,
    },
    timeout: 180000,
  });
  process.stdout.write('COMMAND node --test --test-reporter=tap lab/issue-65-packet-b/postgres-lab.test.js exit='
    + result.status + ' summary=' + JSON.stringify(testSummary(result.stdout)) + '\n');
  process.stdout.write(result.stdout + '\n');
  if (result.stderr) process.stdout.write(result.stderr + '\n');
  if (result.status !== 0 || testSummary(result.stdout).fail !== 0) {
    throw new Error('Windows Node PostgreSQL lab suite failed');
  }
}

function runWslTests() {
  const wslRoot = ROOT.replace(/^([A-Za-z]):/, (_, drive) => '/mnt/' + drive.toLowerCase()).replace(/\\/g, '/');
  const shellCommand = 'cd ' + JSON.stringify(wslRoot) + ' && node --test --test-reporter=tap postgres-lab.test.js';
  const requested = ['PGB_CONTAINER', 'PGB_CONTAINER_ID', 'PGB_DATABASE', 'PGB_MODE', 'PGPASSWORD'];
  const currentWslEnv = (process.env.WSLENV || '').split(':').filter(Boolean);
  const kept = currentWslEnv.filter((entry) => !requested.includes(entry.split('/')[0]));
  const env = {
    ...process.env,
    PGB_CONTAINER: containerName,
    PGB_CONTAINER_ID: containerId,
    PGB_DATABASE: 'p65lab',
    PGB_MODE: 'green',
    PGPASSWORD: syntheticPassword,
    WSLENV: kept.concat(requested).join(':'),
  };
  const result = command('wsl.exe', ['--exec', 'bash', '-lc', shellCommand], { env, timeout: 180000 });
  process.stdout.write('COMMAND wsl.exe --exec bash -lc "cd ' + wslRoot
    + ' && node --test --test-reporter=tap postgres-lab.test.js" exit=' + result.status
    + ' summary=' + JSON.stringify(testSummary(result.stdout)) + '\n');
  process.stdout.write(result.stdout + '\n');
  if (result.stderr) process.stdout.write(result.stderr + '\n');
  if (result.status !== 0 || testSummary(result.stdout).fail !== 0) {
    throw new Error('WSL Node PostgreSQL lab suite failed');
  }
}

function cleanup() {
  let clean = true;
  if (containerId && containerName) {
    const inspect = docker(['container', 'inspect', '--format', '{{.Id}}|{{index .Config.Labels "rootark.lab"}}|{{index .Config.Labels "rootark.owner"}}', containerName]);
    const expected = containerId + '|issue65-packet-b|local-feasibility';
    if (inspect.status === 0 && inspect.stdout === expected) {
      const removed = docker(['container', 'rm', '--force', containerId]);
      if (removed.status === 0) process.stdout.write('CLEANUP container_id=' + containerId + ' removed=true\n');
      else {
        clean = false;
        process.stdout.write('CLEANUP container_id=' + containerId + ' removed=false exit=' + removed.status + '\n');
      }
    } else if (inspect.status === 0) {
      clean = false;
      process.stdout.write('CLEANUP container_id=' + containerId + ' removed=false reason=identity_or_label_mismatch\n');
    }
  }
  if (volumeName) {
    const inspect = docker(['volume', 'inspect', '--format', '{{.Name}}|{{index .Labels "rootark.lab"}}|{{index .Labels "rootark.owner"}}', volumeName]);
    const expected = volumeName + '|issue65-packet-b|local-feasibility';
    if (inspect.status === 0 && inspect.stdout === expected) {
      const removed = docker(['volume', 'rm', volumeName]);
      if (removed.status === 0) process.stdout.write('CLEANUP volume=' + volumeName + ' removed=true\n');
      else {
        clean = false;
        process.stdout.write('CLEANUP volume=' + volumeName + ' removed=false exit=' + removed.status + '\n');
      }
    } else if (inspect.status === 0) {
      clean = false;
      process.stdout.write('CLEANUP volume=' + volumeName + ' removed=false reason=label_mismatch\n');
    }
  }
  if (syntheticPassword) syntheticPassword = undefined;
  return clean;
}

let failure;
try {
  startContainer();
  runRedControl();
  if (SCHEMA_ONLY) {
    runSchema();
    process.stdout.write('SCHEMA_ONLY_CREATED=' + psql("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'p65_lab';") + '\n');
  } else if (!RED_ONLY) {
    runSchema();
    runWindowsTests();
    runSchema();
    runWslTests();
  }
} catch (error) {
  failure = error;
  process.stderr.write('RUNNER_ERROR ' + error.message + '\n');
} finally {
  if (!cleanup()) failure = failure || new Error('lab resource cleanup incomplete');
}
if (failure) process.exitCode = 1;
