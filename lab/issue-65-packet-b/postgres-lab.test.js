'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');

const MODE = process.env.PGB_MODE || 'green';
const CONTAINER = process.env.PGB_CONTAINER;
const CONTAINER_ID = process.env.PGB_CONTAINER_ID;
// This is an opt-in disposable Docker/PostgreSQL integration laboratory, not
// a prerequisite for running the repository's ordinary unit test command.
// Never connect to an unspecified real database or fail 10 unrelated tests
// merely because the external lab container has not been provisioned.
const pgTest = (name, options, run) => test(name, {
  ...options, ...(!CONTAINER ? { skip: "PGB_CONTAINER (disposable PostgreSQL lab) is not provisioned" } : {}),
}, run);
const DATABASE = process.env.PGB_DATABASE || 'p65lab';
const DOCKER = process.platform === 'win32'
  ? 'docker'
  : (fs.existsSync('/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe')
    ? '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
    : 'docker');

function sqlText(value) {
  return "'" + String(value).replace(/'/g, "''") + "'";
}

function sqlBytea(value) {
  return "'\\x" + Buffer.from(value).toString('hex') + "'::bytea";
}

function psql(sql, options = {}) {
  assert.ok(CONTAINER, 'PGB_CONTAINER must name the disposable PostgreSQL lab container');
  const args = [
    'exec', '-i', '--env', 'PGPASSWORD',
    CONTAINER,
    'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-h', '127.0.0.1', '-d', DATABASE,
    '-A', '-t', '-P', 'pager=off',
  ];
  const result = spawnSync(DOCKER, args, {
    input: sql + '\n',
    encoding: 'utf8',
    timeout: options.timeout || 15000,
    env: process.env,
    windowsHide: true,
  });
  if (result.error) {
    throw new Error('docker exec psql failed: ' + result.error.message);
  }
  if (result.status !== 0) {
    const stderr = (result.stderr || '').trim();
    const stdout = (result.stdout || '').trim();
    throw new Error(('docker exec psql exited ' + result.status + ': ' + stderr + ' ' + stdout).trim());
  }
  return (result.stdout || '').trim();
}

function docker(args, options = {}) {
  const result = spawnSync(DOCKER, args, {
    encoding: 'utf8',
    timeout: options.timeout || 15000,
    env: process.env,
    windowsHide: true,
  });
  if (result.error) throw new Error('docker command failed: ' + result.error.message);
  return {
    status: result.status,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
  };
}

function oneRow(sql, role) {
  const prefix = role ? 'SET ROLE ' + role + ';\n' : '';
  return psql(prefix + sql).split(/\r?\n/).filter(Boolean).at(-1) || '';
}

function jsonRow(sql, role) {
  const raw = oneRow(sql, role);
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error('expected JSON result from PostgreSQL, received ' + JSON.stringify(raw) + ': ' + error.message);
  }
}

function digest(input) {
  return crypto.createHash('sha256').update(input).digest();
}

function scopeFor(suffix) {
  return {
    accountId: 'lab-account-' + suffix,
    compartmentId: 'lab-compartment-' + suffix,
    keyringId: 'lab-keyring-' + suffix,
  };
}

function scopeSql(scope) {
  return [scope.accountId, scope.compartmentId, scope.keyringId].map(sqlText).join(', ');
}

function requestBytes(input) {
  const canonical = {
    account_id: input.scope.accountId,
    compartment_id: input.scope.compartmentId,
    keyring_id: input.scope.keyringId,
    operation_id: input.operationId,
    reservation_id: input.reservationId,
    expected_revision: input.expectedRevision,
    expected_digest: Buffer.from(input.expectedDigest).toString('hex'),
    proposed_revision: input.proposedRevision,
    proposed_digest: Buffer.from(input.proposedDigest).toString('hex'),
    package_digest: input.packageDigest ? Buffer.from(input.packageDigest).toString('hex') : null,
    expires_at: input.expiresAt,
    transition_bytes: Buffer.from(input.transitionBytes).toString('hex'),
  };
  return Buffer.from(JSON.stringify(canonical), 'utf8');
}

function makeRequest(input) {
  const request = {
    scope: { ...input.scope },
    operationId: input.operationId,
    reservationId: input.reservationId,
    expectedRevision: input.expectedRevision,
    expectedDigest: Buffer.from(input.expectedDigest),
    proposedRevision: input.proposedRevision === undefined
      ? input.expectedRevision + 1
      : input.proposedRevision,
    proposedDigest: Buffer.from(input.proposedDigest),
    packageDigest: input.packageDigest ? Buffer.from(input.packageDigest) : null,
    expiresAt: input.expiresAt,
    transitionBytes: Buffer.from(input.transitionBytes || 'synthetic-transition'),
  };
  request.bytes = requestBytes(request);
  request.requestDigest = digest(request.bytes);
  return request;
}

function requestExpr(request, schema = 'p65_lab', overrides = {}) {
  const fields = [
    sqlText(request.scope.accountId),
    sqlText(request.scope.compartmentId),
    sqlText(request.scope.keyringId),
    sqlText(request.operationId),
    sqlText(request.reservationId),
    String(request.expectedRevision),
    sqlBytea(request.expectedDigest),
    String(request.proposedRevision),
    sqlBytea(request.proposedDigest),
    sqlBytea(request.requestDigest),
    request.packageDigest ? sqlBytea(request.packageDigest) : 'NULL::bytea',
    sqlText(request.expiresAt) + '::timestamptz',
    sqlBytea(request.bytes),
    sqlBytea(request.transitionBytes),
  ];
  for (const [index, expression] of Object.entries(overrides)) {
    fields[Number(index)] = expression;
  }
  return 'ROW(' + fields.join(', ') + ')::' + schema + '.request_input';
}

function serverTimestamp(offsetSeconds) {
  assert.ok(Number.isInteger(offsetSeconds));
  const sqlOffset = offsetSeconds < 0
    ? "- interval '" + (-offsetSeconds) + " seconds'"
    : "+ interval '" + offsetSeconds + " seconds'";
  return oneRow("SELECT to_char(clock_timestamp() " + sqlOffset + ", 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')");
}

function seedKeyring(scope, initialDigest, options = {}) {
  const result = jsonRow(
    'SELECT p65_lab.test_seed_keyring(' + scopeSql(scope) + ', ' + sqlBytea(initialDigest) + ', '
      + (options.deviceCount || 0) + ', ' + (options.epochCount || 1) + ', '
      + (options.transitionCount || 0) + ', ' + (options.transitionBytes || 0) + ')',
  );
  return result;
}

function reserve(request) {
  return jsonRow(
    'SELECT p65_lab.reserve_operation(' + requestExpr(request) + ')',
    'p65_cas',
  );
}

function beginQuiesce(request, generation, overrides = {}) {
  const scope = overrides.scope || request.scope;
  const operationId = overrides.operationId || request.operationId;
  const reservationId = overrides.reservationId || request.reservationId;
  return jsonRow(
    'SELECT p65_lab.begin_quiesce(' + scopeSql(scope) + ', ' + sqlText(operationId) + ', '
      + sqlText(reservationId) + ', ' + request.expectedRevision + ', '
      + sqlBytea(request.expectedDigest) + ', ' + generation + ')',
    'p65_gate',
  );
}

function commit(request) {
  return jsonRow(
    'SELECT p65_lab.commit_operation(' + requestExpr(request) + ', false)',
    'p65_cas',
  );
}

function keyringDigest(scope) {
  return digest('genesis:' + scope.accountId + ':' + scope.compartmentId + ':' + scope.keyringId);
}

function normalRequest(suffix, scope, overrides = {}) {
  const expectedDigest = overrides.expectedDigest || keyringDigest(scope);
  const proposedDigest = overrides.proposedDigest || digest('manifest:' + suffix);
  return makeRequest({
    scope,
    operationId: overrides.operationId || 'op-' + suffix,
    reservationId: overrides.reservationId || 'res-' + suffix,
    expectedRevision: overrides.expectedRevision === undefined ? 0 : overrides.expectedRevision,
    expectedDigest,
    proposedRevision: overrides.proposedRevision,
    proposedDigest,
    packageDigest: overrides.packageDigest || digest('package:' + suffix),
    expiresAt: overrides.expiresAt || serverTimestamp(300),
    transitionBytes: overrides.transitionBytes || Buffer.from('synthetic transition ' + suffix),
  });
}

function commitThroughCas(request) {
  seedKeyring(request.scope, request.expectedDigest);
  const reserved = reserve(request);
  assert.equal(reserved.status, 'RESERVED');
  const quiesced = beginQuiesce(request, reserved.generation);
  assert.equal(quiesced.status, 'QUIESCING');
  return commit(request);
}

function storedCount(table, predicate) {
  return oneRow('SELECT count(*) FROM p65_lab.' + table + ' WHERE ' + predicate);
}

function setClockOffset(seconds) {
  return jsonRow('SELECT p65_lab.set_test_clock_offset(' + seconds + ')', 'p65_test');
}

function psqlArgs() {
  return [
    'exec', '-i', '--env', 'PGPASSWORD', CONTAINER,
    'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-h', '127.0.0.1', '-d', DATABASE,
    '-A', '-t', '-P', 'pager=off',
  ];
}

function startSqlSession(sql) {
  assert.ok(CONTAINER, 'PGB_CONTAINER must name the disposable PostgreSQL lab container');
  const child = spawn(DOCKER, psqlArgs(), {
    env: process.env,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const session = { child, stdout: '', stderr: '', closed: false, exitCode: null };
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { session.stdout += chunk; });
  child.stderr.on('data', (chunk) => { session.stderr += chunk; });
  child.stdin.on('error', (error) => {
    if (error.code !== 'EPIPE') session.stderr += error.message;
  });
  child.on('close', (code) => { session.closed = true; session.exitCode = code; });
  child.on('error', (error) => { session.stderr += error.message; session.closed = true; session.exitCode = -1; });
  child.stdin.write(sql);
  return session;
}

function waitForOutput(session, marker, timeoutMs = 10000) {
  if (session.stdout.includes(marker)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const poll = () => {
      if (session.stdout.includes(marker)) return resolve();
      if (session.closed) return reject(new Error('psql session closed before marker ' + marker + ': ' + session.stderr));
      if (Date.now() - startedAt >= timeoutMs) return reject(new Error('timed out waiting for psql marker ' + marker));
      setTimeout(poll, 25);
    };
    poll();
  });
}

function finishSqlSession(session, trailingSql = '') {
  if (!session.closed && !session.child.stdin.destroyed && session.child.stdin.writable) {
    session.child.stdin.end(trailingSql);
  }
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const poll = () => {
      if (session.closed) return resolve(session);
      if (Date.now() - startedAt >= 15000) {
        session.child.kill();
        return reject(new Error('psql session did not close within 15 seconds'));
      }
      setTimeout(poll, 25);
    };
    poll();
  });
}

async function waitForLockWait(applicationName, timeoutMs = 10000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const count = oneRow(
      "SELECT count(*) FROM pg_stat_activity WHERE application_name = " + sqlText(applicationName)
        + " AND wait_event_type = 'Lock' AND datname = " + sqlText(DATABASE),
    );
    if (Number(count) > 0) return Number(count);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('no PostgreSQL lock wait observed for ' + applicationName);
}

function requestFlowSql(request, applicationName) {
  const gen = 1;
  return "SET application_name = " + sqlText(applicationName) + ";\n"
    + 'SET ROLE p65_cas; SELECT p65_lab.reserve_operation(' + requestExpr(request) + '); RESET ROLE;\n'
    + 'SET ROLE p65_gate; SELECT p65_lab.begin_quiesce(' + scopeSql(request.scope) + ', '
    + sqlText(request.operationId) + ', ' + sqlText(request.reservationId) + ', '
    + request.expectedRevision + ', ' + sqlBytea(request.expectedDigest) + ', ' + gen + '); RESET ROLE;\n'
    + 'SET ROLE p65_cas; SELECT p65_lab.commit_operation(' + requestExpr(request) + ', false); RESET ROLE;\n';
}

pgTest('exact retry rejects a changed expected revision', { concurrency: false }, () => {
  if (MODE === 'red') {
    const payloadDigest = digest('same-synthetic-payload');
    assert.equal(
      oneRow('SELECT p65_red.commit_request(' + sqlText('op-red-request') + ', ' + sqlBytea(payloadDigest) + ', 0)'),
      'COMMITTED',
    );
    const changedRevision = oneRow(
      'SELECT p65_red.commit_request(' + sqlText('op-red-request') + ', ' + sqlBytea(payloadDigest) + ', 999)',
    );
    assert.equal(changedRevision, 'OPERATION_CONFLICT');
    return;
  }

  const scope = scopeFor('exact-retry');
  const request = normalRequest('exact-retry', scope);
  assert.equal(seedKeyring(scope, request.expectedDigest).status, 'SEEDED');
  commitThroughCas(request); // Simulate losing the client response after PostgreSQL COMMIT.
  const durable = jsonRow('SELECT result FROM p65_lab.operation_terminal WHERE operation_id = '
    + sqlText(request.operationId));
  assert.equal(durable.status, 'COMMITTED');
  assert.equal(durable.operation_id, request.operationId);
  const exactRetry = commit(request);
  assert.deepEqual(exactRetry, durable);
  assert.equal(storedCount('transition_log', 'operation_id = ' + sqlText(request.operationId)), '1');
  assert.equal(storedCount('operation_terminal', 'operation_id = ' + sqlText(request.operationId)), '1');

  const changedExpectedDigest = Buffer.from(request.expectedDigest);
  changedExpectedDigest[0] ^= 1;
  const changedProposedDigest = Buffer.from(request.proposedDigest);
  changedProposedDigest[0] ^= 1;
  const changedPackageDigest = Buffer.from(request.packageDigest);
  changedPackageDigest[0] ^= 1;
  const mutations = [
    ['expected revision', { expectedRevision: 999, proposedRevision: 1000 }],
    ['expected digest', { expectedDigest: changedExpectedDigest }],
    ['proposed digest', { proposedDigest: changedProposedDigest }],
    ['reservation id', { reservationId: 'res-changed-exact-retry' }],
    ['package digest', { packageDigest: changedPackageDigest }],
    ['scope', { scope: { ...request.scope, accountId: request.scope.accountId + '-changed' } }],
    ['expiry', { expiresAt: serverTimestamp(301) }],
    ['transition bytes', { transitionBytes: Buffer.from('changed transition bytes') }],
  ];
  for (const [component, change] of mutations) {
    const changedRequest = makeRequest({ ...request, ...change });
    const retry = commit(changedRequest);
    assert.equal(retry.status, 'OPERATION_CONFLICT', component + ' change must conflict');
  }
  const badDigestOnly = { ...request, requestDigest: digest('changed request digest') };
  assert.equal(commit(badDigestOnly).status, 'OPERATION_CONFLICT', 'changed request digest must conflict');
  const changedOperationId = makeRequest({ ...request, operationId: request.operationId + '-changed' });
  assert.equal(commit(changedOperationId).status, 'NOT_RESERVED', 'a new operation id is not the stored retry');
  // PostgreSQL's three-valued logic must never turn a NULL-mutated retry
  // into the original committed result (or a nullable exact-match result).
  for (const [field, index, cast] of [
    ['expected revision', 5, 'bigint'],
    ['expected digest', 6, 'bytea'],
    ['scope account', 0, 'text'],
    ['package digest', 10, 'bytea'],
    ['expiry', 11, 'timestamptz'],
    ['request bytes', 12, 'bytea'],
  ]) {
    const changedInput = requestExpr(request, 'p65_lab', { [index]: 'NULL::' + cast });
    const exactMatch = oneRow('SELECT p65_lab.request_matches(o, ' + changedInput + ') IS FALSE '
      + 'FROM p65_lab.operation_request o WHERE o.operation_id = ' + sqlText(request.operationId));
    assert.equal(exactMatch, 't', field + ' NULL must produce an explicit false comparison');
    assert.equal(jsonRow('SELECT p65_lab.reserve_operation(' + changedInput + ')', 'p65_cas').status,
      'OPERATION_CONFLICT', field + ' NULL must reject reserve retry');
    assert.equal(jsonRow('SELECT p65_lab.commit_operation(' + changedInput + ', false)', 'p65_cas').status,
      'OPERATION_CONFLICT', field + ' NULL must reject commit retry');
  }
  assert.equal(storedCount('transition_log', 'operation_id = ' + sqlText(request.operationId)), '1');
  assert.equal(storedCount('operation_terminal', 'operation_id = ' + sqlText(request.operationId)), '1');
  assert.equal(storedCount('operation_request', 'operation_id = ' + sqlText(request.operationId)), '1');
});

pgTest('no-commit seal rejects an unrelated operation after stop acknowledgement', { concurrency: false }, () => {
  if (MODE === 'red') {
    assert.equal(
      oneRow(
        'SELECT p65_red.prepare_gate(' + sqlText('op-a') + ', ' + sqlText('res-a') + ', '
          + sqlText('acct-a') + ', ' + sqlText('comp-a') + ', ' + sqlText('kr-a') + ', 0, 2)',
      ),
      'READY',
    );
    const result = oneRow('SELECT p65_red.seal_no_commit(' + sqlText('unrelated-op') + ')');
    assert.equal(result, 'GATE_BINDING_MISMATCH');
    return;
  }

  const scope = scopeFor('gate-binding');
  const initialDigest = keyringDigest(scope);
  assert.equal(seedKeyring(scope, initialDigest).status, 'SEEDED');
  const request = normalRequest('gate-binding', scope, { expiresAt: serverTimestamp(0) });
  const generationBefore = 1;
  const permitId = 'permit-gate-binding';
  const permitId2 = 'permit-gate-binding-2';
  const stalePermitId = 'permit-stale-generation';
  const effectId = 'effect-gate-binding';
  const effectId2 = 'effect-gate-binding-2';

  const permit = jsonRow(
    'SELECT p65_lab.issue_permit(' + scopeSql(scope) + ', ' + sqlText(request.operationId) + ', '
      + sqlText(request.reservationId) + ', 0, ' + sqlBytea(initialDigest) + ', '
      + 1 + ', ' + generationBefore + ', ' + sqlText(permitId) + ')',
    'p65_gate',
  );
  assert.equal(permit.status, 'PERMIT_ISSUED');
  assert.equal(jsonRow(
    'SELECT p65_lab.issue_permit(' + scopeSql(scope) + ', ' + sqlText(request.operationId) + ', '
      + sqlText(request.reservationId) + ', 0, ' + sqlBytea(initialDigest) + ', 1, '
      + generationBefore + ', ' + sqlText(permitId2) + ')',
    'p65_gate',
  ).status, 'PERMIT_ISSUED');
  assert.equal(jsonRow(
    'SELECT p65_lab.issue_permit(' + scopeSql(scope) + ', ' + sqlText('op-stale') + ', '
      + sqlText('res-stale') + ', 0, ' + sqlBytea(initialDigest) + ', 1, '
      + generationBefore + ', ' + sqlText(stalePermitId) + ')',
    'p65_gate',
  ).status, 'PERMIT_ISSUED');
  assert.equal(jsonRow(
    'SELECT p65_lab.issue_permit(' + scopeSql(scope) + ', ' + sqlText('op-wrong-epoch') + ', '
      + sqlText('res-wrong-epoch') + ', 0, ' + sqlBytea(initialDigest) + ', 2, '
      + generationBefore + ', ' + sqlText('permit-wrong-epoch') + ')',
    'p65_gate',
  ).status, 'STALE_HEAD_OR_GENERATION');

  const wrongConsume = jsonRow(
    'SELECT p65_lab.consume_permit(' + scopeSql(scope) + ', ' + sqlText(permitId) + ', '
      + sqlText('unrelated-op') + ', ' + sqlText(request.reservationId) + ', 0, '
      + sqlBytea(initialDigest) + ', 1, ' + generationBefore + ', ' + sqlText(effectId) + ')',
    'p65_gate',
  );
  assert.equal(wrongConsume.status, 'GATE_BINDING_MISMATCH');
  assert.equal(jsonRow(
    'SELECT p65_lab.consume_permit(' + scopeSql(scope) + ', ' + sqlText(permitId) + ', '
      + sqlText(request.operationId) + ', ' + sqlText(request.reservationId) + ', 0, '
      + sqlBytea(initialDigest) + ', 2, ' + generationBefore + ', ' + sqlText('effect-wrong-epoch') + ')',
    'p65_gate',
  ).status, 'GATE_BINDING_MISMATCH');
  assert.equal(jsonRow(
    'SELECT p65_lab.consume_permit(' + sqlText(scope.accountId) + ', ' + sqlText(scope.compartmentId)
      + ', ' + sqlText(scope.keyringId + '-wrong') + ', ' + sqlText(permitId) + ', '
      + sqlText(request.operationId) + ', ' + sqlText(request.reservationId) + ', 0, '
      + sqlBytea(initialDigest) + ', 1, ' + generationBefore + ', ' + sqlText(effectId) + ')',
    'p65_gate',
  ).status, 'GATE_BINDING_MISMATCH');

  const consumed = jsonRow(
    'SELECT p65_lab.consume_permit(' + scopeSql(scope) + ', ' + sqlText(permitId) + ', '
      + sqlText(request.operationId) + ', ' + sqlText(request.reservationId) + ', 0, '
      + sqlBytea(initialDigest) + ', 1, ' + generationBefore + ', ' + sqlText(effectId) + ')',
    'p65_gate',
  );
  assert.equal(consumed.status, 'CONSUMED');
  assert.equal(jsonRow(
    'SELECT p65_lab.consume_permit(' + scopeSql(scope) + ', ' + sqlText(permitId2) + ', '
      + sqlText(request.operationId) + ', ' + sqlText(request.reservationId) + ', 0, '
      + sqlBytea(initialDigest) + ', 1, ' + generationBefore + ', ' + sqlText(effectId2) + ')',
    'p65_gate',
  ).status, 'CONSUMED');
  assert.equal(jsonRow(
    'SELECT p65_lab.consume_permit(' + scopeSql(scope) + ', ' + sqlText(permitId) + ', '
      + sqlText(request.operationId) + ', ' + sqlText(request.reservationId) + ', 0, '
      + sqlBytea(initialDigest) + ', 1, ' + generationBefore + ', ' + sqlText('effect-replay') + ')',
    'p65_gate',
  ).status, 'PERMIT_REPLAY');
  assert.equal(jsonRow(
    'SELECT p65_lab.allow_simulated_io(' + scopeSql(scope) + ', ' + sqlText(request.operationId) + ', '
      + sqlText(request.reservationId) + ', ' + sqlText(effectId) + ', ' + generationBefore + ')',
    'p65_gate',
  ).status, 'ALLOW_SIMULATED_ONLY');

  const reserved = reserve(request);
  assert.equal(reserved.status, 'RESERVED');
  assert.equal(reserved.generation, 1);
  assert.equal(jsonRow(
    'SELECT p65_lab.consume_permit(' + scopeSql(scope) + ', ' + sqlText(stalePermitId) + ', '
      + sqlText('op-stale') + ', ' + sqlText('res-stale') + ', 0, ' + sqlBytea(initialDigest)
      + ', 1, 1, ' + sqlText('effect-before-quiesce') + ')',
    'p65_gate',
  ).status, 'GATE_CLOSED');
  assert.equal(jsonRow(
    'SELECT p65_lab.read_head(' + scopeSql(scope) + ')',
    'p65_cas',
  ).status, 'GATE_CLOSED');
  assert.equal(jsonRow(
    'SELECT p65_lab.issue_permit(' + scopeSql(scope) + ', ' + sqlText('op-new') + ', '
      + sqlText('res-new') + ', 0, ' + sqlBytea(initialDigest) + ', 1, 1, ' + sqlText('permit-new') + ')',
    'p65_gate',
  ).status, 'GATE_CLOSED');
  assert.equal(jsonRow(
    'SELECT p65_lab.allow_simulated_io(' + scopeSql(scope) + ', ' + sqlText(request.operationId) + ', '
      + sqlText(request.reservationId) + ', ' + sqlText(effectId) + ', 1)',
    'p65_gate',
  ).status, 'BLOCKED_GATE');
  const wrongQuiesce = beginQuiesce(request, reserved.generation, { operationId: 'unrelated-op' });
  assert.equal(wrongQuiesce.status, 'GATE_BINDING_MISMATCH');

  const quiesced = beginQuiesce(request, reserved.generation);
  assert.equal(quiesced.status, 'QUIESCING');
  assert.equal(quiesced.stopCount, 2);
  assert.equal(jsonRow(
    'SELECT p65_lab.consume_permit(' + scopeSql(scope) + ', ' + sqlText(stalePermitId) + ', '
      + sqlText('op-stale') + ', ' + sqlText('res-stale') + ', 0, ' + sqlBytea(initialDigest)
      + ', 1, 1, ' + sqlText('effect-after-quiesce') + ')',
    'p65_gate',
  ).status, 'GATE_CLOSED');

  const expectedAck = oneRow(
    'SELECT expected_ack_id FROM p65_lab.stop_ack_requests WHERE effect_id = ' + sqlText(effectId)
      + ' AND operation_id = ' + sqlText(request.operationId),
  );
  const expectedAck2 = oneRow(
    'SELECT expected_ack_id FROM p65_lab.stop_ack_requests WHERE effect_id = ' + sqlText(effectId2)
      + ' AND operation_id = ' + sqlText(request.operationId),
  );
  assert.equal(jsonRow(
    'SELECT p65_lab.acknowledge_stop(' + scopeSql(scope) + ', ' + sqlText(request.operationId) + ', '
      + sqlText(request.reservationId) + ', ' + sqlText(effectId) + ', ' + sqlText('wrong-ack-id') + ', '
      + reserved.generation + ')',
    'p65_gate',
  ).status, 'STOP_ACK_MISMATCH');
  const wrongAck = jsonRow(
    'SELECT p65_lab.acknowledge_stop(' + scopeSql(scope) + ', ' + sqlText('unrelated-op') + ', '
      + sqlText(request.reservationId) + ', ' + sqlText(effectId) + ', ' + sqlText(expectedAck) + ', '
      + reserved.generation + ')',
    'p65_gate',
  );
  assert.equal(wrongAck.status, 'GATE_BINDING_MISMATCH');

  const acked = jsonRow(
    'SELECT p65_lab.acknowledge_stop(' + scopeSql(scope) + ', ' + sqlText(request.operationId) + ', '
      + sqlText(request.reservationId) + ', ' + sqlText(effectId) + ', ' + sqlText(expectedAck) + ', '
      + reserved.generation + ')',
    'p65_gate',
  );
  assert.equal(acked.status, 'ACKNOWLEDGED');
  const replayedAck = jsonRow(
    'SELECT p65_lab.acknowledge_stop(' + scopeSql(scope) + ', ' + sqlText(request.operationId) + ', '
      + sqlText(request.reservationId) + ', ' + sqlText(effectId) + ', ' + sqlText(expectedAck) + ', '
      + reserved.generation + ')',
    'p65_gate',
  );
  assert.equal(replayedAck.status, 'STOP_ACK_REPLAY');

  const unrelatedRequest = makeRequest({
    ...request,
    operationId: 'unrelated-op',
    requestDigest: undefined,
    bytes: undefined,
  });
  const wrongSeal = jsonRow(
    'SELECT p65_lab.seal_no_commit(' + requestExpr(unrelatedRequest) + ')',
    'p65_status',
  );
  assert.equal(wrongSeal.status, 'GATE_BINDING_MISMATCH');
  assert.equal(storedCount('no_commit_fence', 'reservation_id = ' + sqlText(request.reservationId)), '0');
  assert.equal(
    oneRow(
      'SELECT gate_state FROM p65_lab.keyring_head WHERE account_id = ' + sqlText(scope.accountId)
        + ' AND compartment_id = ' + sqlText(scope.compartmentId)
        + ' AND keyring_id = ' + sqlText(scope.keyringId),
    ),
    'QUIESCING',
  );

  const tooEarly = jsonRow(
    'SELECT p65_lab.seal_no_commit(' + requestExpr(request) + ')',
    'p65_status',
  );
  assert.equal(tooEarly.status, 'WAIT_EXPIRY_BOUND');
  assert.equal(setClockOffset(31).status, 'SET');
  assert.equal(jsonRow(
    'SELECT p65_lab.seal_no_commit(' + requestExpr(request) + ')',
    'p65_status',
  ).status, 'STOP_ACKS_INCOMPLETE');
  assert.equal(jsonRow(
    'SELECT p65_lab.acknowledge_stop(' + scopeSql(scope) + ', ' + sqlText(request.operationId) + ', '
      + sqlText(request.reservationId) + ', ' + sqlText(effectId2) + ', ' + sqlText(expectedAck2) + ', '
      + reserved.generation + ')',
    'p65_gate',
  ).status, 'ACKNOWLEDGED');

  const fence = jsonRow(
    'SELECT p65_lab.seal_no_commit(' + requestExpr(request) + ')',
    'p65_status',
  );
  assert.equal(fence.status, 'NO_COMMIT_FINAL');
  // A finalized result cannot be replayed with an altered nullable field.
  const nullRevisionRetry = requestExpr(request, 'p65_lab', { 5: 'NULL::bigint' });
  assert.equal(jsonRow('SELECT p65_lab.seal_no_commit(' + nullRevisionRetry + ')',
    'p65_status').status, 'OPERATION_CONFLICT');
  assert.equal(storedCount('no_commit_fence', 'reservation_id = ' + sqlText(request.reservationId)), '1');
  assert.equal(jsonRow(
    'SELECT p65_lab.consume_permit(' + scopeSql(scope) + ', ' + sqlText(stalePermitId) + ', '
      + sqlText('op-stale') + ', ' + sqlText('res-stale') + ', 0, ' + sqlBytea(initialDigest)
      + ', 1, 1, ' + sqlText('effect-after-fence') + ')',
    'p65_gate',
  ).status, 'STALE_HEAD_OR_GENERATION');
  assert.equal(setClockOffset(0).status, 'SET');
});

pgTest('two PostgreSQL sessions serialize compare-and-append on one exact head', { concurrency: false }, async (t) => {
  const scope = scopeFor('cas-race');
  const initialDigest = keyringDigest(scope);
  assert.equal(seedKeyring(scope, initialDigest).status, 'SEEDED');
  const requestA = normalRequest('cas-race-a', scope, { expectedDigest: initialDigest });
  const requestB = normalRequest('cas-race-b', scope, { expectedDigest: initialDigest });
  const appA = 'p65-cas-race-a';
  const appB = 'p65-cas-race-b';

  const a = startSqlSession(
    "SET application_name = " + sqlText(appA) + '; BEGIN; SELECT revision FROM p65_lab.keyring_head WHERE account_id = '
      + sqlText(scope.accountId) + ' AND compartment_id = ' + sqlText(scope.compartmentId)
      + ' AND keyring_id = ' + sqlText(scope.keyringId) + ' FOR UPDATE; \\echo P65_HEAD_LOCKED\n'
      + requestFlowSql(requestA, appA) + '\\echo P65_A_READY\n',
  );
  await waitForOutput(a, 'P65_A_READY');
  const b = startSqlSession('BEGIN;\n' + requestFlowSql(requestB, appB) + 'COMMIT;\n\\q\n');
  const lockWaits = await waitForLockWait(appB);
  t.diagnostic('Observed PostgreSQL lock wait for ' + appB + ': ' + lockWaits + ' distinct client session.');
  const aDone = await finishSqlSession(a, 'COMMIT;\n\\q\n');
  const bDone = await finishSqlSession(b);
  assert.equal(aDone.exitCode, 0, aDone.stderr);
  assert.equal(bDone.exitCode, 0, bDone.stderr);
  assert.match(aDone.stdout, /"status": "COMMITTED"/);
  assert.match(bDone.stdout, /"status": "HEAD_MISMATCH"/);
  assert.equal(oneRow('SELECT revision FROM p65_lab.keyring_head WHERE account_id = ' + sqlText(scope.accountId)
    + ' AND compartment_id = ' + sqlText(scope.compartmentId) + ' AND keyring_id = ' + sqlText(scope.keyringId)), '1');
  assert.equal(storedCount('transition_log', 'account_id = ' + sqlText(scope.accountId)), '1');
  assert.equal(storedCount('operation_terminal', 'operation_id IN (' + sqlText(requestA.operationId) + ', '
    + sqlText(requestB.operationId) + ')'), '1');
  assert.equal(storedCount('operation_request', 'operation_id = ' + sqlText(requestB.operationId)), '0');
});

pgTest('account compartment and keyring scopes remain independent', { concurrency: false }, () => {
  const base = scopeFor('scope-base');
  const scopes = [
    base,
    { ...base, accountId: base.accountId + '-other' },
    { ...base, compartmentId: base.compartmentId + '-other' },
    { ...base, keyringId: base.keyringId + '-other' },
  ];
  const operationIds = [];
  for (let index = 0; index < scopes.length; index += 1) {
    const scope = scopes[index];
    const initialDigest = keyringDigest(scope);
    assert.equal(seedKeyring(scope, initialDigest).status, 'SEEDED');
    const request = normalRequest('scope-' + index, scope, { expectedDigest: initialDigest });
    operationIds.push(request.operationId);
    assert.equal(commitThroughCas(request).status, 'COMMITTED');
  }
  const scopePredicate = scopes.map((scope) => '(account_id = ' + sqlText(scope.accountId)
    + ' AND compartment_id = ' + sqlText(scope.compartmentId) + ' AND keyring_id = ' + sqlText(scope.keyringId) + ')').join(' OR ');
  const operationPredicate = 'operation_id IN (' + operationIds.map(sqlText).join(', ') + ')';
  assert.equal(storedCount('keyring_head', '(' + scopePredicate + ') AND revision = 1'), '4');
  assert.equal(storedCount('transition_log', operationPredicate), '4');
  assert.equal(storedCount('operation_terminal', operationPredicate + " AND terminal_status = 'COMMITTED'"), '4');
});

pgTest('fault before commit rolls back transition head result and fence atomically', { concurrency: false }, () => {
  const scope = scopeFor('statement-rollback');
  const request = normalRequest('statement-rollback', scope);
  assert.equal(seedKeyring(scope, request.expectedDigest).status, 'SEEDED');
  const reserved = reserve(request);
  assert.equal(reserved.status, 'RESERVED');
  assert.equal(beginQuiesce(request, reserved.generation).status, 'QUIESCING');
  assert.throws(() => psql('SET ROLE p65_cas; SELECT p65_lab.commit_operation(' + requestExpr(request) + ', true);'), /LAB_INJECTED_BEFORE_HEAD_AND_TERMINAL_COMMIT/);
  const head = oneRow("SELECT revision::text || ':' || gate_state FROM p65_lab.keyring_head WHERE account_id = "
    + sqlText(scope.accountId) + ' AND compartment_id = ' + sqlText(scope.compartmentId)
    + ' AND keyring_id = ' + sqlText(scope.keyringId));
  assert.equal(head, '0:QUIESCING');
  assert.equal(storedCount('transition_log', 'operation_id = ' + sqlText(request.operationId)), '0');
  assert.equal(storedCount('operation_terminal', 'operation_id = ' + sqlText(request.operationId)), '0');
  assert.equal(storedCount('no_commit_fence', 'operation_id = ' + sqlText(request.operationId)), '0');
});

pgTest('commit and not-committed fence race is exclusive in both session orderings', { concurrency: false }, async (t) => {
  const commitScope = scopeFor('commit-wins');
  const commitRequest = normalRequest('commit-wins', commitScope, { expiresAt: serverTimestamp(0) });
  assert.equal(seedKeyring(commitScope, commitRequest.expectedDigest).status, 'SEEDED');
  const commitReservation = reserve(commitRequest);
  assert.equal(commitReservation.status, 'RESERVED');
  assert.equal(beginQuiesce(commitRequest, commitReservation.generation).status, 'QUIESCING');
  const commitAppA = 'p65-fence-commit-a';
  const commitAppB = 'p65-fence-commit-b';
  const commitA = startSqlSession(
    'SET application_name = ' + sqlText(commitAppA) + '; BEGIN; SET ROLE p65_cas; SELECT p65_lab.commit_operation('
      + requestExpr(commitRequest) + ', false); RESET ROLE; \\echo P65_COMMIT_READY\n',
  );
  await waitForOutput(commitA, 'P65_COMMIT_READY');
  const fenceB = startSqlSession('SET application_name = ' + sqlText(commitAppB) + '; SET ROLE p65_status; SELECT p65_lab.seal_no_commit('
    + requestExpr(commitRequest) + '); RESET ROLE; \\q\n');
  const commitWaits = await waitForLockWait(commitAppB);
  t.diagnostic('Commit-first interleaving observed ' + commitWaits + ' waiting PostgreSQL session.');
  const commitADone = await finishSqlSession(commitA, 'COMMIT;\n\\q\n');
  const fenceBDone = await finishSqlSession(fenceB);
  assert.equal(commitADone.exitCode, 0, commitADone.stderr);
  assert.equal(fenceBDone.exitCode, 0, fenceBDone.stderr);
  assert.match(fenceBDone.stdout, /"status": "COMMIT_ALREADY_EXISTS"/);
  assert.equal(storedCount('transition_log', 'operation_id = ' + sqlText(commitRequest.operationId)), '1');
  assert.equal(storedCount('no_commit_fence', 'operation_id = ' + sqlText(commitRequest.operationId)), '0');
  assert.equal(oneRow('SELECT terminal_status FROM p65_lab.operation_terminal WHERE operation_id = '
    + sqlText(commitRequest.operationId)), 'COMMITTED');

  const fenceScope = scopeFor('fence-wins');
  const fenceRequest = normalRequest('fence-wins', fenceScope, { expiresAt: serverTimestamp(0) });
  assert.equal(seedKeyring(fenceScope, fenceRequest.expectedDigest).status, 'SEEDED');
  const fenceReservation = reserve(fenceRequest);
  assert.equal(fenceReservation.status, 'RESERVED');
  assert.equal(beginQuiesce(fenceRequest, fenceReservation.generation).status, 'QUIESCING');
  assert.equal(setClockOffset(31).status, 'SET');
  const fenceAppA = 'p65-fence-wins-a';
  const fenceAppB = 'p65-fence-wins-b';
  const fenceA = startSqlSession(
    'SET application_name = ' + sqlText(fenceAppA) + '; BEGIN; SET ROLE p65_status; SELECT p65_lab.seal_no_commit('
      + requestExpr(fenceRequest) + '); RESET ROLE; \\echo P65_FENCE_READY\n',
  );
  await waitForOutput(fenceA, 'P65_FENCE_READY');
  const commitB = startSqlSession('SET application_name = ' + sqlText(fenceAppB) + '; SET ROLE p65_cas; SELECT p65_lab.commit_operation('
    + requestExpr(fenceRequest) + ', false); RESET ROLE; \\q\n');
  const fenceWaits = await waitForLockWait(fenceAppB);
  t.diagnostic('Fence-first interleaving observed ' + fenceWaits + ' waiting PostgreSQL session.');
  const fenceADone = await finishSqlSession(fenceA, 'COMMIT;\n\\q\n');
  const commitBDone = await finishSqlSession(commitB);
  assert.equal(fenceADone.exitCode, 0, fenceADone.stderr);
  assert.equal(commitBDone.exitCode, 0, commitBDone.stderr);
  assert.match(commitBDone.stdout, /"status": "NO_COMMIT_FINAL"/);
  assert.equal(storedCount('transition_log', 'operation_id = ' + sqlText(fenceRequest.operationId)), '0');
  assert.equal(storedCount('no_commit_fence', 'operation_id = ' + sqlText(fenceRequest.operationId)), '1');
  assert.equal(oneRow('SELECT terminal_status FROM p65_lab.operation_terminal WHERE operation_id = '
    + sqlText(fenceRequest.operationId)), 'NO_COMMIT_FINAL');
  assert.equal(setClockOffset(0).status, 'SET');
});

pgTest('a client disconnect aborts an in-flight reservation transaction', { concurrency: false }, async () => {
  const scope = scopeFor('aborted-transaction');
  const request = normalRequest('aborted-transaction', scope);
  assert.equal(seedKeyring(scope, request.expectedDigest).status, 'SEEDED');
  const applicationName = 'p65-abort-' + crypto.randomBytes(3).toString('hex');
  const session = startSqlSession(
    'SET application_name = ' + sqlText(applicationName) + '; BEGIN; SET ROLE p65_cas; SELECT p65_lab.reserve_operation('
      + requestExpr(request) + '); RESET ROLE; SELECT pg_sleep(60); COMMIT; \\q\n',
  );
  await waitForOutput(session, 'RESERVED');
  const backendCount = oneRow("SELECT count(*) FROM pg_stat_activity WHERE application_name = "
    + sqlText(applicationName) + " AND datname = " + sqlText(DATABASE));
  assert.equal(backendCount, '1');
  assert.equal(oneRow('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = '
    + sqlText(applicationName) + ' AND datname = ' + sqlText(DATABASE) + ' AND pid <> pg_backend_pid()'), 't');
  const aborted = await finishSqlSession(session);
  assert.notEqual(aborted.exitCode, 0, 'terminated PostgreSQL session must fail before COMMIT');
  assert.equal(oneRow('SELECT gate_state FROM p65_lab.keyring_head WHERE account_id = ' + sqlText(scope.accountId)
    + ' AND compartment_id = ' + sqlText(scope.compartmentId) + ' AND keyring_id = ' + sqlText(scope.keyringId)), 'OPEN');
  assert.equal(storedCount('operation_request', 'operation_id = ' + sqlText(request.operationId)), '0');
  assert.equal(storedCount('transition_log', 'operation_id = ' + sqlText(request.operationId)), '0');
  assert.equal(storedCount('operation_terminal', 'operation_id = ' + sqlText(request.operationId)), '0');
  assert.equal(storedCount('no_commit_fence', 'operation_id = ' + sqlText(request.operationId)), '0');
});

pgTest('modeled capacity constraints and table permissions fail closed', { concurrency: false }, () => {
  const badDeviceScope = scopeFor('device-limit');
  assert.equal(seedKeyring(badDeviceScope, keyringDigest(badDeviceScope), { deviceCount: 257 }).status, 'DEVICE_LIMIT');
  const badEpochScope = scopeFor('epoch-limit');
  assert.equal(seedKeyring(badEpochScope, keyringDigest(badEpochScope), { epochCount: 65 }).status, 'EPOCH_LIMIT');
  const maximumScope = scopeFor('capacity-maxima');
  assert.equal(seedKeyring(maximumScope, keyringDigest(maximumScope), { deviceCount: 256, epochCount: 64 }).status, 'SEEDED');
  assert.equal(oneRow('SELECT device_count::text || \'/\' || epoch_count::text FROM p65_lab.keyring_head WHERE account_id = '
    + sqlText(maximumScope.accountId) + ' AND compartment_id = ' + sqlText(maximumScope.compartmentId)
    + ' AND keyring_id = ' + sqlText(maximumScope.keyringId)), '256/64');
  assert.equal(storedCount('keyring_head', "account_id IN ('lab-account-device-limit', 'lab-account-epoch-limit')"), '0');

  const historyCountScope = scopeFor('history-count-limit');
  const historyCountRequest = normalRequest('history-count-limit', historyCountScope);
  assert.equal(seedKeyring(historyCountScope, historyCountRequest.expectedDigest, { transitionCount: 4096 }).status, 'SEEDED');
  assert.equal(reserve(historyCountRequest).status, 'HISTORY_LIMIT');
  const historyBytesScope = scopeFor('history-byte-limit');
  const historyBytesRequest = normalRequest('history-byte-limit', historyBytesScope);
  assert.equal(seedKeyring(historyBytesScope, historyBytesRequest.expectedDigest, { transitionBytes: 67108864 }).status, 'SEEDED');
  assert.equal(reserve(historyBytesRequest).status, 'HISTORY_LIMIT');

  const malformedScope = scopeFor('malformed-request');
  const malformed = normalRequest('malformed-request', malformedScope, { proposedRevision: 7 });
  assert.equal(seedKeyring(malformedScope, malformed.expectedDigest).status, 'SEEDED');
  assert.equal(reserve(malformed).status, 'INVALID_REQUEST');
  const digestScope = scopeFor('bad-digest');
  const badDigestRequest = normalRequest('bad-digest', digestScope);
  assert.equal(seedKeyring(digestScope, badDigestRequest.expectedDigest).status, 'SEEDED');
  badDigestRequest.requestDigest = digest('not-the-request-bytes');
  assert.equal(reserve(badDigestRequest).status, 'INVALID_REQUEST');

  const timeoutScope = scopeFor('timeout-not-fence');
  const unreservedRequest = normalRequest('timeout-not-fence', timeoutScope);
  assert.equal(seedKeyring(timeoutScope, unreservedRequest.expectedDigest).status, 'SEEDED');
  assert.equal(jsonRow('SELECT p65_lab.seal_no_commit(' + requestExpr(unreservedRequest) + ')', 'p65_status').status,
    'GATE_BINDING_MISMATCH');
  assert.equal(storedCount('no_commit_fence', 'operation_id = ' + sqlText(unreservedRequest.operationId)), '0');

  assert.throws(() => oneRow('SELECT count(*) FROM p65_lab.keyring_head', 'p65_cas'), /permission denied/i);
});

pgTest('stale response fails closed against the simulated logical witness high-water', { concurrency: false }, () => {
  const scope = scopeFor('stale-witness');
  const request = normalRequest('stale-witness', scope);
  assert.equal(seedKeyring(scope, request.expectedDigest).status, 'SEEDED');
  assert.equal(commitThroughCas(request).status, 'COMMITTED');
  assert.equal(jsonRow('SELECT p65_lab.set_mock_witness_highwater(' + scopeSql(scope) + ', 1, '
    + sqlBytea(request.proposedDigest) + ')', 'p65_test').status, 'WITNESS_HIGH_WATER_SET');
  assert.equal(jsonRow('SELECT p65_lab.validate_fresh_response(' + scopeSql(scope) + ', 0, '
    + sqlBytea(request.expectedDigest) + ')', 'p65_status').status, 'FAIL_CLOSED_STALE');
  assert.equal(jsonRow('SELECT p65_lab.validate_fresh_response(' + scopeSql(scope) + ', 1, '
    + sqlBytea(request.proposedDigest) + ')', 'p65_status').status, 'FRESH_INTERNAL_ONLY');
  assert.equal(jsonRow('SELECT p65_lab.set_mock_witness_highwater(' + scopeSql(scope) + ', 0, '
    + sqlBytea(request.expectedDigest) + ')', 'p65_test').status, 'WITNESS_HIGH_WATER_REGRESSION');
});

pgTest('container restart preserves committed transition and final fence rows', { concurrency: false }, () => {
  const scope = scopeFor('restart-persistence');
  const committedRequest = normalRequest('restart-committed', scope);
  assert.equal(seedKeyring(scope, committedRequest.expectedDigest).status, 'SEEDED');
  assert.equal(commitThroughCas(committedRequest).status, 'COMMITTED');
  const fenceRequest = normalRequest('restart-fence', scope, {
    expectedRevision: 1,
    expectedDigest: committedRequest.proposedDigest,
    expiresAt: serverTimestamp(0),
  });
  const reservation = reserve(fenceRequest);
  assert.equal(reservation.status, 'RESERVED');
  assert.equal(beginQuiesce(fenceRequest, reservation.generation).status, 'QUIESCING');
  assert.equal(setClockOffset(31).status, 'SET');
  assert.equal(jsonRow('SELECT p65_lab.seal_no_commit(' + requestExpr(fenceRequest) + ')', 'p65_status').status, 'NO_COMMIT_FINAL');
  assert.equal(setClockOffset(0).status, 'SET');

  const labelCheck = docker([
    'inspect', '--format', '{{.Id}}|{{index .Config.Labels "rootark.lab"}}|{{index .Config.Labels "rootark.owner"}}', CONTAINER,
  ]);
  assert.equal(labelCheck.status, 0, labelCheck.stderr);
  assert.equal(labelCheck.stdout, CONTAINER_ID + '|issue65-packet-b|local-feasibility');
  const restarted = docker(['restart', '--time', '10', CONTAINER], { timeout: 30000 });
  assert.equal(restarted.status, 0, restarted.stderr);
  const deadline = Date.now() + 30000;
  let ready = false;
  while (Date.now() < deadline) {
    const probe = docker(['exec', CONTAINER, 'pg_isready', '-U', 'postgres', '-d', DATABASE], { timeout: 5000 });
    if (probe.status === 0) { ready = true; break; }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
  }
  assert.equal(ready, true, 'PostgreSQL did not return after bounded lab container restart');
  assert.equal(storedCount('transition_log', 'operation_id = ' + sqlText(committedRequest.operationId)), '1');
  assert.equal(storedCount('no_commit_fence', 'operation_id = ' + sqlText(fenceRequest.operationId)), '1');
  assert.equal(storedCount('operation_terminal', 'operation_id IN (' + sqlText(committedRequest.operationId) + ', '
    + sqlText(fenceRequest.operationId) + ')'), '2');
  assert.equal(oneRow('SELECT revision FROM p65_lab.keyring_head WHERE account_id = ' + sqlText(scope.accountId)
    + ' AND compartment_id = ' + sqlText(scope.compartmentId) + ' AND keyring_id = ' + sqlText(scope.keyringId)), '1');
});
