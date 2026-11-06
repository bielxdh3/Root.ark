'use strict';
const { randomBytes } = require('node:crypto');
const { spawn } = require('node:child_process');
const { mkdirSync, writeFileSync, rmSync, symlinkSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { createPrivateAuthorityFixture } = require('./issue-65-private-authority-fixture');
const net = require('node:net');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');
const SERVER = resolve(__dirname, '../../server.js');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function port() {
  return new Promise((resolvePort, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const p = probe.address().port;
      probe.close(() => resolvePort(p));
    });
  });
}

async function fixture({ enabled = true } = {}) {
  const directory = createPrivateAuthorityFixture('rootark242app-');
  mkdirSync(join(directory, 'data'));
  symlinkSync(resolve(__dirname, '../../public'), join(directory, 'public'),
    process.platform === 'win32' ? 'junction' : 'dir');
  const password = randomBytes(24).toString('base64url');
  const hash = bcrypt.hashSync(password, 8);
  const users = ['alice', 'bob', 'carol', 'eve'].map(username => ({
    username, password: hash, role: 'user', sessionVersion: 0,
    disabled: false, totpEnabled: false, permissions: { listFiles: username !== 'eve' },
  }));
  const usersPath = join(directory, 'data', 'users.local.json');
  writeFileSync(usersPath, JSON.stringify(users));
  const selectedPort = await port();
  const origin = 'http://127.0.0.1:' + selectedPort;
  const env = { ...process.env, PORT: String(selectedPort), NODE_ENV: 'test', DB_ENABLED: 'false',
    JWT_SECRET: randomBytes(48).toString('hex'), TOTP_POLICY: 'optional',
    ROOTARK_P2P_EXPERIMENTAL: enabled ? 'true' : 'false',
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: 'false',
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: 'false' };
  delete env.ROOTARK_ZK1_CONTENT_CONFIG;
  delete env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [SERVER], { cwd: directory, env,
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let errors = '';
  child.stdout.on('data', () => {});
  child.stderr.on('data', data => { errors = (errors + data.toString()).slice(-1600); });
  const deadline = Date.now() + 75_000; // Windows native ACL cold startup can take >20 seconds.
  async function close() {
    if (child.exitCode === null && child.signalCode === null) {
      const stopped = new Promise(resolveStop => child.once('exit', resolveStop));
      child.kill();
      await stopped;
    }
    rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
  try {
    while (Date.now() < deadline && child.exitCode === null) {
      try { if ((await fetch(origin + '/login.html')).ok) break; }
      catch {}
      await sleep(80);
    }
    if (child.exitCode !== null || Date.now() >= deadline) {
      throw new Error('Disposable Root.ark failed to start: ' + errors.slice(-1000));
    }
  } catch (error) { await close(); throw error; }
  async function request(path, { method = 'GET', session = null, body = null,
    csrf = true, requestOrigin = origin } = {}) {
    const headers = { ...(session ? { Cookie: session.cookie } : {}) };
    if (method !== 'GET') {
      headers.Origin = requestOrigin;
      if (session && csrf) headers['X-CSRF-Token'] = session.csrf;
    }
    const result = await fetch(origin + path, { method, headers, body, redirect: 'manual' });
    return { status: result.status, text: await result.text(), headers: result.headers };
  }
  async function login(username) {
    const result = await fetch(origin + '/auth/login', { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }), redirect: 'manual' });
    if (!result.ok) throw new Error('Login fixture rejected for ' + username + ': ' + result.status +
      ' ' + (await result.text()).slice(0, 200));
    const cookies = result.headers.getSetCookie().map(line => line.split(';')[0]);
    return { cookie: cookies.join('; '), sessionCookie: cookies.find(c => c.startsWith('rootark_session=')),
      csrf: cookies.find(c => c.startsWith('rootark_csrf=')).split('=')[1] };
  }
  async function connect(session) {
    const socket = new WebSocket(origin.replace('http:', 'ws:') + '/ws', {
      headers: { Origin: origin, Cookie: session.cookie }
    });
    const events = [], waiters = [];
    socket.on('message', raw => {
      let msg;
      try { msg = JSON.parse(raw.toString()); } catch { return; }
      const idx = waiters.findIndex(w => w.match(msg));
      if (idx >= 0) waiters.splice(idx, 1)[0].resolve(msg);
      else events.push(msg);
    });
    await new Promise((resolveOpen, reject) => {
      socket.once('open', resolveOpen);
      socket.once('error', reject);
    });
    return {
      socket,
      send: msg => socket.send(JSON.stringify(msg)),
      next: (type, timeoutMs = 4_000) => new Promise((resolveNext, reject) => {
        const idx = events.findIndex(e => e.type === type);
        if (idx >= 0) return resolveNext(events.splice(idx, 1)[0]);
        const waiter = { match: e => e.type === type,
          resolve: e => { clearTimeout(timer); resolveNext(e); } };
        const timer = setTimeout(() => {
          const pos = waiters.indexOf(waiter);
          if (pos >= 0) waiters.splice(pos, 1);
          reject(new Error('WS timeout: ' + type));
        }, timeoutMs);
        waiters.push(waiter);
      })
    };
  }
  return { origin, directory, users, usersPath, request, login, connect, close };
}
module.exports = { fixture };
