'use strict';
// Real Edge / Chromium DevTools Protocol integration. Runs ONE disposable headless
// browser with three tabs against one loopback broker. No Playwright required.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { existsSync, mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const net = require('node:net');
const WebSocket = require('ws');
const { makeBroker } = require('../server.cjs');
const edge = process.env.EDGE_PATH || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const deadline = ms => Date.now() + ms;
const port = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const number = server.address().port;
    server.close(() => resolve(number));
  });
});
async function until(action, reason, timeout = 12_000) {
  const end = deadline(timeout);
  let last;
  while (Date.now() < end) {
    try { const value = await action(); if (value) return value; }
    catch (error) { last = error.message; }
    await sleep(100);
  }
  throw new Error(reason + (last ? ': ' + last : ''));
}
class Cdp {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.serial = 0;
    this.calls = new Map();
  }
  async connect() {
    await new Promise((resolve, reject) => {
      this.ws.once('open', resolve);
      this.ws.once('error', reject);
    });
    this.ws.on('message', raw => {
      const packet = JSON.parse(raw.toString());
      if (!packet.id) return;
      const promise = this.calls.get(packet.id);
      if (!promise) return;
      this.calls.delete(packet.id);
      if (packet.error) promise.reject(new Error(packet.error.message));
      else promise.resolve(packet.result);
    });
    return this;
  }
  call(method, params = {}) {
    const id = ++this.serial;
    return new Promise((resolve, reject) => {
      this.calls.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async evaluate(code) {
    const result = await this.call('Runtime.evaluate', {
      expression: code, awaitPromise: true, returnByValue: true, userGesture: true
    });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text +
      (result.exceptionDetails.exception?.description || ''));
    return result.result.value;
  }
  close() { this.ws.close(); }
}
async function run() {
  if (!existsSync(edge)) { console.log('SKIP: Edge executable unavailable'); return; }
  const broker = makeBroker();
  const origin = await broker.listen();
  const profile = mkdtempSync(join(tmpdir(), 'rootark-242-edge-'));
  const debugPort = await port();
  const pages = [];
  const edgeProcess = spawn(edge, [
    '--headless=new', '--disable-gpu', '--disable-extensions', '--no-first-run',
    '--no-default-browser-check', '--disable-background-networking',
    '--remote-allow-origins=*', '--remote-debugging-port=' + debugPort,
    '--user-data-dir=' + profile, 'about:blank'
  ], { windowsHide: true, stdio: 'ignore' });
  try {
    const base = 'http://127.0.0.1:' + debugPort;
    await until(async () => {
      const result = await fetch(base + '/json/version');
      return result.ok;
    }, 'Edge CDP endpoint unavailable', 18_000);
    async function newPage() {
      const res = await fetch(base + '/json/new?' + encodeURIComponent(origin), { method: 'PUT' });
      if (!res.ok) throw new Error('Could not create Edge tab: ' + res.status);
      const tab = await res.json();
      const page = await new Cdp(tab.webSocketDebuggerUrl).connect();
      pages.push(page);
      await until(() => page.evaluate('Boolean(document.readyState === "complete" && window.__poc)'), 'page not loaded');
      return page;
    }
    const host = await newPage();
    const guest1 = await newPage();
    const guest2 = await newPage();
    await host.evaluate('window.__poc.createRoom()');
    const room = await until(() => host.evaluate('window.__poc.snapshot().role === "host" && window.__poc.snapshot().roomId'), 'host did not join');
    async function addGuest(guest, priorCount) {
      await host.evaluate('window.__poc.invite()');
      const invitation = await until(() => host.evaluate(
        'window.__poc.invitations().length > ' + priorCount + ' && window.__poc.invitations()[' + priorCount + '].invitation'
      ), 'invite not created');
      // Diagnostic string passed only to page Runtime.evaluate; never written to logs.
      await guest.evaluate('window.__poc.joinRoom(' + JSON.stringify(room) + ', ' + JSON.stringify(invitation) + ')');
      await until(() => guest.evaluate('Boolean(document.querySelector("[data-testid=accept-peer]"))'), 'consent request not delivered');
      await guest.evaluate('document.querySelector("[data-testid=accept-peer]").click()');
      await until(() => guest.evaluate('window.__poc.snapshot().peers.some(p=>p.channel==="open")'), 'guest WebRTC DataChannel not open', 18_000);
      await until(() => host.evaluate('window.__poc.snapshot().peers.filter(p=>p.channel==="open").length===' + (priorCount + 1)), 'host WebRTC DataChannel not open', 18_000);
    }
    await addGuest(guest1, 0);
    await addGuest(guest2, 1);
    await host.evaluate('window.__poc.sendText("Root.ark issue 242 fixture")');
    await until(() => guest1.evaluate('window.__poc.snapshot().diagnostics.verifiedTexts.length===1'), 'guest1 text digest not verified');
    await until(() => guest2.evaluate('window.__poc.snapshot().diagnostics.verifiedTexts.length===1'), 'guest2 text digest not verified');
    await host.evaluate('window.__poc.sendFile(new File([Uint8Array.from({length:32768},(_,i)=>i%251)],"fixture.bin"))');
    for (const guest of [guest1, guest2]) {
      await until(() => guest.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'file offer missing');
      await guest.evaluate('document.querySelector("[data-testid=accept-file]").click()');
      await until(() => guest.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.length===1'), 'file SHA-256 not verified', 18_000);
    }
    const r1 = await guest1.evaluate('window.__poc.snapshot()');
    const r2 = await guest2.evaluate('window.__poc.snapshot()');
    assert.deepEqual(r1.diagnostics.verifiedFiles[0].sha256, r2.diagnostics.verifiedFiles[0].sha256);
    assert.equal(r1.diagnostics.verifiedFiles[0].size, 32768);
    assert.equal(r2.diagnostics.verifiedFiles[0].size, 32768);
    assert.equal(r1.diagnostics.verifiedTexts[0].text, 'Root.ark issue 242 fixture');
    assert.equal(r2.diagnostics.verifiedTexts[0].text, 'Root.ark issue 242 fixture');
    assert.deepEqual(r1.diagnostics.rejected, []);
    assert.deepEqual(r2.diagnostics.rejected, []);
    console.log('PASS Edge actual WebRTC DataChannel: 1:1 and 1:2, per-guest consent, text SHA-256 and 32KiB fixture SHA-256');
    console.log('Evidence:', JSON.stringify({ browser: 'Microsoft Edge headless', guests: 2,
      channelOpen: 2, verifiedTexts: 2, verifiedFiles: 2, fileBytesPerGuest: 32768,
      sha256: r1.diagnostics.verifiedFiles[0].sha256 }));
  } finally {
    for (const page of pages) page.close();
    edgeProcess.kill();
    await broker.close();
    // Process may own the transient profile briefly while Chromium child processes close.
    try { rmSync(profile, { recursive: true, force: true, maxRetries: 8, retryDelay: 150 }); }
    catch { /* Disposable OS temp profile can be removed after Edge exits. */ }
  }
}
run().catch(e => { console.error('FAIL: ' + e.message); process.exitCode = 1; });
