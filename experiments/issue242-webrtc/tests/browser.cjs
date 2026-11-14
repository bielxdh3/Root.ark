'use strict';
// Real Edge / Chromium DevTools Protocol integration. Runs ONE disposable headless
// browser with three tabs against one loopback broker. No Playwright required.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { existsSync, mkdtempSync, mkdirSync, readFileSync, statSync, unlinkSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const net = require('node:net');
const WebSocket = require('ws');
const { makeBroker } = require('../server.cjs');
const { createRealtimeAuthenticator, parseCookies } = require('../../../src/middlewares/auth');
const jwt = require('jsonwebtoken');
const { randomBytes, createHash } = require('node:crypto');
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
  let sessionBroker;
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
    assert.equal(await host.evaluate('document.getElementById("rootarkReturn").hidden'), true);
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
    // Adversarial real DataChannel: 256 empty frames before valid final byte.
    // The prior receiver kept every zero-length Uint8Array and still verified the file.
    const oneByteDigest = await host.evaluate(`crypto.subtle.digest('SHA-256',Uint8Array.of(1)).then(
      bytes => Array.from(new Uint8Array(bytes)).map(b=>b.toString(16).padStart(2,'0')).join(''))`);
    await host.evaluate(`window.__poc.testChannel(0).send(JSON.stringify({
      type:'offer-file',id:'11111111111111111111111111111111',name:'zero.bin',size:1,digest:${JSON.stringify(oneByteDigest)}
    }))`);
    await until(() => guest1.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'attack offer missing');
    await guest1.evaluate('document.querySelector("[data-testid=accept-file]").click()');
    await host.evaluate(`(() => {
      const dc = window.__poc.testChannel(0);
      for (let i=0;i<256;i++) dc.send(new Uint8Array(0));
      dc.send(Uint8Array.of(1));
      dc.send(JSON.stringify({type:'end-file',id:'11111111111111111111111111111111'}));
    })()`);
    await until(() => guest1.evaluate(`(() => {
      const s=window.__poc.snapshot();
      return s.diagnostics.rejected.some(c=>c==='INVALID_CHUNK'||c==='UNEXPECTED_CHUNK') ||
        s.diagnostics.verifiedFiles.length>1;
    })()`), 'empty frames were not processed', 6000);
    const postEmpty = await guest1.evaluate('window.__poc.snapshot()');
    assert.equal(postEmpty.diagnostics.verifiedFiles.length, 1, 'malformed transfer must not be verified');
    assert.ok(postEmpty.diagnostics.rejected.some(c=>c==='INVALID_CHUNK'||c==='UNEXPECTED_CHUNK'),
      'empty frames must be rejected even when the bounded rejection ring evicts the first event');
    assert.equal(postEmpty.peers[0].incomingChunks, 0, 'aborted file must release all retained chunks');
    // Even non-empty tiny chunks cannot accumulate for a valid bounded offer.
    await host.evaluate(`window.__poc.testChannel(0).send(JSON.stringify({
      type:'offer-file',id:'22222222222222222222222222222222',name:'tiny.bin',size:512,digest:'0'.repeat(64)
    }))`);
    await until(() => guest1.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'tiny offer missing');
    await guest1.evaluate('document.querySelector("[data-testid=accept-file]").click()');
    const digestTinyDone = await host.evaluate(`crypto.subtle.digest('SHA-256',new TextEncoder().encode('tiny-flood-complete')).then(
      bytes => Array.from(new Uint8Array(bytes)).map(b=>b.toString(16).padStart(2,'0')).join(''))`);
    await host.evaluate(`(() => {
      const dc = window.__poc.testChannel(0);
      for (let i=0;i<129;i++) dc.send(Uint8Array.of(1));
      dc.send(JSON.stringify({type:'text',text:'tiny-flood-complete',digest:${JSON.stringify(digestTinyDone)}}));
    })()`);
    await until(() => guest1.evaluate(`window.__poc.snapshot().diagnostics.verifiedTexts.some(
      x=>x.text==='tiny-flood-complete')`), 'chunk count flood was not processed', 6000);
    const postTiny = await guest1.evaluate('window.__poc.snapshot()');
    assert.equal(postTiny.peers[0].incomingChunks, 0, 'chunk limit must abort and release buffer');
    // Valid but frequent text notifications must not accumulate diagnostics/DOM forever.
    const digestText = await host.evaluate(`crypto.subtle.digest('SHA-256',new TextEncoder().encode('flood')).then(
      bytes => Array.from(new Uint8Array(bytes)).map(b=>b.toString(16).padStart(2,'0')).join(''))`);
    const digestLast = await host.evaluate(`crypto.subtle.digest('SHA-256',new TextEncoder().encode('flood-last')).then(
      bytes => Array.from(new Uint8Array(bytes)).map(b=>b.toString(16).padStart(2,'0')).join(''))`);
    await host.evaluate(`(() => {
      const dc = window.__poc.testChannel(0);
      const payload = JSON.stringify({type:'text',text:'flood',digest:${JSON.stringify(digestText)}});
      for (let i=0;i<256;i++) dc.send(payload);
      dc.send(JSON.stringify({type:'text',text:'flood-last',digest:${JSON.stringify(digestLast)}}));
    })()`);
    await until(() => guest1.evaluate(`window.__poc.snapshot().diagnostics.verifiedTexts.some(x=>x.text==='flood-last')`), 'text flood processing incomplete', 6000);
    const afterFlood = await guest1.evaluate(`({
      lengths:Object.fromEntries(Object.entries(window.__poc.snapshot().diagnostics).map(([k,v])=>[k,v.length])),
      lines:document.getElementById('events').textContent.split('\\n').filter(Boolean).length,
      characters:document.getElementById('events').textContent.length
    })`);
    assert.ok(Object.values(afterFlood.lengths).every(n=>n<=100), 'diagnostic arrays must remain bounded');
    assert.ok(afterFlood.lines<=100 && afterFlood.characters<=16000, 'visible log must remain bounded');
    console.log('PASS Edge P2 flood: 256 zero-byte frames rejected and transfer aborted, 129 tiny chunks aborted, 257 verified text events bounded');
    console.log('Flood evidence:', JSON.stringify({ maxDiagnosticEntries: Math.max(...Object.values(afterFlood.lengths)),
      logLines: afterFlood.lines, logCharacters: afterFlood.characters, incomingChunksAfterAbort: postTiny.peers[0].incomingChunks }));
    // Closing a live channel must drop both ends' pending transfers.
    await until(() => host.evaluate('window.__poc.snapshot().peers.every(p=>p.outgoingPhase===null)'), 'prior send acknowledgement pending');
    await host.evaluate('window.__poc.sendFile(new File([new Uint8Array(2*1024*1024)], "disconnect.bin"))');
    await until(() => guest1.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'disconnect offer missing');
    await guest1.evaluate('document.querySelector("[data-testid=accept-file]").click()');
    await guest1.evaluate('window.__poc.testChannel(0).close()');
    await until(() => guest1.evaluate('window.__poc.snapshot().peers[0].incomingBytes===0'), 'disconnect kept partial incoming');
    await until(() => host.evaluate('window.__poc.snapshot().peers[0].outgoingPhase===null'), 'disconnect kept outgoing');
    console.log('PASS Edge actual channel disconnect: pending transfer discarded on both ends');
    // RED/GREEN: real Root.ark JWT verifier, disposable users and three separate
    // headless Edge cookie jars. No production secrets, accounts or storage.
    const secret = randomBytes(48).toString('hex');
    const users = new Map(['alice', 'bob', 'carol', 'eve'].map(username =>
      [username, { username, role: 'user', sessionVersion: 1, totpEnabled: true, permissions: {} }]));
    const verifier = createRealtimeAuthenticator({
      jwt, jwtSecret: secret, loadUser: username => users.get(username),
      normalizeUserPermissions: user => user.permissions
    });
    sessionBroker = makeBroker({ authenticateSession: req =>
      verifier(parseCookies(req.headers.cookie).get('rootark_session')) });
    const authOrigin = await sessionBroker.listen();
    const version = await (await fetch(base + '/json/version')).json();
    const browser = await new Cdp(version.webSocketDebuggerUrl).connect();
    pages.push(browser);
    const contexts = [];
    const downloadDir = join(profile, 'downloads');
    mkdirSync(downloadDir);
    async function signedPage(username) {
      const { browserContextId } = await browser.call('Target.createBrowserContext');
      contexts.push(browserContextId);
      await browser.call('Browser.setDownloadBehavior', {
        behavior: 'allow', downloadPath: downloadDir, browserContextId
      });
      const { targetId } = await browser.call('Target.createTarget', {
        url: 'about:blank', browserContextId
      });
      const target = await until(async () => {
        const items = await (await fetch(base + '/json/list')).json();
        return items.find(item => item.id === targetId);
      }, 'isolated auth tab not found');
      const page = await new Cdp(target.webSocketDebuggerUrl).connect();
      pages.push(page);
      await page.call('Network.enable');
      await page.call('Network.setCookie', {
        name: 'rootark_session', value: jwt.sign({ username, sessionVersion: 1 },
          secret, { algorithm: 'HS256', expiresIn: '5m' }),
        url: authOrigin, httpOnly: true, sameSite: 'Lax'
      });
      await page.call('Page.enable');
      await page.call('Page.navigate', { url: authOrigin });
      await until(() => page.evaluate('Boolean(document.readyState==="complete" && window.__poc)'), 'auth page not loaded');
      return page;
    }
    const alice = await signedPage('alice');
    const bob = await signedPage('bob');
    const carol = await signedPage('carol');
    const eve = await signedPage('eve');
    await alice.evaluate('window.__poc.createRoom()');
    const roomId = await until(() => alice.evaluate('window.__poc.snapshot().role==="host" && window.__poc.snapshot().roomId'), 'signed host not joined');
    async function signedInvite(recipient) {
      await alice.evaluate('window.__poc.invite(' + JSON.stringify(recipient) + ')');
      return until(() => alice.evaluate('window.__poc.invitations().at(-1)?.recipient===' +
        JSON.stringify(recipient) + ' && window.__poc.invitations().at(-1)?.invitation'), 'targeted invite not issued');
    }
    const bobInvite = await signedInvite('bob');
    await eve.evaluate('window.__poc.joinRoom(' + JSON.stringify(roomId) + ',' + JSON.stringify(bobInvite) + ')');
    await until(() => eve.evaluate('window.__poc.snapshot().diagnostics.rejected.includes("INVALID_INVITE")'), 'wrong signed identity accepted');
    async function signedJoin(page, invitation, username, expectedCount) {
      await page.evaluate('window.__poc.joinRoom(' + JSON.stringify(roomId) + ',' + JSON.stringify(invitation) + ')');
      await until(() => page.evaluate('window.__poc.snapshot().role==="guest"'), username + ' session not joined');
      await until(() => page.evaluate('Boolean(document.querySelector("[data-testid=accept-peer]"))'), username + ' peer consent missing');
      assert.equal(await page.evaluate('window.__poc.snapshot().peers.length'), 0, 'consent must precede RTC offer');
      await page.evaluate('document.querySelector("[data-testid=accept-peer]").click()');
      await until(() => page.evaluate('window.__poc.snapshot().peers.some(x=>x.channel==="open")'), username + ' DataChannel failed', 18000);
      await until(() => alice.evaluate('window.__poc.snapshot().peers.filter(x=>x.channel==="open").length===' + expectedCount),
        'signed host missing channel', 18000);
    }
    await signedJoin(bob, bobInvite, 'bob', 1);
    const carolInvite = await signedInvite('carol');
    await signedJoin(carol, carolInvite, 'carol', 2);
    await alice.evaluate('window.__poc.sendFile(new File([Uint8Array.from({length:32768},(_,i)=>i%239)],"scoped.bin"))');
    for (const page of [bob, carol]) {
      await until(() => page.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'scoped file consent missing');
      await page.evaluate('document.querySelector("[data-testid=accept-file]").click()');
      await until(() => page.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.some(x=>x.name==="scoped.bin")'),
        'signed file digest mismatch', 18000);
    }
    await until(() => alice.evaluate('window.__poc.snapshot().peers.every(p=>p.outgoingPhase===null)'), 'signed SHA acknowledgement missing');
    // Real 1:N browser transfer beyond the old 1 MiB limit. Byte-for-byte
    // download is verified through the Blob URL, with no broker content storage.
    await alice.evaluate('window.__poc.sendFile(new File([Uint8Array.from({length:3*1024*1024},(_,i)=>i%239)],"large-3m.bin"))');
    for (const page of [bob, carol]) {
      await until(() => page.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'large file offer missing');
      await page.evaluate('document.querySelector("[data-testid=accept-file]").click()');
      await until(() => page.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.some(x=>x.name==="large-3m.bin")'),
        'large file SHA mismatch', 30000);
      const download = await page.evaluate(`(() => {
        const a = document.querySelector('#downloads a');
        const name = a.download;
        a.click();
        return { name, href:a.href.startsWith('blob:') };
      })()`);
      assert.equal(download.name, 'large-3m.bin');
      assert.equal(download.href, true, 'verified file must use browser-local Blob URL');
      const target = join(downloadDir, download.name);
      // Edge creates the destination file before it finishes writing bytes.
      // Waiting for mere existence can read a transient zero-byte file.
      await until(() => existsSync(target) && statSync(target).size === 3 * 1024 * 1024,
        'Edge did not finish verified Blob download', 18000);
      const bytes = readFileSync(target);
      assert.equal(bytes.byteLength, 3 * 1024 * 1024);
      assert.deepEqual([...bytes.subarray(0, 256)], Array.from({ length: 256 }, (_, i) => i % 239));
      const expected = await page.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.at(-1).sha256');
      assert.equal(createHash('sha256').update(bytes).digest('hex'), expected);
      unlinkSync(target);
    }
    await until(() => alice.evaluate('window.__poc.snapshot().peers.every(p=>p.outgoingPhase===null)'), 'large SHA acknowledgements missing', 30000);
    const bounded = await alice.evaluate('window.__poc.snapshot().peers.map(p=>p.peakBuffered)');
    assert.ok(bounded.every(n=>n>0 && n<=256*1024+8192+24), 'WebRTC sender exceeded high-water buffer');
    console.log('PASS Edge signed 2-recipient 3MiB P2P: SHA-256 ACK + verified Blob download; peak buffered', bounded);
    // Malicious peer offers a well-formed transfer, then sends a binary frame
    // for a different transfer ID. The recipient must not save it.
    await alice.evaluate(`window.__poc.testChannel(0).send(JSON.stringify({
      type:'offer-file',id:'33333333333333333333333333333333',name:'attacker.bin',
      size:8192,digest:'0'.repeat(64)
    }))`);
    await until(() => bob.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'malicious offer missing');
    await bob.evaluate('document.querySelector("[data-testid=accept-file]").click()');
    await alice.evaluate(`window.__poc.testChannel(0).send(window.P2PFileWire.packFrame(
      '44444444444444444444444444444444',0,new Uint8Array(8192)))`);
    await until(() => bob.evaluate('window.__poc.snapshot().diagnostics.rejected.includes("INVALID_CHUNK")'), 'cross-transfer frame accepted');
    assert.equal(await bob.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.length'), 2);
    assert.equal(await bob.evaluate('window.__poc.snapshot().peers[0].incomingBytes'), 0);
    await alice.evaluate(`window.__poc.testChannel(0).send(JSON.stringify({
      type:'offer-file',id:'55555555555555555555555555555555',name:'corrupted.bin',
      size:8192,digest:'0'.repeat(64)
    }))`);
    await until(() => bob.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'corruption offer missing');
    await bob.evaluate('document.querySelector("[data-testid=accept-file]").click()');
    await alice.evaluate(`(() => {
      const dc = window.__poc.testChannel(0);
      dc.send(window.P2PFileWire.packFrame('55555555555555555555555555555555',0,new Uint8Array(8192)));
      dc.send(JSON.stringify({type:'end-file',id:'55555555555555555555555555555555'}));
    })()`);
    await until(() => bob.evaluate('window.__poc.snapshot().diagnostics.rejected.includes("FILE_DIGEST")'),
      'corrupted file accepted');
    assert.equal(await bob.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.length'), 2);
    // Sender is intentionally slowed between real DataChannel chunks so the
    // browser can cancel after reception begins, including an in-flight read.
    await alice.evaluate(`(() => {
      const file = new File([new Uint8Array(8*1024*1024)], 'cancel.bin');
      const slice = file.slice.bind(file);
      file.slice = (start,end) => ({arrayBuffer:()=>new Promise((resolve,reject) =>
        setTimeout(()=>slice(start,end).arrayBuffer().then(resolve,reject),4))});
      return window.__poc.sendFile(file);
    })()`);
    await until(() => bob.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'cancel offer missing');
    await bob.evaluate('document.querySelector("[data-testid=accept-file]").click()');
    await until(() => bob.evaluate('window.__poc.snapshot().peers[0].incomingBytes>0'), 'cancel fixture did not begin streaming', 15000);
    await bob.evaluate('document.querySelector("[data-testid=cancel-incoming]").click()');
    await until(() => carol.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'), 'other peer offer missing');
    await carol.evaluate('document.querySelector("[data-testid=accept-file]").nextElementSibling.click()');
    await until(() => alice.evaluate('window.__poc.snapshot().peers.every(p=>p.outgoingPhase===null)'), 'cancel not propagated', 15000);
    assert.equal(await bob.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.length'), 2);
    assert.equal(await bob.evaluate('window.__poc.snapshot().peers[0].incomingBytes'), 0);
    console.log('PASS Edge signed cancel during active 8MiB sender: partial data discarded, sender stopped, sibling decline scoped');
    users.get('bob').sessionVersion = 2;
    await until(() => bob.evaluate('window.__poc.snapshot().peers.length===0'), 'revoked user RTC not closed', 6000);
    await until(() => alice.evaluate('window.__poc.snapshot().peers.length===1'), 'revoked peer remains in host', 6000);
    console.log('PASS Edge signed-session 1:N: cross-user invite denial, per-guest consent, 2 SHA-256 files, live session revocation');
    for (const id of contexts) await browser.call('Target.disposeBrowserContext', { browserContextId: id });
    console.log('PASS Edge actual WebRTC DataChannel: 1:1 and 1:2, per-guest consent, text SHA-256 and 32KiB fixture SHA-256');
    console.log('Evidence:', JSON.stringify({ browser: 'Microsoft Edge headless', guests: 2,
      channelOpen: 2, verifiedTexts: 2, verifiedFiles: 2, fileBytesPerGuest: 32768,
      sha256: r1.diagnostics.verifiedFiles[0].sha256 }));
  } finally {
    for (const page of pages) page.close();
    edgeProcess.kill();
    if (sessionBroker) await sessionBroker.close();
    await broker.close();
    // Process may own the transient profile briefly while Chromium child processes close.
    try { rmSync(profile, { recursive: true, force: true, maxRetries: 8, retryDelay: 150 }); }
    catch { /* Disposable OS temp profile can be removed after Edge exits. */ }
  }
}
if (require.main === module) run().catch(e => { console.error('FAIL: ' + e.message); process.exitCode = 1; });
module.exports = { Cdp, until, port };
