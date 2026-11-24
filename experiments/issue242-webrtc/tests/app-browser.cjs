'use strict';
// Real Root.ark HTTP + cookie session + /ws + WebRTC in one disposable Edge.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync, existsSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { fixture } = require('../../../test/support/issue242-app-fixture');
const { Cdp, until, port } = require('./browser.cjs');
const edge = process.env.EDGE_PATH || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';

async function run() {
  if (!existsSync(edge)) throw new Error('Edge required for real Root.ark P2P app test');
  const f = await fixture();
  const profile = mkdtempSync(join(tmpdir(), 'rootark-242-app-edge-'));
  const debugPort = await port();
  const child = spawn(edge, ['--headless=new', '--disable-gpu', '--disable-extensions',
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    '--remote-allow-origins=*', '--remote-debugging-port=' + debugPort,
    '--user-data-dir=' + profile, 'about:blank'], { windowsHide: true, stdio: 'ignore' });
  const pages = [];
  try {
    const base = 'http://127.0.0.1:' + debugPort;
    await until(async () => (await fetch(base + '/json/version')).ok,
      'Edge CDP unavailable', 20_000);
    const version = await (await fetch(base + '/json/version')).json();
    const browser = await new Cdp(version.webSocketDebuggerUrl).connect();
    pages.push(browser);
    async function pageFor(username) {
      const session = await f.login(username);
      const { browserContextId } = await browser.call('Target.createBrowserContext');
      const { targetId } = await browser.call('Target.createTarget', { url: 'about:blank', browserContextId });
      const target = await until(async () => {
        const list = await (await fetch(base + '/json/list')).json();
        return list.find(item => item.id === targetId);
      }, 'isolated tab missing');
      const page = await new Cdp(target.webSocketDebuggerUrl).connect();
      pages.push(page);
      await page.call('Page.enable');
      await page.call('Network.enable');
      for (const cookie of session.cookie.split('; ')) {
        const [name, value] = cookie.split('=');
        await page.call('Network.setCookie', { name, value, url: f.origin,
          httpOnly: name === 'rootark_session', sameSite: 'Lax' });
      }
      await page.call('Page.navigate', { url: f.origin + '/p2p/' });
      if (username !== 'eve') {
        await until(() => page.evaluate('Boolean(document.readyState === "complete" && window.__poc)'),
          'Root.ark authenticated P2P page missing for ' + username, 12_000);
      }
      return page;
    }
    const alice = await pageFor('alice');
    const bob = await pageFor('bob');
    const carol = await pageFor('carol');
    const eve = await pageFor('eve');
    assert.equal(await eve.evaluate('Boolean(window.__poc)'), false, 'non ACL user loaded transfer UI');
    assert.equal(await alice.evaluate('document.querySelector("#sendFile")!==null'), true);
    assert.equal(await alice.evaluate('document.getElementById("rootarkReturn").hidden'), false);
    await alice.evaluate('window.__poc.createRoom()');
    const roomId = await until(() => alice.evaluate('window.__poc.snapshot().role==="host" && window.__poc.snapshot().roomId'),
      'real server host not joined');
    await alice.evaluate('window.__poc.invite("eve")');
    await until(() => alice.evaluate('window.__poc.snapshot().diagnostics.rejected.includes("BAD_RECIPIENT")'),
      'revoked ACL invited to real room');
    async function invite(username) {
      await alice.evaluate('window.__poc.invite(' + JSON.stringify(username) + ')');
      return until(() => alice.evaluate('window.__poc.invitations().at(-1)?.recipient===' +
        JSON.stringify(username) + ' && window.__poc.invitations().at(-1)?.invitation'),
      'invitation for ' + username + ' missing');
    }
    async function joinAs(page, invitation, expected) {
      await page.evaluate('window.__poc.joinRoom(' + JSON.stringify(roomId) + ',' +
        JSON.stringify(invitation) + ')');
      await until(() => page.evaluate('window.__poc.snapshot().role==="guest"'), 'guest did not join');
      await until(() => page.evaluate('Boolean(document.querySelector("[data-testid=accept-peer]"))'),
        'explicit peer consent missing');
      await page.evaluate('document.querySelector("[data-testid=accept-peer]").click()');
      await until(() => page.evaluate('window.__poc.snapshot().peers.some(p=>p.channel==="open")'),
        'DataChannel not open', 20_000);
      await until(() => alice.evaluate('window.__poc.snapshot().peers.filter(p=>p.channel==="open").length===' + expected),
        'host missing peer', 20_000);
    }
    await joinAs(bob, await invite('bob'), 1);
    await joinAs(carol, await invite('carol'), 2);
    const size = 2 * 1024 * 1024;
    await alice.evaluate('window.__poc.sendFile(new File([Uint8Array.from({length:' + size +
      '},(_,i)=>i%253)],"real-session-transfer.bin"))');
    for (const guest of [bob, carol]) {
      await until(() => guest.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'),
        'Root.ark peer file consent missing');
      await guest.evaluate('document.querySelector("[data-testid=accept-file]").click()');
      await until(() => guest.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.some(x=>x.name==="real-session-transfer.bin")'),
        'real Root.ark P2P integrity failed', 30_000);
      assert.equal(await guest.evaluate('window.__poc.snapshot().peers[0].savedDownload'), true);
    }
    await until(() => alice.evaluate('window.__poc.snapshot().peers.every(p=>p.outgoingPhase===null)'),
      'acknowledgment not delivered via actual /ws', 15_000);
    // Change the same real user store backing /auth/me and the upgrade guard.
    f.users.find(user => user.username === 'bob').sessionVersion += 1;
    writeFileSync(f.usersPath, JSON.stringify(f.users));
    await until(() => bob.evaluate('window.__poc.snapshot().peers.length===0'),
      'revoked Root.ark session left live P2P peer', 8_000);
    await until(() => alice.evaluate('window.__poc.snapshot().peers.length===1'),
      'revoked peer not removed from real server', 8_000);
    console.log('PASS real Root.ark app Edge: signed-cookie login, ACL recipient gate, /ws peer consent, 1:N 2MiB SHA-256 and session revocation');
  } finally {
    for (const page of pages) page.close();
    child.kill();
    await f.close();
    try { rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 150 }); }
    catch { /* Edge child may still hold disposable profile briefly. */ }
  }
}
run().catch(error => { console.error('FAIL app Edge: ' + error.message); process.exitCode = 1; });
