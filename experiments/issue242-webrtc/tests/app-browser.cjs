'use strict';
// Real Root.ark HTTP + cookie session + /ws + WebRTC in one disposable Edge.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync } = require('node:fs');
const { createHash } = require('node:crypto');
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
      if (username === 'alice') {
        // Capture real Edge sockets before the protected page loads, then
        // deterministically deliver a delayed event from the prior room.
        await page.call('Page.addScriptToEvaluateOnNewDocument', { source:
          'window.__testSockets=[]; const NativeSocket=WebSocket; ' +
          'window.WebSocket=class extends NativeSocket { constructor(...args) { super(...args); window.__testSockets.push(this); } };'
        });
      }
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
    // Protected-object mode reads the actual locally retained *ciphertext*
    // bytes for the expected SHA-256 and rechecks the authoritative file ACL.
    const ciphertext = Buffer.from(Array.from({ length: 92 }, (_, i) => i + 11));
    mkdirSync(join(f.directory, 'uploads'), { recursive: true });
    writeFileSync(join(f.directory, 'uploads', 'sealed.bin'), ciphertext);
    const objectMetadata = {
      fileName: 'sealed.bin', folderId: 'root', uploadedAt: '2026-11-06T12:00:00.000Z',
      size: 64, encryptedSize: ciphertext.length, encryptionLevel: 'user-key',
      algorithm: 'aes-256-gcm', layers: [{ type: 'user', iv: '0011', authTag: '0022' }],
      accessControl: { owner: 'alice', authorizedUsers: ['alice', 'bob'], expiresAt: null },
    };
    const saveObject = () => writeFileSync(join(f.directory, 'data', 'encrypted-files.json'),
      JSON.stringify({ 'root/sealed.bin': objectMetadata }));
    saveObject();
    writeFileSync(join(f.directory, 'data', 'file-permissions.json'),
      JSON.stringify({ 'root/sealed.bin': { owner: 'alice', public: false,
        users: { bob: { read: true, edit: false } } } }));
    const expectedDigest = createHash('sha256').update(ciphertext).digest('hex');
    assert.equal(await alice.evaluate('document.getElementById("boundObjectControls").hidden'), false);
    await alice.evaluate('window.__poc.createRoom({folderId:"root",fileName:"sealed.bin"})');
    const boundRoom = await until(() => alice.evaluate(
      'window.__poc.snapshot().boundObject?.sha256 && window.__poc.snapshot().roomId'),
    'ciphertext ACL room not opened', 12_000);
    assert.equal(await alice.evaluate('window.__poc.snapshot().boundObject.sha256'), expectedDigest);
    await alice.evaluate('window.__testSockets[0].onmessage({data:JSON.stringify({type:"joined",role:"guest",peerId:"old-room"})})');
    assert.equal(await alice.evaluate('window.__poc.snapshot().boundObject?.sha256'), expectedDigest,
      'stale unbound join stripped the current signed ciphertext room policy');
    assert.equal(await alice.evaluate('window.__poc.snapshot().role'), 'host');
    await alice.evaluate('window.__poc.invite("carol")');
    await until(() => alice.evaluate(
      'window.__poc.snapshot().diagnostics.rejected.includes("OBJECT_ACCESS_DENIED")'),
    'unlisted account received an object grant');
    const invitationsBefore = await alice.evaluate('window.__poc.invitations().length');
    await alice.evaluate('window.__poc.invite("bob")');
    const boundInvitation = await until(() => alice.evaluate(
      'window.__poc.invitations().length>' + invitationsBefore +
      ' && window.__poc.invitations().at(-1)?.recipient==="bob" && window.__poc.invitations().at(-1)?.invitation'),
    'authorized object recipient did not get an invitation');
    const refreshedBob = await pageFor('bob');
    await refreshedBob.evaluate('window.__poc.joinRoom(' + JSON.stringify(boundRoom) + ',' +
      JSON.stringify(boundInvitation) + ')');
    await until(() => refreshedBob.evaluate('window.__poc.snapshot().boundObject?.sha256===' +
      JSON.stringify(expectedDigest)), 'guest did not receive trusted ciphertext SHA-256');
    await until(() => refreshedBob.evaluate('Boolean(document.querySelector("[data-testid=accept-peer]"))'),
      'object peer consent missing');
    await refreshedBob.evaluate('document.querySelector("[data-testid=accept-peer]").click()');
    await until(() => refreshedBob.evaluate('window.__poc.snapshot().peers.some(p=>p.channel==="open")'),
      'object DataChannel did not open', 20_000);
    // A malicious consented sender can bypass sendText and send a valid
    // SHA-256 text control frame directly over the bound DataChannel.
    const forgedText = 'ciphertext-room-must-not-display-text';
    const forgedDigest = createHash('sha256').update(forgedText).digest('hex');
    await alice.evaluate('window.__poc.testChannel(0).send(' +
      JSON.stringify(JSON.stringify({ type: 'text', text: forgedText, digest: forgedDigest })) + ')');
    await until(() => refreshedBob.evaluate(
      'window.__poc.snapshot().diagnostics.rejected.includes("BOUND_ROOM_TEXT")'),
    'bound room recipient accepted direct plaintext from consented peer');
    assert.equal(await refreshedBob.evaluate('window.__poc.snapshot().diagnostics.verifiedTexts.length'), 0);
    await alice.evaluate('window.__poc.sendFile(new File([new Uint8Array(92)],"sealed.bin"))');
    await until(() => alice.evaluate(
      'window.__poc.snapshot().diagnostics.rejected.includes("OBJECT_DIGEST_MISMATCH")'),
    'sender accepted different same-length bytes');
    await alice.evaluate('window.__poc.testChannel(0).send(JSON.stringify({type:"offer-file",id:"1234567890abcdef1234567890abcdef",name:"sealed.bin",size:92,digest:"' +
      '0'.repeat(64) + '"}))');
    await until(() => refreshedBob.evaluate(
      'window.__poc.snapshot().diagnostics.rejected.includes("OBJECT_DIGEST_MISMATCH")'),
    'recipient accepted a forged peer offer');
    await alice.evaluate('window.__poc.sendFile(new File([Uint8Array.from({length:92},(_,i)=>i+11)],"sealed.bin"))');
    await until(() => refreshedBob.evaluate('Boolean(document.querySelector("[data-testid=accept-file]"))'),
      'real sealed ciphertext was not offered');
    await refreshedBob.evaluate('document.querySelector("[data-testid=accept-file]").click()');
    await until(() => refreshedBob.evaluate(
      'window.__poc.snapshot().diagnostics.verifiedFiles.some(f=>f.name==="sealed.bin")'),
    'bound ciphertext bytes did not verify', 15_000);
    objectMetadata.accessControl.authorizedUsers = ['alice'];
    saveObject();
    await until(() => refreshedBob.evaluate('window.__poc.snapshot().peers.length===0'),
      'revoked object guest kept live browser channel', 8_000);
    console.log('PASS real Root.ark Edge: signed-cookie 1:N 2MiB, ciphertext-bound SHA-256 and ACL, forged bytes denied, consent, tenant exclusion and revocation');
  } finally {
    for (const page of pages) page.close();
    child.kill();
    await f.close();
    try { rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 150 }); }
    catch { /* Edge child may still hold disposable profile briefly. */ }
  }
}
run().catch(error => { console.error('FAIL app Edge: ' + error.message); process.exitCode = 1; });
