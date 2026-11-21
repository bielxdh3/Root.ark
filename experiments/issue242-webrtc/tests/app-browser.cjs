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
      if (username !== 'eve') {
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
    assert.equal(await alice.evaluate('document.getElementById("leave").disabled'), true);
    assert.equal(await alice.evaluate('document.getElementById("leave").getAttribute("aria-describedby")'), 'leaveHint');
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
    // A WebRTC offer may reject after the signaling peer was accepted. The
    // async message handler must consume that rejection and retire only the
    // still-current synthetic peer, never leak an unhandled rejection.
    await alice.evaluate(`(async () => {
      const NativePeer = window.RTCPeerConnection;
      window.__restorePeerConstructor = () => { window.RTCPeerConnection = NativePeer; };
      window.__unhandledPeerOffer = false;
      window.addEventListener('unhandledrejection', event => {
        window.__unhandledPeerOffer = true;
        event.preventDefault();
      });
      window.RTCPeerConnection = class extends NativePeer {
        createDataChannel(...args) {
          window.__syntheticDataChannel = super.createDataChannel(...args);
          return window.__syntheticDataChannel;
        }
        async createOffer() { throw new Error('synthetic createOffer rejection'); }
      };
      const socket = window.__testSockets.at(-1);
      await socket.onmessage({ data: JSON.stringify({
        type: 'peer-accepted', peerId: 'synthetic-offer-failure',
      }) });
    })()`);
    await until(() => alice.evaluate('!window.__poc.snapshot().peers.some(' +
      'peer=>peer.id==="synthetic-offer-failure") && ' +
      'document.getElementById("state").textContent==="Negociação falhou: Error"'),
    'rejected WebRTC offer left a synthetic peer registered');
    await alice.evaluate('new Promise(resolve => setTimeout(resolve, 0))');
    assert.equal(await alice.evaluate('window.__unhandledPeerOffer'), false,
      'rejected WebRTC offer escaped as an unhandled promise rejection');
    await alice.evaluate(`(() => {
      window.__syntheticDataChannel.onopen();
      window.__syntheticDataChannel.onclose();
    })()`);
    assert.equal(await alice.evaluate('window.__poc.snapshot().diagnostics.channels.includes("synthetic-offer-failure")'), false,
      'stale DataChannel callback published diagnostics for a retired peer');
    await alice.evaluate('window.__restorePeerConstructor()');
    assert.equal(await alice.evaluate('document.getElementById("leave").textContent'), 'Encerrar sala');
    assert.equal(await bob.evaluate('document.getElementById("leave").textContent'), 'Sair da sala');
    assert.equal(await alice.evaluate('document.getElementById("leave").getAttribute("aria-label")'), 'Encerrar sala');
    assert.equal(await bob.evaluate('document.getElementById("leave").getAttribute("aria-label")'), 'Sair da sala');
    assert.equal(await alice.evaluate('document.getElementById("leave").disabled'), false);
    assert.equal(await bob.evaluate('document.getElementById("leave").disabled'), false);
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
    // A guest can leave independently without closing the host's room or
    // disturbing another guest. A concurrent create must be aborted and must
    // not log a stale AbortError after the guest leaves.
    await bob.evaluate(`(async () => {
      window.__staleConsentSends = 0;
      const nativeSend = WebSocket.prototype.send;
      window.__restoreConsentSend = () => { WebSocket.prototype.send = nativeSend; };
      WebSocket.prototype.send = function (data) {
        try {
          const message = JSON.parse(data);
          if (message.type === 'consent' && message.requestId === 'stale-consent-request') {
            window.__staleConsentSends += 1;
          }
        } catch { /* Non-JSON WebSocket frames are not consent messages. */ }
        return nativeSend.call(this, data);
      };
      await window.__testSockets.at(-1).onmessage({ data: JSON.stringify({
        type: 'peer-request', requestId: 'stale-consent-request', username: 'synthetic',
      }) });
      window.__staleConsentButton = document.querySelector('[data-testid=accept-peer]');
      if (!window.__staleConsentButton) throw new Error('synthetic consent control missing');
    })()`);
    await bob.evaluate(`(() => {
      const originalFetch = window.fetch.bind(window);
      window.__createAbortObserved = false;
      window.__restoreCreateFetch = () => { window.fetch = originalFetch; };
      window.fetch = (input, init = {}) => {
        const url = new URL(typeof input === 'string' ? input : input.url, location.href);
        if (url.pathname === '/p2p/rooms' && init.method === 'POST') {
          return new Promise((resolve, reject) => {
            const signal = init.signal;
            const abort = () => {
              window.__createAbortObserved = true;
              reject(new DOMException('Aborted', 'AbortError'));
            };
            if (!signal) return reject(new Error('missing create abort signal'));
            if (signal.aborted) return abort();
            signal.addEventListener('abort', abort, { once: true });
          });
        }
        return originalFetch(input, init);
      };
      document.getElementById('create').click();
    })()`);
    await until(() => bob.evaluate('document.getElementById("create").disabled && ' +
      'document.getElementById("createObjectRoom").disabled'),
    'room-create controls were not locked during the pending request');
    await bob.evaluate('document.getElementById("leave").click()');
    await until(() => bob.evaluate('window.__poc.snapshot().roomId===null && ' +
      'window.__poc.snapshot().role===null && window.__poc.snapshot().peers.length===0 && ' +
      'document.getElementById("leave").disabled && window.__createAbortObserved && ' +
      '!document.getElementById("create").disabled && !document.getElementById("createObjectRoom").disabled'),
    'guest leave did not abort creation, clear local state and release the controls');
    assert.equal(await bob.evaluate('document.getElementById("state").textContent'), 'Você saiu da sala',
      'stale AbortError overwrote the guest leave status');
    await bob.evaluate('window.__restoreCreateFetch()');
    await until(() => alice.evaluate('window.__poc.snapshot().role==="host" && ' +
      'window.__poc.snapshot().peers.length===1'), 'guest leave disturbed the remaining room');
    await joinAs(bob, await invite('bob'), 2);
    await bob.evaluate('window.__staleConsentButton.click()');
    await bob.evaluate('new Promise(resolve => setTimeout(resolve, 0))');
    assert.equal(await bob.evaluate('window.__staleConsentSends'), 0,
      'stale consent callback from the previous room was sent on the replacement socket');
    await bob.evaluate('window.__restoreConsentSend()');
    assert.equal(await bob.evaluate('document.getElementById("leave").textContent'), 'Sair da sala');
    // Change the same real user store backing /auth/me and the upgrade guard.
    f.users.find(user => user.username === 'bob').sessionVersion += 1;
    writeFileSync(f.usersPath, JSON.stringify(f.users));
    await until(() => bob.evaluate('window.__poc.snapshot().roomId===null && ' +
      'window.__poc.snapshot().role===null && window.__poc.snapshot().peers.length===0 && ' +
      'document.getElementById("leave").disabled'),
      'revoked Root.ark session left live P2P peer', 8_000);
    await until(() => alice.evaluate('window.__poc.snapshot().peers.length===1'),
      'revoked peer not removed from real server', 8_000);
    // The host ends the room for every remaining participant. All transient
    // peer, invitation, transfer and download UI must be retired on both sides.
    assert.equal(await alice.evaluate('document.getElementById("leave").textContent'), 'Encerrar sala');
    await alice.evaluate(`(() => {
      const originalFetch = window.fetch.bind(window);
      window.__createResponseHeld = false;
      window.__createResponseReleased = false;
      window.__releaseCreateResponse = null;
      window.__createSignal = null;
      window.__createPostCount = 0;
      window.__restoreFetch = () => { window.fetch = originalFetch; };
      window.fetch = async (input, init) => {
        const response = await originalFetch(input, init);
        const url = new URL(typeof input === 'string' ? input : input.url, location.href);
        if (url.pathname === '/p2p/rooms' && init?.method === 'POST') {
          window.__createPostCount += 1;
          window.__createSignal = init.signal;
          const originalJson = response.json.bind(response);
          response.json = async (...args) => {
            const payload = await originalJson(...args);
            window.__createResponseHeld = true;
            await new Promise(resolve => { window.__releaseCreateResponse = resolve; });
            window.__createResponseReleased = true;
            return payload;
          };
        }
        return response;
      };
      document.getElementById('create').click();
    })()`);
    await until(() => alice.evaluate('window.__createResponseHeld === true'),
      'pending create-room JSON response was not held');
    assert.equal(await alice.evaluate('document.getElementById("create").disabled && ' +
      'document.getElementById("createObjectRoom").disabled'), true,
    'both create actions must remain disabled while one create is in flight');
    assert.equal(await alice.evaluate('window.__poc.createRoom()'), false,
      'a second programmatic create must be rejected while the first is pending');
    assert.equal(await alice.evaluate('window.__createPostCount'), 1,
      'single-flight guard allowed a second room reservation');
    await alice.evaluate('document.getElementById("leave").click()');
    const cleared = 'window.__poc.snapshot().roomId===null && window.__poc.snapshot().role===null && ' +
      'window.__poc.snapshot().peers.length===0 && document.getElementById("leave").disabled && ' +
      '["invites","peers","incoming","transfers","downloads"].every(id => ' +
      'document.getElementById(id).childElementCount===0)';
    await until(() => alice.evaluate(cleared), 'host leave did not clear host room state');
    await until(() => carol.evaluate(cleared), 'host leave did not clear guest room state');
    assert.equal(await alice.evaluate('window.__createSignal.aborted'), true,
      'host leave did not abort the in-flight create request');
    await alice.evaluate('window.__releaseCreateResponse()');
    await until(() => alice.evaluate('window.__createResponseReleased === true'),
      'pending create-room response was not released');
    await alice.evaluate('new Promise(resolve => setTimeout(resolve, 0))');
    await until(() => alice.evaluate('!document.getElementById("create").disabled && ' +
      '!document.getElementById("createObjectRoom").disabled'),
    'create controls were not released after the aborted response settled');
    await alice.evaluate('window.__restoreFetch()');
    assert.equal(await alice.evaluate('window.__poc.snapshot().roomId'), null,
      'late create-room response re-entered after the host left');
    assert.equal(await alice.evaluate('window.__poc.snapshot().role'), null,
      'late create-room response restored the host role after leaving');
    // A Join must also invalidate an older create whose HTTP response has
    // arrived but whose JSON body is still pending. The stale body must not
    // replace the newly admitted guest room when it is finally released.
    await carol.evaluate('window.__poc.createRoom()');
    const carolRoomId = await until(() => carol.evaluate(
      'window.__poc.snapshot().role==="host" && window.__poc.snapshot().roomId'),
    'Carol could not create the replacement host room');
    await carol.evaluate('window.__poc.invite("alice")');
    const carolInvitation = await until(() => carol.evaluate(
      'window.__poc.invitations().at(-1)?.recipient==="alice" && window.__poc.invitations().at(-1)?.invitation'),
    'Carol could not invite Alice to the replacement room');
    await alice.evaluate(`(() => {
      const originalFetch = window.fetch.bind(window);
      window.__createResponseHeld = false;
      window.__createResponseReleased = false;
      window.__createSignal = null;
      window.__releaseCreateResponse = null;
      window.__restoreFetch = () => { window.fetch = originalFetch; };
      window.fetch = async (input, init) => {
        const response = await originalFetch(input, init);
        const url = new URL(typeof input === 'string' ? input : input.url, location.href);
        if (url.pathname === '/p2p/rooms' && init?.method === 'POST') {
          window.__createSignal = init.signal;
          const originalJson = response.json.bind(response);
          response.json = async (...args) => {
            const payload = await originalJson(...args);
            window.__createResponseHeld = true;
            await new Promise(resolve => { window.__releaseCreateResponse = resolve; });
            window.__createResponseReleased = true;
            return payload;
          };
        }
        return response;
      };
      document.getElementById('create').click();
    })()`);
    await until(() => alice.evaluate('window.__createResponseHeld === true'),
      'pending create JSON was not held before Join');
    await alice.evaluate('window.__poc.joinRoom(' + JSON.stringify(carolRoomId) + ',' +
      JSON.stringify(carolInvitation) + ')');
    await until(() => alice.evaluate('window.__poc.snapshot().role==="guest" && ' +
      'window.__poc.snapshot().roomId===' + JSON.stringify(carolRoomId)),
    'Join did not complete while the earlier create JSON was held');
    assert.equal(await alice.evaluate('window.__createSignal.aborted'), true,
      'Join did not abort the earlier create intent');
    await alice.evaluate('window.__releaseCreateResponse()');
    await until(() => alice.evaluate('window.__createResponseReleased === true'),
      'held create JSON was not released after Join');
    await alice.evaluate('new Promise(resolve => setTimeout(resolve, 0))');
    assert.equal(await alice.evaluate('window.__poc.snapshot().role'), 'guest',
      'stale create JSON replaced the newly joined guest role');
    assert.equal(await alice.evaluate('window.__poc.snapshot().roomId'), carolRoomId,
      'stale create JSON replaced the newly joined room ID');
    assert.equal(await alice.evaluate('!document.getElementById("create").disabled && ' +
      '!document.getElementById("createObjectRoom").disabled'), true,
    'create controls remained locked after the new room was admitted');
    await alice.evaluate('window.__restoreFetch()');
    // A failed protected-object create must not leave the retired room ID/key
    // visible or keep the client in a protected-room-only state.
    await alice.evaluate(`(() => {
      const originalFetch = window.fetch.bind(window);
      window.__restoreBoundFailureFetch = () => { window.fetch = originalFetch; };
      window.fetch = (input, init = {}) => {
        const url = new URL(typeof input === 'string' ? input : input.url, location.href);
        if (url.pathname === '/p2p/rooms' && init.method === 'POST' && init.body) {
          return Promise.resolve(new Response('{"error":"Denied"}', {
            status: 403, headers: { 'content-type': 'application/json' },
          }));
        }
        return originalFetch(input, init);
      };
      document.getElementById('createObjectRoom').click();
    })()`);
    await until(() => alice.evaluate('document.getElementById("state").textContent===' +
      '"A autorização do arquivo foi negada"'), 'bound-object denial was not reported');
    assert.equal(await alice.evaluate('window.__poc.snapshot().roomId'), null,
      'failed bound create retained a stale room ID');
    assert.equal(await alice.evaluate('document.getElementById("room").textContent'), '',
      'failed bound create retained stale room text');
    assert.equal(await alice.evaluate('window.__poc.snapshot().role'), null,
      'failed bound create retained a stale role');
    assert.equal(await alice.evaluate('document.getElementById("leave").disabled'), true,
      'failed bound create left the leave action enabled without a room');
    assert.equal(await alice.evaluate('document.getElementById("createObjectRoom").disabled'), false,
      'failed bound create did not release the create controls');
    await alice.evaluate('window.__restoreBoundFailureFetch()');
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
    // The room POST may succeed while the subsequent authoritative WebSocket
    // admission recheck rejects the room. That failure must retire all pending
    // room identity and protected-only state rather than leave a dead room UI.
    await alice.evaluate(`(() => {
      const originalFetch = window.fetch.bind(window);
      window.__restoreAdmissionFetch = () => { window.fetch = originalFetch; };
      window.fetch = (input, init = {}) => {
        const url = new URL(typeof input === 'string' ? input : input.url, location.href);
        if (url.pathname === '/p2p/rooms' && init.method === 'POST' && init.body) {
          return Promise.resolve(new Response(JSON.stringify({
            roomId: 'missing-bound-room',
            hostKey: 'invalid-host-key',
            boundObject: { folderId: 'root', fileName: 'sealed.bin',
              sha256: '${expectedDigest}', size: ${ciphertext.length} },
          }), { status: 201, headers: { 'content-type': 'application/json' } }));
        }
        return originalFetch(input, init);
      };
    })()`);
    await alice.evaluate('window.__poc.createRoom({folderId:"root",fileName:"sealed.bin"})');
    await until(() => alice.evaluate('document.getElementById("state").textContent===' +
      '"Erro: INVALID_INVITE" && window.__poc.snapshot().roomId===null && ' +
      'window.__poc.snapshot().role===null && window.__poc.snapshot().boundObject===null && ' +
      'document.getElementById("room").textContent==="" && document.getElementById("leave").disabled && ' +
      '!document.getElementById("create").disabled && !document.getElementById("createObjectRoom").disabled'),
    'WebSocket admission failure retained a stale protected room');
    assert.equal(await alice.evaluate('window.__poc.snapshot().diagnostics.rejected.includes("INVALID_INVITE")'), true,
      'WebSocket admission rejection was not recorded');
    await alice.evaluate('window.__restoreAdmissionFetch()');
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
    // A signaling socket can be retired by the broker while a second room
    // creation is still waiting for its HTTP response. Socket close must abort
    // that request and invalidate its intent, not allow a late room reconnect.
    await refreshedBob.evaluate(`(() => {
      const originalFetch = window.fetch.bind(window);
      window.__createAbortObserved = false;
      window.__createSocketCountBeforeClose = window.__testSockets.length;
      window.__restoreCloseCreateFetch = () => { window.fetch = originalFetch; };
      window.__releaseCloseCreateFetch = null;
      window.fetch = (input, init = {}) => {
        const url = new URL(typeof input === 'string' ? input : input.url, location.href);
        if (url.pathname === '/p2p/rooms' && init.method === 'POST') {
          return new Promise((resolve, reject) => {
            const signal = init.signal;
            const abort = () => {
              window.__createAbortObserved = true;
            };
            if (!signal) return reject(new Error('missing create abort signal'));
            if (signal.aborted) return abort();
            signal.addEventListener('abort', abort, { once: true });
            // Deliberately ignore AbortSignal and deliver a late success. The
            // room-intent fence, not fetch cooperation, must prevent reconnect.
            window.__releaseCloseCreateFetch = () => resolve({ ok: true,
              json: async () => ({ roomId: 'late-room-after-close', hostKey: 'late-host-after-close' }) });
          });
        }
        return originalFetch(input, init);
      };
      document.getElementById('create').click();
    })()`);
    await until(() => refreshedBob.evaluate('document.getElementById("create").disabled'),
      'room create was not pending before broker socket close');
    await refreshedBob.evaluate('document.querySelector("[data-testid=accept-peer]").click()');
    // No shared mutation-serialized ACL authority exists in this legacy app.
    // The broker must close the bound room rather than relay the WebRTC offer.
    // peers.length===0 can be TRUE before any signaling is processed. Require
    // BOTH affirmative server ROOM_CLOSED and the socket-close side effect,
    // which clears the pinned object on the real browser client.
    await until(() => refreshedBob.evaluate(
      'window.__poc.snapshot().diagnostics.rejected.includes("ROOM_CLOSED")' +
      ' && window.__poc.snapshot().boundObject===null' +
      ' && window.__poc.snapshot().peers.length===0' +
      ' && window.__createAbortObserved'),
    'broker did not affirmatively close bound signaling without all-party authority', 20_000);
    await refreshedBob.evaluate('window.__releaseCloseCreateFetch()');
    await until(() => refreshedBob.evaluate(
      '!document.getElementById("create").disabled && !document.getElementById("createObjectRoom").disabled'),
    'late room response did not settle after the aborted intent');
    assert.equal(await refreshedBob.evaluate('window.__poc.snapshot().roomId'), null,
      'a late room-creation response restored the room after signaling closed');
    assert.equal(await refreshedBob.evaluate('window.__poc.snapshot().role'), null,
      'a late room-creation response reconnected the closed room');
    assert.equal(await refreshedBob.evaluate('window.__testSockets.length'),
      await refreshedBob.evaluate('window.__createSocketCountBeforeClose'),
      'a late room-creation response created a new signaling socket');
    await refreshedBob.evaluate('window.__restoreCloseCreateFetch()');
    assert.equal(await refreshedBob.evaluate('window.__poc.snapshot().diagnostics.verifiedFiles.length'), 0,
      'no bound ciphertext transfer can be received without snapshot authority');
    console.log('PASS real Root.ark Edge: signed-cookie manual 1:N transfer, bound owner ACL/digest admission, and bound signaling fail-closed without atomic authority');
  } finally {
    for (const page of pages) page.close();
    child.kill();
    await f.close();
    try { rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 150 }); }
    catch { /* Edge child may still hold disposable profile briefly. */ }
  }
}
run().catch(error => { console.error('FAIL app Edge: ' + error.message); process.exitCode = 1; });
