'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const MAX_EVENTS = 100;
  const logLines = [];
  const record = (list, value) => {
    if (list.length >= MAX_EVENTS) list.shift();
    list.push(value);
  };
  const log = message => {
    const line = String(message).slice(0, 150).replace(/[\r\n]/g, ' ');
    record(logLines, line);
    $('events').textContent = logLines.join('\n') + '\n';
    $('state').textContent = line;
  };
  const toHex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
  const sha = async bytes => toHex(await crypto.subtle.digest('SHA-256', bytes));
  const wsUrl = location.origin.replace(/^http/, 'ws') + '/signal';
  const MAX_FILE = 1024 * 1024;
  const MAX_FILE_CHUNKS = MAX_FILE / (8 * 1024); // Honest sender emits at most 64.
  let ws, roomId, hostKey, selfId, role;
  const peers = new Map(), invites = new Map();
  const diagnostics = { verifiedFiles: [], verifiedTexts: [], rejected: [], channels: [] };
  const wire = data => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(data)); };

  function connect(credentials) {
    const oldSocket = ws;
    ws = null; // old callbacks must not retain authority over the new room.
    if (oldSocket && oldSocket.readyState < 2) oldSocket.close();
    for (const p of peers.values()) p.pc.close();
    peers.clear();
    invites.clear();
    $('peers').replaceChildren();
    $('invites').replaceChildren();
    $('incoming').replaceChildren();
    selfId = null;
    role = null;
    $('invite').disabled = true;
    ws = new WebSocket(wsUrl);
    const eventSocket = ws;
    ws.onopen = () => {
      if (ws !== eventSocket) return;
      wire({ type: 'join', roomId, ...credentials });
    };
    ws.onmessage = async event => {
      if (ws !== eventSocket) return;
      let m;
      try { m = JSON.parse(event.data); } catch { return; }
      if (m.type === 'error') { record(diagnostics.rejected, m.code); return log('Erro: ' + m.code); }
      if (m.type === 'joined') {
        selfId = m.peerId; role = m.role;
        $('invite').disabled = role !== 'host';
        log('Entrou na sala como ' + role);
      } else if (m.type === 'invited') {
        invites.set(m.inviteId, m);
        const div = document.createElement('div');
        div.className = 'entry';
        const title = document.createElement('span');
        title.textContent = 'Convite: ' + m.invitation + ' (60 s) ';
        const revoke = document.createElement('button');
        revoke.textContent = 'Revogar';
        revoke.addEventListener('click', () => wire({ type: 'revoke', inviteId: m.inviteId }));
        div.append(title, revoke);
        div.dataset.id = m.inviteId;
        $('invites').append(div);
      } else if (m.type === 'revoked') {
        document.querySelectorAll('#invites [data-id]').forEach(el => { if (el.dataset.id === m.inviteId) el.remove(); });
        invites.delete(m.inviteId);
        log('Convite revogado');
      } else if (m.type === 'peer-joined' && role === 'host') {
        const line = document.createElement('div');
        line.className = 'entry';
        line.dataset.peerId = m.peerId;
        line.textContent = 'Convidado ' + m.peerId.slice(0, 5) + ' ';
        const kick = document.createElement('button');
        kick.textContent = 'Revogar participante';
        kick.addEventListener('click', () => wire({ type: 'kick', to: m.peerId }));
        line.append(kick);
        $('peers').append(line);
        wire({ type: 'request-peer', to: m.peerId });
      } else if (m.type === 'peer-request') {
        const div = document.createElement('div');
        div.className = 'entry';
        div.textContent = 'Host solicita conexão: ';
        for (const accept of [true, false]) {
          const button = document.createElement('button');
          button.textContent = accept ? 'Aceitar conexão' : 'Recusar';
          button.dataset.testid = accept ? 'accept-peer' : 'decline-peer';
          button.addEventListener('click', () => {
            wire({ type: 'consent', requestId: m.requestId, accept });
            div.remove();
          });
          div.append(button);
        }
        $('peers').append(div);
      } else if (m.type === 'peer-accepted') {
        const p = preparePeer(m.peerId, true);
        const dc = p.pc.createDataChannel('fixture-transfer', { ordered: true });
        attachChannel(p, dc);
        await p.pc.setLocalDescription(await p.pc.createOffer());
        if (ws !== eventSocket || peers.get(p.id) !== p) return;
        wire({ type: 'signal', to: p.id, signal: { kind: 'offer', sdp: p.pc.localDescription } });
      } else if (m.type === 'peer-allowed') {
        preparePeer(m.peerId, false);
      } else if (m.type === 'signal') {
        const p = peers.get(m.peerId);
        if (!p) return;
        try {
          if (m.signal.kind === 'ice') {
            if (m.signal.candidate) {
              if (p.pc.remoteDescription) await p.pc.addIceCandidate(m.signal.candidate);
              else p.candidates.push(m.signal.candidate);
            }
          } else if (m.signal.kind === 'offer') {
            await p.pc.setRemoteDescription(m.signal.sdp);
            await flushIce(p);
            await p.pc.setLocalDescription(await p.pc.createAnswer());
            wire({ type: 'signal', to: p.id, signal: { kind: 'answer', sdp: p.pc.localDescription } });
          } else if (m.signal.kind === 'answer') {
            await p.pc.setRemoteDescription(m.signal.sdp);
            await flushIce(p);
          }
        } catch (e) { log('Negociação falhou: ' + e.name); }
      } else if (m.type === 'peer-left') {
        const p = peers.get(m.peerId);
        if (p) p.pc.close();
        peers.delete(m.peerId);
        document.querySelectorAll('#peers [data-peer-id]').forEach(el => {
          if (el.dataset.peerId === m.peerId) el.remove();
        });
        log('Par desconectado');
      }
    };
    ws.onclose = () => {
      if (ws !== eventSocket) return;
      $('invite').disabled = true;
      for (const p of peers.values()) p.pc.close();
      peers.clear();
      log('Conexão de sinalização encerrada');
    };
  }
  async function flushIce(p) {
    for (const c of p.candidates.splice(0)) await p.pc.addIceCandidate(c);
  }
  function preparePeer(id, initiator) {
    if (peers.has(id)) return peers.get(id);
    // No STUN/TURN: prove only same-host WebRTC, never claim cross-NAT functionality.
    const pc = new RTCPeerConnection({ iceServers: [] });
    const p = { id, pc, initiator, dc: null, candidates: [], outgoing: null, incoming: null, pendingOffer: null };
    peers.set(id, p);
    pc.onicecandidate = e => {
      if (e.candidate) wire({ type: 'signal', to: id, signal: { kind: 'ice', candidate: e.candidate.toJSON() } });
    };
    pc.ondatachannel = e => attachChannel(p, e.channel);
    pc.onconnectionstatechange = () => log('WebRTC (' + id.slice(0, 5) + '): ' + pc.connectionState);
    return p;
  }
  function attachChannel(p, dc) {
    p.dc = dc;
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 32 * 1024;
    dc.onopen = () => {
      record(diagnostics.channels, p.id);
      log('DataChannel aberto: ' + p.id.slice(0, 5));
    };
    dc.onclose = () => {
      p.incoming = null;
      p.outgoing = null;
      log('DataChannel fechado: ' + p.id.slice(0, 5));
    };
    function abortIncoming() {
      const rx = p.incoming;
      if (rx) {
        p.incoming = null;
        rx.chunks.length = 0;
        rx.chunksSize = 0;
        if (dc.readyState === 'open') dc.send(JSON.stringify({ type: 'abort-file', id: rx.id }));
      }
      record(diagnostics.rejected, 'INVALID_CHUNK');
      log('Chunk rejeitado');
    }
    dc.onmessage = async event => {
      if (event.data instanceof ArrayBuffer) {
        const rx = p.incoming;
        if (!rx || event.data.byteLength === 0 || rx.chunks.length >= MAX_FILE_CHUNKS ||
          rx.chunksSize + event.data.byteLength > rx.size ||
          rx.chunksSize + event.data.byteLength > MAX_FILE) return abortIncoming();
        rx.chunks.push(new Uint8Array(event.data));
        rx.chunksSize += event.data.byteLength;
        return;
      }
      let m;
      try { m = JSON.parse(event.data); } catch { return; }
      if (m.type === 'text' && typeof m.text === 'string' && m.text.length <= 1000 && /^[0-9a-f]{64}$/.test(m.digest)) {
        const hash = await sha(new TextEncoder().encode(m.text));
        if (hash === m.digest) {
          record(diagnostics.verifiedTexts, { from: p.id, text: m.text, sha256: hash });
          log('Texto SHA-256 OK de ' + p.id.slice(0, 5));
        } else record(diagnostics.rejected, 'TEXT_DIGEST');
      } else if (m.type === 'offer-file' && typeof m.id === 'string' &&
        /^[A-Za-z0-9_-]{1,64}$/.test(m.id) &&
        typeof m.name === 'string' && m.name.length <= 100 &&
        Number.isSafeInteger(m.size) && m.size > 0 && m.size <= MAX_FILE &&
        /^[0-9a-f]{64}$/.test(m.digest) && !p.incoming && !p.pendingOffer) {
        p.pendingOffer = m.id;
        const div = document.createElement('div');
        div.className = 'entry';
        div.textContent = 'Arquivo ' + m.name + ' (' + m.size + ' bytes) ';
        const button = document.createElement('button');
        button.textContent = 'Aceitar arquivo';
        button.dataset.testid = 'accept-file';
        button.addEventListener('click', () => {
          p.incoming = { ...m, chunksSize: 0, chunks: [] };
          p.pendingOffer = null;
          dc.send(JSON.stringify({ type: 'accept-file', id: m.id }));
          div.remove();
        });
        const decline = document.createElement('button');
        decline.textContent = 'Recusar arquivo';
        decline.addEventListener('click', () => {
          p.pendingOffer = null;
          dc.send(JSON.stringify({ type: 'decline-file', id: m.id }));
          div.remove();
        });
        div.append(button, decline);
        $('incoming').append(div);
      } else if (m.type === 'accept-file' && p.outgoing && m.id === p.outgoing.id) {
        await sendChunks(p);
      } else if (m.type === 'decline-file' && p.outgoing && m.id === p.outgoing.id) {
        p.outgoing = null;
        log('Arquivo recusado pelo destinatário');
      } else if (m.type === 'abort-file' && p.outgoing && m.id === p.outgoing.id) {
        p.outgoing = null;
        log('Arquivo abortado pelo destinatário');
      } else if (m.type === 'end-file' && p.incoming && m.id === p.incoming.id) {
        const rx = p.incoming;
        p.incoming = null;
        if (rx.chunksSize !== rx.size) { record(diagnostics.rejected, 'SIZE_MISMATCH'); return log('Arquivo incompleto'); }
        const bytes = new Uint8Array(rx.size);
        let offset = 0;
        for (const chunk of rx.chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        const digest = await sha(bytes);
        if (digest !== rx.digest) { record(diagnostics.rejected, 'FILE_DIGEST'); return log('Arquivo corrompido'); }
        record(diagnostics.verifiedFiles, { from: p.id, name: rx.name, size: rx.size, sha256: digest });
        log('Arquivo SHA-256 OK: ' + rx.name);
      }
    };
  }
  async function sendChunks(p) {
    const { dc, outgoing } = p;
    if (!outgoing) return;
    for (let offset = 0; offset < outgoing.bytes.byteLength; offset += 16 * 1024) {
      if (p.outgoing !== outgoing) return;
      if (dc.readyState !== 'open') { p.outgoing = null; return; }
      while (dc.bufferedAmount > 64 * 1024) {
        await new Promise(resolve => {
          const wake = () => {
            dc.removeEventListener('bufferedamountlow', wake);
            dc.removeEventListener('close', wake);
            resolve();
          };
          dc.addEventListener('bufferedamountlow', wake, { once: true });
          dc.addEventListener('close', wake, { once: true });
        });
        if (p.outgoing !== outgoing) return;
        if (dc.readyState !== 'open') { p.outgoing = null; return; }
      }
      dc.send(outgoing.bytes.slice(offset, offset + 16 * 1024));
    }
    if (p.outgoing !== outgoing) return;
    dc.send(JSON.stringify({ type: 'end-file', id: outgoing.id }));
    p.outgoing = null;
    log('Enviado: ' + outgoing.name);
  }
  async function sendFile(file) {
    if (!file || file.size === 0 || file.size > MAX_FILE) return log('Arquivo fora do limite de 1 MiB');
    const bytes = await file.arrayBuffer();
    const digest = await sha(bytes);
    const receivers = [...peers.values()].filter(p => p.dc && p.dc.readyState === 'open' && !p.outgoing);
    for (const p of receivers) {
      const id = crypto.randomUUID();
      p.outgoing = { id, name: file.name.slice(0, 100), bytes, digest };
      p.dc.send(JSON.stringify({ type: 'offer-file', id, name: file.name.slice(0, 100), size: bytes.byteLength, digest }));
    }
    log('Arquivo oferecido a ' + receivers.length + ' destinatário(s)');
  }
  async function sendText(value) {
    if (!value || value.length > 1000) return;
    const digest = await sha(new TextEncoder().encode(value));
    let count = 0;
    for (const p of peers.values()) if (p.dc?.readyState === 'open') {
      p.dc.send(JSON.stringify({ type: 'text', text: value, digest }));
      count++;
    }
    log('Texto enviado a ' + count + ' destinatário(s)');
  }
  async function createRoom() {
    const response = await fetch('/rooms', { method: 'POST' });
    if (!response.ok) throw new Error('room creation failed');
    const result = await response.json();
    ({ roomId, hostKey } = result);
    $('room').textContent = roomId;
    connect({ hostKey });
  }
  function joinRoom(room, invitation) {
    roomId = room; $('room').textContent = roomId;
    connect({ invitation });
  }
  $('create').onclick = () => createRoom().catch(e => log(e.message));
  $('invite').onclick = () => wire({ type: 'invite' });
  $('join').onclick = () => joinRoom($('roomInput').value, $('inviteInput').value);
  $('sendFile').onclick = () => sendFile($('fileInput').files[0]);
  $('sendText').onclick = () => sendText($('textInput').value);
  // Diagnostic surface is in-memory and only used by the disposable Edge CDP test.
  window.__poc = {
    createRoom, joinRoom, sendFile, sendText,
    invite: () => wire({ type: 'invite' }),
    invitations: () => [...invites.values()],
    // Exposed only for disposable Edge CDP adversarial regression tests.
    testChannel: index => [...peers.values()][index]?.dc,
    snapshot: () => ({ roomId, role, peerId: selfId, peers: [...peers.values()].map(p => ({
      id: p.id, channel: p.dc?.readyState || 'none',
      incomingChunks: p.incoming?.chunks.length ?? 0,
      incomingBytes: p.incoming?.chunksSize ?? 0
    })), diagnostics })
  };
})();
