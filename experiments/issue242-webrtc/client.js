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
  const inRootark = Boolean(location.pathname?.startsWith('/p2p/'));
  $('rootarkReturn').hidden = !inRootark;
  $('boundObjectControls').hidden = !inRootark;
  const wsUrl = location.origin.replace(/^http/, 'ws') + (inRootark ? '/ws' : '/signal');
  const fileWire = window.P2PFileWire;
  const MAX_FILE = fileWire ? fileWire.MAX_FILE : (32 * 1024 * 1024);
  const BUFFER_HIGH = 256 * 1024;
  let preparingFile = false;
  let ws, roomId, hostKey, selfId, role, activeBoundObject = null;
  let roomIntent = 0;
  let protectedRoomRequired = false;
  const peers = new Map(), invites = new Map();
  const diagnostics = { verifiedFiles: [], verifiedTexts: [], rejected: [], channels: [] };
  const wire = data => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(data)); };

  function retireRoom() {
    const oldSocket = ws;
    ws = null; // Ignore callbacks from the previous room immediately.
    if (oldSocket && oldSocket.readyState < 2) oldSocket.close();
    // A room switch must not reuse peer channels, offers or invitations from
    // the previous authenticated room while its old socket is still closing.
    for (const peer of peers.values()) closePeer(peer);
    peers.clear();
    invites.clear();
    $('invites').replaceChildren();
    $('peers').replaceChildren();
    $('incoming').replaceChildren();
    selfId = null;
    role = null;
    activeBoundObject = null;
    $('invite').disabled = true;
  }
  function connect(credentials) {
    retireRoom();
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
        activeBoundObject = inRootark && m.boundObject &&
          fileWire.validDigest(m.boundObject.sha256) &&
          Number.isSafeInteger(m.boundObject.size) &&
          m.boundObject.size > 0 && m.boundObject.size <= MAX_FILE
          ? m.boundObject : null;
        $('invite').disabled = role !== 'host';
        log('Entrou na sala como ' + role + (m.username ? ' (' + m.username + ')' : ''));
      } else if (m.type === 'invited') {
        invites.set(m.inviteId, m);
        const div = document.createElement('div');
        div.className = 'entry';
        const title = document.createElement('span');
        title.textContent = 'Convite' + (m.recipient ? ' para ' + m.recipient : '') +
          ': ' + m.invitation + ' (60 s) ';
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
        line.textContent = 'Convidado ' + (m.username || m.peerId.slice(0, 5)) + ' ';
        const kick = document.createElement('button');
        kick.textContent = 'Revogar participante';
        kick.addEventListener('click', () => wire({ type: 'kick', to: m.peerId }));
        line.append(kick);
        $('peers').append(line);
        wire({ type: 'request-peer', to: m.peerId });
      } else if (m.type === 'peer-request') {
        const div = document.createElement('div');
        div.className = 'entry';
        div.textContent = (m.username ? 'Host ' + m.username : 'Host') + ' solicita conexão: ';
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
            if (ws !== eventSocket) return;
            wire({ type: 'signal', to: p.id, signal: { kind: 'answer', sdp: p.pc.localDescription } });
          } else if (m.signal.kind === 'answer') {
            await p.pc.setRemoteDescription(m.signal.sdp);
            await flushIce(p);
          }
        } catch (e) { if (ws === eventSocket) log('Negociação falhou: ' + e.name); }
      } else if (m.type === 'peer-left') {
        const p = peers.get(m.peerId);
        if (p) closePeer(p);
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
      activeBoundObject = null;
      for (const p of peers.values()) closePeer(p);
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
    const p = { id, pc, initiator, dc: null, candidates: [], outgoing: null, incoming: null,
      pendingOffer: null, outgoingUi: null, incomingUi: null, saved: null, peakBuffered: 0 };
    peers.set(id, p);
    pc.onicecandidate = e => {
      if (e.candidate) wire({ type: 'signal', to: id, signal: { kind: 'ice', candidate: e.candidate.toJSON() } });
    };
    pc.ondatachannel = e => attachChannel(p, e.channel);
    pc.onconnectionstatechange = () => {
      log('WebRTC (' + id.slice(0, 5) + '): ' + pc.connectionState);
      if (['disconnected', 'failed', 'closed'].includes(pc.connectionState)) resetTransfers(p);
    };
    return p;
  }
  function sendControl(p, message) {
    if (peers.get(p.id) !== p || p.dc?.readyState !== 'open') return;
    try { p.dc.send(JSON.stringify(message)); } catch { resetTransfers(p); }
  }
  function clearPending(p) {
    p.pendingOffer?.element.remove();
    p.pendingOffer = null;
  }
  function clearIncoming(p) {
    if (p.incoming) {
      p.incoming.chunks.length = 0;
      p.incoming.chunksSize = 0;
      p.incoming = null;
    }
    p.incomingUi?.node.remove();
    p.incomingUi = null;
  }
  function clearOutgoing(p) {
    if (p.outgoing) {
      p.outgoing.abort.abort(); // Wakes a sender paused on bufferedamountlow.
      clearTimeout(p.outgoing.timer);
      p.outgoing.file = null;
      p.outgoing = null;
    }
    p.outgoingUi?.node.remove();
    p.outgoingUi = null;
  }
  function resetTransfers(p) {
    clearPending(p);
    clearIncoming(p);
    clearOutgoing(p);
  }
  function closePeer(p) {
    resetTransfers(p);
    if (p.saved) {
      URL.revokeObjectURL(p.saved.url);
      p.saved.element.remove();
      p.saved = null;
    }
    p.pc.close();
  }
  function transferUi(p, title, direction, cancel) {
    const node = document.createElement('div');
    node.className = 'entry';
    const status = document.createElement('span');
    status.textContent = title + ' ';
    const button = document.createElement('button');
    button.dataset.testid = direction === 'incoming' ? 'cancel-incoming' : 'cancel-outgoing';
    button.textContent = 'Cancelar';
    button.addEventListener('click', cancel);
    node.append(status, button);
    $('transfers').append(node);
    return { node, status };
  }
  function showVerifiedDownload(p, rx, blob) {
    if (p.saved) {
      URL.revokeObjectURL(p.saved.url);
      p.saved.element.remove();
    }
    const url = URL.createObjectURL(blob);
    const element = document.createElement('div');
    element.className = 'entry';
    const anchor = document.createElement('a');
    anchor.href = url;
    // The sender's filename is untrusted: no paths, control characters or executable MIME.
    anchor.download = rx.name.replace(/[\x00-\x1f\\/<>:"|?*]/g, '_').slice(0, 100) || 'arquivo.bin';
    anchor.textContent = 'Baixar arquivo verificado: ' + anchor.download + ' (' + rx.size + ' bytes)';
    element.append(anchor);
    $('downloads').append(element);
    p.saved = { url, element };
  }
  function attachChannel(p, dc) {
    // One reliable, ordered channel per consented peer. A second or unordered
    // peer-created channel must never replace the active transfer state.
    const invalid = p.dc || !dc || dc.label !== 'fixture-transfer' ||
      dc.ordered !== true ||
      dc.maxRetransmits !== null || dc.maxPacketLifeTime !== null;
    if (invalid) {
      if (dc && typeof dc.close === 'function') dc.close();
      record(diagnostics.rejected, 'INVALID_CHANNEL');
      return;
    }
    p.dc = dc;
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 64 * 1024;
    dc.onopen = () => {
      record(diagnostics.channels, p.id);
      log('DataChannel aberto: ' + p.id.slice(0, 5));
    };
    dc.onclose = () => {
      resetTransfers(p);
      log('DataChannel fechado: ' + p.id.slice(0, 5));
    };
    function abortIncoming(code) {
      const rx = p.incoming;
      clearIncoming(p);
      if (rx) sendControl(p, { type: 'abort-file', id: rx.id });
      record(diagnostics.rejected, code);
      log('Arquivo rejeitado: ' + code);
    }
    dc.onmessage = async event => {
      if (peers.get(p.id) !== p || p.dc !== dc) return;
      if (event.data instanceof ArrayBuffer) {
        const rx = p.incoming;
        if (!rx) { record(diagnostics.rejected, 'UNEXPECTED_CHUNK'); return; }
        if (rx.phase !== 'receiving' || rx.chunks.length >= fileWire.MAX_CHUNKS) {
          return abortIncoming('INVALID_CHUNK');
        }
        try {
          const chunk = fileWire.parseFrame(event.data, rx.id, rx.chunksSize, rx.size);
          rx.chunks.push(chunk.slice());
          rx.chunksSize += chunk.byteLength;
          if (rx.chunksSize % (256 * 1024) === 0 && p.incomingUi) {
            p.incomingUi.status.textContent = 'Recebido ' + rx.chunksSize + '/' + rx.size + ' bytes ';
          }
        } catch { abortIncoming('INVALID_CHUNK'); }
        return;
      }
      if (typeof event.data !== 'string' || event.data.length > 4096) {
        record(diagnostics.rejected, 'INVALID_CONTROL'); return;
      }
      let m;
      try { m = JSON.parse(event.data); } catch { return; }
      if (!m || typeof m !== 'object' || Array.isArray(m)) return;
      if (m.type === 'text' && activeBoundObject) {
        record(diagnostics.rejected, 'BOUND_ROOM_TEXT');
        return;
      }
      if (m.type === 'text' && typeof m.text === 'string' && m.text.length <= 1000 && /^[0-9a-f]{64}$/.test(m.digest)) {
        const hash = await sha(new TextEncoder().encode(m.text));
        if (hash === m.digest) {
          record(diagnostics.verifiedTexts, { from: p.id, text: m.text, sha256: hash });
          log('Texto SHA-256 OK de ' + p.id.slice(0, 5));
        } else record(diagnostics.rejected, 'TEXT_DIGEST');
      } else if (m.type === 'offer-file') {
        const isValid = (fileWire && typeof fileWire.validOffer === 'function')
          ? (fileWire.validOffer(m) && (
              typeof m.id === 'string' &&
              /^[A-Za-z0-9_-]{1,64}$/.test(m.id) &&
              typeof m.name === 'string' && m.name.length > 0 && m.name.length <= 100 &&
              Number.isSafeInteger(m.size) && m.size > 0 && m.size <= MAX_FILE &&
              /^[0-9a-f]{64}$/.test(m.digest)
            ))
          : (
              typeof m.id === 'string' &&
              /^[A-Za-z0-9_-]{1,64}$/.test(m.id) &&
              typeof m.name === 'string' && m.name.length > 0 && m.name.length <= 100 &&
              Number.isSafeInteger(m.size) && m.size > 0 && m.size <= MAX_FILE &&
              /^[0-9a-f]{64}$/.test(m.digest)
            );
        if (!isValid) {
          record(diagnostics.rejected, 'BAD_OFFER'); return;
        }
        if (activeBoundObject && (m.name !== activeBoundObject.fileName ||
          m.size !== activeBoundObject.size || m.digest !== activeBoundObject.sha256)) {
          record(diagnostics.rejected, 'OBJECT_DIGEST_MISMATCH');
          sendControl(p, { type: 'decline-file', id: m.id });
          return;
        }
        if (p.incoming || p.pendingOffer) {
          sendControl(p, { type: 'decline-file', id: m.id }); return;
        }
        const div = document.createElement('div');
        div.className = 'entry';
        div.textContent = 'Arquivo ' + m.name + ' (' + m.size + ' bytes) ';
        p.pendingOffer = { id: m.id, element: div };
        const button = document.createElement('button');
        button.textContent = 'Aceitar arquivo';
        button.dataset.testid = 'accept-file';
        button.addEventListener('click', () => {
          if (p.pendingOffer?.id !== m.id || dc.readyState !== 'open') return;
          clearPending(p);
          p.incoming = { ...m, chunksSize: 0, chunks: [], phase: 'receiving' };
          p.incomingUi = transferUi(p, 'Recebendo ' + m.name, 'incoming', () => {
            if (p.incoming?.id !== m.id) return;
            clearIncoming(p);
            sendControl(p, { type: 'cancel-file', id: m.id });
            log('Recebimento cancelado');
          });
          sendControl(p, { type: 'accept-file', id: m.id });
        });
        const decline = document.createElement('button');
        decline.textContent = 'Recusar arquivo';
        decline.addEventListener('click', () => {
          if (p.pendingOffer?.id !== m.id) return;
          clearPending(p);
          sendControl(p, { type: 'decline-file', id: m.id });
        });
        div.append(button, decline);
        $('incoming').append(div);
      } else if (m.type === 'accept-file' && p.outgoing?.id === m.id && p.outgoing.phase === 'offered') {
        clearTimeout(p.outgoing.timer);
        p.outgoing.phase = 'sending';
        void sendChunks(p, p.outgoing);
      } else if (m.type === 'decline-file' && p.outgoing && m.id === p.outgoing.id) {
        clearOutgoing(p);
        log('Arquivo recusado pelo destinatário');
      } else if (m.type === 'abort-file' && p.outgoing && m.id === p.outgoing.id) {
        clearOutgoing(p);
        log('Arquivo abortado pelo destinatário');
      } else if (m.type === 'cancel-file' && fileWire.validId(m.id)) {
        if (p.outgoing?.id === m.id) clearOutgoing(p);
        if (p.incoming?.id === m.id) clearIncoming(p);
        if (p.pendingOffer?.id === m.id) clearPending(p);
        log('Transferência cancelada pelo par');
      } else if (m.type === 'end-file' && p.incoming && m.id === p.incoming.id) {
        const rx = p.incoming;
        if (rx.phase !== 'receiving') return abortIncoming('INVALID_CONTROL');
        rx.phase = 'verifying';
        if (rx.chunksSize !== rx.size) return abortIncoming('SIZE_MISMATCH');
        try {
          const blob = new Blob(rx.chunks, { type: 'application/octet-stream' });
          const digest = await sha(await blob.arrayBuffer());
          if (p.incoming !== rx) return; // Receiver canceled during hashing.
          if (digest !== rx.digest) return abortIncoming('FILE_DIGEST');
          clearIncoming(p);
          showVerifiedDownload(p, rx, blob);
          record(diagnostics.verifiedFiles, { from: p.id, name: rx.name, size: rx.size, sha256: digest });
          sendControl(p, { type: 'verified-file', id: rx.id, digest });
          log('Arquivo SHA-256 OK: ' + rx.name);
        } catch { if (p.incoming === rx) abortIncoming('VERIFY_FAILED'); }
      } else if (m.type === 'verified-file' && p.outgoing?.id === m.id &&
        p.outgoing.phase === 'verifying' && m.digest === p.outgoing.digest) {
        const name = p.outgoing.name;
        clearOutgoing(p);
        log('Recebimento confirmado SHA-256: ' + name);
      }
    };
  }
  async function awaitBufferSpace(dc, signal) {
    if (dc.bufferedAmount < BUFFER_HIGH || signal.aborted || dc.readyState !== 'open') return;
    await new Promise(resolve => {
      const finish = () => {
        dc.removeEventListener('bufferedamountlow', finish);
        dc.removeEventListener('close', finish);
        signal.removeEventListener('abort', finish);
        resolve();
      };
      dc.addEventListener('bufferedamountlow', finish);
      dc.addEventListener('close', finish);
      signal.addEventListener('abort', finish, { once: true });
      if (signal.aborted || dc.readyState !== 'open' || dc.bufferedAmount < BUFFER_HIGH) finish();
    });
  }
  async function sendChunks(p, tx) {
    const { dc } = p;
    try {
      for (let offset = 0; offset < tx.size; offset += fileWire.CHUNK_BYTES) {
        await awaitBufferSpace(dc, tx.abort.signal);
        if (p.outgoing !== tx || tx.abort.signal.aborted || dc.readyState !== 'open') return;
        const bytes = new Uint8Array(await tx.file.slice(offset, offset + fileWire.CHUNK_BYTES).arrayBuffer());
        if (p.outgoing !== tx || tx.abort.signal.aborted || dc.readyState !== 'open') return;
        dc.send(fileWire.packFrame(tx.id, offset, bytes));
        p.peakBuffered = Math.max(p.peakBuffered, dc.bufferedAmount);
        if (p.outgoingUi && offset % (256 * 1024) === 0) {
          p.outgoingUi.status.textContent = 'Enviando ' + (offset + bytes.byteLength) + '/' + tx.size + ' bytes ';
        }
      }
      if (p.outgoing !== tx || dc.readyState !== 'open') return;
      tx.file = null; // Only the recipient's final SHA-256 acknowledgement completes the send.
      tx.phase = 'verifying';
      p.outgoingUi.status.textContent = 'Aguardando verificação SHA-256 ';
      sendControl(p, { type: 'end-file', id: tx.id });
      if (p.outgoing !== tx) return;
      tx.timer = setTimeout(() => {
        if (p.outgoing !== tx) return;
        cancelOutgoing(p, true);
        log('Confirmação de integridade expirou');
      }, 30_000);
    } catch {
      if (p.outgoing !== tx) return;
      cancelOutgoing(p, true);
      record(diagnostics.rejected, 'SEND_FAILED');
    }
  }
  function cancelOutgoing(p, notify) {
    const tx = p.outgoing;
    if (!tx) return;
    clearOutgoing(p);
    if (notify) sendControl(p, { type: 'cancel-file', id: tx.id });
  }
  async function sendFile(file) {
    if (protectedRoomRequired && !activeBoundObject) {
      record(diagnostics.rejected, 'ROOM_CHANGED');
      return log('Aguarde a confirmação da sala vinculada');
    }
    if (!file || file.size === 0 || file.size > MAX_FILE || preparingFile) {
      return log('Selecione arquivo de até 32 MiB');
    }
    if (activeBoundObject && (file.name !== activeBoundObject.fileName ||
      file.size !== activeBoundObject.size)) {
      record(diagnostics.rejected, 'OBJECT_DIGEST_MISMATCH');
      return log('O arquivo selecionado não corresponde ao objeto vinculado');
    }
    const receivers = [...peers.values()].filter(p => p.dc?.readyState === 'open' && !p.outgoing);
    if (!receivers.length) return log('Nenhum par disponível');
    const sendingIntent = roomIntent;
    preparingFile = true;
    try {
      const digest = await sha(await file.arrayBuffer());
      if (sendingIntent !== roomIntent || (protectedRoomRequired && !activeBoundObject)) {
        record(diagnostics.rejected, 'ROOM_CHANGED');
        return log('Envio de arquivo cancelado após troca de sala');
      }
      if (activeBoundObject && digest !== activeBoundObject.sha256) {
        record(diagnostics.rejected, 'OBJECT_DIGEST_MISMATCH');
        return log('O SHA-256 não corresponde ao ciphertext da sala');
      }
      const name = file.name.slice(0, 100) || 'arquivo.bin';
      for (const p of receivers) {
        if (sendingIntent !== roomIntent) break;
        if (peers.get(p.id) !== p || p.dc?.readyState !== 'open' || p.outgoing) continue;
        const id = crypto.randomUUID().replace(/-/g, '');
        const tx = { id, name, size: file.size, digest, file, phase: 'offered',
          abort: new AbortController(), timer: null };
        p.outgoing = tx;
        p.outgoingUi = transferUi(p, 'Aguardando aceite de ' + p.id.slice(0, 5), 'outgoing',
          () => cancelOutgoing(p, true));
        sendControl(p, { type: 'offer-file', id, name, size: file.size, digest });
        if (p.outgoing !== tx) continue;
        tx.timer = setTimeout(() => {
          if (p.outgoing === tx) cancelOutgoing(p, true);
        }, 60_000);
      }
      log('Arquivo oferecido a ' + receivers.length + ' destinatário(s)');
    } catch { log('Falha ao ler ou oferecer arquivo'); }
    finally { preparingFile = false; }
  }
  async function sendText(value) {
    if (protectedRoomRequired || activeBoundObject) {
      return log('Sala vinculada aceita somente ciphertext do arquivo selecionado');
    }
    if (!value || value.length > 1000) return;
    const sendingSocket = ws;
    const sendingRoom = roomId;
    const sendingPeerId = selfId;
    const sendingRole = role;
    const sendingIntent = roomIntent;
    const receivers = [...peers.values()].map(peer => ({ peer, dc: peer.dc }));
    const sameRoom = () => ws === sendingSocket && roomId === sendingRoom &&
      selfId === sendingPeerId && role === sendingRole &&
      roomIntent === sendingIntent && !protectedRoomRequired && !activeBoundObject;
    const digest = await sha(new TextEncoder().encode(value));
    if (!sameRoom()) {
      record(diagnostics.rejected, 'ROOM_CHANGED');
      return log('Envio de texto cancelado após troca de sala');
    }
    let count = 0;
    for (const { peer, dc } of receivers) {
      if (!sameRoom()) break;
      if (peers.get(peer.id) !== peer || peer.dc !== dc || dc?.readyState !== 'open') continue;
      dc.send(JSON.stringify({ type: 'text', text: value, digest }));
      count++;
    }
    log('Texto enviado a ' + count + ' destinatário(s)');
  }
  async function createRoom(boundObject = null) {
    const intent = ++roomIntent;
    protectedRoomRequired = Boolean(boundObject);
    if (protectedRoomRequired) retireRoom();
    const headers = {};
    if (inRootark) {
      const csrf = document.cookie.split(';').map(value => value.trim())
        .find(value => value.startsWith('rootark_csrf='));
      if (csrf) headers['X-CSRF-Token'] = csrf.slice('rootark_csrf='.length);
      if (boundObject) headers['Content-Type'] = 'application/json';
    }
    const body = inRootark && boundObject ? JSON.stringify({ boundObject }) : undefined;
    const response = await fetch(inRootark ? '/p2p/rooms' : '/rooms',
      { method: 'POST', headers, body, credentials: 'same-origin' });
    if (intent !== roomIntent) return;
    if (!response.ok) throw new Error('room creation failed');
    const result = await response.json();
    if (intent !== roomIntent) return;
    ({ roomId, hostKey } = result);
    $('room').textContent = roomId;
    if (result.boundObject) log('Sala vinculada à ACL e SHA-256: ' +
      result.boundObject.folderId + '/' + result.boundObject.fileName);
    connect({ hostKey });
  }
  function joinRoom(room, invitation) {
    ++roomIntent;
    protectedRoomRequired = false;
    roomId = room; $('room').textContent = roomId;
    connect({ invitation });
  }
  $('create').onclick = () => createRoom().catch(e => log(e.message));
  $('createObjectRoom').onclick = () => createRoom({
    folderId: $('objectFolderInput').value.trim(),
    fileName: $('objectFileInput').value.trim(),
  }).catch(() => log('A autorização do arquivo foi negada'));
  $('invite').onclick = () => wire({ type: 'invite', recipient: $('recipientInput').value.trim() });
  $('join').onclick = () => joinRoom($('roomInput').value, $('inviteInput').value);
  $('sendFile').onclick = () => sendFile($('fileInput').files[0]);
  $('sendText').onclick = () => sendText($('textInput').value);
  // Diagnostic surface is in-memory and only used by the disposable Edge CDP test.
  window.__poc = {
    createRoom, joinRoom, sendFile, sendText,
    invite: recipient => wire({ type: 'invite', recipient }),
    invitations: () => [...invites.values()],
    // Exposed only for disposable Edge CDP adversarial regression tests.
    testChannel: index => [...peers.values()][index]?.dc,
    snapshot: () => ({ roomId, role, peerId: selfId, boundObject: activeBoundObject,
      peers: [...peers.values()].map(p => ({
      id: p.id, channel: p.dc?.readyState || 'none',
      incomingChunks: p.incoming?.chunks.length ?? 0,
      incomingBytes: p.incoming?.chunksSize ?? 0,
      outgoingPhase: p.outgoing?.phase || null,
      pendingOffer: Boolean(p.pendingOffer),
      savedDownload: Boolean(p.saved),
      peakBuffered: p.peakBuffered
    })), diagnostics })
  };
})();
