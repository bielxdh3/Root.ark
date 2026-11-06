# Issue #242: disposable browser WebRTC room

**Research-only, loopback-only demo**. Contains no Root.ark app imports, storage, secrets, user data, persisted rooms, or upstream code/assets. Original Node CommonJS broker with the existing `ws` dependency, plus browser-native `RTCPeerConnection` and `crypto.subtle`. License/source reuse comparisons are in [the issue research document](../../docs/roadmap/issue-242-p2p-feasibility-2026-11-06.md).

## Run

```powershell
cd E:\servidor\.worktrees\rootark-issue242-poc-20261106\experiments\issue242-webrtc
npm ci --ignore-scripts
npm test
npm run test:browser
npm start
```

Open the printed `http://127.0.0.1:<port>` in two or three local browser tabs. Create a room in the host tab; generate and manually copy the **room ID** plus **invitation token** (never use URL query strings). Join as guest, approve the host's peer request, and manually approve any offered file. Choose a local fixture file (1 MiB maximum) or send a small text. Host can revoke an unused invite or remove a joined participant. All data-channel bytes go between browser peers; the broker forwards only signaling objects and transient invitation/room metadata.

## Security and scope

- Server binds to `127.0.0.1`, accepts matching WebSocket origin only, caps each room at 4 members, each message at 16 KiB, 120 messages per 10 seconds, and 16 rooms. An invitation is a random 256-bit one-use token with 60-second TTL, not a human PIN. Rooms expire after 5 minutes, and host disconnect closes a room. Invite revocation invalidates an **unredeemed** token; already-joined guests need an explicit kick.
- Only the host may ask a guest to establish WebRTC; guest approval is required before SDP/ICE signaling is relayed. The file receiver separately approves each file. There are no public ICE servers (`iceServers: []`), TURN credentials, account/session authority or protected files.
- Per-recipient memory is bounded by 1 MiB fixture payload plus JS/browser overhead. This demo buffers whole files in memory and checks SHA-256 on receipt. **No large-file streaming, resume, Android, NAT traversal, TURN, end-to-end app identity verification, authenticated key exchange or ZK file key proof**. DTLS transport security is not equivalent to Root.ark ZK.
- `npm test` verifies negative signaling and invitations; `npm run test:browser` drives three actual Edge pages over CDP and checks two receiver SHA-256 results. The browser test creates one ephemeral headless Edge profile and one loopback broker, exits and attempts profile cleanup after validation. No external service is required.

Do not deploy or merge as a product feature. No root route, user files, package scripts or CI config were changed.
