# Issue #242: disposable browser WebRTC room

**Research-only, loopback-only demo.** The broker has no Root.ark production routes, user data, secrets, persisted rooms or storage. It accepts an optional trusted callback that uses Root.ark's existing signed-session verifier. The experiments now require `ws` and `jsonwebtoken`, which are already declared Root.ark application dependencies; the browser uses native `RTCPeerConnection` and `crypto.subtle`. No GPL or upstream code was copied. See [research](../../docs/roadmap/issue-242-p2p-feasibility-2026-11-06.md).

## Run

```powershell
cd experiments\issue242-webrtc
npm ci --ignore-scripts
npm test
npm run test:browser
npm start
```

Open the printed `http://127.0.0.1:<port>` in two or three local browser tabs. Create a room in the host tab; generate and manually copy the **room ID** plus **invitation token** (never use URL query strings). Join as guest, approve the host's peer request, and manually approve any offered file. Choose a local fixture file (1 MiB maximum) or send a small text. Host can revoke an unused invite or remove a joined participant. All data-channel bytes go between browser peers; the broker forwards only signaling objects and transient invitation/room metadata.

## Optional authenticated-room test mode

The caller may supply `makeBroker({ authenticateSession })`, where the callback receives the HTTP request or WebSocket upgrade and returns the currently authenticated Root.ark principal. The trusted host must compose the existing `createRealtimeAuthenticator` using its active `jwt`, `jwtSecret`, `loadCurrentUser` and `normalizeUserPermissions`, extracting the HttpOnly `rootark_session` cookie with `parseCookies` from `src/middlewares/auth.js`. The callback is checked on room creation, upgrade, each incoming/outgoing message and a 1-second sweep. Missing/invalid/expired/revoked/TOTP-enrollment sessions are denied.

In authenticated mode the room is bound to its creator's **server-verified username and session-version epoch**, the invitation is issued for one exact recipient username, and only that signed-in recipient may join. A stolen host key or invitation does not change the signed-in identity. Browser peer requests and individual file offers still require separate consent; the UI displays the verified usernames. A new session epoch cannot reuse the old room; no JWT or session token enters an invite URL or log.

`npm start` intentionally remains the original **anonymous loopback** demo. The signed-session mode is exercised through `npm test` and `npm run test:browser` with real Root.ark auth middleware, newly signed disposable HS256 JWTs and in-memory fixture users. The browser test isolates Alice, Bob, Carol and Eve into separate HttpOnly cookie contexts in **one** temporary Edge process. No genuine Root.ark session, database, protected file or user credential is accessed. Mounting the broker same-origin with Root.ark's live server/user store, permission policy and key authority remains a **separate security-reviewed task**; this PoC does not provide device signature binding, file ACL grants, authenticated end-to-end key exchange, ZK file keys, instant remote deletion or reliable transfer across NAT.

## Security and scope

- Server binds to `127.0.0.1`, accepts matching WebSocket origin only, caps each room at 4 members, each message at 16 KiB, 120 messages per 10 seconds, and 16 rooms. An invitation is a random 256-bit one-use token with 60-second TTL, not a human PIN. Rooms expire after 5 minutes, and host disconnect closes a room. Invite revocation invalidates an **unredeemed** token; already-joined guests need an explicit kick.
- Only the host may ask a guest to establish WebRTC; guest approval is required before SDP/ICE signaling is relayed. The file receiver separately approves each file. There are no public ICE servers (`iceServers: []`), TURN credentials or protected files. Signed session checks run only with an explicitly provided trusted callback.
- Per-recipient file memory is bounded by 1 MiB fixture bytes and at most 128 nonempty chunks (plus browser overhead). Zero-byte, too-many or oversized chunks abort the receiver and discard partial chunks. The peer receives an abort message. Diagnostics retain at most 100 entries per category; the visible event log retains 100 lines of at most 150 characters each. This demo buffers whole files in memory and checks SHA-256 on receipt. **No large-file streaming, resume, Android, NAT traversal, TURN, end-to-end app identity verification, authenticated key exchange or ZK file key proof**. DTLS transport security is not equivalent to Root.ark ZK.
- `npm test` verifies original signaling plus signed-session, wrong-recipient, revoked-epoch, expiration, TOTP and immediate signaling-denial cases. `npm run test:browser` validates the original 1:N SHA-256 flow/flood limits and a second session-scoped 1:N run with two validated recipients, file approval, wrong-user rejection and mid-room revocation. The browser test uses one ephemeral Edge process and two sequential loopback brokers, cleaning up its disposable profiles and sockets afterward.

Do not deploy or merge as a product feature. No Root.ark runtime route, user record, storage, root package script or CI config was changed.
