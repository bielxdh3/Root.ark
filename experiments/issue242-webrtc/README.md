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

Open the printed `http://127.0.0.1:<port>` in two or three local browser tabs. Create a room in the host tab; generate and manually copy the **room ID** plus **invitation token** (never use URL query strings). Join as guest, approve the host's peer request, and manually approve any offered file. Choose a local test file (32 MiB maximum) or send a small text. Each participating browser has a cancel button; after the entire file passes SHA-256 verification the receiver sees a download link. The sender waits for a matching verification acknowledgment. Host can revoke an unused invite or remove a joined participant. All data-channel bytes go between browser peers; the broker forwards only signaling objects and transient invitation/room metadata.

## Optional authenticated-room test mode

The caller may supply `makeBroker({ authenticateSession })`, where the callback receives the HTTP request or WebSocket upgrade and returns the currently authenticated Root.ark principal. The trusted host must compose the existing `createRealtimeAuthenticator` using its active `jwt`, `jwtSecret`, `loadCurrentUser` and `normalizeUserPermissions`, extracting the HttpOnly `rootark_session` cookie with `parseCookies` from `src/middlewares/auth.js`. The callback is checked on room creation, upgrade, each incoming/outgoing message and a 1-second sweep. Missing/invalid/expired/revoked/TOTP-enrollment sessions are denied.

In authenticated mode the room is bound to its creator's **server-verified username and session-version epoch**, the invitation is issued for one exact recipient username, and only that signed-in recipient may join. A stolen host key or invitation does not change the signed-in identity. Browser peer requests and individual file offers still require separate consent; the UI displays the verified usernames. A new session epoch cannot reuse the old room; no JWT or session token enters an invite URL or log.

`npm start` intentionally remains the original **anonymous loopback** demo. The signed-session mode is exercised through `npm test` and `npm run test:browser` with real Root.ark auth middleware, newly signed disposable HS256 JWTs and in-memory fixture users. The browser test isolates Alice, Bob, Carol and Eve into separate HttpOnly cookie contexts in **one** temporary Edge process. That standalone test accesses no actual Root.ark storage/account. The separately gated app integration below uses real account/session authority but still does not connect to object ACLs, independent device signatures, ZK keys, TURN, NAT guarantees or durable file storage.

## Root.ark application integration (opt-in, not a release)

Set `ROOTARK_P2P_EXPERIMENTAL=true` on a **development or test** Root.ark server (the main `server.js`, with its normal JWT secret, users and HTTPS configuration). This activates the authenticated `/p2p/` page, signed-cookie + CSRF guarded `POST /p2p/rooms` and the existing `/ws` signaling connection. The main navigation displays **Transferência experimental** only for a logged-in user who currently has `listFiles`. The browser fetches no stored file automatically: the sender must manually choose a local `File`, and each recipient must explicitly accept. Only browser WebRTC DataChannels carry content.

Room admission uses Root.ark's actual HS256 `rootark_session`, TOTP enrollment checks, session version and *authoritative* user store; disabled users, missing `listFiles`, missing origin/CSRF, unknown recipients, old recipient session epochs and login revocation are rejected. The broker revalidates participants before signaling and on a periodic sweep. A 60-second single-use invite is bound to an exact username and its session-version epoch. Other `/ws` events continue using their existing path; P2P frames have their own room `type` protocol and cannot be sent without session and consent.

**Opt-in ACL-bound ciphertext room:** the same authenticated page includes a separate "Criar sala vinculada à ACL" action; provide an exact Root.ark `folderId` and filename. The server requires the **current owner** of an existing locally stored encrypted file (`user-key` or `dual`), its explicit `encrypted-files` authorized-user record, current folder/file read ACL, active object/ACL expiry and a regular retained ciphertext file with size **1–32 MiB**. It computes SHA-256 over only those local encrypted bytes (no decryption, plaintext or keys), pins the encrypted metadata and digest to the temporary room, and rechecks that binding on each room action and a 1-second sweep. Any recipient removal, ACL revocation, folder permission loss, object replacement or ciphertext change closes admission/signaling. Only the exact signed-in recipient may join; both peers must consent. The server supplies trusted expected ciphertext filename, size and SHA-256 in `joined`, and the built-in sender and receiver reject mismatched file offers and prohibit text in bound rooms. The user still selects a **local ciphertext file** explicitly; the server never sends file contents over its signaling connection. Local-only ciphertext hashing is intentionally bounded and fail-closed for cloud-backed objects, aliases and symlinks.

This is a **legacy server-authoritative ACL** integration, **not an independent owner-signed Zero-Knowledge grant**, ZK device identity, or proof that source ciphertext was correctly encrypted. The original manually selected file rooms remain a separate behavior. A modified WebRTC client can transmit arbitrary DataChannel frames after a connection opens; broker revocation closes cooperating browsers but cannot revoke bytes already transferred or enforce every peer-to-peer packet. Production requires independently signed object/version/recipient authorization, security review, cross-device identity/NAT/TURN gates and a unified policy for legacy/manual transfers.

For the bound mode, both `encrypted-files` and `file-permissions` must contain explicit current records for the exact folder/filename. The file ACL must be private (`public: false`), owned by the room creator, and explicitly grant read access to the recipient. Missing/failed permission storage and default-public legacy fallback are denied.

To prevent one authenticated account from exhausting the shared signaling capacity by creating rooms without joining, an owner may reserve at most **two** concurrent active rooms across its sessions. Unjoined rooms expire after **15 seconds**, reclaimable immediately on the next room-creation request; a successfully joined host keeps the existing **five-minute** room TTL. The global maximum remains **16** rooms. These limits apply to Root.ark signed-session rooms; the standalone anonymous loopback demo keeps its legacy global-only limit.

`node --test test/issue-242-app-session.test.js test/issue-242-bound-object.test.js` starts disposable instances of **actual Root.ark `server.js`**, signs in through `/auth/login` and exercises sessions, CSRF, recipient isolation, ACL restrictions, ciphertext digests, object replacement and live revocation. `npm run test:app-browser` exercises manual 1:N and bound ciphertext rooms using real Edge and consenting WebRTC peers. CI runs these gates on Ubuntu Node 22 and Windows Node 22/Edge.

**Security boundary:** unbound rooms are session-scoped manual browser-to-browser sharing: `listFiles` only gates the feature and sender-advertised SHA-256 does not establish stored-object identity. The explicitly bound mode additionally checks the **server-authoritative legacy encrypted-file ACL** and stored local ciphertext SHA-256/size. It does **not** verify an independent owner signature, device identity, file CEK or Zero-Knowledge decryption grant. No stored file is downloaded automatically. No TURN, NAT fallback, real-world cross-network assurance, streaming-to-disk, resume, production credential delegation or cutover. The feature flag is ignored in production.

## 2026-11-07 critical bound signaling NO-GO (supersedes earlier success descriptions)

The earlier text describes what the owner/recipient ACL checks and client-side
DataChannel validation could do; it is NOT proof of current safe bound signaling.
Sequential asynchronous authorizeObject checks can leak SDP/ICE: a revoked
guest can lose access while the final owner hash awaits, or a revoked owner
while a later guest's hash awaits. The room action queue does not serialize
HTTP ACL mutations. Reordering those awaits cannot repair this TOCTOU.

A bound signal now requires a trusted, **synchronous all-party ACL snapshot**
via the makeBroker authorizeSignalSnapshot callback. The contract covers owner,
all currently joined guests, exact object metadata fingerprint, digest, size,
and a monotonic shared authority revision. The callback must read a single
consistent authority view protected against **all** in-process and external
ACL writers; per-user hashes, independently mutable JSON/SQLite reads,
cached grants and a made-up revision do not qualify. The broker verifies the
snapshot shape and match, then sends immediately without another await.
Absent, asynchronous, malformed or denied snapshots close the room before
any bound SDP/ICE signal. Only the trusted adapter can guarantee the
consistency contract: shape checks alone cannot prove atomicity.

The existing Root.ark server application reads independently mutable legacy
ACL metadata and **does not** implement a shared snapshot transaction or
writer lock. It deliberately supplies no such callback. Therefore its current
DEV/TEST ACL-bound rooms can be created and invited, but bound SDP/ICE is
**fail-closed**: no bound DataChannel transfer is authorized. The separate
loopback unit fixture demonstrates functioning 1:1 and 1:N with a coherent
in-memory test authority only; that test does not enable the real app.
Manual, unbound single-peer and 1:N signed-session rooms continue to work.
The actual app/Edge tests now prove manual transfers and bound admission/
denial, not a functioning bound transfer. Before enabling bound signaling,
review a real transactional multi-user ACL revision/fence shared with every
mutation path (including cross-process writers), plus independently signed
object/version/device grants and external TURN acceptance.

## Security and scope

- Server binds to `127.0.0.1`, accepts matching WebSocket origin only, caps each room at 4 members, each message at 16 KiB, 120 messages per 10 seconds, and 16 rooms. An invitation is a random 256-bit one-use token with 60-second TTL, not a human PIN. Rooms expire after 5 minutes, and host disconnect closes a room. Invite revocation invalidates an **unredeemed** token; already-joined guests need an explicit kick.
- Only the host may ask a guest to establish WebRTC; guest approval is required before SDP/ICE signaling is relayed. The file receiver separately approves each file. There are no public ICE servers (`iceServers: []`), TURN credentials or protected files. Signed session checks run only with an explicitly provided trusted callback.
- Each file is capped at 32 MiB. The sender reads 8 KiB slices after its initial browser SHA-256 pass and keeps no entire-file output buffer; queued DataChannel bytes have a 256 KiB high-water and 64 KiB low-water mark. **A receiver stuck above the high-water mark for 30 seconds is canceled independently**, and buffered/close/abort listeners and timeout are removed on settle; an accepting sibling remains independent. Cancellation still discards partial receiver data. Every binary frame carries a 128-bit transfer ID and absolute offset. Receiver validates the exact next offset, 8 KiB chunk length (or final remainder), byte count and maximum 4,096 chunks; malformed/replayed/foreign frames abort and discard partial data. This is ordered/reliable WebRTC only, with no resumability. Each receiver holds up to 32 MiB of accepted chunks (plus Blob/digest temporary copies) and **one previously verified downloadable Blob**; replacing a verified file or ending a peer session revokes the previous download URL. Sender cancel, receiver cancel, channel close, room/session revocation and a missing final acknowledgment release transfer state. Diagnostics retain at most 100 entries per category; visible logs retain 100 lines of at most 150 characters. **No streaming to disk, resume, files larger than available browser RAM, Android, NAT traversal, TURN, end-to-end app identity verification, authenticated key exchange or ZK file key proof**. The advertised SHA-256 verifies transport integrity against the sender's own digest, not the sender's independent identity. DTLS transport security is not equivalent to Root.ark ZK.
- `npm test` verifies original signaling, Root.ark signed-session security, binary frame bounds/replay rejection and deterministic 1:N buffer-stall/abort/independent healthy sibling plus corruption handling. The stall test uses a disposable synthetic DataChannel clock, **not** a real TURN relay or cross-NAT proof. `npm run test:browser` exercises actual 1:N Edge DataChannels, a signed 2-recipient transfer of 3 MiB with downloadable verified bytes, explicit per-recipient cancel during active 8 MiB read, malicious cross-transfer binary frames, disconnect/revocation and bounded logs. The browser test uses one ephemeral Edge process and two sequential loopback brokers, cleaning up disposable profiles and sockets afterward.

Do not deploy or merge as a product feature. The opt-in app integration changes only session-gated routing, the temporary room signaling adapter, navigation and targeted CI. It leaves Root.ark file storage, object encryption, user schema and root application dependencies unchanged.
