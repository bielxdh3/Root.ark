# Issue #242 — browser P2P rooms research (source-pinned)

**Decision status: RESEARCH ONLY — no integration, copy, production PoC, merge or deployment.** The owner requested a practical reuse assessment of PrivyDrop, PairDrop and Magic Wormhole alongside Root.ark Zero-Knowledge v1. This report records upstream source and licensing as of 2026-11-06, **not** proof of upstream runtime behavior or a completed issue #242 acceptance gate.

## Exact upstream inputs

| Upstream source | Verified immutable HEAD | Repository license | Practical takeaway |
| --- | --- | --- | --- |
| [PrivyDrop](https://github.com/david-bai00/PrivyDrop) | [`add211dd2a3e893458e0249d98fe6f6ef0165ec0`](https://github.com/david-bai00/PrivyDrop/tree/add211dd2a3e893458e0249d98fe6f6ef0165ec0) | MIT | Closest technical reference for browser rooms, 1:N, file/text transfer and resume; its complete Next.js + Socket.IO + Redis stack need not be imported |
| [PairDrop](https://github.com/schlagmichdoch/PairDrop) | [`1b0c9c9d903c3cfc706df1303dc75c3b54d04c77`](https://github.com/schlagmichdoch/PairDrop/tree/1b0c9c9d903c3cfc706df1303dc75c3b54d04c77) | GPL-3.0 | Good UX reference for five-letter temporary rooms, six-digit persistent pairing, discovery, QR and consent, **not** a copy/paste source for Apache-2.0 Root.ark without licensing/legal resolution |
| [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) | [`c480f84cefac49c7675a87f4b9d60278ccec0b56`](https://github.com/magic-wormhole/magic-wormhole/tree/c480f84cefac49c7675a87f4b9d60278ccec0b56) | MIT | Reusable design ideas for single-use human codes and authenticated rendezvous, but the upstream is a Python client/CLI with distinct mailbox + transit-relay services, not a browser WebRTC room implementation |

Repo licenses were checked from the GitHub repository's SPDX metadata; final reuse requires reading the pinned `LICENSE` and every copied component's transitive/asset licenses and preserving required notices. No upstream files or third-party assets were copied into Root.ark.

## Source modules worth inspecting in a disposable PoC

- **PrivyDrop**: [`backend/src/services/roomCore.ts`](https://github.com/david-bai00/PrivyDrop/blob/add211dd2a3e893458e0249d98fe6f6ef0165ec0/backend/src/services/roomCore.ts), [`backend/src/socket/handlersCore.ts`](https://github.com/david-bai00/PrivyDrop/blob/add211dd2a3e893458e0249d98fe6f6ef0165ec0/backend/src/socket/handlersCore.ts), [`frontend/lib/fileSender.ts`](https://github.com/david-bai00/PrivyDrop/blob/add211dd2a3e893458e0249d98fe6f6ef0165ec0/frontend/lib/fileSender.ts), [`fileReceiver.ts`](https://github.com/david-bai00/PrivyDrop/blob/add211dd2a3e893458e0249d98fe6f6ef0165ec0/frontend/lib/fileReceiver.ts), and [`useWebRTCConnection.ts`](https://github.com/david-bai00/PrivyDrop/blob/add211dd2a3e893458e0249d98fe6f6ef0165ec0/frontend/hooks/useWebRTCConnection.ts). Upstream README advertises multiparticipant rooms and resumable browser transfers; refresh and browser direct-to-disk requirements are explicitly described, **not independently benchmarked here**.
- **PairDrop**: [`server/ws-server.js`](https://github.com/schlagmichdoch/PairDrop/blob/1b0c9c9d903c3cfc706df1303dc75c3b54d04c77/server/ws-server.js), [`server/peer.js`](https://github.com/schlagmichdoch/PairDrop/blob/1b0c9c9d903c3dc75c3b54d04c77/server/peer.js), [`public/scripts/network.js`](https://github.com/schlagmichdoch/PairDrop/blob/1b0c9c9d903c3dc75c3b54d04c77/public/scripts/network.js), and [`persistent-storage.js`](https://github.com/schlagmichdoch/PairDrop/blob/1b0c9c9d903c3dc75c3b54d04c77/public/scripts/persistent-storage.js). Use behavior as a **design reference** only pending licensing resolution; short room/pairing codes need explicit Root.ark grants, bounded attempts and revocation.
- **Magic Wormhole**: [`docs/file-transfer-protocol.rst`](https://github.com/magic-wormhole/magic-wormhole/blob/c480f84cefac49c7675a87f4b9d60278ccec0b56/docs/file-transfer-protocol.rst), [`src/wormhole/_mailbox.py`](https://github.com/magic-wormhole/magic-wormhole/blob/c480f84cefac49c7675a87f4b9d60278ccec0b56/src/wormhole/_mailbox.py) and [`src/wormhole/_dilation/connector.py`](https://github.com/magic-wormhole/magic-wormhole/blob/c480f84cefac49c7675a87f4b9d60278ccec0b56/src/wormhole/_dilation/connector.py) demonstrate a fundamentally different transit/rendezvous protocol; importing its Python stack into a browser transfer feature would add needless dependencies.

## Fit for Root.ark (smallest useful design)

**Recommendation for a PoC, not authorization for production:** isolated disposable UI + one owner-authorized temporary room service; browser `RTCPeerConnection`/DataChannel for peer transfer. Root.ark already declares `ws` and `express` runtime dependencies; start with those **rather than importing Next.js, Redis or Socket.IO**. A single-process, single-host PoC may keep only expiring room state in memory; no cross-host promise. TURN is optional and is a ciphered relay, **not** proof of direct P2P or Zero-Knowledge file keys.

Keep these separate:

1. **Root.ark authority:** authentication, invite authorization, room scope, participant roles, expiry, revocation and per-room resource grants. A room code/link alone must not grant storage ACLs or reuse the account's file-share capability.
2. **Peer authentication:** explicitly bind the invited device/recipient identity to its negotiated peer and consent, rather than treating WebRTC DTLS encryption as an independent proof of Root.ark account identity.
3. **File data:** transfer only consented browser-selected bytes; do not upload plaintext to Root.ark or make Root.ark hold universal file keys. A later ZK-1 file transfer must use its approved device/key-epoch boundary; no silent bridging of unrelated file keys.
4. **Resilience/privacy:** bounded file/chunk memory, hashes, cancellation, disconnected peers, optional direct-to-disk support, clear behavior when TURN/ICE fails, ICE IP exposure, no room tokens in logs/history and no persistent plaintext temp files.

## Required proof before #242 can be closed or code imported

| Check | Current evidence | PoC gate |
| --- | --- | --- |
| Room 1:1 and 1:N over real desktop/Android browsers | **NOT TESTED** | Send bytes/text, consent per recipient and identical SHA-256 upon receipt |
| Expired/revoked/guessed invites, wrong identity, repeated join and quota abuse | **NOT TESTED** | Negative requests and concurrent joins fail without storage access |
| Large file, resume after refresh/disconnect, cancellation and bounded memory | **NOT TESTED** | Check actual browser File System Access availability; report unsupported platforms honestly |
| Direct ICE and TURN fallback on different NATs, offline Redis/STUN/TURN | **NOT TESTED** | Demonstrate each separately with infrastructure explicitly provisioned for the disposable test |
| License/asset/dependency inventory and precise copied-source attribution | **PARTIAL (SPDX and upstream file paths only)** | Pin every imported file's license/NOTICE, direct and transitive dependencies, security review |
| Retained Root.ark auth/ACL, Zero-Knowledge and sharing invariants | **DESIGN ONLY** | Independent source review and integration gates on any future implementation PR |

**Current decision:** run a separate, minimal, owner-authorized PoC; borrow **concepts** from all three, preferentially inspect PrivyDrop's MIT browser transfer modules, do not copy PairDrop GPL code, and do not introduce a second server framework or Redis solely for this feature. This concludes the *comparative source-scouting slice only*. Issue #242 stays **OPEN** until the actual disposable PoC and permission/licensing acceptance are proven.

## Isolated browser PoC evidence (separate DRAFT PR, 2026-11-06)

The independently written experiment lives in `experiments/issue242-webrtc/`; it has **zero imports of source from PrivyDrop, PairDrop or Magic Wormhole**, and no imports, credentials, ACLs, file paths, authentication or storage from Root.ark. It runs a `ws` broker bound to `127.0.0.1` with in-memory room state. This is a local test of a possible transport, **not** a Root.ark integration or implementation of issue #242.

| Component | Upstream and pinned SHA | License | Recommendation | Verified in this PoC and limits |
| --- | --- | --- | --- | --- |
| Ephemeral rooms and owner invitations | PrivyDrop `roomCore.ts` at `add211dd` | MIT | **Reimplement** small scoped server grants; inspect before any copied code | Loopback broker: 5-minute room TTL, 60-second single-use 256-bit invites, max 4 members; no Root.ark account identity |
| Signaling and room membership | PrivyDrop `handlersCore.ts` at `add211dd` | MIT | **Reimplement** with existing `ws`; no Redis, Socket.IO or Next.js for the experiment | Same-host WebSocket passed consent/forbidden signaling tests; no multi-host scale proof |
| WebRTC DataChannel transfer | PrivyDrop `useWebRTCConnection.ts`, `fileSender.ts`, `fileReceiver.ts` at `add211dd` | MIT | **Adapt design**, with separate full license/transitive review if code later copied | Actual Edge headless: 1:1 and 1:2 DTLS DataChannels, per-peer consent, SHA-256 of text + 32 KiB fixture |
| Local discovery, short public room codes, QR | PairDrop `ws-server.js`, `peer.js`, `network.js` at `1b0c9c9` | GPL-3.0 | **Ideas only, reimplement if needed**; no GPL code copied | Not built or empirically compared; short code guessing is a separate threat |
| Persistent pairing and reconnection | PairDrop `persistent-storage.js` at `1b0c9c9` | GPL-3.0 | **Defer/reimplement independently** after device identity design | No persistent pairing, reconnect, QR or device ACL proof |
| Single-use human code, SPAKE2, mailbox, transit relay | Magic Wormhole `_mailbox.py`, `_dilation/connector.py`, protocol doc at `c480f84` | MIT | **Study concepts**; do not transplant Python/relay protocol into browser WebRTC | 256-bit random invites are NOT Wormhole PAKE or an authenticated Root.ark user binding |
| Browser UI, permissions, share links, Zero-Knowledge | Root.ark `ea0445df` baseline | Apache-2.0 | **Preserve untouched**; separate issue and authorization required before real integration | No Root.ark UI/auth/storage code changed; WebRTC DTLS alone proves no ZK file encryption |
| Resume, large files, disk streaming, NAT/TURN | PrivyDrop described at `add211dd`; PairDrop described at `1b0c9c9` | MIT / GPL-3.0 | **Defer** pending browser/platform benchmarks and legal constraints | In-memory fixture capped at 1 MiB; no resume, large-than-RAM, Android, cross-NAT, TURN or relay test |

**Reproducible validation:** from `experiments/issue242-webrtc`, run `npm ci --ignore-scripts`, then `npm test` and `npm run test:browser` on Windows 10 with Edge installed. The first test suite checks guessed, expired, revoked and replayed invitations; bounded room size/payload; wrong WebSocket Origin; unauthorized signaling; explicit refusal of peer consent; and idle-room expiration. Observed: **4/4 Node tests PASS**. The second starts a single disposable headless Edge instance and validates **1 host + 2 consenting guests** with two real open `RTCPeerConnection` DataChannels; two SHA-256-verified texts and two SHA-256-verified 32,768-byte in-memory file fixtures. Observed: **PASS**, checksum `09fed9cbfb98b6ab0f3e8ff63b7b1f9b0e07d58b225295c78fdc023cc4985a72`. No physical devices, real content or outside host were used.

**Residual gates / GO-NO-GO:** **GO** for the narrow feasibility claim that browser DataChannels and consented ephemeral 1:N rooms can be prototyped without changing Root.ark. **NO-GO** for production copying, user data, storage/ZK integration, security identity equivalence, persistent sessions, cross-platform, large-file streaming/resume, restricted NAT, TURN fallback, reliability and scale. A revoked *unused* invite cannot join; a participant who has already joined must be separately removed. The browser closes RTC peers upon broker disconnect/revocation; it is not independent proof of remote deletion or recall of already-received data. Actual upstream behavior, license contents of copied files, all transitive dependencies, and performance remain unverified.
