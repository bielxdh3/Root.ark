# Root.ark Web-First Trusted Recovery and Offline Transfer Boundary — Design Specification

**Status:** `DRAFT_FOR_OWNER_AND_INDEPENDENT_SECURITY_REVIEW`; documentation only. **Not** implementation, migration, merge, or deployment approval.

**Date:** 2026-10-19

**Repository:** `bielxdh3/Root.ark`

**Local reference head inspected:** `dd4e8a2d04152470e86352af20a300952b5a97a5` on `cdx/rootark-dual-recovery-20261019`

**Related:** issue #65 (Zero-Knowledge and dual recovery); issue #64 (future Android); issues #66 and #68 (sync and recipient links).
**Foundational crypto:** `7dd1c861d2b570d7bc51ce66e8054bcc431f4c07` (F-01/F-02 independently accepted for the bounded Node-library scope; no runtime integration approval).

## 1. Product decision and interpretation

The owner clarified on 2026-10-19 that **Root.ark is primarily a temporary file-transfer destination, not a permanent file vault**. The approved first-party user interface is **the web**; a native **Android** client remains wanted because it simplifies transfers. **No new native Windows or Linux desktop application** is wanted. This is a product-direction decision, not permission to delete an existing CLI or rewrite existing customer data.

The owner expressly approved the following offline boundary:

> Files already downloaded may be accessed offline; **new authorizations, account/content recovery, and transfers require an online connection**.

Browsers may be registered as **trusted devices** for Zero-Knowledge recovery **only if the specific browser/platform/key-custody configuration passes an independently verified security eligibility gate**. Ineligible browsers may use permitted online transfer features but **must not silently become trusted recovery devices**. The future Android app may implement a separately verified Android Keystore-backed trusted-device profile. No native Windows/Linux desktop app is in scope.

The existing, owner-approved independent recovery mechanisms remain:
1. A user-held, password-protected emergency recovery package.
2. A previously authorized trusted device.

No administrator universal decryption key, default human delegate, password-reset-as-content-recovery, silent downgrade, or third recovery path is introduced.

**Clarification:** the new rule concerns protected-file availability and new security-sensitive actions, not a retroactive claim that exported plaintext can be revoked, and not an automatic change to existing D-008 trash/backup retention.

## 2. Scope, architectural split, and gates

This document is the **first** of three separately reviewable architecture packets:

| Packet | Scope | This document's authority |
|---|---|---|
| A — **web trusted-device eligibility and offline boundary** | Web key custody, trusted browser enrollment, recovery UX contracts, online-only sensitive operations, offline downloaded-file semantics | **Specified here; no product code authorized** |
| B — **shared state, status authority, and witness** | Linearizable shared CAS, irreversible terminal status, independent signing/ledger, pending admission gate, authoritative freshness, backup/restore | **Dependent on later independently approved specification; no provider selected** |
| C — **temporary protected transfers and Android interoperability** | End-to-end encrypted upload/download, finite TTL, authorized recipient capabilities, content-key delivery, Android protocol compatibility | **Separate approval; this document states interface constraints only** |

Keep the already-reviewed library modules isolated. The spec may define interface requirements but does not add routes, storage schemas, provider adapters, browser code, Android code, migration, or production configuration.

**Non-goals:** automatic bidirectional offline sync, Windows/Linux native clients or mounts, a WebDAV local bridge, public-link policy resolution (#68), unreviewed KDF cost changes, guaranteed deletion of recipient downloads, choosing PostgreSQL/Cloudflare/SQLite as a live authority, or issuing a claim of current end-to-end Zero-Knowledge compliance.

## 3. Evidence-based inventory and reconciliation

The following observations come from the inspected local worktree, not a production deployment claim:

| Existing surface | Verified behavior | Design consequence |
|---|---|---|
| `db/index.js` | `better-sqlite3`, local `data/rootark.sqlite` and `DB_ENABLED=false` default | **Not** evidence of shared CAS or deployed production topology |
| `src/routes/sync.js` | `SyncObjectStore` uses JSON, process-local Promise queue, and local durability | Not a cross-process, cross-host, restorable linearizable recovery authority |
| `public/client/rootark-client-crypto.js` | Web Crypto AES-GCM helper, caller-supplied raw key | Not a recovery key-vault or reviewed browser HPKE/Argon2id implementation |
| `public/client/rootark-protected-store.js` | IndexedDB ciphertext under caller-provided key | No proved key non-extractability, hardware protection, or rollback-resistant high-water |
| `public/client/rootark-protected-session.js` | Receives a key-provider callback and has enqueue/sync hooks | Cannot be treated as an existing trusted-device implementation |
| `public/service-worker.js` | Caches public shell/code assets; blocks caching selected API routes | Review stale-client-code and origin-integrity risks before delivering sensitive web recovery |
| `public/client/rootark-offline-queue.js` | Existing encrypted-envelope queue in localStorage | A legacy capability, **not** permission for offline new ZK transfers; reconcile separately |
| `sync-client/rootark-sync-v2.js` | Node sync client loads file/device keys from environment | Existing legacy/CLI code is not the approved future Windows/Linux desktop-client direction |
| `android/` and `android/README.md` | A Kotlin/Gradle scaffold exists without verified secure key custody, network, or usable UI | Do not assert that Android is absent, finished, or authorized to ship |
| `docs/product-discovery.md` D-006 | Previously required authorized offline device access | Reconcile with **offline access only to already-downloaded files**; no new remote authorization while disconnected |
| `docs/product-discovery.md` D-008 | 30-day trash/backup retention, distinct audit-log retention | **Does not set** transfer expiry; retain historical deletion/backup rules pending explicit reconciliation |

The existing `docs/architecture/zero-knowledge-migration-contract.md` and `docs/superpowers/specs/2026-10-19-rootark-dual-recovery-design.md` remain authoritative for the reviewed crypto protocol where not explicitly superseded by the owner's newer product decision. This document **does not rewrite those existing records**. Their offline-cache/sync/WebDAV and Android assumptions must be reconciled in explicit follow-up changes rather than silently overridden.

## 4. Trust boundaries and threat model

**Client assets:** per-file content keys (CEKs), compartment epoch keys, X25519/HPKE and Ed25519 device credentials, package secret and private key, plaintext while viewed, browser key-unlock material, local high-water state, and consent evidence. **Server-visible assets:** opaque ciphertext, exact authenticated public manifests, IDs, expiry/admission metadata, witness/status receipts, and minimal routing metadata. No server/admin access to content keys or plaintext is authorized.

Attackers and relevant failures include:
- Malicious or restored-back server state; withheld/reordered/replayed/forked authorization history and independent-witness outages.
- XSS, injected dependencies, malicious/untrusted service-worker updates, hostile extensions, compromised browser profiles or operating systems, and a compromised first-party web delivery path.
- Stolen or synchronized WebAuthn credentials, browser-profile copy/restore, cross-tab operations, private-browsing or browser-storage deletion, device loss, and stolen exported packages.
- Unauthorized future-epoch access after revocation; offline recipient-held plaintext that cannot be retracted; expired transfer links/retention races.
- Clock rollback/skew, server/CAS/witness crash or restore, idempotency conflicts, independent witness/operator collusion, and denial of service.

**Honesty boundary:** no web feature can guarantee confidentiality when the JavaScript origin, execution environment, extension, or endpoint is compromised. WebAuthn authentication and a `CryptoKey.extractable=false` flag **do not independently prove** hardware-backed storage, non-clonability, device binding, or rollback resistance. No supported browser profile is declared eligible by this specification alone.

The independent witness prevents a malicious server from silently presenting an older trusted head **only after** its trust anchor, signing protocol, monotonic ledger, and the client's fresh online verification have been validated. An old signed receipt alone is not freshness.

## 5. Browser capability tiers and exact rules

Treat each device enrollment attempt as a **capability evaluation**, not as a browser-name allowlist. A browser can use a lower tier without inventing a weaker trusted-device profile.

| Tier | Allowed | Prohibited |
|---|---|---|
| **Transfer-only web session** | Authenticated online upload/download according to later approved ZK content protocol; explicit local user export | Persisted recovery authority or trusted-device enrollment; offline upload/replay/recovery; server-blind claim without actual client crypto |
| **Ephemeral recovery-import session** | On a separately validated browser crypto runtime, decrypt the user's supplied emergency package transiently and verify current online signed/witnessed state before an allowed recovery operation | Claiming persistent trusted-device status without passing its gate; caching passwords, private keys, opened state, or package plaintext; using an unapproved KDF downgrade |
| **Eligible trusted browser device** | With separately evidenced protected key custody, enrollment and scoped recovery authorization via the reviewed dual-recovery protocol after fresh online state verification | Treating feature detection, WebAuthn login alone, synced passkeys, IndexedDB, software-only keys, or an unverified monotonic counter as proof of device-bounded security |
| **Android (future)** | Planned interoperable native trusted-device role after Android KeyStore/device testing and separate approval | Reusing assumptions from browser IndexedDB; bypassing Android issue #64 review and physical-device checks |

**Eligibility gate before a trusted browser can be enrolled:**

1. Validated secure origin and controlled JS delivery: origin isolation and anti-XSS controls, strict CSP/Trusted Types where compatible, build-integrity review, safe service-worker update/caching strategy, and tested revocation of compromised deployments. No third-party script can gain recovery secrets.
2. A supported, reviewed mechanism for **user-mediated local unlock and confidentiality/integrity of the persisted device private keys**. WebAuthn PRF plus encrypted private-key wrapping is a *candidate to evaluate*, not an approved universal solution. Verify feature presence, actual PRF results/semantics, relying-party/origin/credential binding, platform-specific copy/sync behavior, lifecycle, and application security. Check that required X25519/Ed25519 private operations and key formats are possible without an unsupported export or persistence shortcut.
3. Explicit distinction among authentication, local key unsealing, Ed25519 authorization, and X25519 key possession. Bind challenge, compartment, device, operation ID, target public keys, expiry, and response to the prior signed authorization state. Reuse existing review-approved live proof-of-possession protocol; public transcript alone never proves target X25519 private-key possession.
4. An **independently trusted online freshness proof** for every state-dependent protected operation, not a local high-water counter assumed to be OS-backed. If a separately validated monotonic protected high-water store is not available, online witness is mandatory; do not assert offline trusted-device authority.
5. Documented cleanup, logout, revocation, profile restoration, key invalidation, credential syncing, security-key loss, browser upgrade, and recovery of failed/incomplete enrollment. Any unsupported condition blocks enrollment, never silently downgrades to raw private-key persistence.

The eventual browser eligibility matrix must enumerate **exact browser/version/OS/credential configuration**, test date and environment, feature behavior, storage/export/copy guarantees that can *actually* be verified, and the independent security reviewer. Unsupported/unknown combinations: **transfer-only**, with emergency-package import only when its own ephemeral cryptography is independently validated. Do not list a browser as eligible merely because a feature API exists.

## 6. Online and offline behavior

| User action/state | Online | Offline |
|---|---|---|
| Read an ordinary **already downloaded/exported** file from the user's own device | Available independently of Root.ark, according to local OS/app controls | **Allowed**. The file is the user's copy and outside server revocation/control |
| View the already loaded, locally held plaintext in the current browser session | Only while authorized in-session; no claimed infinite lease | May remain visible only as already-held bytes; do not turn this into offline unlock, reauthentication, or new sensitive operations |
| Download or transfer a new file / resume a transfer | Requires a new authenticated and witnessed authorization and valid scoped receipt | **Blocked**; do not silently queue a new protected transfer |
| Create, enroll, revoke, rotate, or replace a trusted device/package | Requires server + CAS-status + independent witness online checks, per operation | **Blocked** even if the client remembers prior keys |
| Import/recover through emergency package | Requires online witness, validated authenticated history, current active recovery authority, user confirmation, and a supported client crypto runtime | **Blocked**; local package bytes alone do not authorize online-state changes |
| Browse remotely managed protected file indexes, issue recipient capabilities, restore, or approve/delete content | Must use fresh authorization according to separately reviewed admission contract | **Blocked** unless a future explicit offline policy is separately owner-approved |
| Service worker/offline shell | Public static shell may remain cached if compatible with security controls | May display non-sensitive offline guidance only; no claim of fresh auth or privileged background execution |
| Previously queued **legacy** operations | Existing behavior remains inventoried, not implicitly approved for new protected transfers | **No new ZK workflow** may inherit an offline queue automatically |

**No automatic local file vault:** in the web v1 target, do not introduce an app-managed persistent decrypted-content cache, offline unlock, or indefinite access to encrypted content based solely on IndexedDB. Explicit user download/export is separate and permissible; advise that copied files and recipients may retain plaintext outside Root.ark. The user may choose local storage through the browser's normal download mechanism.

**Online authoritative rule:** `navigator.onLine` and UI connectivity indicators are hints only. Server-mediated actions must fail closed on missing, stale, partial, unsigned, wrong-scope, or unverified witness/CAS terminal information. Offline actions cannot be queued as pre-approved future authorization. A draft ciphertext generated while offline, if ever supported, must be explicitly reassessed online before any upload; that feature is *not* approved by this spec.

## 7. Recovery and enrollment user journeys (normative security UX, not screen design)

**A. First-time setup (supported web profile):** create scoped client secrets; demonstrate both independent recovery methods; create emergency package with the fixed reviewed KDF; write/download its **exact ciphertext bytes**, require explicit user read-back and successful local reopening of the same file and export-retention confirmation before signing package activation. Activation and user-device enrollment use fresh online trusted-state checks. Do not claim the export-retention confirmation proves the user will keep the file.

**B. Existing trusted browser approves new browser/Android (when supported):** original device authenticates and unseals its own keys, obtains a fresh signed + witnessed head, approves an explicit target and compartment, verifies live target HPKE + Ed25519 possession through the approved challenge exchange, performs one authorized CAS transition, reconciles the exact terminal result, and waits for a fresh witness receipt. An unsupported target is not enrolled.

**C. Emergency package with no trusted device:** on a validated web crypto runtime, read the user's selected package, parse/cost-bound before Argon2id worker, decrypt locally, check exact activation/envelope binding and authenticated intervening history, derive future epochs from verified package HPKE wraps (F-01), verify active package authority and **fresh independently witnessed head**, then authorize the target only when it passes its device eligibility and online enrollment requirements. The service never receives the password, package plaintext, private key, or epoch keys.

**D. Lost/compromised browser or package:** revocation is online only. Package compromise requires replacement and an atomic forward key rotation under the previously reviewed `compromise-package` transition, performed by a remaining active device; never invent last-device fallback. Future files use new keys; already exported plaintext/ciphertext cannot be revoked.

**E. Unsupported, private, or restored browser:** clearly explain that trusted-device recovery/enrollment is unavailable here. Basic permitted online transfers may still work under a separately approved web content-encryption protocol. Do not convert a weaker browser into a registered trusted device by silently storing raw keys.

Every journey must distinguish login identity, content-key authorization, local secret availability, user consent, and freshness proof. Show accurate states: pending, committed and witnessed, terminal no-commit, rejected, unverifiable/blocked. An ambiguous CAS outcome must not be displayed as successful.

Detailed copy, accessibility, UI layout, step-up/2FA coupling, cross-origin link handling, and consent/retention screens require a separate UI-UX review; this document defines their security meaning only.

## 8. Provider interfaces required for later integration (not provider choice)

The next architecture packet must define a provider-neutral shared state and external witness protocol, including:

- **Shared CAS record per (account, compartment, keyring):** revision, digest, signed authorized transition, serialized history, current active package/device metadata, pending reservation and admission state, idempotent request identity, and durable irreversible status. No process-local queues or single-host JSON/SQLite substitute.
- **Truthful CAS terminal-status authority:** independently authenticated/pinned, linearizable answer for a specific reservation, exact signed request digest, revision and resulting digest; disallow forged or ambiguous no-commit and prevent old restored heads from admitting protected reads.
- **Independently operated witness:** separately pinned signing key, durable monotonic sequence/head, signed snapshot base receipt distinct from fresh head receipt, capacity/ledger policy, restart and backup/restore consistency, anti-equivocation and operator-collusion analysis.
- **Admission gate:** durable pending reservation blocks new state-dependent protected reads/writes before CAS; only exact trusted terminal proof and fresh witness resolves. Prevent an old committed head or stale browser/tab from opening a transfer while revocation is pending.
- **History and operation constraints:** preserve the reviewed 4096-transition/64-MiB prototype cap (and per-entry limits) with fail-closed exhaustion; 300-second nominal operation TTL and no more than 330 seconds effective under monitored 30-second skew; no post-expiry admission.
- **Client contract:** `verifyRecoveryHistoryPublicV2` validates public signed history only; `verifyTrustedDeviceRecoveryHistoryV2` is the secret-bearing authorized-device history; `verifyRecoveryPackageHistoryV2` uses base-snapshot keys + package HPKE wraps. `freshnessProven=false` from the library must never be relabeled true without separately verified current witnessed head; `packageEnvelopeBound=false` never establishes package activation.

Candidate PostgreSQL transactions and other systems are **options only**, not selected or approved providers. Backend correctness, independent trust anchors, multi-replica crash/restore tests, deployment topology, and retention-life-cycle safety remain hard gates. A witness or status oracle hosted under the same uncontrolled trust and rollback domain as the application is not automatically independent.

## 9. Temporary-transfer and data-lifecycle constraints for the later packet

- A protected transfer must have an **explicit finite expiry** and scoped rights, distinct from account lifetime and emergency-package validity. No permanent-default encrypted-object retention in the new transfer workflow. **Owner has not chosen the default/minimum/maximum transfer lifetime**; do not pick one in implementation.
- Existing D-008 defaults for trash, deletion, backups, and logs are **separate historical decisions**. Do not silently reinterpret their 30-day retention as transfer TTL, or silently override those controls. Document and approve interactions between transfer expiry, orphan blobs, backups, audit, link expiry, queued work, and physical/cryptographic deletion.
- Downloaded, exported or recipient-retained files cannot be recalled. File-level expiry prevents *future service-mediated access*; it is not proof of deletion of every ciphertext backup or user copy.
- Protected objects must use the reviewed client-generated CEK/per-compartment hierarchy and authenticated metadata. Do not carry plaintext names or full source paths from the current sync v2 wire contract into a server-blind transfer without a protocol review.
- A transfer-only deployment must preserve file-integrity/partial-chunk/resume semantics and not bypass upload scanning/quarantine or trust boundaries. Server-side content scanning of end-to-end encrypted plaintext is unavailable; choose a separately approved client-side/quarantine UX.
- Existing link capabilities (#68) and account-owned downloads have different authorization models. Do not assume the recovery package is a public recipient's link key or a substitute for least-privilege scoped recipient access.

## 10. Acceptance and adversarial test matrix for a future implementation plan

| Test family | Required evidence and explicit failures |
|---|---|
| Browser tier/capability matrix | Precise browser/OS/version, WebAuthn PRF behavior, user verification, credential sync/copy, origin binding, CryptoKey lifecycle, reboots, private mode, platform gaps; unknown result blocks trusted enrollment |
| Cross-platform crypto | Independently sourced deterministic CBOR/HPKE/Ed25519/AES-GCM/Argon2id vectors; Node 22 ↔ browser byte-for-byte protocol tests; 256-MiB KDF worker performance/RSS and allocation failure on minimum supported web hardware, no weaker fallback |
| Web origin/client supply chain | Injected script and extension threat disclosures, CSP/Trusted Types test, service-worker stale/replay and cache poisoning, load-after-update, cross-tab races, sensitive no-store routes, no leaking secrets to logs/network/storage |
| Two recovery paths | Web package import using only package and password; browser trusted-device approval without package key; wrong password/key/scope, old/revoked package, unusable target and absent/wrong freshness proof fail closed |
| Concurrent authorization | Two tabs + two devices, revoked browser restore, replay/expired challenge, ambiguous commit, forged/stale terminal status, witness outage, restored app DB, fork, equivocation and pending gate blocking file read/write admission |
| Offline behavior | Completed OS download remains accessible offline; no new ZK transfer/download/recovery/enrollment/rotation works offline; legacy queue never uploads a new protected operation without fresh re-authorization; `navigator.onLine` spoof cannot bypass server gate |
| Lifecycle/retention | Explicit expiry on protected transfers; expired link/download fails; backup/trash semantics remain separately recorded; no promise to destroy recipient-held copies; no silent extension or resurrection by restore |
| Accessibility/security UX | Clear warning when browser cannot be trusted; mandatory emergency-package export confirmation; explicit user-authorized target; pending/failed/success statuses match durable witnessed events |
| Compatibility/regression | Existing legacy transfers, existing Node CLI, Android scaffold and historical D-008 retention unchanged until separately approved migration; full test/release gates must be complete and green for exact code SHA |

Test fixtures and mock-only CAS/witness state models **cannot** substitute for a real shared provider, independently pinned monotonic witness, browser custody assurance, or end-to-end content recovery. A browser test that passes on a developer machine is not a blanket browser support declaration.

## 11. Ordered gates and implementation exclusions

1. **This design first:** owner and independent security review of the web-first/offline/capability decisions and evidence boundaries. This draft is not self-approved. Reconcile D-002/D-006/D-008/D-009 and Android/client records after the owner accepts the exact updated policy. If any material ambiguity remains, stop.
2. **Web eligibility technical spike:** read-only browser/feature feasibility and disposable test-only crypto prototypes, after a separate approved spike question. No persistence of real user keys or claims of universal WebAuthn PRF support.
3. **Separate shared CAS/status/witness design:** propose provider alternatives, a credible independent failure domain, protected-content admission, terminal proofs and rollback-safe lifecycle; receive owner and security approval before backend code.
4. **Separate protected transfer lifecycle/protocol specification:** decide finite TTL defaults, links/recipient scope, backup interaction, encrypted metadata and migration from legacy; get explicit owner review.
5. **Implementation plans only for approved individual packets:** PONYTAIL and applicable Superpowers workflow, precise files/interfaces, test-first phases, independent review, evidence at exact SHAs. UI-UX-PRO-MAX must review actual future UI and usability work. No sneaking unapproved server or browser implementation into a documentation phase.
6. **Integration/release:** cross-process real storage/witness tests, real browser security profiles, end-to-end ciphertext-only upload/decrypt/restore, Android interoperability when available, completed exact-SHA CI/security checks, separate merge/deploy owner authorization. Keep issue #65 open until its full acceptance conditions are truly met.

**Explicit prohibitions for this draft phase:** No product source edits; no dependency changes or installs; no production inspection, provider provisioning, schema migration, service-worker changes, browser-client changes, release or PR; no push/merge/deploy; no issue #65 closure; no local work outside the authorized repository/worktree and approved E: test paths.

## 12. Open owner choices (not invented by this spec)

- **Finite transfer duration:** choose default, allowed limits, whether successful download triggers early expiry, and link versus account-owned transfer semantics. New temporary-transfer flow may not ship without it.
- **Browser trusted-device eligibility:** choose minimum supported browsers/OS and whether a validated user-mediated key-wrapping model adequately fulfills the intended assurance level after capability and security proofs. Until then, eligibility is **not established**.
- **Retention and offline legacy reconciliation:** decide whether to retire or migrate existing offline queues/managed cached views and how that affects previously approved D-006/D-009 offline/sync features, without deleting current behavior unilaterally.
- **Infrastructure trust:** independently operated witness/status authority, backup/restore and operator-control model, persistence provider, and history exhaustion lifecycle need their own owner decision.

This draft intentionally contains **no implementation plan or approval to implement**. Its acceptance proves agreement on product direction and testable requirements only.
