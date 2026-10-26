# Root.ark Plan Tree

## Issue #65 / PR #228: legacy V2 two-authority signed stage readback (DEV, 2026-10-25)

After the opt-in phase-1 legacy V2 dual-archive write quarantine (`a4b5ea6`),
operators can now request signed, challenge-bound READBACK from independently
pinned CAS and FLOOR mTLS authorities. Each checks its native immutable staged
SQLite marker and original V2 signed history; a distinct role Ed25519 signer
binds the owner consent hash, old #128 baseline, current legacy #129+ terminal,
and the distinct full 1..128 archive root/checkpoint. An operator-side bounded
verifier requires separate out-of-band owner/archive/V1/V2 public pins, actual
pinned V1/V2 HTTPS clients, complete 128-head signed history, two fresh V1
provider checks, both role signatures, an independently signed fresh owner
witness and double remote stage readback. Missing/partial stage, foreign owner,
tampered signature, changed roots or owner revision fail closed. Legacy history
verification is capped at 1,024 successor transitions in this DEV gate.

Windows Node24 targeted real synthetic TLS1.3 mTLS suites (V1 #128 and legacy
V2 #129/#130) **2 PASS / 0 FAIL**; four changed JS source/test files
`node --check` **PASS**, `git diff --check` **PASS**. This proves only
bounded read-only stage evidence: historical consent may be expired but the
128-archive handoff still needs a current authenticated owner signature.
The endpoint cannot restore ciphertext, issue new V2 writes, delete legacy
sources or assert a distributed migration. Independent monotonic physical
stage witness, durable two-host reconciliation, provider readback/restore
and signed dual-anchor successor envelopes remain **NO-GO** prerequisites.
Details: `docs/issue-65-v2-legacy-remote-dual-archive-readback-dev.md`.

## Issue #65 / PR #228: browser offline native source-root contract (2026-10-25)

After native two-chunk source-root verification became mandatory in
`rootark-zk1-persisted-portable-chunk-recovery`, the outer browser coordinator
still omitted `independentlyPinnedSourceChunkRoot`. The existing standalone
SQLite/owner-signature cryptography remained fail-closed, but all real offline
browser restore attempts were denied, including the opt-in Edge UI. The
development-only browser coordinator now requires and passes this distinct
**externally supplied** 32-byte native source-root pin, without defaulting to
the bundle's portable ciphertext root, signed inventory, fetched server data
or hashes calculated from locally supplied chunks. The opt-in lab form has a
separate manual input for that pinned native source root; the existing online
protected GET mode is unchanged.

Windows Node 24 TDD reproduced the integrated regression (4 FAIL/2 PASS);
real Edge and isolated SQLite after the fix verify owner Ed25519, all native
two-chunk hashes/root, the portable root, external pins and final liveness,
including explicit missing-root rejection without a download. Wrong native
pin and substituting the portable root remain fail-closed. This verifies only
the equality to the operator-supplied pin, **not its independent provenance**;
missing live remote witness/CAS and external storage durability remain
out-of-scope. PR #228 stays DRAFT / NO-GO.

## Issue #65 / PR #228: Windows release-gate Phase 16 authorization fixture (2026-10-25)

At hosted SHA `37efce2`, Windows Node 22 mandatory release gate job
`121238464999` failed only the Phase 16 final-corrections suite (27/28):
its historical `device authorization is exact, signed, expiry-bound, and
revocable` fixture still used an **external mutable JSON device registry** and
expected an HTTP `201`. The new protected Sync v2 atomic-ingress rule correctly
returned HTTP `503 SYNC_PROTECTED_ATOMIC_REQUIRED`. Production behavior is
unchanged; weakening this rejection would reinstate the revocation race.

The test now provisions its own protected Windows ACL/owner-only POSIX directory,
authoritative disposable SQLite user/session/permission record, and co-located
atomic registry with explicit Ed25519 device enrollment. It exercises real HTTP
creation (`201`), replay rejection (`409`), an **independently signed** proof
rejected after expiry (`403`), and an independently signed proof rejected after
durable device revocation (`403`). No legacy JSON trust is treated as an atomic
authority. Windows Node 22 targeted RED was `503 !== 201`, corrected targeted
GREEN **1/1**, full Phase 16 **28/28**; Windows Node 24 targeted **1/1**.
Hosted release-gate revalidation remains necessary; the PR stays DRAFT / NO-GO.

## Issue #65 / standalone histórico estrito com autoridade externa (2026-10-25)

`scripts/zk1-witness-standalone.js` permite agora injeção **somente em memória**
de autoridade histórica através de `serve(config, { historicalAuthority })`.
O comando legado `node scripts/zk1-witness-standalone.js --config arquivo.json`
**nunca** habilita emissão histórica e rejeita `cas-historical-admit` no JSON
**antes de abrir qualquer SQLite ou ler chaves**. Isso impede que um editor do
JSON atribua a si mesmo o papel histórico ou retire a exigência externa.

A *separate operator launcher*, hospedado com credenciais/permissions do
operador fora do diretório modificável pelo writer, constrói e injeta um
`Zk1WitnessCasPhysicalAdmission` real, instanciado com Ed25519 independentes
de owner/inventário/PG, cliente PG read-only mTLS, cliente de inventário e
snapshot mínimo autenticado. O objeto `historicalAuthority` **não é
serializável em JSON**: exige exatamente `physicalAdmission`, função síncrona
`trustedSyncDevicePolicyProvider` (estado vivo de revogações),
`trustedMinimumHead` (sequence/lastHash/physicalFenceDigest),
`trustedHistoricalAdmissionHead` (sequence/lastHash), pins `witnessPublicKey`
e `statusPublicKey`, e `principals` contendo apenas certificados mTLS com o
papel exclusivo `cas-historical-admit` e escopos explícitos. Os pins de
identidade devem corresponder às chaves efetivamente carregadas pelo
standalone, protegidas pelo verificador nativo de arquivos e ACL. O mínimo
físico externo deve corresponder ao mínimo owner-autenticado legado. O
emissor W2 reconsulta a política antes de emitir e antes do INSERT durável.

Exemplo de chamada **somente do launcher externo confiável** (não adicione o
módulo de autoridade, os pins ou paths secretos ao JSON editável):

```js
const { serve } = require("/operator/install/scripts/zk1-witness-standalone");
const { buildHistoricalAuthority, loadPublicRuntimeConfig } =
  require("/operator/private/owned-historical-bootstrap");
const historicalAuthority = buildHistoricalAuthority();
serve(loadPublicRuntimeConfig(), { historicalAuthority });
```

`buildHistoricalAuthority` e os paths `/operator/...` acima são **interfaces
exemplificativas não fornecidas neste repositório**: a emissão física segura
depende de provisionamento independente real pelo operador. O `serve` utiliza
o mesmo listener TLS1.3, tratamento de sinais e mensagens de erro genéricas
do CLI legado; nenhuma chave, pin ou caminho de segredo aparece nos logs.
Uma configuração sem injeção, um papel histórico adicionado no JSON, pins
incoerentes, falta de escopo, retirada do floor ou rollback do high-water
externo são rejeitados antes de abrir os bancos no modo estrito.

O laboratório opt-in `--historical-e2e-only` foi adaptado para chamar este
`configure` de standalone com autoridade externa enquanto executa
PostgreSQL18 real, assinatura PG em processo read-only separado, witness
SQLite e consumidor Sync v2 sobre mTLS. Isso não constitui implantação real
com custódia remota e não prova durabilidade externa/multi-host, atomicidade
PG×SQLite nem piso antirrollback atualizado após cada nova emissão. O PR #228
continua DRAFT/NO-GO produção.

## Issue #65 / PR #228: protected Sync v2 atomic revocation ingress gate (2026-10-25)

**Security follow-up (independent W15 P1/P2 review).** The legacy direct-store
gate now also checks the **current record and every retained historical
version** for any `authorization` field, including malformed values, inside
the transaction's freshly reloaded on-disk snapshot and **before** replay,
stale revision, create, update or delete handling. A historically signed
ciphertext can no longer be downgraded to an unsigned tombstone through an
otherwise permitted legacy route, even after process restart or when a peer
commits the signed version after HTTP request parsing. The route returns
`503 SYNC_PROTECTED_ATOMIC_REQUIRED` rather than an unhandled 500. Unsigned
legacy-only objects remain writable. This can only protect signed history
**still present in the legacy inventory**; a former signed version already
erased from all durable records before this patch requires independent
reconciliation and cannot be proven from absent evidence.

POSIX atomic registry storage validation now rejects **every foreign-owned
ancestor** (owner neither the current service UID nor trusted root), even if
its mode is `0755`: the foreign owner could still rename/chmod the parent
and replace the private registry tree. The real root-owned world-writable
sticky `/tmp` exception remains permitted, and a foreign-owned sticky
directory does not qualify. On Windows the shared chunk/registry ACL helper
executes the **absolute canonical system PowerShell path for create, verify
and SDDL**. A real malicious `powershell.exe` injected first in `PATH`
previously made an unsafe NTFS directory pass verification; the focused
adversarial test now verifies it is rejected and genuine secured roots
still pass. No ACLs or legacy data are silently modified.

The signed, encrypted Sync v2 object PUT/POST/DELETE ingress now **fails closed**
with `503 SYNC_PROTECTED_ATOMIC_REQUIRED` when the server does not use an
explicitly provisioned, co-located atomic device registry. This applies when
the route requires device authorization **or** the operation carries a signed
authorization, including on a route accidentally configured without mandatory
authorization. A direct `SyncObjectStore.put()` using a signed operation also
rejects that non-atomic mode. An *unsigned*, explicitly non-protected legacy
development route with `requireDeviceAuthorization: false` retains its
existing behavior. No legacy data or authority is silently upgraded.

The concrete pre-fix P1 was reproduced through a genuine HTTP PUT of a
correctly signed encrypted operation: the separate legacy
`SYNC_DEVICE_REGISTRY` authorized the device; it was then durably marked
revoked before `SyncObjectStore.put()`; the old route still replied HTTP 200
and persisted the ciphertext. Rechecking that separate registry at a different
point would only move the TOCTOU window, so it is **not** the fix. This ingress
gate makes that same test return HTTP 503 with no object committed, including
after restart. The existing explicit strict mode binds the currently enrolled
key, Ed25519 authorization and the ciphertext write under one process-external
lock/atomic JSON state transaction; the same lock fences device revocation.
In particular, a revocation that **durably commits first** must deny the PUT;
a PUT that commits first is not retroactively canceled by a later revocation
request or by a delay in sending its HTTP acknowledgement.

Enabling strict mode is an **operator-owned, separate migration gate**:
provision a new private service-owned storage directory with verified Windows
NTFS ACL or POSIX ownership/mode; use `SYNC_ATOMIC_DEVICE_REGISTRY=true`,
do not set `SYNC_DEVICE_REGISTRY` or supply a separate authorization callback,
and explicitly enroll authorized device keys using the trusted owner/admin
workflow. The code never infers device enrollment from legacy signatures,
never rewrites legacy object stores in place, and refuses an unmigrated store.
If strict startup fails (including unsafe ACL or missing registry), protected
writes return `503 SYNC_ATOMIC_REGISTRY_UNAVAILABLE`; there is no fallback to
legacy. Unmigrated existing stores remain untouched for explicit reconciliation.
Do **not** enable production or merge PR #228 until the authorized migration,
rollback/recovery procedure, external authority requirements and independent
security review are complete. PR #228 remains **DRAFT / NO-GO**.

## Issue #65 / PR #228: opt-in browser restore of signed persisted ciphertext chunks (2026-10-25)

The development-only `/zk1-protected-file-lab.html` now offers a separate,
explicit **local ciphertext-chunk recovery** option. Without that checkbox,
the existing signed protected HTTP GET path remains unchanged. With it, the
owner imports the portable encrypted bundle, separate ciphertext-root pin,
signed owner-root/history, signed persisted-chunk inventory and every opaque
chunk file from their **local device**. Owner Ed25519 raw key, independent
raw/SPKI SHA-256 fingerprints and current revision/digest/epoch come only from
the manually provided off-server inputs, never from a Root.ark endpoint or
the self-attesting archive. Missing trust material displays an explicit refusal
before ciphertext reads. A separately and explicitly provisioned IndexedDB
owner floor, active owner-signed device grant, signed history and root are
checked before accessing chunks. The `rootark-zk1-persisted-portable-chunk-recovery`
module authenticates all chunk hashes/lengths, reassembled ciphertext root,
and encrypted bundle before local HKDF/AES-GCM decryption; the browser rechecks
the floor after the last asynchronous decryption and before downloading.
A synchronous liveness callback returning a rejection value, rather than
throwing, is also denied at the final plaintext-release fence: an adversarial
late-revocation test failed before this fix and passed afterward.

The disposable local SQLite integration tests on Node 24/22 cover missing
pins, fork, wrong key, revocation, rollback/mismatched head and missing chunk
without using a legacy or production restore route. A real headless Edge
test verifies the **actual UI** refuses missing external pins, accepts correctly
signed local chunks, and denies a revised pinned head without a second file
download. Its test server does not expose a protected ciphertext GET endpoint.
The focused local matrix (including the existing portable recovery crypto
regressions) completed **17 PASS / 0 FAIL** each on Windows Node 24 and Node 22,
including the actual Edge scenario on each runtime. The unrelated full legacy
suite was not rerun in this isolated worktree, where optional dependencies
for that broader suite are not installed.
This does not verify pin *provenance*, defend against jointly rolled-back
off-server pins and browser IndexedDB, provide external witness/CAS freshness,
live server revocation, external provider durability or recovery of an entire
account. The experimental option cannot authorize production restore; PR #228
remains DRAFT / NO-GO.

## Issue #65 / PR #228: remote CAS witness-enrollment preflight (2026-10-25)

The opt-in standalone CAS status service now refuses an RFC1918/private-interface
listener unless `casAnchorWitness` is explicitly provisioned. As before,
the service obtains and verifies a fresh signed, nonce-bound witness high-water
head over pinned mutual TLS **before opening CAS SQLite or its terminal log**.
Missing, null, offline or misconfigured witness configuration fails closed;
loopback-only legacy/laboratory workflows remain unchanged. Adversarial
separate-process tests exercise an assigned private interface with IP-SAN
certificate, genuine HTTPS witness, missing witness (including a fresh CAS
genesis), witness outage and successful pinned restart, without rewriting
the existing CAS/FLOOR consensus protocols.

This is a startup/configuration fail-closed gate, **not** proof that the
witness lives on a different machine, has separately administered keys, uses
independently monotonic media, or is externally recoverable after coordinated
rollback. A same-host SQLite witness in a disposable test gives only a
local runtime invariant. No hosted two-administrator independent witness,
provider durability, cross-service atomicity or production GO is claimed.
PR #228 remains DRAFT / NO-GO.

## Issue #65 / PR #228: Windows hosted 2,000-chunk assembly latency (2026-10-25)

The hosted Windows Node 22 gate on `16dfd12` reported a socket timeout on
the **final** chunk of 2,000 while the server was still running. The final
request is uniquely responsible for joining 2,000 on-disk `.part` files.
Its prior implementation serialized 2,000 independent `fs.createReadStream`
open/read/close cycles, multiplying intermittent Windows filesystem/AV latency
into a single 30-second idle-socket boundary. This is the identified local
amplification mechanism; the exact hosted machine bottleneck remains unproven
without server-side stage traces from that run.

The assembler now opens up to 16 part descriptors in parallel and streams their
contents **sequentially** into an exclusively created destination. Only bounded
stream buffers are retained; each descriptor is closed before release, and
missing/hardlinked parts, I/O failures and a preexisting destination fail
closed without overwriting or deleting an existing payload. Storage quota,
required part count, the request's existing deadline, scanning, encryption,
and durable handoff rules are unchanged. A disposable Windows Node 22/24
fixture validates exact 2,000-byte ordering under synthetic 7ms/open latency
and concurrent independent disk writes; the bounded stage took approximately
1.8–2.0 seconds, with 16 peak concurrent opens. Tests also cover two full
8 MiB parts, absent parts and intact destination preservation. Full HTTP
2,000-chunk flows were verified locally on Node 22/24 with the unchanged
socket timeout; this local result does not establish hosted CI completion.

## Issue #65 / PR #228: real Edge positive persisted restore signer-id repair (2026-10-25)

Independent review of standalone commit `07e6f43` found an unconditional
browser UI denial: `restore-persisted` decoded the **16-byte / 22-character**
owner `signer_key_id` with `from64`, which only accepts a 32-byte digest.
The existing strict `signerIdFrom64` decoder is now used at that call site;
neither the owner trust source nor the signed checkpoint contract changed.

TDD RED reproduced the failed real Edge workspace contract, followed by a
real Edge witnessed-V2 **GREEN** with the original signed owner approval,
independent mTLS CAS/witness peers, authenticated Express/SQLite protected PUT,
two local ciphertext chunks, distinct owner-pinned native and portable roots,
and two fresh device-signed protected GETs bracketing local HKDF/AES-GCM
decryption. Edge's intercepted local download bytes match the original
plaintext and no plaintext, filename or holder secret is sent on the HTTP
content route. An incorrect owner SPKI or native root denies before GET;
revoking the actual disposable mTLS witness after reading the second local
chunk forces the second GET to deny, with **zero new plaintext downloads**.
The browser's fixed script allowlist includes both persisted modules. This
is DEV-only; a successful signed GET does not establish external physical
durability, production restore authorization or custody of the independent
pins. PR #228 remains **DRAFT / NO-GO for production**.

## Issue #65 / PR #228: browser persisted-chunk opt-in with real protected readback (2026-10-25)

The development authenticated files workspace now has an explicit opt-in
`restore-persisted` action backed by the browser UMD
`rootark-zk1-persisted-browser-recovery`. The operator supplies the already
existing **offline** owner key/SPKI fingerprint, owner signed checkpoint chain,
current head, signed device grant, independent portable root, and an additional
**independent owner-signed native source-chunk root**. It also requires an
owner-root Ed25519 checkpoint for the exact object/revision/native root, the
user-held 32-byte secret, a signed persisted-chunk inventory, and locally
selected opaque chunk files in the owner's signed order. Neither the bundle,
SQLite, server response, nor mutable config may be promoted into an owner pin.

The bridge re-verifies the owner grant and browser monotonic floor, verifies
native owner-root provenance before HTTP, performs a nonce-fresh device-signed
historical GET against the existing protected route, and checks exact remote
ciphertext against the externally pinned **portable single-envelope root**.
It then verifies every local persisted chunk, its independent native root,
the owner Ed25519 inventory, and portable HKDF/AES-GCM before allowing plaintext
to leave the function. A **second independently signed GET** after slow local
reads/decryption refuses plaintext if the real server-side witness gate revoked
the device in that interval. Local liveness guards cover session changes,
closed dialogs, CSRF changes, slow file reads, and the final download. Copies
of the recovery secret, ciphertext and plaintext are zeroized on failure;
UI-owned file buffers and returned plaintext are wiped after use.

The focused integration test runs a real authenticated Express protected route,
Ed25519 user/device keys, real SQLite persisted two-chunk rows, real HTTP GETs,
and actual portable AES-GCM recovery. The revocation-during-local-read test
was RED before the second GET and GREEN afterward. The browser UMD is also
loaded in a Node-free VM. This is NOT a production restore, not remote SQLite
chunk-proof, not current independent owner pin custody, and NOT a proof of
off-host fsync, provider physical independence or cross-provider durable
atomicity. The server still returns only opaque ciphertext, no trusted pins.
PR #228 remains DRAFT and NO-GO for production; do not infer a deployment
authorization from this opt-in development user interface.

## Issue #65 / PR #228: local persisted encrypted-chunk backup/recovery binding (2026-10-25)

The browser-compatible, offline `rootark-zk1-persisted-portable-chunk-recovery`
module can create an Ed25519 owner-signed inventory of the exact encrypted
chunks in a user-held portable recovery bundle. On recovery it requires an
**independently retained** owner SPKI SHA-256, current `{revision,digest,epoch}`
head, portable ciphertext root **and separate native source-chunk root**,
authenticates the signed inventory before any chunk
read, and fetches every bounded persisted chunk. Each chunk length and SHA-256,
the reassembled ciphertext SHA-256/root and the exact encrypted bundle are
checked before the existing client-side HKDF/AES-256-GCM CEK and file recovery
can return any plaintext. It rechecks a caller-provided local liveness guard
after each asynchronous read and before return, and wipes temporary ciphertext
and holder-secret copies on every path. The source-chunk root is computed with
the actual persisted boundaries (chunk count, order, lengths and digests),
not `computeCiphertextRoot([concatenatedCiphertext])`: the latter remains the
portable HKDF/AES-GCM bundle's original one-envelope wrapping context. The
additional native source root MUST come from an independently retained owner
checkpoint, never the portable bundle or SQLite archive. This is a required
consumer input, not a change to the signed-inventory or portable bundle wire
formats.

The focused test uses an actual disposable SQLite file on disk across close,
restart and rollback, with real Ed25519 signatures and AES-GCM encryption.
An older correct DB snapshot, another owner's valid signature, wrong holder
secret, missing/modified chunk and liveness loss during reading all deny.
An adversarial real two-chunk source root test distinguishes the native root
from the portable one and rejects omission or substitution of the native pin.
Windows Node 24: **7 focused tests PASS / 0 FAIL**, plus five existing portable
file cryptography regressions (**12 PASS / 0 FAIL** combined). Earlier six-test
Node 22 evidence predates the extra native two-chunk source-root test; rerun
the revised suite on Node 22 before claiming that runtime's updated results.
SQLite's built-in
`node:sqlite` API is experimental on these runtimes, and is test-only here.
The signer and recovery consumer are available as an explicit opt-in client
module; they are not automatically wired to a production backup scheduler,
app restore route or disaster-recovery ceremony. A coherently rolled-back
database **plus independently rolled-back owner pins** cannot be detected by
this module. It does not establish witness/CAS freshness, off-host storage,
durability, distributed epoch fencing or production restore authorization.
PR #228 remains DRAFT / NO-GO.

## Issue #65 / PR #228: development browser vault cross-tab revocation (2026-10-25)

The **experimental** `/zk-dev` browser vault uses an IndexedDB v3 per-account
`{epoch, nonce}` fence. "Forget this browser" atomically deletes stored
content keys, trusted-device escrow and pending recovery requests, and commits
the next fence in the same readwrite transaction. Open tabs verify the fence
before releasing decrypted content or a trusted-device approval, and before
restoring, storing or exporting key material. BroadcastChannel and `storage`
events are advisory wakeups only; stale/replayed messages do not choose the
authoritative epoch. Focus/page restore and foreground operations resample
IndexedDB even after a sender tab closes. A real Edge multi-tab test covers
revocation during an in-flight read and during paused trusted-device approval,
closing the revoker tab and replaying old notifications.

This is local browser-session invalidation. It cannot revoke already exported
recovery secrets, prevent same-origin script/profile compromise, enforce a
server-authoritative device policy or protect against coherent IndexedDB
rollback/deletion across a full browser restart. A tab terminated **before**
its revocation transaction commits also cannot guarantee another tab was
invalidated. No independent witness, zk-1 epoch policy or production GO follows.

## Issue #65 / PR #228: disposable real loopback WebDAV mTLS physical-copy milestone (2026-10-25)

The opt-in, development-only ZK1 ciphertext WebDAV adapter now refuses any
HTTPS destination other than the literal `127.0.0.1`, avoiding DNS rebinding,
private-network and cloud-metadata SSRF through experimental provider setup.
Redirect responses remain errors; no remote redirect is followed. The
disposable real HTTPS fixture provisions WebDAV parents using `MKCOL`, then
exercises bounded `PUT`, `GET` and independent `HEAD`, with separately
enrolled writer and reader mTLS identities, unknown-client rejection, a
pinned server leaf certificate, strong ETag CAS, stale-version refusal,
corrupted PUT/GET content and malicious redirect rejection. WebDAV parents
must be provisioned by an operator; the client does not automatically create
arbitrary remote folders.

The isolated PostgreSQL 18 extension verifies the exact physical ciphertext
and signed local inventory operation before any WebDAV PUT, then challenges
the reader with a separate real HTTPS GET. A successful `PUT` remains
`CLOUD_COPY_PUT_ACK_NONAUTHORITATIVE`, and a matched GET is only a point-in-time
observation. Neither proves remote durable persistence, independent provider
administration, nonrollbackable external epochs, atomic PostgreSQL-to-WebDAV
commit, client authorization, or production readiness. Tests and the adapter
do not enable a production endpoint. Windows Node 24 and Node 22 focused
WebDAV regressions passed 10/10 each; a separate isolated PostgreSQL 18
physical-copy lab passed 1/1 for each Node version, with verified disposable
database cleanup. PR #228 remains DRAFT / NO-GO.

## Issue #65: current-device revocation at strict historical Sync read (2026-10-25)

Strict Sync v2 now requires an operator-injected, independently maintained
`trustedCurrentDevicePolicyProvider` in addition to the initial pinned device
policy. It resamples this synchronous source **after** awaited Ed25519/PG
verification, before claiming a historical read is authorized, and checks the
exact original device SPKI, username, and current revocation. Fresh incoming
operations also recheck after signature verification, and new outgoing
operations check the current device policy rather than the startup snapshot.
The adversarial regression revokes the device while the signed PostgreSQL
proof is being verified. This local decision does **not** itself provide
cross-process transactionality with file application or queued HTTP retries,
distributed revocation fencing, or a guarantee that an external policy source
is authoritative/fresh. The independent server-side atomic registry and
end-to-end final I/O fencing remain separate required guarantees.

## CodeQL document preview DOC/DOCX local filesystem race (2026-10-24)

The authenticated DOC/DOCX preview worker now parses only a bounded private
in-memory snapshot captured through a verified regular-file descriptor.
The original path is checked before and after the read using exact bigint
device/inode, size and change timestamps; symlinks and hardlink aliases fail
closed. The DOCX archive preflight examines these exact bytes; the worker
receives the bounded bytes through a private standard-input pipe and parses
from memory. No plaintext temporary directory or file is created. Parent
bytes are zeroized on successful close or failure, including unreaped-child
timeouts. Adversarial rename, oversized replacement, symlink and timeout
cases and a real Mammoth DOCX extraction were added. This is a conditional
local-filesystem threat; no network-only exploit has been demonstrated.
It does not establish completion of PR #228 or release readiness.

## Issue #65 / PR #228: strict atomic device-registry storage permissions (2026-10-25)

The opt-in same-file device registry now **fails closed** unless the complete
storage directory is provisioned with a private service-owned ACL (Windows) or
strict private ownership/mode (POSIX). On Windows it reuses the native NTFS
GetNamedSecurityInfoW-based verification used for protected chunk staging:
the storage directory must have a protected DACL with only the service
principal, SYSTEM and Administrators, and its ancestors must not be replaceable
by other local principals. Store, exclusive writer lock and rename-temp files
are inspected before critical operations. An ACL failure observed after the
atomic JSON rename quarantines the writer lock and flags the commit as
indeterminate rather than permitting a blind retry. On POSIX the owned directory must
be 0700, store/lock/temp files 0600, without symlinks or hardlinks, and
writable ancestors require a root-owned sticky directory. Existing shared
directories or ACLs are **never altered or hardened automatically**.

In particular, the existing `E:/servidor/data` inherits broad local Modify
rights in the tested Windows environment and **cannot** host the protected
atomic registry. An operator must separately provision a service-private
directory under safe ancestry before enabling
`SYNC_ATOMIC_DEVICE_REGISTRY=true` and point `SYNC_OBJECTS_FILE` there.
No claim of external nonrollbackable monotonic anchoring, protection against
the privileged service principal/Administrators/SYSTEM, cross-volume
durability, or readiness for production is made. Native NTFS ACL verification
adds measurable latency to synchronous operations and may reject concurrent
changes closed; only atomic mode receives a longer bounded writer-lock wait.
The existing legacy mode remains unchanged.


## Issue #65 / PR #228: dedicated mTLS transport for W2 historical issuer (2026-10-25)

The isolated witness HTTPS server has an opt-in
`POST /v1/cas-anchor/historical-admit` transport for the existing W2
`Zk1WitnessCasAnchorFloor.issueSyncHistoricalAdmission()` service. No new
receipt ledger, signing key or admission policy is introduced. The distinct,
exclusive `cas-historical-admit` mTLS role requires exact provisioned scopes;
neither the global `cas-anchor` role nor an unrelated scope can issue receipts.
The endpoint accepts an exact 32-byte **client-generated nonce**, the canonical
encrypted Sync v2 envelope, scope, checkpoint and bounded inventory receipt,
and returns only the witness's admission and nonce-bound signed physical floor.
The issued receipt must name precisely the returned floor, including physical
fence digest; otherwise the endpoint denies the response. These checks do not
replace the published client's Ed25519 and fresh PG-proof verifiers.

**Critical W2 integration gate:** server configuration refuses to enroll the
historical mTLS principal unless the real W2 witness core advertises
`supportsClientHistoricalNonce === true`. This property MUST be an immutable
read-only class getter enabled only when W2 pins the exact provided client nonce
and uses it in the returned signed V2 physical floor. Older W2 commits which
generate their own floor nonce are rejected at server startup **before** they
can irreversibly persist a receipt that the client cannot authenticate. Do
not set the capability with a mutable caller-supplied flag or bypass it.

A real TLS 1.3 client-certificate test covers positive and negative roles,
scope mismatch, malformed nonce, unrecognized fields, tampered signed floor,
and cryptographic verification against the published Sync v2 historical
consumer loaded from its own commit. The transport fixture signs test-only PG
proofs; it does NOT prove real PostgreSQL18 fsync or external durability.
An incremental transport hardening gate now **requires** the existing W2 issuer
to return its own independently verified signed `physicalAttestation` Buffer
(1..2048 bytes); the endpoint inspects the deterministic CBOR PG-attestation
nonce, requires it to equal the exact 32-byte caller challenge, and sends the
same raw bytes as canonical base64url in `physicalAttestation`. Missing,
non-Buffer, oversized or nonce-mismatched evidence is refused; transport tests
feed **only the HTTP-returned physical proof** to the published consumer,
never fabricate a PG signature on behalf of the caller after HTTP succeeds.

Authenticated historical clients additionally face a fixed monotonic 60s
window at most **12 attempted requests per principal** and **24 globally**,
plus **one in-flight request per principal** and **two globally**. The slot is
reserved immediately after mTLS role authentication and **before reading** the
up-to-12MiB body, and always released after request completion/error. HTTP
429 never invokes the issuer or reads the body. Tests hold simultaneous issuer
calls, reject a third authorized peer with a deliberately unsent 12MiB body,
and exhaust both principal/global request budgets. These local process budgets
do not replace a cross-host distributed rate limit or an external witness
monotonicity guarantee.
This scoped patch alone does not make W2's historical issuer/PR #228 production
ready. Cherry-pick **only the transport commit** onto W2's verified latest
core, then run full issuer+TLS+consumer tests together. Do not combine the
overlapping alternate W4 issuer SQLite schema.

## Issue #65 / PR #228: Windows Edge V2 IPv4 fixture binding (2026-10-24)

The disposable positive Edge + strict mTLS CAS/witness fixture bound both HTTPS
authorities to `127.0.0.1` but requested them through `localhost`. When Node 22
was forced to resolve localhost to `::1` first without network-family fallback,
the previously passing end-to-end test reproduced `ERR_TEST_FAILURE` and
`ZK_BROWSER_CONTENT_UNAVAILABLE` during the first authenticated ciphertext PUT.
The isolated fixture now connects to the actual IPv4 listener using its
existing `127.0.0.1` certificate IP SAN, without weakening TLS or fingerprint
pinning. Windows Node 22 original/fixed RED→GREEN in forced IPv6 resolution,
and the normal case remains GREEN (1 PASS / 0 FAIL each fixed run). This matches
the hosted failure category and test hash but does not establish that hosted
Windows had the same DNS configuration; a completed hosted run is required.
No production transport or deployment was changed. PR remains DRAFT / NO-GO.

## Issue #65 / PR #228: physical evidence freshness after multiprovider owner verification (2026-10-24)

The strict multiprovider recovery path now retains the independently verified
Ed25519-signed physical readback `issuedAt` from its final PostgreSQL inventory
reconcile and checks it again after awaited owner-checkpoint authentication.
Previously, a signed proof verified at age 29 seconds could be returned as a
fresh composite after the owner verification stalled until age 31 seconds.
An adversarial isolated WebDAV HTTPS + S3/Drive fixture reproduced this RED,
then passed GREEN; Windows Node 22 and 24 focused matrix: 12 PASS / 0 FAIL
each. This avoids an extra physical network request and does not establish
trusted monotonic time, independent external durability, historic Sync v2
admission, or end-to-end PG18 correctness. PR #228 remains DRAFT / NO-GO.

## Issue #65 / PR #228: strict PostgreSQL bridge proof freshness (2026-10-24)

The strict independent-attestor branch of `Zk1PgPhysicalInventoryBridge`
now rechecks the signed `issuedAt` after each asynchronous verification of
remote physical readback, and again after verifying the composite inventory
receipt. A valid Ed25519 signature alone may not outlive its 30-second
challenge freshness window. A signed proof crossing from age 29 seconds at
verification to 31 seconds at return was reproduced RED and now fails closed.
The original non-independent local verifier path is unchanged. Windows Node 24
and Node 22 focused regressions: 24 PASS / 0 FAIL each. This patch does not
establish independent trusted time, full distributed fencing, cloud fsync,
or historical Sync v2 admission and does not imply merge readiness.

## Issue #65 / PR #228: physical proof expiry across async verification (2026-10-24)

The opt-in Sync v2 to ZK1 physical-envelope verifier now requires the physical
readback to remain within its signed 30-second freshness window **after**
awaiting both Ed25519 and deterministic CBOR checks. Previously, a response
starting at age 29 seconds could finish at age 31 seconds and still be accepted.
The physical attestation parser returns the already-verified `issuedAt` claim;
the Sync v2 bridge rechecks it against the wall clock just before returning.
RED before the patch; Windows Node 24 and Node 22 focused tests 23 PASS / 0 FAIL
each after the change, including a non-finite clock rejection. This is a
non-authorizing proof freshness repair; it does
not establish original historical server admission time, an independently
anchored floor, actual external provider durability, or a complete Sync v2
PostgreSQL runtime integration. PR #228 remains DRAFT / NO-GO.

## Issue #65 / PR #228: canonical JSON and idempotency object identity (2026-10-24)

A JSON object carrying its own `__proto__` field previously collided with an
object lacking that field when constructing deterministic sync JSON and
idempotency fingerprints: the plain-object accumulator invoked JavaScript's
prototype setter instead of preserving the field. Both the outer and nested
variants were reproduced RED. Canonical accumulators now use null-prototype
objects so every own JSON field is retained in the signed/hash input without
mutating shared prototypes. Node 22/24 focused historical authorization,
readiness, and idempotency tests: 12 PASS/0 FAIL each; Node 24 adjacent client
and sync regressions: 33 PASS/0 FAIL. These are local serializations only:
they do not prove historical admission, distributed authority or external
provider durability. PR #228 remains DRAFT and NO-GO.

## Issue #65 / PR #228: independently attested strict inventory chain (2026-10-24)

The opt-in strict mTLS inventory chain now requires a fresh caller challenge per
page and derives a distinct challenge for every signed entry. The server
verifies each ledger receipt under its pinned inventory identity, asks the
separate read-only physical attestor for a fresh PostgreSQL readback, and
returns both. The client independently verifies each Ed25519 receipt/readback
pair against the exact operation and pinned identities before authenticating
the complete chain against its caller-retained signed floor and fresh snapshot.
Missing, forged, or downgraded physical evidence fails closed. Strict pages
are capped at four receipts. The independently reviewed P2 in `98c2f4d`
was that sharing the 4-request append/status budget made a 9-entry chain
impossible; a separate 16-page-per-minute budget now permits the full 64-entry
client cap while retaining a shared two-active-read ceiling and the tighter
append/status quotas. Contention can still return unavailable; it must never
be mistaken for a verified result. This is nonauthorizing proof of local
physical readback, **not** a
cloud durability guarantee or an externally anchored floor.

Windows Node 24 mTLS after the rate-budget RED/GREEN: 24 PASS / 0 FAIL,
including 9-entry status continuation and the full 64-entry client cap.
Ubuntu WSL Node 22 mTLS: 24 PASS / 0 FAIL. The separate independent-attestor
transport test and its synthetic ledger fixture passed before this revision;
the multi-page restart fixture uses a synthetic signed
readback; it does not replace the separate PostgreSQL 18 laboratory, and the
sync historical-admission gap below remains NO-GO. No publication or cutover.

## Issue #65 / PR #228: historical signed sync reads (2026-10-24)

The isolated descendant of `caf3ed2` separates fresh authorization for new
sync writes from verification of a previously stored remote operation. Pull,
conflict-current, cache eviction, and remote-only materialization parse the
historical record without re-imposing its expired write deadline; the Sync v2
client still checks its Ed25519 signature, exact operation scope, independently
pinned device key, current revocation snapshot, selected path and key epoch.
Server ingress and outgoing writes retain fresh expiry enforcement. Malformed
expiry values fail closed. A persisted signed operation was pulled after expiry
and local restart in adversarial tests; Windows Node 24 focused regressions
passed 43/0, Ubuntu WSL Node 22 focused regressions passed 14/0, and syntax
validation checked 646 files/0 failures. This does not independently prove
the *time of original server admission* for an old signed operation; a separate
admission anchor remains necessary for a compromised-server threat model.
Normative physical inclusion, final independent review, Windows hosted Edge
failure and CodeQL gate remain NO-GO; no publication/cutover.

## Issue #65 / PR #228: exact-factor grant and local cross-process sync fencing (2026-10-24)

The descendant of `59bc97c` adds SQLite migration 8, `sync_resume_factor_spend_grant`.
An already-consumed TOTP/recovery factor may resume a staged intent **only**
when the durable `(username, replay_digest, code_mac, device_id, pause_fence)`
grant matches exactly. A competing device, changed pause marker, or different
MAC cannot borrow an earlier spent factor; the selective account mutation and
grant insertion are one `BEGIN IMMEDIATE` transaction. The live route fails
closed for JSON-only or dual JSON-mirror account persistence, where that SQLite
transaction is unavailable.

The local sync JSON store now obtains an exclusive `wx` writer lock before
opening or mutating the file, refreshes and validates the latest persisted
state **under** the lock, and holds the lock through durable rename/fence. A
stale second Node process can no longer overwrite a sibling's committed pause,
intent, history or object state. Orphaned locks are never stolen automatically:
recovery is deliberately blocked pending operator investigation. The lock is
only a **single-host, cooperating-process filesystem boundary**, not a remote
CAS, distributed quorum, independent monotonic floor, NFS safety proof or
guarantee against a host filesystem attacker.

Adversarial RED before the cross-process fix: **2 FAIL** (stale reopened
instance and actual independent child processes lost records). GREEN after
the fix: Windows Node 24 **39 PASS / 0 FAIL** across focused SQLite grant,
resume, local child process, and strict witness tests; Ubuntu WSL Node 22
**36 PASS / 0 FAIL** on local child process plus resume tests. Independently
signed PG readback inclusion, truly remote monotonic fencing, physical PG18
validation, complete suite on this new HEAD, mandatory independent review,
and published CI remain separately blocked/unverified. PR #228 stays
**OPEN/DRAFT; NO-GO; no push/merge/deploy/cutover**.

## Issue #65 / PR #228: resumable 2FA CAS and physical witness startup minimum (2026-10-24)

The remote draft branch was still at 6a5e71e when verified. In an
isolated descendant of local 21d9047, e99500a introduced a durable,
MAC-bound resume intent before consuming a second factor. Failed final
sync persistence leaves the device paused and a same-code/same-device/
same-pause restart-safe recovery grant; staging failure spends nothing.
The reviewer found a concrete P1: awaiting staging before bulk saveUsers
could overwrite a simultaneous administrative revocation. The follow-up
removes bulk saves from this path: SQLite performs selective one-row
compare-and-update inside BEGIN IMMEDIATE and rejects stale password,
session version, disabled, key, or second-factor state. The JSON-only path
is single-process only, and dual-store JSON mirroring is denied for this
sensitive operation until an atomic protocol exists.

Strict witness restart now pins and verifies the signed physical fence
chain digest independently of the CAS last hash. Unpinned, mismatched,
and whole-file-restored physical histories fail closed.

RED-to-GREEN covered recovery failure/restart, code replay, forged resume
intent, concurrent reactivation, admin revoke race, SQLite selective CAS,
and strict physical witness minimum. The unchanged prior 21d9047
Windows Node 24 complete suite reported 2476 PASS / 0 FAIL / 167 SKIP;
those numbers are NOT evidence for these newer edits. No claim of
PostgreSQL-to-SQLite atomicity or remote durability is made.
Hosted CI, PostgreSQL 18 locally, Ubuntu native SQLite coverage,
physical normative client inclusion, full affected suite and independent
re-review still gate publication. PR stays DRAFT and NO-GO.

## Issue #65 / PR #228 native authority and signed-claim fixes — 2026-10-24

The last *remote* draft PR HEAD observed for
`cdx/rootark-dual-recovery-20261019` remains
`6a5e71ed33ae44d65f7c3a124632cb4d5c4ae4f3`. In the isolated worktree,
local unpublished commits `b5792b2`, `e16f5b3`, `bf18851`, `ea9a8a2`,
`3323737`, `62fff4f`, `e91053e`, `48f3da7`, `0722405`,
`083f3b0`, `a3a9f13`, `e1824f4`, `a1dd767`, `228dc6d`, `eb54e5b`,
`b2ff600` and `c607e81` are descendants, not
published CI checkpoints.
They preserve the previously integrated owner V2 security fixes `356bf2f`
and `d014005`.

Fresh adversarial RED→GREEN cases found and fixed independently pinned
Ed25519 public keys spoofed by instance-owned `KeyObject.export()`, affecting
offline witness/CAS signed claims, owner inventory trust heads, owner device
enrollment, multi-provider domain pins, remote V2 CAS/FLOOR constructor pins,
owner-retained CAS/FLOOR checkpoint pins, and the separate signed V2 floor
SQLite identity across restart. The independent floor now rejects reuse of
the same actual signing key across CAS/FLOOR/owner/witness roles and closes its
SQLite connection if constructor validation fails. A separate signed-claims
attack could present valid fields A during verification and fields B for the
decision; immutable primitive snapshots now bind the offline CAS/witness
decisions to the exact bytes verified.
The later `48f3da7` reproduces and closes another authority-separation bypass:
the V2 device would accept the existing CAS public key as an independently
pinned historical signer-grant root if the caller overrode that key's
`KeyObject.export()`. The native fingerprint now rejects this alias before
creating the client SQLite journal; Windows Node 24 and Ubuntu Node 22 each
validated 6 PASS / 0 FAIL, and actual V2 mTLS/owner-history regression passed
2 / 0 on Windows.

Focused validation: Windows Node 24 signed-claim and pin tests 34 PASS/0 FAIL;
Ubuntu Node 22 corresponding tests 20 PASS/0 FAIL; real V2 mTLS, signer
revocation, uncertain ACK, restart and authenticated historical signer
rotation tests 2 PASS/0 FAIL; independently pinned V2 floor process/mTLS
plus regressions 3 PASS/0 FAIL. S3/Drive/WebDAV loopback remote GET/integrity
and failover 14 PASS/0 FAIL on each Node 22/24. Syntax, runtime artifact and
diff checks PASS. A broad Windows Node 24 suite returned **2620 total / 2453
PASS / 0 FAIL / 167 SKIP**, but source files were edited during its run;
this is *not* final-HEAD CI evidence. A subsequent exact-code suite on
`e91053e` completed **2626 total / 2459 PASS / 0 FAIL / 167 SKIP**. Since
`48f3da7` then changed runtime behavior and added a regression test.
An overlapping Windows Node 24 run reached **2627 total / 2460 PASS /
0 FAIL / 167 SKIP**, but synchronization source was changed during that run;
it is not an exact-current-HEAD validation. A fresh Windows Node 24 full
suite after the pinned synchronization commits finished with **2628 total /
2461 PASS / 0 FAIL / 167 SKIP**, `duration_ms=707405.1237`, in
`.local-full-node24-20261024-final-pinned-sync.log` (local-only evidence,
not hosted PR CI).

Additional RED→GREEN security changes in `083f3b0` and `a3a9f13` close
three concrete synchronization authorization gaps: a reusable `SyncEngine`
with `requireAuthorization:true` previously accepted remote ciphertext
without any incoming verifier; the Sync v2 CLI trusted self-signed remote
device public keys without an independently provisioned device-to-key pin;
and the shared proof verifier silently allowed callers to omit that pin.
The CLI now requires a pinned Ed25519-SPKI device map and explicit revoked
device snapshot; the server passes the already-registered key into the shared
verifier. Windows Node 24 sync/HTTP/WebDAV tests **41 PASS / 0 FAIL**;
Ubuntu Node 22 corresponding tests **32 PASS / 0 FAIL / 8 SKIP**.
Those snapshots are *not* owner-signed monotonic revocation records and can
be rolled back by an attacker controlling local configuration.

`a1dd767` adds crash/failure recovery on the real persisted sync JSON store.
Adversarial RED cases confirmed that a rejected transaction permanently
poisoned the in-process queue and that merely clearing the rejection could
silently overwrite an operation already renamed onto disk when directory
`fsync` failed. The repaired queue recovers only pre-rename failures;
post-rename durability ambiguity now fences all reads and writes, including
HTTP sync endpoints (`503 sync_commit_indeterminate`), until a fresh store
instance reads and validates the disk state. A second RED case caught the
previously uncaught HTTP rejection; GREEN requires the explicit 503.
This proves only bounded local failure handling and a fresh readback, not
external fsync, process-independent CAS, or revocation atomicity. Windows
Node 24 targeted 69 tests: **68 PASS / 0 FAIL / 1 SKIP**; Ubuntu Node 22
targeted 41: **39 PASS / 0 FAIL / 2 SKIP**; the final three focused
Ubuntu Node 22 failure/recovery tests **3 PASS / 0 FAIL**. The full
Windows Node 24 run on `a1dd767` finished **2631 total / 2464 PASS /
0 FAIL / 167 SKIP**, `duration_ms=723095.6808`, in
`.local-full-node24-20261024-post-ambiguous-fsync-fence.log`. This run
precedes the following recovery guard and is not final-HEAD evidence.

`228dc6d` closes a separate availability/credential-consumption gap:
when the sync store is already quarantined or becomes indeterminate
during asynchronous bcrypt/recovery verification, the device-resume
HTTP route now returns **503 SYNC_COMMIT_INDETERMINATE** before persisting
TOTP replay state or spending a single-use recovery code. Adversarial
RED tests saw **400** (already quarantined) and **401** (became quarantined
after bcrypt) instead of the required **503**. GREEN on the actual
server route and real JSON store, including opening a separate store
instance and using the previously untouched recovery code once:
Windows Node 24 **30 PASS / 0 FAIL / 0 SKIP**; Ubuntu Node 22
**30 PASS / 0 FAIL / 0 SKIP**. This does **not** make writes to
the separate user account file atomic with sync-store transactions,
nor establish a process-independent monotonic revocation authority.

`eb54e5b` resolves a separate sync tenant/index isolation bug: JavaScript
inherited properties such as `constructor` and `toString` were previously
treated as committed operations or existing objects, while an authenticated
`__proto__` username could mutate the process-wide prototype and fail to
persist a private tenant. Legacy accounts with missing index maps could also
read inherited ciphertext or history when a different component had already
polluted `Object.prototype`. Child-process adversarial tests reproduced
all three failure classes in RED, including a GET of counterfeit history
*before* the first write. GREEN uses own-property reads, defined own keys and
safe index initialization, including V1 migration and restart. Integrated
Windows Node 24: **71 total / 70 PASS / 0 FAIL / 1 SKIP**; Ubuntu/WSL
Node 22: **71 total / 69 PASS / 0 FAIL / 2 SKIP**. Syntax:
**638 checked / 0 FAIL**; artifact validation and diff-check PASS.
Independent read-only P1/P2 review identified the inherited GET gap,
which was reproduced and closed in this same commit, and found no further
concrete P1/P2 in this bounded patch. Neither this review nor focused
validation constitutes acceptance of the entire issue.

`c607e81` tightens the authenticated loopback sync WebDAV bridge:
plain-text error/denial responses now send `Content-Type: text/plain` and
`X-Content-Type-Options: nosniff` (CodeQL alert #2), while `PROPFIND`
remains XML. GET/HEAD now use a verified regular single-link file descriptor
instead of opening the pathname again when streaming, send bounded MIME
headers, refuse leaf swaps between `lstat` and `open`, and close the stream
when a client aborts. RED tests reproduced the missing MIME headers, path
reopen, and descriptor leak on abrupt disconnect; GREEN on Windows Node 24
and Ubuntu/WSL Node 22 **4 PASS / 0 FAIL / 0 SKIP each**. The broader
Windows WebDAV crash/recovery/remediation matrix initially FAILED when run
concurrently with WSL (server readiness timeout, not silently reclassified);
an isolated Windows `--test-concurrency=1` rerun passed **84 / 0 / 0**.
An independent reviewer confirmed the abort-FD fix, but found a remaining
conditional parent-directory symlink swap/restore race: `O_NOFOLLOW` on the
leaf cannot replace native secure open-relative-to-pinned-directories.
This is an explicit **P2 / NO-GO** under an adversarial local-filesystem
trust boundary; the WebDAV patch as a whole is not approved for publication.
CodeQL open-alert spot triage without suppressions: #268
(`js/insufficient-password-hash`) refers to an ephemeral
`HMAC-SHA256(random-process-secret, username + NUL + password)` used only
as a cache lookup key in `webdavCredentialCache.js`, with actual password
verification performed separately by bcrypt; this is not a password hash
substituting for the password verifier. #160
(`js/user-controlled-bypass`) flags the optional `authorization` field
in a client-side operation builder; the shipped `server.js` sync route
explicitly starts with `requireDeviceAuthorization: true` and fails
closed absent a verified registered device. These findings do not prove
a bypass on those checked runtime paths; unrelated call sites and remaining
CodeQL sinks require separate triage. Neither alert was blanket-suppressed.

Hosted checks still refer **only** to the published `6a5e71e`: Ubuntu Node 22
full, disposable PostgreSQL 18, Windows mandatory release gates, JavaScript
analysis and dependency review PASS; Windows canonical Edge V2, its dependent
syntax gate and CodeQL policy FAIL. The Edge failure could not be reproduced
in five local real-Edge repetitions; no timeout or failure masking was done.
CodeQL findings require exact-sink triage, not blanket suppressions. The
independent reviewer service blocked an earlier broad review attempt.
The later bounded independent read-only review of `083f3b0` + `a3a9f13`
found no newly introduced P1/P2, but identified a **pre-existing P2**:
`src/routes/sync.js` checks device revocation before `store.put()` without
a shared registry/store fence, permitting a concurrent revocation race.
The formal security-diff-scan reference was unavailable, and no independent
final approval covers the whole issue #65 integration. Therefore **NO PUSH**
until the mandatory full review gate and remaining security conditions are
met; PR remains DRAFT and the release/cutover decision remains NO-GO.

Physical PostgreSQL Ed25519/mTLS and inventory composite readback remain
non-authorizing opt-in evidence. They do **not** yet prove an independently
anchored normative CAS/FLOOR/witness admission, shared PG/SQLite/provider
atomicity, external multi-provider durability, or full legacy history/trash/
derived/retention inventory and safe cutover. Missing joins remain UNKNOWN.
PR #228 stays OPEN/DRAFT, issue #65 OPEN, overall **NO-GO**; no merge, deploy,
production activation, cutover or legacy deletion.

## Issue #65 / PR #228 security development checkpoint — 2026-10-24

The last remotely confirmed draft-PR HEAD before this checkpoint is
`6a5e71ed33ae44d65f7c3a124632cb4d5c4ae4f3`; the new *local* isolated
worktree commit `b5792b246d1adbe5eb87420c176acd6e54ae7ffe` has **not**
yet been counted as a published or CI-accepted milestone.

Two adversarial RED→GREEN regressions prevent a compromised owner from using
an overridable `KeyObject.export()` to fabricate independently pinned Ed25519
generation evidence in the read-only legacy S3/Drive inventory or to pass one
signing identity off as two separate witness/CAS authorities during owner-side
V2 device revocation and epoch rotation. Revocation also pins the actual native
owner/CAS/witness SPKI identities rather than caller-provided export bytes.
Focused Node 24/Windows and Node 22/Ubuntu tests for both modules each yielded
**11 PASS / 0 FAIL**; artifact and diff checks passed; syntax checked **629 / 0**.

The hosted checks for the *published* `6a5e71e` HEAD show Ubuntu Node 22 full,
disposable PostgreSQL 18, JavaScript analysis and Windows mandatory release
gates **PASS**. The hosted Windows canonical suite has **one FAIL** in the real
Edge V2 witnessed-recovery test, while Windows syntax dependent gate and CodeQL
policy also **FAIL** (CodeQL reports 57 high + 35 medium untriaged alerts).
The failing Edge test name and file were identified from the canonical runner's
privacy-preserving hashes; the same real-Edge test passed **5/5** consecutive
local stress runs, which does **not** erase the hosted Windows failure.
An earlier complete local Node 24 run at the preceding code checkpoint yielded
**2445 PASS / 0 FAIL / 167 SKIP**, which must not be transferred to this diff.
Independent final review for the new local patch could not finish because the
reviewer service blocked the request; do not claim that gate passed.

This narrows cryptographic forgery, **not** physical external custody, a
monotonic independently retained CAS/FLOOR, PostgreSQL-to-remote atomicity,
complete legacy reference inventory, or safe migration cutover. PR #228 remains
**OPEN/DRAFT**, issue #65 **OPEN**, overall status **NO-GO**; no merge, deploy,
production activation or legacy deletion is authorized.

> **Most recent issue #65 development checkpoint — 2026-10-23:**
> [PR #228 source, validation and remaining blocker evidence](validation/2026-10-23-issue-65-pr228-development-checkpoint.md).
> The `da02715` checkpoint below is historical and not the current HEAD.
> PR #228 remains OPEN/DRAFT, issue #65 OPEN; no merge/deploy/cutover.

## Live issue #65 development evidence — 2026-10-23 (`da02715`)

At the observed checkpoint, PR #228 (`cdx/rootark-dual-recovery-20261019`)
is **OPEN/DRAFT** and issue #65 is **OPEN**. Local integration HEAD and
remote branch HEAD both equal `da02715a8a6787836a05aeb06e6d1b0bdc61d61a`;
the worktree was clean. This checkpoint supersedes the *live-status claims*
in the older dated addenda below, not their historical test evidence.

Newly integrated development work includes `7feb752` (restore missing local
catalog snapshots from remotely signed CAS snapshots after an uncertain ACK),
`db7baa6` (private POSIX SQLite file creation), `80baa3a` (authenticated
browser writable opaque catalog), `7a93a9b` (an independently signed,
monotonically advancing mTLS/SQLite floor with owner V2 signer rotation),
and `da02715` (browser relay of independently signed witness/CAS heads).
These are *opt-in protected* paths and must not be conflated with ordinary
plaintext sync-v2, a physically independent deployed authority or provider
durability. The catalog still has a fail-closed 128-head limit; authenticated
logical delete/trash, complete account inventory and automatic safe legacy
cutover need their own end-to-end evidence before declaring 100% development.

Exact-HEAD hosted checks: Ubuntu Node22 full suite **2358 total / 2221 PASS /
0 FAIL / 137 SKIP**; real disposable PostgreSQL18 **PASS**; JS/TS analysis
**PASS**; dependency review **PASS**. Windows Node22's release gate was
**CANCELLED** after earlier steps had passed, not a proved assertion failure.
The separate CodeQL policy check remains **FAIL**; do not label it green or
silently dismiss its findings. The next validated HEAD must be checked again
after publication: CI results do not transfer between SHAs.

Local Windows Node24 on the same `da02715` checkpoint: focused browser,
owner revocation, authenticated catalog, multi-version Edge archive, session
fencing and rename selection **67 PASS / 0 FAIL / 0 SKIP**; real mTLS CAS,
owner signer rotation and re-endorsement selection **6 PASS / 0 FAIL**;
independent floor/CAS/Edge selection **17 PASS / 0 FAIL** (overlapping
selections, **not** additive coverage). `validate-syntax.js`: **513 checked /
0 failed**; `validate-runtime-artifacts.js` and `git diff --check`: **PASS**.
These local focused runs do not substitute for the hosted full suite.

The trust boundary still requires independent custody of out-of-band SPKI
pins, witness/floor keys and monotonic state. Distinguish Ed25519 receipts,
PostgreSQL local readback, SQLite WAL/FULL commits, HTTP ACK and actual remote
storage durability. No merge, deploy, production activation, plaintext-to-
server fallback or destructive migration cutover is authorized.

## Current development addendum — 2026-10-23, issue #65 / PR #228

**Additional integration after the published `0e571eb` milestone (local DEV
checkpoint `df7c8f2`, pending next coherent push):** `9239e52` adds real Edge
12-version archive creation and recovery assertions; `a8116a7` reconciles its
test fixture with separately integrated legacy signed transition; `aa8091e`
implements owner-local V2 revocation/epoch rotation requiring distinct
independently pinned witness and CAS commitment with fresh HPKE wraps only for
survivors; `e71ef3b` fixes a reproduced independently identified P2 browser
roster substitution (RED before fix, GREEN after, strict pin and exact signed
roster equality); `df7c8f2` adds the normal authenticated **read-only** ZK1
opaque catalog UI, owner-pinned page/delta visibility and signed version GET.
The combined checks on this local sequence yielded Node24 **70 PASS / 0 FAIL**,
Node22 pure crypto **19 PASS / 0 FAIL**, syntax **492 / 0**, and a separate
real Edge catalog+archive **11 PASS / 0 FAIL**. This is not a full-suite or
exact-head CI verdict. The previous published `0e571eb` passed Ubuntu Node22,
PostgreSQL18, JS/TS and dependency review, but the Windows Node22 job was
**cancelled during the release gate**; the CodeQL policy still listed 62 alerts.
Do not count a canceled job as a code failure, or static alerts as resolved.
The browser catalog still requires independently pinned CAS/owner authority
and user-imported head and remains read-only; owner revocation transfer is not
automatic proof of current full V2 grant/history or remote key custody.

**Independent catalog CAS development extension:** local commit `90932d7`
adds an explicit opt-in standalone mTLS HTTPS CAS service/client with a
separately pinned Ed25519 signing identity, trusted device-signed catalog
headers and encrypted pages, atomic local SQLite WAL/FULL persistence and
monotonic floor, writer competition, replay checks, bounded transport and
lost-ACK reconciliation. Its integrated Node24 catalog/Edge selection passed
**12 PASS / 0 FAIL**; focused Node22 owner/catalog crypto **9 PASS / 0 FAIL**;
syntax **499 / 0**. The separate standalone CAS service tests used actual
disposable OS child processes and mTLS, not cloud infrastructure. This is a
local physical SQLite durability boundary, **not proof of cloud fsync**, a
physically independent host or guaranteed operator control of the external
floor. External CAS and historical catalog recovery still require explicit
trust-pin provisioning and operator-owned records, not a server-supplied pin.

This is an additive development snapshot, not a revision of the dated phase
history below. The PR branch `cdx/rootark-dual-recovery-20261019` remains
`OPEN/DRAFT` with issue #65 open; no merge, deployment or production activation
is authorized. The last *verified published* code baseline before this addendum
was `0c9034c` (full Ubuntu Node22 2183 PASS / 0 FAIL / 136 SKIP; full Windows
Node24 local 2153 PASS / 0 FAIL / 166 SKIP, on the same code; local Windows
Node22 release gate canceled, not failed). That snapshot's CodeQL policy check
was red with 62 static findings, no new runtime P1/P2 confirmed by its focused
audit. None of those prior CI outcomes is a new-head verdict.

The active isolated issue #65 integration now includes local commits
`b6635a9` (metadata leakage register), `7d55c4c` (witnessed owner enrollment
CLI), `dd7cf11` (opt-in owner/device-signed opaque catalog with externally
pinned CAS head), `a4f63f2` (owner-signed per-version legacy transition state)
and `de94f1f` (normal-browser opt-in versioned archive, original per-version
ciphertext and CEK). Together they passed targeted local Node24 **78 PASS /
0 FAIL**, Node22 crypto **14 PASS / 0 FAIL**, and syntax **485 / 0**. The
catalog's two-device authenticated HTTP read is tested; this does not prove a
production authority, a complete protected bidirectional sync client or every
destructive mutation. Signed migration receipts permit verified state for
individually selected versions only, *never* deletion/cutover of legacy sources
whose references or retention are unknown. Default owner upload uses a
single-use CEK and is not inherently recoverable without user-held archive
material.

Still open in development: real end-to-end normal-browser catalog discovery and
delta sync, authenticated rename/move/delete/trash/conflict operations,
owner-signed witnessed revocation and epoch rotation ceremony, full account
inventory completeness and recovery UX, and cutover graph completeness for
legacy backup/trash/links/derived/retention. Absence of external provider
durability or physically independent witness evidence must remain explicitly
distinguished from local cryptographic and PostgreSQL proof. Do not mark issue
#65 100% done until each acceptance criterion has executable evidence. See
`docs/issue-65-zk1-runtime-leakage-register.md` for the current threat boundary.

Sync v2 historical admission development note (2026-10-24): a device's expired
Ed25519 authorization proves historical signing, not when a server admitted the
operation. The current CLI intentionally rejects never-observed expired
envelopes; only exact pre-expiry signed envelopes recorded in the local durable
journal can be replayed after expiry, subject to ongoing revocation. Legacy
`seen` IDs, HTTP success/opaque ACKs, unsigned server timestamps, and mismatched
push echoes do not constitute admission evidence. Conflicting envelopes using
the same `operationId` are rejected before remote-only snapshot or filesystem
mutation, including conflicts within a single pulled batch. Incoming envelopes
are detached from mutable transport references before asynchronous application.
Verified remote winners of 409 conflicts are also pinned by their own exact
envelope IDs only after snapshot persistence, not by the unsigned conflict ACK.
The journal is
local JSON. For materialization, local operation authorization, file-key resolution,
AEAD decryption and path validation precede the fsynced pre-expiry observation;
excluded/remote-only entries preserve signed-envelope-only observation without
requiring client-side file keys. Observations are fsynced before file/snapshot
mutation and only later promoted to applied admissions; a failed final journal write
retains the pre-observation across restart without falsely setting `seen`.
Outstanding pre-observations have a fail-closed limit of 10,000 without an
independent lifecycle/GC witness: prolonged failed applications can exhaust
this budget and block new entries. This remains a development availability
limitation, not an assurance of infinite historical retention.
The journal can be forged or rolled back by a filesystem writer; it is NOT
an independent monotonic witness, proof of external admission, or physical
PostgreSQL attestation. Independent Sync v2 admission receipts bound to the
ZK1 physical inventory/CAS/FLOOR authority remain an acceptance blocker.

Sync v2 to ZK1 physical-binding prototype (2026-10-24, isolated development):
`sync-client/rootark-sync-zk1-physical-binding.js` deterministically binds
the FULL canonical signed and encrypted Sync v2 envelope bytes (not a
server-provided flag) to a scoped ZK1 inventory operation, including
domain-separated 128-bit operation/object IDs, epoch/revision and SHA-256 of
the exact bytes to be physically stored as opaque ciphertext. Its opt-in
`physicalWriteRequest` prepares the existing bridge's exact gate request with
bounded 1 MiB ciphertext chunks and an authenticated chunk root, but requires
fresh, currently non-revoked client Ed25519 authorization before returning
any candidate write. It verifies
real Ed25519 client authorization and the existing independently pinned
inventory + physical PostgreSQL readback signatures, rejecting a different
valid signed envelope with the same operation ID. This is **pure
cryptographic interface validation**, tested with signed PG-proof-shaped
fixtures, **not a completed PostgreSQL write/attestation integration**. The
normal sync server and clients do not yet produce or consume this composite;
the PG ciphertext writer must be proven to store exactly those canonical
envelope bytes before it can be used normatively. The result explicitly does
NOT prove when the server originally admitted an expired operation, an
independently anchored monotonic floor, remote durability, or IO authority.
Only explicit `epoch-N` key epochs are interoperable with this prototype;
other epoch names fail closed rather than inventing a numeric mapping.

Isolated Sync v2 witness-admission verifier milestone (2026-10-25):
`verifySyncV2HistoricalWitnessAdmission` checks an independently pinned
Ed25519 witness signature over the full encrypted, signed envelope hash,
device identity and SPKI hash, operation ID, epoch, inventory checkpoint and
stable signed-inventory receipt digest. The signed witness `admittedAtMs` must
precede the device's signed expiry, and the verifier independently challenges
fresh PostgreSQL readback and a separate physically fenced witness head using
the caller-owned nonce. The fresh physical witness floor must match an exact
out-of-band pinned minimum, including its physical-fence digest; this
conservatively refuses later head advances until signed ancestry is supported.
The opt-in `independent-physical-witness-v1` CLI engine mode disregards mutable
local journal historical-admission evidence, MUST be enforced independently via
`requireIndependentHistoricalAdmission` or the external
`ROOTARK_SYNC_REQUIRE_INDEPENDENT_HISTORY=1` environment setting, requires separately injected
trusted keys/floor and an independent evidence provider, and refuses to start
without all. A JSON-only `historicalAdmissionMode` setting is rejected even if
evidence/pins are supplied: deleting it before restart would silently fall
back to forgeable legacy `locallyAdmitted` journal evidence. Removing the JSON
setting does NOT disable the externally required mode. Previously seen remote
entries are rechecked in strict mode,
because mutable `seen` journal IDs cannot suppress independent authorization
on a restarted LIST. Default CLI behavior remains unchanged. Fixture-level negative
tests cover forged signatures, replay, floor rollback, wrong device/checkpoint,
expired device signing and valid witness/PG signatures with wrong contents.
**Not a deployed issuance path or PostgreSQL integration:** no independently
durable admission-receipt issuer, real mTLS evidence adapter, witnessed
historical enrollment timestamp, externally retained post-restart floor, or
full signed ancestry for later witness heads exists. No production historical
admission guarantee or issue #65 GO can be claimed from this standalone
verifier. Do not bootstrap witness trust from the mutable local sync config.

Follow-up security validation (2026-10-25): the witness's signed admission
timestamp must be STRICTLY earlier than the device signature expiration (equal
milliseconds fail), and strict fresh verification checks expiration again after
asynchronous signature verification. Signer separation compares native Ed25519
KeyObject identities, bypassing attacker-defined `.export()` methods. Strict
mode now also requires a separately provisioned `localTrustedDevicePolicy`
containing username, device SPKI pins and current revocations; both historical
and fresh verification use that detached policy, and local outgoing revocations
cannot be lifted by editing the on-disk config. Without independent policy
custody the strict mode refuses to start; this is not a substitute for a
fresh network revocation source or durable independent floor retention.

Isolated Sync v2 strict witness historical-ISSUER development milestone
(2026-10-25): the opt-in `enableSyncHistoricalIssuer` mode of
`Zk1WitnessCasAnchorFloor` issues an independently witness-Ed25519-signed
historical receipt over the full canonical encrypted and device-signed Sync v2
envelope SHA-256, device ID and SPKI fingerprint, ZK1 operation ID, epoch,
inventory predecessor checkpoint, exact committed inventory receipt digest,
pre-device-expiry admission timestamp, and witness CAS/physical-fence head.
Issuance requires fresh device Ed25519 authorization and revocation check,
fresh independently pinned inventory and PostgreSQL-attestor signature proof
over the exact 32-byte **caller-provided challenge nonce** (the same challenge
is also signed into the witness physical floor), and an existing owner-authorized physically fenced CAS
terminal record whose operation ID, inventory sequence and root agree exactly.
It uses a separate witness-owned immutable SQLite receipt table with
`synchronous=FULL`, an Ed25519-signed and SHA-256 chained operation history,
unique operation IDs, and a mandatory **externally retained exact** historical
receipt high-water on restart (in addition to the external physical floor).
Duplicate issuance and missing/tampered historical rows fail closed.
The issuer has no default HTTP/Sync CLI wiring, grants no historical-read or
I/O permission by itself, and the receipt still needs a fresh independent
witness/physical check by a separately pinned client before historical use.
The issuer requires a witness-constructor-injected, operator-controlled
**synchronous** `trustedSyncDevicePolicyProvider` rather than a remote
operation's mutable device-policy object. Policy is re-read at commit, and
both the current signed device expiration and physical proof freshness are
rechecked inside the SQLite immediate transaction **directly before INSERT**;
post-Ed25519-signature expiration and late device revocation fail closed.
The time is sampled only **after** the synchronous trusted policy-provider
refresh and SQL statement preparation, and sampled again after INSERT while
the SQLite transaction can still roll back. An independently pinned non-genesis
historical high-water forbids fresh SQLite bootstrap. The published strict
`verifySyncV2HistoricalWitnessAdmission` verifier is used with the emitted
admission, fresh signed floor and ephemeral PG attestation using that same
nonce; wrong challenge, altered floor and substituted PG proof are rejected.
Only an active, opt-in strict witness issuer advertises the read-only
`supportsClientHistoricalNonce` capability used by the separate mTLS transport;
legacy floors and closed issuers advertise false.
Focused tests exercise signed and revoked device envelopes, forged inventory
proofs, operation/floor mismatch, replay, SQLite rewind/restart and a real
mTLS peer in a separate OS child **whose PostgreSQL readback is simulated**.
This is a local durable signing milestone, **not** a demonstrated production
PG18 end-to-end deployment, atomic PG-to-witness commit, owner-custodied
monotonic receipt floor, cross-provider external durability, or issue #65 GO.

Last reconstructed: 2026-07-25 (historical baseline)
Latest application-code snapshot for this closure: 2026-10-16 after PR #201 merged at `341804fa2bfd02dcd50f2d1bde560cb677fc27fd`. The [2026-10-16 pre-publication snapshot](validation/2026-10-16-rootark-prepublication-closure.md) records GitHub state and validation evidence queried after PR #199; it is historical and does not describe PR #201 or later commits. Track the final exact `Root/main` SHA and local validation for the documentation-only closure publication in the [final closure PR #202](https://github.com/bielxdh3/Root.ark/pull/202).

Repository: bielxdh3/root.ark

PRs #195–#201 are merged. This milestone includes the aggregate chunk-upload quota follow-up test (#199), the Windows WebDAV journal rename retry (#200), and the closure ledger/evidence reconciliation (#201). The [pre-publication snapshot](validation/2026-10-16-rootark-prepublication-closure.md) contains exact branch-head release-gate results and the remote Windows-job outcomes for #199–#200; those results do not transfer to later SHAs. PR #97 is merged as partial selective-sync work; issue #66 remains open. Use the [final closure PR #202](https://github.com/bielxdh3/Root.ark/pull/202) as the durable record for the exact final default-branch SHA and local validation.

Historical sections below preserve their original evidence and claims; they are not current live status. Validation statements are tied to their named SHA and do not transfer to later commits.

Historical canonical baseline HEAD at the 2026-10-01 reconciliation start: `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1` (`refs/heads/Root/main`). It is not the current default-branch SHA.

Historical reconstruction baseline retained for provenance: `4062f4c67bfda9d144aceb6dbbed539b8a917e4a` (2026-07-25).

## Historical live GitHub reconciliation — 2026-10-01

This dated section superseded older statements at the time it was written. Its issue, branch, and PR states are historical; use the current snapshot linked above for live state. Historical phase reports below retain their original dates and evidence boundaries.

- The live default branch was `Root/main` at `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`. At that snapshot GitHub had seven open issues (#63–68 and #94) and one open PR (#95).
- Issue #83 is closed. Its sensitive-name policy remains active: `.env`, credential/service-account names, and private-key/certificate extensions remain excluded from backup content and quarantine payload references. PRs #86 and #90 contain its completion evidence.
- PR #96 is merged at `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; its exact-head CodeQL analysis, dependency review, Ubuntu validation, Windows validation, and GHAS scan passed. This does not authorize a release.
- Issue #94 is represented by PR #95, which remains open. Exact head `95d99e4a934384fcfa2101dfc210741cd791a3d1` passes CodeQL, Analyze JavaScript / TypeScript, dependency review, Ubuntu Node 22 full validation, and Windows Node 22 syntax/tests. The focused upload-security suite passes 26/26, and targeted independent reviews approve parser ordering and server-generated staging-path identity/cleanup. Production replica topology is still unknown; the in-memory limiter and local-disk staging need shared/edge enforcement or confirmed single-process deployment before #94 can close.
- Issue #63 is an approved future feature tracker, not implementation authorization. The protected-index primitive exists, but the UI does not populate it; FTS5 and advanced search remain deferred until the searchable corpus, encrypted-index lifecycle, privacy leakage, and acceptance criteria are defined.
- Issue #64 is a future Android-client tracker, not implementation authorization. There is no Android/Gradle project or Android CI. A native implementation remains gated on a separate architecture/threat-model and protocol-compatibility test plan.
- Issue #65 approves the Zero-Knowledge direction and bounded cryptographic foundation; it does not establish a Zero-Knowledge runtime. Current uploads and server-side operations can still expose plaintext. Migration inventory, client authorization, recovery authority, mixed-mode window, and exact-head runtime/backup acceptance remain open.
- Issue #66 is approved but not complete. PR #97 implements selected-path reconciliation, remote-only state, and guarded cache/materialization flows. Metadata-only remote listing and pagination, a Files On-Demand native provider/UI, and a portable guarantee that eviction cannot race an external writer with an open handle remain missing.
- Issue #67 is approved but not complete: existing backups and sync revisions are recovery prerequisites, not a ransomware shield. Burst detection, a recoverable pause/review barrier, protected per-object recovery history, and authorized restore are absent.
- Issue #68 is approved but not complete: existing public links are single-file bearer links with expiry/limits, not operation-scoped capabilities. Protected-link delivery remains gated on least-privilege capability enforcement and owner choices for link UX, expiry, and recipient recovery.

## Historical reconciliation work after the live baseline — 2026-10-01

This addendum records the published work after the live GitHub baseline above. PR #97 remains open and unmerged; PR #98 was merged into `Root/main` at `1df5e4640d4aea7dc700f2088059f489c2e51af0`. Neither PR changes issue state or marks an issue complete. PR #95 remains open after all exact-head checks passed because production replica topology is still unverified.

- Issue #64 has a native-client architecture and threat-model document only. No Android application, Gradle project, build, or CI exists.
- Issue #65 has a Zero-Knowledge migration contract and a read-only inventory prototype limited to explicitly selected fixture files under an operating-system temporary directory. The prototype reports recognized legacy encryption modes using run-scoped opaque references; it does not inspect live application storage or establish migration readiness. Its four focused tests pass. Runtime migration, authorization, recovery authority, mixed-mode window, backup/restore acceptance, and the remaining owner decisions are still open.
- Issue #66 has a selective-sync implementation in PR #97 at `a6a33a92cd6902f303254e60031da4bdc04cec04`, including selected-path tracking, remote-only state, move-out reconciliation, and guarded cache/materialization flows. The focused `test/phase16-sync-engine.test.js` run records 31 passing tests and one platform-skipped test. The current list API still transfers complete remote records including ciphertext before local path filtering, so network payload transfer is not selective. Exact-head CodeQL, Analyze JavaScript / TypeScript, dependency review, and Ubuntu/Windows CI pass; an independent targeted review of the move-out change found no actionable findings. There is no Windows Files On-Demand provider/UI, metadata-only catalog, or paginated remote listing, and portable open-handle quiescence for eviction is unresolved. PR #97 and the issue remain open.
- Issues #67 and #68 have architecture/acceptance contracts only. No runtime protection or capability-sharing feature is implemented; the owner choices recorded in those contracts remain unresolved.
- PR #98 merged the previous documentation reconciliation. This update records the later #95/#97 checks and open acceptance gates above.

## Status labels

- `[DONE]`: implemented and supported by relevant validation evidence.
- `[ACCEPTED-LOCAL]`: reviewed and accepted for the bounded local engineering scope; environment, production, or publication acceptance may remain open.
- `[IMPLEMENTED-UNVERIFIED]`: code/documentation exists, but operational or regression proof is incomplete.
- `[CURRENT]`: active phase. New execution should stay within this phase.
- `[NEXT]`: next approved phase after the current gate.
- `[PARALLEL-DISCOVERY]`: product questions may proceed without runtime implementation.
- `[LATER]`: valid future work after prerequisites.
- `[BLOCKED]`: must not start until named prerequisites are complete.
- `[DECISION REQUIRED]`: requires an explicit product or architecture decision.
- `[DO NOT IMPLEMENT YET]`: recorded idea, not approved execution work.

A feature is not `[DONE]` merely because files, routes, UI, or documentation exist. Completion requires relevant tests, disposable-data validation, or an explicit manual validation record.

## Source-of-truth order

1. Current code and tests on the actual branch.
2. `docs/issue-ledger.md` for the latest verified live GitHub issue, PR, and default-branch snapshot.
3. This plan tree for phase order and historical acceptance evidence.
4. Dedicated security, architecture, operations, and validation documents.
5. GitHub issues for executable scope.
6. Historical chat context only as input, never as proof.

The issue ledger begins with the post-#174 GitHub snapshot and labels later changes as point-in-time evidence. Re-query GitHub for live state after that snapshot; older dated reconciliations below remain historical evidence.

Master Phase 0-16 ledger and independent local blocker taxonomy: `docs/issue-ledger.md`. The governing continuation supplies the original meanings for all phases; local statuses and evidence are reconciled there without converting design or historical evidence into acceptance.

## 0. Historical product snapshot

This product inventory was reconstructed before the 2026-10-07 live-state snapshot above. Treat its implementation labels as dated evidence rather than current release acceptance.

### Application identity

- `[IMPLEMENTED-UNVERIFIED]` Independent Node.js/Express file-management application currently exists in this repository.
- `[DECIDED]` D-001 keeps this repository actively developed as Root.ark while allowing only a future, explicitly designed and approved migration or selective reuse into BielOS. Track remaining relationship consequences in issue #10.
- `[HISTORICAL DECISION REQUIRED AS OF 2026-08-13; RESOLVED 2026-08-17]` Issue #4 later resolved the final product name as `Root.ark`; any future visual rebrand remains a separate owner/product decision.
- `[RECONCILED — historical 2026-08-13]` At that local reconciliation, GitHub reported `Root/main` and `origin/HEAD` resolved to `28747c6ebdac873650e2d5a3c6193824e7cc9985`. That SHA is historical; the current default-branch SHA is recorded in `docs/issue-ledger.md`. The `codex/folders-acl` references remain historical provenance. Issue #14 was locally closure-ready at that time; remote issue closure was not claimed.

### Verified code-level capabilities

The following are present in code or project documentation, but several require operational validation:

- `[IMPLEMENTED-UNVERIFIED]` User login with bcrypt and JWT.
- `[IMPLEMENTED-UNVERIFIED]` Login rate limiting, progressive delay, IP/username blocking, generic errors, analytics, and audit events.
- `[IMPLEMENTED-UNVERIFIED]` Role and granular permission handling.
- `[IMPLEMENTED-UNVERIFIED]` Logical folders and file-level permissions.
- `[IMPLEMENTED-UNVERIFIED]` Simple and chunked upload flows with pending approval.
- `[IMPLEMENTED-UNVERIFIED]` File versions, expiration, previews, downloads, public links, and access limits.
- `[IMPLEMENTED-UNVERIFIED]` Encryption modes and encrypted-file metadata.
- `[IMPLEMENTED-UNVERIFIED]` Analytics, dashboard, audit logs, CSV export, and WebSocket refresh.
- `[IMPLEMENTED-UNVERIFIED]` Local, S3, and Google Drive storage compatibility.
- `[IMPLEMENTED-UNVERIFIED]` SQLite repositories and JSON-to-SQLite migration with legacy fallback.
- `[IMPLEMENTED-UNVERIFIED]` Backup, automatic backup, restore validation, and pre-restore backup.
- `[IMPLEMENTED-UNVERIFIED]` Trash for files and folders with restore and permanent deletion.
- `[IMPLEMENTED-UNVERIFIED]` Suspicious extension blocking, optional ClamAV integration, and quarantine.
- `[IMPLEMENTED-UNVERIFIED]` WebDAV MVP.
- `[IMPLEMENTED-UNVERIFIED]` One-way local-to-server synchronization CLI MVP.
- `[IMPLEMENTED-UNVERIFIED]` Partial modularization into repositories, services, routes, middleware, and database modules.

### Known architectural condition

- `[IMPLEMENTED-UNVERIFIED]` `server.js` remains the central integration file and is several thousand lines long.
- `[BLOCKED]` Broad modularization is blocked until critical security fixes and automated regression coverage exist. Track in issue #5.
- `[IMPLEMENTED-UNVERIFIED]` JSON and SQLite modes coexist; rollback flexibility exists, but behavioral parity and drift require proof.
- `[IMPLEMENTED-UNVERIFIED]` The main README does not accurately describe the current product surface.

## 1. Governance recovery

### Phase 1.0: Repository control layer

- `[CURRENT]` Create a short root `AGENTS.md` defining scope, safety, token economy, reasoning, validation, Git, and output rules. Issue #8.
- `[CURRENT]` Create this `docs/plan-tree.md` as the phase source of truth. Issue #8.
- `[CURRENT]` Create `docs/codex-workflow.md` with planner, executor, reviewer, and orchestrator boundaries. Issues #8 and #12.
- `[CURRENT]` Create `docs/product-discovery.md` for explicit future product decisions. Issues #4 and #8.
- `[CURRENT]` Create an initial code-backed security findings record. Issue #11.
- `[NEXT]` Open and review the governance PR.
- `[NEXT]` Merge only after confirming the documents do not claim unverified runtime behavior as completed.
- `[NEXT]` Close issue #8 after the governance PR merges.

### Phase 1.1: Release discipline

- `[NEXT]` Require one coherent goal per branch and PR. Issue #12.
- `[NEXT]` Require starting/final SHA, changed files, validations, unvalidated items, and remaining limitations in completion reports.
- `[NEXT]` Require plan-tree updates only after evidence.
- `[NEXT]` Prohibit force-pushes, history rewrites, and accidental removal of newer user work.
- `[NEXT]` Record CI status for the exact final SHA once CI exists.

## 2. Security stabilization

No new product feature should begin before the minimum security gate in phases 2.0 through 2.3 is completed.

### Phase 2.0: Bounded security inventory

Issue: #11

- `[NEXT]` Confirm the exact current code paths for the known findings below.
- `[NEXT]` Inspect only adjacent auth, realtime, and rendering helpers for equivalent defects.
- `[NEXT]` Assign severity, preconditions, impact, remediation issue, and validation requirement.
- `[NEXT]` Do not change runtime code during the inventory.
- `[NEXT]` Update `docs/security/current-findings.md` with confirmed evidence.

Known starting findings:

- hard-coded fallback for `JWT_SECRET`;
- bearer token and permission metadata in browser `localStorage`;
- user-controlled dashboard event text rendered through `innerHTML`;
- JWT passed in the WebSocket URL query string;
- role and permission claims embedded for an eight-hour token lifetime;
- no confirmed functional 2FA despite the QR dependency;
- dependency and regression-test baseline incomplete.

### Phase 2.1: Critical configuration and XSS fixes

Issue: #1

Prerequisite: phase 2.0 inventory confirms exact surfaces.

- `[DONE]` Remove the hard-coded JWT secret fallback and replace dashboard user-controlled activity/error rendering with text DOM nodes; startup, login/dashboard, adjacent-surface, and malicious-payload browser evidence are recorded.
- `[DONE]` Fail startup safely when a required production secret is absent or unacceptably weak; the disposable startup acceptance harness verifies non-zero exit and sanitized configuration output for missing and weak secrets.
- `[DONE]` Preserve a safe local-development setup with an ignored `.env` pattern, trackable invalid-placeholder template, and explicit process-environment startup instructions using a fresh Node `crypto` secret.
- `[DONE]` Replace unsafe dashboard activity rendering with DOM/text rendering; the real analytics-to-dashboard malicious-payload browser proof confirms literal rendering and no execution.
- `[DONE]` Review only directly adjacent changed dashboard surfaces for equivalent injection sinks.
- `[DONE]` Add focused startup and rendering regression tests; rendering, session-bootstrap, direct startup acceptance, and malicious-payload browser validation are recorded.
- `[DONE]` Verify login and dashboard behavior after the fixes with the recorded disposable browser validation.

Completion evidence:

- missing/unsafe production secret prevents startup;
- explicit safe configuration starts correctly;
- malicious event fields display as text;
- no real secret is committed or logged;
- relevant tests or manual validation are recorded.

### Phase 2.2: Session, token transport, and authorization freshness

Issue: #2

Prerequisites: phase 2.1 complete and initial auth tests available.

- `[DONE]` Stop placing JWTs in WebSocket query strings; cookie-authenticated upgrades validate Origin and the current session user before events are sent. Focused checks and recorded disposable browser/WebSocket validation passed.
- `[DONE]` Design and implement one bounded cookie-authenticated WebSocket handshake.
- `[DONE]` Revalidate the current user and permissions on the server rather than trusting stale permission claims for the full token lifetime. Every authenticated HTTP request reloads the active identity and derives current permissions; active WebSockets recheck expiry, current identity, disabled state, and `sessionVersion` before the next authenticated message or send. The Phase 2.2 closure audit reconciled the representative permission-removal and expiry regressions.
- `[DONE]` Implement token/session revocation or versioning for password, role, permission, disable, and deletion changes. The shared `PUT /users/:username` decision increments persisted `sessionVersion`; JSON preserves a Git-ignored per-username generation ledger across restart, and SQLite retains/increments a soft-deleted row generation atomically on recreation. Old HTTP and active-WebSocket credentials remain revoked.
- `[DONE]` Browser sessions use secure HttpOnly cookies (`SameSite=Lax`) with CSRF checks for cookie-authenticated writes; the transport decision and browser-session threat model are documented in `docs/security/browser-session-threat-model.md`. Issue #2 is ready to close after the Phase 2.2 closure-audit PR merges.
- `[DONE]` Add representative tests for disabled users, removed permissions, expiry, revocation, and realtime authentication. `test/auth-security.test.js` proves permission removal, JWT expiry, JSON delete/recreate rejection of old HTTP and active-WebSocket sessions, and new-session success; `test/users-repository.test.js` proves repeated SQLite recreation advances generation. Shared update-path analysis establishes the same protection for password, role, permissions, and disabled-state changes without redundant per-field integration tests.

Completion evidence:

- no bearer token in realtime URLs;
- removed access stops within the approved bound;
- disabled/deleted users cannot retain indefinite access;
- existing authorized HTTP and realtime behavior still works.

Closure audit: `docs/security/phase-2-2-closure-audit.md` reconciles source, regressions, merged PRs #17/#19/#20/#21/#22/#23, and successful `Security Regression` runs through #23 (`30650435892`). Issue #2 is ready to close after this documentation-only audit PR merges.

### Phase 2.3: Engineering and dependency baseline

Issue: #3

- `[DONE]` Add repeatable `test` and static-validation scripts. A clean checkout runs `npm ci` then `npm run validate`; reusable package scripts perform complete first-party JavaScript syntax validation, `npm test`, and the locked high-severity dependency audit. CI invokes the same scripts in separate steps.
- `[DONE]` Establish one meaningful vertical slice of automated security regression tests; eight focused tests now cover session, browser-token, WebSocket, WebDAV, rendering, and Archiver compatibility boundaries.
- `[IMPLEMENTED-UNVERIFIED]` Add tests for authentication, authorization, path handling, upload safety, trash, and backup/restore boundaries in small steps; authentication, backup compatibility, disposable real-server simple-upload authorization, suspicious-extension quarantine, filename containment, file-trash lifecycle, and JSON-mode backup/restore coverage are covered. The backup regression proves representative `manageBackups` denial before archive/history/lock side effects, runtime-only JSON/upload inclusion, backup-recursion exclusion (`data/backups`), no absolute/traversal archive entry names, child runtime-root archive/history/restore confinement, module-checkout non-modification, binary download checksum equality, invalid-confirmation non-mutation, pre-restore backup, and a disposable JSON round trip; existing sensitive-path filters remain source-reviewed, while dedicated hostile/sensitive archive fixtures remain the next task. A focused SQLite test preserves a configured external database path. Cloud backup, scheduler behavior, retention pressure, hostile ZIP corpus expansion, and full production SQLite recovery remain unverified.
- `[IMPLEMENTED-UNVERIFIED]` Upgrade Multer and Express through compatibility-preserving changes; Express is upgraded and validated, while Multer remains a separate bounded follow-up.
- `[IMPLEMENTED-UNVERIFIED]` Review remaining dependencies in bounded groups rather than one mass upgrade; the current lockfile audit is clean, while continuing dependency review remains open.
- `[DONE]` Add GitHub Actions CI for clean install, syntax checks, automated tests, and dependency audit; `Security Regression` run `30600354792` succeeded against `666fcbe5aee30710b20a01e13b1a24c8c6313206`.
- `[DONE]` Ensure this validation baseline and CI never include or upload real databases, uploads, backups, quarantine contents, tokens, credentials, or generated runtime ledgers; tests use disposable fixtures only.

Completion evidence:

- clean checkout has a documented validation command;
- tests fail when protected behavior is intentionally broken;
- CI reports against the exact commit;
- dependency changes preserve existing behavior.

Next bounded issue #3 task: add focused hostile-archive restore fixtures that exercise the existing traversal, symlink, sensitive-entry, and checksum rejection paths without changing restore behavior.

### Phase 2.4: 2FA design and implementation

Issue: #9

Prerequisites: phases 2.1 through 2.3 and a product decision about 2FA scope.

- `[DONE]` Implement the bounded all-user-compatible TOTP mechanism in `src/services/totp.js` and `src/routes/auth.js`: authenticated enrollment/confirmation, RFC 6238 login challenge, recovery-code consumption, secure disable, and privileged reset.
- `[DONE]` Encrypt seeds with the existing application master-key boundary, hash recovery codes with scrypt, fail closed on missing/invalid key material, and avoid secret-bearing audit/response paths.
- `[DONE]` Preserve session-version revocation, cookie/CSRF checks, enrollment-only route fencing, realtime freshness, and JSON/SQLite user persistence through migration 5.
- `[DONE]` Add optional, role-required, and global-required policy modes without implicit all-user activation; default behavior for existing users remains optional/inactive.
- `[ACCEPTED-LOCAL]` `PHASE_10_TOTP_IMPLEMENTED_AND_SECURITY_REVIEW_APPROVED`: independent evidence records 52/52 focused auth/TOTP/security tests, 616/616 broad `npm.cmd test` in 38.2 seconds, syntax 88/88, runtime artifacts, `npm ci --dry-run`, `git diff --check`, targeted secret scan, and bounded disposable HTTP evidence passing. The subsequent fail-closed policy-configuration correction passed the broader auth/TOTP/security regression matrix at 51/51, including startup and dynamic HTTP/realtime invalid-configuration rejection. `npm audit` remains non-clean only for the pre-existing high `brace-expansion` advisory. The +301s→+600s future-iat change was test-only and production behavior was unchanged. Shared live policy re-evaluation, HKDF seed-key derivation, and no-store sensitive responses are covered. Browser automation, providers, production, remote CI, release, and publication acceptance remain open; see `docs/security/phase-10-totp.md`.

Phase 9 bounded foundation closeout: `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED` for the reviewed `rootark-zk-1` foundation at the starting SHA, with local crypto vectors now passing after dependency installation. This does not accept zero-knowledge migration/runtime/release behavior. Residual Phase 9 handoffs remain dependency provenance/reproducibility, integration/runtime migration, provider/browser/CI/production evidence, and independent review.

### Phase 9 runtime protocol compatibility — Issue #65

- `[IN PROGRESS]` Add a separately versioned authorization-manifest profile for HPKE sender setup: v2 `info` binds every static core field before setup, `hpke_enc` is bound by the HPKE KEM context, and v2 AAD binds the digest of the complete core after setup. Preserve exact v1 group-wrap bytes and reject unsupported manifest versions.
- Acceptance requires deterministic v2 manifest/info/AAD vectors; public RFC 9180 context setup followed by AAD-dependent sealing/opening; signature, scope, expiry, and replay checks; v2 replay may be claimed only by the compound opener after HPKE authentication; a tampered HPKE ciphertext must not consume a replay ID; plaintext may be returned only after an atomic replay claim; unchanged v1 group-sharing behavior; independent crypto/security review; and exact-head CI. This local step does not claim full ZK runtime migration or release acceptance.

## 3. Operational validation of existing features

Issue: #7

Prerequisites: critical security fixes complete and disposable local workspace available.

### Phase 3.0: SQLite migration and persistence

- `[BLOCKED]` Run migrations in a disposable workspace.
- `[BLOCKED]` Run JSON-to-SQLite import twice and prove idempotence.
- `[BLOCKED]` Verify users, permissions, folders, links, versions, audit, analytics, pending uploads, and encrypted metadata.
- `[BLOCKED]` Restart and confirm persistence.
- `[BLOCKED]` Record JSON fallback and dual-write limitations.

### Phase 3.1: Backup and restore

- `[BLOCKED]` Create a disposable backup containing controlled metadata and files.
- `[BLOCKED]` Verify manifest, checksum, exclusion of secrets, and retention behavior.
- `[BLOCKED]` Execute a restore only against disposable data.
- `[BLOCKED]` Verify pre-restore backup and restart requirements.
- `[BLOCKED]` Test traversal, absolute-path, and symlink rejection with safe fixtures.

### Phase 3.2: Trash and file lifecycle

- `[BLOCKED]` Verify file and folder move to trash.
- `[BLOCKED]` Verify restore conflicts and metadata preservation.
- `[BLOCKED]` Verify permanent-delete authorization.
- `[BLOCKED]` Verify public links, preview, download, versions, and cloud references do not bypass trash state.
- `[BLOCKED]` Verify cleanup behavior and restart persistence.

### Phase 3.3: Upload scanning and quarantine

- `[BLOCKED]` Verify safe file upload.
- `[BLOCKED]` Verify suspicious extension handling.
- `[BLOCKED]` Verify quarantine invisibility and access denial.
- `[DONE]` Verify unavailable ClamAV fails closed by default: simple, final-chunk, and WebDAV PUT uploads are quarantined with 503 before pending registration or approval; unknown providers fail startup; production rejects disabled or fail-open scanner configuration. Focused disposable regressions passed 4/4 in the follow-up worktree based on `dec7ef02f86adc07c7f17f7d834c7bed92026ca4`.
- `[BLOCKED]` Run live ClamAV validation only when the daemon is actually available.
- `[BLOCKED]` Verify simple, chunked, pending, preview, download, share, cloud-sync, and audit boundaries.

### Phase 3.4: WebDAV MVP

- `[BLOCKED]` Verify OPTIONS, PROPFIND, GET, HEAD, PUT, and MKCOL.
- `[BLOCKED]` Verify authorization and permission filtering.
- `[BLOCKED]` Verify expired, trashed, encrypted, version-internal, and unauthorized files remain hidden.
- `[BLOCKED]` Verify traversal rejection.
- `[BLOCKED]` Verify DELETE, MOVE, LOCK, and UNLOCK remain blocked as documented.
- `[BLOCKED]` Test an actual Windows mount where feasible.

### Phase 3.5: Synchronization MVP

- `[BLOCKED]` Verify initialization without saving passwords.
- `[BLOCKED]` Verify state, hash, mtime, and ignored-file handling.
- `[BLOCKED]` Verify new and changed uploads, pending approval, optional auto-approval, and token renewal.
- `[BLOCKED]` Verify the documented 8 MB limit.
- `[BLOCKED]` Confirm that download, deletion sync, conflict resolution, background service, and bidirectional sync remain unsupported.

### Phase 3.6: Validation report

- `[BLOCKED]` Create a dated report under `docs/validation/`.
- `[BLOCKED]` Mark each claim passed, failed, blocked, or not tested.
- `[BLOCKED]` Convert confirmed defects into separate scoped issues.
- `[BLOCKED]` Do not repair unrelated defects opportunistically inside the validation run.

### Phase 3 status reconciliation (2026-08-13)

The committed Issue #7 report at `docs/validation/2026-08-02-operational-validation.md` is the current historical evidence for Phase 3: it records 21 `PASS`, 0 `FAIL`, and 2 environmental `BLOCKED` claims for live ClamAV and an actual OS WebDAV mount, with no product failure. The existing `[BLOCKED]` lines in Phases 3.0–3.6 are preserved as a derived reproduction checklist, not a claim that the validated historical run never occurred. A fresh rerun remains environment-dependent and is not claimed by this continuation.

## 4. Architecture stabilization

Issue: #5

Prerequisites: phases 2.1 through 2.3 complete and relevant tests covering each extraction target.

### Phase 4.0: Responsibility map

- `[DONE]` Map routes, repositories, services, persistence paths, and shared helpers in `docs/architecture/current-server-responsibility-map.md` at the current default SHA.
- `[DONE]` Identify concrete duplicated authorization, path, JSON/SQLite, audit, and storage logic with classifications and locations.
- `[DONE]` Define an evidence-backed extraction order and select realtime authentication/notifications as the first bounded candidate.
- `[DONE]` Complete the mapping task without moving runtime code.

### Phase 4.0.1: Realtime transport contract coverage

- `[DONE]` Add focused public-contract coverage for rejected upgrades, connected-first ordering, exact event envelopes, notification source/timestamps, message-rate reset, heartbeat/idle termination, and child-process shutdown cleanup in `test/realtime-transport-boundaries.test.js`.
- `[DONE]` Validate the focused realtime suite twice at 7/7, the auth-security suite at 13/13, and the combined auth/realtime run at 20/20; syntax and `git diff --check` also passed at local HEAD `28747c6ebdac873650e2d5a3c6193824e7cc9985`.
- `[IMPLEMENTED-UNVERIFIED]` Buffered-client close remains not directly covered because a deterministic public fixture would require brittle backpressure forcing or runtime changes; browser, CI, provider, and production behavior remain outside this phase.

### Phase 4.1: Bounded extractions

- `[DONE]` Extract the realtime transport and notification fan-out boundary into `src/realtime/server.js`; retain thin compatibility adapters in `server.js`, preserve the shared `parseBoundedNumber` helper used by WebDAV, and leave producer call sites and public contracts unchanged.
- `[DONE]` Validate the extracted working tree with realtime transport 7/7 twice, auth-security 13/13, realtime/WebDAV meta-remediation 62/62, combined realtime/auth 20/20, syntax checks, and `git diff --check` at local base `28747c6ebdac873650e2d5a3c6193824e7cc9985`.
- `[IMPLEMENTED-UNVERIFIED]` Buffered-client close is not directly covered; browser, CI, provider, production, and remote-closure behavior remain outside this local phase.
- `[HISTORICAL]` Earlier disposable upload-scanning coverage included ClamAV-unavailable fail-open, fail-closed quarantine, clean INSTREAM parsing, infected INSTREAM quarantine, suspicious extensions, and path containment; the recorded focused suite passed 16/16 twice in that earlier working tree. The fail-open expectation is not the current safe default.
- `[IMPLEMENTED-UNVERIFIED]` Live ClamAV daemon/provider behavior and zero-knowledge client-side scanning remain unverified; current route regressions cover unavailable-scanner fail-closed behavior across simple, final-chunk, and WebDAV PUT entry points.
- `[HISTORICAL]` An earlier working-tree note recorded extraction to `src/upload-scanning.js` at local base `28747c6ebdac873650e2d5a3c6193824e7cc9985`. That module is absent at current base `dec7ef02f86adc07c7f17f7d834c7bed92026ca4`; upload scanning and quarantine are inline in `server.js` here.
- `[HISTORICAL]` The earlier extraction validation record remains attached to its local base `28747c6ebdac873650e2d5a3c6193824e7cc9985`; it is not evidence for the current implementation.
- `[DONE]` Validate the existing `services/cloudStorage.js` boundary with mock-only inventory contracts for S3/Drive prefix, parent, metadata, and duplicate-identity containment; `test/cloud-storage.test.js` passed 27/27 twice without provider credentials.
- `[IMPLEMENTED-UNVERIFIED]` No redundant cloud runtime extraction was made; external provider behavior and D-003/D-009 compatibility remain unverified.
- `[DONE]` Validate the existing direct-protocol WebDAV boundary with executable/oversize/abort, completed-journal recovery, crash-consistency, and meta-remediation suites (90/90 combined); no OS mount or runtime extraction was claimed.
- `[IMPLEMENTED-UNVERIFIED]` WebDAV remains inline because metadata journaling, cloud intent, and D-009 local-bridge requirements make a safe bounded extraction larger than this phase; mount/provider/production behavior remains gated.
- `[NEXT]` Execute the missing disposable JSON/SQLite parity, migration, and restart probes described in `docs/validation/2026-08-13-json-sqlite-parity-matrix.md`; native binding availability, full parity, and the final SQLite production policy remain environment- and owner-gated.
- `[BLOCKED]` Prefer existing partial boundaries rather than inventing a new framework.
- `[BLOCKED]` Preserve CommonJS, route names, response shapes, storage behavior, and UI contracts.
- `[BLOCKED]` Use one coherent commit per extraction.
- `[BLOCKED]` Compare behavior before and after with focused tests.

Potential extraction order after coverage exists:

1. realtime authentication and notifications;
2. upload scanning and quarantine;
3. cloud storage;
4. WebDAV;
5. file versions and lifecycle;
6. encryption;
7. remaining route families;
8. persistence-mode simplification.

### Phase 4.2: Persistence convergence

- `[DONE]` Validate focused SQLite recovery, migration-generation, trash-persistence, and archive/staging safety contracts: the disposable combined run passed 70/70 after rebuilding the native `better-sqlite3` binding.
- `[DONE]` Add the source-backed JSON/SQLite parity matrix at `docs/validation/2026-08-13-json-sqlite-parity-matrix.md`; it records the bounded 70/70 evidence and the remaining probes without claiming full parity.
- `[IMPLEMENTED-UNVERIFIED]` Targeted recovery/generation/transaction evidence does not establish complete JSON/SQLite parity, migration/restart coverage across every entity, or long-running production migration safety.
- `[DECISION REQUIRED]` Decide whether SQLite becomes mandatory for production; the parity matrix recommends it only after parity and migration acceptance and owner approval.
- `[DONE]` Record bounded migration, rollback, restart, and production-policy limitations in the JSON/SQLite parity matrix; implementation and full parity remain open.
- `[BLOCKED]` Remove legacy paths only after data migration and rollback strategy are proven.

## 5. Product discovery track

Issues: #4 and #10

This track may proceed conversationally in parallel with stabilization. Runtime implementation remains blocked until decisions are recorded and approved.

### Phase 5.0: Product identity and repository relationship

- `[DECIDED]` The final product name is `Root.ark`; any future visual rebrand or broader branding direction requires a separate owner/product decision.
- `[DECIDED]` D-001 keeps Root.ark active in this repository; future migration or selective reuse into BielOS requires a dedicated architecture, security, and contract phase.
- `[DECIDED]` Root.ark runtime, data, sessions, and authentication remain independent until an explicit integration is designed and approved.
- `[DONE]` Document the current independent Root.ark/BielOS boundary in `docs/architecture/rootark-bielos-relationship-contract.md`; Issue #10 was closed on 2026-08-17. Future integration, migration, identity, and key relationships remain owner-dependent and require separate approval.
- `[PARALLEL-DISCOVERY]` Existing features to preserve, redesign, or retire.

### Phase 5.1: Users and trust model

- `[DECIDED]` Private administrator-controlled storage and transfer service; accounts, compartments, and access are created or approved by an administrator, with no normal public registration.
- `[DECIDED]` Unrelated users may coexist only in rigorously isolated compartments; external links or keys do not create normal users.
- `[DECIDED]` D-004 defines bounded administrator powers, explicit time-limited audited support impersonation, and minimum metadata visibility without plaintext access.
- `[DECIDED]` D-003 selects client-side zero-knowledge protection for user content; the server and administrator do not normally receive plaintext.
- `[DECIDED]` D-005 defines direct administrator account creation, revocable expiring invitations, user-controlled recovery, default retention, and audited permanent deletion.
- `[DECIDED]` D-006 defines trusted-device and recovery-package authorization, compartment-isolated keys, future-content rotation, and authorized offline access.
- `[DECIDED]` Public account registration is not part of the approved model; isolated request or sharing surfaces require separate design and approval.

### Phase 5.2: File and storage behavior

- `[DECIDED]` Backups may preserve encrypted blobs and required metadata, but must not create an administrator plaintext-recovery path.
- `[DECIDED]` D-006 requires client-side key generation, compartment-isolated key sets, rotation for new content after access loss, and protected offline material on authorized devices.
- `[DECIDED]` D-007 requires per-file keys, isolated compartment hierarchies, mandatory recovery-package verification, explicit historical re-encryption, and future-authorization rotation after package compromise; the frozen Phase 8 technical profile records the accepted implementation parameters, while executable proof and product policy remain separate.
- `[DECIDED]` D-008 sets 30-day normal deletion and backup retention, immediate access revocation, and backup-aware cryptographic erasure that cannot be declared complete while service-controlled decryption material remains usable.
- `[DECIDED]` D-009 requires encrypted client-generated previews and indexes, server-blind sharing, local-bridge-only zero-knowledge WebDAV, and eventual mandatory bidirectional synchronization; the accepted architecture/migration contract is documented, while Phase 9 implementation and acceptance remain separate.
- `[DONE]` Record the accepted zero-knowledge architecture and migration contract at `docs/architecture/zero-knowledge-migration-contract.md`; the bounded Phase 9 foundation closeout is recorded below and full zero-knowledge migration remains separate.
- `[DONE]` Complete the independent Phase 8 security closure in `docs/validation/2026-08-14-rootark-phase8-independent-security-closure.md`; the verdict is `PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`, with the exact HPKE tuple, sender manifest, deterministic encoding, one-shot wrap construction, candidate policy, and residual risks frozen.
- `[DONE]` Close the bounded Phase 9 foundation as `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED`: the reviewed `rootark-zk-1` implementation and vectors pass locally after reproducible dependency installation; full zero-knowledge migration/runtime/provider/browser/CI/production/release acceptance remains open.
- `[DECISION REQUIRED]` Resolve only the genuine owner decisions: sharing/public-link UX, recovery authority, migration window/UX, and sync conflict UX. Primitive, envelope, nonce, library, vector, parser, and bounded 2FA policy choices are recorded technical/security decisions.
- `[IMPLEMENTED-UNVERIFIED]` Current server-readable encryption, metadata, previews/search, ClamAV, server-native WebDAV, sync MVP, and backup behavior remain legacy/current behavior and are not a claim that Root.ark is zero-knowledge today.
- `[PARALLEL-DISCOVERY]` Local, S3, Google Drive, or hybrid canonical storage.
- `[PARALLEL-DISCOVERY]` Approval workflow and intended purpose.
- `[PARALLEL-DISCOVERY]` Define the remaining sharing recipient, public-link, expiration, and limit details under D-009.
- `[PARALLEL-DISCOVERY]` Define the remaining version, restore, backup-key invalidation, and permanent-deletion mechanics under D-008.
- `[PARALLEL-DISCOVERY]` Define the remaining synchronization, conflict, offline, local-bridge, desktop, mobile, and PWA architecture under D-009.

### Phase 5.3: Privacy and operations

- `[DECIDED]` D-004 permits auditable security and operational logs with actor, IP, device, time, and action, without content, keys, decrypted names, or unnecessary sensitive data.
- `[DECIDED]` D-005 separates immediate access revocation from retained permanent deletion and requires reinforced confirmation for immediate destruction.
- `[DECIDED]` D-008 sets 30-day operational logs, 180-day security/audit logs, immediate access revocation, and truthful pending/completed states for backup-aware cryptographic erasure; detailed access, export, deletion, and privacy rules remain `[OPEN]`.
- `[DECIDED]` D-009 requires quarantine for unverified external uploads and preserves the zero-knowledge boundary for scanning, derived data, sharing, WebDAV, synchronization, and restore.
- `[DONE]` Public-link audit events correlate a link with a one-way SHA-256 token digest and do not persist the bearer token; route-level regression coverage is in `test/public-share-audit-security.test.js`. This closes the audit-secret exposure only; Issue #68 capability and zero-knowledge acceptance remains open.
- `[PARALLEL-DISCOVERY]` Define the remaining audit access, export, deletion, privacy, investigation-extension, quarantine, and operational ownership details.
- `[PARALLEL-DISCOVERY]` Data export and portability.
- `[PARALLEL-DISCOVERY]` Operational ownership, deployment, updates, and recovery.
- `[PARALLEL-DISCOVERY]` Features explicitly rejected or deferred.

### Phase 5.4: Approved product brief

The Round 1–3 status notes below preserve the local decision state at those checkpoints. Issues #4 and #10 were later closed in GitHub on 2026-08-17; the current issue status and remaining implementation gates are recorded in section 8.

- `[DONE]` Record approved Round 1 decisions D-001 through D-003 with consequences and follow-up dependencies; this checkpoint kept Issue #4 open pending final closeout.
- `[DONE]` Record approved Round 2 decisions D-004 through D-006 with consequences and explicitly open deferred details; this checkpoint kept Issue #4 open, while Issue #10's independent relationship was closure-ready locally and future integration remained owner-dependent.
- `[DONE]` Record approved Round 3 decisions D-007 through D-009 with consequences and explicitly open expert architecture and implementation details; this checkpoint kept Issue #4 open, while Issue #10's independent relationship was closure-ready locally and future integration remained owner-dependent.
- `[DONE]` Add `docs/architecture/rootark-bielos-relationship-contract.md` and `docs/architecture/zero-knowledge-migration-contract.md` for the high-risk relationship and zero-knowledge boundaries; these are architecture/threat-model deliverables, not runtime implementation or product acceptance.
- `[DONE]` Synchronize this plan tree with the accepted relationship, zero-knowledge, and parity documents while preserving owner-dependent choices, current implementation limitations, and dated local decision states as historical evidence.
- `[BLOCKED]` Do not silently reinterpret old implementation as the final product contract.

## 6. Feature backlog

Issue: #6

All items below are candidates, not commitments.

### Phase 11 backlog reconciliation — 2026-08-16

- `[ACCEPTED-LOCAL]` `PHASE_11_BACKLOG_RECONCILED` is recorded in `docs/roadmap/phase-11-backlog-reconciliation.md` for the exact accepted Phase 10 starting SHA `76f2a02cf6e3872ab2d7b61ff617021daf893c61`.
- `[DO NOT IMPLEMENT YET]` The canonical nine-item matrix maps current evidence, status, prerequisites, security boundaries, owner decisions, implementation boundaries, acceptance, validation, dependencies, and the required separate future issue for every candidate.
- `[DO NOT IMPLEMENT YET]` TOTP is reconciled to accepted Phase 10; bidirectional sync and WebDAV mutations target Phase 12; search, previews, PWA/clients, groups, and admin UX target Phase 13; deployment prerequisites target Phase 14. At the 2026-08-16 reconciliation, naming and branding remained an owner decision; Issue #4 resolved the product name as `Root.ark` on 2026-08-17, and any future visual rebrand remains a separate owner/product decision.
- `[HISTORICAL SCOPE]` No Phase 12+ source, test, migration, UI, dependency, synchronization, WebDAV, deployment, or product implementation was authorized by that reconciliation turn; later phase-specific authorizations and evidence are recorded below.

### Phase 12: ZK sync and local WebDAV bridge — 2026-08-16

- `[ACCEPTED-LOCAL]` Add the versioned client protocol with stable IDs, deterministic allow-listed metadata, AES-256-GCM/AAD envelopes, key epoch/compartment/device context, Lamport revisions, create/update/move/delete tombstones, and base-revision conflict semantics.
- `[ACCEPTED-LOCAL]` Add an atomic durable pending/seen journal with restart recovery.
- `[ACCEPTED-LOCAL]` Add the loopback-only bearer-protected local WebDAV bridge with containment/symlink/traversal checks, safe PROPFIND/GET/PUT/MKCOL/MOVE/DELETE, journal callbacks, and DELETE-to-trash behavior.
- `[ACCEPTED-LOCAL]` Add the authenticated, bounded, opaque `/sync/v1/objects` routes, including DELETE tombstone persistence, with per-user authorization, atomic persistence, conflict/replay/stale rejection, and no decryption/key handling; existing public WebDAV routes remain unchanged.
- `[ACCEPTED-LOCAL]` Record the independent 65/65 Phase 12 focused gate; the local executable slice passes 4/4. Broader dependency/provider/browser/production validation remains separate.
- `[BLOCKED]` Provider/browser/production validation, deployment hardening, release acceptance, and remote/owner review remain external to this local implementation.

### Phase 14: Deployment/adapters/resilience — 2026-08-16

- `[IMPLEMENTED-UNVERIFIED]` Add standard-library `/health` and fail-closed `/ready` adapters for JWT, explicit TOTP policy, master-key, and provider-critical configuration; responses are unauthenticated and sanitized.
- `[IMPLEMENTED-UNVERIFIED]` Normalize provider errors, cap retry/backoff and cancellation, provide idempotency helpers, and redact secret-bearing log/metric values.
- `[IMPLEMENTED-UNVERIFIED]` Attest protected sync records during sync-store restart, backup creation, and restore archive validation without decrypting ciphertext or accepting plaintext/key fields; preserve backup, trash, version, and route contracts.
- `[IMPLEMENTED-UNVERIFIED]` Focused failure-mode coverage is recorded in `test/phase14-deployment-resilience.test.js`; provider, dependency, native-binding, TLS, production, remote CI, and release gates remain open.

### Phase 15: Local release gate — 2026-08-16

- `[ACCEPTED-LOCAL]` Add `scripts/validate-release-gate.js` and preserve the exact Phase 14 starting SHA `bcf0861e3c6987331228816cb479ade525b3b555`.
- `[ACCEPTED-LOCAL]` Repair only the transitive `brace-expansion` lock resolution from 5.0.8 to the reviewed 5.0.9 registry tarball and integrity; package manifest parity and audit threshold remain unchanged.
- `[ACCEPTED-LOCAL]` The controlled pre-commit matrix records 13 passed, 0 failed, and 1 expected clean-worktree block. It covers lock/provenance, syntax, artifacts, diff, secret-material patterns, Phase 9 crypto, Phase 10 auth/TOTP, Phase 12 sync/WebDAV, Phase 13 client/groups, Phase 14 readiness/attestation, backup/restore, high-severity audit, and ciphertext-only evidence.
- `[BLOCKED]` Provider credentials/interoperability, browser/device behavior, live production/TLS/rollback, remote CI for the final commit, product approval, publication, and independent Phase 16 review remain external gates.

### Phase 16: Final security/quality review — 2026-08-16

- `[ACCEPTED-LOCAL]` Protocol v2 metadata AAD/schema enforcement, recoverable WebDAV overwrite journaling, bidirectional encrypted sync, strict client/offline boundaries, protected index/preview identity binding, and approved `rootark-zk-1` opaque group wraps are implemented and locally reviewed.
- `[ACCEPTED-LOCAL]` The controlled final-head cross-phase matrix recorded 66/66 tests passed, with separate realtime transport 4/4 and upload-security 12/12 boundary runs; syntax validation recorded 116/116 passed. WebDAV PUT has a distinct durable mutation event and explicit protocol-v2 translation, and the browser protected store now has an in-memory session hook.
- `[BLOCKED]` Canonical full `npm test` was attempted but remains blocked by the unavailable `better-sqlite3` native binding in the disposable install; remote CI, browser/provider/live-production/TLS, owner approval, and release evidence remain external.
- `[RECONCILED — 2026-10-06]` The previously unnamed Draft-PR statement cannot be mapped to a current live PR. PR #96 is merged; PR #95 remains open with its current CodeQL and Security Regression checks passing, while Issue #94's multi-process/replica enforcement gate remains unresolved. Merge state is not release authorization; no Phase 17 item is created or inferred.

### Authentication and administration

- `[ACCEPTED-LOCAL]` 2FA/TOTP Issue #9 is implemented and security-reviewed within the bounded local scope; final independent evidence is 52/52 focused and 616/616 broad tests, with remote/publication/release acceptance remaining separate.
- `[DO NOT IMPLEMENT YET]` Recovery and session-management UI.
- `[ACCEPTED-LOCAL]` Phase 13 adds authenticated group CRUD/membership with an atomic JSON store; `manageUsers` is required and folder `groupIds` add membership access without changing individual sharing.

### Search and previews

- `[DO NOT IMPLEMENT YET]` SQLite FTS5 content indexing.
- `[DO NOT IMPLEMENT YET]` Advanced filters.
- `[ACCEPTED-LOCAL]` Protected client index and preview services use browser AES-256-GCM and local decrypt-before-search/render; server search/preview behavior remains unchanged.
- `[DO NOT IMPLEMENT YET]` Thumbnail generation and lifecycle.

### Clients and protocols

- `[ACCEPTED-LOCAL]` Installable public-shell PWA, service-worker cache exclusions, encrypted client-local offline queue boundary, and opaque Phase 12 browser protocol adapter are present.
- `[ACCEPTED-LOCAL]` Bidirectional encrypted synchronization is implemented by the protocol-v2 `SyncEngine`; provider/browser/production acceptance remains external.
- `[ACCEPTED-LOCAL]` Deterministic remote-wins conflict handling, tombstones, retry, and deletion sync are covered by focused engine tests.
- `[ACCEPTED-LOCAL]` The protocol-v2 `sync:start` entrypoint runs the bidirectional engine; the legacy uploader requires an explicit development-only opt-in.
- `[ACCEPTED-LOCAL]` WebDAV PUT/MOVE/DELETE mutation events translate into strict protocol-v2 journal operations with trash/rollback protection.
- `[DO NOT IMPLEMENT YET]` Mobile client or mobile-specific strategy.

### Product and interface

- `[DO NOT IMPLEMENT YET]` Future visual rebrand or route/branding migration; none is authorized by the product-name decision alone.
- `[ACCEPTED-LOCAL]` Minimal groups admin section and protected-search/offline status panel are wired into the existing UI; no redesign was performed.
- `[DO NOT IMPLEMENT YET]` New product features proposed casually in chat without discovery and issue creation.

## 7. Documentation and release readiness

### Phase 7.0: Documentation synchronization

- `[LATER]` Rewrite README to match the actual stack and capabilities.
- `[LATER]` Add safe setup and environment-variable documentation.
- `[LATER]` Link backup, migration, trash, WebDAV, sync, scanning, and security documents.
- `[LATER]` Clearly label MVP limitations and unvalidated claims.
- `[LATER]` Remove references to dependencies or architecture that no longer exist.

### Phase 7.1: Release gate

- `[ACCEPTED]` Phase 8 independent security verdict is `PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`; the bounded Phase 9 foundation is now `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED`, while Phase 15 remains `RELEASE_GATE_BLOCKED_ENVIRONMENT`.
- `[BLOCKED]` Critical security findings closed or explicitly accepted.
- `[BLOCKED]` Repeatable tests and CI pass for the exact release SHA.
- `[BLOCKED]` Disposable operational validation completed.
- `[BLOCKED]` Backup and restore procedure proven.
- `[BLOCKED]` Secrets and generated data excluded.
- `[BLOCKED]` Deployment exposure and TLS/reverse-proxy configuration documented and verified.
- `[BLOCKED]` Product trust model and intended audience explicitly approved.
- `[BLOCKED]` Known limitations published honestly.

## 8. Immediate execution order

Issues #1, #2, #3, #4, #6, #7, #9, #10, and #11 were closed in the live repository state by 2026-08-17; their dated checkpoint notes remain historical evidence and do not imply that separately tracked future features are implemented.

1. `[NEXT]` Measure JSON/SQLite parity and migration/restart behavior with disposable fixtures; native binding availability and final SQLite production policy remain open.
2. `[DONE]` Structured product discovery Rounds 1 through 3 and decision D-010 are recorded; Issues #4 and #10 were closed on 2026-08-17. Future implementation still requires a separate approved issue and its prerequisites; Issues #63 and #64 do not authorize implementation.
3. `[BLOCKED]` Approve individual future features only after stabilization and discovery. Issues #6 and #9 were closed on 2026-08-17; any remaining or new feature work still requires its prerequisites, owner decisions, and a separate approved issue.

## 9. Plan-tree update rule

When completing a task:

1. verify the actual final commit and branch;
2. record the exact validations performed;
3. distinguish passed, failed, blocked, and not run;
4. update only the affected plan-tree items;
5. do not erase historical limitations;
6. link the PR, issue, validation report, or architecture decision;
7. select the next item based on remaining risk, not novelty;
8. stop instead of inventing filler phases.
