# Issue #65 — owner revocation versus independent CAS/FLOOR (2026-10-25)

**Status: P2 reproduced; NO-GO for strict atomic revocation fencing.** This
document reports an unsolved authorization ordering gap. It does **not** claim
that CAS, FLOOR, and the owner witness commit in one transaction. No currently
used CAS/FLOOR protocol, schema, authorization check, or protected-mode
requirement was weakened or changed. An isolated opt-in **witness-side**
prerequisite is implemented below, but no existing deployed flow invokes
it or treats it as an authorization guarantee.

## Exact base and boundaries

- Baseline: `c0fd8cd6692b5df228d147b70991155878a987fb`.
- CAS admission: `src/services/zk1OpaqueCatalogCasLedger.js:603-665`.
  `#verifyOwnerEvidence` checks a newly challenged, independently signed
  current witness head in `:420-434`; the local FULL CAS snapshot subsequently
  commits in `:634-665`. The durable local `owner_authority` row can reject
  revisions previously observed by that **same** database but is not
  synchronized with an owner revocation committed independently.
- Independent floor: `src/services/zk1OpaqueCatalogIndependentFloor.js:343-396`.
  It requests a fresh signed witness head in `:347-359`, then validates the
  signer and performs its own IMMEDIATE/FULL SQLite transaction in `:383-396`.
  There is no shared lock, reservation, conditional owner-epoch token or
  fencing primitive spanning the remote witness and floor transaction.
- `src/services/zk1OpaqueCatalog.js:505-521` invokes the browser/session
  guard before the external CAS POST, not while the witness and FLOOR execute.
  The browser `beforeCasAdmission` probe in
  `test/issue-65-browser-opaque-catalog-commit.test.js:617-645` ensures a
  revoked local grant prevents sending a POST *when already observed*, but
  does not atomically fence a remote revocation **after** the POST.

## Reproducible adversarial schedule — real disposable CAS/FLOOR/mTLS

Temporarily instrument
`test/issue-65-opaque-cas-signer-rotation-mtls.test.js` inside its existing
valid signer-A / signer-B fixture; **do not commit the failing test as a
passing security guarantee**:

1. Establish the initial valid A-signed CAS head at sequence 1, owner witness
   revision 2, with real private `authority.sqlite` and `floor.sqlite`.
2. Build another valid A-signed sequence-2 proposal from the still-active
   owner revision 2.
3. In the shared fixture's `ownerTrust.freshWitnessHead({nonce})` callback,
   return a cryptographically signed revision-2 head at the CAS's own fresh
   witness check. At the FLOOR's next independent fresh witness check,
   construct its **valid signed revision-2 response**, then
   `await fixtures.appendDeviceRevocation(state, "trusted-0")`, advancing
   the independently modeled owner/witness state to revision 3 and revoking
   signer A **before the old response is returned**.
4. Permit FLOOR's previously awaited response to resolve; request
   `client.compareAndSwap(proposal)`. Require no ACK and no floor advance.
5. Inspect `floorLedger.inspect()`, its durable `owner_authority` row and the
   current owner/witness fixture revision *after* the request.

The temporary TDD instrumentation was limited to two additions inside that
single preexisting test: replace its `ownerTrust.freshWitnessHead` callback
with the following shared callback, retaining all other ownerTrust fields:

```js
let adversarialRevocation = false;
let admissionReads = 0;
let revokedBeforeFloor = false;
// ownerTrust.freshWitnessHead = ...
freshWitnessHead: async ({ nonce }) => {
  const oldSigned = await witnessed(nonce);
  if (adversarialRevocation && ++admissionReads === 2) {
    await fixtures.appendDeviceRevocation(state, "trusted-0");
    revokedBeforeFloor = true;
  }
  return oldSigned;
}
```

Immediately after the fixture's first successful A-signed CAS
(`first = { sequence: 1, digest: initial.nextDigest }`) and *before*
its existing scripted revocation, inject this expectation:

```js
const raced = await build(0, first);
adversarialRevocation = true;
let acknowledged = false;
try {
  await client.compareAndSwap(raced);
  acknowledged = true;
} finally {
  adversarialRevocation = false;
}
const owner = floorLedger.db.prepare("SELECT revision FROM owner_authority").get();
assert.deepEqual({
  revokedBeforeFloor,
  acknowledged,
  floorSequence: floorLedger.inspect().sequence,
  witnessRevision: state.headManifest.revision,
  floorOwnerRevision: owner.revision,
}, {
  revokedBeforeFloor: true,
  acknowledged: false,
  floorSequence: 1,
  witnessRevision: 3,
  floorOwnerRevision: 2,
});
```

Executed on Windows Node 24 using:

```powershell
$env:NODE_PATH='E:/servidor/.worktrees/fix-idempotency-key/node_modules'
node --test --test-reporter=spec --test-name-pattern='mTLS independent CAS rotates owner-granted signer' test/issue-65-opaque-cas-signer-rotation-mtls.test.js
```

**Deterministic RED result (actual):**

```text
revocationDuringRemoteFloor = true
witnessRevision             = 3   (signer A revoked)
acknowledged                = true   <-- unacceptable
floorSequence              = 2      <-- durable FLOOR advance
floorOwnerRevision         = 2      <-- stale accepted owner grant
```

The assertion demanding `acknowledged=false` and `floorSequence=1`
failed, showing that a signed, nonce-bound but already-obsolete fresh witness
head can be accepted during an asynchronously overlapping commit. The
cryptographic witness heads were signed with fixture witness keys; the
revision change in this probe is made in the test fixture, **not in a
separate production-backed durable witness SQLite database**. CAS and FLOOR
SQLite files, their commit paths, HTTPS/mTLS connections and resulting CAS ACK
are real. Thus this is deterministic evidence of the authorization
interleaving accepted by the implementation, **not** a multi-host production
simulation or proof of the actual witness's physical durability.

## Why a local second check is not a repair

An extra `freshWitnessHead` immediately before or after `transaction.immediate()`
still has an interval before the independently committed owner revocation.
Holding CAS's SQLite `BEGIN IMMEDIATE` cannot lock the witness; FLOOR's
`BEGIN IMMEDIATE` cannot lock the witness either. A postcommit recheck might
withhold an ACK, but would still leave an independently durable invalid FLOOR
transition and trigger ambiguous recovery; it does **not** establish atomic
authorization fencing. Local `owner_authority` monotonic checks detect a
known newer revision, not an unobserved concurrent external revision.
Similarly, a browser/session guard cannot reverse a remote commit.

## Developable portion: witness-side durable admission prerequisite

An opt-in witness-side reservation precursor now exists in
`src/services/zk1DurableWitnessLedger.js`, with adversarial fixtures in
`test/issue-65-witness-catalog-fence-partial.test.js`. This is **NOT** the
missing cross-host revocation fence:

- Only a **newly bootstrapped** witness SQLite explicitly configured with
  both `catalogFloorPublicKey` and a **distinct, independently provisioned**
  `catalogPolicyPublicKey` creates the new pinned
  `witness_catalog_identity`, immutable `witness_catalog_admission` and
  immutable `witness_catalog_terminal` tables. There is no automatic
  migration of existing witness files, **including the older W20 FLOOR-only
  schema**; a pre-W25 catalog database cannot be automatically authorized.
  An already opted-in W25 database must reopen with the exact original FLOOR
  **and independent policy** public keys or fail closed. The
  persisted identity and immutability trigger targets are checked on restart.
  **Post-W25 terminal-seal hardening changes this fresh-only schema again**:
  old witness catalog databases without `terminal_seal` fail closed and
  require separately reviewed migration; do not add missing columns by hand.
- `beginCatalogAdmission` now requires a domain-separated Ed25519 policy grant
  verified under that pinned external policy key, binding the exact scope,
  operation, committed owner revision/digest, signer device, epoch, sequence,
  catalog digest, CAS key fingerprint, authenticated-transport principal,
  expiry, issuance time and a 32-byte nonce. Unauthenticated/mismatched/stale
  grants cannot insert an ACTIVE row; used nonces are unique per scope and
  permanently retained. This method does **not** authenticate the caller's
  transport, discover device membership, independently prove epoch or issue
  the external grant. Only the real independent policy authority, when
  implemented and audited, may make that authorization decision. With no
  independently provisioned policy key the opt-in gate fails closed.
- After that independent external-policy grant check, `beginCatalogAdmission`
  verifies the committed witness revision/digest
  and no pending owner/quiescence transition. The **same** witness SQLite
  `BEGIN IMMEDIATE` as owner reservation commits a FULL-durable, signer
  device + owner revision/digest + epoch + operation ID + catalog
  sequence/digest + CAS fingerprint + principal + expiry-bound signed grant.
  While active it blocks owner `reserve`, and `prepareQuiesce` cannot
  report DRAINED.
- Identical START replays are idempotent only with the same externally signed
  policy grant, without extending deadline or changing authorization. On
  QUIESCING, owner HEAD advance or expiry, a previously ACTIVE identical START
  may return only `{admissionId, proceed:false}` for recovery/cleanup: no new
  grant, floor nonce or ticket is issued; no SQLite state changes, new work,
  revocation bypass or implicit unquiesce. The original signed grant is still
  bound to the immutable admission and may not be substituted. Once
  a terminal is durably stored, exact-byte FINISH replay remains idempotent
  across revocation/owner HEAD advance, restart and expiry, without creating
  any fresh authority; a different terminal is denied. Expiry/restart never
  silently erases an unresolved ACTIVE record: owner revocation remains
  blocked. A legitimately policy-authorized but unresolved operation can still
  halt revocation indefinitely until independent audited reconciliation exists.
  This is a deliberate safety stop; granting automatic timeout release
  without physical CAS evidence would reintroduce the race.
- A FLOOR terminal is checked against the exact original admission and pinned
  FLOOR Ed25519 key **before storage**. The witness then signs a separate
  domain-specific immutable `terminal_seal` over the full saved admission
  binding and exact FLOOR bytes. Its seal is checked synchronously at startup
  and under the owner writer's `BEGIN IMMEDIATE` lock before every
  completion-count/quiescence/reserve decision; terminal FLOOR Ed25519
  signature and fields are independently reverified on the associated read
  path. A direct SQLite `INSERT` containing untrusted FLOOR bytes, even when
  `PRAGMA quick_check` reports `ok`, therefore causes **DENY** instead of
  subtracting an ACTIVE physical job from the count. SQLite cannot prohibit
  direct INSERT while allowing the trusted writer to insert; it is the
  witness-owned signature and repeated binding verification that prevent
  forged rows from authorizing owner revocation.
- `completeCatalogAdmission` only accepts a new token-specific Ed25519
  FLOOR terminal signature pinned to admission ID, operation ID, owner
  revision/digest, device, epoch, catalog head, nonce and expiry. A generic
  signed FLOOR read/head **cannot** release it. **Today's FLOOR does not
  issue this terminal type**. Fixture-signed terminals test the verifier
  only, not a real independent FLOOR commit.

No production CAS or FLOOR endpoint consumes that signed grant, no mTLS
route binds authenticated peer identity to its principal, no normative
externally signed terminal is emitted, and unresolved/expired admissions
have no independently proved audited recovery. The existing unguarded
remote CAS path still exists. Do **not** enable this laboratory capability
in production or call this a resolved race.

## Required external contract before production implementation

A dedicated independently durable owner authority must linearize **both**
owner revocation and catalog authorization. An acceptable design needs an
authenticated, scope+signer+revision+digest-bound, replay-proof **conditional
grant/reservation** with a monotonic generation/fencing token; revocation must
serialize against outstanding authorizations, and FLOOR CAS must validate
and consume the token with an explicit, crash-recoverable finalize/reconcile
protocol that cannot acknowledge an order forbidden by the witness.
Expiration, replay, dropped ACK, restart, failed revoke/commit, and
independently operated hosts require adversarial real-storage tests. The
current `freshHead` API is only a signed read, not that transaction protocol.

Do not gate off existing assertions, weaken cryptographic checks, invent a
simultaneously atomic cross-DB quorum claim, or ship a cosmetic fresh-read
workaround as a security fix. Until the independent FLOOR consumes and
terminally attests a witness-issued grant and every CAS admission enforces
it, the conditional revocation race remains **NO-GO**. The temporary RED
instrumentation was reverted; existing positive/revoked-signer regressions
continue unchanged.
