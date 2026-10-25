# Issue #65 — owner revocation versus independent CAS/FLOOR (2026-10-25)

**Status: P2 reproduced; NO-GO for strict atomic revocation fencing.** This
document reports an unsolved authorization ordering gap. It does **not** claim
that CAS, FLOOR, and the owner witness commit in one transaction. No production
protocol, schema, authorization check, or protected-mode requirement was
weakened or changed in this investigation.

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

## Required external contract before implementation

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
workaround as a security fix. Until such a protocol exists, the conditional
revocation race remains **NO-GO**. The temporary RED instrumentation was
reverted; the original positive/revoked-signer regression must continue to
pass unchanged.
