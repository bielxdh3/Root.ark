# Issue #65 ZK10: account-wide legacy downgrade gate (W101 research)

Status: **architecture blocker**, no cutover enabled or asserted. Scope: published
PR235 `31190a7d` and PR236 `a4bfc0c2`. This is a design/test contract,
not a signed grant, a migration receipt, or release authorization.

## Demonstrated state

- `src/routes/sync.js:831-854` exposes legacy object list, GET, POST, PUT
  and DELETE using the ordinary authenticated account and permissions. The
  legacy wire `metadata.name/path` is server-readable. Its existing signed
  device registry protects certain writes; it does not certify ZK cutover.
- `src/routes/zk1ProtectedObjectRoutes.js` explicitly mounts opt-in,
  scope-resolved ciphertext APIs separately, with no link to the legacy gate.
- `public/client/rootark-zk1-legacy-transition-receipt.js` signs ONE pinned
  legacy source version and returns `authorizesCutover: false` and
  `wholeCorpusVerified: false`. Its reference inventory remains `unknown`.
  `src/services/zk1LegacyArchiveStageWitness.js` likewise forbids treating
  stage receipts as a cutover capability.
- A signed owner inventory head and independent monotonic witness/CAS floor
  establish other protection properties, but the observed head/receipt schemas
  contain no owner-issued, signed **`protected_enforced` monotonic,
  account-wide cutover** decision with a persistent no-legacy-downgrade grant.
  The application cannot infer that grant from protected PUT, user JWT, local
  enrollment flag, successful migration of one object, or an operator toggle.
- Legacy servers have already received server-readable filenames, metadata,
  and possibly plaintext through ordinary files, previews, backups, trash,
  search indexes or other references. A future `protected_enforced` cutover
  cannot erase knowledge or external copies that already exist; its guarantee
  is prospective prevention of covered legacy access and writes.

## Required trust contract before implementing a route fence

1. Define an explicit, domain-separated **owner-signed `protected_enforced`
   account-wide cutover authorization**, bound to immutable legacy-account
   identity and canonical ZK `account_id`. Its signed statement must bind
   exact covered compartments, protocol/suite, monotonic **account** generation,
   prior head hash, signed inventory/corpus completeness, non-legacy egress
   scope, nonce, and migration/reference disposition. Once the independent
   authority accepts `protected_enforced`, the account's state cannot regress
   to legacy/mixed through revocation, owner/device rotation or client request.
2. Bind login's server-authenticated `username` and durable account
   identity to the ZK `account_id` through an independently pinned,
   immutable mapping or verified owner enrollment. Account rename,
   username recycling, account deletion or database restore cannot rebind or
   remove that association. An arbitrary JWT claim, `req.body`, local DB
   flag, or user-selected account ID is not authority for this mapping.
3. Commit that owner statement at a genuinely **external custody**,
   independently administered monotonic CAS/witness, with separately
   controlled keys and independently retained minimum/floor. Verify its
   *current* head under a fresh nonce and pinned transport/signatures; local
   fixtures or a co-hosted test witness do not establish independent custody.
   Both cutover and enforcement survive process restart, DB restore, witness
   rollback and owner/device revocation. A stale, missing, conflicting, or
   unreachable current head fails closed **for previously enrolled accounts**.
4. Resolve uncutover/legacy accounts with a cryptographically verified
   **never-enrolled negative membership proof** under the *current* external
   authority head, bound to the immutable account mapping. A missing record,
   absent local flag or 404 is not a non-membership proof. If the service can
   delete its enrollment flag and then assume legacy, a formerly protected
   account can be downgraded. Resolve this before classifying unknown as legacy.
5. Gate ALL covered server-readable egress/write routes under the same
   authoritative decision and ordering boundary, including both Sync GETs,
   POST/PUT/DELETE, native WebDAV, ordinary preview/search/download, sharing,
   backup/restore, derived artifacts and legacy compatibility adapters.
   Revalidate immediately before bytes leave the server, including streaming
   and async authorization races, and before durable writes. Return a bounded
   403/409 for authenticated, definitively enforced access; use 503 when
   current authority cannot be established. No plaintext fallback.
6. Existing users who never opted in remain on legacy behavior. During an
   owner-approved migration window expose only specifically granted
   compatibility actions and label them legacy/mixed; never report full ZK.
   A completed cutover must not be undone by a password reset, session replay,
   missing local state, old backup, or request header. Report historical
   server-readable plaintext/metadata exposure and uncontrolled legacy copies
   as residual, non-reversible limitations even after enforcing the fence.

## Exact HTTP TDD acceptance after authority protocol exists

Use real `POST /auth/login` to issue JWT; test authenticated same-account,
other account, invalid token and revoked session. Seed ordinary legacy Sync
metadata and protected ciphertext for one account. **Positive:** an
independently proven, never-cutover account retains legacy list/read/write,
and scoped intentional migration reads work only for their signed window.
**Negative:** owner cutover signed/committed to the independent CAS/witness
rejects same-account list, object GET, POST/PUT/DELETE, native WebDAV and
ordinary preview even with a previously issued valid bearer, while unrelated
legacy accounts still work. Repeat after restart, forged local state, rollback,
revoked device, missing head, unreachable/lying witness, epoch advance,
cross-account mapping, and concurrent cutover vs in-flight read/write; prove
no bytes escaped. Reject malformed or forged signatures, incomplete corpus,
stale generation, wrong scope and replay. Verify with externally pinned
current head and independently retained minimum, not in-process fake state.

The focused `test/issue-65-w101-legacy-jwt-http-characterization.test.js`
proves the **current legacy behavior** with a real auth-issued JWT; it is not
the blocked cutover RED. A genuine fail-closed RED requires the currently
missing owner cutover authority protocol and an external head fixture.
