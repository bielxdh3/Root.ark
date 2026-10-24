# Root.ark #65 — CAS mTLS signed-manifest-history paging (experimental)

## Scope

The isolated durable CAS/status ledger already validates terminal seals and
the independently anchored status of all committed transitions when a caller
requests its latest manifest. However, that latest manifest alone is
insufficient for an independent device to verify an enrollment/revocation
chain. This milestone exposes **canonical raw signed manifest bytes** through
a bounded, scoped, mTLS `POST /v1/history` endpoint, using the *same*
`manifest` role as `/v1/manifest`. It adds
`getCommittedHistoryPage({scope,startRevision})` to the pinned HTTPS client.

Each page contains `headRevision`, `headDigest`, `startRevision`,
`nextRevision` and contiguous `entries`. The server refuses unregistered
scopes, invalid revisions, pending **locally registered CAS** reservations,
and foreign mTLS roles. The declared head and page bytes remain
**UNTRUSTED**, even over authenticated TLS: the server does **not** independently
establish witness freshness or anchored signed chain correctness for this
read. Only **8 MiB total raw manifest bytes** can be returned per page;
SQLite rows are streamed lazily instead of materializing full history. The
client rejects malformed or oversized JSON, invalid canonical base64url,
inconsistent page continuation, and missing entries. The additional client
`getCommittedHistory` fetches every contiguous page with one consistent
declared head and a 64 MiB / 4097-entry cap, but still returns **untrusted
bytes**, not a verified authorization object. Independent verification of
the *entire* signed chain using
`verifyRecoveryHistoryPublicV2`, independently pinned base receipt,
activation envelopes, and a fresh nonce-bound witnessed head **is still
required separately before authorization**.

## Evidence

- TDD RED: real mTLS test lacked `getCommittedHistoryPage` and failed.
- Real pinned-mTLS CAS test: exact genesis bytes, head digest/revision,
  denied foreign principal/account/keyring, invalid start revision, and
  valid peer sending a contradictory continuation are all exercised.
- Durable CAS + witness test: three genuine signed transitions (genesis,
  device enrollment, revocation), exact bytes, and withholding the page
  while an already registered CAS reservation is pending.
- TDD RED/GREEN for full-chain transport across **three individually paged
  mTLS responses**. The client rejects a changed declared head across pages.
- Reviewer identified CPU/memory amplification from calling the full CAS
  history auditor for every untrusted page. A second RED/GREEN regression
  proves `getCommittedHistoryPage` is independent of
  `getCommittedManifest`. It now takes a small read transaction and does
  **no signature-validation or release decision**. The separate legacy
  `getCommittedManifest` read received SQL size/count preflight guards
  before its full-ledger materialization to deny oversized corrupted DB
  rows; it is still not a general-purpose streaming history verifier.
- Targeted Node: `node --test test/issue-65-cas-status-mtls-http.test.js
  test/issue-65-cas-witness-content-e2e.test.js
  test/issue-65-authority-https-pin-reuse.test.js` — 3/3 PASS.

## NO-GO boundaries

This code does **not** automatically promote history into trusted device
authorization. It has no independently deployed multi-host CAS/witness or
global monotonic device provider, does not prove client-secure key custody,
does not atomically link signed ciphertext approval + nonce tombstone +
provider physical GET/PUT, and does not authorize production. The caller must
reject absent, truncated, repeated, forked or mutated pages; one page or a
valid-looking latest manifest alone cannot authorize recovery/protected I/O.
The authority-root and client integration gates of issue #65 remain open.
