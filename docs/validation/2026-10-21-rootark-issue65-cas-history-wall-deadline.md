# Root.ark issue #65 — bound pinned CAS history wall time

**Scope:** development-only CAS manifest/history mTLS client. Transport
deadlines do not grant release, prove independent operators or authorize
production protected I/O.

## Confirmed P2 starvation

`https.request({ timeout })` limits socket inactivity only. A pinned CAS peer
could send one byte periodically without completing the JSON response,
keeping the request alive indefinitely. Separately, `getCommittedHistory`
accepted up to 4,097 individually timely pages without a total deadline.
When two signed-history authorization requests hung, the protected store's
two expensive-verification slots stayed occupied and other valid requests
failed closed with 503 until the promises finally resolved.

The real HTTPS fixture signs in with an mTLS client certificate, pins the
server's SHA-256 certificate fingerprint, then sends whitespace chunks every
25 ms without ending `/v1/manifest`. The per-request inactivity timeout of
150 ms never fires in the old code. A second adversarial endpoint returns
one valid history entry after 110 ms on each of eight pages, defeating
per-request 150 ms limits while exceeding the requested history budget.

**RED:** the trickle request was still pending after 500 ms rather than
rejecting. The test failed deterministically while preserving fixture cleanup.

## Correction and GREEN

Each CAS manifest/history response now has an absolute wall-clock timer in
addition to its socket inactivity timeout. On deadline, the request is
destroyed and rejects as `CAS_MANIFEST_TRANSPORT_UNAVAILABLE`, freeing the
caller and its signed-history concurrency slot. All success and rejection
paths clear the timer. The history aggregator starts an end-to-end monotonic
deadline using `performance.now()` and passes remaining time to each new
page request. Default history budget: 120,000 ms, configurable between
100 and 300,000 ms. Each individual response remains capped by `timeoutMs`
(default 15,000 ms; range 100..30,000 ms). These finite defaults also
allow a legitimate 8 MiB raw (~10.7 MiB base64 JSON) CAS page on a
~10 Mb/s connection and a 64 MiB raw history on the same link, rather than
turning a slow but continuous valid transfer into an automatic denial.
The normal application's development/test-only `cas` bootstrap configuration
can specify optional `timeoutMs` and `historyDeadlineMs` in the same bounded
ranges. Unknown, mistyped, or out-of-range fields fail before opening the
content database; existing five-field CAS configuration remains accepted.

Regression evidence:

- `node --test test/issue-65-authority-https-pin-reuse.test.js`
  — GREEN 2/2 PASS (one existing TLS-pin reuse test + new adversarial test).
  The new test counts multiple valid pages before a short aggregate deadline
  and verifies the same eight-page history succeeds when given sufficient
  aggregate time. It also confirms the hostile peer emitted repeated chunks.
- `node --test test/issue-65-authority-https-pin-reuse.test.js
  test/issue-65-remote-history-head-mtls.test.js
  test/issue-65-cas-status-mtls-http.test.js` — 8/8 PASS, 0 FAIL.
- `npm run validate:syntax` — 377 checked / 0 failed.
- `npm run validate:artifacts` and `git diff --check` — PASS.
- `node --test test/issue-65-protected-content-bootstrap.test.js`:
  RED rejected valid bounded CAS deadline overrides; GREEN 1/1 PASS, with
  bad values rejected before database creation.

## Remaining constraints

Legitimate large histories might require more pages than the configured
wall-time budget permits on a slow network; that request safely fails rather
than allowing unbounded verification. CAS page count and aggregate bytes
remain bounded by the existing transport and public-history validator.
Independent CAS/witness custody, signed external anti-rollback roots,
distributed physical STOP and remote provider fencing remain unproven.
This does not enable production or close issue #65 (**NO-GO**).
