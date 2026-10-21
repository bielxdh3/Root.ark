# Root.ark #65 — PostgreSQL Gate mTLS response hard deadline

## Runtime defect reproduced

`zk1SharedPgGateHttpsClient.send()` previously used only the Node HTTPS
socket *idle* timeout. A pinned authenticated Gate peer could send a single
whitespace byte every 25 ms and never complete its JSON admission response.
The caller would remain pending indefinitely, obstructing safe quiescence,
reconciliation and future work.

The adversarial HTTPS/mTLS fixture in
`test/issue-65-authority-https-pin-reuse.test.js` opens a valid TLS1.3
connection with a pinned server certificate, streams repeated response bytes
and intentionally never ends the first response. The RED test observed
`still-pending` after 650 ms despite a configured 160 ms timeout.

## Fix and bounded evidence

The Gate client now enforces an independent hard timer spanning the whole
request, TLS handshake, response stream and JSON parsing. On deadline or
transport failure it atomically marks the promise finished, clears the timer,
destroys its owned socket and fails with `ZK_GATE_TRANSPORT_UNAVAILABLE`.
On verified success the timer is cleared. The default deadline is 15 seconds,
configurable from 100 ms through 30 seconds, so ordinary large opaque chunk
transfers on slower links are not rejected by the old 3-second default.

GREEN: the same actual mTLS test denies the trickling response, records at
least two chunks actually delivered by its server and accepts a fresh exact
admission from the same client against a new independent TLS socket.

- Focused Gate transport + sink tests: 7 PASS / 0 FAIL / 1 SKIP. The skip
  requires explicitly configured disposable PostgreSQL role credentials.
- Syntax validation: 377 checked, 0 failed.
- Artifact validation and `git diff --check`: PASS.
- Independent static P1/P2 review found no bypass in this delta.

## Limits

This bounds *transport availability* only. Repeating a request after an
uncertain ACK remains governed by exact idempotent tuples and separate
PostgreSQL/witness terminal decisions. No GET/egress path was newly enabled.
Root.ark's current Express ciphertext response still lacks physical
GateAuthority fencing and STOP of its own socket-owning process. Neither
the mTLS fixture nor same-machine tests establish independently operated
CAS/witness, cross-provider cancellation, or rollback resistance after
hostile restoration. Issue #65 remains **NO-GO**.
