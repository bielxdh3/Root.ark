# Root.ark #65 — isolated process STOP reference boundary

The optional `stopSupervisor` + `stopRecorder` parameters on
`createIsolatedZk1SharedPgGateServer()` expose `server.strictStopOperator`
**only to trusted code in the operator process**. The local operator must
independently authorize and provision the complete scope, `workerId`, mTLS
certificate fingerprint, object, revision and digest with `prepare()` before
calling `beginTrustedLocalAdmission()`. The supervisor supplies the process
epoch, PID and pinned Ed25519 host identity from the actual `ChildProcess`
handle. `finishTrustedLocalAdmission()` stops that handle, awaits real OS
`exit`/`close`, records the signed evidence through the independent restricted
STOP SQL principal, and then invokes the gate's signature-verifying FINISH.
Only `createZk1PhysicalStopRecorder()` can provision an acceptable recorder:
it first verifies that the PostgreSQL login has the independent STOP-only
privileges, then marks the actual instance as checked; a directly constructed
recorder, a superuser/dual-role pool or a later attempt to replace its pool
cannot serve as STOP authority.

If the supervised child exits just **after** SQL START commits but **before**
the operator binds the returned admission ID, the still-held original child
handle can be bound to that exact returned ID/epoch/PID for reconciliation.
This binding never makes a dead process live. The operator rechecks the gate
head before returning any positive `proceed` result and denies a dead worker;
it may still issue an independently signed STOP, finish and drain to PENDING.
If QUIESCING commits in the same gap, the existing admission is bound but the
reply is `proceed:false`. A crash/restart that loses the supervisor's original
ChildProcess handle cannot fabricate this posthumous proof. Persistent OS
supervision/recovery remains an unresolved separate design requirement.

**This is a laboratory reference for a single local child process.** The child
fixture does not execute ciphertext writes or own the HTTPS listener. Current
`/v1/admission/start`, `/v1/chunk/put`, `/v1/chunk/seal`, and
`/v1/admission/finish` requests execute outside the supervised child and are
therefore explicitly denied for a scope with `require_stop_proof=TRUE`, even
with a prepared operator session. Caller-supplied `hostKeyId`, `processEpoch`
or `processPid` must never become authority. Legacy non-strict scopes preserve
their existing API. The `/v1/quiesce` and `/v1/pending` routes continue to use
the real PostgreSQL gate and independently verified physical STOP receipts.

This milestone does not establish physical STOP of an HTTP connection, remote
writer, process descendant, cloud provider, buffered egress or multi-host
worker. A strict remotely writable path requires a separate design in which
the actual physical I/O executor is owned by the pinned supervisor and whose
termination is proven before FINISH. A local child STOP receipt by itself is
not evidence that another process has stopped emitting bytes. The PostgreSQL
row-lock fencing already tested for physical SQL writes is a separate,
narrower guarantee. Do not enable strict HTTP writes based on this reference.

Disposable tests: `node lab/issue-65-packet-b/run-shared-gate-postgres.js`.
No production database, migration, deploy, key provisioning or HTTPS listener
is installed by this milestone.
