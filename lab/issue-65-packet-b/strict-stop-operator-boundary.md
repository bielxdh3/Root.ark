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
