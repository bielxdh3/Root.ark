# Root.ark issue #65 — hidden SQL role privilege escalation in gate and STOP

**Scope:** disposable PostgreSQL role-isolation hardening, no production
schema/credential change, cross-host proof or ZK publication.

The existing `verifyZk1SharedPgRuntimePool` and
`verifyZk1StopRuntimePool` preflights checked the caller's actively
inherited privileges (`pg_has_role(..., 'USAGE')`) and table grants but
did not check a dormant `NOINHERIT` membership with `SET TRUE`.
PostgreSQL 18 can grant a gate login the STOP role with
`WITH INHERIT FALSE, SET TRUE`, or grant STOP login the gate role with
the same policy. Both logins pass the original preflight as apparently
separated, then can execute `SET ROLE` to obtain the other authority's
capabilities. A similar flaw was independently reproduced and corrected
in the delegated chunk-writer preflight at `cfca018`; the two controller
preflights remained vulnerable.

**TDD RED:** new `test/issue-65-gate-stop-hidden-role.test.js` created
separate randomly named disposable LOGINs, one with gate+hidden STOP and
another with STOP+hidden gate. Both preflights unexpectedly accepted them,
while PostgreSQL itself reported `USAGE=false`, `MEMBER=true`,
`SET=true`. Real PostgreSQL 18.6 focused suite was
**37 PASS / 2 FAIL**, cleanup verified. No such grants were applied to
real service accounts.

**Mitigation:** gate preflight now denies **any** inherited, MEMBER or
SET capability on STOP or chunk-writer roles. Independently verified
STOP recorder likewise denies inherited, MEMBER or SET capability on
gate or writer roles, even when privileges are not inherited. Both remain
restricted to distinct non-superuser operator-provisioned logins and
fail closed at startup. The unchanged original gate, STOP and writer
regressions must continue to pass.

**GREEN:** disposable PG18.6 Windows Node24 runner
`node lab/issue-65-packet-b/run-shared-gate-postgres.js` passed
**39/39 tests, 0 FAIL, 0 SKIP**, exit 0, including the two previously
failing cross-role escalation cases.
`SHARED_GATE_PG_CLEANUP verified=true` confirmed labeled disposable
container cleanup.

This closes the specific hidden-login capability boundary in the tested
runtime. It does **not** make database administrators untrusted, prove
remote OS process STOP, validate geographic multi-host quorum, or authorize
production deployment or real ZK content operation.
