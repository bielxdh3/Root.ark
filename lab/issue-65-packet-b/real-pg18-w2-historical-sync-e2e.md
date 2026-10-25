# Issue #65 / PR #228: physical PG18 to historical Sync v2 E2E

Run from the repository root with the Node 24 installation and dependencies
available. This test **requires an opt-in disposable PostgreSQL 18 container**
and cannot silently claim coverage with synthetic PG signatures:

```powershell
node lab/issue-65-packet-b/run-shared-gate-postgres.js --historical-e2e-only
```

The runner requires the **cached** `postgres:18.6-alpine3.24` image and a
working Docker Engine. It generates a randomly named, labelled, loopback-only
container, applies the existing shared-gate SQL schema and creates distinct
ephemeral SQL logins for the gate and read-only physical attestor. Its
existing verified-cleanup routine removes only its own labelled resource.
The new test is also included in the runner's regular PostgreSQL suite.

The test stores the **canonical encrypted Sync v2 envelope bytes** through the
real gate/physical inventory intent into PG18, checks committed
`sealed_object` storage and WAL readback, and verifies the real local signed
inventory receipt. A separate Node child process runs the
`Zk1SharedPgPhysicalCiphertextVerifier` under the attestor SQL login, signing
only fresh readbacks through pinned client-cert mTLS. The attestor SQL login
must differ from the gate login and must have no raw ciphertext write grants.
An invented operation without a PG row is refused.

Next the real W2 `Zk1WitnessCasPhysicalAdmission` challenges that child via
mTLS and verifies the inventory proof, while the witness accepts a real
owner-signed CAS physical fence. The `Zk1WitnessCasAnchorFloor` issuer then
durably persists the historical admission to a temporary SQLite database
through the dedicated `cas-historical-admit` TLS 1.3 endpoint. The test
rejects an unauthorized mTLS principal, a changed but freshly device-signed
envelope whose ciphertext was **never** committed in PG, and a replay. In the
failure case the SQLite historical-admission head stays at zero. The valid
case must return actual signed PG readback bytes, and the published strict
`verifySyncV2HistoricalWitnessAdmission` consumer must accept the original
challenge while refusing a substituted nonce. It also verifies the persisted
SQLite admission and nonauthorizing I/O flags.

Without the three restricted PostgreSQL URLs, `node --test
test/issue-65-real-pg-w2-historical-sync-e2e.test.js` reports an explicit
**SKIP**, not a PG pass. Native Windows Node 24 covers the live disposable
PG18 experiment; Linux/WSL Node 22 can separately run
`test/issue-65-sync-v2-physical-envelope-binding.test.js` for the cryptographic
consumer regressions. WSL-only crypto verification does **not** attest
WSL PostgreSQL I/O.

**Limits:** This is local PostgreSQL 18 WAL/readback durability and local
SQLite FULL-sync issuance in different **processes**, not independent
machines. It does not prove external provider durability, an external
monotonic witness floor, atomic PostgreSQL×SQLite commit, backup recovery, or
production eligibility. NO-GO production and PR DRAFT remain.
