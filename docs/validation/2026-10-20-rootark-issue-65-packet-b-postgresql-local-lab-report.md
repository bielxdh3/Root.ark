# Root.ark #65 Packet B — PostgreSQL local lab report

**Report timestamp:** 2026-10-20 14:05:53 UTC
**Verdict:** `LOCAL_POSTGRES — CONDITIONAL`

This is test-only evidence from a real PostgreSQL server running in a disposable local Docker container. The database transaction cases passed. This is not product implementation, wire-protocol approval, production approval, provider selection, or evidence of independent operators or physical I/O fencing.

## 1. Source, scope, and worktree state

- Repository: `bielxdh3/Root.ark`.
- Approved worktree: `E:\servidor\.worktrees\zk-dual-recovery-20261019`.
- Branch: `cdx/rootark-dual-recovery-20261019`.
- Starting and final HEAD: `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`.
- No commits, branch movement, package changes, or tracked product-file changes were made.
- Four original untracked files were present at the start. The two mock files and the prior `MOCK_ONLY` report were left untouched. The existing lab `README.md` was extended.
- The final untracked set contains those four originals plus the following additions/extension:

| State | Path |
|---|---|
| Extended existing untracked file | `lab/issue-65-packet-b/README.md` |
| Created | `lab/issue-65-packet-b/postgres-lab.test.js` |
| Created | `lab/issue-65-packet-b/postgres-negative-control.sql` |
| Created | `lab/issue-65-packet-b/postgres-schema.sql` |
| Created | `lab/issue-65-packet-b/run-postgres-lab.js` |
| Created | `docs/validation/2026-10-20-rootark-issue-65-packet-b-postgresql-local-lab-report.md` |

No writes were made elsewhere in the repository. The Superpowers SDD plan and ledger were kept in the approved disposable scratch area `E:\Chats\rootark-tests\issue65-pgb-plan-20261020`, with the ledger's Git metadata pointed at the verified worktree. The ledger records this path ruling. No native subagents were started, consistent with the selected single-primary-agent orchestration. The requested local AI Memory and Obsidian preflight, global and repository instructions, Ponytail, project security review, applicable Superpowers skills, and UI-UX-PRO-MAX applicability check were completed; UI work was `N/A`.

## 2. Environment and Docker isolation

| Component | Observed value |
|---|---|
| Host OS | Microsoft Windows 10 Pro, 10.0.19045, build 19045 |
| Windows Node/npm | Node v24.14.1; npm 11.11.0 |
| WSL | Ubuntu 26.04.1 LTS; Node v22.22.1; npm 9.2.0 |
| Docker Desktop / Engine | Docker Desktop 4.84.0; Engine 29.6.2, Linux AMD64 |
| PostgreSQL image | Docker Official Image `postgres:18.6-alpine3.24` |
| Image identity | local ID `sha256:c293117fcecda7344b5480222e813b9f673d7abd69b1dd95eff239b768b04f59`; RepoDigest `postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873` |
| Server version observed by `SELECT version()` | PostgreSQL 18.6, x86_64-pc-linux-musl, Alpine GCC 15.2.0 |

The image was already cached. No `docker pull` was run, so the original cache acquisition provenance is unknown; the local tag, image ID, and registry RepoDigest were recorded. The tag appears in the [Docker Official Image PostgreSQL tags](https://hub.docker.com/_/postgres/tags?name=18); PostgreSQL's [versioning policy](https://www.postgresql.org/support/versioning/) was checked for current support status.

The final full run after the startup-readiness correction reported PostgreSQL ready at **2026-10-20T14:15:11.939Z**. Windows and WSL suites each passed 10/10, then the runner confirmed removal of the container and volume. TAP reported 26.850 seconds for Windows and 32.759 seconds for WSL. Individual test wall-clock timestamps were not emitted; the exact server-ready timestamp and per-suite durations are retained.

Isolation decisions:

- Every lab container used labels `rootark.lab=issue65-packet-b` and `rootark.owner=local-feasibility`.
- Container options included `--network none`, 1 GiB memory, 1 CPU, 128 PIDs, and 64 MiB shared memory. No host port was published; no user-defined network was created.
- A fresh named volume was mounted at `/var/lib/postgresql`, matching PostgreSQL 18's major-version-specific data layout. The corrected run connected with `psql` over the container's own loopback interface via `docker exec`.
- Passwords were generated randomly for each container, passed through process environment, and never printed or stored in repository artifacts. Host authentication used SCRAM; `trust` was not used.
- Docker Desktop was started using its existing user-level application mechanism after the first read-only daemon check found it unavailable. No Docker/WSL settings or system services were changed.
- Windows and WSL Node ran sequentially against the same PostgreSQL container/database; the lab schema was dropped and recreated between suites. Each suite used separate PostgreSQL sessions for its races.

All Docker objects created during setup, correction, and final runs are listed below. Each volume name is the corresponding container name plus `-data`; every container and volume carried both labels shown above and was removed after its run.

| Container name | Full container ID | Run result | Cleanup |
|---|---|---|---|
| `rootark-issue65-pgb-20261020-4ca2d50395` | `af10c9ad6b08d3c9d3d7c1230e3f1984111cbf6fbb83478b8e548b2d48e7ef88` | Initial PostgreSQL 18 mount-path probe exited before readiness | Removed container and volume |
| `rootark-issue65-pgb-20261020-1c9405884e` | `f6cf646c10fb507bd3f37a4663175479c86228b479dfd000a6d7fa62ef69f0ac` | Diagnostic startup probe confirmed the image requires mount at `/var/lib/postgresql` | Removed container and volume |
| `rootark-issue65-pgb-20261020-12090b7b83` | `e41796b5889351a989d69291a86c7699914ad4f6ede0dcb9c78146e50ff7705d` | RED assertions ran; runner output-count check needed TAP normalization | Removed container and volume |
| `rootark-issue65-pgb-20261020-687df6abef` | `72ef5a2ec0ba236141569a7bf034c528bc5799a9e9ac5e8db8881949bbfab18` | Two RED regression assertions verified | Removed container and volume |
| `rootark-issue65-pgb-20261020-a50ee5d738` | `0bdf7e0f54e56b7b342a7ad84f6e255a3cc0eff2950ecf3616ca42213899a3c1` | RED plus SQL schema-load probe passed | Removed container and volume |
| `rootark-issue65-pgb-20261020-77d8822987` | `c6451014069eecd88c5e3572795abfdd05652724ec1775ff85d7b31ff2be29b9` | First full harness run: 7/10 passed; three test harness assertions were corrected | Removed container and volume |
| `rootark-issue65-pgb-20261020-66515f0507` | `3cad9950aec6cd15aa3d47eb67bc2d3cfe4cd1613daa102d40009c7de4d2c1a4` | Second full harness run: 9/10 passed; missing Docker helper was corrected | Removed container and volume |
| `rootark-issue65-pgb-20261020-15e94bb579` | `408e42127ecf0782c356e393f5a263301b61b0661aac2ff6c3646bce1f99647c` | Windows and WSL suites passed 10/10 before the final boundary assertions were added | Removed container and volume |
| `rootark-issue65-pgb-20261020-297b0a3239` | `92d63cf5a73fd752d0bac550b71ef08397a88b64cd258cd3361b067ed00e432b` | Final Windows and WSL suites each passed 10/10 | Removed container and volume |
| `rootark-issue65-pgb-20261020-b4c4388341` | `6935de11c1b3e88a8eb089c2951f01c5ce3b92b01ca1e48be051058edb53b5e0` | Bounded schema-only startup retry: `pg_isready` succeeded before authenticated `psql SELECT version()` was ready; the first query was refused and no test ran | Removed container and volume |
| `rootark-issue65-pgb-20261020-841b98f1f6` | `2f79164eb85c910f9e98402c989a4f32d6daa1876f06db9b6f5343f94a57f1a5` | Schema-only run passed after runner readiness was tightened to require an authenticated `SELECT 1` | Removed container and volume |
| `rootark-issue65-pgb-20261020-f1afb9c3bd` | `acd718d731aad8214cba89e075a1649150a6dbe94a7c6a81d5e1b9c7e27b7a0d` | Final post-correction run: Windows 10/10 and WSL 10/10; PostgreSQL ready at 2026-10-20T14:15:11.939Z | Removed container and volume |

After the first authenticated-readiness race, the runner was narrowly changed to require both `pg_isready` and a successful authenticated `SELECT 1` within 60 seconds. The failed attempt was cleaned up by exact container ID and volume name; the schema-only retry and final cross-platform run both passed. The final label-filtered `docker ps -a`, `docker volume ls`, and `docker network ls` checks returned no lab objects. No unrelated Docker resource was changed or removed.

## 3. Model and transaction semantics

`postgres-schema.sql` creates ten tables in disposable schema `p65_lab`, the `pgcrypto` extension for server-side SHA-256 validation, and restricted non-login roles (`p65_cas`, `p65_gate`, `p65_status`, `p65_test`). The application roles have function execution rights but no direct table read/write rights; direct table access under `p65_cas` was tested and denied.

The modeled keyring scope is the exact `(account_id, compartment_id, keyring_id)` tuple. Its row stores committed revision/digest, active epoch, modeled capacities, gate state, and generation. `reserve_operation`, `begin_quiesce`, permit consumption, simulated-I/O decisions, stop acknowledgements, commit, and no-commit seal lock authoritative rows with `SELECT ... FOR UPDATE`. Calls on one keyring serialize on its head row; commit and fence also serialize on the operation row. Unique keys on operation, terminal, reservation, transition, permit, effect, and fence records provide collision barriers. `READ COMMITTED` plus these row locks and uniqueness constraints was used; serializable isolation was not required for the measured single-keyring cases.

The internal `request_input` bytes are canonical synthetic JSON generated by Node. The database checks `pgcrypto.digest(request_bytes, 'sha256')`, stores the exact request bytes and all request fields, and compares them on retry. A changed scope, expected/proposed revision or digest, package digest, reservation, expiry, transition bytes, or request digest conflicts for the same operation ID. A changed operation ID is not found as the stored retry. The lab intentionally makes operation IDs globally unique to expose changed-scope retries; that uniqueness choice is lab-local and is not an approved protocol rule.

A successful compare-and-append writes one immutable transition row, advances the head, and inserts one durable terminal result inside one PostgreSQL function statement/transaction. An injected exception after the transition insert rolled the entire statement back. A no-commit fence is available only for the exact reserved operation, after quiesce and all modeled stop acknowledgements, when the database clock reaches `expires_at + 30 seconds`, the expected head still matches, and no committed terminal or transition exists. The `test_clock.offset_seconds` fixture is test-only; the boundary was checked at zero offset (wait) and +31 seconds (eligible), then reset.

The gate uses a single generation across the permit, active-effect, reservation, quiesce, stop-ack, and terminal-fence rows. Reservation changes `OPEN` to `PENDING`; terminal completion reopens the gate and advances generation. Read/admission and permit calls fail while the gate is closed. The permit is one-use, bound to scope, operation, reservation, revision/digest, epoch, and generation. Missing, wrong, replayed, stale-generation, cross-keyring, and unrelated-operation attempts fail closed.

Lab-only deviations and limits:

- `request_input`, operation result JSON, `operation_terminal`, `no_commit_fence`, permits, and stop-ack IDs are internal lab representations. There are no protocol `type` literals, receipt schemas, signer roles, signature payloads, public proofs, or wire-compatibility claims.
- Device and epoch limits are counters, not a full device/epoch registry. The history counters model 4,096 transitions, 64 MiB aggregate bytes, and 8 MiB per entry; they do not reproduce all serialized product validation.
- The test clock is a controllable offset over `clock_timestamp()` for the expiry-bound test. It is not a production time source.
- The simulated witness high-water is in this same database. It is not an independently operated ledger, signer, or rollback-resistant checkpoint.
- `allow_simulated_io` records an ordering decision while holding database locks. The function returns and the database transaction ends before any real storage or network action could run. This remains a TOCTOU boundary; PostgreSQL does not prove that physical I/O stopped or that a packet was not already sent.
- The lab uses a `postgres` superuser harness which sets its role before calling restricted functions. This tests SQL privilege separation, not an application service's real database credential or connection pool.

## 4. Scenario matrix

| Scenario | Result | Evidence and limit |
|---|---|---|
| Changed-request retry and lost-ack path | `PASS` | The client response was discarded at the harness boundary after the committed function returned; the exact operation ID was then queried from `operation_terminal`, compared, and retried. The retry returned the identical stored result without another append. Changed expected revision/digest, proposed digest, package digest, reservation, scope, expiry, transition bytes, or request digest returned `OPERATION_CONFLICT`; a changed operation ID returned `NOT_RESERVED`. This simulates response loss at the client boundary, not a network disconnect after COMMIT. |
| RED control for changed expected revision | `PASS` (expected RED) | Before GREEN schema installation, unsafe PostgreSQL negative control returned `COMMITTED` for the same operation/payload with expected revision `999` after an initial revision-0 commit. The regression assertion failed with actual `COMMITTED`, expected `OPERATION_CONFLICT`. |
| RED control for unrelated no-commit seal | `PASS` (expected RED) | After preparing `op-a` and its stop acknowledgement, the unsafe control sealed `unrelated-op`, returning `NO_COMMIT_FINAL`; assertion failed with actual `NO_COMMIT_FINAL`, expected `GATE_BINDING_MISMATCH`. |
| Two concurrent compare-and-appends | `PASS` | Distinct psql sessions/processes contested one keyring head. `pg_stat_activity` observed one session waiting on a PostgreSQL lock. Exactly one advanced to revision 1 with one transition/terminal; the other returned `HEAD_MISMATCH` and created no operation row. |
| Account, compartment, keyring noninterference | `PASS` | Four independently seeded tuple variants each committed one revision-1 transition and terminal result without cross-scope collision. |
| Injected fault before commit | `PASS` | Exception after transition insert left revision 0, no transition, no terminal result, and no fence. The separately committed pre-fault gate state remained `QUIESCING`, as expected. |
| Commit vs no-commit race, commit first | `PASS` | Separate sessions; one observed lock wait. Commit stored one transition/terminal. Fence returned `COMMIT_ALREADY_EXISTS`; no fence row existed. |
| Commit vs no-commit race, fence first | `PASS` | Separate sessions; one observed lock wait. Fence stored one no-commit terminal/fence. Commit returned the stored `NO_COMMIT_FINAL`; no transition row existed. |
| Expiry, head, acknowledgement, timeout-related fence guards | `PASS` | A zero-offset pre-expiry attempt returned `WAIT_EXPIRY_BOUND`; incomplete ACK rows returned `STOP_ACKS_INCOMPLETE`; wrong/unreserved operation returned binding mismatch and left no fence. Test-only +31-second offset enabled the exact fence. No timeout-only finalization input exists. |
| Gate, admissions, permits, and simulated effect ordering | `PASS` | Pending/quiescing gate blocked head reads, permit issuance/consumption, and simulated I/O authorization. Two effect rows required two acknowledgements. Wrong operation/scope/epoch, stale generation, replayed permit/ACK, wrong ACK ID, and missing ACK attempts failed closed. The DB decision is not physical I/O fencing. |
| Aborted in-flight transaction | `PASS` | A separate backend reserved within an open transaction and was terminated inside the lab container. PostgreSQL aborted the uncommitted request; head stayed `OPEN`, with no operation, transition, terminal, or fence row. |
| Container restart persistence | `PASS` | The lab-owned PostgreSQL container was restarted after a commit and a fence. The transition, fence, terminal rows, and revision persisted in the named volume. This is a single-machine container restart only. |
| Stale witness/status response | `PASS` | After local head advanced, a response at revision 0 failed `FAIL_CLOSED_STALE`; current internal row returned `FRESH_INTERNAL_ONLY`; lowering the simulated witness high-water was rejected. Both head and witness are stored in the same DB. No full old-snapshot restore was attempted. |
| Capacity, malformed request, and permissions | `PASS` | 256 devices/64 epochs were accepted as maxima; 257 devices and 65 epochs rejected. At 4,096 transitions or 64 MiB history, another reservation rejected. Invalid proposed revision and bad request digest rejected. Application-role direct table read was denied. |

## 5. Commands and validation results

All commands below ran on 2026-10-20. The final PostgreSQL run's exact database-ready timestamp and per-suite TAP durations are above. The runner printed no synthetic credentials. After the readiness correction, the complete Windows and WSL PostgreSQL suites were rerun once and passed.

| Command / phase | Exit | Result |
|---|---:|---|
| `node lab/issue-65-packet-b/run-postgres-lab.js` | `0` | Final run: RED control produced exactly 2 expected failures; SQL schema load exit `0`; Windows Node PostgreSQL suite 10 tests, 10 pass, 0 fail, 0 skipped; WSL Node suite 10 tests, 10 pass, 0 fail, 0 skipped; container and volume removed. |
| `node /e/servidor/.worktrees/zk-dual-recovery-20261019/lab/issue-65-packet-b/run-postgres-lab.js --schema-only` (first authenticated-readiness attempt) | `1` | PostgreSQL reported ready before the first authenticated `psql SELECT version()` succeeded; connection was refused, no schema assertion ran, and the owned container/volume were removed. |
| `node /e/servidor/.worktrees/zk-dual-recovery-20261019/lab/issue-65-packet-b/run-postgres-lab.js --schema-only` (after bounded readiness correction) | `0` | Authenticated readiness probe succeeded; schema loaded and the owned container/volume were removed. |
| Internal RED invocation: Node `--test --test-reporter=tap --test-name-pattern=... postgres-lab.test.js` | `1` expected | 2 tests, 0 pass, 2 fail, 0 skipped against the intentionally unsafe PostgreSQL negative control. Both failures demonstrated the known regressions. |
| Internal Windows invocation: `node --test --test-reporter=tap lab/issue-65-packet-b/postgres-lab.test.js` | `0` | 10 tests, 10 pass, 0 fail, 0 skipped; Windows Node v24.14.1. |
| Internal WSL invocation: `wsl.exe --exec bash -lc "cd /mnt/e/servidor/.worktrees/zk-dual-recovery-20261019/lab/issue-65-packet-b && node --test --test-reporter=tap postgres-lab.test.js"` | `0` | 10 tests, 10 pass, 0 fail, 0 skipped; WSL Ubuntu 26.04.1, Node v22.22.1; same PostgreSQL server after lab schema reset. |
| PowerShell-expanded `node --test --test-reporter=tap` over all 13 `test/issue-65-*.test.js` files plus the mock test | `0` | 118 tests, 118 pass, 0 fail, 0 skipped. Existing mock remains unmodified and `MOCK_ONLY`. |
| `npm run validate:syntax` | `0` | Final run after the runner readiness correction: 233 checked, 0 failed. |
| `npm run validate:artifacts` | `0` | Final run after the runner readiness correction: completed with no validator errors. |
| `node --check` for `postgres-lab.test.js`, `run-postgres-lab.js`, and the two pre-existing lab JavaScript files | `0` | All four syntax checks passed. |

Exact existing-test command:

```powershell
$testFiles = @(Get-ChildItem -Path test -Filter 'issue-65-*.test.js' -File | ForEach-Object { $_.FullName })
Write-Output ('ISSUE65_TEST_FILES=' + $testFiles.Count)
node --test --test-reporter=tap $testFiles 'lab/issue-65-packet-b/mock-packet-b.test.js'
exit $LASTEXITCODE
```

The RED test process used these Node arguments (the test names are a single regular-expression argument):

```text
--test
--test-reporter=tap
--test-name-pattern=exact retry rejects a changed expected revision|no-commit seal rejects an unrelated operation after stop acknowledgement
lab/issue-65-packet-b/postgres-lab.test.js
```

The four explicit JavaScript syntax commands were `node --check lab/issue-65-packet-b/postgres-lab.test.js`, `node --check lab/issue-65-packet-b/run-postgres-lab.js`, `node --check lab/issue-65-packet-b/mock-packet-b.js`, and `node --check lab/issue-65-packet-b/mock-packet-b.test.js`, each exit `0`.

The initial PostgreSQL startup probes and bounded full-suite corrections are retained in the Docker resource table. The first authenticated-readiness retry after `pg_isready` exposed a startup race; the runner now waits for an authenticated query, and both the schema-only retry and the final full run succeeded. The final full run is the evidence used for the `PASS` rows above.

## 6. Final repository and artifact checks

Final audit timestamp: **2026-10-20 14:21:48 UTC**.

- `git diff --check`: exit `0`; no tracked diff was present.
- Trailing-whitespace scan over all 9 untracked repository files: exit `0`, `TRAILING_WHITESPACE=0`, 9 files scanned. This covers untracked files that `git diff --check` cannot see.
- Bounded secret/endpoint scan: exit `0`, zero secret-pattern matches and 7 endpoint-reference lines. Six code lines contain container-local loopback psql targets/commands; one report line contains two official documentation links. No external runtime endpoint or non-loopback IP was found.
- Docker label filters: exit `0`, zero lab containers, volumes, or networks remain.
- Final Git identity: root `E:/servidor/.worktrees/zk-dual-recovery-20261019`; branch `cdx/rootark-dual-recovery-20261019`; HEAD `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`.
- Final `git status --porcelain=v1 --untracked-files=all` contains exactly these nine untracked paths and no tracked modifications:

  ```text
  ?? docs/validation/2026-10-20-rootark-issue-65-packet-b-local-lab-report.md
  ?? docs/validation/2026-10-20-rootark-issue-65-packet-b-postgresql-local-lab-report.md
  ?? lab/issue-65-packet-b/README.md
  ?? lab/issue-65-packet-b/mock-packet-b.js
  ?? lab/issue-65-packet-b/mock-packet-b.test.js
  ?? lab/issue-65-packet-b/postgres-lab.test.js
  ?? lab/issue-65-packet-b/postgres-negative-control.sql
  ?? lab/issue-65-packet-b/postgres-schema.sql
  ?? lab/issue-65-packet-b/run-postgres-lab.js
  ```

The tracked-diff check was the exact command `git diff --check`. The untracked-inclusive whitespace scan covered all nine untracked repository files with this PowerShell command:

```powershell
$files = @(Get-ChildItem -Path 'lab/issue-65-packet-b' -Recurse -File) + @(Get-Item 'docs/validation/2026-10-20-rootark-issue-65-packet-b-local-lab-report.md') + @(Get-Item 'docs/validation/2026-10-20-rootark-issue-65-packet-b-postgresql-local-lab-report.md')
$hits = @()
foreach ($file in $files) {
  $lineNumber = 0
  foreach ($line in (Get-Content -LiteralPath $file.FullName)) {
    $lineNumber += 1
    if ($line -match '[ \t]+$') { $hits += ($file.FullName + ':' + $lineNumber) }
  }
}
if ($hits.Count -eq 0) { Write-Output ('TRAILING_WHITESPACE=0 FILES=' + $files.Count); exit 0 }
$hits | ForEach-Object { Write-Output ('TRAILING_WHITESPACE=' + $_) }
exit 1
```

The bounded secret/endpoint scan reported only counts and locations, not matched text. It scanned all nine untracked files (lab JavaScript, SQL, Markdown, the prior report, and this report) for private-key headers, common token prefixes, and high-entropy password/secret/token/API-key assignments; it separately counted HTTP(S) references and IPv4 literals. Its result was zero secret patterns. The seven endpoint-reference lines were six container-local loopback references in lab code and one report line with two official documentation links; no external runtime endpoint or non-loopback IP was found. The final label-filtered Docker checks were `docker ps -aq --filter label=rootark.lab=issue65-packet-b --filter label=rootark.owner=local-feasibility`, `docker volume ls -q --filter label=rootark.lab=issue65-packet-b --filter label=rootark.owner=local-feasibility`, and `docker network ls -q --filter label=rootark.lab=issue65-packet-b --filter label=rootark.owner=local-feasibility`; all returned no rows.

The scan command was:

```powershell
$files = @(Get-ChildItem -Path 'lab/issue-65-packet-b' -Recurse -File -Include '*.js','*.sql','*.md') + @(Get-Item 'docs/validation/2026-10-20-rootark-issue-65-packet-b-local-lab-report.md') + @(Get-Item 'docs/validation/2026-10-20-rootark-issue-65-packet-b-postgresql-local-lab-report.md')
$secretPatterns = @('-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', '(?i)\b(?:sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b', '(?i)\b(?:password|secret|token|api[_-]?key)\s*[:=]\s*["'']?[A-Za-z0-9+/=_-]{24,}')
$secretHits = @()
$endpointHits = @()
foreach ($file in $files) {
  $lineNumber = 0
  foreach ($line in (Get-Content -LiteralPath $file.FullName)) {
    $lineNumber += 1
    foreach ($pattern in $secretPatterns) { if ($line -match $pattern) { $secretHits += ($file.FullName + ':' + $lineNumber); break } }
    if ($line -match 'https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b') { $endpointHits += ($file.FullName + ':' + $lineNumber) }
  }
}
Write-Output ('SECRET_PATTERN_MATCHES=' + $secretHits.Count)
$endpointHits | ForEach-Object { Write-Output ('ENDPOINT_REFERENCE_LOCATION=' + $_) }
Write-Output ('ENDPOINT_REFERENCE_COUNT=' + $endpointHits.Count)
if ($secretHits.Count -gt 0) { $secretHits | ForEach-Object { Write-Output ('SECRET_PATTERN_LOCATION=' + $_) }; exit 1 }
exit 0
```

## 7. Unresolved gates and risk boundary

- `INDEPENDENT_OPERATORS_NOT_PROVEN`
- `PROVIDER_MULTI_NODE_HA_NOT_PROVEN`
- `PHYSICAL_IO_FENCING_NOT_PROVEN`
- `BROWSER_NOT_RUN`
- `WEB_TRUST_ROOT_NOT_PROVEN`
- `WIRE_V1_BLOCKED`: the terminal-status proof, reservation-ticket, and cancellation-receipt v1 literal `type` values remain unfrozen. No wire schema or valid v1 proof was invented.
- Rollback resistance against restoring an old database snapshot remains incomplete and unproven.
- Key lifecycle, transfer TTL, status freshness authority, and independent trust-root bootstrap remain unresolved. D-008 retention is not the transfer TTL.
- Already downloaded/exported user copies cannot be retroactively revoked. Fresh online authority for new transfers, service downloads, device changes, recovery, and protected state operations remains the product boundary.
- The local DB restart is not multi-AZ/HA, power-loss, fsync, replication, or independent-provider evidence.

No product/runtime path, real user data, production database, external infrastructure, real credentials/keys, paid service, or hosted database was used. No code was deployed, committed, pushed, merged, or released. Cleanup is complete; there are no lab Docker leftovers.

## 8. Next engineering gate recommendation

**NO-GO for product implementation or provider selection.** The next gate should be an owner-approved protocol clarification that freezes the three v1 terminal `type` literals, followed by cryptographic review of exact signed bytes, freshness, and verifier obligations. Only after that approval should the provider-neutral feasibility work define independently operated witness/status roles, rollback-resistant high-water evidence, and externally verified storage/egress fencing acceptance criteria.

## 9. Bounded self-review

One internal self-review checked SQL literal escaping, test-generated inputs, role/function permissions, exact request comparison, lock order, terminal uniqueness, lost-response lookup, rollback path, container identity checks, clock reset, and cleanup labels. No further lab-only defect was found. This was not an independent review or security audit; the single independent review remains for the owner to request against this report.
