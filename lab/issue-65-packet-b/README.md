# Issue #65 Packet B local feasibility lab

This directory contains a disposable PostgreSQL experiment and a separate in-memory mock. Neither is a Root.ark product implementation. Lab names are internal records only; they do not define v1 wire literals, signatures, provider behavior, or production semantics.

## PostgreSQL experiment

Run from the approved worktree on Windows with the existing Docker Desktop daemon available:

```powershell
node lab/issue-65-packet-b/run-postgres-lab.js
```

The runner uses the cached Docker Official Image `postgres:18.6-alpine3.24`, creates one labeled container and one labeled disposable volume, and attaches no host ports or external network. It runs the two unsafe negative controls first, loads the corrected lab schema, runs the suite with Windows Node and WSL Node when available, resets only the lab schema between those runs, then removes only the created container and volume after checking their IDs/labels.

The schema uses `SELECT ... FOR UPDATE`, unique constraints, immutable event/fence rows, and atomic PostgreSQL function calls. It demonstrates single-database ordering and transaction behavior. It does not prove independent operators, multi-node or multi-AZ failover, rollback resistance, physical I/O fencing, real witness independence, browser/device behavior, or cryptographic status proofs. The test clock offset and mock witness high-water are synthetic fixtures.

The detailed evidence and blockers are in [the local PostgreSQL lab report](../../docs/validation/2026-10-20-rootark-issue-65-packet-b-postgresql-local-lab-report.md).

## In-memory mock

Run separately with:

```powershell
node --test lab/issue-65-packet-b/mock-packet-b.test.js
```

The mock remains `MOCK_ONLY`. Its stop acknowledgement and chunk journal are model inputs and in-memory records. They do not prove that a process stopped, storage or egress was fenced, a database transaction is durable, state is isolated across processes, or operators/providers are independent. The PostgreSQL negative controls reproduce the known changed-request retry and unrelated-operation seal gaps without modifying this mock.

`WIRE_V1_BLOCKED` remains in force pending owner-approved protocol clarification and cryptographic review.
