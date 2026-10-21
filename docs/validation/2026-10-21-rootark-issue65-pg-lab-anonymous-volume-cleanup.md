# Root.ark issue #65 — Disposable PostgreSQL data-volume cleanup

**Scope:** three isolated, loopback-only PostgreSQL 18 lab runners, **not**
database migrations, any production storage/SQL, protected-client release,
remote cloud STOP, or a complete zero-knowledge acceptance claim.

## Concrete defect

The official `postgres:18.6-alpine3.24` image declares the data directory as
a Docker volume. The existing shared GateAuthority, supervised mTLS PUT and
supervised GET/egress runners used `docker rm -f <id>`. That can leave the
image-created **anonymous PostgreSQL data volume** on the host even after the
container is gone. The prior `CLEANUP verified=true` line proved removal of
the container alone; it did not prove removal of the disposable database data.

## Narrow correction and refusal boundary

`lab/issue-65-packet-b/verified-anonymous-pg-cleanup.js` centralizes the
cleanup for those three runners. Before deletion it requires:

- the exact 64-character container ID and both disposable-only Docker labels;
- a single Docker volume mount, exactly at `/var/lib/postgresql`, whose name
  is a Docker-generated-style 64-character lowercase hexadecimal ID;
- no unexpected, named or bind mounts.

After verifying the exact identity, it runs `docker rm -f -v <verified-id>`
and verifies the same anonymous volume is no longer inspectable: **exit
status 1 AND an explicit Docker error naming that exact missing volume**.
Exit 1 alone is not evidence (daemon offline/permission errors also return 1).
Unknown identities, unexpected mounts, a still-present volume and
inconclusive Docker results are **hard failures**, never claims of verified
cleanup. It never enumerates or removes other containers, volumes or
historical fixtures. The runners themselves create random names and pass
no volume/mount options; the verification is an additional fail-closed gate.
The verification does **not** claim protection against an attacker who
controls Docker root or has replaced the Docker executable.

## Test evidence

- Targeted RED: the new helper did not exist; the focused tests failed.
- Targeted GREEN: `node --test test/issue-65-disposable-pg-cleanup.test.js`,
  **3/3 PASS** including exact owned ID, foreign labels, named/bind mounts
  and ambiguous volume inspection. Independent review uncovered a P2
  where exit status 1 from a disconnected Docker daemon was falsely treated
  as proof of deletion. The adversarial regression was RED (2/3 PASS);
  exact-volume not-found error matching repaired it before publication.
- `node lab/issue-65-packet-b/run-supervised-get-egress.js`: **5/5 PASS**
  native Windows + **5/5 PASS** WSL Node 22, exact volume cleanup verified.
- `node lab/issue-65-packet-b/run-supervised-mtls-bound-writer.js`:
  **4/4 PASS** native Windows + **4/4 PASS** WSL Node 22, exact volume cleanup verified.
- `node lab/issue-65-packet-b/run-shared-gate-postgres.js`:
  **41/41 PASS** native Windows (real disposable PostgreSQL 18), exact volume
  cleanup verified. This runner's PostgreSQL suite is not automatically
  a real multi-host or multi-provider proof.

The published PR must remain **DRAFT / NO-GO** until the normative full #65
end-to-end trust and remote physical I/O guarantees are demonstrated.
