# Issue #65 / PR #228 — CodeQL policy triage, 2026-10-25

Source: GitHub CodeQL check-run 121138563157, analyzed commit
c11ca9540f028420aaa07e4dcbff48432550b84b. Analysis completed but
security policy failed: check summary says 101 (62 high, 39 medium).
Its annotations API returned only 100 (61 failure, 39 warning). The
one-entry discrepancy is unresolved; the policy gate remains NO-GO.

Of the 100 annotated findings at PR head e6c3e1bc vs base 8fadd1de:
all paths were changed somewhere in the large PR, but 19 findings refer
to files already present in base (not necessarily newly vulnerable);
81 are in files created by the PR. 37 are test paths, not shipped
service code. Categories: 45 filesystem races, 33 outbound file data,
9 missing rate limits, 5 network-to-file, 3 user-controlled checks,
2 insecure temporary files, and 1 each of untrusted path,
sanitization and reflected XSS. Test-only findings require examination:
their location alone does not prove safety or exploitation.

The alleged bypass at src/services/zk1PgPhysicalAttestorHttpsServer.js:109
concerns method/route selection AFTER the TLS authentication, peer
fingerprint and grant checks at 105–107 (and scope checks at 120–124).
It is not evidence of client authentication bypass by itself.
The alerts on sync-client/rootark-sync-protocol.js:245,258 involve
optional authorization fields; upstream admission paths must be
examined before concluding whether those are exploitable.

## Confirmed narrow security fix

scripts/zk1-cas-status-standalone.js and scripts/zk1-witness-standalone.js
previously loaded operator Ed25519 keys, TLS credentials, pins and JSON
through separate stat(path) then readFile(path) operations. A local
rename between the calls could substitute attacker-selected authority
bytes. Both entrypoints now use the same bounded pinned descriptor
helper src/services/zk1AuthorityPinnedFile.js. It verifies a regular
single-link leaf, file identity, mode, size and modification/change
stamps before/after a capped read, and refuses altered path, extra
bytes, growth or symlink substitution. Startup errors stay generic.

Tests exercise real isolated Node processes, files, replacement before
opening, replacement after opening and mid-read growth; existing real
mTLS CAS/witness tests guard compatibility. No CodeQL policy suppression
or reduction in severity was made.

This prevents the scoped substitution but does not establish trusted
ancestor ACLs against arbitrary service-principal compromise or any
independent hardware/remote durable witness. A future CodeQL rerun
and review of remaining alerts remain necessary before production GO.

## Follow-up: independent opaque CAS/floor startup readers

At the later CodeQL policy check 121248957734 (analyzed commit a2a032dc),
the policy still reported 61 high and 39 medium annotations. Its high
filesystem-race annotations included the standalone opaque CAS and independent
floor service readers (`src/services/zk1OpaqueCatalogCasService.js:40` and
`src/services/zk1OpaqueCatalogIndependentFloorService.js:36`). Unlike the two
already corrected standalone witness/CAS scripts, these two services kept
separate `lstat -> open -> fstat -> read` logic and accepted public-readable
operator key material or a symlinked/junction parent path. Their operator
Ed25519/TLS/CA/config file readers now use `readAuthorityPinnedFile` with
owner-only ACL, safe ancestors, bounded fd read, and named-file identity
revalidation. The caller retains its existing generic configuration denial.

Actual Windows tests exercise normal private material (allowed), an explicit
untrusted Users read ACE (denied), and an ancestor junction (denied) for both
CAS and floor entrypoints. This is an isolated loader hardening, not proof of
CodeQL policy clearance, remote durability, or security against a compromised
privileged service account. Operator configuration, public-key and CA files
must also have private permissions where used as authority trust material.

## Current CodeQL policy check 121328433002 (2026-10-25)

All 100 annotations were retrieved for PR #228 published head `c9c7a7c`:
60 high (`failure`) and 40 medium (`warning`). The 100 break down into
43 filesystem races, 33 outbound file-data flows, 10 missing rate limits,
5 network-to-file flows, 3 user-controlled check bypasses, 2 sanitization,
2 insecure temporaries, 1 untrusted path and 1 reflected XSS. By location:
40 tests, 1 script and 59 remaining runtime paths. These are scanner counts,
not 100 independently established exploits.

One confirmed Windows authority boundary defect was reproduced at
`src/services/zk1WitnessCasAnchorFloor.js:288`: although file identity was
checked before `better-sqlite3`, a witness-floor parent could grant the
untrusted local Users SID `S-1-5-32-545` Modify, including rename/delete
rights against the SQLite DB and its WAL/SHM sidecars. The old constructor
accepted such a fixture and created the database. The constructor now calls
the existing owner-only `assertPrivateSqliteAuthorityDirectory` before
either opening or creating the witness-floor SQLite. A disposable physical
Windows ACL regression went RED 1 FAIL / 1 PASS, then GREEN 2 PASS / 0 FAIL;
private operator directory bootstrap remains accepted. Witness standalone
startup, 30k-row async signed head and mTLS CAS/witness floor tests pass.

Targeted triage: the `zk1PgPhysicalAttestorHttpsServer.js:109` method/route
check occurs after mTLS peer authorization and before body/PG access; that
annotation alone is not an authentication bypass. The WebDAV adapter's
`readBoundedFile` FD is checked against its named inode and digest before
upload; its configured endpoint is literal `127.0.0.1` with certificate
pinning. The `zk1ProtectedObjectStore.js:232` bootstrap uses exclusive
creation and follows with identity checks, but its separate Windows local
SQLite authority ACL remains a review target. The PG attestor uses a
read-only transaction, verifies the effective login/role and rejects
prohibited grants before serving a signed physical claim. None of this
disposes of other CodeQL findings without route-specific review. The
policy check remains **NO-GO** until the hosted gate passes independently.
