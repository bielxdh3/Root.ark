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
