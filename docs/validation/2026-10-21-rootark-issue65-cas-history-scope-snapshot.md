# Root.ark issue #65 — mTLS CAS paginated history pins its request scope

**Status:** narrowly scoped security hardening for the experimental CAS
history transport. This is **NOT** authority activation or protected I/O
authorization. No production deployment or data mutation.

## Reproduced gap

`createZk1CasManifestHttpsClient().getCommittedHistory()` previously retained
the caller's mutable `scope` object across multiple network awaits. Each
`getCommittedHistoryPage` request validated/serialized that same mutable
scope afresh. A caller modifying account, compartment or keyring buffers
after page 1 sent subsequent pages under a *different* identity. This could
cause a confusing mid-request scope switch rather than one coherent
snapshot; the server's strict principal/scope ACL correctly rejected
unapproved new scopes, so this test is **not evidence of a proven cross-account
data leak**.

## Correction and evidence

The client now validates and snapshots all three binary scope identifiers
synchronously **before its first await**, then uses this pinned copy for
every HTTPS page. The endpoint, CA, client credentials and TLS peer pin
continue to be fixed by the same client instance.

- TDD RED: real mTLS pagination test deliberately overwrote all three
  buffers from the CAS server after the first authorized request; the
  unpatched client retried the next page with the changed scope and failed.
- GREEN: the same test requires all three pages to succeed under the
  originally selected scope.
- Adversarial size tests deliver **9 MiB raw over two distinct HTTPS pages**,
  confirming continuation across the 8 MiB page boundary, and reject a
  single malicious page exceeding 8 MiB.
- Existing tests continue to reject inconsistent/changed claimed CAS head
  across pages, foreign keyring, invalid revision, wrong mTLS role and bad pin.

All CAS pages and their claimed heads remain **untrusted** until separately
verified using signed genesis, full Ed25519 transition chain, independent
nonce-bound witness, trusted high-water and normative device authorization.
The snapshot fix does not solve real multi-host quiescence, provider fencing,
or atomic nonce-consumption/admission and must not be presented as a
completed #65 implementation.
