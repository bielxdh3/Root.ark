# Root.ark issue #65 — browser byte-input bounds before clone

**Scope:** opt-in development-only protected ciphertext signer and the
explicit non-destructive legacy file copy. This change neither activates
production zk-1 nor authorizes legacy cutover.

## Confirmed P2 / RED

The browser modules `rootark-zk1-protected-http-client.js` and
`rootark-zk1-legacy-protected-copy.js` previously cloned `ArrayBuffer` or
typed-array backing bytes *before* checking the expected length. An oversized
4 MiB ciphertext or a 33-byte manifest digest could reach `.slice()` and
allocate memory, despite being rejected immediately afterward.

The new regressions override `.slice()` on a 4 MiB + 1 byte ciphertext,
33-byte manifest digest and 33-byte GET expected ciphertext digest and
assert zero clone calls. The legacy regression also asserts that invalid
digest input causes zero plaintext source reads. RED: 2 tests failed with
`sliceCalls 1 !== 0` before the fix.

## GREEN

Both copy helpers now validate `byteLength` as a safe integer and compare
it against the allowed size *before* creating the snapshot. They retain a
post-copy length check against detached/malformed memory. The signed
operation still snapshots valid inputs before its first await; the legacy
source copy still remains non-destructive and bounded by its independent
2 MiB reader. No HTTP protocol, signature wire format or existing storage
behavior changed.

Focused real Express/SQLite + browser UMD/WebCrypto regressions:

- `node --test test/issue-65-browser-signed-content-http.test.js
  test/issue-65-browser-legacy-protected-copy-http.test.js` — 7 PASS, 0 FAIL.

## Remaining limits

This rejects resource amplification from oversized caller-supplied inputs.
It does not establish independent CAS/witness operators, externally anchored
rollback protection, physical distributed GET/PUT/STOP fencing, or normative
production migration. No deletion or remote provider mutation occurs.
Issue #65 remains **NO-GO**.
