# Issue #65 — independent issuer provisioning bridge (DEV-OFF)

This is a cryptographic verification contract only. It does not change the
production `/share`, `/open-file`, Sync, legacy, or protected-object routes.
No independent issuer service, enrollment registry, or off-host retained head
has been deployed or demonstrated. **No production cutover or I/O grant exists.**

## Provisioning boundary

`createIssuerProvisionedObjectVerifier` accepts three values at setup time:

- `trustedIssuerPublicKey`: independently provisioned Ed25519 issuer key;
- `immutableAccountId`: immutable legacy-account UUID from independent mapping;
- `independentlyRetainedProvisioningDigest`: exact current issuer statement
  digest from independently maintained custody.

These values must come from a separately authenticated configuration or an
independently administered authority, outside any link request, local account
database, JWT, `createdBy`, owner manifest, or user-uploaded proof. The
factory cannot authenticate the origin or freshness of its own setup inputs.
It rejects a missing pin, but caller code must never use request-supplied
values to initialize the verifier.

The issuer signs a canonical, domain-separated statement binding the
immutable account UUID, ZK account UUID, initial owner Ed25519 SPKI, exact
owner cutover generation and digest, complete-inventory root, object UUID,
object revision and ciphertext SHA-256. The signed grant is strictly
`protected_enforced`, with an affirmative complete-corpus **attestation**.
The signature and independently retained exact statement digest are checked
before the verifier validates the existing owner-signed cutover history,
rotations, anonymous share/open token binding, and 256-level sparse object
inclusion proof. The owner root and object expectations are derived from the
issuer certificate, so an anonymous caller cannot substitute its own pins.
The issuer wire is captured once into an immutable canonical data snapshot;
the exact same canonical message and signature bytes supply both signature
verification and the independently retained digest comparison. Accessors
and throwing descriptor traps fail closed. The owner object statement is
likewise copied once before passing to the existing owner verifier and
comparing its issuer-bound fields. This prevents an attacker-controlled Proxy
from presenting a stale but correctly signed issuer statement for verification
and a different current statement for the pinned digest comparison.

For a completed cutover, an unsigned legacy identity or missing issuer
certificate fails closed within this verifier. A valid owner-signed subset
inventory is rejected when its root differs from the independently
issuer-signed current inventory root. Old generations and owner key
substitution are rejected under the current provisioning digest. The
issuer-signed complete-corpus claim alone cannot prove the issuer actually
enumerated all historical objects or references.

## Missing dependencies before enforcement

An independent issuer must obtain the true complete legacy corpus and
historical references, authenticate immutable account-to-owner provisioning,
sign the verified mapping, and commit each current provisioning digest into
monotonic, off-host custody with freshness and rollback protection. Every
covered server-readable route needs a shared enforced gate, and a never-enrolled
account needs authenticated *negative* membership under the current authority
head before any legacy fallback. Failed or unavailable authority must fail
closed for previously enrolled accounts. Such systems are not supplied by
this module; `authorizesIo`, `completeExternalCorpusProven` and
`independentAnchorCustodyProven` remain false.

Focused verification:

```sh
node --test test/issue-65-zk10-independent-issuer-bridge.test.js \
  test/issue-65-zk10-anonymous-object-binding.test.js \
  test/issue-65-zk10-account-policy.test.js
```
