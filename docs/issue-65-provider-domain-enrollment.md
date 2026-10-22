# Issue #65 — externally pinned provider identity and current-device restore

**Status: development-only, NO-GO production.** No deployment, provider
durability guarantee, atomic multiprovider commit, or physical independence
claim is established by this implementation.

## Separate operator enrollment

Zk1ExternallyPinnedProviderDomains requires 2–3 distinct Ed25519 administrator
public keys and explicit SHA-256 DER/SPKI fingerprints, with unique 32-byte
administration-domain IDs. These pins MUST reach the operator outside the
Root.ark API, SQLite ledger, restore sidecar, and storage accounts they vouch
for. Supplying public keys alongside remote sidecar JSON is NOT independent
enrollment.

Each operator signs a short-lived provider-domain-attestation/v1 over provider
kind, administration-domain ID, configured namespace hash, resolved principal
context hash, exact Drive ID (if applicable), Root.ark account/compartment/
keyring scope, and issue/expiry timestamps. The catalog and ciphertext copy
require separately signed bindings if Drive IDs differ. Caller labels,
duplicate signing SPKI keys, duplicate domain IDs, duplicated principal
contexts, expired signatures, mismatched scopes, or changed adapter identity
fail closed before cloud GET/PUT. Signed bytes use the v1 domain separator
and fixed-order JSON; arbitrary JSON is not evidence of authorization.

**Important:** a malicious administrator can issue multiple keys, or cloud
accounts can share infrastructure. A certificate proves the enrolled
administrator signed a configured identity claim; it cannot independently
prove physical custody or separate fault domains. Therefore success results
retain providerPhysicalIndependenceProven:false and remoteDurabilityProven:false.
Operational review of actual identities, credentials, cloud tenancy, TLS peer,
and provider isolation is still needed.

## Current-device authorization

The restore gateway requires a separately pinned SHA-256 of the owner's
DER/SPKI public key, the existing owner-signed current-device grant, and a
fetchFreshSignedDeviceState callback. Each fresh check creates a random
256-bit nonce bound to the exact operation, device ID, authorization key ID,
owner manifest revision/digest and epoch.

The independently operated owner-state authority must sign
current-device-restore-state/v1 with at most 15-second validity and state
ACTIVE. The enrolled device separately signs the nonce, operation ID and
owner-grant signature using its private key. Both signatures are mandatory.
Revocation, stale/replayed nonces, expired responses, wrong owner SPKI,
wrong device/grant and changed epoch fail before remote reads; checks repeat
after provider reads. An additional application active:true callback cannot
replace cryptographic evidence.

The HTTP adapter requires the application session authorizer to return
authorized:true, deviceId, authorizationKeyId matching the verified device
grant before and after restore. Callers must independently authenticate the
session and not copy identifiers from an untrusted HTTP request.

The owner authority and device key MUST NOT be colocated with an untrusted
storage server. Software cannot prove independent owner service custody,
durable revocation linearizability, or current eligibility between two signed
checks. No production route is installed and no plaintext/CEK reaches server.

## Verification

The provider-domain-and-fresh-authorization test exercises duplicate domain
IDs/SPKI, cloned identities and namespaces, expiry, forged signatures,
revoked grants, expired owner response and nonce replay.
The full-multiprovider-http-restore suite uses disposable S3 SDK, Drive HTTPS
and WebDAV mTLS transport while requiring both forms of signed evidence,
including a deliberately dishonest legacy active:true callback that cannot
override an owner-signed revocation.
