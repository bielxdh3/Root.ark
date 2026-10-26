# Issue #65 DEV — owner-pinned ciphertext versions

`Zk1MultiproviderCiphertextRestore.restoreExact()` and
`restoreFromCloudCatalog()` require **every** selected provider reader to
carry `ownerSignedVersionPin`. An Ed25519 signature from the independently
pinned owner authenticates each exact operation, current owner manifest head,
ciphertext root and length, provider namespace/context, object key, and the
provider's immutable S3 `VersionId`, WebDAV `ETag`, or Google Drive file ID.
The service enforces this requirement unconditionally, across requests and
new gateway instances. No caller option or detected field count can disable it.

An omitted pin, a mixed signed/unsigned quorum, or a tampered/replayed pin
rejects the restore before any ciphertext provider GET. Cloud catalog restore
also rejects omitted pins before sidecar GET; a signed sidecar does not supply
permission to fall back to unversioned ciphertext. The HTTP GET and
authenticated Express POST only use these strict ciphertext restore paths.

Legacy copies without owner-signed remote version pins remain **read-only
evidence**. Their separately signed inventory, checkpoints and catalog sidecars
may be inspected/recovered using the existing verification/recovery tools,
subject to their independent bounds. These copies cannot contribute bytes to
the strict restoration quorum or receive a new protected write on that basis.
The owner must issue complete operation-bound version signatures, after
checking the intended provider versions, before cloud ciphertext egress.

## Late rebind while collecting a ciphertext quorum

An individually valid S3/Drive/WebDAV GET does **not** keep its principal or
namespace pinned while later providers finish their GETs. Before releasing
any returned ciphertext, the restore service independently rechecks the fresh
owner/device authorization and **every reader actually counted** in the
matching quorum. Each counted reader must still report the exact originally
signed provider, enabled status, namespace, principal/inventory context, and
opaque object key. These checks use the same bounded request deadline. An S3
principal/namespace switch during a later Drive GET, or during the final owner
authorization check, invalidates the entire result even if both remote copies
have the same signed digest and ciphertext root. The externally pinned provider
domain attestations are also revalidated at the final decision point.
Because the last reader's asynchronous principal check can change an earlier
reader's local namespace, key or enabled status, a final synchronous sweep of
all counted quorum readers follows the last await. A late local rebind fails
closed even when both previously downloaded ciphertext copies still hash to
the owner's pinned root. The DEV HTTP fixture reproduces this rebind after
the first reader has already passed its prior synchronous and asynchronous
checks, and verifies rejection for namespace, key and enabled-status changes.
The signed owner callback can itself wait while a provider's remote principal
changes without altering the locally visible namespace or key. A second
bounded remote principal probe of every counted quorum reader, another fresh
signed owner/device challenge and a final synchronous local reader sweep
reject the demonstrated late principal substitution. The final decision also
checks that signed owner/device status and independently signed provider-domain
attestations have not expired during the last asynchronous authorization.
The adversarial HTTP fixture covers these late owner, principal, nonce and
expiry races without relaxing the required 2/3 ciphertext quorum.

These are best-effort fail-closed observations, **not** a cross-provider atomic
snapshot, lease, fencing token, or durable custody proof: a provider could
change its credentials, remote state, or namespace again immediately after its
last recheck. Production assurance of a simultaneous quorum would require an
independent lease/fencing or comparable coordinated authority. This DEV path
does not claim that protection, remote fsync, or production recovery readiness.

The caller must independently retain/provision the owner public key and head;
the cloud cannot establish that trust anchor. A verified signature establishes
the owner's chosen version, not remote fsync, durability, independence of
administrators, current provider custody, or production recovery readiness.
Only DEV local S3/Drive/WebDAV HTTP fixtures exercise this policy; no real
external provider credentials or production restore are covered.
