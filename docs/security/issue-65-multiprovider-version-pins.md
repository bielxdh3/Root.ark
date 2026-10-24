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

The caller must independently retain/provision the owner public key and head;
the cloud cannot establish that trust anchor. A verified signature establishes
the owner's chosen version, not remote fsync, durability, independence of
administrators, current provider custody, or production recovery readiness.
Only DEV local S3/Drive/WebDAV HTTP fixtures exercise this policy; no real
external provider credentials or production restore are covered.
