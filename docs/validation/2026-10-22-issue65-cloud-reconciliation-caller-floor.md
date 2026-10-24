# Issue #65 — multiprovider cloud readback with caller-supplied minimum floor

This development-only coordination method requires the caller to provide a
minimum signed inventory snapshot and minimum head, and verifies the current
signed Ed25519 inventory chain against them. It verifies exact operation ID,
PostgreSQL physical ciphertext intent/root and GET bytes for S3, Drive and
WebDAV. It reconciles a lost HTTP acknowledgment with read-before-write and
per-provider repair, then independently rereads every provider.

**Important scope:** This does *not* prove the minimum floor was separately
retained or authenticated by the owner. The verification result is now called
`callerSuppliedFloorConsistencyVerified`. It explicitly emits
`independentlyAnchoredFloorProven: false` and
`externalOwnerCustodyVerified: false`; the status is
`PG_SIGNED_AND_CALLER_FLOOR_CLOUD_COPIES_REREAD`, not an assertion of owner
provenance. The caller MUST verify the floor's independently retained source
before making any owner-trust decisions. No current result grants I/O,
production restore, remotely durable commit, atomic multi-cloud transaction or
remote rollback/fencing protection.

Adversarial development fixtures exercise actual disposable S3-compatible HTTP,
simulated Google Drive media HTTPS and real WebDAV TLS/mTLS with independently
signed inventory data; no cloud account/remote production target was used.
