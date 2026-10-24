# Issue #65 — independent HTTP final-egress authorization fence (DEV)

The opt-in low-level `createZk1MultiproviderRestoreGetHandler` is a separate
surface from the authenticated Express protected-object route. A valid signed
inventory, owner root and identical 2/3 S3/Google Drive/WebDAV ciphertext GETs
do not imply that the requesting device remains authorized while the final
HTTP identity callback is awaited.

## Adversarial failure and repair

- Reproduced RED on the pre-patch code in
  `test/issue-65-full-multiprovider-http-restore.test.js`: revoke the enrolled
  device at the **fourth fresh signed owner-state query**, after the actual
  provider quorum is read. The low-level route returned HTTP **200**, exposing
  `ciphertextBase64` to the formerly authorized caller. This is ciphertext,
  **not server-side plaintext**, but it violates revocation at response egress.
- The route now pins a detached exact operation at construction and refuses
  mismatched URL/operation IDs or ciphertext digests. After the second HTTP
  identity callback and JSON body construction, it invokes the gateway's
  independent nonce-fresh owner/device recheck and rejects expired status
  **before** writing any 200 header or response body.
- GREEN: Node 24 and Node 22 each **12 PASS / 0 FAIL / 0 SKIP** in the two
  multi-provider E2E suites, including real S3 SDK HTTP, Drive HTTPS, WebDAV
  mTLS, owner-signed remote version pins, quorum, restart, signed sidecar,
  late revocation and denial without ciphertext output.

## Non-claims / remaining DEV work

This is an additional rejection boundary, **not an atomic distributed
transaction**. A revocation that races after the final signed check and before
kernel socket write remains a multi-authority fencing design problem. It does
not prove external cloud fsync, physically independent custody, or final
PostgreSQL/SQLite/CAS/witness atomicity. Existing standalone witness admission
`158c130` has a separate independently reported P1 regarding self-certified
terminal proof; do not integrate or advertise it as secure without resolution.
Do not merge, deploy, cut over legacy data or close issue #65 on this evidence.
