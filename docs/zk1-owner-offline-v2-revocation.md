# Root.ark #65 — owner-offline V2 revocation and epoch rotation (DEV)

This is a bounded owner-host ceremony, NOT a production revocation
service. It requires canonical WeakMap-branded trusted-device history,
independently pinned owner Ed25519 SPKI, current V2 head (revision,
manifest digest and epoch), independently pinned witness Ed25519 SPKI,
previous witness receipt SHA-256, an independently pinned CAS Ed25519
SPKI and a monotonic CAS sequence floor. Epoch secrets and signing keys
remain on the offline owner machine; only wrapped ciphertext is exported.

## Local execution

Use a fresh private directory under owner control and a trusted local
operator module called owner-context.js (see the existing offline owner
enrollment documentation). It must reconstruct the full signed V2 history
with canonical verifier and provide:

- verifiedHistory, trustedOwnerPublicKey, ownerPrivateKey;
- trustedCommitmentSignerPublicKey, trustedPriorCommitment;
- trustedCasSignerPublicKey and trustedActorPrivateKey (an ACTIVE survivor);
- verifyExternalCommittedCas, which reads a genuinely committed CAS head
  from an independently administered authority, not a browser claim.

Invocation:

    node scripts/zk1-owner-offline-revoke-local.js ^
      --owned-dir E:\trusted-owner-ceremony ^
      --context-module owner-context.js ^
      --owner-spki <independent-owner-spki-sha256-b64url> ^
      --witness-spki <independent-witness-spki-sha256-b64url> ^
      --cas-spki <independent-CAS-spki-sha256-b64url> ^
      --cas-sequence <independently-retained-monotonic-sequence> ^
      --head-revision <pinned-revision> --head-digest <pinned-digest-b64url> ^
      --head-epoch <pinned-epoch> ^
      --prior-receipt-sha256 <independently-pinned-prior-digest-b64url> ^
      --revoke-device <exact-active-device-ID>

The process first writes revocation-candidate.json. It is an
ACTIVE-survivor-signed canonical V2 revoke-device transition, with a
new random 256-bit epoch key and genuine HPKE wraps only for surviving
active devices. A separately active recovery authority also receives a
genuine encrypted package wrap. A revoked device gets no new-epoch wrap.
The candidate is NOT committed and does not authorize any activity.

The operator must have the actual witness/CAS service commit that exact
candidate. Supply its independently witnessed commit as
revocation-committed-receipt.json. The trusted local context separately
reads a higher-sequence signed post-commit witness head and a
CAS-signed offline-cas-commit-proof/v1, which bind the same operation ID,
revision, head digest/epoch, request and commit nonces, witness receipt
SHA-256, and monotonically increasing CAS sequence. Witness and CAS
signers must be different independently pinned identities. A bare
success boolean or unsigned head never suffices.

Only then does the owner sign revocation-browser-delivery.json. It
contains the signed V2 manifest, predecessor/current witness receipts,
the separate signed CAS head, and owner-signed current-head device
grants ONLY for survivors. Browser code can verify the transfer using
RootarkZk1V2OwnerRevocationImport.verifyRevocationDelivery with the
delivery, owner/witness/CAS SPKI byte arrays and independently acquired
head, receipt and CAS sequence pins. Stale grants, the revoked device,
forks, replayed CAS and missing signatures fail closed.

## Explicit limitations

The browser transfer proof is NOT full verified V2 manifest history or
fresh protected-I/O admission. Its result always has
authorizesProtectedIo=false and liveCasOrCustodyVerified=false. The
normal client/server still must authenticate the canonical full
genesis-to-current history, current ACTIVE grant, owner and witness
head, and all protected read/provider pins. No automatic UI admission
or production service is added.

An old content-catalog root signed by the newly revoked device is
NOT re-endorsed automatically: signatures on historical ciphertext
prove past provenance, not current ACTIVE authority. Browser
backup/restore and protected-read routes must fail closed until an
independently pinned current owner re-endorses the exact catalog root
under the new epoch and a current ACTIVE grant. This offline ceremony
cannot replace separately witnessed catalog re-endorsement.

Offline cryptographic signatures do not prove physical storage
durability, infrastructure/operator independence, current remote
availability or erasure of already downloaded old-epoch ciphertext.
The independent SPKI/head/receipt and CAS sequence floors MUST be
persisted and advanced outside the app after a successful ceremony.
A lost commitment ACK requires a separately verified fresh CAS head
before any subsequent transition; never replay the old candidate.

The tests use disposable synthetic keys and a separate real Node CLI
subprocess. Locally generated witness/CAS fixture signatures prove
protocol checks, NOT a real remote CAS deployment. No server plaintext,
CEKs or private owner keys are exported.
