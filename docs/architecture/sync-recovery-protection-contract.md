# Sync recovery protection contract

Status: architecture proposal for approved roadmap issue #67. The goal is approved; this document does not claim the runtime feature exists or establish unresolved retention, quota, detection, restore, or metadata-leakage policy.

Related decisions: issue #67, the Zero-Knowledge baseline in `zero-knowledge-migration-contract.md`, and product decisions D-008 and D-009 in `../product-discovery.md`.

## Current evidence and boundary

The repository has ordinary file version history, trash, and instance backup/restore. Those systems do not by themselves prove that an authorized sync client cannot remove every useful recovery point through ordinary overwrite or delete operations. The approved sync engine also has normal mutation and tombstone flows. No anomaly-triggered pause, immutable sync recovery point, protected-retention policy, or exact-head protected restore evidence is recorded as complete for issue #67.

The implementation must be designed with the Zero-Knowledge protocol, existing versioning/trash, backup restore, storage adapters, audit, and device authorization. It must not create a second incompatible content store or silently change normal retention/deletion behavior.

## Security invariants

1. Protected file bytes, names, paths, previews, and recovery keys stay opaque to the server. A recovery point preserves the exact encrypted payload plus the crypto metadata and key-envelope relationships required by an authorized client to verify and decrypt it.
2. Before an accepted overwrite or delete can replace current state, the prior recoverable ciphertext and its required envelope metadata are committed to protected history. The client’s ordinary overwrite/delete API cannot edit, shorten, or erase that history.
3. Protected retention is controlled by service policy, is visible as an explicit state, and cannot be reduced by a normal client. Capacity pressure must not silently shorten protection or discard the only recoverable copy. If safe capacity is unavailable, reject or pause the mutation before it can destroy the last protected state.
4. Detection uses bounded operation and provenance metadata, not server-side plaintext inspection. A service may observe opaque object/compartment identifiers, operation kind, authorized device/session, operation count, and timestamps only after the precise metadata leakage is reviewed against the Zero-Knowledge contract.
5. A pause is enforced at the server mutation boundary for all devices and protocol entry points in the affected scope; a client-side warning alone is not a protection boundary. Replayed requests cannot bypass or reset the pause.
6. A false positive retains both the current state and protected history. Resume/review must not require an implicit restore or discard. Every pause, resume, protected restore, and policy-driven expiry has an attributable, content-free audit event.
7. Restore is a new authorized, auditable operation. It validates stored ciphertext and crypto metadata, preserves the current state as another recovery point, and proves decryption with an authorized client after restoration. A server-side checksum alone is not proof that a user can recover plaintext.

## Proposed bounded architecture

### 1. Immutable recovery records

Extend the existing version and encrypted-object lifecycle rather than maintaining an independent content namespace. For each protected sync mutation, create a recovery record referencing an immutable ciphertext generation and the corresponding versioned crypto metadata/envelopes. The record uses opaque IDs and a content digest, records actor/device/session and server time, and has a server-enforced `protectUntil` value. The content digest detects storage corruption; it is not treated as authorization or proof of successful decryption.

Commit the new recovery record, the new current generation or tombstone, and the detection counters as one idempotent server mutation. A retry with the same operation ID cannot create multiple quota-consuming snapshots or bypass detection. A partial storage or metadata write fails closed before reporting the mutation as accepted.

Do not reuse ordinary trash deletion or ordinary version deletion to expire protected records. Expiry is a separate service-controlled transition after the protected window and any applicable hold. Keep the existing backup rules independent: backups remain a separate copy and expiry boundary, not a substitute for sync recovery history.

### 2. Bounded anomaly state

Maintain a bounded rolling window per approved protection scope. Feed it operation classes that are observable without decrypting content, including delete/tombstone, overwrite/update, move/rename, and repeated key/envelope replacement where protocol metadata exposes those events. Never infer that an encrypted payload is ransomware by examining its content on the server.

If server metadata remains insufficient to distinguish an authorized bulk edit from a destructive burst, pause the affected scope and preserve history; do not auto-resume by deleting old history. Thresholds, window duration, scope boundaries (account, compartment, or device), and the user-visible review path require an explicit product and threat-model decision before the detector is enabled.

The pause state and idempotency/provenance data must be authoritative on the server, bounded in storage, and recoverable across restart. Quota exhaustion and malformed or replayed operations must not erase this state or protected records.

### 3. Retention and capacity behavior

Each protected generation has a service-computed expiry and policy version. Clients may request a protected mutation but cannot set or shorten the expiry. The expiry is not silently extended forever: approved policy may show pending expiry and a clear reason when a hold prevents expiration.

Define both a minimum protected horizon and a hard storage budget before rollout. Near the budget, stop accepting destructive mutations that would require an unretainable prior generation; report a recoverable quota/pause state and preserve the latest current bytes. Do not silently evict the oldest protected generation to make room. The numerical horizon and quota are open: D-008 specifies ordinary trash and backup defaults but does not, by itself, approve the protected-sync retention and capacity values for issue #67.

### 4. Review, resume, and restore

An authorized client must be able to review an opaque change summary and identify files locally using keys it already controls. The server must not return protected names or plaintext previews to an unkeyed operator. Resuming normal writes and restoring an earlier encrypted generation are separate actions. Resume keeps the current generation and every unexpired protected generation; restore creates a new current generation and retains the displaced current state.

The identity permitted to resume a paused scope or select a restore generation, and the recovery UX for devices without keys, are not defined by this document. Do not let a compromised device unilaterally clear its own server pause or delete the only recovery path.

## Required proof before issue #67 can be called complete

- An exact-head test proves every supported ordinary overwrite/delete entry point preserves the prior ciphertext and crypto metadata before changing current state.
- A destructive burst causes one server-enforced pause across devices, survives restart, is idempotent under replay, and does not expose file plaintext or names to the server.
- A safe false-positive resume preserves current files and all protected records; it does not depend on destructive rollback.
- Capacity exhaustion and interrupted writes fail before the only recoverable generation is lost.
- An authorized client verifies and decrypts a restored protected generation after restart and storage-provider round trip; restore and expiry events are audited without content or keys.
- Tests cover legitimate bulk rename/edit, compromised authorized device, replay, cross-device continuation, delete storms, quota exhaustion, interrupted storage, retention expiry, and holds.
- Exact retention horizon, capacity, pause thresholds/window/scope, resume/restore authority, audit fields, storage-provider coverage, and Zero-Knowledge metadata leakage are approved and recorded before enabling production behavior.

## Explicit non-claims

This proposal does not implement a ransomware detector, immutable archive, client review UI, restore workflow, or retention policy. It does not claim server-side content scanning, successful plaintext recovery based only on server checksums, cryptographic erasure, external backup coverage, or production provider behavior. Those claims require implementation, approved policy, and exact-head evidence.
