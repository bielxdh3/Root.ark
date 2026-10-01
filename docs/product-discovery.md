# Root.ark Product Discovery

Status: discovery open; Round 1 through Round 3 decisions recorded

Related issues: #4 and #10

## Purpose

This document records explicit product decisions before they become implementation tasks. Root.ark previously evolved through spontaneous feature requests sent directly to an executor. That produced useful capabilities, but no stable product contract, trust model, or ordered roadmap.

Future discovery should work like the AIP planning process: ask a small number of concrete questions per round, record exact answers and consequences, and implement only after the decision is approved and added to `docs/plan-tree.md`.

## Decision status labels

- `[DECIDED]`: explicitly approved by the product owner.
- `[PROVISIONAL]`: current assumption, not yet approved as permanent.
- `[OPEN]`: unresolved and requires a concrete answer.
- `[REJECTED]`: explicitly not wanted.
- `[DEFERRED]`: valid question intentionally postponed.
- `[CONFLICT]`: existing code or older plans disagree and require reconciliation.

## Rules

1. Do not infer product decisions from existing code alone.
2. Do not treat an old chat idea as approved merely because it was discussed.
3. Record the exact answer, date, consequences, and affected plan-tree items.
4. Ask at most a small number of high-value questions per round.
5. Prefer concrete choices and scenarios over abstract preference questions.
6. Do not implement while a material trust, data, recovery, or identity decision remains open.
7. When an answer changes, preserve the superseded decision and explain the migration consequence.
8. Product discovery may run in parallel with bounded stabilization, but it must not interrupt critical security work.

## Current known facts

- `[PROVISIONAL]` A working Node.js/Express file-management product exists in `bielxdh3/root.ark`.
- `[PROVISIONAL]` The existing application supports users, permissions, folders, uploads, approval, versions, public links, encryption, analytics, audit, SQLite, backups, trash, scanning/quarantine, WebDAV, cloud storage, and a one-way sync MVP.
- `[DECIDED]` D-001 keeps Root.ark active in this repository while allowing only a future, explicitly designed and approved migration or selective reuse with BielOS.
- `[DECIDED]` D-002 defines Root.ark as a private administrator-controlled storage and transfer service with rigorously isolated compartments and no normal public registration.
- `[DECIDED]` D-003 selects client-side, zero-knowledge encryption; the server and administrator must not normally read plaintext user content.
- `[DECIDED]` D-004 permits bounded, least-privilege administrator operations and auditable support access while keeping content and unnecessary metadata hidden.
- `[DECIDED]` D-005 defines administrator-controlled accounts, revocable invitations, user-controlled recovery, and audited deletion with default retention.
- `[DECIDED]` D-006 defines client-side key lifecycle, compartment-isolated keys, trusted-device recovery, rotation for future content, and authorized offline access.
- `[DECIDED]` D-007 defines versioned client-side cryptography, per-file keys, compartment-isolated hierarchies, mandatory recovery-package verification, explicit historical re-encryption, and forced future-authorization rotation after package compromise.
- `[DECIDED]` D-008 defines 30-day normal deletion and backup retention, 30-day operational logs, 180-day security logs, immediate access revocation, and cryptographic erasure that cannot be declared complete while service-controlled backup key material remains usable.
- `[DECIDED]` D-009 defines quarantined unverified external uploads, encrypted client-generated previews and indexes, server-blind public links, local-bridge-only zero-knowledge WebDAV, and eventual mandatory bidirectional synchronization.
- `[CONFLICT]` Existing server-readable, metadata-dependent, preview, scanning, WebDAV, sync, and backup behaviors require reconciliation with D-003; implementation is not itself product approval.
- `[OPEN]` The final product name and spelling are not confirmed.
- `[FROZEN TECHNICAL PROFILE]` Algorithms, library policy, KDF domain separation, nonce construction, and envelope serialization are specified in `docs/architecture/zero-knowledge-migration-contract.md` section 2.1 for bounded Phase 9 foundation work. This does not establish implementation, interoperability, or runtime acceptance.
- `[OPEN]` Recovery authority, migration scope/window, backup key invalidation mechanics, quarantine workflow, sync conflict authority/protocol implementation, WebDAV bridge deployment, and detailed client behavior remain unresolved or unimplemented as documented in the architecture and owner-decision packet.

## Decision record format

Use this template for every approved decision:

```md
### D-XXX: Decision title

- Status: `[DECIDED]`
- Date: YYYY-MM-DD
- Decision: <exact approved behavior>
- Reason: <why>
- Consequences:
  - <security/architecture consequence>
  - <data/migration consequence>
  - <UX/operations consequence>
- Rejected alternatives:
  - <alternative and reason>
- Affected plan-tree phases:
  - <phase>
- Required follow-up issues:
  - #<issue>
```

## Approved Round 1 decisions

The product owner approved these records on 2026-08-02. They are durable product decisions; unresolved implementation and architecture details remain open.

### D-001: Root.ark and BielOS relationship

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: Option D. Root.ark remains actively developed in this repository. The long-term possibility is a controlled migration or selective reuse into BielOS after a dedicated architecture, security, and contract-definition phase. Root.ark runtime, data, and authentication remain isolated until an integration is explicitly designed and approved.
- Reason: BielOS may centralize accounts in the future, but integration must not happen automatically.
- Consequences:
  - Analysis: The current canonical runtime and data boundary remains this repository.
  - Analysis: Future identity sharing requires an explicit integration contract, threat model, and migration plan.
  - Analysis: Existing stabilization work remains valid without making this repository a legacy product.
- Explicitly prohibited automatic actions:
  - Copying or merging code with BielOS.
  - Sharing databases, sessions, or authentication.
  - Migrating user files.
  - Changing the encryption model.
  - Reclassifying this repository as legacy.
- Rejected alternatives:
  - Options A, B, and C were not selected for the current direction; they are not recorded as permanently impossible future states.
- Affected plan-tree phases:
  - Phase 5.0: Product identity and repository relationship.
  - Phase 5.4: Approved product brief.
- Required follow-up issues:
  - #10 remains open until the decision is reconciled in merged documentation and all required consequences are satisfied.
  - #4 remains open for the rest of product discovery.

### D-002: Intended users and tenancy

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: Option E with owner-specific bounds. Root.ark is a private storage and transfer service administered by BielOS or an authorized administrator. The administrator creates or approves accounts, compartments, and access. Public requests such as `/apply` may exist as isolated requests but never grant access automatically. Unrelated users may coexist only in rigorously isolated compartments. External recipients may use links or access keys without becoming normal system users.
- Reason: Unrelated users must not see one another's data, names, metadata, or activity.
- Consequences:
  - Analysis: Account, compartment, permission, and activity isolation are tenant-boundary requirements.
  - Analysis: External links and keys require a separate access principal and revocation model from ordinary accounts.
  - Analysis: Public registration, abuse handling, and support remain bounded private-service concerns rather than SaaS defaults.
- Explicitly prohibited automatic actions:
  - Normal public registration.
  - Automatic access from a public application request.
  - Cross-compartment visibility of data, names, metadata, or activity.
- Rejected alternatives:
  - Public hosted SaaS registration is not the selected audience model.
  - Other public sharing surfaces remain possible only when separately designed and approved.
- Affected plan-tree phases:
  - Phase 5.1: Users and trust model.
  - Phase 5.2: File and storage behavior.
- Required follow-up issues:
  - #4 remains open for account, invitation, sharing, and scope-boundary discovery.

### D-003: Server, administrator, and metadata visibility

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: Option B. User content uses client-side, zero-knowledge encryption. The server and administrator must not normally decrypt or read plaintext content. Filenames and folder names should preferably be encrypted; only the minimum operational metadata may remain visible. Previews and search indexes should be client-generated or unavailable for zero-knowledge files. Upload scanning should occur before client encryption when possible. Administrators may back up and restore encrypted blobs and required metadata, manage accounts, compartments, permissions, blocks, backups, and deletion, but may not silently access decrypted content.
- Reason: The server and administrator must not be able to read user content normally, and lost encryption keys may make files unrecoverable.
- Consequences:
  - Analysis: Key generation, storage, rotation, revocation, sharing, and recovery become client-side or user-controlled security boundaries.
  - Analysis: Server-side previews, full-text search, and decryption-based scanning cannot be assumed for zero-knowledge files.
  - Analysis: Backup and restore preserve encrypted material without creating an administrator plaintext-recovery path.
- Explicitly prohibited automatic actions:
  - Server decryption for ordinary administrator inspection.
  - Automatic recovery of encrypted files after key loss.
  - Treating password reset as encryption-key recovery.
- Rejected alternatives:
  - Normal server-readable encryption is not the selected final trust model.
  - A mixed model was not approved in this round, although future compartment-specific exceptions were not permanently ruled out.
- Affected plan-tree phases:
  - Phase 5.1: Users and trust model.
  - Phase 5.2: File and storage behavior.
  - Phase 5.3: Privacy and operations.
- Required follow-up issues:
  - #4 remains open for the exact metadata, key-recovery, sharing, scanning, preview, search, and client requirements.
  - #10 remains open until the BielOS relationship and its trust-model consequences are reconciled after documentation merge.

## Approved Round 2 decisions

The product owner approved these records on 2026-08-02. They define policy boundaries only; all deferred architecture and implementation details remain explicitly open.

### D-004: Administrator authority and metadata visibility

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: Administrators may create, invite, approve, disable, and delete accounts; create and manage isolated compartments; grant and revoke permissions; revoke sessions and access links; manage quotas, operational blocks, quarantine decisions, backup jobs, restores of encrypted material, retention, and permanent deletion; and view security and operational audit events required to administer the service. Support impersonation is never silent: it requires explicit user authorization, limited duration, and complete audit logging. Filenames and folder names remain encrypted and invisible to administrators whenever technically possible. MIME and extensions derived from content remain hidden, except for strictly necessary operational categories. Audit logs may identify the acting user, IP, device, time, and action, but must not contain content, keys, decrypted names, or unnecessary sensitive data.
- Reason: No separate reason was supplied; the owner approved least-privilege administration, explicit support access, and minimization of content-derived metadata.
- Consequences:
  - Analysis: Support impersonation requires a consent, expiry, authorization, and audit workflow.
  - Analysis: Logs become a protected personal-data surface with separate retention and access requirements.
  - Analysis: Operational features must use opaque identifiers and minimum metadata where possible.
- Explicitly prohibited automatic actions:
  - Silent user impersonation.
  - Plaintext content access or reconstruction of encryption keys.
  - Password reset as content-key recovery.
  - Bypassing compartment boundaries.
  - Server-generated plaintext previews or search indexes.
- Rejected alternatives:
  - Silent support impersonation and indiscriminate administrator visibility of names, MIME details, or content-derived metadata.
- Deferred details that remain `[OPEN]`:
  - Consent and maximum duration for support impersonation.
  - Audit retention, access, export, and deletion rules.
  - Exact operational MIME categories and metadata inventory.
- Affected plan-tree phases:
  - Phase 5.1: Users and trust model.
  - Phase 5.3: Privacy and operations.
- Required follow-up issues:
  - #4 remains open for the exact authority, metadata, and audit requirements.
  - #10 remains open; D-004 does not resolve the BielOS integration gate.

### D-005: Accounts, invitations, and recovery

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: Administrators may create accounts directly or issue revocable, expiring invitations. No normal public registration exists, and an `/apply` request never grants access automatically. Username is sufficient; email is optional for notifications and recovery. A user-controlled recovery package is mandatory during encryption setup, with a clear warning that losing all recovery methods may make files unrecoverable. Trusted devices and, optionally, a person or device explicitly chosen by the user may participate in recovery. No universal administrator decryption key exists. Account deletion revokes access immediately, while permanent deletion follows a default retention period; immediate permanent deletion requires explicit administrative action, reinforced confirmation, and audit.
- Reason: No separate reason was supplied; the owner explicitly requires clear warning of unrecoverability when all recovery methods are lost.
- Consequences:
  - Analysis: Login recovery and content-key recovery are separate operations.
  - Analysis: Invitation and application flows require revocation, expiry, non-automatic access, and audit boundaries.
  - Analysis: Account deletion must distinguish immediate access revocation from later data destruction.
- Explicitly prohibited automatic actions:
  - Public account registration.
  - Automatic access from an application request.
  - A universal administrator recovery key.
  - Password reset that silently decrypts zero-knowledge content.
  - Immediate permanent deletion without reinforced confirmation and audit.
- Rejected alternatives:
  - Mandatory email identity, administrator-only recovery of encrypted content, and unconfirmed immediate deletion.
- Deferred details that remain `[OPEN]`:
  - Invitation token format and exact expiry.
  - Recovery-package structure and storage.
  - Rules for a trusted recovery person or device.
  - Default retention duration and restoration during retention.
- Affected plan-tree phases:
  - Phase 5.1: Users and trust model.
  - Phase 5.3: Privacy and operations.
- Required follow-up issues:
  - #4 remains open for authentication, invitation, recovery, retention, and deletion details.
  - #10 remains open; D-005 does not authorize shared BielOS identity or recovery.

### D-006: Client-side key lifecycle and device access

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: Encryption keys are generated client-side. A trusted device may approve a new device, and a valid recovery package may authorize one without an existing device. Each compartment has its own key or isolated key set. When a user or device loses access, keys rotate for new content; content already downloaded or previously decrypted cannot be revoked retroactively. Authorized devices must support offline access, storing only indispensable cryptographic material protected by the operating system and local authentication.
- Reason: No separate reason was supplied; the owner explicitly requires compartment isolation and authorized offline access.
- Consequences:
  - Analysis: Key hierarchy and authorization must be isolated per compartment.
  - Analysis: Device authorization, removal, and rotation must be auditable and affect future content without claiming retroactive revocation.
  - Analysis: Offline clients create a local key-material and device-security boundary.
- Explicitly prohibited automatic actions:
  - Reusing one key across compartments.
  - Storing unnecessary local key material.
  - Claiming that previously downloaded ciphertext or plaintext can be revoked retroactively.
  - Creating a universal administrator key.
- Rejected alternatives:
  - No-offline-access as the default and a shared key model across compartments.
- Deferred details that remain `[OPEN]`:
  - Cryptographic protocol and key-envelope format.
  - Rotation schedule and membership-change procedure.
  - Lost-device handling and offline retention.
  - Interactions with scanning, previews, search, sharing, WebDAV, synchronization, and backups.
- Affected plan-tree phases:
  - Phase 5.1: Users and trust model.
  - Phase 5.2: File and storage behavior.
  - Phase 5.3: Privacy and operations.
- Required follow-up issues:
  - #4 remains open for the client-side architecture and key lifecycle details.
  - #10 remains open; D-006 does not authorize BielOS key sharing or migration.

## Approved Round 3 decisions

The product owner explicitly approved these records on 2026-08-02. They define product policy only; no implementation is authorized by these decisions.

### D-007: Cryptographic architecture and recovery

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: Use a versioned, standards-based, independently reviewable client-side encryption design with no custom primitives or improvised algorithms. Each file receives a unique random key. Each compartment has an isolated key hierarchy, and file keys are wrapped by keys from that compartment. The server stores ciphertext, authenticated metadata required for decryption, versions, and key envelopes that it cannot independently open. Encryption must provide confidentiality, integrity, and tamper detection. Recovery packages are generated client-side, contain only protected recovery material, are exportable and versioned, and must be tested by the user before encryption setup is considered complete. Removing a user or device rotates material used for future content and authorizations. A user may explicitly request historical re-encryption; it must be presented as potentially expensive and time-consuming and must never run silently. A suspected recovery-package leak revokes the old package and forces rotation of material used for future authorizations. Historical re-encryption after a leak may be offered separately and is never automatic. Recovery must not grant plaintext access to the server or administrator.
- Reason: Compartment isolation limits the impact of compromise. Mandatory package verification proves that recovery works. Historical re-encryption is costly and requires explicit authorization. A leaked package must not authorize future operations.
- Consequences:
  - The setup flow must block completion until package verification succeeds.
  - Key rotation must distinguish future authorization from historical content.
  - Historical re-encryption requires an explicit, auditable, resumable operation with integrity checks.
  - Package replacement must invalidate the old package for future authorization.
  - Login recovery and content-key recovery remain separate operations.
- Explicitly prohibited automatic actions:
  - Custom cryptographic primitives or a universal administrator key.
  - Reusing keys across files or compartments.
  - Completing setup without verified recovery material.
  - Automatically re-encrypting historical content.
  - Allowing a compromised recovery package to authorize future operations.
  - Claiming retroactive erasure of ciphertext or plaintext already copied outside managed storage.
- Rejected alternatives:
  - A shared hierarchy across compartments.
  - Optional recovery-package verification.
  - Silent historical re-encryption.
  - Silent handling of a leaked recovery package.
  - Selecting algorithms, libraries, KDFs, nonces, or formats during product discovery.
- Deferred details that remain `[OPEN]`:
  - Recovery-package format and approved authority policy; implementation evidence must verify the frozen technical profile and the agreed recovery policy.
  - Versioned test vectors, cross-client interoperability fixtures, and migration tests.
  - Device authorization, rotation, rollback, failure recovery, and concurrent-operation rules.
  - Historical re-encryption scope, progress, cancellation, and restore behavior.
- Affected plan-tree phases:
  - Phase 5.1: Users, trust, recovery, and devices.
  - Phase 5.2: Storage, keys, versions, and lifecycle.
  - Phase 5.3: Privacy, audit, and operations.
  - Phase 5.4: Approved product brief.
- Required follow-up issues:
  - #4 remains open for the client-side architecture and key lifecycle details.
  - #10 remains open; D-007 does not authorize shared BielOS identity, keys, or recovery.

### D-008: Retention, deletion, audit, backups, and offline copies

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: Normal trash and deletion retention is 30 days. Access revocation is immediate regardless of retention. Operational logs are retained for 30 days, security and audit logs for 180 days, and backups use a rolling 30-day retention with automatic expiry. Deleted ciphertext may remain physically present in already-created backups until those backups expire. Immediate cryptographic erasure may be explicitly requested and requires reinforced confirmation and audit. It is complete only when every service-controlled key or envelope that could decrypt the content has been destroyed or made unusable, including related backup structures. Ciphertext may remain in backups after completion, but must be cryptographically unrecoverable by the service. If old backup envelopes cannot be invalidated safely, erasure remains pending until those backups expire and must not be reported as complete. Erasure does not remove downloaded, exported, already-decrypted, recipient-held, or externally stored copies. Logs may contain actor, opaque account or compartment identifier, IP, device, timestamp, action, result, and relevant security state, but not plaintext, decrypted names, keys, recovery material, search terms, previews, or unnecessary payloads. Access to audit logs is itself audited.
- Reason: Access must be revoked immediately even when permanent destruction occurs later. The owner requires truthful reporting of cryptographic erasure and clear warnings about copies outside service control.
- Consequences:
  - Revocation, retention, logical deletion, cryptographic erasure, and backup expiry are separate states.
  - Erasure requires a service-wide inventory of usable key and envelope paths, including backups.
  - The system needs a pending state when backup key invalidation is not yet proven.
  - Erasure requests require strong authorization, explicit scope, reinforced confirmation, and audit evidence.
  - The product cannot promise retroactive deletion of copies outside managed storage.
- Explicitly prohibited automatic actions:
  - Keeping access active because content remains within retention.
  - Declaring erasure complete while service-controlled backup key material remains usable.
  - Claiming that ciphertext remaining in backups is plaintext-recoverable by the service after completed erasure.
  - Promising removal of downloaded, exported, decrypted, recipient-held, or external copies.
  - Logging plaintext, keys, or recovery material.
  - Silently executing cryptographic erasure.
- Rejected alternatives:
  - Retention periods other than the approved 30/30/180-day defaults.
  - Indefinite backups.
  - Weak or implicit confirmation for immediate destruction.
  - Reporting erasure as complete before old backup envelopes are invalidated or expired.
- Deferred details that remain `[OPEN]`:
  - Exact backup key topology, invalidation mechanism, proof of destruction, and idempotence.
  - Who may request or approve erasure and its file/compartment/account scope.
  - Legal holds, investigation extensions, restore permissions, and export/deletion permissions.
  - Cache expiry and secure local deletion for offline clients.
- Affected plan-tree phases:
  - Phase 5.2: Versions, trash, backups, restore, and permanent deletion.
  - Phase 5.3: Audit, privacy, and operations.
  - Phase 5.4: Approved product brief.
- Required follow-up issues:
  - #4 remains open for retention, deletion, audit, backup, and recovery details.
  - #10 remains open; D-008 does not authorize shared BielOS data, databases, or retention policy.

### D-009: Zero-knowledge feature compatibility

- Status: `[DECIDED]`
- Date: 2026-08-02
- Decision: External uploads that cannot be scanned client-side enter quarantine by default and are clearly marked unverified. An administrator may reject or release them only under an explicit policy, without server decryption; release does not itself claim malware verification. Scanning, previews, thumbnails, MIME detection, and full-text indexes are generated client-side where supported, and derived data is stored encrypted. Devices without keys cannot access previews or indexes, and server-side plaintext indexing is prohibited. Sharing wraps the required file or compartment keys. Public links are allowed only with a server-blind key design. Revocation blocks future service access but cannot revoke plaintext or keys already obtained by recipients; upload-only and download/share links remain separate capabilities. Bidirectional synchronization is a mandatory final product capability, but belongs to a later dedicated phase covering conflicts, versions, exclusions, renames, offline access, and security. Zero-knowledge WebDAV requires a trusted local bridge or client; server-native WebDAV must not decrypt content. Backups preserve ciphertext, authenticated metadata, encrypted indexes/previews, and key envelopes, and restore must preserve crypto versions, envelope relationships, and integrity metadata. Restore success requires proof that authorized clients can decrypt after restoration.
- Reason: The approved compatibility rules must preserve the zero-knowledge trust boundary while allowing controlled quarantine, encrypted derived data, server-blind sharing, local WebDAV access, and a future complete synchronization capability.
- Consequences:
  - Quarantine, rejection, release, warnings, and audit need their own explicit workflow; released content remains potentially unverified.
  - Clients without keys must fail closed for previews and indexes without revealing protected content.
  - Public links and recipients create explicit limits on future revocation.
  - A local WebDAV bridge is a separate trust boundary requiring its own architecture and security model.
  - Bidirectional synchronization cannot be treated as a small extension of the existing one-way MVP.
- Explicitly prohibited automatic actions:
  - Server decryption for scanning, indexing, previews, WebDAV, or conflict resolution.
  - Automatic release of unverified external uploads.
  - Describing quarantined or released content as verified without evidence.
  - Public links whose decryption secret is independently available to the server.
  - Claiming retroactive revocation of plaintext or keys already obtained by recipients.
  - Treating existing server-readable WebDAV behavior as the final zero-knowledge contract.
  - Implementing bidirectional synchronization before its dedicated architecture phase.
  - Creating a universal administrator recovery path through backups.
- Rejected alternatives:
  - Blocking every unscanned external upload as the only default; quarantine is the approved default.
  - Plaintext server-side previews, search indexes, or malware scanning.
  - Server-decryptable public links.
  - Native server-side WebDAV decryption for protected compartments.
  - Treating bidirectional synchronization as optional or indefinitely unspecified.
- Deferred details that remain `[OPEN]`:
  - Client scanning integration, quarantine policy, release authority, notifications, and audit.
  - Preview/index formats, key binding, sharing-link expiry, recipient controls, and limits.
  - Synchronization protocol, conflict authority, version/deletion/rename semantics, offline state, and device security.
  - Local bridge platforms, isolation, backup/restore tests, and migration behavior.
- Affected plan-tree phases:
  - Phase 5.1: Users and trust model.
  - Phase 5.2: Storage, previews, search, sharing, WebDAV, synchronization, and restore.
  - Phase 5.3: Privacy, audit, and operations.
  - Phase 5.4: Approved product brief.
  - Phases 3.3, 3.4, and 3.5 remain historical operational-validation phases and are not reopened or reclassified by D-009.
- Required follow-up issues:
  - #4 remains open for client, scanning, preview, search, sharing, WebDAV, and synchronization requirements.
  - #10 remains open; D-009 does not authorize shared BielOS identity, keys, sessions, data, or runtime behavior.

## Discovery sequence

The orchestrator should normally follow this order because later answers depend on earlier trust and user decisions.

## Round 1: Product identity and relationship

### Q1. Canonical product

- Status: `[DECIDED]` — recorded in D-001.
- Question: Is this repository the final independent Root.ark product, a legacy prototype, or a code source for a future BielOS module?
- Why it matters:
  - determines canonical repository and roadmap;
  - prevents accidental merging of incompatible trust models;
  - determines whether stabilization is an end state or migration preparation.

Concrete answer options:

1. Keep this repository as an independent product.
2. Treat it as a legacy prototype and design a separate BielOS module.
3. Keep both, with independent purposes and no shared runtime.
4. Plan a controlled migration/reuse after a dedicated architecture phase.
5. Another explicitly described relationship.

### Q2. Final name

- Status: `[OPEN]`
- Question: What is the exact canonical spelling and capitalization?
- Existing variants:
  - `Root.ark`
  - `root.ark`
  - `root.arc`
  - another name
- Consequences:
  - repository naming;
  - UI branding;
  - domains and documentation;
  - migration/compatibility labels;
  - package and executable names.

### Q3. Intended audience

- Status: `[DECIDED]` — recorded in D-002.
- Question: Who is expected to use the final product?

Concrete models:

1. Biel only.
2. Biel plus explicitly invited family/partner/team.
3. Private self-hosted product for technical users.
4. Public hosted SaaS with customer accounts.
5. Public sharing surface with private administrator-created compartments.
6. Another bounded audience.

The answer determines registration, invitations, abuse handling, support, tenant isolation, and legal/privacy obligations.

## Round 2: Trust and administrator powers

### Q4. Can the server administrator read files?

- Status: `[DECIDED]` — recorded in D-003.
- Question: Under the intended security model, can the administrator/server decrypt and inspect user files?

Concrete models:

1. Yes, normal server-managed encryption and access controls.
2. No, zero-knowledge/client-side encryption for all user content.
3. Mixed: some compartments are zero-knowledge and some are server-readable.
4. Personal-only deployment where this distinction is intentionally less strict.

This decision must be made before redesigning encryption, recovery, previews, scanning, search, WebDAV, or sharing.

### Q5. Administrator authority

- Status: `[DECIDED]` — recorded in D-004; exact consent, retention, and operational metadata details remain open.
- Question: Which actions may an administrator perform?

D-003 establishes that account, compartment, permission, block, backup, and deletion management does not grant plaintext content access. The complete authority matrix remains open.

Decide separately:

- create/disable/delete accounts;
- reset passwords;
- reset or revoke encryption access;
- view filenames and metadata;
- read file contents;
- restore backups;
- release quarantined files;
- view audit logs and analytics;
- impersonate users;
- transfer ownership;
- permanently delete data.

Avoid a vague `admin can do everything` rule. Every power has recovery and abuse consequences.

### Q6. Lost password or key

- Status: `[DECIDED]` at policy level in D-005 and D-006; exact recovery-package, trusted-recovery, and key-protocol details remain open.
- Question: What should happen when a user loses a password, second factor, recovery code, or encryption key?

Possible policies:

- administrator resets access and files remain readable;
- account access resets but zero-knowledge files remain unrecoverable;
- designated recovery key/person;
- recovery package exported by the user;
- no recovery by design;
- mixed policy by compartment.

## Round 3: Accounts, identity, and sessions

### Q7. Account creation

- Status: `[DECIDED]` — D-002 and D-005 require administrator creation or approval, direct creation or revocable expiring invitations, and no automatic `/apply` access.
- Question: Who may create accounts?

Models:

- administrator only;
- invitation only;
- public registration with verification;
- no accounts, only compartments/share links;
- external identity provider;
- shared identity with BielOS after a dedicated integration phase.

### Q8. Authentication requirements

- Status: `[OPEN]`
- D-005 fixes username sufficiency, optional email, and separation of login recovery from content-key recovery. Password policy, 2FA, session duration, device lists, and lockout details remain open.
- Decide:
  - username versus email;
  - password requirements;
  - 2FA scope: administrator only, optional, or mandatory;
  - session duration;
  - device/session list and revocation;
  - trusted devices;
  - passwordless or external identity later;
  - recovery and lockout policy.

### Q9. Identity relationship with BielOS

- Status: `[OPEN]`
- Question: If Root.ark and BielOS coexist, should authentication be independent, federated, or shared?
- Rule: no direct integration until issue #10 is resolved and a dedicated threat model exists.

## Round 4: Storage and encryption

### Q10. Canonical storage

- Status: `[OPEN]`
- Choose the source of truth:
  - local disk;
  - S3-compatible storage;
  - Google Drive;
  - hybrid local cache plus cloud authority;
  - user-selected backend;
  - encrypted blobs in one backend with replicated backup.

Clarify whether changing providers is migration, replication, or live multi-backend operation.

### Q11. Encryption levels

- Status: `[DECIDED]` at policy level in D-003, D-007, and D-009; exact protocol, implementation, and compatibility design remain `[OPEN]`.
- Decide whether the current multiple encryption modes remain product behavior or are simplified.
- Required consequences:
  - preview/search support;
  - backup/restore;
  - key rotation;
  - sharing;
  - WebDAV;
  - scanning;
  - synchronization;
  - recovery.

### Q12. Metadata privacy

- Status: `[DECIDED]` at the policy level in D-003 and D-004; exact operational categories, retention, access, and export rules remain open.
- Decide whether the server may see:
  - filenames;
  - folder names;
  - sizes;
  - MIME/extensions;
  - timestamps;
  - owners/recipients;
  - activity;
  - search index;
  - thumbnail/preview data.

Zero-knowledge content does not automatically mean zero-knowledge metadata.

## Round 5: File lifecycle

### Q13. Upload approval

- Status: `[DECIDED]` at policy level in D-009; exact quarantine, release, notification, and audit workflow remains `[OPEN]`.
- Question: Why does upload approval exist in the final product?

Possible purposes:

- administrator moderation;
- protection for shared/inbox folders;
- all uploads require approval;
- only external uploads require approval;
- legacy behavior to remove.

### Q14. Versions

- Status: `[OPEN]`
- Decide:
  - automatic versions versus overwrite;
  - maximum count or age;
  - user/admin deletion rights;
  - encrypted-version handling;
  - backup and storage billing consequences.

### Q15. Trash and permanent deletion

- Status: `[DECIDED]` at policy level in D-005 and D-008; exact restore permissions, backup key invalidation, and cryptographic-erasure implementation remain `[OPEN]`.
- Decide:
  - default retention period;
  - who can restore;
  - who can permanently delete;
  - whether backup copies survive deletion;
  - legal/operational meaning of `permanent`;
  - zero-knowledge key deletion as cryptographic erasure.

### Q16. Backup and restore promise

- Status: `[DECIDED]` at policy level in D-008 and D-009; exact backup key topology, restore authority, testing, and erasure proof remain `[OPEN]`.
- Decide:
  - what is backed up;
  - schedule and retention;
  - off-device copies;
  - encrypted key handling;
  - restoration authority;
  - recovery point and recovery time expectations;
  - how restore is tested.

## Round 6: Sharing and external access

### Q17. Share recipients

- Status: `[DECIDED]` at policy level in D-009; exact recipient identity, public-link controls, expiry, and key-envelope design remain `[OPEN]`.
- Choose supported models:
  - authenticated internal users;
  - public bearer links;
  - password-protected links;
  - recipient email/identity binding;
  - one-time links;
  - upload-only inbox links;
  - zero-knowledge recipient encryption.

### Q18. Share controls

- Status: `[OPEN]`
- Decide:
  - expiration;
  - view/download limits;
  - revocation;
  - preview versus download;
  - watermarking;
  - audit visibility;
  - whether public links survive file moves/restores;
  - whether recipients can redistribute access.

## Round 7: Clients and protocols

### Q19. Synchronization

- Status: `[DECIDED]` at policy level in D-009: bidirectional synchronization is a required final capability, but implementation remains deferred to a dedicated architecture phase.
- Decide:
  - upload-only versus bidirectional;
  - deletion synchronization;
  - rename/move synchronization;
  - conflicts;
  - offline edits;
  - selective folders;
  - background startup/service;
  - maximum file size;
  - encryption location;
  - multi-device state.

### Q20. WebDAV

- Status: `[DECIDED]` at policy level in D-009: zero-knowledge WebDAV requires a trusted local bridge or client; server-native decryption is not approved. Exact bridge architecture remains `[OPEN]`.
- Decide whether WebDAV is:
  - a supported core interface;
  - an optional advanced feature;
  - local/private only;
  - deprecated in favor of a sync client.

Clarify MOVE, DELETE, locking, encrypted files, nested folders, and client compatibility.

### Q21. Web, PWA, desktop, and mobile

- Status: `[OPEN]`
- Decide required clients and their priority.
- Do not build every client because it sounds complete. Each client creates authentication, offline, update, storage, and security obligations.

## Round 8: Privacy, audit, analytics, and operations

### Q22. Audit visibility

- Status: `[DECIDED]` at policy level in D-004 and D-008; retention is 30 days for operational logs and 180 days for security/audit logs. Exact access, export, deletion, privacy, and investigation-extension rules remain `[OPEN]`.
- Decide who sees which events and how long they are retained.
- Separate security audit from product analytics.
- Decide export, deletion, IP/user-agent treatment, and privacy limits.

### Q23. Product analytics

- Status: `[OPEN]`
- Decide whether analytics are needed for a personal/private product.
- If retained, define minimum necessary metrics and whether users can see or disable them.

### Q24. Deployment and ownership

- Status: `[OPEN]`
- Decide:
  - personal machine, home server, VPS, managed service, or BielOS host;
  - operating system support;
  - domain and reverse proxy;
  - TLS and remote access;
  - updates and rollback;
  - monitoring;
  - storage capacity alerts;
  - disaster recovery responsibility.

## Round 9: Scope boundaries

### Q25. Explicitly rejected features

- Status: `[OPEN]`
- Record features that should not be built, even if technically possible.
- Examples to decide rather than assume:
  - public registration;
  - social feed;
  - collaborative document editing;
  - arbitrary server shell;
  - broad file execution;
  - public anonymous upload;
  - permanent admin impersonation;
  - third-party tracking;
  - cryptocurrency/storage marketplace nonsense, because apparently every product is eventually threatened by this idea.

### Q26. Success criteria

- Status: `[OPEN]`
- Question: What observable state would make the product successful for its intended users?
- Define a small set of product outcomes, reliability targets, and safety guarantees.

## How answers become work

After a discovery answer:

1. create/update a decision record;
2. identify affected existing behavior;
3. identify migration/data consequences;
4. identify security/architecture work;
5. update only relevant plan-tree sections;
6. create scoped GitHub issues only after the decision checkpoint is published and separately authorized; Round 3 does not create implementation issues automatically;
7. keep implementation blocked until dependencies and acceptance criteria are explicit;
8. give Codex one coherent issue step, not the entire product brief.

## Round 1 checkpoint

Round 1 is complete. D-001, D-002, and D-003 are approved and recorded. Issue #4 remains open. Issue #10 remains open and must not be closed until its required relationship consequences are documented, merged, and reconciled.

## Round 2 checkpoint

Round 2 is complete at the policy-decision level. D-004, D-005, and D-006 are approved and prepared for publication. This checkpoint's unresolved architecture, protocol, retention, recovery, and client-behavior details are historical; the current Zero-Knowledge technical profile and its remaining owner gates are reconciled below and in `docs/architecture/zero-knowledge-migration-contract.md`. Issues #4 and #10 remain open.

## Round 3 checkpoint

Round 3 is complete at the policy-decision level. D-007, D-008, and D-009 are recorded. The backup-aware cryptographic-erasure rule is preserved, and Phases 3.3, 3.4, and 3.5 remain historical operational-validation phases; they are not reopened or reclassified. The Zero-Knowledge technical profile and architecture/threat-model baseline are now recorded and accepted for bounded Phase 9 foundation work. Implementation, interoperability, migration, runtime proof, and the remaining detailed operational workflows remain open. No implementation issues were created automatically. Issues #4 and #10 remain open.

## Current discovery queue

Round 3 questions are resolved locally in D-007 through D-009. The next discovery round is not started by this checkpoint:

1. `[DECIDED]` D-007: cryptographic architecture and recovery policy; the frozen technical profile is in `docs/architecture/zero-knowledge-migration-contract.md`, while vectors, interoperability, implementation, and owner-directed recovery/migration choices remain open.
2. `[DECIDED]` D-008: retention, audit, deletion, backup, and offline-copy limits; detailed mechanics remain `[OPEN]`.
3. `[DECIDED]` D-009: zero-knowledge compatibility for scanning, previews, search, sharing, WebDAV, synchronization, and restore; the architecture baseline is recorded, while runtime implementation and owner-directed sharing/migration/sync choices remain open.

Do not ask all remaining questions at once. Each round must preserve explicit decisions, inferred consequences, and unresolved details separately.
