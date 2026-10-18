package dev.rootark.core.sync

/**
 * Wire shapes for the Root.ark sync protocol (`protocolVersion = 2`).
 *
 * Property names are the exact JSON names. Types follow the JSON values: integers are
 * JSON numbers (Long/Int), ids and encrypted fields are strings, and `null` is only
 * accepted where the property is nullable. The server sends no timestamps in these
 * objects. Source of truth: `src/routes/sync.js` (`publicRecord`, list/conflict bodies)
 * and `sync-client/rootark-sync-protocol.js` (operation fields, metadata allow-list).
 *
 * Checked by test/issue-64-android-contract.test.js against
 * android/core/src/test/resources/server-responses.json, which is captured from the
 * real handlers by scripts/issue-64-android-fixtures.js.
 */

/** Wire value of `protocolVersion` in every sync operation and list response. */
const val SYNC_PROTOCOL_VERSION: Int = 2

enum class SyncOperationType(val wire: String) {
    CREATE("create"),
    UPDATE("update"),
    MOVE("move"),
    DELETE("delete");

    companion object {
        fun fromWire(value: String): SyncOperationType =
            entries.firstOrNull { it.wire == value } ?: throw IllegalArgumentException("Unknown sync operation")
    }
}

/** Lamport-style revision. Ordering is by `counter`, then `deviceId`; never wall-clock time. */
data class SyncRevision(
    val counter: Long,
    val deviceId: String,
)

/**
 * Deterministic metadata allow-list. The server emits only the keys the operation
 * type allows, so absent keys are null here. `path` and `name` are server-visible
 * routing metadata and must pass `PortablePathValidator` before being sent.
 */
data class SyncMetadata(
    val fileId: String? = null,
    val versionId: String? = null,
    val path: String? = null,
    val parentId: String? = null,
    val name: String? = null,
    val contentType: String? = null,
    val size: Long? = null,
    val keyEpoch: String? = null,
    val compartmentId: String? = null,
    val deviceId: String? = null,
    val sourcePath: String? = null,
)

/**
 * Device authorization proof attached as `authorization` (schema from
 * `PROOF_FIELDS` in `sync-client/rootark-sync-authorization.js`). Digests, keys and
 * signatures are base64url strings. It carries no key material.
 */
data class SyncAuthorizationProof(
    val schemaVersion: Int,
    val type: String,
    val suite: String,
    val protocolVersion: Int,
    val username: String,
    val deviceId: String,
    val operationId: String,
    val objectId: String,
    val fileId: String,
    val versionId: String,
    val operation: String,
    val revision: SyncRevision,
    val baseRevision: SyncRevision?,
    val keyEpoch: String,
    val compartmentId: String,
    val metadata: SyncMetadata,
    val aadDigest: String,
    val ciphertextDigest: String,
    val nonceDigest: String,
    val tagDigest: String,
    val expiresAt: Long,
    val replayId: String,
    val idempotencyKey: String,
    val publicKey: String,
    val signature: String,
)

/**
 * Body of `POST /sync/v1/objects`, `PUT /sync/v1/objects/:objectId` and
 * `DELETE /sync/v1/objects/:objectId`. `authorization` is optional and only sent when
 * the server requires device authorization.
 */
data class SyncOperationRequest(
    val protocolVersion: Int,
    val operationId: String,
    val objectId: String,
    val fileId: String,
    val versionId: String,
    val operation: SyncOperationType,
    val revision: SyncRevision,
    val baseRevision: SyncRevision?,
    val keyEpoch: String,
    val compartmentId: String,
    val deviceId: String,
    val metadata: SyncMetadata,
    val tombstone: Boolean,
    val ciphertext: String,
    val nonce: String,
    val tag: String,
    val aad: String,
    val authorization: SyncAuthorizationProof? = null,
)

/** Stored record returned by the server (`publicRecord` in `src/routes/sync.js`). */
data class SyncRecord(
    val protocolVersion: Int,
    val operationId: String,
    val objectId: String,
    val fileId: String,
    val versionId: String,
    val operation: SyncOperationType,
    val revision: SyncRevision,
    val baseRevision: SyncRevision?,
    val keyEpoch: String,
    val compartmentId: String,
    val deviceId: String,
    val metadata: SyncMetadata,
    val tombstone: Boolean,
    /** Empty string for tombstones (delete operations), not null. */
    val ciphertext: String,
    val nonce: String,
    val tag: String,
    val aad: String,
    val authorization: SyncAuthorizationProof? = null,
)

/** Response of `GET /sync/v1/objects`. */
data class SyncListResponse(
    val protocolVersion: Int,
    val objects: List<SyncRecord>,
)

/**
 * Body of a 409 response from the write routes. `error` is the server's text. The
 * revision and record are present for stale and base-revision conflicts, and absent
 * for replay rejections.
 */
data class SyncConflict(
    val error: String,
    val currentRevision: SyncRevision? = null,
    val current: SyncRecord? = null,
)
