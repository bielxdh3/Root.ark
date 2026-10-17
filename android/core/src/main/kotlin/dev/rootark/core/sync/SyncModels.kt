package dev.rootark.core.sync

/**
 * Data shapes for the Root.ark sync wire protocol (`protocolVersion = 2`).
 *
 * Source of truth: `sync-client/rootark-sync-protocol.js` (operation fields,
 * metadata allow-list) and `src/routes/sync.js` (`publicRecord`, list/get
 * responses). Field names are the exact JSON names. Only ciphertext and the
 * allow-listed metadata travel to the server; keys and plaintext never do.
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

/** Lamport-style revision. Ordering is by [counter] then [deviceId], never wall-clock time. */
data class SyncRevision(
    val counter: Long,
    val deviceId: String,
)

/**
 * Deterministic metadata allow-list. Each operation type uses a subset of these
 * keys (see `METADATA_KEYS_BY_OPERATION` in the Node protocol). Unused keys are null.
 * `path` and `name` are routing metadata visible to the server; they must be
 * validated with `PortablePathValidator` before being sent.
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
 * Operation body sent to `POST /sync/v1/objects` (create), `PUT .../:objectId`
 * (update, move) and `DELETE .../:objectId` (delete, tombstone). Ciphertext
 * fields are base64url strings produced client-side.
 */
data class SyncOperationRequest(
    val protocolVersion: Int = SYNC_PROTOCOL_VERSION,
    val operationId: String,
    val objectId: String,
    val fileId: String,
    val versionId: String,
    val operation: SyncOperationType,
    val revision: SyncRevision,
    val baseRevision: SyncRevision? = null,
    val keyEpoch: String,
    val compartmentId: String,
    val deviceId: String,
    val metadata: SyncMetadata,
    val tombstone: Boolean = false,
    val ciphertext: String = "",
    val nonce: String = "",
    val tag: String = "",
    val aad: String = "",
    /** Raw JSON object of the device authorization proof, when the server requires one. */
    val authorizationJson: String? = null,
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
    val ciphertext: String?,
    val nonce: String?,
    val tag: String?,
    val aad: String?,
    val authorizationJson: String?,
)

/** Response of `GET /sync/v1/objects`. */
data class SyncListResponse(
    val protocolVersion: Int,
    val objects: List<SyncRecord>,
)
