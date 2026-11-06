package dev.rootark.core.sync

/** Small in-memory display-only projection; ciphertext is never part of this object. */
class ReadOnlyFileRow(
    val name: String,
    val path: String?,
    val size: Long?,
    val contentType: String?,
    val deleted: Boolean,
)

/** Limits the unpaginated protocol-v2 listing before it may reach native UI. */
object ReadOnlyFileListPolicy {
    const val MAX_RESPONSE_BYTES = 1024 * 1024
    const val MAX_ENTRIES = 128

    fun canList(permissions: Map<String, Boolean>): Boolean = permissions["listFiles"] == true

    fun checkEnvelope(protocolVersion: Int, count: Int) {
        require(protocolVersion == SYNC_PROTOCOL_VERSION && count in 0..MAX_ENTRIES) {
            "Unsupported or oversized sync listing"
        }
    }

    fun project(
        protocolVersion: Int,
        objectId: String,
        operation: String,
        tombstone: Boolean,
        name: String?,
        path: String?,
        size: Long?,
        contentType: String?,
    ): ReadOnlyFileRow {
        require(protocolVersion == SYNC_PROTOCOL_VERSION)
        require(operation in setOf("create", "update", "move", "delete"))
        require(tombstone == (operation == "delete"))
        require(validText(objectId, 256) && objectId.isNotBlank())
        require(name == null || validText(name, 512))
        require(path == null || validText(path, 512))
        require(contentType == null || validText(contentType, 512))
        require(size == null || size >= 0L)

        return ReadOnlyFileRow(
            name = name?.takeIf { it.isNotBlank() } ?: path?.substringAfterLast('/')?.takeIf { it.isNotBlank() } ?: objectId,
            path = path,
            size = size,
            contentType = contentType,
            deleted = tombstone,
        )
    }

    private fun validText(value: String, maxLength: Int): Boolean =
        value.length <= maxLength && value.none { it.code < 32 || it.code == 127 }
}
