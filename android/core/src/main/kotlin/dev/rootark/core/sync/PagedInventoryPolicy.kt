package dev.rootark.core.sync

/** Advisory, metadata-only page. No ciphertext, proof, key, or token fields. */
data class InventoryPage(val rows: List<ReadOnlyFileRow>, val nextCursor: String?)

/** Exact public limits of issue #66's authenticated metadata inventory. */
object PagedInventoryPolicy {
    const val MAX_RESPONSE_BYTES = 128 * 1024
    const val MAX_ENTRIES = 64
    const val MAX_CURSOR_CHARS = 1024

    fun checkCursor(value: String, previouslyUsed: Set<String>): Boolean {
        require(value.isNotEmpty() && value.length <= MAX_CURSOR_CHARS &&
            value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '_' || it == '-' } &&
            value !in previouslyUsed) { "Invalid or repeated inventory cursor" }
        return true
    }

    fun checkEnvelope(protocolVersion: Int, view: String, count: Int, nextCursor: String?, previouslyUsedCursors: Set<String> = emptySet()) {
        require(protocolVersion == SYNC_PROTOCOL_VERSION && view == "metadata") { "Invalid inventory view" }
        require(count in 0..MAX_ENTRIES) { "Oversized inventory page" }
        if (nextCursor != null) {
            checkCursor(nextCursor, previouslyUsedCursors)
            require(count > 0) { "Non-advancing inventory page" }
        }
    }
}
