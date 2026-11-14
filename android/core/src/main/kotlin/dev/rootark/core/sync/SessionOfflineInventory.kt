package dev.rootark.core.sync

/** Random login nonce, canonical HTTPS origin and account; never a bearer token. */
data class OfflineSession(val origin: String, val account: String, val sessionNonce: String)

/** Historical, advisory metadata captured during this login. No signed authorization or content. */
data class OfflineInventoryPage(val number: Int, val rows: List<ReadOnlyFileRow>)

/** Volatile only: callers must clear it on logout, backgrounding and session rejection. */
class SessionOfflineInventory(private val session: OfflineSession) {
    private data class CapturedPage(val page: OfflineInventoryPage, val hasNext: Boolean)
    private val captured = linkedMapOf<Int, CapturedPage>()

    init {
        require(session.origin.startsWith("https://") && session.account.isNotBlank() &&
            session.sessionNonce.isNotBlank())
    }

    /** Returns false after the cache cap; online browsing is allowed to continue. */
    fun capture(requester: OfflineSession, pageNumber: Int, page: InventoryPage): Boolean {
        require(requester == session) { "Offline session mismatch" }
        require(pageNumber >= 1) { "Invalid offline page number" }
        if (pageNumber > MAX_PAGES) return false
        PagedInventoryPolicy.checkEnvelope(SYNC_PROTOCOL_VERSION, "metadata", page.rows.size, page.nextCursor)
        if (pageNumber > 1) require(captured[pageNumber - 1]?.hasNext == true) {
            "Offline pages must follow the captured cursor chain"
        }
        val safeRows = page.rows.map { row ->
            ReadOnlyFileListPolicy.project(
                SYNC_PROTOCOL_VERSION, row.objectId, if (row.deleted) "delete" else "update", row.deleted,
                row.name, row.path, row.size, row.contentType,
            )
        }
        val priorIds = if (pageNumber == 1) emptySet() else captured.values
            .filter { it.page.number < pageNumber }
            .flatMap { it.page.rows }
            .mapTo(mutableSetOf()) { it.objectId }
        require(safeRows.map { it.objectId }.distinct().size == safeRows.size &&
            safeRows.none { it.objectId in priorIds }) { "Duplicate object in offline snapshot" }

        if (pageNumber == 1) captured.clear()
        else captured.keys.removeAll { it >= pageNumber }
        captured[pageNumber] = CapturedPage(OfflineInventoryPage(pageNumber, safeRows), page.nextCursor != null)
        return true
    }

    fun pages(requester: OfflineSession): List<OfflineInventoryPage> {
        require(requester == session) { "Offline session mismatch" }
        return captured.values.map { it.page }
    }

    fun clear() = captured.clear()

    companion object { const val MAX_PAGES = 8 }
}
