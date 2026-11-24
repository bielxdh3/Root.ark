package dev.rootark.core.sync

/** Alias names are stored in AndroidKeyStore, outside app-file backup/rollback. */
object OwnerFloorRevisionIndex {
    const val PREFIX = "dev.rootark.android.owner-floor-v2."
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private val SUFFIX = Regex("([1-9][0-9]{0,18})\\.([0-9a-f]{64})\\.([1-9][0-9]{0,18})\\.([1-9][0-9]{0,18})")

    data class Entry(
        val alias: String,
        val revision: Long,
        val digest: String,
        val seenAtMillis: Long,
        val sequence: Long,
    )

    data class Selection(val latest: Entry?, val next: Entry)

    @JvmStatic
    fun entries(aliases: Collection<String>): List<Entry> = aliases.filter { it.startsWith(PREFIX) }.map { alias ->
        val match = SUFFIX.matchEntire(alias.removePrefix(PREFIX))
            ?: throw ProtectedSyncException()
        Entry(alias, match.groupValues[1].toLong(), match.groupValues[2],
            match.groupValues[3].toLong(), match.groupValues[4].toLong())
    }

    /**
     * Return the existing key for the requested head or null when a new
     * higher-revision hardware key must be created. A missing index is only
     * accepted for a first, independently pinned enrollment.
     */
    @JvmStatic
    fun select(aliases: Collection<String>, revision: Long, digest: String, nowMillis: Long,
               allowInitialProvisioning: Boolean): Selection {
        try {
            require(revision >= 1 && nowMillis > 0 && digest.matches(Regex("[0-9a-f]{64}")))
            val parsed = entries(aliases)
            if (parsed.isEmpty()) {
                check(allowInitialProvisioning)
                return Selection(null, entry(revision, digest, nowMillis, 1))
            }
            check(parsed.all { it.revision <= MAX_SAFE_INTEGER &&
                it.seenAtMillis <= MAX_SAFE_INTEGER && it.sequence <= MAX_SAFE_INTEGER })
            check(parsed.groupBy { it.revision }.values.all { sameRevision ->
                sameRevision.map { it.digest }.distinct().size == 1
            })
            var previousRevisionMaxSeenAt = 0L
            parsed.groupBy { it.revision }.toSortedMap().values.forEach { sameRevision ->
                check(sameRevision.minOf { it.seenAtMillis } >= previousRevisionMaxSeenAt)
                previousRevisionMaxSeenAt = sameRevision.maxOf { it.seenAtMillis }
            }
            // A higher owner revision must not mask a wall-clock rollback
            // already recorded by an older hardware alias (including a
            // partially completed rotation that left both aliases present).
            check(nowMillis >= parsed.maxOf { it.seenAtMillis })
            val latestRevision = parsed.maxOf { it.revision }
            val latest = parsed.filter { it.revision == latestRevision }
                .maxWith(compareBy<Entry> { it.seenAtMillis }.thenBy { it.sequence })
            check(revision >= latestRevision)
            if (revision == latestRevision) check(digest == latest.digest)
            val sequence = if (revision == latestRevision && nowMillis == latest.seenAtMillis) {
                latest.sequence + 1
            } else 1
            return Selection(latest, entry(revision, digest, nowMillis, sequence))
        } catch (error: ProtectedSyncException) {
            throw error
        } catch (_: Exception) {
            throw ProtectedSyncException()
        }
    }

    @JvmStatic
    fun aliasFor(revision: Long, digest: String, seenAtMillis: Long, sequence: Long): String =
        entry(revision, digest, seenAtMillis, sequence).alias

    private fun entry(revision: Long, digest: String, seenAtMillis: Long, sequence: Long): Entry {
        require(revision in 1..MAX_SAFE_INTEGER && seenAtMillis in 1..MAX_SAFE_INTEGER &&
            sequence in 1..MAX_SAFE_INTEGER && digest.matches(Regex("[0-9a-f]{64}")))
        val alias = PREFIX + revision + "." + digest + "." + seenAtMillis + "." + sequence
        return Entry(alias, revision, digest, seenAtMillis, sequence)
    }
}
