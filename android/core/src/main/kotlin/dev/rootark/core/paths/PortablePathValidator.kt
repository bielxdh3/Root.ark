package dev.rootark.core.paths

import java.util.Locale

/**
 * Thrown when a relative path is not portable. The message never contains the
 * rejected value, so it is safe to log.
 */
class UnsafePathException(message: String) : IllegalArgumentException(message)

/**
 * Portable relative-path validator. Mirrors `validatePortableRelativePath` in
 * `sync-client/rootark-sync-paths.js` rule for rule; the shared fixture
 * `android/core/src/test/resources/portable-paths.json` keeps both in sync.
 */
object PortablePathValidator {
    private const val MAX_LENGTH = 512

    private val DOS_RESERVED = Regex("""^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$""", RegexOption.IGNORE_CASE)
    private val CONTROL_CHARS = Regex("""[\u0000-\u001f\u007f]""")
    private val WINDOWS_DRIVE = Regex("""^[A-Za-z]:""")

    private val INTERNAL_NAMES = setOf(
        ".rootark-trash", ".rootark-sync", ".rootark-sync-state.json",
        ".rootark-sync.json", ".rootark-sync-journal.json", ".rootark-sync-index.json",
        ".rootark-sync.lock",
    )
    private val INTERNAL_PREFIXES = listOf(".rootark-sync-lock-init-")

    /**
     * Returns [value] unchanged when it is a safe portable relative path, otherwise
     * throws [UnsafePathException].
     */
    @Throws(UnsafePathException::class)
    fun validate(value: String?, name: String = "path"): String {
        val text = value ?: ""
        if (text.isEmpty() || text.length > MAX_LENGTH || text.contains('%') || text.contains('\\') ||
            text.contains(':') || text.startsWith('/') || WINDOWS_DRIVE.containsMatchIn(text)
        ) fail(name)
        if (CONTROL_CHARS.containsMatchIn(text)) fail(name)
        val unsafe = text.split("/").any { segment ->
            segment.isEmpty() || segment == "." || segment == ".." || isInternalSegment(segment) ||
                DOS_RESERVED.containsMatchIn(segment) || segment.endsWith('.') || segment.endsWith(' ')
        }
        if (unsafe) fail(name)
        return text
    }

    /** True when any segment of [value] is a Root.ark-internal name. */
    fun isInternalRelativePath(value: String?): Boolean =
        (value ?: "").split("/").any { isInternalSegment(it) }

    private fun isInternalSegment(segment: String): Boolean {
        val normalized = segment.lowercase(Locale.ROOT)
        return normalized in INTERNAL_NAMES || INTERNAL_PREFIXES.any { normalized.startsWith(it) }
    }

    private fun fail(name: String): Nothing = throw UnsafePathException("Invalid $name")
}
