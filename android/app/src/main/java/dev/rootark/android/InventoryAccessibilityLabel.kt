package dev.rootark.android

import dev.rootark.core.sync.ReadOnlyFileRow

internal fun protectedContentAccessibilityLabel(row: ReadOnlyFileRow): String {
    val context = row.path?.takeIf(::isSafeAccessibilityContext)
        ?: row.name.takeIf(::isSafeAccessibilityContext)
        ?: "arquivo"
    return "Conteúdo protegido: $context"
}

private fun isSafeAccessibilityContext(value: String): Boolean {
    if (value.isBlank()) return false
    val iterator = value.codePoints().iterator()
    while (iterator.hasNext()) {
        val codePoint = iterator.nextInt()
        val joiner = codePoint == 0x200C || codePoint == 0x200D
        if (codePoint < 32 || codePoint in 0x7F..0x9F || codePoint == 0x034F ||
            codePoint in 0x202A..0x202E || codePoint in 0x2066..0x2069 ||
            codePoint == 0x200B || codePoint == 0x200E || codePoint == 0x200F || codePoint == 0xFEFF
        ) return false
        val type = Character.getType(codePoint).toByte()
        if ((type == Character.FORMAT && !joiner) || type == Character.CONTROL ||
            type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR
        ) return false
    }
    return true
}
