package dev.rootark.android

/** Insets overlap at each edge; the larger obstruction determines padding. */
internal data class ScreenInsets(val left: Int, val top: Int, val right: Int, val bottom: Int) {
    fun union(other: ScreenInsets) = ScreenInsets(
        maxOf(left, other.left),
        maxOf(top, other.top),
        maxOf(right, other.right),
        maxOf(bottom, other.bottom),
    )
}
