package dev.rootark.android

import org.junit.Assert.*
import org.junit.Test

class SecurePreviewBufferLifecycleTest {
    @Test fun successfulReplacementKeepsNewTextUntilClose() {
        val buffer = SecurePreviewBuffer()
        val first = "first".toCharArray()
        val second = "second".toCharArray()
        var displayed: CharArray? = null
        var firstClears = 0
        var secondClears = 0

        buffer.show(first, { displayed = it }, {
            firstClears++
            displayed = null
        })
        assertSame(first, displayed)
        buffer.show(second, { displayed = it }, {
            secondClears++
            displayed = null
        })
        assertEquals(1, firstClears)
        assertTrue(first.all { it == '\u0000' })
        assertSame(second, displayed)
        assertArrayEquals("second".toCharArray(), displayed)
        assertEquals(0, secondClears)

        buffer.clear()
        assertNull(displayed)
        assertTrue(second.all { it == '\u0000' })
        buffer.clear()
        assertEquals(1, firstClears)
        assertEquals(1, secondClears)
    }
}
