package dev.rootark.android

import org.junit.Assert.*
import org.junit.Test

class SecurePreviewBufferTest {
    @Test fun retainedBackingArrayRemainsReadableUntilClear() {
        val buffer = SecurePreviewBuffer()
        val secret = "verified".toCharArray()
        var retained: CharArray? = null
        buffer.show(secret, { retained = it }, {
            assertTrue(secret.all { it == '\u0000' })
            retained = null
        })
        assertSame(secret, retained)
        assertArrayEquals("verified".toCharArray(), retained)
        buffer.clear()
        assertNull(retained)
        assertTrue(secret.all { it == '\u0000' })
        buffer.clear()
    }

    @Test fun replacementAndFailedDisplayWipeOwnedArrays() {
        val buffer = SecurePreviewBuffer()
        val first = "old".toCharArray()
        val second = "new".toCharArray()
        var cleared = 0
        buffer.show(first, {}, { cleared++ })
        try {
            buffer.show(second, {
                assertTrue(first.all { c -> c == '\u0000' })
                throw IllegalStateException("display failed")
            }, { cleared++ })
            fail("display exception must propagate")
        } catch (_: IllegalStateException) {
            assertTrue(second.all { it == '\u0000' })
            assertEquals(2, cleared)
        }
        buffer.clear()
        assertEquals(2, cleared)
    }
}
