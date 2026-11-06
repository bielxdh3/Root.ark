package dev.rootark.core.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PagedInventoryPolicyTest {
    @Test
    fun `a library larger than 128 entries can be browsed in bounded pages`() {
        val seen = mutableSetOf<String>()
        for (page in 0..2) {
            val count = if (page == 2) 7 else 64
            val cursor = if (page < 2) "page_${page + 1}" else null
            PagedInventoryPolicy.checkEnvelope(2, "metadata", count, cursor)
            repeat(count) { offset -> seen.add("object-${page * 64 + offset}") }
        }
        assertEquals(135, seen.size)
    }

    @Test
    fun `fail closed on invalid page view length or cursor including loops`() {
        PagedInventoryPolicy.checkEnvelope(2, "metadata", 64, "a_-Z09")
        assertThrows(IllegalArgumentException::class.java) { PagedInventoryPolicy.checkEnvelope(1, "metadata", 1, null) }
        assertThrows(IllegalArgumentException::class.java) { PagedInventoryPolicy.checkEnvelope(2, "full", 1, null) }
        assertThrows(IllegalArgumentException::class.java) { PagedInventoryPolicy.checkEnvelope(2, "metadata", 65, null) }
        assertThrows(IllegalArgumentException::class.java) { PagedInventoryPolicy.checkEnvelope(2, "metadata", 0, "next") }
        assertThrows(IllegalArgumentException::class.java) { PagedInventoryPolicy.checkEnvelope(2, "metadata", 1, "") }
        assertThrows(IllegalArgumentException::class.java) { PagedInventoryPolicy.checkEnvelope(2, "metadata", 1, "a&x=1") }
        assertThrows(IllegalArgumentException::class.java) { PagedInventoryPolicy.checkEnvelope(2, "metadata", 1, "c".repeat(1025)) }
        assertThrows(IllegalArgumentException::class.java) { PagedInventoryPolicy.checkCursor("cursor", setOf("cursor")) }
        assertTrue(PagedInventoryPolicy.checkCursor("fresh", setOf("old")))
    }
}
