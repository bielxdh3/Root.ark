package dev.rootark.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InventoryPagingTrackerTest {
    @Test
    fun previousPageNavigationRestoresHistoryAndAllowsForwardAgain() {
        val first = MainActivity.InventoryPagingTracker()
        assertTrue(first.isValid())
        assertNull(first.previous())

        val second = first.advance("cursor-one")
        val third = second.advance("cursor-two")
        assertTrue(second.isValid())
        assertTrue(third.isValid())

        assertEquals(second, third.previous())
        assertEquals(first, second.previous())

        val secondAgain = third.previous() ?: error("Page three must return to page two")
        val thirdAgain = secondAgain.advance("cursor-two")
        assertEquals(third, thirdAgain)
        assertTrue(thirdAgain.isValid())

        assertFalse("A repeated cursor must remain invalid", second.advance("cursor-one").isValid())
    }
}
