package dev.rootark.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import dev.rootark.core.sync.PagedInventoryPolicy

class InventoryPagingTrackerTest {
    @Test
    fun previousPageNavigationRestoresHistoryAndAllowsForwardAgain() {
        val first = InventoryPagingTracker()
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

    @Test
    fun paginationHistoryHasABoundedPageCount() {
        val priorCursors = (1 until PagedInventoryPolicy.MAX_PAGES - 1)
            .map { "cursor-$it" }
        val atLimit = InventoryPagingTracker(
            cursor = "last-cursor",
            pageNumber = PagedInventoryPolicy.MAX_PAGES,
            usedCursors = priorCursors.toSet(),
            previousCursors = listOf(null) + priorCursors,
        )
        assertTrue(atLimit.isValid())
        assertFalse(atLimit.advance("one-too-many").isValid())

        val tooManyPriorCursors = (1 until PagedInventoryPolicy.MAX_PAGES)
            .map { "cursor-$it" }
        val overLimit = InventoryPagingTracker(
            cursor = "last-cursor",
            pageNumber = PagedInventoryPolicy.MAX_PAGES + 1,
            usedCursors = tooManyPriorCursors.toSet(),
            previousCursors = listOf(null) + tooManyPriorCursors,
        )
        assertFalse(overLimit.isValid())
        assertEquals(1_000, PagedInventoryPolicy.MAX_PAGES)
    }
}
