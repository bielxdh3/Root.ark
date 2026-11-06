package dev.rootark.core.sync

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SessionOfflineInventoryTest {
    private val alice = OfflineSession("https://files.example.org:9443", "alice", "login-A")
    private val otherAccount = alice.copy(account = "bob")
    private val otherSession = alice.copy(sessionNonce = "login-B")
    private val otherServer = alice.copy(origin = "https://evil.example.org")

    private fun row(index: Int): ReadOnlyFileRow = ReadOnlyFileListPolicy.project(
        protocolVersion = 2,
        objectId = "opaque-$index",
        operation = "create",
        tombstone = false,
        name = "file-$index.txt",
        path = "docs/file-$index.txt",
        size = index.toLong(),
        contentType = "text/plain",
    )

    @Test fun `captured pages are session bound and never include a continuation cursor`() {
        val store = SessionOfflineInventory(alice)
        store.capture(alice, 1, InventoryPage(listOf(row(1), row(2)), "secret_cursor"))
        store.capture(alice, 2, InventoryPage(listOf(row(3)), null))
        val pages = store.pages(alice)
        assertEquals(listOf(1, 2), pages.map { it.number })
        assertEquals(listOf("opaque-1", "opaque-2", "opaque-3"), pages.flatMap { it.rows }.map { it.objectId })
        assertFalse(pages.toString().contains("secret_cursor"))
        assertThrows(IllegalArgumentException::class.java) { store.pages(otherAccount) }
        assertThrows(IllegalArgumentException::class.java) { store.pages(otherSession) }
        assertThrows(IllegalArgumentException::class.java) { store.capture(otherServer, 1, InventoryPage(listOf(row(99)), null)) }
        assertEquals(3, store.pages(alice).sumOf { it.rows.size })
    }

    @Test fun `refresh replaces old pages and logout erases the inventory`() {
        val store = SessionOfflineInventory(alice)
        store.capture(alice, 1, InventoryPage(listOf(row(1)), "page2"))
        store.capture(alice, 2, InventoryPage(listOf(row(2)), null))
        store.capture(alice, 1, InventoryPage(listOf(row(3)), null))
        assertEquals(listOf("opaque-3"), store.pages(alice).flatMap { it.rows }.map { it.objectId })
        store.clear()
        assertTrue(store.pages(alice).isEmpty())
    }

    @Test fun `only eight bounded contiguous pages are retained`() {
        val store = SessionOfflineInventory(alice)
        assertThrows(IllegalArgumentException::class.java) {
            store.capture(alice, 2, InventoryPage(listOf(row(1)), null))
        }
        assertThrows(IllegalArgumentException::class.java) {
            store.capture(alice, 1, InventoryPage(List(65) { row(it) }, null))
        }
        for (page in 1..8) {
            store.capture(alice, page, InventoryPage(listOf(row(page)), if (page == 8) null else "p$page"))
        }
        assertFalse(store.capture(alice, 9, InventoryPage(listOf(row(9)), null)))
        assertEquals(8, store.pages(alice).size)
        assertThrows(IllegalArgumentException::class.java) {
            store.capture(alice, 8, InventoryPage(listOf(row(7)), null))
        }
        assertEquals(8, store.pages(alice).size)
    }

    @Test fun `malformed unprojected metadata is rejected without corrupting snapshot`() {
        val store = SessionOfflineInventory(alice)
        store.capture(alice, 1, InventoryPage(listOf(row(1)), "p1"))
        assertThrows(IllegalArgumentException::class.java) {
            store.capture(alice, 2, InventoryPage(listOf(ReadOnlyFileRow("opaque-2", "bad\u0000name", null, 1, null, false)), null))
        }
        assertEquals(listOf("opaque-1"), store.pages(alice).flatMap { it.rows }.map { it.objectId })
    }
}
