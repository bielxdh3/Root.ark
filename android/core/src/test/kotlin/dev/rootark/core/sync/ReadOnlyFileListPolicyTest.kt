package dev.rootark.core.sync

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReadOnlyFileListPolicyTest {
    @Test
    fun `only explicit listFiles permission enables the client listing`() {
        assertFalse(ReadOnlyFileListPolicy.canList(emptyMap()))
        assertFalse(ReadOnlyFileListPolicy.canList(mapOf("listFiles" to false, "upload" to true)))
        assertFalse(ReadOnlyFileListPolicy.canList(mapOf("manageUsers" to true)))
        assertTrue(ReadOnlyFileListPolicy.canList(mapOf("listFiles" to true)))
    }

    @Test
    fun `captured server record yields only display metadata and no protected bytes`() {
        val stream = javaClass.classLoader.getResourceAsStream("server-responses.json")!!
        val record = JSONObject(stream.bufferedReader().use { it.readText() })
            .getJSONObject("responses").getJSONObject("sync.list.200")
            .getJSONObject("body").getJSONArray("objects").getJSONObject(0)
        ReadOnlyFileListPolicy.checkEnvelope(2, 1)
        val metadata = record.getJSONObject("metadata")
        val row = ReadOnlyFileListPolicy.project(
            record.getInt("protocolVersion"), record.getString("objectId"), record.getString("operation"),
            record.getBoolean("tombstone"), metadata.getString("name"), metadata.getString("path"),
            metadata.getLong("size"), metadata.getString("contentType"),
        )
        assertEquals("readme.txt", row.name)
        assertEquals("docs/readme.txt", row.path)
        assertEquals(5L, row.size)
        assertEquals("text/plain", row.contentType)
        assertFalse(row.deleted)
        val rendered = listOf(row.name, row.path, row.contentType).joinToString(" ")
        assertFalse(rendered.contains(record.getString("ciphertext")))
        assertFalse(rendered.contains(record.getString("nonce")))
        assertFalse(rendered.contains(record.getString("tag")))
    }

    @Test
    fun `rejects mismatched protocols, excess count, malformed metadata and delete mismatch`() {
        assertThrows(IllegalArgumentException::class.java) { ReadOnlyFileListPolicy.checkEnvelope(1, 1) }
        assertThrows(IllegalArgumentException::class.java) { ReadOnlyFileListPolicy.checkEnvelope(2, 129) }
        assertThrows(IllegalArgumentException::class.java) { ReadOnlyFileListPolicy.checkEnvelope(2, -1) }
        assertThrows(IllegalArgumentException::class.java) { row(protocol = 1) }
        assertThrows(IllegalArgumentException::class.java) { row(name = "bad\nname") }
        assertThrows(IllegalArgumentException::class.java) { row(name = "x".repeat(257)) }
        assertThrows(IllegalArgumentException::class.java) { row(path = "p".repeat(513)) }
        assertThrows(IllegalArgumentException::class.java) { row(size = -1) }
        assertThrows(IllegalArgumentException::class.java) { row(operation = "unknown") }
        assertThrows(IllegalArgumentException::class.java) { row(operation = "delete", deleted = false) }
        assertThrows(IllegalArgumentException::class.java) { row(objectId = "") }
    }

    private fun row(
        protocol: Int = 2, objectId: String = "file-1", operation: String = "create",
        deleted: Boolean = false, name: String = "hello.txt", path: String = "docs/hello.txt", size: Long = 1,
    ) = ReadOnlyFileListPolicy.project(protocol, objectId, operation, deleted, name, path, size, "text/plain")
}
