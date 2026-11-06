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
    fun `real signed HTTP listing with 300 character name and 512 character type remains visible`() {
        val stream = javaClass.classLoader.getResourceAsStream("server-responses.json")!!
        val response = JSONObject(stream.bufferedReader().use { it.readText() })
            .getJSONObject("responses").getJSONObject("sync.list.long-metadata.200")
        assertEquals(200, response.getInt("status"))
        val body = response.getJSONObject("body")
        val objects = body.getJSONArray("objects")
        ReadOnlyFileListPolicy.checkEnvelope(body.getInt("protocolVersion"), objects.length())
        assertEquals(2, objects.length())
        val rows = (0 until objects.length()).map { index ->
            val record = objects.getJSONObject(index)
            val metadata = record.getJSONObject("metadata")
            ReadOnlyFileListPolicy.project(
                record.getInt("protocolVersion"), record.getString("objectId"),
                record.getString("operation"), record.getBoolean("tombstone"),
                metadata.getString("name"), metadata.getString("path"),
                metadata.getLong("size"), metadata.getString("contentType"),
            )
        }
        assertTrue(rows.any { it.name == "readme.txt" })
        assertTrue(rows.any { it.name.length == 300 && it.contentType?.length == 512 })
    }

    @Test
    fun `protocol accepts display metadata through 512 characters but not 513`() {
        for (length in listOf(257, 300, 512)) {
            val name = "n".repeat(length)
            val type = "t".repeat(length)
            val result = ReadOnlyFileListPolicy.project(
                2, "file-1", "create", false, name, "docs/a.txt", 1L, type,
            )
            assertEquals(name, result.name)
            assertEquals(type, result.contentType)
        }
        assertThrows(IllegalArgumentException::class.java) { row(name = "n".repeat(513)) }
        assertThrows(IllegalArgumentException::class.java) {
            ReadOnlyFileListPolicy.project(2, "file-1", "create", false, "ok", "docs/a.txt", 1L, "t".repeat(513))
        }
    }

    @Test
    fun `rejects mismatched protocols, excess count, malformed metadata and delete mismatch`() {
        assertThrows(IllegalArgumentException::class.java) { ReadOnlyFileListPolicy.checkEnvelope(1, 1) }
        assertThrows(IllegalArgumentException::class.java) { ReadOnlyFileListPolicy.checkEnvelope(2, 129) }
        assertThrows(IllegalArgumentException::class.java) { ReadOnlyFileListPolicy.checkEnvelope(2, -1) }
        assertThrows(IllegalArgumentException::class.java) { row(protocol = 1) }
        assertThrows(IllegalArgumentException::class.java) { row(name = "bad\nname") }
        assertThrows(IllegalArgumentException::class.java) { row(name = "x".repeat(513)) }
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
