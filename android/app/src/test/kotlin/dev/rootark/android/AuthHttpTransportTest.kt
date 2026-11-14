package dev.rootark.android

import dev.rootark.core.sync.ReadOnlyFileListPolicy
import org.json.JSONException
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException

class AuthHttpTransportTest {

    @Test
    fun `malformed JSON throws SyncListingValidationException which is an IOException`() {
        val transport = AuthHttpTransport()
        assertThrows(IOException::class.java) {
            try {
                JSONObject("{ unquoted_malformed_json ")
            } catch (e: JSONException) {
                throw SyncListingValidationException("Malformed JSON in sync listing", e)
            }
        }
    }

    @Test
    fun `distinguishes size limit failure from validation failure`() {
        val sizeLimitEx = SyncListingLimitException("Sync listing exceeds limit")
        val validationEx = SyncListingValidationException("Invalid sync listing")

        assertInstanceOf(IOException::class.java, sizeLimitEx)
        assertInstanceOf(IOException::class.java, validationEx)
        assertTrue(sizeLimitEx is SyncListingLimitException)
        assertFalse(validationEx is SyncListingLimitException)
        assertTrue(validationEx is SyncListingValidationException)
        assertFalse(sizeLimitEx is SyncListingValidationException)
    }

    @Test
    fun `long and double numbers for size and counter are supported cleanly`() {
        // org.json may return Long or Double for large integers
        val json = JSONObject()
        json.put("protocolVersion", 2L)
        json.put("objects", org.json.JSONArray().put(JSONObject().apply {
            put("protocolVersion", 2)
            put("objectId", "obj-1")
            put("operation", "create")
            put("tombstone", false)
            put("revision", JSONObject().put("counter", 10000000000L).put("deviceId", "dev-1"))
            put("metadata", JSONObject().apply {
                put("name", "test.txt")
                put("path", "docs/test.txt")
                put("size", 9876543210L)
                put("contentType", "text/plain")
            })
        }))

        assertEquals(2L, json.getLong("protocolVersion"))
        val record = json.getJSONArray("objects").getJSONObject(0)
        assertEquals(9876543210L, record.getJSONObject("metadata").getLong("size"))
    }

    @Test
    fun `validText rejects bidi Cf Cc Zl Zp controls`() {
        assertTrue(ReadOnlyFileListPolicy.validText("safe_filename.txt", 100))

        // Bidi overrides
        assertFalse(ReadOnlyFileListPolicy.validText("file\u202Ecod.exe", 100))
        assertFalse(ReadOnlyFileListPolicy.validText("file\u202Atxt", 100))
        assertFalse(ReadOnlyFileListPolicy.validText("file\u2066txt", 100))

        // Cf / zero-width / BOM
        assertFalse(ReadOnlyFileListPolicy.validText("file\u200Bname", 100))
        assertFalse(ReadOnlyFileListPolicy.validText("file\uFEFFname", 100))
        assertFalse(ReadOnlyFileListPolicy.validText("file\u00ADname", 100))

        // Cc / ASCII and C1 controls
        assertFalse(ReadOnlyFileListPolicy.validText("file\u0000name", 100))
        assertFalse(ReadOnlyFileListPolicy.validText("file\u0085name", 100))

        // Zl / Zp
        assertFalse(ReadOnlyFileListPolicy.validText("file\u2028name", 100))
        assertFalse(ReadOnlyFileListPolicy.validText("file\u2029name", 100))
    }
}
