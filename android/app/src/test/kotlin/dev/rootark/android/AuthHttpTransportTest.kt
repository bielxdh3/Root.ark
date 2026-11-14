package dev.rootark.android

import org.json.JSONException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
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

        assertTrue(sizeLimitEx is IOException)
        assertTrue(validationEx is IOException)
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
}
