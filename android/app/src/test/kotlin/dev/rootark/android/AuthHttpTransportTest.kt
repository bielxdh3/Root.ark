package dev.rootark.android

import org.json.JSONException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.io.InputStream
import java.math.BigDecimal
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import dev.rootark.core.auth.ServerOrigin

class AuthHttpTransportTest {

    @Test
    fun `adversarial slow-drip sync listing exhausts total response budget before EOF`() {
        val origin = ServerOrigin.parse("https://sync.example.test")
        val expected = """{"protocolVersion":2,"objects":[]}""".toByteArray(StandardCharsets.UTF_8)
        val elapsed = AtomicLong(0L)
        val reads = AtomicInteger(0)
        var offset = 0
        var disconnected = false
        // Each successful socket read supplies data in under its 10-second
        // per-read timeout. Without a cumulative BODY deadline this stream
        // can keep the authenticated listing worker alive indefinitely.
        val dripper = object : InputStream() {
            override fun read(): Int = if (offset < expected.size) {
                reads.incrementAndGet()
                elapsed.addAndGet(4_000_000_000L)
                expected[offset++].toInt() and 0xff
            } else -1

            override fun read(buffer: ByteArray, start: Int, length: Int): Int {
                if (length == 0) return 0
                val next = read()
                if (next < 0) return -1
                buffer[start] = next.toByte()
                return 1
            }
        }
        val connection = object : HttpURLConnection(URL("https://sync.example.test/sync/v1/objects")) {
            override fun connect() = Unit
            override fun disconnect() { disconnected = true }
            override fun usingProxy() = false
            override fun getResponseCode() = 200
            override fun getInputStream() = dripper
        }
        val transport = AuthHttpTransport(
            openSyncConnection = { requested ->
                assertEquals("https://sync.example.test/sync/v1/objects", requested.toString())
                connection
            },
            monotonicNanos = elapsed::get,
        )
        val failure = assertThrows(SyncListingLimitException::class.java) {
            transport.listSyncObjects(origin, "independent-bearer")
        }
        assertTrue(failure.message?.contains("deadline") == true)
        assertEquals("the third short read crosses the body budget", 3, reads.get())
        assertEquals("Bearer independent-bearer", connection.getRequestProperty("Authorization"))
        assertTrue("failed listing must release the authenticated connection", disconnected)
    }

    private fun createValidSyncListing(): JSONObject {
        val json = JSONObject()
        json.put("protocolVersion", 2)
        val objects = org.json.JSONArray()
        val record = JSONObject().apply {
            put("protocolVersion", 2)
            put("objectId", "obj-1")
            put("operation", "create")
            put("tombstone", false)
            put("revision", JSONObject().put("counter", 1L).put("deviceId", "dev-1"))
            put("metadata", JSONObject().apply {
                put("name", "test.txt")
                put("path", "docs/test.txt")
                put("size", 100L)
                put("contentType", "text/plain")
            })
        }
        objects.put(record)
        json.put("objects", objects)
        return json
    }

    @Test
    fun `malformed JSON throws SyncListingValidationException which is an IOException`() {
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
    fun `projectList rejects missing or non-string deviceId, objectId, and operation`() {
        val transport = AuthHttpTransport()

        // Missing deviceId
        val json1 = createValidSyncListing()
        json1.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").remove("deviceId")
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json1)
        }

        // Non-string deviceId
        val json2 = createValidSyncListing()
        json2.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").put("deviceId", 12345)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json2)
        }

        // Blank deviceId
        val json3 = createValidSyncListing()
        json3.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").put("deviceId", "   ")
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json3)
        }

        // Missing objectId
        val json4 = createValidSyncListing()
        json4.getJSONArray("objects").getJSONObject(0).remove("objectId")
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json4)
        }

        // Non-string objectId
        val json5 = createValidSyncListing()
        json5.getJSONArray("objects").getJSONObject(0).put("objectId", 999)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json5)
        }

        // Missing operation
        val json6 = createValidSyncListing()
        json6.getJSONArray("objects").getJSONObject(0).remove("operation")
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json6)
        }

        // Non-string operation
        val json7 = createValidSyncListing()
        json7.getJSONArray("objects").getJSONObject(0).put("operation", true)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json7)
        }
    }

    @Test
    fun `projectList rejects Double and Float in counter and size`() {
        val transport = AuthHttpTransport()

        // Double in counter
        val json1 = createValidSyncListing()
        json1.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").put("counter", 10.0)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json1)
        }

        // Overflowed Double in counter
        val json2 = createValidSyncListing()
        json2.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").put("counter", 1e308)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json2)
        }

        // Double in size
        val json3 = createValidSyncListing()
        json3.getJSONArray("objects").getJSONObject(0).getJSONObject("metadata").put("size", 100.0)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json3)
        }

        // Direct parser checks
        assertNull(transport.parseNonNegativeLong(10.0))
        assertNull(transport.parseNonNegativeLong(1e308))
        assertNull(transport.parseNonNegativeLong(10.0f))
        assertThrows(SyncListingValidationException::class.java) {
            transport.optionalLong(JSONObject().put("size", 10.0), "size")
        }
    }

    @Test
    fun `number parsing accepts BigInteger greater than 2^53 that fits in Long`() {
        val transport = AuthHttpTransport()
        val bigVal = BigInteger("9007199254740993") // 2^53 + 1

        val json = createValidSyncListing()
        json.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").put("counter", bigVal)
        json.getJSONArray("objects").getJSONObject(0).getJSONObject("metadata").put("size", bigVal)

        val rows = transport.projectList(json)
        assertEquals(1, rows.size)
        assertEquals(9007199254740993L, rows[0].size)
        assertEquals(9007199254740993L, transport.parseNonNegativeLong(bigVal))
    }

    @Test
    fun `number parsing rejects BigInteger overflowing Long`() {
        val transport = AuthHttpTransport()
        val overflowBi = BigInteger("9223372036854775808") // Long.MAX_VALUE + 1

        val json1 = createValidSyncListing()
        json1.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").put("counter", overflowBi)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json1)
        }

        val json2 = createValidSyncListing()
        json2.getJSONArray("objects").getJSONObject(0).getJSONObject("metadata").put("size", overflowBi)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json2)
        }

        assertNull(transport.parseNonNegativeLong(overflowBi))
        assertThrows(SyncListingValidationException::class.java) {
            transport.optionalLong(JSONObject().put("size", overflowBi), "size")
        }
    }

    @Test
    fun `number parsing rejects fractional BigDecimal and accepts integral BigDecimal`() {
        val transport = AuthHttpTransport()
        val frac = BigDecimal("100.5")

        val json1 = createValidSyncListing()
        json1.getJSONArray("objects").getJSONObject(0).getJSONObject("metadata").put("size", frac)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json1)
        }

        val json2 = createValidSyncListing()
        json2.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").put("counter", frac)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(json2)
        }

        assertNull(transport.parseNonNegativeLong(frac))
        assertThrows(SyncListingValidationException::class.java) {
            transport.optionalLong(JSONObject().put("size", frac), "size")
        }

        // Integral BigDecimal with trailing zeroes should be accepted
        val integral = BigDecimal("5000.00")
        val json3 = createValidSyncListing()
        json3.getJSONArray("objects").getJSONObject(0).getJSONObject("revision").put("counter", integral)
        json3.getJSONArray("objects").getJSONObject(0).getJSONObject("metadata").put("size", integral)

        val rows = transport.projectList(json3)
        assertEquals(1, rows.size)
        assertEquals(5000L, rows[0].size)
        assertEquals(5000L, transport.parseNonNegativeLong(integral))
    }

    @Test
    fun `parseProtocolVersion and parsePositiveInt respect exact contracts`() {
        val transport = AuthHttpTransport()

        // parseProtocolVersion
        assertEquals(2, transport.parseProtocolVersion(2))
        assertEquals(2, transport.parseProtocolVersion(2L))
        assertEquals(2, transport.parseProtocolVersion(BigInteger.valueOf(2)))
        assertEquals(2, transport.parseProtocolVersion(BigDecimal("2.0")))
        assertNull(transport.parseProtocolVersion(2.0))
        assertNull(transport.parseProtocolVersion(BigDecimal("2.5")))
        assertNull(transport.parseProtocolVersion(BigInteger("99999999999999999999")))
        assertNull(transport.parseProtocolVersion("2"))

        // parsePositiveInt
        assertEquals(1, transport.parsePositiveInt(1))
        assertEquals(1, transport.parsePositiveInt(1L))
        assertEquals(1, transport.parsePositiveInt(BigInteger.ONE))
        assertEquals(1, transport.parsePositiveInt(BigDecimal("1.0")))
        assertNull(transport.parsePositiveInt(0))
        assertNull(transport.parsePositiveInt(-1))
        assertNull(transport.parsePositiveInt(1.0))
        assertNull(transport.parsePositiveInt(BigDecimal("1.5")))
        assertNull(transport.parsePositiveInt(BigInteger("99999999999999999999")))
    }

    @Test
    fun `extreme-scale BigDecimal values reject cleanly without stripTrailingZeros DoS`() {
        val transport = AuthHttpTransport()
        val hugePositive = BigDecimal("1e100000000")
        val tinyNegativeScale = BigDecimal("1e-100000000")
        val zeroHugeScale = BigDecimal("0e-100000000")

        assertNull(transport.parseProtocolVersion(hugePositive))
        assertNull(transport.parseProtocolVersion(tinyNegativeScale))
        assertEquals(0, transport.parseProtocolVersion(zeroHugeScale))
        assertNull(transport.parseNonNegativeLong(hugePositive))
        assertNull(transport.parseNonNegativeLong(tinyNegativeScale))
        assertEquals(0L, transport.parseNonNegativeLong(zeroHugeScale))
        assertNull(transport.parsePositiveInt(hugePositive))
        assertNull(transport.parsePositiveInt(zeroHugeScale))

        val jsonHuge = createValidSyncListing()
        jsonHuge.getJSONArray("objects").getJSONObject(0).getJSONObject("metadata").put("size", hugePositive)
        assertThrows(SyncListingValidationException::class.java) {
            transport.projectList(jsonHuge)
        }
    }
}
