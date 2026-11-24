package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.ProtectedSyncException
import dev.rootark.core.sync.RootArkApiException
import dev.rootark.core.sync.OfflineSession
import dev.rootark.core.sync.SessionOfflineInventory
import dev.rootark.core.sync.PagedInventoryPolicy
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.net.URL
import java.security.Principal
import java.security.cert.Certificate
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/**
 * Exact metadata HTTP pages captured from pinned PR #255, whose backing
 * disposable 130 Sync v2 objects were signed with test-only Ed25519 keys.
 * This verifies the combined #273 paging adapter + #275 protected selection.
 */
class PagedProtectedInventoryTest {
    private val origin = ServerOrigin.parse("https://files.example.org:9443")
    private val fixture by lazy {
        val loader = requireNotNull(javaClass.classLoader) { "Missing test fixture classloader" }
        val bytes = loader.getResourceAsStream("paged-server255-http.json")
            ?: throw IOException("Missing captured #255 HTTP response fixture")
        JSONObject(bytes.bufferedReader(Charsets.UTF_8).use { it.readText() })
    }

    private class SecureResponse(
        url: URL,
        private val status: Int = 200,
        private val payload: ByteArray = ByteArray(0),
        private val mime: String? = "application/json; charset=utf-8",
        private val encoding: String? = null,
        private val declaredSize: Long = -1L,
        private val stream: InputStream? = null,
        private val source: InputStream? = null,
    ) : HttpsURLConnection(url) {
        var disconnected = false
        override fun getResponseCode() = status
        override fun getInputStream() = source ?: stream ?: ByteArrayInputStream(payload)
        override fun getContentType(): String? = mime
        override fun getContentEncoding(): String? = encoding
        override fun getContentLengthLong() = declaredSize
        override fun disconnect() { disconnected = true }
        override fun usingProxy() = false
        override fun connect() = Unit
        override fun getCipherSuite() = "TLS_AES_128_GCM_SHA256"
        override fun getLocalCertificates(): Array<Certificate>? = null
        override fun getServerCertificates(): Array<Certificate> = emptyArray()
        override fun getPeerPrincipal(): Principal = Principal { "CN=fixture" }
        override fun getLocalPrincipal(): Principal? = null
    }

    @Test fun signedInPagedInventoryRejectsSlowDripBeforeCompleteBody() {
        val body = """{"protocolVersion":2,"view":"metadata","objects":[],"nextCursor":null}"""
            .toByteArray(Charsets.UTF_8)
        val ordinary = AuthHttpTransport {
            SecureResponse(origin.syncInventoryUrl(), payload = body)
        }.listInventoryPage(origin, "test-token")
        assertTrue("The complete body must be a valid empty metadata page", ordinary.rows.isEmpty())

        val elapsed = AtomicLong(0L)
        val reads = AtomicInteger(0)
        var offset = 0
        var closed = false
        // Each read returns one byte in 4s, below the per-read 10s timeout.
        // The full, valid JSON takes far more than a cumulative 10s budget.
        val drip = object : InputStream() {
            override fun read(): Int {
                if (offset == body.size) return -1
                reads.incrementAndGet()
                elapsed.addAndGet(4_000_000_000L)
                return body[offset++].toInt() and 0xff
            }
            override fun read(buffer: ByteArray, start: Int, length: Int): Int {
                if (length == 0) return 0
                val next = read()
                if (next < 0) return -1
                buffer[start] = next.toByte()
                return 1
            }
            override fun close() { closed = true }
        }
        val response = SecureResponse(origin.syncInventoryUrl(), source = drip)
        val transport = AuthHttpTransport(
            openInventoryConnection = { requested ->
                assertEquals(origin.syncInventoryUrl().toString(), requested.toString())
                response
            },
            monotonicNanos = elapsed::get,
        )
        val denied = assertThrows(SyncListingLimitException::class.java) {
            transport.listInventoryPage(origin, "test-token")
        }
        assertTrue(denied.message?.contains("deadline") == true)
        assertEquals("Third short body read exhausts the cumulative 10s limit", 3, reads.get())
        assertTrue("The valid metadata page remains incomplete at rejection", offset < body.size)
        assertEquals("Bearer test-token", response.getRequestProperty("Authorization"))
        assertTrue("The response stream is closed after denial", closed)
        assertTrue("The HTTPS connection is disconnected after denial", response.disconnected)
    }

    @Test fun realSignedStorePagesKeep130DistinctOpaqueIdsAndLockedViewer() {
        val pages = fixture.getJSONArray("pages")
        assertEquals(3, pages.length())
        val requested = mutableListOf<URL>()
        val responses = mutableListOf<SecureResponse>()
        val adapter = AuthHttpTransport { url ->
            val page = pages.getJSONObject(requested.size)
            val body = page.getJSONObject("body").toString().toByteArray(Charsets.UTF_8)
            SecureResponse(url, page.getInt("status"), body).also {
                requested.add(url)
                responses.add(it)
            }
        }
        var cursor: String? = null
        val ids = mutableSetOf<String>()
        val lengths = mutableListOf<Int>()
        for (pageIndex in 1..3) {
            val page = adapter.listInventoryPage(origin, "fixture-token", cursor)
            lengths.add(page.rows.size)
            assertTrue(page.rows.all { !it.deleted && it.objectId.startsWith("alice-file-") })
            for (row in page.rows) assertTrue(ids.add(row.objectId))
            val picked = page.rows.last().objectId
            assertEquals(
                "https://files.example.org:9443/sync/v1/objects/$picked",
                origin.syncObjectUrl(picked).toString(),
            )
            val viewer = VerifiedTextPreview(null, ProtectedSyncFetch {
                throw AssertionError("Never fetch ciphertext without an independent grant")
            })
            assertFalse(viewer.available)
            assertThrows(ProtectedSyncException::class.java) {
                viewer.open(
                    origin,
                    LoginOutcome.Authenticated("fixture-token", "alice", "user", mapOf("listFiles" to true)),
                    picked,
                )
            }
            cursor = page.nextCursor
            assertEquals(pageIndex < 3, cursor != null)
        }
        assertEquals(listOf(64, 64, 2), lengths)
        assertEquals(130, ids.size)
        assertEquals(
            "https://files.example.org:9443/sync/v1/objects?view=metadata&limit=64",
            requested.first().toString(),
        )
        for (index in 1..2) {
            assertEquals(
                "https://files.example.org:9443/sync/v1/objects?view=metadata&limit=64&cursor=" +
                    pages.getJSONObject(index - 1).getJSONObject("body").getString("nextCursor"),
                requested[index].toString(),
            )
        }
        for (connection in responses) {
            assertEquals("GET", connection.requestMethod)
            assertEquals("Bearer fixture-token", connection.getRequestProperty("Authorization"))
            assertEquals("identity", connection.getRequestProperty("Accept-Encoding"))
            assertEquals("no-store", connection.getRequestProperty("Cache-Control"))
            assertFalse(connection.instanceFollowRedirects)
            assertFalse(connection.useCaches)
            assertTrue(connection.disconnected)
        }
    }

    @Test fun capturedHttp401403409RemainFailuresAndDisconnect() {
        for (status in listOf(401, 403, 409)) {
            val response = SecureResponse(origin.syncInventoryUrl(), status)
            val adapter = AuthHttpTransport { response }
            val failure = assertThrows(RootArkApiException::class.java) {
                adapter.listInventoryPage(origin, "fixture-token")
            }
            assertEquals(status, failure.statusCode)
            assertTrue(response.disconnected)
        }
    }

    @Test fun tricklingInventoryResponseStopsAtTotalDeadlineEvenWithinEachSocketReadTimeout() {
        var nowNanos = 0L
        var reads = 0
        val trickle = object : InputStream() {
            override fun read(): Int = throw AssertionError("Expected bulk reads")
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                reads++
                // Nine seconds per byte: always below the 10-second socket idle timeout.
                nowNanos += 9_000_000_000L
                buffer[offset] = '{'.code.toByte()
                return 1
            }
        }
        val response = SecureResponse(origin.syncInventoryUrl(), stream = trickle)
        val adapter = AuthHttpTransport(clockNanos = { nowNanos }) { response }

        val failure = assertThrows(SyncListingException::class.java) {
            adapter.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(failure.message.orEmpty().contains("deadline"))
        assertEquals(4, reads)
        assertTrue(response.disconnected)
    }

    @Test fun realHttpCaptureCanBeReadOfflineOnlyByOriginalLogin() {
        val pages = fixture.getJSONArray("pages")
        val binding = OfflineSession("https://files.example.org:9443", "alice", "ephemeral-login-A")
        val cache = SessionOfflineInventory(binding)
        var requests = 0
        val adapter = AuthHttpTransport { url ->
            val body = pages.getJSONObject(requests++).getJSONObject("body").toString().toByteArray(Charsets.UTF_8)
            SecureResponse(url, payload = body)
        }
        var cursor: String? = null
        for (number in 1..3) {
            val page = adapter.listInventoryPage(origin, "one-session-token", cursor)
            assertTrue(cache.capture(binding, number, page))
            cursor = page.nextCursor
        }
        assertEquals(130, cache.pages(binding).flatMap { it.rows }.size)
        assertEquals(130, cache.pages(binding).flatMap { it.rows }.map { it.objectId }.distinct().size)
        assertThrows(IllegalArgumentException::class.java) { cache.pages(binding.copy(sessionNonce = "relogin")) }
        assertThrows(IllegalArgumentException::class.java) { cache.pages(binding.copy(account = "bob")) }
        val display = cache.pages(binding).flatMap { it.rows }.joinToString { it.name }
        assertFalse(display.contains("one-session-token"))
        cache.clear()
        assertTrue(cache.pages(binding).isEmpty())
    }

    @Test fun rejectUntrustedMetadataAndRfc8259AmbiguitiesBeforeProjection() {
        val first = fixture.getJSONArray("pages").getJSONObject(0).getJSONObject("body")
        val raw = first.toString()
        val malformed = listOf(
            "{}",
            raw.replaceFirst("\"view\":\"metadata\"", "\"view\":\"metadata\",\"view\":\"full\""),
            JSONObject(raw).put("view", "full").toString(),
            JSONObject(raw).put("nextCursor", "bad&other=1").toString(),
            JSONObject(raw).apply { getJSONArray("objects").put(getJSONArray("objects").getJSONObject(0)) }.toString(),
        )
        assertNotEquals(raw, malformed[1])
        for (text in malformed) {
            val adapter = AuthHttpTransport { url -> SecureResponse(url, payload = text.toByteArray(Charsets.UTF_8)) }
            assertThrows(Exception::class.java) { adapter.listInventoryPage(origin, "fixture-token") }
        }
        val rejectedBodies = listOf(
            SecureResponse(origin.syncInventoryUrl(), payload = raw.toByteArray(), mime = "text/html"),
            SecureResponse(origin.syncInventoryUrl(), payload = raw.toByteArray(), encoding = "gzip"),
            SecureResponse(origin.syncInventoryUrl(), payload = raw.toByteArray(), declaredSize = 128 * 1024L + 1L),
        )
        for (response in rejectedBodies) {
            assertThrows(IOException::class.java) {
                AuthHttpTransport { response }.listInventoryPage(origin, "fixture-token")
            }
            assertTrue(response.disconnected)
        }

        // Repeated cursor must be rejected by AuthHttpTransport
        val adapter = AuthHttpTransport { url -> SecureResponse(url, payload = raw.toByteArray()) }
        assertThrows(IllegalArgumentException::class.java) {
            adapter.listInventoryPage(origin, "fixture-token", cursor = "already_used", usedCursors = setOf("already_used"))
        }
    }

    @Test fun listingByteAndEntryBudgetsUseTheSpecificLimitException() {
        val baseBody = fixture.getJSONArray("pages").getJSONObject(0).getJSONObject("body")
            .toString().toByteArray(Charsets.UTF_8)
        val exactBoundaryPayload = baseBody + ByteArray(PagedInventoryPolicy.MAX_RESPONSE_BYTES - baseBody.size) {
            ' '.code.toByte()
        }
        val exactBoundary = SecureResponse(
            origin.syncInventoryUrl(), payload = exactBoundaryPayload,
            declaredSize = PagedInventoryPolicy.MAX_RESPONSE_BYTES.toLong(),
        )
        assertEquals(64, AuthHttpTransport { exactBoundary }.listInventoryPage(origin, "fixture-token").rows.size)
        assertTrue(exactBoundary.disconnected)

        val declaredTooLarge = SecureResponse(
            origin.syncInventoryUrl(), declaredSize = PagedInventoryPolicy.MAX_RESPONSE_BYTES.toLong() + 1L,
        )
        assertThrows(SyncListingLimitException::class.java) {
            AuthHttpTransport { declaredTooLarge }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(declaredTooLarge.disconnected)

        val streamedTooLarge = SecureResponse(
            origin.syncInventoryUrl(), payload = ByteArray(PagedInventoryPolicy.MAX_RESPONSE_BYTES + 1),
        )
        assertThrows(SyncListingLimitException::class.java) {
            AuthHttpTransport { streamedTooLarge }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(streamedTooLarge.disconnected)

        val oversizedPage = JSONObject(
            fixture.getJSONArray("pages").getJSONObject(0).getJSONObject("body").toString()
        ).apply {
            val objects = getJSONArray("objects")
            objects.put(objects.getJSONObject(0))
        }
        val tooManyEntries = SecureResponse(
            origin.syncInventoryUrl(), payload = oversizedPage.toString().toByteArray(Charsets.UTF_8),
        )
        assertThrows(SyncListingLimitException::class.java) {
            AuthHttpTransport { tooManyEntries }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(tooManyEntries.disconnected)

        val structurallyTooLarge = SecureResponse(
            origin.syncInventoryUrl(),
            payload = ("{\"protocolVersion\":2,\"view\":\"metadata\",\"objects\":[" +
                List(257) { "null" }.joinToString(",") + "],\"nextCursor\":null}")
                .toByteArray(Charsets.UTF_8),
        )
        assertThrows(SyncListingLimitException::class.java) {
            AuthHttpTransport { structurallyTooLarge }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(structurallyTooLarge.disconnected)
    }

    @Test fun malformedUtf8JsonAndInventoryEnvelopeUseTheSpecificValidationException() {
        val malformedUtf8 = SecureResponse(
            origin.syncInventoryUrl(), payload = byteArrayOf(0xC3.toByte(), 0x28),
        )
        assertThrows(SyncListingValidationException::class.java) {
            AuthHttpTransport { malformedUtf8 }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(malformedUtf8.disconnected)

        val malformedJson = SecureResponse(
            origin.syncInventoryUrl(), payload = "not-json".toByteArray(Charsets.UTF_8),
        )
        assertThrows(SyncListingValidationException::class.java) {
            AuthHttpTransport { malformedJson }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(malformedJson.disconnected)

        val invalidEnvelope = JSONObject(
            fixture.getJSONArray("pages").getJSONObject(0).getJSONObject("body").toString()
        ).put("view", "full")
        val invalidView = SecureResponse(
            origin.syncInventoryUrl(), payload = invalidEnvelope.toString().toByteArray(Charsets.UTF_8),
        )
        assertThrows(SyncListingValidationException::class.java) {
            AuthHttpTransport { invalidView }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(invalidView.disconnected)

        val invalidRecord = JSONObject(
            fixture.getJSONArray("pages").getJSONObject(0).getJSONObject("body").toString()
        ).apply {
            getJSONArray("objects").getJSONObject(0).put("objectId", "")
        }
        val invalidObjectId = SecureResponse(
            origin.syncInventoryUrl(), payload = invalidRecord.toString().toByteArray(Charsets.UTF_8),
        )
        assertThrows(SyncListingValidationException::class.java) {
            AuthHttpTransport { invalidObjectId }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(invalidObjectId.disconnected)

        val invalidOperation = JSONObject(
            fixture.getJSONArray("pages").getJSONObject(0).getJSONObject("body").toString()
        ).apply {
            getJSONArray("objects").getJSONObject(0).put("operation", "")
        }
        val invalidOperationResponse = SecureResponse(
            origin.syncInventoryUrl(), payload = invalidOperation.toString().toByteArray(Charsets.UTF_8),
        )
        assertThrows(SyncListingValidationException::class.java) {
            AuthHttpTransport { invalidOperationResponse }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(invalidOperationResponse.disconnected)

        val invalidMime = SecureResponse(
            origin.syncInventoryUrl(),
            payload = fixture.getJSONArray("pages").getJSONObject(0).getJSONObject("body")
                .toString().toByteArray(Charsets.UTF_8),
            mime = "text/html",
        )
        assertThrows(SyncListingValidationException::class.java) {
            AuthHttpTransport { invalidMime }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(invalidMime.disconnected)

        val invalidEncoding = SecureResponse(
            origin.syncInventoryUrl(),
            payload = fixture.getJSONArray("pages").getJSONObject(0).getJSONObject("body")
                .toString().toByteArray(Charsets.UTF_8),
            encoding = "gzip",
        )
        assertThrows(SyncListingValidationException::class.java) {
            AuthHttpTransport { invalidEncoding }.listInventoryPage(origin, "fixture-token")
        }
        assertTrue(invalidEncoding.disconnected)
    }
}
