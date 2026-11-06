package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.ProtectedSyncException
import dev.rootark.core.sync.RootArkApiException
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.URL
import java.security.Principal
import java.security.cert.Certificate
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
        val bytes = javaClass.classLoader.getResourceAsStream("paged-server255-http.json")
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
    ) : HttpsURLConnection(url) {
        var disconnected = false
        override fun getResponseCode() = status
        override fun getInputStream() = ByteArrayInputStream(payload)
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
    }
}
