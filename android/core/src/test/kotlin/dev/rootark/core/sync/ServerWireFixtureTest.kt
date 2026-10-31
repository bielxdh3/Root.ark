package dev.rootark.core.sync

import org.json.JSONObject
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Deserializes the real server responses in server-responses.json (captured from the
 * Node route handlers by scripts/issue-64-android-fixtures.js) into the Kotlin wire models.
 */
class ServerWireFixtureTest {

    private val root: JSONObject by lazy {
        val stream = javaClass.classLoader.getResourceAsStream("server-responses.json")
            ?: error("server-responses.json missing from test resources")
        JSONObject(stream.bufferedReader(Charsets.UTF_8).use { it.readText() })
    }

    private fun response(name: String): JSONObject = root.getJSONObject("responses").getJSONObject(name)

    private fun body(name: String): JSONObject = response(name).getJSONObject("body")

    private fun status(name: String): Int = response(name).getInt("status")

    @Test
    fun createRecordMatchesStatusAndShape() {
        assertEquals(201, status("sync.post.201"))
        val record = body("sync.post.201").toRecord()
        assertEquals(SYNC_PROTOCOL_VERSION, record.protocolVersion)
        assertEquals(SyncOperationType.CREATE, record.operation)
        assertEquals(SyncRevision(1L, "fixture-device-a"), record.revision)
        assertNull(record.baseRevision)
        assertEquals(false, record.tombstone)
        assertEquals("text/plain", record.metadata.contentType)
        assertEquals(5L, record.metadata.size)
        val proof = assertNotNull(record.authorization, "create record must carry the authorization proof")
        assertEquals("rootark-sync-device-authorization-v1", proof.type)
        assertEquals(1, proof.schemaVersion)
    }

    @Test
    fun updateMoveAndDeleteStatusCodes() {
        assertEquals(200, status("sync.put.200.update"))
        assertEquals(200, status("sync.put.200.move"))
        assertEquals(200, status("sync.delete.200"))
        val move = body("sync.put.200.move").toRecord()
        assertEquals(SyncOperationType.MOVE, move.operation)
        assertEquals("docs/readme.txt", move.metadata.sourcePath)
    }

    @Test
    fun tombstoneHasEmptyCiphertextNotNull() {
        val delete = body("sync.delete.200").toRecord()
        assertEquals(SyncOperationType.DELETE, delete.operation)
        assertEquals(true, delete.tombstone)
        assertEquals("", delete.ciphertext)
        assertNull(delete.authorization)
    }

    @Test
    fun listResponseMapsToSyncListResponse() {
        val list = body("sync.list.200")
        val objects = list.getJSONArray("objects")
        val parsed = SyncListResponse(
            protocolVersion = list.getInt("protocolVersion"),
            objects = (0 until objects.length()).map { objects.getJSONObject(it).toRecord() },
        )
        assertEquals(SYNC_PROTOCOL_VERSION, parsed.protocolVersion)
        assertEquals(1, parsed.objects.size)
    }

    @Test
    fun conflictBodiesMapToSyncConflict() {
        assertEquals(409, status("sync.put.409.stale"))
        val stale = body("sync.put.409.stale").toConflict()
        assertEquals(SyncRevision(2L, "fixture-device-a"), stale.currentRevision)
        assertTrue(stale.current != null, "stale conflict carries the current record")

        val replay = body("sync.post.409.replay").toConflict()
        assertEquals("Replay rejected", replay.error)
        assertNull(replay.currentRevision)
        assertNull(replay.current)
    }

    @Test
    fun writeStatusesMapToWriteResults() {
        assertTrue(writeResult("sync.post.201") is SyncWriteResult.Accepted)
        assertTrue(writeResult("sync.put.200.update") is SyncWriteResult.Accepted)
        assertTrue(writeResult("sync.put.409.base") is SyncWriteResult.Rejected)
    }

    @Test
    fun errorBodiesCarryOnlyTheErrorText() {
        assertEquals(404, status("sync.get.404"))
        assertEquals("Sync object not found", body("sync.get.404").getString("error"))
        assertEquals(403, status("sync.post.403.invalid"))
    }

    @Test
    fun loginSuccessMapsPermissionsAsBooleanMap() {
        val login = body("login.200.authenticated")
        val permissions = login.getJSONObject("permissions")
        val parsed = LoginOutcome.Authenticated(
            token = login.getString("token"),
            username = login.getString("username"),
            role = login.getString("role"),
            permissions = permissions.keys().asSequence().associateWith { permissions.getBoolean(it) },
        )
        assertEquals("alice", parsed.username)
        assertEquals(true, parsed.permissions["listFiles"])
        assertEquals(200, status("login.200.authenticated"))
    }

    @Test
    fun challengeAndEnrollmentBodiesMapWithNumericExpiry() {
        val challenge = body("login.200.challenge")
        val parsed = LoginOutcome.ChallengeRequired(
            challengeRequired = challenge.getBoolean("challengeRequired"),
            challengeId = challenge.getString("challengeId"),
            expiresIn = challenge.getInt("expiresIn"),
        )
        assertTrue(parsed.challengeRequired)
        assertTrue(parsed.expiresIn > 0)

        assertEquals(403, status("login.403.enrollment"))
        val enrollment = body("login.403.enrollment")
        assertEquals(900, enrollment.getInt("expiresIn"))
        assertEquals(true, enrollment.getBoolean("enrollmentRequired"))
    }

    @Test
    fun invalidCredentialAndTwoFactorFailuresUseGenericErrors() {
        assertEquals(401, status("login.401.invalid"))
        assertEquals(401, status("login.2fa.401"))
        assertTrue(body("login.401.invalid").has("error"))
        assertTrue(body("login.2fa.401").has("error"))
    }

    // ---- mapping helpers: JSON -> Kotlin wire models ----

    private fun writeResult(name: String): SyncWriteResult {
        val code = status(name)
        val json = body(name)
        return when (code) {
            200, 201 -> SyncWriteResult.Accepted(json.toRecord(), code)
            409 -> SyncWriteResult.Rejected(json.toConflict())
            else -> error("unexpected status $code")
        }
    }

    private fun JSONObject.toRevision() = SyncRevision(getLong("counter"), getString("deviceId"))

    private fun JSONObject.optString2(key: String): String? = if (has(key) && !isNull(key)) getString(key) else null

    private fun JSONObject.toMetadata() = SyncMetadata(
        fileId = optString2("fileId"),
        versionId = optString2("versionId"),
        path = optString2("path"),
        parentId = optString2("parentId"),
        name = optString2("name"),
        contentType = optString2("contentType"),
        size = if (has("size") && !isNull("size")) getLong("size") else null,
        keyEpoch = optString2("keyEpoch"),
        compartmentId = optString2("compartmentId"),
        deviceId = optString2("deviceId"),
        sourcePath = optString2("sourcePath"),
    )

    private fun JSONObject.toProof() = SyncAuthorizationProof(
        schemaVersion = getInt("schemaVersion"),
        type = getString("type"),
        suite = getString("suite"),
        protocolVersion = getInt("protocolVersion"),
        username = getString("username"),
        deviceId = getString("deviceId"),
        operationId = getString("operationId"),
        objectId = getString("objectId"),
        fileId = getString("fileId"),
        versionId = getString("versionId"),
        operation = getString("operation"),
        revision = getJSONObject("revision").toRevision(),
        baseRevision = optJSONObject("baseRevision")?.toRevision(),
        keyEpoch = getString("keyEpoch"),
        compartmentId = getString("compartmentId"),
        metadata = getJSONObject("metadata").toMetadata(),
        aadDigest = getString("aadDigest"),
        ciphertextDigest = getString("ciphertextDigest"),
        nonceDigest = getString("nonceDigest"),
        tagDigest = getString("tagDigest"),
        expiresAt = getLong("expiresAt"),
        replayId = getString("replayId"),
        idempotencyKey = getString("idempotencyKey"),
        publicKey = getString("publicKey"),
        signature = getString("signature"),
    )

    private fun JSONObject.toRecord() = SyncRecord(
        protocolVersion = getInt("protocolVersion"),
        operationId = getString("operationId"),
        objectId = getString("objectId"),
        fileId = getString("fileId"),
        versionId = getString("versionId"),
        operation = SyncOperationType.fromWire(getString("operation")),
        revision = getJSONObject("revision").toRevision(),
        baseRevision = optJSONObject("baseRevision")?.toRevision(),
        keyEpoch = getString("keyEpoch"),
        compartmentId = getString("compartmentId"),
        deviceId = getString("deviceId"),
        metadata = getJSONObject("metadata").toMetadata(),
        tombstone = getBoolean("tombstone"),
        ciphertext = getString("ciphertext"),
        nonce = getString("nonce"),
        tag = getString("tag"),
        aad = getString("aad"),
        authorization = optJSONObject("authorization")?.toProof(),
    )

    private fun JSONObject.toConflict() = SyncConflict(
        error = getString("error"),
        currentRevision = optJSONObject("currentRevision")?.toRevision(),
        current = optJSONObject("current")?.toRecord(),
    )
}
