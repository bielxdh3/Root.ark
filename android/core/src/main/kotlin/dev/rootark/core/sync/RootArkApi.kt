package dev.rootark.core.sync

/**
 * Transport-independent API for the existing Root.ark login and sync endpoints.
 *
 * Implementations (added later in the Android app module, not in `core`) must:
 * - send `Authorization: Bearer <token>` on authenticated calls;
 * - never log request/response bodies, tokens, passwords or ciphertext;
 * - map non-2xx responses to [RootArkApiException] carrying only the status and
 *   the server's short error code.
 */
interface RootArkApi {
    /** `POST /auth/login` with JSON `{"username","password"}`. */
    suspend fun login(username: String, password: String): LoginOutcome

    /** `GET /sync/v1/objects[?objectId=...]`. Response: `{protocolVersion, objects[]}`. */
    suspend fun listSyncObjects(token: String, objectId: String? = null): SyncListResponse

    /** `GET /sync/v1/objects/:objectId`. Responds 404 when the object does not exist. */
    suspend fun getSyncObject(token: String, objectId: String): SyncRecord

    /** `POST /sync/v1/objects`. Responds 201 with the stored record. */
    suspend fun createSyncObject(token: String, request: SyncOperationRequest): SyncRecord

    /** `PUT /sync/v1/objects/:objectId`. Body `objectId`, when present, must equal the path value. */
    suspend fun updateSyncObject(token: String, objectId: String, request: SyncOperationRequest): SyncRecord

    /** `DELETE /sync/v1/objects/:objectId` with a delete operation body (tombstone). */
    suspend fun deleteSyncObject(token: String, objectId: String, request: SyncOperationRequest): SyncRecord
}

/** Outcome of `POST /auth/login`. Second-factor completion is not modeled in this step. */
sealed interface LoginOutcome {
    /** HTTP 200 with `{token, username, role, permissions}`. */
    data class Authenticated(
        val token: String,
        val username: String,
        val role: String,
        val permissions: List<String>,
    ) : LoginOutcome

    /** HTTP 200 with `{challengeRequired: true, challengeId, expiresIn}`. */
    data class ChallengeRequired(
        val challengeId: String,
        val expiresInSeconds: Int,
    ) : LoginOutcome

    /** HTTP 403 with `{enrollmentRequired: true, token, username, expiresIn}`; the token is enrollment-only. */
    data class EnrollmentRequired(
        val token: String,
        val username: String,
        val expiresInSeconds: Int,
    ) : LoginOutcome
}

/** Error raised for non-2xx responses. Carries no request or response body. */
class RootArkApiException(
    val statusCode: Int,
    val errorCode: String?,
) : RuntimeException("Root.ark API request failed with HTTP $statusCode")
