package dev.rootark.core.sync

/**
 * Transport-independent API for the existing Root.ark login and sync endpoints.
 *
 * Implementations (added later in the Android app module, not in `core`) must:
 * - send `Authorization: Bearer <token>` on authenticated calls;
 * - never log request/response bodies, tokens, passwords or ciphertext;
 * - return [SyncWriteResult] for 200, 201 and 409 write responses, and throw
 *   [RootArkApiException] for every other non-2xx status.
 */
interface RootArkApi {
    /** `POST /auth/login` with JSON `{"username","password"}`. */
    suspend fun login(username: String, password: String): LoginOutcome

    /** `POST /auth/login/2fa` with JSON `{"challengeId","code"}`. Responds with the same body as a login. */
    suspend fun completeTwoFactorLogin(challengeId: String, code: String): LoginOutcome.Authenticated

    /** `GET /sync/v1/objects[?objectId=...]`. */
    suspend fun listSyncObjects(token: String, objectId: String? = null): SyncListResponse

    /** `GET /sync/v1/objects/:objectId`. Throws [RootArkApiException] with status 404 when missing. */
    suspend fun getSyncObject(token: String, objectId: String): SyncRecord

    /** `POST /sync/v1/objects`. 201 is [SyncWriteResult.Accepted]; 409 is [SyncWriteResult.Rejected]. */
    suspend fun createSyncObject(token: String, request: SyncOperationRequest): SyncWriteResult

    /** `PUT /sync/v1/objects/:objectId`. 200 is accepted; 409 is rejected. The body `objectId` must match the path. */
    suspend fun updateSyncObject(token: String, objectId: String, request: SyncOperationRequest): SyncWriteResult

    /** `DELETE /sync/v1/objects/:objectId` with a delete operation body (tombstone). */
    suspend fun deleteSyncObject(token: String, objectId: String, request: SyncOperationRequest): SyncWriteResult
}

/** Outcome of `POST /auth/login`. */
sealed interface LoginOutcome {
    /** HTTP 200 with `{token, username, role, permissions}`. `permissions` maps each permission name to a boolean. */
    data class Authenticated(
        val token: String,
        val username: String,
        val role: String,
        val permissions: Map<String, Boolean>,
    ) : LoginOutcome

    /** HTTP 200 with `{challengeRequired: true, challengeId, expiresIn}`. `expiresIn` is seconds. */
    data class ChallengeRequired(
        val challengeRequired: Boolean,
        val challengeId: String,
        val expiresIn: Int,
    ) : LoginOutcome

    /** HTTP 403 with `{enrollmentRequired: true, token, username, expiresIn}`. The token is enrollment-only. */
    data class EnrollmentRequired(
        val enrollmentRequired: Boolean,
        val token: String,
        val username: String,
        val expiresIn: Int,
    ) : LoginOutcome
}

/** Result of a sync write. Only 200, 201 and 409 are modeled as results. */
sealed interface SyncWriteResult {
    /** HTTP 200 (update, move, delete) or 201 (create) with the stored record. */
    data class Accepted(
        val record: SyncRecord,
        val httpStatus: Int,
    ) : SyncWriteResult

    /** HTTP 409 with [SyncConflict] (replay, stale revision, or base-revision conflict). */
    data class Rejected(
        val conflict: SyncConflict,
    ) : SyncWriteResult
}

/** Error for other non-2xx responses. Carries the status only, never the body. */
class RootArkApiException(
    val statusCode: Int,
) : RuntimeException("Root.ark API request failed with HTTP $statusCode")
