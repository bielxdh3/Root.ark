package dev.rootark.android

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties

/** Small platform-independent gate so software-key refusal is covered by JVM tests. */
internal data class AndroidKeySecurityEvidence(
    val securityLevel: Int,
    val insideSecureHardware: Boolean,
    val userAuthenticationRequired: Boolean,
    val userAuthenticationType: Int,
    val authenticationValiditySeconds: Int,
    val authenticationEnforcedBySecureHardware: Boolean,
    val purposes: Int,
    val origin: Int,
)

internal object AndroidKeySecurityPolicy {
    @TargetApi(Build.VERSION_CODES.S)
    fun requireHardwareDeviceCredentialKey(
        evidence: AndroidKeySecurityEvidence,
        requiredPurposes: Int,
    ) {
        check(evidence.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
            evidence.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX)
        check(evidence.insideSecureHardware && evidence.authenticationEnforcedBySecureHardware)
        check(evidence.userAuthenticationRequired)
        check(evidence.userAuthenticationType and android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL != 0)
        check(evidence.authenticationValiditySeconds == 30)
        check(evidence.purposes and requiredPurposes == requiredPurposes)
        check(evidence.origin == android.security.keystore.KeyProperties.ORIGIN_GENERATED)
    }
}

/** The UI/provider gate is false until a device-authenticated hardware ECDH probe succeeded. */
internal object OwnerEnrollmentCapabilityPolicy {
    fun isEnabled(ecdhCapabilityVerified: Boolean, originMatches: Boolean, usernameMatches: Boolean): Boolean =
        ecdhCapabilityVerified && originMatches && usernameMatches
}

/** The independent owner fingerprint can survive app switching, but no login token does. */
internal object OwnerFingerprintResumePolicy {
    private const val MAX_PENDING_MILLIS = 300_000L

    fun isWithinWindow(startedAtElapsedMs: Long, nowElapsedMs: Long): Boolean =
        startedAtElapsedMs > 0 && nowElapsedMs >= startedAtElapsedMs &&
            nowElapsedMs - startedAtElapsedMs <= MAX_PENDING_MILLIS

    fun canResume(
        startedAtElapsedMs: Long, nowElapsedMs: Long,
        expectedOrigin: String?, expectedUsername: String?,
        authenticatedOrigin: String, authenticatedUsername: String,
    ): Boolean = isWithinWindow(startedAtElapsedMs, nowElapsedMs) &&
        expectedOrigin != null && expectedOrigin == authenticatedOrigin &&
        expectedUsername != null && expectedUsername == authenticatedUsername
}

/** Keyguard authorization is a short-lived hint, never a substitute for a fresh server login. */
internal object OwnerCredentialResumePolicy {
    private const val MAX_PENDING_MILLIS = 25_000L // hardware keys expire after 30 seconds

    fun isWithinWindow(approvedAtElapsedMs: Long, nowElapsedMs: Long): Boolean =
        approvedAtElapsedMs > 0 && nowElapsedMs >= approvedAtElapsedMs &&
            nowElapsedMs - approvedAtElapsedMs <= MAX_PENDING_MILLIS

    fun canResume(
        approvedAtElapsedMs: Long, nowElapsedMs: Long,
        expectedOrigin: String?, expectedUsername: String?,
        authenticatedOrigin: String, authenticatedUsername: String,
    ): Boolean = isWithinWindow(approvedAtElapsedMs, nowElapsedMs) &&
        expectedOrigin != null && expectedOrigin == authenticatedOrigin &&
        expectedUsername != null && expectedUsername == authenticatedUsername
}

@TargetApi(Build.VERSION_CODES.S)
internal fun KeyInfo.securityEvidence() = AndroidKeySecurityEvidence(
    securityLevel, isInsideSecureHardware, isUserAuthenticationRequired,
    userAuthenticationType, userAuthenticationValidityDurationSeconds,
    isUserAuthenticationRequirementEnforcedBySecureHardware, purposes, origin,
)
