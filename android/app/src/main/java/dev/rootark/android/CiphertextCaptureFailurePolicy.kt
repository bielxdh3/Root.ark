package dev.rootark.android

internal enum class CiphertextCaptureUiResult { ALREADY_CAPTURED, FAILED }

/** Transport failures cannot invalidate a previously authenticated local AEAD capture. */
internal object CiphertextCaptureFailurePolicy {
    fun handle(failure: Exception?, discardCaptureAndKeystoreKey: () -> Unit): CiphertextCaptureUiResult {
        if (failure is DuplicateCiphertextCaptureException) return CiphertextCaptureUiResult.ALREADY_CAPTURED
        // Cache save/inspect failures are SecurityException; HTTP revocations
        // (401/403/404/409) are handled before this policy by MainActivity.
        // An IOException from a failed GET never proves old disk corruption.
        if (failure is SecurityException) discardCaptureAndKeystoreKey()
        return CiphertextCaptureUiResult.FAILED
    }
}
