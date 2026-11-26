package dev.rootark.android

internal enum class CiphertextCaptureUiResult { ALREADY_CAPTURED, FAILED }

/** Transport failures cannot invalidate a previously authenticated local AEAD capture. */
internal object CiphertextCaptureFailurePolicy {
    fun handle(failure: Exception?, discardCaptureAndKeystoreKey: () -> Unit): CiphertextCaptureUiResult {
        if (failure is DuplicateCiphertextCaptureException) return CiphertextCaptureUiResult.ALREADY_CAPTURED
        // Only a failed local AEAD inspection justifies erasing a previously
        // authenticated cache and its Keystore key. A malformed/replayed new
        // GET (including a generic SecurityException) cannot revoke old bytes.
        // Explicit HTTP revocations are handled separately by MainActivity.
        if (failure is LocalCiphertextCacheIntegrityException) discardCaptureAndKeystoreKey()
        return CiphertextCaptureUiResult.FAILED
    }
}
