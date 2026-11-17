package dev.rootark.android

import java.io.IOException

internal enum class CiphertextCaptureUiResult { ALREADY_CAPTURED, FAILED }

/** MainActivity's capture error boundary: a validated duplicate leaves the login cache intact. */
internal object CiphertextCaptureFailurePolicy {
    fun handle(failure: Exception?, discardCaptureAndKeystoreKey: () -> Unit): CiphertextCaptureUiResult {
        if (failure is DuplicateCiphertextCaptureException) return CiphertextCaptureUiResult.ALREADY_CAPTURED
        if (failure is SecurityException || failure is IOException) discardCaptureAndKeystoreKey()
        return CiphertextCaptureUiResult.FAILED
    }
}
