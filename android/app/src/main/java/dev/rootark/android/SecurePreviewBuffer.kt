package dev.rootark.android

/** Owns the mutable text while a view may retain its backing array. UI-thread only. */
internal class SecurePreviewBuffer {
    private var current: CharArray? = null
    private var clearDisplay: (() -> Unit)? = null

    fun show(characters: CharArray, display: (CharArray) -> Unit, clearView: () -> Unit) {
        try {
            clear()
            current = characters
            clearDisplay = clearView
            display(characters)
        } catch (failure: Throwable) {
            characters.fill('\u0000')
            clear()
            throw failure
        }
    }

    fun clear() {
        val previous = current
        val clearView = clearDisplay
        current = null
        clearDisplay = null
        // Android TextView.setText(char[], ...) may keep this array until
        // the next setText. Wipe immediately before replacing the text.
        previous?.fill('\u0000')
        clearView?.invoke()
    }
}
