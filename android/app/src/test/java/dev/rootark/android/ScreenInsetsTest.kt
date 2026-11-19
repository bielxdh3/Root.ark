package dev.rootark.android

import org.junit.Assert.assertEquals
import org.junit.Test

class ScreenInsetsTest {
    @Test
    fun preservesBarsWhenKeyboardIsHidden() {
        val bars = ScreenInsets(8, 24, 12, 16)
        assertEquals(bars, bars.union(ScreenInsets(0, 0, 0, 0)))
    }

    @Test
    fun usesKeyboardHeightWithoutAddingNavigationHeight() {
        val bars = ScreenInsets(8, 24, 12, 16)
        assertEquals(ScreenInsets(8, 24, 12, 240), bars.union(ScreenInsets(0, 0, 0, 240)))
    }

    @Test
    fun preservesLargestInsetAtEveryEdge() {
        val bars = ScreenInsets(40, 24, 12, 16)
        assertEquals(ScreenInsets(40, 24, 32, 240), bars.union(ScreenInsets(0, 0, 32, 240)))
    }

    @Test
    fun usesImeInsetsWhenSystemBarsAreAbsent() {
        val bars = ScreenInsets(0, 0, 0, 0)
        assertEquals(ScreenInsets(0, 0, 0, 240), bars.union(ScreenInsets(0, 0, 0, 240)))
    }

    @Test
    fun preservesNavigationInsetWhenImeIsSmaller() {
        val bars = ScreenInsets(8, 24, 12, 48)
        assertEquals(bars, bars.union(ScreenInsets(0, 0, 0, 16)))
    }

    @Test
    fun usesLargerLeftAndTopFromSecondOperand() {
        val bars = ScreenInsets(8, 24, 12, 48)
        assertEquals(ScreenInsets(40, 64, 12, 48), bars.union(ScreenInsets(40, 64, 4, 16)))
    }
}
