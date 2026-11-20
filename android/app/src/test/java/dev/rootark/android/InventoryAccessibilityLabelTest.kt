package dev.rootark.android

import dev.rootark.core.sync.ReadOnlyFileRow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class InventoryAccessibilityLabelTest {
    @Test
    fun duplicateNamesUseTheirPathInAccessibleLabel() {
        val finance = row("id-finance", "report.pdf", "finance/report.pdf")
        val legal = row("id-legal", "report.pdf", "legal/report.pdf")

        assertEquals("Conteúdo protegido: finance/report.pdf", protectedContentAccessibilityLabel(finance))
        assertEquals("Conteúdo protegido: legal/report.pdf", protectedContentAccessibilityLabel(legal))
        assertNotEquals(protectedContentAccessibilityLabel(finance), protectedContentAccessibilityLabel(legal))
    }

    @Test
    fun missingOrBlankPathFallsBackToName() {
        assertEquals("Conteúdo protegido: report.pdf", protectedContentAccessibilityLabel(row("id-null", "report.pdf", null)))
        assertEquals("Conteúdo protegido: report.pdf", protectedContentAccessibilityLabel(row("id-blank", "report.pdf", "   ")))
    }

    @Test
    fun bidiAndFormatCharactersNeverEnterAccessibleLabel() {
        val unsafePath = row("id-path", "report.pdf", "finance/\u202Ereport.pdf")
        val unsafeName = row("id-name", "report\u2066.pdf", null)
        val invisiblePath = row("id-invisible", "report.pdf", "finance/\u034Freport.pdf")

        assertEquals("Conteúdo protegido: report.pdf", protectedContentAccessibilityLabel(unsafePath))
        assertEquals("Conteúdo protegido: arquivo", protectedContentAccessibilityLabel(unsafeName))
        assertEquals("Conteúdo protegido: report.pdf", protectedContentAccessibilityLabel(invisiblePath))
    }

    @Test
    fun ordinaryUnicodeEmojiAndCombiningMarksArePreserved() {
        val path = "cafe\u0301/relatório 👨‍👩‍👧‍👦.pdf"
        assertEquals("Conteúdo protegido: $path", protectedContentAccessibilityLabel(row("id-unicode", "relatório 📄.pdf", path)))
        val persianPath = "پیش\u200Cنویس.pdf"
        assertEquals("Conteúdo protegido: $persianPath", protectedContentAccessibilityLabel(row("id-persian", "نویس.pdf", persianPath)))
    }

    private fun row(objectId: String, name: String, path: String?) = ReadOnlyFileRow(
        objectId = objectId,
        name = name,
        path = path,
        size = null,
        contentType = null,
        deleted = false,
    )
}
