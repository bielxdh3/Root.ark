package dev.rootark.core.paths

import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.DynamicTest.dynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PortablePathValidatorTest {

    private fun loadCases(): JSONArray {
        val stream = javaClass.classLoader.getResourceAsStream("portable-paths.json")
            ?: error("portable-paths.json missing from test resources")
        val text = stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        return JSONObject(text).getJSONArray("cases")
    }

    private fun caseInput(entry: JSONObject): String {
        if (entry.has("repeat")) {
            val repeat = entry.getJSONObject("repeat")
            return repeat.getString("char").repeat(repeat.getInt("count"))
        }
        return entry.getString("path")
    }

    /** Runs every shared fixture case, identical to the Node contract test. */
    @TestFactory
    fun sharedFixtureCases(): List<DynamicTest> {
        val cases = loadCases()
        return (0 until cases.length()).map { index ->
            val entry = cases.getJSONObject(index)
            val name = entry.getString("name")
            val expectValid = entry.getBoolean("valid")
            dynamicTest("$name (valid=$expectValid)") {
                val input = caseInput(entry)
                if (expectValid) {
                    assertEquals(input, PortablePathValidator.validate(input, "path"))
                } else {
                    assertThrows<UnsafePathException> { PortablePathValidator.validate(input, "path") }
                }
            }
        }
    }

    @Test
    fun rejectsNullAndEmpty() {
        assertThrows<UnsafePathException> { PortablePathValidator.validate(null) }
        assertThrows<UnsafePathException> { PortablePathValidator.validate("") }
    }

    @Test
    fun errorMessageDoesNotEchoRejectedValue() {
        val error = assertThrows<UnsafePathException> { PortablePathValidator.validate("../secret-name.txt") }
        assertFalse(error.message!!.contains("secret-name"))
    }

    @Test
    fun internalDetectionMatchesSegments() {
        assertTrue(PortablePathValidator.isInternalRelativePath("a/.rootark-trash/b.txt"))
        assertTrue(PortablePathValidator.isInternalRelativePath(".ROOTARK-SYNC.LOCK"))
        assertFalse(PortablePathValidator.isInternalRelativePath("a/b/c.txt"))
    }
}
