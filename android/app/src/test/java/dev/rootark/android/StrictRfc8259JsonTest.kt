package dev.rootark.android

import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException

/** Checks wire syntax independently of the JVM vs Android org.json implementations. */
class StrictRfc8259JsonTest {
    @Test fun acceptsOnlyOrdinaryJsonGrammarAndEscapes() {
        StrictRfc8259Json.validate(""" { "a": [1, -2.5e+3, true, null, {"x":"\u0041"}], "other": "olá" } """)
        StrictRfc8259Json.validate("""{"emoji":"😀","escaped":"\"\\\/\b\f\n\r\t"}""")
    }

    @Test fun rejectsDuplicateNamesAtEveryLevelIncludingEscapedAliases() {
        for (bad in listOf(
            """{"objectId":"attacker","objectId":"legitimate"}""",
            """{"obj\u0065ctId":"attacker","objectId":"legitimate"}""",
            """{"authorization":{"deviceId":"attacker","deviceId":"legitimate"}}""",
            """{"a":[{"x":1,"x":2}]}""",
            """{"a":{"\u0061":1,"a":2}}""",
        )) {
            assertThrows(IOException::class.java) { StrictRfc8259Json.validate(bad) }
        }
    }

    @Test fun rejectsAndroidJsonTokenerLenienciesAndMalformedNumbers() {
        for (bad in listOf(
            """/* comment */ {"objectId":"legitimate"}""",
            """{"objectId"="legitimate"}""",
            """{"objectId";"legitimate"}""",
            """{objectId:"legitimate"}""",
            """{'objectId':'legitimate'}""",
            """{"objectId":"legitimate",}""",
            """[1,]""", """[1;2]""",
            """{"n":01}""", """{"n":+1}""", """{"n":1.}""",
            """{"n":1e}""", """{"n":NaN}""",
            """{"n":Infinity}""", """{"n":0x10}""",
            """{"a":true} // suffix""",
        )) {
            assertThrows(IOException::class.java) { StrictRfc8259Json.validate(bad) }
        }
        assertThrows(IOException::class.java) {
            StrictRfc8259Json.validate("[".repeat(40) + "0" + "]".repeat(40))
        }
    }
}
