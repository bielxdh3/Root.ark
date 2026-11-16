package dev.rootark.android

import java.io.IOException

/**
 * A bounded RFC 8259 syntax gate, before Android's permissive org.json parser.
 *
 * AOSP JSONTokener silently overwrites duplicate object keys and accepts
 * comments, unquoted values and non-JSON separators. Desktop org.json rejects
 * some of those inputs, so JVM-only tests do not protect the Android runtime.
 * This parser only validates syntax and key uniqueness; the existing exact
 * field/type validation and signed Sync v2 verification remain authoritative.
 */
internal object StrictRfc8259Json {
    fun validate(text: String) {
        Parser(text).parse()
    }

    private class Parser(private val text: String) {
        private var index = 0

        fun parse() {
            whitespace()
            value(0)
            whitespace()
            if (index != text.length) invalid()
        }

        private fun value(depth: Int) {
            if (depth > 16) invalid()
            whitespace()
            when (peek()) {
                '{' -> objectValue(depth + 1)
                '[' -> arrayValue(depth + 1)
                '"' -> stringValue()
                't' -> literal("true")
                'f' -> literal("false")
                'n' -> literal("null")
                else -> if (peek() == '-' || isDigit(peek())) numberValue() else invalid()
            }
        }

        private fun objectValue(depth: Int) {
            expect('{')
            whitespace()
            if (take('}')) return
            val keys = HashSet<String>()
            var count = 0
            while (true) {
                if (peek() != '"') invalid()
                val key = stringValue()
                count++
                if (count > 64 || !keys.add(key)) invalid()
                whitespace()
                expect(':')
                value(depth)
                whitespace()
                if (take('}')) return
                expect(',')
                whitespace()
            }
        }

        private fun arrayValue(depth: Int) {
            expect('[')
            whitespace()
            if (take(']')) return
            var count = 0
            while (true) {
                count++
                if (count > 256) invalid()
                value(depth)
                whitespace()
                if (take(']')) return
                expect(',')
                whitespace()
            }
        }

        private fun stringValue(): String {
            expect('"')
            val result = StringBuilder()
            while (index < text.length) {
                val char = text[index++]
                when (char) {
                    '"' -> return result.toString()
                    '\\' -> {
                        if (index >= text.length) invalid()
                        when (val escape = text[index++]) {
                            '"', '\\', '/' -> result.append(escape)
                            'b' -> result.append('\b')
                            'f' -> result.append('\u000c')
                            'n' -> result.append('\n')
                            'r' -> result.append('\r')
                            't' -> result.append('\t')
                            'u' -> {
                                if (index + 4 > text.length) invalid()
                                var point = 0
                                repeat(4) {
                                    val digit = text[index++].digitToIntOrNull(16) ?: invalid()
                                    point = (point shl 4) or digit
                                }
                                result.append(point.toChar())
                            }
                            else -> invalid()
                        }
                    }
                    else -> {
                        if (char.code < 0x20) invalid()
                        result.append(char)
                    }
                }
            }
            invalid()
        }

        private fun numberValue() {
            take('-')
            if (!take('0')) {
                val first = peek()
                if (first == null || first !in '1'..'9') invalid()
                while (isDigit(peek())) index++
            }
            if (take('.')) digits()
            if (take('e') || take('E')) {
                if (!take('+')) take('-')
                digits()
            }
        }

        private fun digits() {
            if (!isDigit(peek())) invalid()
            while (isDigit(peek())) index++
        }

        private fun literal(word: String) {
            for (char in word) expect(char)
        }

        private fun whitespace() {
            while (peek() == ' ' || peek() == '\t' || peek() == '\r' || peek() == '\n') index++
        }

        private fun peek(): Char? = text.getOrNull(index)

        private fun isDigit(char: Char?): Boolean = char != null && char in '0'..'9'

        private fun take(char: Char): Boolean {
            if (peek() != char) return false
            index++
            return true
        }

        private fun expect(char: Char) {
            if (!take(char)) invalid()
        }

        private fun invalid(): Nothing = throw IOException("Invalid protected sync response")
    }
}
