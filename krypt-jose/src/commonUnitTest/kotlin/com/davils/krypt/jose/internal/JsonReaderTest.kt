/*
 * Copyright 2026 Davils
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.davils.krypt.jose.internal

import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.hex
import com.davils.krypt.jose.fixture.value
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val WHITESPACE: String = "\t" + "\r\n"
private const val LIMIT_BYTES: Int = 64
private val ESCAPED: String = listOf("\"\\/", "\b\u000C", "\n\r", "\t\u00E9", "\uD83D\uDE00").joinToString("")
private val CONTROLS: String =
    listOf("\"\\", "\b", "\u000C\n", "\r\t", "\u0001\u001F", " /\u00E9", "\uD83D", "\uDE00").joinToString("")
private val limits = JoseLimits(maximumBytes = 64, maximumDepth = 3, maximumMembers = 2, maximumStringLength = 4)

private fun read(text: String, with: JoseLimits = JoseLimits.Default) = JsonReader.read(text.encodeToByteArray(), with)

private fun readHex(bytes: String) = JsonReader.read(hex(bytes).toByteArray(), JoseLimits.Default)

class JsonReaderTest : FunSpec({
    test("reads every kind of value with whitespace around it") {
        val parts = listOf(""" {"a" :""", """[1, -2, 0, true, false, null, "x"]""", """, "b": {}, "c": []} """)
        val value = read(parts.joinToString(separator = WHITESPACE)).value()
        value shouldBe JsonValue.Object.of(
            "a" to JsonValue.Array(
                listOf(
                    JsonValue.Integer(1),
                    JsonValue.Integer(value = -2),
                    JsonValue.Integer(0),
                    JsonValue.Bool(true),
                    JsonValue.Bool(false),
                    JsonValue.Null,
                    JsonValue.Text("x"),
                ),
            ),
            "b" to JsonValue.Object.Empty,
            "c" to JsonValue.Array(emptyList()),
        )
        read("9007199254740991").value() shouldBe JsonValue.Integer(JsonValue.Integer.MAXIMUM)
        read("-9007199254740991").value() shouldBe JsonValue.Integer(-JsonValue.Integer.MAXIMUM)
    }

    test("reads escapes and UTF-8 of every length") {
        read(""""\"\\\/\b\f\n\r\t\u00E9\ud83d\ude00"""").value() shouldBe
            JsonValue.Text(ESCAPED)
        readHex("22c3a9e282acf09f988022").value() shouldBe JsonValue.Text("\u00E9\u20AC\uD83D\uDE00")
    }

    test("refuses broken structure") {
        val outcome1 = listOf(
            "",
            " ",
            "{",
            """{"a"}""",
            """{"a":1,}""",
            "[1,]",
            "[1 2]",
            """{"a":1 "b":2}""",
            "{1:2}",
            """{"a":1}x""",
            "tru",
            "nul",
            "fals",
            """"abc""",
            "\"a\u0001\"",
            """"\x"""",
            """"\u00g0"""",
            """"\u12"""",
            """"\ud800"""",
            """"\udc00"""",
            """"\ud800\u0041"""",
            """"\ud800\ue000"""",
            """"\ud800x"""",
            """"\ufdd0"""",
            """"\uffff"""",
            """"\ud83f\udffe"""",
            """{"a":1,"a":2}""",
        )
        outcome1.forEach { text -> read(text).failure() shouldBe JoseFailure.Malformed }
    }

    test("refuses every number JOSE does not need") {
        listOf("01", "-0", "1.5", "1e3", "-", "+1", "9007199254740992", "12345678901234567", "1E2", ".5")
            .forEach { text -> read(text).failure() shouldBe JoseFailure.Malformed }
    }

    test("refuses invalid UTF-8") {
        val outcome2 = listOf(
            "efbbbf7b7d",
            "22c08022",
            "22c18122",
            "22e0808022",
            "22f080808022",
            "22eda08022",
            "22f490808022",
            "22f522",
            "228022",
            "22c322",
            "22e282",
            "22efbfbf22",
            "22efb79022",
        )
        outcome2.forEach { bytes -> readHex(bytes).failure() shouldBe JoseFailure.Malformed }
    }

    test("enforces every limit at the limit and one past it") {
        read("[[[1]]]", limits).value()
        read("""{"a":{"b":{}}}""", limits).value()
        read("""{"a":{"b":{"c":{}}}}""", limits).failure() shouldBe JoseFailure.LimitExceeded
        read("[[[[1]]]]", limits).failure() shouldBe JoseFailure.LimitExceeded
        read("""{"a":1,"b":2}""", limits).value()
        read("""{"a":1,"b":2,"c":3}""", limits).failure() shouldBe JoseFailure.LimitExceeded
        read("[1,2]", limits).value()
        read("[1,2,3]", limits).failure() shouldBe JoseFailure.LimitExceeded
        read(""""abcd"""", limits).value()
        read(""""abcde"""", limits).failure() shouldBe JoseFailure.LimitExceeded
        read(""""\uD83D\uDE00\uD83D\uDE00"""", limits).value()
        val longest = "[" + "1,".repeat(31) + "1]"
        read("1" + " ".repeat(n = LIMIT_BYTES - 1), limits).value()
        read("1" + " ".repeat(n = LIMIT_BYTES), limits).failure() shouldBe JoseFailure.LimitExceeded
        read(longest).value()
    }

    test("reads only objects where an object is required") {
        JsonReader.readObject("[]".encodeToByteArray(), JoseLimits.Default).failure() shouldBe JoseFailure.Malformed
        JsonReader.readObject(""""a"""".encodeToByteArray(), JoseLimits.Default).failure() shouldBe
            JoseFailure.Malformed
        JsonReader.readObject("1".encodeToByteArray(), JoseLimits.Default).failure() shouldBe JoseFailure.Malformed
        JsonReader.readObject("true".encodeToByteArray(), JoseLimits.Default).failure() shouldBe
            JoseFailure.Malformed
        JsonReader.readObject("null".encodeToByteArray(), JoseLimits.Default).failure() shouldBe
            JoseFailure.Malformed
        JsonReader.readObject("x".encodeToByteArray(), JoseLimits.Default).failure() shouldBe JoseFailure.Malformed
        JsonReader.readObject("{}".encodeToByteArray(), JoseLimits.Default).value() shouldBe JsonValue.Object.Empty
    }

    test("writes compact JSON that reads back") {
        val value = JsonValue.Object.of(
            "text" to JsonValue.Text(CONTROLS),
            "list" to JsonValue.Array(listOf(JsonValue.Integer(-1), JsonValue.Bool(false), JsonValue.Null)),
            "empty" to JsonValue.Object.Empty,
        )
        val text = JsonWriter.write(value)
        val expected = """{"text":"\"\\\b\f\n\r\t\u0001\u001f /""" +
            "\u00E9\uD83D" +
            "\uDE00\"," +
            """"list":[-1,false,null],"empty":{}}"""
        text shouldBe expected
        read(text).value() shouldBe value
    }
})
