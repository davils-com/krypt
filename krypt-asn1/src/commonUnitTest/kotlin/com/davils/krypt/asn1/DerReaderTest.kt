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

package com.davils.krypt.asn1

import com.davils.krypt.asn1.fixture.decoded
import com.davils.krypt.asn1.fixture.hex
import com.davils.krypt.asn1.fixture.refusal
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlin.time.Instant

private const val SAMPLE: String = "300F 0201 05 0101 FF 0500 0603 2A0304 0400"
private const val FIVE: Long = 5
private const val TWO_ELEMENTS: Int = 2
private const val SMALL_DEPTH: Int = 2
private const val UNUSED_BITS: Int = 7

class DerReaderTest : FunSpec({
    test("a sequence of primitives is read in order") {
        val read = decoded(SAMPLE) {
            readSequence {
                listOf(
                    readInteger().toLongOrNull(),
                    readBoolean(),
                    readNull(),
                    readObjectIdentifier().dotted,
                    readOctetString().size,
                )
            }
        }
        read shouldBe listOf(FIVE, true, Unit, "1.2.3.4", 0)
    }

    test("optional components are read only when their tag is next") {
        val read = decoded("3007 A003 020101 0500") {
            readSequence {
                val version = readOptionalExplicit(0) { readInteger().toLongOrNull() }
                val missing = readOptionalExplicit(1) { readNull() }
                val boolean = readOptional(Tag.Boolean)
                readNull()
                listOf(version, missing, boolean)
            }
        }
        read shouldBe listOf(1L, null, null)
    }

    test("a list is read element by element up to its limit") {
        decoded(
            "3006 020101 020102",
        ) { readListOf(maximum = TWO_ELEMENTS) { readInteger().toLongOrNull() } } shouldBe listOf(1L, 2L)
        refusal("3006 020101 020102") { readListOf(maximum = 1) { readInteger() } } shouldBe DerFailure.LimitExceeded
        decoded("3100") { readSet { isExhausted } } shouldBe true
        decoded("0101FF 0500") { readRemaining().size } shouldBe TWO_ELEMENTS
    }

    test("a bounded integer is read or refused") {
        decoded("020102") { readInt(0..TWO_ELEMENTS) } shouldBe TWO_ELEMENTS
        refusal("020103") { readInt(0..TWO_ELEMENTS) } shouldBe DerFailure.InvalidValue
        refusal("0209 010000000000000000") { readInt(0..TWO_ELEMENTS) } shouldBe DerFailure.InvalidValue
    }

    test("bit strings keep their unused bits") {
        val bits = checkNotNull(decoded("03020780") { readBitString() })
        bits.unusedBits shouldBe UNUSED_BITS
        bits[0] shouldBe true
        decoded("030100") { readBitString().size } shouldBe 0
    }

    context("every encoding DER does not allow is refused") {
        withData(
            listOf(
                "30" to DerFailure.Truncated,
                "3003 0201" to DerFailure.Truncated,
                "3080 0000" to DerFailure.NonMinimalEncoding,
                "308101 00" to DerFailure.NonMinimalEncoding,
                "3085 0000000001 00" to DerFailure.NonMinimalEncoding,
                "30820001 00" to DerFailure.NonMinimalEncoding,
                "3082" to DerFailure.Truncated,
                "1F1E00" to DerFailure.NonMinimalEncoding,
                "1F8001 00" to DerFailure.NonMinimalEncoding,
                "1F 80" to DerFailure.NonMinimalEncoding,
                "1F FFFFFF7F 00" to DerFailure.NonMinimalEncoding,
                "1F" to DerFailure.Truncated,
            ),
        ) { (input, failure) -> refusal(input) { readElement() } shouldBe failure }
    }

    context("values DER does not allow are refused") {
        withData(
            listOf(
                "020200 01" to DerFailure.NonCanonicalValue,
                "0202FF 80" to DerFailure.NonCanonicalValue,
                "0200" to DerFailure.NonCanonicalValue,
            ),
        ) { (input, failure) -> refusal(input) { readInteger() } shouldBe failure }
        withData(listOf("010101", "0100", "01020000")) { input ->
            refusal(input) { readBoolean() } shouldBe DerFailure.NonCanonicalValue
        }
        withData(listOf("03020701", "030108", "0300", "030201FF")) { input ->
            refusal(input) { readBitString() } shouldBe DerFailure.NonCanonicalValue
        }
        refusal("050100") { readNull() } shouldBe DerFailure.NonCanonicalValue
        refusal("0601 80") { readObjectIdentifier() } shouldBe DerFailure.InvalidValue
    }

    test("structural mistakes are refused") {
        refusal("0500 0500") { readNull() } shouldBe DerFailure.TrailingData
        refusal("0500") { readBoolean() } shouldBe DerFailure.UnexpectedTag
        refusal("") { readNull() } shouldBe DerFailure.Truncated
        refusal("3003 0500") { readSequence { readNull() } } shouldBe DerFailure.Truncated
        refusal("3004 0500 0500") { readSequence { readNull() } } shouldBe DerFailure.TrailingData
        refusal("0500") { readElement().reader() } shouldBe DerFailure.UnexpectedTag
        refusal("0500") { refuse(DerFailure.InvalidValue, "nothing") } shouldBe DerFailure.InvalidValue
    }

    test("the limits of size, depth and element count hold") {
        refusal(text = "0500", limits = DerLimits(maximumBytes = 1)) { readNull() } shouldBe DerFailure.LimitExceeded
        val deep = "3006 3004 3002 3000"
        refusal(text = deep, limits = DerLimits(maximumDepth = SMALL_DEPTH)) {
            readSequence { readSequence { readSequence { readSequence { } } } }
        } shouldBe DerFailure.LimitExceeded
        refusal(text = "0500 0500", limits = DerLimits(maximumElements = 1)) { readRemaining() } shouldBe
            DerFailure.LimitExceeded
    }

    context("strings are read with the characters their type permits") {
        withData(
            listOf(
                "0C03 C3A46F" to "äo",
                "1302 4142" to "AB",
                "1602 6162" to "ab",
                "1203 312033" to "1 3",
                "1A02 7E21" to "~!",
                "1401 E4" to "ä",
                "1E04 00E40041" to "äA",
                "1E04 D83DDE00" to "😀",
                "1C08 000000E40001F600" to "ä😀",
            ),
        ) { (input, text) -> decoded(input) { readText() } shouldBe text }
        withData(
            listOf("0C01 FF", "1301 2A", "1601 80", "1201 41", "1A01 1F", "1E01 00", "1E02 D800", "0401 00"),
        ) { input ->
            refusal(input) { readText() } shouldBe DerFailure.InvalidValue
        }
        decoded(
            "8203 616263",
        ) { readText(tag = Tag.context(number = 2, isConstructed = false), type = Tag.Ia5String) } shouldBe
            "abc"
        refusal("1601 80") { readText(Tag.Ia5String) } shouldBe DerFailure.InvalidValue
        refusal("1C04 0000D800") { readText() } shouldBe DerFailure.InvalidValue
    }

    context("times are read in the one form DER allows") {
        withData(
            listOf(
                "170D 3439313233313233353935395A" to Instant.parse("2049-12-31T23:59:59Z"),
                "170D 3530303130313030303030305A" to Instant.parse("1950-01-01T00:00:00Z"),
                "180F 32303234303232393132303030305A" to Instant.parse("2024-02-29T12:00:00Z"),
                "1811 32303030303232393132303030302E355A" to Instant.parse("2000-02-29T12:00:00.5Z"),
            ),
        ) { (input, instant) -> decoded(input) { readTime() } shouldBe instant }
        withData(
            listOf(
                "180F 32313030303232393132303030305A",
                "1812 32303030303232393132303030302E35305A",
                "1810 32303030303232393132303030302E5A",
                "170D 3439313233313234353935395A",
                "170C 34393132333132333539355A",
                "170D 3439313233313233353935392B",
                "0C0D 3439313233313233353935395A",
                "180E 3230323430323239313230303030",
            ),
        ) { input -> refusal(input) { readTime() } shouldBe DerFailure.InvalidValue }
        decoded(
            "180F 32303234303232393132303030305A",
        ) { readGeneralizedTime() } shouldBe Instant.parse("2024-02-29T12:00:00Z")
        refusal("170D 3439313233313233353935395A") { readGeneralizedTime() } shouldBe DerFailure.UnexpectedTag
        refusal("180E 323032343032323931323030305A") { readGeneralizedTime() } shouldBe DerFailure.InvalidValue
    }

    test("an element keeps its exact encoding and shows no content") {
        val element = checkNotNull(decoded("0403 010203") { readElement() })
        element.encoded shouldBe hex("0403010203")
        element.content shouldBe hex("010203")
        element.toString() shouldBe "DerElement(Universal 4 primitive, length=3)"
        element shouldBe checkNotNull(decoded("0403 010203") { readElement() })
        element.hashCode() shouldBe element.encoded.hashCode()
        element.equals("element") shouldBe false
    }
})
