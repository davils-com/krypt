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

package com.davils.krypt.cose.cbor

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.value
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val DEPTH: Int = 4
private const val ITEMS: Int = 5
private const val STRING: Int = 3
private const val ENTRIES: Int = 2
private const val BYTES: Int = 8

private val TRUNCATED: List<String> = listOf(
    "",
    "18",
    "1901",
    "1A0000",
    "1B00000000",
    "4201",
    "6261",
    "8201",
    "A101",
    "D8",
    "C1",
    "F900",
    "FA0000",
    "FB000000",
    "F8",
    "5A00010000",
)

private val MALFORMED: List<String> = listOf(
    "1C",
    "1D",
    "1E",
    "3C",
    "5C",
    "7C",
    "9C",
    "BC",
    "DC",
    "FC",
    "FD",
    "FE",
    "FF",
    "1F",
    "3F",
    "DF",
    "F818",
    "F800",
)

private val INVALID_TEXT: List<String> = listOf(
    "61FF",
    "6180",
    "62C080",
    "62C1BF",
    "62C341",
    "63E0809F",
    "63EDA080",
    "64F4908080",
    "64F0808080",
    "64F5808080",
    "63E1C080",
    "61C3",
    "62E0A0",
)

private val limits: CborLimits = CborLimits(
    maximumBytes = BYTES,
    maximumDepth = DEPTH,
    maximumItems = ITEMS,
    maximumStringBytes = STRING,
    maximumMapEntries = ENTRIES,
)

private fun decode(encoded: String): Any? = Cbor.decode(encoded = hex(encoded), limits = limits).failure()

class CborHostileTest : FunSpec({
    test("truncated input is refused") {
        TRUNCATED.forEach { encoded -> Cbor.decode(hex(encoded)).failure() shouldBe CborFailure.Truncated }
    }

    test("input that is not well formed is refused") {
        MALFORMED.forEach { encoded -> Cbor.decode(hex(encoded)).failure() shouldBe CborFailure.Malformed }
    }

    test("text that is not valid UTF-8 is refused") {
        INVALID_TEXT.forEach { encoded -> Cbor.decode(hex(encoded)).failure() shouldBe CborFailure.InvalidText }
        Cbor.decode(hex("64F09F9880")).value() shouldBe CborText("😀")
    }

    test("bytes after the item are refused") {
        Cbor.decode(hex("0000")).failure() shouldBe CborFailure.TrailingData
    }

    test("every limit holds at its bound and refuses one past it") {
        decode("8181818100") shouldBe null
        decode("818181818100") shouldBe CborFailure.LimitExceeded
        decode("C1C1C1C100") shouldBe null
        decode("C1C1C1C1C100") shouldBe CborFailure.LimitExceeded
        decode("8400000000") shouldBe null
        decode("850000000000") shouldBe CborFailure.LimitExceeded
        decode("43010203") shouldBe null
        decode("4401020304") shouldBe CborFailure.LimitExceeded
        decode("63616263") shouldBe null
        decode("6461626364") shouldBe CborFailure.LimitExceeded
        decode("A201020304") shouldBe null
        decode("A3010203040506") shouldBe CborFailure.LimitExceeded
        decode("8700000000000000") shouldBe CborFailure.LimitExceeded
        decode("870000000000000000") shouldBe CborFailure.LimitExceeded
    }

    test("huge lengths and counts are refused before any work") {
        listOf("5BFFFFFFFFFFFFFFFF", "7BFFFFFFFFFFFFFFFF", "9BFFFFFFFFFFFFFFFF", "BBFFFFFFFFFFFFFFFF").forEach {
            Cbor.decode(hex(it)).failure() shouldBe CborFailure.LimitExceeded
        }
        listOf("5A00100000", "9A00010000", "B90100").forEach { encoded ->
            Cbor.decode(hex(encoded)).failure() shouldBe CborFailure.Truncated
        }
    }

    test("deep nesting is refused") {
        val deep = "81".repeat(CborLimits.HARD_MAXIMUM_DEPTH) + "00"
        Cbor.decode(hex(deep)).failure() shouldBe CborFailure.LimitExceeded
        val tags = "C1".repeat(CborLimits.HARD_MAXIMUM_DEPTH) + "00"
        Cbor.decode(hex(tags)).failure() shouldBe CborFailure.LimitExceeded
        val maps = "A100".repeat(CborLimits.HARD_MAXIMUM_DEPTH) + "00"
        Cbor.decode(hex(maps)).failure() shouldBe CborFailure.LimitExceeded
    }

    test("the input size is checked first") {
        Cbor.decode(encoded = ByteString(ByteArray(BYTES + 1)), limits = limits).failure() shouldBe
            CborFailure.LimitExceeded
    }

    test("limits stay within their hard ceilings") {
        CborLimits.Default shouldBe CborLimits()
        CborLimits.Default.hashCode() shouldBe CborLimits().hashCode()
        (limits == CborLimits.Default) shouldBe false
        limits.equals("limits") shouldBe false
        limits.toString() shouldBe
            "CborLimits(maximumBytes=8, maximumDepth=4, maximumItems=5, maximumStringBytes=3, maximumMapEntries=2)"
        shouldThrow<ValidationException> { CborLimits(maximumBytes = 0) }
        shouldThrow<ValidationException> { CborLimits(maximumDepth = CborLimits.HARD_MAXIMUM_DEPTH + 1) }
        shouldThrow<ValidationException> { CborLimits(maximumItems = 0) }
        shouldThrow<ValidationException> { CborLimits(maximumStringBytes = CborLimits.HARD_MAXIMUM_BYTES + 1) }
        shouldThrow<ValidationException> { CborLimits(maximumMapEntries = 0) }
    }
})
