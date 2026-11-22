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

package com.davils.krypt.core.encoding

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.fixture.bytes
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlinx.io.bytestring.ByteString

private const val MAXIMUM_SIZE: Int = 48
private const val SAMPLE: String = "000f10ffa0"

class HexTest : FunSpec({
    test("encoding writes lower case pairs with an optional separator") {
        val sample = bytes(SAMPLE)
        Hex.encode(sample) shouldBe SAMPLE
        Hex.encode(bytes = ByteString(sample), separator = ':') shouldBe "00:0f:10:ff:a0"
        Hex.encode(ByteArray(0)) shouldBe ""
        Hex.encode(ByteString(sample)) shouldBe SAMPLE
    }

    test("decoding reads both cases and round-trips any bytes") {
        Hex.decode("000FFFA0") shouldBe Hex.decode("000fffa0")
        Hex.decode("").getOrNull() shouldBe ByteString()
        Hex.decode(text = "", separator = ':').getOrNull() shouldBe ByteString()
        checkAll(Arb.byteArray(length = Arb.int(0..MAXIMUM_SIZE), content = Arb.byte())) { sample ->
            Hex.decode(Hex.encode(sample)).getOrNull() shouldBe ByteString(sample)
            val separated = Hex.encode(bytes = sample, separator = ':')
            Hex.decode(text = separated, separator = ':').getOrNull() shouldBe ByteString(sample)
        }
    }

    context("every character next to a range of digits is refused") {
        withData(listOf("/0", ":0", "@0", "`0", "G0", "g0", "0[", "0x", " 0")) { text ->
            Hex.decode(text) shouldBe Outcome.Failure(EncodingFailure.InvalidCharacter)
        }
    }

    test("decoding refuses a wrong shape or a wrong separator") {
        Hex.decode("abc") shouldBe Outcome.Failure(EncodingFailure.InvalidLength)
        Hex.decode(text = "aa-bb", separator = ':') shouldBe Outcome.Failure(EncodingFailure.InvalidCharacter)
        Hex.decode(text = "aabb", separator = ':') shouldBe Outcome.Failure(EncodingFailure.InvalidLength)
    }

    test("decoding refuses a text past the limit and reads one at the limit") {
        Hex.decode("0".repeat(Hex.MAXIMUM_TEXT_LENGTH + 2)) shouldBe Outcome.Failure(EncodingFailure.TooLong)
        val decoded = Hex.decode("0".repeat(Hex.MAXIMUM_TEXT_LENGTH)).getOrNull()
        decoded?.size shouldBe Hex.MAXIMUM_TEXT_LENGTH / 2
    }
})
