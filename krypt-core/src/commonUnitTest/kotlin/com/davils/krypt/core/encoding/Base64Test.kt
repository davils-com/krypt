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
import kotlinx.io.bytestring.encodeToByteString
import kotlin.io.encoding.Base64 as KotlinBase64

private const val MAXIMUM_SIZE: Int = 70
private const val PADDING: Char = '='
private const val GROUP: Int = 4

class Base64Test : FunSpec({
    context("the test vectors of RFC 4648 section 10") {
        withData(
            listOf(
                "" to "",
                "f" to "Zg==",
                "fo" to "Zm8=",
                "foo" to "Zm9v",
                "foob" to "Zm9vYg==",
                "fooba" to "Zm9vYmE=",
                "foobar" to "Zm9vYmFy",
            ),
        ) { (plain, encoded) ->
            val unpadded = encoded.trimEnd(PADDING)
            Base64.encode(plain.encodeToByteArray()) shouldBe encoded
            Base64.decode(encoded).getOrNull() shouldBe plain.encodeToByteString()
            Base64.encode(bytes = plain.encodeToByteString(), padding = false) shouldBe unpadded
            Base64.decode(text = unpadded, padding = false).getOrNull() shouldBe plain.encodeToByteString()
        }
    }

    test("both alphabets agree with the standard library for any bytes") {
        checkAll(Arb.byteArray(length = Arb.int(0..MAXIMUM_SIZE), content = Arb.byte())) { sample ->
            Base64.encode(sample) shouldBe KotlinBase64.encode(sample)
            Base64.encode(bytes = sample, alphabet = Base64Alphabet.Url) shouldBe KotlinBase64.UrlSafe.encode(sample)
            Base64.decode(Base64.encode(sample)).getOrNull() shouldBe ByteString(sample)
            val url = Base64.encode(bytes = sample, alphabet = Base64Alphabet.Url, padding = false)
            Base64.decode(text = url, alphabet = Base64Alphabet.Url, padding = false).getOrNull() shouldBe
                ByteString(sample)
        }
    }

    test("the characters 62 and 63 belong to their alphabet only") {
        val sample = bytes("fbff")
        Base64.encode(sample) shouldBe "+/8="
        Base64.encode(ByteString(sample)) shouldBe "+/8="
        Base64.encode(bytes = sample, alphabet = Base64Alphabet.Url) shouldBe "-_8="
        Base64.decode("-_8=") shouldBe Outcome.Failure(EncodingFailure.InvalidCharacter)
        Base64.decode(text = "+/8=", alphabet = Base64Alphabet.Url) shouldBe
            Outcome.Failure(EncodingFailure.InvalidCharacter)
    }

    context("decoding refuses every text that is not the canonical encoding") {
        withData(
            listOf(
                "Zh==" to EncodingFailure.NonCanonical,
                "Zm9=" to EncodingFailure.NonCanonical,
                "Zg" to EncodingFailure.InvalidPadding,
                "Zg=" to EncodingFailure.InvalidPadding,
                "Z===" to EncodingFailure.InvalidPadding,
                "Zg==Zg==" to EncodingFailure.InvalidPadding,
                "Zm9v\nYmF" to EncodingFailure.InvalidCharacter,
                "Zm9 " to EncodingFailure.InvalidCharacter,
                "Zm9vYmF!" to EncodingFailure.InvalidCharacter,
            ),
        ) { (text, failure) ->
            Base64.decode(text) shouldBe Outcome.Failure(failure)
        }
    }

    test("decoding without padding refuses padding and impossible lengths") {
        Base64.decode(text = "Zg==", padding = false) shouldBe Outcome.Failure(EncodingFailure.InvalidPadding)
        Base64.decode(text = "Z", padding = false) shouldBe Outcome.Failure(EncodingFailure.InvalidLength)
    }

    test("decoding refuses a text past the limit") {
        val text = "A".repeat(Base64.MAXIMUM_TEXT_LENGTH + GROUP)
        Base64.decode(text) shouldBe Outcome.Failure(EncodingFailure.TooLong)
    }
})
