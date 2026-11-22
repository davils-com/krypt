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

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.fixture.decoded
import com.davils.krypt.asn1.fixture.hex
import com.davils.krypt.asn1.fixture.hexOf
import com.davils.krypt.asn1.fixture.refusal
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.asn1.pem.PemBlock
import com.davils.krypt.asn1.pem.PemFailure
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val UNUSED: Int = 7
private const val OVERSIZED_ARC: String = "1.1.1"
private const val HEADED: String = "-----BEGIN A-----\nH: v\n-----END A-----"
private const val CONTROL_LABEL: String = "-----BEGIN A\u0001-----\nAQID\n-----END A\u0001-----"

class EdgeCasesTest : FunSpec({
    test("peeking, explicit tags and optional elements behave at the edges") {
        decoded("") { peekTag() } shouldBe null
        decoded("A003 020101") { readExplicit(0) { readInteger().toLongOrNull() } } shouldBe 1L
        decoded("0101FF") { readOptional(Tag.Boolean)?.content } shouldBe hex("FF")
        decoded("010100") { readBoolean() } shouldBe false
        decoded("0A0101") { readElement(Tag.Enumerated).content } shouldBe hex("01")
        Tag.Enumerated.number shouldBe Tag.Enumerated.number
    }

    test("lengths beyond an Int or with a leading zero are refused") {
        refusal("3084 80000000") { readElement() } shouldBe DerFailure.NonMinimalEncoding
        refusal("3082 0080") { readElement() } shouldBe DerFailure.NonMinimalEncoding
        refusal("030101") { readBitString() } shouldBe DerFailure.NonCanonicalValue
        refusal("02010A") { readInt(0..1) } shouldBe DerFailure.InvalidValue
        refusal("0201FF") { readInt(0..1) } shouldBe DerFailure.InvalidValue
    }

    test("object identifiers refuse every malformed arc") {
        ObjectIdentifier.decodeOrNull(hex("2a" + "01".repeat(ObjectIdentifier.MAXIMUM_ARCS))) shouldBe null
        ObjectIdentifier.decodeOrNull(hex("2a8080")) shouldBe null
        ObjectIdentifier.decodeOrNull(hex("2a 81808080808080808000")) shouldBe null
        ObjectIdentifier.parseOrNull("2.${Long.MAX_VALUE}") shouldBe null
        ObjectIdentifier.parseOrNull("1.39") shouldNotBe null
        ObjectIdentifier.parseOrNull("0.1") shouldNotBe null
        ObjectIdentifier.of(OVERSIZED_ARC) shouldBe ObjectIdentifier.decodeOrNull(hex("2901"))
        ObjectIdentifier.decodeOrNull(hex("2a ff")) shouldBe null
        ObjectIdentifier.parseOrNull("1.0") shouldNotBe null
    }

    test("integers compare equal values and show large negatives in hexadecimal") {
        DerInteger.of(1L).compareTo(DerInteger.of(1L)) shouldBe 0
        val negative = checkNotNull(DerInteger.decodeOrNull(hex("80 00000000 00000000")))
        negative.isNegative shouldBe true
        negative.toString() shouldBe "0x800000000000000000"
        (negative < DerInteger.of(Long.MIN_VALUE)) shouldBe true
        DerInteger.of(Long.MAX_VALUE).toString() shouldBe Long.MAX_VALUE.toString()
        (DerInteger.of(Long.MIN_VALUE) > negative) shouldBe true
        hexOf(Der.encode { integer(DerInteger.of(1L)) }) shouldBe "020101"
    }

    test("bit strings compare every property") {
        val bits = BitString(bytes = hex("80"), unusedBits = UNUSED)
        bits shouldNotBe BitString(bytes = hex("00"), unusedBits = UNUSED)
        bits[UNUSED + 1] shouldBe false
        shouldThrow<IllegalArgumentException> { BitString(bytes = hex("80"), unusedBits = -1) }
    }

    test("limits and blocks compare every property") {
        DerLimits(maximumBytes = 1) shouldNotBe DerLimits(maximumBytes = 1, maximumDepth = 1)
        DerLimits(maximumElements = 1) shouldNotBe DerLimits()
        val block = PemBlock(label = "A", bytes = hex("01"))
        block shouldNotBe PemBlock(label = "A", bytes = hex("02"))
    }

    test("PEM refuses too many blocks and reads odd lines") {
        val block = Pem.encode(label = "A", bytes = hex("01"))
        Pem.decode(block.repeat(Pem.MAXIMUM_BLOCKS + 1)).failureOrNull() shouldBe PemFailure.LimitExceeded
        Pem.decode("-----BEGIN A\n-----END A-----").getOrNull() shouldBe emptyList()
        val headed = checkNotNull(Pem.decode(HEADED).getOrNull())
        headed.single().headers shouldBe listOf("H" to "v")
        Pem.encode(label = "A B-C", bytes = ByteString()).length shouldNotBe 0
    }

    context("times refuse every impossible date and clock") {
        withData(
            listOf(
                "180F 32303234313330313030303030305A",
                "180F 32303234303130303030303030305A",
                "180F 32303234303130313030363030305A",
                "180F 32303234303130313030303036305A",
                "170D34393132333132333539353A5A",
                "180F323032343031303130303030302B5A",
                "181032303234303130313030303030302E5A",
                "181A32303234303130313030303030302E313233343536373839305A",
                "181F32303234303130313030303030302E3132333435363738393031323334355A",
                "180F 32303234303030313030303030305A",
                "180F 32303234303133323030303030305A",
                "170D 4130313233313233353935395A",
                "180F 413032343031303130303030305A",
                "180E 3230323430313031303030303030",
            ),
        ) { input -> decoded(input) { readTime() } shouldBe null }
        decoded("180F 30303030303130313030303030305A") { readTime() } shouldBe Instant.parse("0000-01-01T00:00:00Z")
        shouldThrow<IllegalArgumentException> { Der.encode { generalizedTime(Instant.parse("-0001-01-01T00:00:00Z")) } }
    }

    context("strings refuse what their type forbids") {
        withData(
            listOf("1301 41", "1301 7A", "1301 30", "1301 3F"),
        ) { input -> decoded(input) { readText() } shouldNotBe null }
        withData(listOf("1201 2E", "1A01 7F", "1C04 00110000", "1C03 000041", "1E03 004100", "1E02 DC00")) { input ->
            decoded(input) { readText() } shouldBe null
        }
        decoded("1A01 20") { readText() } shouldBe " "
        decoded("1201 80") { readText() } shouldBe null
        decoded("1A01 80") { readText() } shouldBe null
        decoded("1801 41") { readTime() } shouldBe null
        decoded("1812 3230323430313031303030303030 2E41 5A") { readTime() } shouldBe null
        shouldThrow<IllegalArgumentException> { Der.encode { printableString("Ä") } }
        shouldThrow<IllegalArgumentException> { Pem.encode(label = "Ä", bytes = ByteString()) }
        decoded("1C04 80000000") { readText() } shouldBe null
        decoded("1C04 0010FFFF") { readText() }?.length shouldBe 2
        decoded("1301 C0") { readText() } shouldBe null
        decoded("1E04 D800 0041") { readText() } shouldBe null
        Pem.decode(CONTROL_LABEL).failureOrNull() shouldBe PemFailure.InvalidLabel
        Pem.decode("-----BEGIN-----").getOrNull() shouldBe emptyList()
        Pem.decode("-----BEGIN A-----").failureOrNull() shouldBe PemFailure.Unterminated
    }
})
