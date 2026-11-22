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

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.asn1.fixture.hex
import com.davils.krypt.asn1.fixture.hexOf
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll

private const val RSA_OID: String = "1.2.840.113549"
private const val KEY_CERT_SIGN: Int = 5
private const val CRL_SIGN: Int = 6
private const val UNUSED: Int = 7
private const val HIGH_ARC: Long = 999
private const val LARGE_SECOND_ARC_MARGIN: Long = 80

class ValuesTest : FunSpec({
    test("integers convert, compare and show themselves") {
        checkAll(Arb.long(), Arb.long()) { first, second ->
            val left = DerInteger.of(first)
            val right = DerInteger.of(second)
            left.toLongOrNull() shouldBe first
            left.compareTo(right).coerceIn(minimumValue = -1, maximumValue = 1) shouldBe first.compareTo(second)
            DerInteger.decodeOrNull(left.bytes) shouldBe left
        }
        val big = DerInteger.ofMagnitude(hex("ffffffffffffffffff"))
        big.isNegative shouldBe false
        big.toLongOrNull() shouldBe null
        big.toString() shouldBe "0x00ffffffffffffffffff"
        big.magnitude() shouldBe hex("ffffffffffffffffff")
        big shouldBeGreaterThan DerInteger.of(Long.MAX_VALUE)
        DerInteger.ofMagnitude(hex("000001")).magnitude() shouldBe hex("01")
        DerInteger.Zero.magnitude() shouldBe hex("")
        DerInteger.of(-1L) shouldBeLessThan DerInteger.Zero
        DerInteger.of(-1L).toString() shouldBe "-1"
        shouldThrow<IllegalStateException> { DerInteger.of(-1L).magnitude() }
        DerInteger.Zero.hashCode() shouldBe hex("00").hashCode()
        DerInteger.Zero.equals("0") shouldBe false
    }

    test("named bits are minimal and readable") {
        val usage = BitString.ofNamedBits(setOf(KEY_CERT_SIGN, CRL_SIGN))
        hexOf(usage.bytes) shouldBe "06"
        usage.unusedBits shouldBe 1
        usage[KEY_CERT_SIGN] shouldBe true
        usage[0] shouldBe false
        usage[UNUSED] shouldBe false
        usage[-1] shouldBe false
        usage.size shouldBe UNUSED
        BitString.ofNamedBits(emptySet()).size shouldBe 0
        usage shouldBe BitString(bytes = hex("06"), unusedBits = 1)
        usage shouldNotBe BitString(bytes = hex("06"), unusedBits = 0)
        usage.hashCode() shouldBe BitString(bytes = hex("06"), unusedBits = 1).hashCode()
        usage.toString() shouldBe "BitString(06, unusedBits=1)"
        usage.equals("06") shouldBe false
        shouldThrow<IllegalArgumentException> { BitString.ofNamedBits(setOf(-1)) }
        shouldThrow<IllegalArgumentException> { BitString(bytes = hex(""), unusedBits = 1) }
        shouldThrow<IllegalArgumentException> { BitString(bytes = hex("01"), unusedBits = 1) }
        shouldThrow<IllegalArgumentException> { BitString(bytes = hex("00"), unusedBits = UNUSED + 1) }
    }

    test("object identifiers parse, encode and order") {
        val rsa = ObjectIdentifier.of(RSA_OID)
        hexOf(rsa.content) shouldBe "2a864886f70d"
        rsa.arcs.size shouldBe RSA_OID.split('.').size
        rsa.toString() shouldBe RSA_OID
        ObjectIdentifier.decodeOrNull(rsa.content) shouldBe rsa
        ObjectIdentifier.decodeOrNull(hex("8837")) shouldBe ObjectIdentifier.of("2.$HIGH_ARC")
        hexOf(ObjectIdentifier.of("2.$HIGH_ARC").content) shouldBe "8837"
        ObjectIdentifier.of("1.2") shouldBeLessThan ObjectIdentifier.of("1.2.1")
        ObjectIdentifier.of("1.10") shouldBeGreaterThan ObjectIdentifier.of("1.9")
        rsa.hashCode() shouldBe rsa.arcs.hashCode()
        rsa.equals(RSA_OID) shouldBe false
        ObjectIdentifier.parseOrNull("2.${Long.MAX_VALUE - LARGE_SECOND_ARC_MARGIN}") shouldNotBe null
    }

    context("invalid object identifiers are refused") {
        withData(
            listOf("1", "3.1", "1.40", "0.39.01", "1..2", "1.2.", "a.b", "1.99999999999999999999", "1.-2"),
        ) { dotted ->
            ObjectIdentifier.parseOrNull(dotted) shouldBe null
        }
        withData(listOf("80", "2a86", "ffffffffffffffffff7f", "2a8001", "802a")) { content ->
            ObjectIdentifier.decodeOrNull(hex(content)) shouldBe null
        }
        shouldThrow<IllegalArgumentException> { ObjectIdentifier.of("3") }
        ObjectIdentifier.parseOrNull("") shouldBe null
        ObjectIdentifier.decodeOrNull(hex("")) shouldBe null
        ObjectIdentifier.parseOrNull("1" + ".1".repeat(ObjectIdentifier.MAXIMUM_ARCS)) shouldBe null
    }

    test("tags compare, hash and show themselves") {
        val tag = Tag.context(number = 0, isConstructed = true)
        tag shouldBe Tag(tagClass = TagClass.ContextSpecific, isConstructed = true, number = 0)
        tag shouldNotBe Tag.context(number = 0, isConstructed = false)
        tag shouldNotBe Tag.context(number = 1, isConstructed = true)
        tag shouldNotBe Tag(tagClass = TagClass.Application, isConstructed = true, number = 0)
        tag.hashCode() shouldBe Tag.context(number = 0, isConstructed = true).hashCode()
        tag.toString() shouldBe "ContextSpecific 0 constructed"
        tag.equals("[0]") shouldBe false
        shouldThrow<IllegalArgumentException> { Tag.context(number = -1, isConstructed = false) }
        shouldThrow<IllegalArgumentException> { Tag.context(number = Tag.MAXIMUM_NUMBER + 1, isConstructed = false) }
    }

    test("limits are bounded by their hard ceilings") {
        val limits = DerLimits(maximumBytes = 1, maximumDepth = 1, maximumElements = 1)
        limits shouldBe DerLimits(maximumBytes = 1, maximumDepth = 1, maximumElements = 1)
        limits shouldNotBe DerLimits.Default
        limits.hashCode() shouldBe DerLimits(maximumBytes = 1, maximumDepth = 1, maximumElements = 1).hashCode()
        limits.toString() shouldBe "DerLimits(maximumBytes=1, maximumDepth=1, maximumElements=1)"
        limits.equals("limits") shouldBe false
        shouldThrow<ValidationException> { DerLimits(maximumBytes = 0) }
        shouldThrow<ValidationException> { DerLimits(maximumDepth = DerLimits.HARD_MAXIMUM_DEPTH + 1) }
        shouldThrow<ValidationException> { DerLimits(maximumElements = DerLimits.HARD_MAXIMUM_ELEMENTS + 1) }
    }
})
