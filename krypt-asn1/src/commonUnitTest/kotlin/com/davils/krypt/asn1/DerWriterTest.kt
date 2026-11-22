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
import com.davils.krypt.asn1.fixture.hexOf
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import io.kotest.property.Arb
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val SHORT_CONTENT: Int = 127
private const val LONG_CONTENT: Int = 200
private const val LONGER_CONTENT: Int = 300
private const val HIGH_TAG_NUMBER: Int = 31
private const val LARGE_TAG_NUMBER: Int = 200
private const val FIRST_SECOND: Long = 2_524_608_000
private const val LAST_SECOND: Long = 253_402_300_799

class DerWriterTest : FunSpec({
    context("integers are written in their minimal two's complement form") {
        withData(
            listOf(
                0L to "020100",
                Byte.MAX_VALUE.toLong() to "02017f",
                Byte.MAX_VALUE + 1L to "02020080",
                UByte.MAX_VALUE.toLong() + 1L to "02020100",
                Byte.MIN_VALUE.toLong() to "020180",
                Byte.MIN_VALUE - 1L to "0202ff7f",
                Long.MIN_VALUE to "02088000000000000000",
            ),
        ) { (value, encoding) -> hexOf(Der.encode { integer(value) }) shouldBe encoding }
    }

    test("primitives are written in their one DER form") {
        val encoded = Der.encode {
            sequence {
                boolean(true)
                boolean(false)
                nullValue()
                objectIdentifier(ObjectIdentifier.of("1.2.840.113549"))
                octetString(hex("0102"))
                bitString(BitString(bytes = hex("80"), unusedBits = 7))
                utf8String("ä")
                printableString("A B")
                ia5String("a@b")
                explicit(0) { integer(1L) }
                octetStringOf { nullValue() }
            }
        }
        hexOf(
            encoded,
        ) shouldBe "30" +
            "2f" +
            "0101ff" +
            "010100" +
            "0500" +
            "06062a864886f70d" +
            "04020102" +
            "03020780" +
            "0c02c3a4" +
            "1303412042" +
            "1603614062" +
            "a003020101" +
            "04020500"
    }

    test("lengths of 128 and more use the long form") {
        hexOf(Der.encode { octetString(ByteString(ByteArray(SHORT_CONTENT))) }) shouldStartWith "047f"
        hexOf(Der.encode { octetString(ByteString(ByteArray(LONG_CONTENT))) }) shouldStartWith "0481c8"
        hexOf(Der.encode { octetString(ByteString(ByteArray(LONGER_CONTENT))) }) shouldStartWith "0482012c"
    }

    test("tag numbers of 31 and more use the high tag form") {
        val tag = Tag.context(number = HIGH_TAG_NUMBER, isConstructed = false)
        hexOf(Der.encode { nullValue(tag) }) shouldBe "9f1f00"
        val large = Tag(tagClass = TagClass.Private, isConstructed = true, number = LARGE_TAG_NUMBER)
        hexOf(Der.encode { constructed(large) { } }) shouldBe "ff814800"
        decoded("ff814800") { readElement().tag } shouldBe large
    }

    test("a SET OF is sorted by encoding") {
        val encoded = Der.encode {
            setOf {
                integer(2L)
                integer(1L)
                octetString(hex("01"))
                integer(1L)
            }
        }
        hexOf(encoded) shouldBe "310c" + "020101" + "020101" + "020102" + "040101"
    }

    test("times use UTCTime up to 2049 and GeneralizedTime afterwards") {
        hexOf(Der.encode { time(Instant.parse("2049-12-31T23:59:59.9Z")) }) shouldBe
            "170d" + hexOf(ByteString("491231235959Z".encodeToByteArray()))
        hexOf(Der.encode { time(Instant.parse("2050-01-01T00:00:00Z")) }) shouldBe
            "180f" + hexOf(ByteString("20500101000000Z".encodeToByteArray()))
        hexOf(Der.encode { time(Instant.parse("1949-12-31T23:59:59Z")) }) shouldBe
            "180f" + hexOf(ByteString("19491231235959Z".encodeToByteArray()))
        hexOf(Der.encode { generalizedTime(Instant.parse("2024-01-02T03:04:05.25Z")) }) shouldBe
            "1812" + hexOf(ByteString("20240102030405.25Z".encodeToByteArray()))
        shouldThrow<IllegalArgumentException> {
            Der.encode {
                generalizedTime(
                    Instant.parse("+10000-01-01T00:00:00Z"),
                )
            }
        }
    }

    test("every time from 2050 to 9999 survives a round trip") {
        checkAll(Arb.long(FIRST_SECOND..LAST_SECOND)) { second ->
            val instant = Instant.fromEpochSeconds(second)
            decoded(hexOf(Der.encode { time(instant) })) { readTime() } shouldBe instant
        }
    }

    test("raw elements and constructed tags are checked") {
        hexOf(Der.encode { raw(hex("0500")) }) shouldBe "0500"
        shouldThrow<IllegalArgumentException> { Der.encode { raw(hex("05000500")) } }
        shouldThrow<IllegalArgumentException> { Der.encode { raw(hex("05")) } }
        shouldThrow<IllegalArgumentException> { Der.encode { constructed(Tag.Null) { } } }
        shouldThrow<IllegalArgumentException> { Der.encode { printableString("a*b") } }
        shouldThrow<IllegalArgumentException> { Der.encode { ia5String("ä") } }
        hexOf(Der.encode { element(tag = Tag.Null, content = ByteString()) }) shouldBe "0500"
    }
})
