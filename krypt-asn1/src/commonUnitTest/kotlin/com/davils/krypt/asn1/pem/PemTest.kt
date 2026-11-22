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

package com.davils.krypt.asn1.pem

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.fixture.hex
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldNotContain
import kotlinx.io.bytestring.ByteString

private const val CERTIFICATE: String = "CERTIFICATE"
private const val PRIVATE_KEY: String = "PRIVATE KEY"
private const val BEGIN_CERTIFICATE: String = "-----BEGIN CERTIFICATE-----"
private const val END_CERTIFICATE: String = "-----END CERTIFICATE-----"
private const val BODY: String = "AQID"
private const val NEWLINE: String = "\n"
private const val LINE: Int = 64
private const val LONG_BODY: Int = 100
private const val BLOCKS: Int = 3

private fun text(vararg lines: String): String = lines.joinToString(separator = NEWLINE)

class PemTest : FunSpec({
    test("blocks are read from around explanatory text") {
        val pem = text(
            "Subject: CN=example",
            BEGIN_CERTIFICATE,
            BODY,
            END_CERTIFICATE,
            "between",
            "-----BEGIN PRIVATE KEY-----",
            "BA U=",
            "-----END PRIVATE KEY-----",
        )
        val blocks = checkNotNull(Pem.decode(pem).getOrNull())
        blocks.map { block -> block.label } shouldBe listOf(CERTIFICATE, PRIVATE_KEY)
        blocks.first().bytes shouldBe hex("010203")
        blocks.last().bytes shouldBe hex("0405")
        Pem.decode("no blocks here").getOrNull() shouldBe emptyList()
    }

    test("the headers of a legacy encrypted key are reported") {
        val pem = text(
            "-----BEGIN RSA PRIVATE KEY-----",
            "Proc-Type: 4,ENCRYPTED",
            "DEK-Info: AES-256-CBC,00",
            "",
            BODY,
            "-----END RSA PRIVATE KEY-----",
        )
        val block = checkNotNull(Pem.decode(pem).getOrNull()).single()
        block.headers shouldBe listOf("Proc-Type" to "4,ENCRYPTED", "DEK-Info" to "AES-256-CBC,00")
        block.bytes shouldBe hex("010203")
    }

    context("malformed PEM is refused") {
        withData(
            listOf(
                text(BEGIN_CERTIFICATE, BODY) to PemFailure.Unterminated,
                text(BEGIN_CERTIFICATE, BODY, "-----END CRL-----") to PemFailure.Unterminated,
                text("-----BEGIN CERT--IFICATE-----", BODY, "-----END CERT--IFICATE-----") to PemFailure.InvalidLabel,
                text(BEGIN_CERTIFICATE, "AQI", END_CERTIFICATE) to PemFailure.InvalidBase64,
                text(BEGIN_CERTIFICATE, "AQ=D", END_CERTIFICATE) to PemFailure.InvalidBase64,
            ),
        ) { (pem, failure) -> Pem.decode(pem) shouldBe Outcome.Failure(failure) }
    }

    test("too many headers and too long a text are refused") {
        val headers = (0..Pem.MAXIMUM_HEADERS).map { index -> "H$index: v" }
        val pem = (listOf("-----BEGIN X-----") + headers + listOf("", BODY, "-----END X-----")).joinToString(NEWLINE)
        Pem.decode(pem) shouldBe Outcome.Failure(PemFailure.LimitExceeded)
        Pem.decode("A".repeat(Pem.MAXIMUM_TEXT_LENGTH + 1)) shouldBe Outcome.Failure(PemFailure.LimitExceeded)
    }

    test("writing wraps the body at 64 characters and round-trips") {
        val bytes = ByteString(ByteArray(LONG_BODY) { index -> index.toByte() })
        val pem = Pem.encode(label = CERTIFICATE, bytes = bytes)
        val lines = pem.lines()
        lines[1].length shouldBe LINE
        val block = checkNotNull(Pem.decode(pem).getOrNull()).single()
        block shouldBe PemBlock(label = CERTIFICATE, bytes = bytes)
        val twice = Pem.encode(listOf(block, block))
        twice.split("-----BEGIN").size shouldBe BLOCKS
        shouldThrow<IllegalArgumentException> { Pem.encode(label = "A--B", bytes = bytes) }
        shouldThrow<IllegalArgumentException> { Pem.encode(label = "A\tB", bytes = bytes) }
        Pem.encode(label = "", bytes = ByteString()) shouldBe text("-----BEGIN -----", "-----END -----", "")
    }

    test("a block shows its label and size, never its bytes") {
        val block = PemBlock(label = PRIVATE_KEY, bytes = hex("0102"))
        block.toString() shouldBe "PemBlock(PRIVATE KEY, size=2, headers=0)"
        block.toString() shouldNotContain "0102"
        block shouldNotBe PemBlock(label = PRIVATE_KEY, bytes = hex("0102"), headers = listOf("a" to "b"))
        block shouldNotBe PemBlock(label = "KEY", bytes = hex("0102"))
        block.hashCode() shouldBe PemBlock(label = PRIVATE_KEY, bytes = hex("0102")).hashCode()
        block.equals("block") shouldBe false
    }
})
