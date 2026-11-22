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

package com.davils.krypt.ct

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.ct.fixture.Authority
import com.davils.krypt.ct.fixture.U16
import com.davils.krypt.ct.fixture.U64
import com.davils.krypt.ct.fixture.bytes
import com.davils.krypt.ct.fixture.concat
import com.davils.krypt.ct.fixture.crypto
import com.davils.krypt.ct.fixture.der
import com.davils.krypt.ct.fixture.number
import com.davils.krypt.ct.fixture.transparency
import com.davils.krypt.x509.extension.ExtensionIds
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val MILLISECONDS: Long = 1_800_000_000_000L
private const val SMALL_LIST: Int = 100
private const val CLAIMED: Long = 200L
private const val TRUNCATED: Int = 10
private const val HUGE_FIELD: Int = 65_535
private const val HALF_FIELD: Int = 40_000
private const val FUTURE_VERSION: Int = 1
private val LOG_ID: ByteString = ByteString(
    ByteArray(SignedCertificateTimestamp.LOG_ID_BYTES) { index -> index.toByte() },
)

private fun entry(
    version: Int = 0,
    milliseconds: Long = MILLISECONDS,
    extensions: ByteString = ByteString(),
    signature: ByteString = bytes(1, 2),
): ByteString = concat(
    bytes(version),
    LOG_ID,
    number(milliseconds, U64),
    number(extensions.size.toLong(), U16),
    extensions,
    bytes(SignedCertificateTimestamp.SHA256, SignedCertificateTimestamp.ECDSA),
    number(signature.size.toLong(), U16),
    signature,
)

private fun list(vararg entries: ByteString): ByteString {
    val framed = entries.map { entry -> concat(number(entry.size.toLong(), U16), entry) }
    val body = ByteString(framed.fold(ByteArray(0)) { all, part -> all + part.toByteArray() })
    return concat(number(body.size.toLong(), U16), body)
}

private fun failureOf(encoded: ByteString, limits: CtLimits = CtLimits.Default): CtFailure? {
    val reader = Transparency(crypto, limits)
    return reader.decodeList(encoded).failureOrNull()
}

private fun timestamp(signatureBytes: Int, extensionBytes: Int): SignedCertificateTimestamp =
    SignedCertificateTimestamp(
        logId = LOG_ID,
        timestamp = Instant.fromEpochMilliseconds(MILLISECONDS),
        extensions = ByteString(ByteArray(extensionBytes)),
        hashAlgorithm = SignedCertificateTimestamp.SHA256,
        signatureAlgorithm = SignedCertificateTimestamp.ECDSA,
        signature = ByteString(ByteArray(signatureBytes)),
    )

class CodecTest : FunSpec({
    test("a list reads, encodes back byte for byte and skips unknown versions") {
        val encoded = list(entry())
        val timestamps = checkNotNull(transparency.decodeList(encoded).getOrNull())
        val timestamp = timestamps.single()
        timestamp.logId shouldBe LOG_ID
        timestamp.timestamp shouldBe Instant.fromEpochMilliseconds(MILLISECONDS)
        timestamp.signature shouldBe bytes(1, 2)
        timestamp.encoded shouldBe entry()
        transparency.encodeList(timestamps) shouldBe encoded
        val mixed = list(entry(version = FUTURE_VERSION), entry())
        checkNotNull(transparency.decodeList(mixed).getOrNull()).size shouldBe 1
        val extension = transparency.extension(timestamps)
        extension.id shouldBe ExtensionIds.SignedCertificateTimestamps
        extension.isCritical shouldBe false
        transparency.fromOcsp(extension.value) shouldBe Outcome.Success(timestamps)
    }

    test("malformed lists are refused") {
        listOf(
            ByteString(),
            bytes(0),
            bytes(0, 0),
            concat(number(CLAIMED, U16), bytes(1)),
            concat(list(entry()), bytes(0)),
            concat(number(U16.toLong(), U16), number(0L, U16)),
            list(entry().substring(startIndex = 0, endIndex = TRUNCATED)),
            list(concat(entry(), bytes(0))),
            list(entry(milliseconds = -1L)),
            list(entry(signature = ByteString())),
        ).forEach { encoded -> failureOf(encoded) shouldBe CtFailure.Malformed }
    }

    test("lists past their limits are refused") {
        val signatureLimit = CtLimits(maximumSignatureBytes = 1)
        failureOf(list(entry()), signatureLimit) shouldBe CtFailure.LimitExceeded
        val extensionLimit = CtLimits(maximumExtensionBytes = 0)
        failureOf(list(entry(extensions = bytes(1))), extensionLimit) shouldBe CtFailure.LimitExceeded
        failureOf(list(entry(), entry()), CtLimits(maximumTimestamps = 1)) shouldBe CtFailure.LimitExceeded
        val small = CtLimits(maximumListBytes = SMALL_LIST)
        failureOf(concat(number(CLAIMED, U16), bytes(1)), small) shouldBe CtFailure.LimitExceeded
        failureOf(ByteString(ByteArray(SMALL_LIST + 1)), small) shouldBe CtFailure.LimitExceeded
        failureOf(list(entry(), entry()), CtLimits(maximumListBytes = 1)) shouldBe CtFailure.LimitExceeded
    }

    test("lists that cannot be encoded are refused") {
        shouldThrow<IllegalArgumentException> { transparency.encodeList(emptyList()) }
        val oversized = timestamp(signatureBytes = HUGE_FIELD, extensionBytes = HUGE_FIELD)
        shouldThrow<IllegalArgumentException> { transparency.encodeList(listOf(oversized)) }
        val half = timestamp(signatureBytes = HALF_FIELD, extensionBytes = 0)
        shouldThrow<IllegalArgumentException> { transparency.encodeList(listOf(half, half)) }
    }

    test("extensions and OCSP values that are no octet string are refused") {
        transparency.fromOcsp(der { integer(1L) }).failureOrNull() shouldBe CtFailure.Malformed
        val root = Authority.root()
        val plain = root.issue()
        transparency.embedded(plain) shouldBe Outcome.Success(emptyList())
        val logs = LogList(emptyList())
        val malformedTls = transparency.check(
            certificate = plain,
            issuer = root.certificate,
            logs = logs,
            tls = bytes(0),
        )
        malformedTls.failureOrNull() shouldBe CtFailure.Malformed
        val malformedOcsp = transparency.check(
            certificate = plain,
            issuer = root.certificate,
            logs = logs,
            ocsp = bytes(0),
        )
        malformedOcsp.failureOrNull() shouldBe CtFailure.Malformed
        val verdict = checkNotNull(
            transparency.check(certificate = plain, issuer = root.certificate, logs = logs).getOrNull(),
        )
        verdict.compliance shouldBe CtCompliance.NotEnoughTimestamps
        verdict.results shouldBe emptyList()
    }
})
