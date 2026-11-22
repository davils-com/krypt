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

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.ct.fixture.FIRST_OPERATOR
import com.davils.krypt.ct.fixture.NOW
import com.davils.krypt.ct.fixture.SECOND_OPERATOR
import com.davils.krypt.ct.fixture.TestLog
import com.davils.krypt.ct.fixture.U64
import com.davils.krypt.ct.fixture.bytes
import com.davils.krypt.ct.fixture.number
import com.davils.krypt.ct.fixture.transparency
import com.davils.krypt.ct.internal.LogParts
import com.davils.krypt.ct.internal.ResultParts
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private const val MAXIMUM_LOGS: Int = 1_024
private const val MAXIMUM_CODE: Int = 255
private const val MAXIMUM_FIELD: Int = 65_535
private const val MAXIMUM_OPERATOR: Int = 256
private const val SHA1: Int = 2
private const val UNKNOWN_SIGNATURE: Int = 2
private val LOG_ID: ByteString = ByteString(ByteArray(SignedCertificateTimestamp.LOG_ID_BYTES))

private fun timestamp(
    logId: ByteString = LOG_ID,
    at: Instant = NOW,
    extensions: ByteString = ByteString(),
    hash: Int = SignedCertificateTimestamp.SHA256,
    signature: Int = SignedCertificateTimestamp.ECDSA,
    signatureBytes: ByteString = bytes(1),
): SignedCertificateTimestamp = SignedCertificateTimestamp(
    logId = logId,
    timestamp = at,
    extensions = extensions,
    hashAlgorithm = hash,
    signatureAlgorithm = signature,
    signature = signatureBytes,
)

private fun resultOf(origin: SctOrigin, log: CtLog?, status: SctStatus): SctResult =
    SctResult(ResultParts(timestamp = timestamp(), origin = origin, log = log, status = status))

class ValuesTest : FunSpec({
    test("a timestamp checks its fields and names its algorithm") {
        shouldThrow<IllegalArgumentException> { timestamp(logId = bytes(1)) }
        shouldThrow<IllegalArgumentException> { timestamp(at = Instant.fromEpochMilliseconds(-1L)) }
        shouldThrow<IllegalArgumentException> { timestamp(hash = -1) }
        shouldThrow<IllegalArgumentException> { timestamp(hash = MAXIMUM_CODE + 1) }
        shouldThrow<IllegalArgumentException> { timestamp(signature = -1) }
        shouldThrow<IllegalArgumentException> { timestamp(signature = MAXIMUM_CODE + 1) }
        shouldThrow<IllegalArgumentException> { timestamp(extensions = ByteString(ByteArray(MAXIMUM_FIELD + 1))) }
        shouldThrow<IllegalArgumentException> { timestamp(signatureBytes = ByteString(ByteArray(MAXIMUM_FIELD + 1))) }
        timestamp().algorithm shouldBe SignatureAlgorithm.EcdsaSha256
        timestamp(signature = SignedCertificateTimestamp.RSA).algorithm shouldBe SignatureAlgorithm.RsaPkcs1Sha256
        timestamp(hash = SHA1).algorithm shouldBe null
        timestamp(signature = UNKNOWN_SIGNATURE).algorithm shouldBe null
        timestamp() shouldBe timestamp()
        timestamp() shouldNotBe timestamp(signatureBytes = bytes(2))
        timestamp() shouldNotBe Any()
        timestamp().hashCode() shouldBe timestamp().hashCode()
        timestamp().toString() shouldContain "SignedCertificateTimestamp(log=0000"
        timestamp().encoded.substring(startIndex = 1 + LOG_ID.size, endIndex = 1 + LOG_ID.size + U64) shouldBe
            number(NOW.toEpochMilliseconds(), U64)
    }

    test("a log knows when it is usable and logs compare by their id") {
        val first = TestLog.create(FIRST_OPERATOR, usableFrom = NOW, usableUntil = NOW + 1.days).log
        first.isUsableAt(NOW) shouldBe true
        first.isUsableAt(NOW - 1.days) shouldBe false
        first.isUsableAt(NOW + 1.days) shouldBe false
        val always = TestLog.create(SECOND_OPERATOR).log
        always.isUsableAt(NOW) shouldBe true
        first shouldNotBe always
        first shouldNotBe Any()
        first shouldBe first
        first.hashCode() shouldBe first.logId.hashCode()
        first.toString() shouldContain "operator=$FIRST_OPERATOR"
        val key = first.publicKey
        shouldThrow<IllegalArgumentException> { transparency.log(publicKey = key, operator = " ") }
        shouldThrow<IllegalArgumentException> {
            transparency.log(publicKey = key, operator = "x".repeat(MAXIMUM_OPERATOR + 1))
        }
        shouldThrow<IllegalArgumentException> {
            transparency.log(publicKey = key, operator = FIRST_OPERATOR, usableFrom = NOW, usableUntil = NOW)
        }
        transparency.log(publicKey = key, operator = FIRST_OPERATOR, usableUntil = NOW) shouldBe first
    }

    test("a log list holds each log once and finds logs by their id") {
        val first = TestLog.create(FIRST_OPERATOR).log
        val second = TestLog.create(SECOND_OPERATOR).log
        val list = LogList(listOf(first, second))
        list.find(second.logId) shouldBe second
        list.find(LOG_ID) shouldBe null
        list shouldBe LogList(listOf(first, second))
        list shouldNotBe LogList(listOf(first))
        list shouldNotBe Any()
        list.hashCode() shouldBe LogList(listOf(first, second)).hashCode()
        list.toString() shouldBe "LogList(2 logs)"
        shouldThrow<IllegalArgumentException> { LogList(listOf(first, first)) }
        val many = (0..MAXIMUM_LOGS).map { index ->
            val parts = LogParts(
                logId = number(index.toLong(), SignedCertificateTimestamp.LOG_ID_BYTES),
                publicKey = first.publicKey,
                operator = FIRST_OPERATOR,
                usableFrom = null,
                usableUntil = null,
            )
            CtLog(parts)
        }
        shouldThrow<IllegalArgumentException> { LogList(many) }
        LogList(many.drop(1)).logs.size shouldBe MAXIMUM_LOGS
    }

    test("limits refuse values outside their ceilings") {
        shouldThrow<IllegalArgumentException> { CtLimits(maximumListBytes = 0) }
        shouldThrow<IllegalArgumentException> { CtLimits(maximumListBytes = CtLimits.HARD_MAXIMUM_LIST_BYTES + 1) }
        shouldThrow<IllegalArgumentException> { CtLimits(maximumTimestamps = 0) }
        shouldThrow<IllegalArgumentException> { CtLimits(maximumTimestamps = CtLimits.HARD_MAXIMUM_TIMESTAMPS + 1) }
        shouldThrow<IllegalArgumentException> { CtLimits(maximumSignatureBytes = 0) }
        shouldThrow<IllegalArgumentException> {
            CtLimits(maximumSignatureBytes = CtLimits.HARD_MAXIMUM_FIELD_BYTES + 1)
        }
        shouldThrow<IllegalArgumentException> { CtLimits(maximumExtensionBytes = -1) }
        shouldThrow<IllegalArgumentException> {
            CtLimits(maximumExtensionBytes = CtLimits.HARD_MAXIMUM_FIELD_BYTES + 1)
        }
        CtLimits() shouldBe CtLimits.Default
        CtLimits() shouldNotBe CtLimits(maximumTimestamps = 1)
        CtLimits() shouldNotBe Any()
        CtLimits().hashCode() shouldBe CtLimits.Default.hashCode()
        CtLimits().toString() shouldContain "maximumTimestamps=16"
        transparency.limits shouldBe CtLimits.Default
    }

    test("a policy checks its bounds and closes its builder") {
        shouldThrow<ValidationException> { ctPolicy { shortLifetimeDays = 0 } }
        shouldThrow<ValidationException> { ctPolicy { shortLifetimeDays = CtPolicy.MAXIMUM_DAYS + 1 } }
        shouldThrow<ValidationException> { ctPolicy { minimumForShort = 0 } }
        shouldThrow<ValidationException> { ctPolicy { minimumForLong = CtPolicy.MAXIMUM_COUNT + 1 } }
        shouldThrow<ValidationException> { ctPolicy { minimumOperators = 0 } }
        val lenient = ctPolicy {
            shortLifetimeDays = 1
            minimumForLong = 1
        }
        lenient.shortLifetimeDays shouldBe 1
        CtPolicy.Default shouldBe ctPolicy { }
        CtPolicy.Default shouldNotBe lenient
        CtPolicy.Default shouldNotBe Any()
        CtPolicy.Default.hashCode() shouldBe ctPolicy { }.hashCode()
        CtPolicy.Default.toString() shouldContain "shortLifetimeDays=180"
        val builder = CtPolicyBuilder()
        builder.build()
        shouldThrow<IllegalStateException> { builder.shortLifetimeDays = 1 }
        shouldThrow<IllegalStateException> { builder.minimumForShort = 1 }
        shouldThrow<IllegalStateException> { builder.minimumForLong = 1 }
        shouldThrow<IllegalStateException> { builder.minimumOperators = 1 }
    }

    test("results compare every field") {
        val log = TestLog.create(FIRST_OPERATOR).log
        val result = resultOf(origin = SctOrigin.Tls, log = log, status = SctStatus.Valid)
        result shouldBe resultOf(origin = SctOrigin.Tls, log = log, status = SctStatus.Valid)
        result shouldNotBe resultOf(origin = SctOrigin.Ocsp, log = log, status = SctStatus.Valid)
        result shouldNotBe resultOf(origin = SctOrigin.Tls, log = null, status = SctStatus.Valid)
        result shouldNotBe resultOf(origin = SctOrigin.Tls, log = log, status = SctStatus.InvalidSignature)
        result shouldNotBe Any()
        result.hashCode() shouldBe timestamp().hashCode()
        result.toString() shouldBe "SctResult(Tls, Valid)"
    }
})
