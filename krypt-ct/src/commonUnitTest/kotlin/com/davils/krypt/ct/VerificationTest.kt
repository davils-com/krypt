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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.ct.fixture.Authority
import com.davils.krypt.ct.fixture.FIRST_OPERATOR
import com.davils.krypt.ct.fixture.NOW
import com.davils.krypt.ct.fixture.SECOND_OPERATOR
import com.davils.krypt.ct.fixture.Subject
import com.davils.krypt.ct.fixture.TestLog
import com.davils.krypt.ct.fixture.flipped
import com.davils.krypt.ct.fixture.transparency
import com.davils.krypt.ct.fixture.utf8
import com.davils.krypt.ct.fixture.x509Entry
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private const val RSA_4096: Int = 4_096
private const val SHA1: Int = 2

private suspend fun Transparency.statusOf(
    timestamp: SignedCertificateTimestamp,
    subject: Subject,
    log: TestLog?,
    origin: SctOrigin = SctOrigin.Tls,
): SctStatus {
    val logs = LogList(listOfNotNull(log?.log))
    val result = verify(
        timestamp = timestamp,
        origin = origin,
        certificate = subject.certificate,
        issuer = subject.root.certificate,
        logs = logs,
        at = NOW,
    )
    return result.status
}

private fun SignedCertificateTimestamp.copy(
    hashAlgorithm: Int = this.hashAlgorithm,
    signatureAlgorithm: Int = this.signatureAlgorithm,
    signature: ByteString = this.signature,
    timestamp: Instant = this.timestamp,
): SignedCertificateTimestamp = SignedCertificateTimestamp(
    logId = logId,
    timestamp = timestamp,
    extensions = extensions,
    hashAlgorithm = hashAlgorithm,
    signatureAlgorithm = signatureAlgorithm,
    signature = signature,
)

class VerificationTest : FunSpec({
    test("unknown logs, future timestamps and logs out of service do not count") {
        val subject = Subject.create()
        val entry = x509Entry(subject.certificate)
        val log = TestLog.create(FIRST_OPERATOR)
        val timestamp = log.sign(entry, NOW)
        transparency.statusOf(timestamp = timestamp, subject = subject, log = null) shouldBe SctStatus.UnknownLog
        transparency.statusOf(timestamp = timestamp, subject = subject, log = log) shouldBe SctStatus.Valid
        val future = log.sign(entry, NOW + 1.seconds)
        transparency.statusOf(timestamp = future, subject = subject, log = log) shouldBe SctStatus.FutureTimestamp
        val retired = TestLog.create(FIRST_OPERATOR, usableUntil = NOW - 1.days)
        val late = retired.sign(entry, NOW)
        transparency.statusOf(timestamp = late, subject = subject, log = retired) shouldBe SctStatus.LogNotUsable
        val pending = TestLog.create(FIRST_OPERATOR, usableFrom = NOW - 1.days, usableUntil = NOW + 1.days)
        val early = pending.sign(entry, NOW - 2.days)
        transparency.statusOf(timestamp = early, subject = subject, log = pending) shouldBe SctStatus.LogNotUsable
        val inService = pending.sign(entry, NOW)
        transparency.statusOf(timestamp = inService, subject = subject, log = pending) shouldBe SctStatus.Valid
        val result = transparency.verify(
            timestamp = timestamp,
            origin = SctOrigin.Tls,
            certificate = subject.certificate,
            issuer = subject.root.certificate,
            logs = LogList(listOf(log.log)),
            at = NOW,
        )
        result.log shouldBe log.log
    }

    test("tampered signatures, other entries and other issuers are invalid") {
        val subject = Subject.create()
        val entry = x509Entry(subject.certificate)
        val log = TestLog.create(FIRST_OPERATOR)
        val timestamp = log.sign(entry, NOW, extensions = utf8("extension"))
        transparency.statusOf(timestamp = timestamp, subject = subject, log = log) shouldBe SctStatus.Valid
        val lastByte = timestamp.signature.size - 1
        val tampered = timestamp.copy(signature = flipped(timestamp.signature, lastByte))
        transparency.statusOf(timestamp = tampered, subject = subject, log = log) shouldBe SctStatus.InvalidSignature
        val moved = timestamp.copy(timestamp = timestamp.timestamp - 1.milliseconds)
        transparency.statusOf(timestamp = moved, subject = subject, log = log) shouldBe SctStatus.InvalidSignature
        val asEmbedded = transparency.statusOf(
            timestamp = timestamp,
            subject = subject,
            log = log,
            origin = SctOrigin.Embedded,
        )
        asEmbedded shouldBe SctStatus.InvalidSignature
        val second = TestLog.create(SECOND_OPERATOR)
        val certificate = subject.root.precertified(listOf(log, second))
        val embedded = checkNotNull(transparency.embedded(certificate).getOrNull()).first()
        val otherIssuer = Subject(Authority.root(), certificate)
        val status = transparency.statusOf(
            timestamp = embedded,
            subject = otherIssuer,
            log = log,
            origin = SctOrigin.Embedded,
        )
        status shouldBe SctStatus.InvalidSignature
    }

    test("algorithms that do not fit the log or that the policy forbids are refused") {
        val subject = Subject.create()
        val entry = x509Entry(subject.certificate)
        val log = TestLog.create(FIRST_OPERATOR)
        val timestamp = log.sign(entry, NOW)
        val asRsa = timestamp.copy(signatureAlgorithm = SignedCertificateTimestamp.RSA)
        transparency.statusOf(timestamp = asRsa, subject = subject, log = log) shouldBe SctStatus.AlgorithmNotPermitted
        val sha1 = timestamp.copy(hashAlgorithm = SHA1)
        transparency.statusOf(timestamp = sha1, subject = subject, log = log) shouldBe SctStatus.AlgorithmNotPermitted
        val noP256 = Transparency(Crypto(environment { policy = cryptoPolicy { curves(EllipticCurve.P384) } }))
        noP256.statusOf(timestamp = timestamp, subject = subject, log = log) shouldBe SctStatus.AlgorithmNotPermitted
        val noEcdsa = Transparency(
            Crypto(environment { policy = cryptoPolicy { forbid(SignatureAlgorithm.EcdsaSha256) } }),
        )
        noEcdsa.statusOf(timestamp = timestamp, subject = subject, log = log) shouldBe SctStatus.AlgorithmNotPermitted
        val rsa = TestLog.create(SECOND_OPERATOR, type = KeyType.Rsa3072)
        val rsaTimestamp = rsa.sign(entry, NOW)
        transparency.statusOf(timestamp = rsaTimestamp, subject = subject, log = rsa) shouldBe SctStatus.Valid
        val strict = Transparency(
            Crypto(
                environment {
                    policy = cryptoPolicy {
                        minimumVerifiedRsaBits = RSA_4096
                        minimumRsaBits = RSA_4096
                    }
                },
            ),
        )
        strict.statusOf(timestamp = rsaTimestamp, subject = subject, log = rsa) shouldBe SctStatus.AlgorithmNotPermitted
    }
})
