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
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.ct.fixture.Authority
import com.davils.krypt.ct.fixture.FIRST_OPERATOR
import com.davils.krypt.ct.fixture.LONG_DAYS
import com.davils.krypt.ct.fixture.NOW
import com.davils.krypt.ct.fixture.SECOND_OPERATOR
import com.davils.krypt.ct.fixture.TestLog
import com.davils.krypt.ct.fixture.der
import com.davils.krypt.ct.fixture.transparency
import com.davils.krypt.ct.fixture.x509Entry
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.KeyUsage
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

private const val THIRD_OPERATOR: String = "Third"
private val PAST: Instant = Instant.fromEpochSeconds(1_600_000_000L)

private suspend fun verdictOf(
    certificate: Certificate,
    issuer: Authority,
    logs: List<TestLog>,
    policy: CtPolicy = CtPolicy.Default,
): CtVerdict {
    val list = LogList(logs.map { log -> log.log })
    val outcome = transparency.check(
        certificate = certificate,
        issuer = issuer.certificate,
        logs = list,
        policy = policy,
        at = NOW,
    )
    return checkNotNull(outcome.getOrNull())
}

class TransparencyTest : FunSpec({
    test("embedded timestamps of two operators make a short-lived certificate compliant") {
        val root = Authority.root()
        val first = TestLog.create(FIRST_OPERATOR)
        val second = TestLog.create(SECOND_OPERATOR)
        val certificate = root.precertified(listOf(first, second))
        val verdict = verdictOf(certificate = certificate, issuer = root, logs = listOf(first, second))
        verdict.compliance shouldBe CtCompliance.Compliant
        verdict.isCompliant shouldBe true
        verdict.results.map { result -> result.status } shouldBe listOf(SctStatus.Valid, SctStatus.Valid)
        verdict.results.map { result -> result.origin } shouldBe listOf(SctOrigin.Embedded, SctOrigin.Embedded)
        verdict.toString() shouldBe "CtVerdict(Compliant, logs=2/2, operators=2)"
    }

    test("a long-lived certificate needs three logs") {
        val root = Authority.root()
        val first = TestLog.create(FIRST_OPERATOR)
        val second = TestLog.create(SECOND_OPERATOR)
        val third = TestLog.create(THIRD_OPERATOR)
        val twice = root.precertified(listOf(first, second), lifetime = LONG_DAYS.days)
        val short = verdictOf(certificate = twice, issuer = root, logs = listOf(first, second, third))
        short.compliance shouldBe CtCompliance.NotEnoughTimestamps
        short.required shouldBe CtPolicy.Default.minimumForLong
        short.isCompliant shouldBe false
        val thrice = root.precertified(listOf(first, second, third), lifetime = LONG_DAYS.days)
        verdictOf(certificate = thrice, issuer = root, logs = listOf(first, second, third)).isCompliant shouldBe true
    }

    test("logs of one operator are not enough and a log counts once") {
        val root = Authority.root()
        val first = TestLog.create(FIRST_OPERATOR)
        val sibling = TestLog.create(FIRST_OPERATOR)
        val sameOperator = root.precertified(listOf(first, sibling))
        val verdict = verdictOf(certificate = sameOperator, issuer = root, logs = listOf(first, sibling))
        verdict.compliance shouldBe CtCompliance.NotEnoughOperators
        verdict.operators shouldBe 1
        val repeated = root.precertified(listOf(first, first))
        val once = verdictOf(certificate = repeated, issuer = root, logs = listOf(first))
        once.logs shouldBe 1
        once.compliance shouldBe CtCompliance.NotEnoughTimestamps
        val lenient = ctPolicy {
            minimumForShort = 1
            minimumOperators = 1
        }
        verdictOf(
            certificate = repeated,
            issuer = root,
            logs = listOf(first),
            policy = lenient,
        ).isCompliant shouldBe true
    }

    test("timestamps from TLS and OCSP sign the certificate itself") {
        val root = Authority.root()
        val first = TestLog.create(FIRST_OPERATOR)
        val second = TestLog.create(SECOND_OPERATOR)
        val certificate = root.issue()
        val entry = x509Entry(certificate)
        val tls = transparency.encodeList(listOf(first.sign(entry, NOW - 1.hours)))
        val stapled = transparency.encodeList(listOf(second.sign(entry, NOW - 1.hours)))
        val ocsp = der { octetString(stapled) }
        val outcome = transparency.check(
            certificate = certificate,
            issuer = root.certificate,
            logs = LogList(listOf(first.log, second.log)),
            tls = tls,
            ocsp = ocsp,
            at = NOW,
        )
        val verdict = checkNotNull(outcome.getOrNull())
        verdict.isCompliant shouldBe true
        verdict.results.map { result -> result.origin } shouldBe listOf(SctOrigin.Tls, SctOrigin.Ocsp)
    }

    test("RSA logs verify and the precertificate drops only the timestamp extension") {
        val root = Authority.root()
        val first = TestLog.create(FIRST_OPERATOR)
        val rsa = TestLog.create(SECOND_OPERATOR, type = KeyType.Rsa3072)
        val logs = listOf(first, rsa)
        val middle = root.precertified(
            logs = logs,
            after = { keyUsage(setOf(KeyUsage.DigitalSignature)) },
        )
        verdictOf(certificate = middle, issuer = root, logs = logs).isCompliant shouldBe true
        val alone = root.precertified(logs = logs, before = {})
        alone.extensions.all.size shouldBe 1
        verdictOf(certificate = alone, issuer = root, logs = logs).isCompliant shouldBe true
    }

    test("the clock of the environment is the default time") {
        val root = Authority.root()
        val first = TestLog.create(FIRST_OPERATOR)
        val second = TestLog.create(SECOND_OPERATOR)
        val certificate = root.precertified(listOf(first, second), at = PAST)
        val logs = LogList(listOf(first.log, second.log))
        val outcome = transparency.check(certificate = certificate, issuer = root.certificate, logs = logs)
        checkNotNull(outcome.getOrNull()).isCompliant shouldBe true
        val timestamp = checkNotNull(transparency.embedded(certificate).getOrNull()).first()
        val result = transparency.verify(
            timestamp = timestamp,
            origin = SctOrigin.Embedded,
            certificate = certificate,
            issuer = root.certificate,
            logs = logs,
        )
        result.status shouldBe SctStatus.Valid
    }
})
