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

package com.davils.krypt.cms.timestamp

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.TIME_STAMP_REQUEST
import com.davils.krypt.cms.fixture.TIME_STAMP_REQUEST_NO_NONCE
import com.davils.krypt.cms.fixture.TIME_STAMP_RESPONSE
import com.davils.krypt.cms.fixture.TIME_STAMP_RESPONSE_NO_NONCE
import com.davils.krypt.cms.fixture.TIME_STAMP_RESPONSE_REJECTED
import com.davils.krypt.cms.fixture.checkValue
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.signed.SignatureParameters
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration.Companion.milliseconds

private const val PART: Int = 999
private val POLICY: ObjectIdentifier = ObjectIdentifier.of("1.2.3.4")

class TimeStampValuesTest : FunSpec({
    test("accuracies are checked and compared") {
        checkValue(
            value = Accuracy(millis = 1),
            same = Accuracy(millis = 1),
            different = listOf(Accuracy(seconds = 1), Accuracy(millis = 2), Accuracy(millis = 1, micros = 1)),
        ) shouldBe "Accuracy(1ms)"
        Accuracy(seconds = 1, millis = PART, micros = PART).duration shouldBe 1_999.999.milliseconds
        val invalid = listOf<() -> Accuracy>(
            { Accuracy() },
            { Accuracy(seconds = -1) },
            { Accuracy(millis = -1) },
            { Accuracy(millis = PART + 1) },
            { Accuracy(micros = -1) },
            { Accuracy(micros = PART + 1) },
        )
        invalid.forEach { create -> shouldThrow<IllegalArgumentException> { create() } }
    }

    test("requests, responses, tokens and infos compare their encodings") {
        val timeStamps = TimeStamps(crypto)
        val request = timeStamps.decodeRequest(TIME_STAMP_REQUEST).value()
        val other = timeStamps.decodeRequest(TIME_STAMP_REQUEST_NO_NONCE).value()
        checkValue(
            value = request,
            same = timeStamps.decodeRequest(TIME_STAMP_REQUEST).value(),
            different = listOf(other),
        ) shouldBe
            "TimeStampRequest(SHA-256, policy=, nonce=true, certificate=true)"
        other.toString() shouldContain "policy=1.3.6.1.4.1.99999.2"
        val response = timeStamps.decodeResponse(TIME_STAMP_RESPONSE).value()
        val rejected = timeStamps.decodeResponse(TIME_STAMP_RESPONSE_REJECTED).value()
        checkValue(
            value = response,
            same = timeStamps.decodeResponse(TIME_STAMP_RESPONSE).value(),
            different = listOf(rejected),
        ) shouldContain
            "Granted"
        rejected.toString() shouldContain "Requested policy is not supported."
        val token = checkNotNull(response.token)
        val otherToken = checkNotNull(timeStamps.decodeResponse(TIME_STAMP_RESPONSE_NO_NONCE).value().token)
        checkValue(
            value = token,
            same = timeStamps.decodeToken(token.encoded).value(),
            different = listOf(otherToken),
        ) shouldContain
            "TstInfo("
        checkValue(
            value = token.info,
            same = timeStamps.decodeToken(token.encoded).value().info,
            different = listOf(otherToken.info),
        )
        timeStamps.toString() shouldContain "CmsLimits"
        TimeStampStatus.Rejection.isGranted shouldBe false
    }

    test("parameters compare every property") {
        val pki = Pki.create()
        checkValue(
            value = TimeStampParameters(),
            same = TimeStampParameters(),
            different = listOf(
                TimeStampParameters(signature = pki.parameters),
                TimeStampParameters(nonce = DerInteger.of(1)),
                TimeStampParameters(policy = POLICY),
                TimeStampParameters(isCertificateRequired = true),
            ),
        ) shouldContain "policy=,"
        TimeStampParameters(SignatureParameters(), policy = POLICY).toString() shouldContain "policy=1.2.3.4"
        val tsa = pki.authority()
        val authority = TimeStampAuthority(
            crypto = crypto,
            signer = tsa.signer,
            certificate = tsa.certificate,
            policy = POLICY,
        )
        authority.toString() shouldContain "1.2.3.4"
    }
})
