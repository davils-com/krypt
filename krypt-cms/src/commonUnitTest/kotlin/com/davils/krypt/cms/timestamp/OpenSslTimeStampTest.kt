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

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.fixture.CA_CERTIFICATE
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.TIME_STAMP_REQUEST
import com.davils.krypt.cms.fixture.TIME_STAMP_REQUEST_BAD_POLICY
import com.davils.krypt.cms.fixture.TIME_STAMP_REQUEST_NO_NONCE
import com.davils.krypt.cms.fixture.TIME_STAMP_RESPONSE
import com.davils.krypt.cms.fixture.TIME_STAMP_RESPONSE_NO_NONCE
import com.davils.krypt.cms.fixture.TIME_STAMP_RESPONSE_REJECTED
import com.davils.krypt.cms.fixture.TSA_CERTIFICATE
import com.davils.krypt.cms.fixture.certificate
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.signed.SignatureParameters
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.milliseconds

private const val UNACCEPTED_POLICY: Int = 15

class OpenSslTimeStampTest : FunSpec({
    val timeStamps = TimeStamps(crypto)
    val validator = PathValidator(crypto = crypto, anchors = listOf(TrustAnchor.of(certificate(CA_CERTIFICATE))))
    val trusted = SignatureParameters(
        validator = validator,
        validation = ValidationParameters(isRevocationRequired = false),
    )

    test("krypt reads OpenSSL's request and verifies its response") {
        val request = timeStamps.decodeRequest(TIME_STAMP_REQUEST).value()
        request.digest shouldBe DigestAlgorithm.Sha256
        request.isCertificateRequested shouldBe true
        request.hashedMessage shouldBe crypto.digests.digest(CONTENT)
        val response = timeStamps.decodeResponse(TIME_STAMP_RESPONSE).value()
        response.status shouldBe TimeStampStatus.Granted
        val token = timeStamps.verify(response, request, trusted).value()
        token.info.policy shouldBe ObjectIdentifier.of("1.3.6.1.4.1.99999.1")
        token.info.nonce shouldBe request.nonce
        token.info.accuracy?.duration shouldBe 1_500.milliseconds + Accuracy(micros = 100).duration
        timeStamps.verifyToken(token, CONTENT, TimeStampParameters(trusted)).value() shouldBe token
        timeStamps.decodeToken(token.encoded).value() shouldBe token
    }

    test("a requested policy without a nonce, and a rejection") {
        val request = timeStamps.decodeRequest(TIME_STAMP_REQUEST_NO_NONCE).value()
        request.nonce shouldBe null
        request.isCertificateRequested shouldBe false
        val response = timeStamps.decodeResponse(TIME_STAMP_RESPONSE_NO_NONCE).value()
        timeStamps.verify(response, request, trusted).failureOrNull() shouldBe CmsFailure.SignerNotFound
        val supplied = SignatureParameters(
            certificates = listOf(certificate(TSA_CERTIFICATE)),
            validator = validator,
            validation = ValidationParameters(isRevocationRequired = false),
        )
        val token = timeStamps.verify(response, request, supplied).value()
        token.signedData.certificates shouldBe emptyList()
        timeStamps
            .verify(response, timeStamps.decodeRequest(TIME_STAMP_REQUEST).value(), supplied)
            .failureOrNull() shouldBe CmsFailure.TimeStampMismatch
        val bad = timeStamps.decodeRequest(TIME_STAMP_REQUEST_BAD_POLICY).value()
        val rejected = timeStamps.decodeResponse(TIME_STAMP_RESPONSE_REJECTED).value()
        rejected.status shouldBe TimeStampStatus.Rejection
        rejected.failures shouldBe setOf(UNACCEPTED_POLICY)
        rejected.statusText shouldBe listOf("Requested policy is not supported.")
        timeStamps.verify(rejected, bad, trusted).failureOrNull() shouldBe CmsFailure.TimeStampRejected
    }
})
