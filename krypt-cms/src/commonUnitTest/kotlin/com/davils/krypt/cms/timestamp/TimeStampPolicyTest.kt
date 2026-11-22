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
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.FixedClock
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private val POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.10")

private val strict: TimeStamps = TimeStamps(
    Crypto(
        environment {
            clock = FixedClock
            policy = CryptoPolicy.Cnsa2
        },
    ),
)

class TimeStampPolicyTest : FunSpec({
    test("a token whose imprint digest the policy forbids gives a failure, not an exception") {
        val pki = Pki.create()
        val tsa = pki.authority()
        val authority = TimeStampAuthority(
            crypto = crypto,
            signer = tsa.signer,
            certificate = tsa.certificate,
            policy = POLICY,
        )
        val timeStamps = TimeStamps(crypto)
        val request = timeStamps.request(CONTENT)
        val response = timeStamps.decodeResponse(authority.respond(request.encoded)).value()
        val token = checkNotNull(response.token)
        timeStamps.verifyToken(token = token, data = CONTENT).value() shouldBe token
        val decoded = strict.decodeToken(token.encoded).value()
        strict.verifyToken(token = decoded, data = CONTENT).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        strict.verify(response = response, request = request).failureOrNull() shouldBe
            CmsFailure.AlgorithmNotPermitted
    }
})
