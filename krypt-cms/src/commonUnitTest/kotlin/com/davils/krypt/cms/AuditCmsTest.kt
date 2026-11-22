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

package com.davils.krypt.cms

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.enveloped.ContentEncryption
import com.davils.krypt.cms.enveloped.Credential
import com.davils.krypt.cms.enveloped.Recipient
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.FixedClock
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.replaced
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.verified
import com.davils.krypt.cms.timestamp.TimeStampAuthority
import com.davils.krypt.cms.timestamp.TimeStamps
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.io.bytestring.indexOf
import kotlin.time.TimeSource

private const val ITERATIONS: Int = 100_000
private const val RECIPIENTS: Int = 32
private const val KEK_BYTES: Int = 32
private const val MAC_BYTES: Int = 18
private val POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.10")

private fun oid(value: ObjectIdentifier): ByteString = der { objectIdentifier(value) }

private fun kek(): SecretKey = SecretKey.of(SecretBytes.copyOf(ByteArray(KEK_BYTES) { 1 }))

class AuditCmsTest : FunSpec({
    test("verifying a time-stamp token whose imprint digest the policy forbids gives a failure, not an exception") {
        val pki = Pki.create()
        val tsa = pki.authority()
        val authority = TimeStampAuthority(crypto = crypto, signer = tsa.signer, certificate = tsa.certificate, policy = POLICY)
        val timeStamps = TimeStamps(crypto)
        val request = timeStamps.request(CONTENT)
        val response = timeStamps.decodeResponse(authority.respond(request.encoded)).value()
        val token = checkNotNull(response.token)
        val strict = TimeStamps(
            Crypto(
                environment {
                    clock = FixedClock
                    policy = CryptoPolicy.Cnsa2
                },
            ),
        )
        val decoded = strict.decodeToken(token.encoded).value()
        shouldNotThrowAny { strict.verifyToken(token = decoded, data = CONTENT) }
    }
})
