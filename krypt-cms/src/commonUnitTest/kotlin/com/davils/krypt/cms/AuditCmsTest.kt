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
    test("a signer without signed attributes does not authenticate a content type other than id-data") {
        val pki = Pki.create()
        val identity = pki.issue(KeyType.P256, "signer")
        val signed = cms.sign(CONTENT) {
            signer(identity.signer, identity.certificate) { isSignedAttributesUsed = false }
        }
        cms.verified(signed, parameters = pki.parameters)
        val relabelled = replaced(signed.encoded, oid(ContentTypes.Data), oid(ContentTypes.SignedData))
        val decoded = cms.decodeSigned(relabelled).value()
        decoded.contentType shouldBe ContentTypes.SignedData
        cms.verify(signedData = decoded, parameters = pki.parameters).failureOrNull() shouldNotBe null
    }

    test("authenticated enveloped data binds its content type") {
        val identifier = "kek".encodeToByteString()
        val enveloped = cms.envelop(
            content = CONTENT,
            recipients = listOf(Recipient.Kek(identifier, kek())),
            encryption = ContentEncryption.Aes256Gcm,
            contentType = ContentTypes.SignedData,
        )
        val relabelled = replaced(enveloped.encoded, oid(ContentTypes.SignedData), oid(ContentTypes.Data))
        val decoded = cms.decodeEnveloped(relabelled).value()
        decoded.contentType shouldBe ContentTypes.Data
        cms.decrypt(decoded, Credential.Kek(identifier, kek())).failureOrNull() shouldNotBe null
    }

    test("the tag of authenticated enveloped data has exactly 16 bytes") {
        val identifier = "kek".encodeToByteString()
        val enveloped = cms.envelop(CONTENT, listOf(Recipient.Kek(identifier, kek())), ContentEncryption.Aes256Gcm)
        val bytes = enveloped.encoded.toByteArray()
        val dataOid = oid(ContentTypes.Data).toByteArray()
        val contentInfo = ByteString(bytes).indexOf(ByteString(dataOid)) - 2
        val macStart = bytes.size - MAC_BYTES
        val ciphertextStart = macStart - CONTENT.size - 2
        val moved = bytes.copyOf()
        moved[contentInfo + 1] = (bytes[contentInfo + 1] + 1).toByte()
        moved[ciphertextStart + 1] = (CONTENT.size + 1).toByte()
        moved[macStart] = bytes[macStart + 2]
        moved[macStart + 1] = 0x04
        moved[macStart + 2] = (MAC_BYTES - 3).toByte()
        val decoded = cms.decodeEnveloped(ByteString(moved)).value()
        decoded.encryptedContent?.size shouldBe CONTENT.size + 1
        cms.decrypt(decoded, Credential.Kek(identifier, kek())).failureOrNull() shouldNotBe null
    }

    test("the PBKDF2 iterations of all password recipients of one message are bounded together") {
        val fast = Crypto(
            environment {
                policy = cryptoPolicy {
                    minimumIterations = 1_000
                    minimumVerifiedIterations = 1_000
                    maximumIterations = ITERATIONS
                }
            },
        )
        val quick = Cms(fast)
        val recipients = List(RECIPIENTS) { Recipient.Password(SecretText.of("correct horse"), ITERATIONS) }
        val one = quick.envelop(CONTENT, recipients.take(1), ContentEncryption.Aes128Gcm)
        val many = quick.envelop(CONTENT, recipients, ContentEncryption.Aes128Gcm)
        val wrong = Credential.Password(SecretText.of("wrong"))
        val single = TimeSource.Monotonic.markNow()
        quick.decrypt(one, wrong)
        val singleTime = single.elapsedNow()
        val start = TimeSource.Monotonic.markNow()
        val failure = quick.decrypt(many, wrong).failureOrNull()
        val manyTime = start.elapsedNow()
        println(
            "PWRI: 1 recipient ${singleTime.inWholeMilliseconds} ms, $RECIPIENTS recipients " +
                "${manyTime.inWholeMilliseconds} ms, ${many.encoded.size} bytes",
        )
        failure shouldBe CmsFailure.AlgorithmNotPermitted
    }

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
