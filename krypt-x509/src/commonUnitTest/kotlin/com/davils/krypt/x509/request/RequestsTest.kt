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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.x509.request

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.Verification
import com.davils.krypt.x509.AlgorithmIdentifiers
import com.davils.krypt.x509.X509Failure
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.fixture.flipped
import com.davils.krypt.x509.fixture.requests
import com.davils.krypt.x509.fixture.utf8
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val HOST: String = "api.example.com"
private val CHALLENGE: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.7")

private fun requestWith(attributes: DerWriter.() -> Unit, publicKey: ByteString): ByteString {
    val info = der {
        sequence {
            integer(0L)
            sequence { }
            raw(publicKey)
            constructed(Tag.context(number = 0, isConstructed = true)) { attributes() }
        }
    }
    return der {
        sequence {
            raw(info)
            raw(AlgorithmIdentifiers.encode(SignatureAlgorithm.EcdsaSha256))
            bitString(BitString(ByteString(0)))
        }
    }
}

class RequestsTest : FunSpec({
    test("a request proves the key of its subject and carries its extensions") {
        val pair = crypto.keys.generate(KeyType.P256)
        val request = requests.create(crypto.signatures.signer(pair.privateKey)) {
            subject { commonName(HOST) }
            extensions { subjectAlternativeNames(listOf(GeneralName.Dns(HOST))) }
        }
        request.subject.commonName shouldBe HOST
        request.publicKey shouldBe pair.publicKey
        request.requestedExtensions.subjectAlternativeNames shouldBe listOf(GeneralName.Dns(HOST))
        request.attributeTypes.size shouldBe 1
        requests.verify(request) shouldBe Verification.Valid
        requests.decodePem(requests.encodePem(request)).getOrNull() shouldBe request
        request shouldNotBe Any()
        request.hashCode() shouldBe request.encoded.hashCode()
        request.toString() shouldContain HOST
        requests.toString() shouldContain "CertificationRequests"
        val plain = requests.create(crypto.signatures.signer(pair.privateKey)) {}
        plain.attributeTypes shouldBe emptyList()
        plain.subject.isEmpty shouldBe true
    }

    test("a changed or foreign request is refused") {
        val pair = crypto.keys.generate(KeyType.Ed25519)
        val request = requests.create(crypto.signatures.signer(pair.privateKey)) { subject { commonName(HOST) } }
        val changed = flipped(request.encoded, request.encoded.size - 1)
        val changedRequest = checkNotNull(requests.decode(changed).getOrNull())
        requests.verify(changedRequest) shouldBe Verification.Invalid
        requests.decode(utf8("junk")).failureOrNull() shouldBe X509Failure.Malformed
        requests.decodePem("nothing").failureOrNull() shouldBe X509Failure.Malformed
        requests.decodePem("-----BEGIN CERTIFICATE REQUEST-----\n!!\n").failureOrNull() shouldBe X509Failure.Malformed
        val tiny = CertificationRequests(crypto, X509Limits(maximumBytes = 10))
        tiny.decode(request.encoded).failureOrNull() shouldBe X509Failure.Malformed
        val unknownKey = der {
            sequence {
                sequence {
                    objectIdentifier(
                        CHALLENGE,
                    )
                }
                bitString(BitString(ByteString(1)))
            }
        }
        val withUnknownKey = requestWith({}, unknownKey)
        val decoded = checkNotNull(requests.decode(withUnknownKey).getOrNull())
        decoded.publicKey shouldBe null
        requests.verify(decoded) shouldBe Verification.Invalid
        val challenge = requestWith(
            {
                sequence {
                    objectIdentifier(CHALLENGE)
                    setOf { utf8String("secret") }
                }
            },
            pair.publicKey.encoded,
        )
        requests.decode(challenge).getOrNull()?.attributeTypes shouldBe listOf(CHALLENGE)
        val twice = requestWith(
            {
                repeat(2) {
                    sequence {
                        objectIdentifier(CHALLENGE)
                        setOf { utf8String("x") }
                    }
                }
            },
            pair.publicKey.encoded,
        )
        requests.decode(twice).failureOrNull() shouldBe X509Failure.Malformed
        val many = requestWith(
            {
                repeat(3) { index ->
                    sequence {
                        objectIdentifier(ObjectIdentifier.of("1.2.3.$index"))
                        setOf { }
                    }
                }
            },
            pair.publicKey.encoded,
        )
        val narrow = CertificationRequests(crypto, X509Limits(maximumExtensions = 2))
        narrow.decode(many).failureOrNull() shouldBe X509Failure.Malformed
        val odd = der {
            sequence {
                raw(checkNotNull(requests.decode(challenge).getOrNull()).info)
                raw(AlgorithmIdentifiers.encode(SignatureAlgorithm.EcdsaSha256))
                bitString(BitString(ByteString(0), 1))
            }
        }
        requests.decode(odd).failureOrNull() shouldBe X509Failure.Malformed
        val trailing = der {
            sequence {
                sequence {
                    integer(0L)
                    sequence { }
                    raw(pair.publicKey.encoded)
                    constructed(Tag.context(number = 0, isConstructed = true)) { }
                    nullValue()
                }
                raw(AlgorithmIdentifiers.encode(SignatureAlgorithm.EcdsaSha256))
                bitString(BitString(ByteString(0)))
            }
        }
        requests.decode(trailing).failureOrNull() shouldBe X509Failure.Malformed
    }
})
