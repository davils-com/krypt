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

package com.davils.krypt.x509

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.certificates
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.fixture.flipped
import com.davils.krypt.x509.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days

private const val FINGERPRINT_BYTES: Int = 32
private const val IDENTIFIER_BYTES: Int = 20
private const val SERIAL_BYTES: Int = 20
private const val SMALL: Int = 100
private const val VERSION_3: Int = 3
private const val SERIAL: Long = 7L
private const val OTHER_PEM: String = """-----BEGIN X-----
AAAA
-----END X-----
"""
private const val BROKEN_PEM: String = """-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
"""
private const val UNFINISHED_PEM: String = """-----BEGIN CERTIFICATE-----
!!
"""

private fun tbsWith(certificate: Certificate, change: DerWriter.() -> Unit): ByteString = der {
    sequence {
        change()
        raw(
            AlgorithmIdentifiers.encode(checkNotNull(certificate.signatureAlgorithm)),
        )
        bitString(BitString(certificate.signature))
    }
}

class CertificatesTest : FunSpec({
    test("an issued certificate reads back with every field") {
        val root = Authority.root()
        val leaf = root.issue("leaf")
        val certificate = leaf.certificate
        certificate.version shouldBe VERSION_3
        certificate.issuer shouldBe root.certificate.subject
        certificate.subject.commonName shouldBe "leaf"
        certificate.serialNumber.magnitude().size shouldBe SERIAL_BYTES
        certificate.isCa shouldBe false
        root.certificate.isCa shouldBe true
        root.certificate.isSelfIssued shouldBe true
        certificate.isSelfIssued shouldBe false
        certificate.isValidAt(NOW) shouldBe true
        certificate.isValidAt(NOW + 365.days) shouldBe false
        certificate.publicKey shouldNotBe null
        certificates.decode(certificate.encoded).getOrNull() shouldBe certificate
        certificate shouldNotBe root.certificate
        certificate shouldNotBe Any()
        certificate.hashCode() shouldBe certificate.encoded.hashCode()
        certificate.toString() shouldContain "subject=CN=leaf"
        certificates.verifySignature(certificate, checkNotNull(root.certificate.publicKey)) shouldBe Verification.Valid
        certificates.verifySignature(certificate, checkNotNull(certificate.publicKey)) shouldBe Verification.Invalid
        certificates.fingerprint(certificate).size shouldBe FINGERPRINT_BYTES
        certificates.keyIdentifier(certificate.publicKey).size shouldBe IDENTIFIER_BYTES
        certificates.toString() shouldContain "maximumBytes"
    }

    test("a certificate fixes its serial number and refuses an empty validity") {
        val pair = crypto.keys.generate(KeyType.Ed25519)
        val signer = crypto.signatures.signer(pair.privateKey)
        val certificate = certificates.issue(signer) {
            serialNumber = DerInteger.of(SERIAL)
            publicKey = pair.publicKey
            notBefore = NOW
            notAfter = NOW
        }
        certificate.serialNumber shouldBe DerInteger.of(SERIAL)
        certificate.subject.isEmpty shouldBe true
        shouldThrow<IllegalArgumentException> {
            certificates.issue(signer) {
                notBefore = NOW
                notAfter = NOW
            }
        }
        shouldThrow<IllegalArgumentException> {
            certificates.issue(
                signer,
            ) {
                publicKey = pair.publicKey
                notAfter = NOW
            }
        }
        shouldThrow<IllegalArgumentException> {
            certificates.issue(
                signer,
            ) {
                publicKey = pair.publicKey
                notBefore = NOW
            }
        }
        shouldThrow<IllegalArgumentException> {
            certificates.issue(signer) {
                publicKey = pair.publicKey
                notBefore = NOW
                notAfter = NOW - 1.days
            }
        }
    }

    test("PEM chains are read in order and anything else is refused") {
        val root = Authority.root()
        val leaf = root.issue("leaf")
        val chain = certificates.encodePem(leaf.certificate) + certificates.encodePem(root.certificate)
        certificates.decodePem(chain).getOrNull() shouldBe listOf(leaf.certificate, root.certificate)
        certificates.decodePem("nothing").failureOrNull() shouldBe X509Failure.Malformed
        val other = certificates.decodePem(OTHER_PEM)
        other.failureOrNull() shouldBe X509Failure.Malformed
        val broken = BROKEN_PEM
        certificates.decodePem(broken).failureOrNull() shouldBe X509Failure.Malformed
        certificates.decodePem(UNFINISHED_PEM).failureOrNull() shouldBe X509Failure.Malformed
    }

    test("hostile encodings are refused") {
        val root = Authority.root()
        val certificate = root.certificate
        certificates.decode(utf8("junk")).failureOrNull() shouldBe X509Failure.Malformed
        val changed = certificates.decode(flipped(certificate.encoded, certificate.encoded.size - 1))
        changed.getOrNull() shouldNotBe certificate
        val small = Certificates(crypto, X509Limits(maximumBytes = SMALL))
        small.decode(certificate.encoded).failureOrNull() shouldBe X509Failure.Malformed
        val oddSignature = der {
            sequence {
                raw(certificate.tbs)
                raw(
                    AlgorithmIdentifiers.encode(checkNotNull(certificate.signatureAlgorithm)),
                )
                bitString(BitString(ByteString(certificate.signature.toByteArray() + byteArrayOf(0)), 1))
            }
        }
        certificates.decode(oddSignature).failureOrNull() shouldBe X509Failure.Malformed
        val otherAlgorithm = der {
            sequence {
                raw(certificate.tbs)
                raw(
                    AlgorithmIdentifiers.encode(
                        SignatureAlgorithm.Ed25519,
                    ),
                )
                bitString(BitString(certificate.signature))
            }
        }
        certificates.decode(otherAlgorithm).failureOrNull() shouldBe X509Failure.Malformed
        val version1WithExtensions = tbsWith(certificate) {
            sequence {
                raw(der { explicit(0) { integer(0L) } })
                integer(DerInteger.of(1L))
                raw(
                    AlgorithmIdentifiers.encode(checkNotNull(certificate.signatureAlgorithm)),
                )
                raw(certificate.issuer.encoded)
                sequence {
                    time(certificate.notBefore)
                    time(certificate.notAfter)
                }
                raw(certificate.subject.encoded)
                raw(certificate.subjectPublicKeyInfo)
                bitString(BitString(ByteString(1)), Tag.context(number = 1, isConstructed = false))
                explicit(
                    3,
                ) {
                    sequence {
                        sequence {
                            objectIdentifier(
                                ExtensionIds.OcspNoCheck,
                            )
                            octetString(der { nullValue() })
                        }
                    }
                }
            }
        }
        certificates.decode(version1WithExtensions).failureOrNull() shouldBe X509Failure.Malformed
        val duplicate = Extension(ExtensionIds.OcspNoCheck, false, der { nullValue() })
        val twice = tbsWith(certificate) {
            sequence {
                explicit(0) { integer(2L) }
                integer(DerInteger.ofMagnitude(ByteString(ByteArray(22) { 1 })))
                raw(
                    AlgorithmIdentifiers.encode(checkNotNull(certificate.signatureAlgorithm)),
                )
                raw(certificate.issuer.encoded)
                sequence {
                    time(certificate.notBefore)
                    time(certificate.notAfter)
                }
                raw(certificate.subject.encoded)
                raw(certificate.subjectPublicKeyInfo)
                explicit(3) {
                    sequence {
                        listOf(duplicate, duplicate).forEach { extension ->
                            sequence {
                                objectIdentifier(extension.id)
                                boolean(false)
                                octetString(extension.value)
                            }
                        }
                    }
                }
            }
        }
        certificates.decode(twice).failureOrNull() shouldBe X509Failure.Malformed
    }

    test("signatures the policy forbids or the platform lacks do not verify") {
        val root = Authority.root()
        val leaf = root.issue("leaf")
        val strict = Certificates(Crypto(environment { policy = CryptoPolicy.Cnsa2 }))
        strict.verifySignature(leaf.certificate, checkNotNull(root.certificate.publicKey)) shouldBe Verification.Invalid
        val rsa = crypto.keys.generate(KeyType.Rsa3072)
        certificates.verifySignature(leaf.certificate, rsa.publicKey) shouldBe Verification.Invalid
        val limits = X509Limits()
        limits shouldBe X509Limits.Default
        limits shouldNotBe X509Limits(maximumBytes = 1)
        limits shouldNotBe Any()
        limits.hashCode() shouldBe X509Limits().hashCode()
        limits.toString() shouldContain "maximumPathLength=10"
        shouldThrow<IllegalArgumentException> { X509Limits(maximumBytes = 0) }
        shouldThrow<IllegalArgumentException> { X509Limits(maximumExtensions = 0) }
        shouldThrow<IllegalArgumentException> { X509Limits(maximumNames = 0) }
        shouldThrow<IllegalArgumentException> { X509Limits(maximumRevokedEntries = 0) }
        shouldThrow<IllegalArgumentException> { X509Limits(maximumPathLength = 0) }
        shouldThrow<IllegalArgumentException> { X509Limits(maximumPathAttempts = 0) }
    }
})
