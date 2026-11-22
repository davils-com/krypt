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

@file:OptIn(DavilsInternal::class, LegacyCryptography::class)

package com.davils.krypt.x509

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.AlgorithmIdentifiers.readSignatureAlgorithm
import com.davils.krypt.x509.fixture.der
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private val PSS: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.10")
private val MGF1: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.8")
private val SHA256: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.1")
private val SHA384: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.2")
private val SHA256_RSA: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.11")
private const val SALT: Long = 32L

private fun read(encoded: ByteString): SignatureAlgorithm? = Der.decodeOrNull(encoded) { readSignatureAlgorithm() }

private const val TRAILER: Int = 3
private const val SALT_384: Long = 48L
private const val SHORT_SALT: Long = 20L

private fun pss(hash: ObjectIdentifier?, mask: ObjectIdentifier?, salt: Long?): ByteString = der {
    sequence {
        objectIdentifier(PSS)
        sequence {
            hash?.let { oid ->
                explicit(0) {
                    sequence {
                        objectIdentifier(oid)
                        nullValue()
                    }
                }
            }
            mask?.let { oid ->
                explicit(1) {
                    sequence {
                        objectIdentifier(MGF1)
                        sequence { objectIdentifier(oid) }
                    }
                }
            }
            salt?.let { value -> explicit(2) { integer(value) } }
            explicit(TRAILER) { integer(1L) }
        }
    }
}

class AlgorithmIdentifiersTest : FunSpec({
    test("every modern signature algorithm survives its identifier") {
        val algorithms = SignatureAlgorithm.entries.filter { algorithm -> !algorithm.isLegacy }
        algorithms.forEach { algorithm -> read(AlgorithmIdentifiers.encode(algorithm)) shouldBe algorithm }
        shouldThrow<IllegalArgumentException> { AlgorithmIdentifiers.encode(SignatureAlgorithm.RsaPkcs1Sha1) }
    }

    test("identifiers with wrong or unknown parameters are not known") {
        read(der { sequence { objectIdentifier(SHA256_RSA) } }) shouldBe SignatureAlgorithm.RsaPkcs1Sha256
        read(
            der {
                sequence {
                    objectIdentifier(SHA256_RSA)
                    integer(1L)
                }
            },
        ) shouldBe null
        read(
            der {
                sequence {
                    objectIdentifier(ObjectIdentifier.of("1.3.101.112"))
                    nullValue()
                }
            },
        ) shouldBe null
        read(
            der {
                sequence {
                    objectIdentifier(ObjectIdentifier.of("1.2.840.113549.1.1.5"))
                    nullValue()
                }
            },
        ) shouldBe null
        read(pss(hash = SHA384, mask = SHA384, salt = SALT_384)) shouldBe SignatureAlgorithm.RsaPssSha384
        read(pss(hash = SHA256, mask = SHA384, salt = SALT)) shouldBe null
        read(pss(hash = SHA256, mask = SHA256, salt = SHORT_SALT)) shouldBe null
        read(pss(hash = null, mask = null, salt = null)) shouldBe null
        read(pss(hash = SHA256, mask = null, salt = SALT)) shouldBe null
        read(pss(hash = SHA256, mask = SHA256, salt = null)) shouldBe null
        read(pss(hash = ObjectIdentifier.of("1.3.14.3.2.26"), mask = SHA256, salt = SALT)) shouldBe null
        val wrongMask = der {
            sequence {
                objectIdentifier(PSS)
                sequence {
                    explicit(0) { sequence { objectIdentifier(SHA256) } }
                    explicit(1) {
                        sequence {
                            objectIdentifier(SHA256)
                            sequence { objectIdentifier(SHA256) }
                        }
                    }
                    explicit(2) { integer(SALT) }
                }
            }
        }
        read(wrongMask) shouldBe null
        val digestWithParameters = der {
            sequence {
                objectIdentifier(PSS)
                sequence {
                    explicit(0) {
                        sequence {
                            objectIdentifier(SHA256)
                            integer(1L)
                        }
                    }
                }
            }
        }
        read(digestWithParameters) shouldBe null
    }
})
