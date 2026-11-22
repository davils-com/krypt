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

@file:OptIn(LegacyCryptography::class)

package com.davils.krypt.ocsp

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.ocsp.fixture.SHA256_BYTES
import com.davils.krypt.ocsp.fixture.Scenario
import com.davils.krypt.ocsp.fixture.crypto
import com.davils.krypt.ocsp.fixture.der
import com.davils.krypt.ocsp.fixture.filled
import com.davils.krypt.ocsp.fixture.ocsp
import com.davils.krypt.ocsp.internal.CertIdCodec.writeCertId
import com.davils.krypt.ocsp.internal.OcspOids
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val OVERSIZED_NONCE: Int = 129
private const val SHORT_NONCE: Int = 31
private const val SMALL_BYTES: Int = 64
private const val NONCED: Int = 3
private val OTHER: ObjectIdentifier = ObjectIdentifier.of("1.2.3.4")
private val ID: CertId = CertId(
    hashAlgorithm = DigestAlgorithm.Sha256,
    issuerNameHash = filled(SHA256_BYTES),
    issuerKeyHash = filled(SHA256_BYTES),
    serialNumber = DerInteger.of(1L),
)
private val SINGLE: DerWriter.() -> Unit = { sequence { sequence { writeCertId(ID) } } }

private fun request(
    prefix: DerWriter.() -> Unit = {},
    list: DerWriter.() -> Unit = SINGLE,
    suffix: DerWriter.() -> Unit = {},
    outer: DerWriter.() -> Unit = {},
): ByteString = der {
    sequence {
        sequence {
            prefix()
            list()
            suffix()
        }
        outer()
    }
}

private fun extensions(vararg entries: DerWriter.() -> Unit): DerWriter.() -> Unit = {
    explicit(2) { sequence { entries.forEach { entry -> sequence(entry) } } }
}

private fun nonce(value: ByteString): DerWriter.() -> Unit = {
    objectIdentifier(OcspOids.NONCE)
    octetString(der { octetString(value) })
}

private fun certIdList(certId: DerWriter.() -> Unit): DerWriter.() -> Unit = {
    sequence {
        sequence {
            sequence(
                certId,
            )
        }
    }
}

class RequestTest : FunSpec({
    test("requests round-trip with several identifiers and nonces") {
        val scenario = Scenario.create()
        val ids = listOf(DigestAlgorithm.Sha256, DigestAlgorithm.Sha384, DigestAlgorithm.Sha512).map { algorithm ->
            scenario.certId(algorithm)
        }
        val request = ocsp.request(ids)
        request.nonce?.size shouldBe Ocsp.DEFAULT_NONCE_SIZE
        val decoded = checkNotNull(ocsp.decodeRequest(request.encoded).getOrNull())
        decoded shouldBe request
        decoded.certIds shouldBe ids
        decoded.nonce shouldBe request.nonce
        val largest = ocsp.request(ids, Ocsp.MAXIMUM_NONCE_SIZE)
        ocsp.decodeRequest(largest.encoded).getOrNull()?.nonce shouldBe largest.nonce
        val plain = ocsp.request(ids, nonceBytes = null)
        plain.nonce shouldBe null
        ocsp.decodeRequest(plain.encoded).getOrNull()?.nonce shouldBe null
        ocsp.request(ids) shouldNotBe request
    }

    test("requests outside their bounds are not built") {
        val ids = listOf(ID)
        shouldThrow<IllegalArgumentException> { ocsp.request(ids, SHORT_NONCE) }
        shouldThrow<IllegalArgumentException> { ocsp.request(ids, OVERSIZED_NONCE) }
        shouldThrow<IllegalArgumentException> { ocsp.request(emptyList()) }
        shouldThrow<IllegalArgumentException> { Ocsp(crypto, OcspLimits(maximumEntries = 1)).request(ids + ids) }
    }

    test("lenient parts of a request are read and skipped") {
        val accepted = listOf(
            request(prefix = { explicit(1) { ia5String("ops", Tag.context(number = 1, isConstructed = false)) } }),
            request(outer = { explicit(0) { sequence { nullValue() } } }),
            request(
                list = {
                    sequence {
                        sequence {
                            writeCertId(
                                ID,
                            )
                            explicit(0) { sequence { sequence(nonce(ByteString(1))) } }
                        }
                    }
                },
            ),
            request(
                suffix = extensions({
                    objectIdentifier(OTHER)
                    octetString(ByteString())
                }, nonce(ByteString(1))),
            ),
            request(
                list = certIdList {
                    sequence {
                        objectIdentifier(
                            OcspOids.DIGESTS.getValue(DigestAlgorithm.Sha256),
                        )
                    }
                    octetString(filled(SHA256_BYTES))
                    octetString(filled(SHA256_BYTES))
                    integer(1L)
                },
            ),
        )
        accepted.forEach { encoded -> ocsp.decodeRequest(encoded).getOrNull()?.certIds shouldBe listOf(ID) }
        ocsp.decodeRequest(accepted[NONCED]).getOrNull()?.nonce shouldBe ByteString(1)
    }

    test("hostile requests are refused") {
        val refused = listOf(
            request(prefix = { explicit(0) { integer(0L) } }),
            request(list = { sequence { } }),
            request(
                suffix = extensions({
                    objectIdentifier(OTHER)
                    boolean(true)
                    octetString(ByteString())
                }),
            ),
            request(
                suffix = extensions({
                    objectIdentifier(OTHER)
                    boolean(false)
                    octetString(ByteString())
                }),
            ),
            request(suffix = extensions(nonce(ByteString()))),
            request(suffix = extensions(nonce(filled(OVERSIZED_NONCE)))),
            request(
                suffix = extensions({
                    objectIdentifier(OcspOids.NONCE)
                    octetString(ByteString(1))
                }),
            ),
            request(suffix = extensions(nonce(ByteString(1)), nonce(ByteString(2)))),
            request(suffix = { explicit(2) { sequence { } } }),
            request(
                list = certIdList {
                    sequence {
                        objectIdentifier(
                            OTHER,
                        )
                    }
                    octetString(filled(SHA256_BYTES))
                    octetString(filled(SHA256_BYTES))
                    integer(1L)
                },
            ),
            request(
                list = certIdList {
                    sequence {
                        objectIdentifier(
                            OcspOids.DIGESTS.getValue(DigestAlgorithm.Sha256),
                        )
                    }
                    octetString(filled(1))
                    octetString(filled(SHA256_BYTES))
                    integer(1L)
                },
            ),
            request(
                list = certIdList {
                    sequence {
                        objectIdentifier(
                            OcspOids.DIGESTS.getValue(DigestAlgorithm.Sha256),
                        )
                        integer(0L)
                    }
                    octetString(filled(SHA256_BYTES))
                    octetString(filled(SHA256_BYTES))
                    integer(1L)
                },
            ),
            request(
                list = certIdList {
                    sequence { objectIdentifier(OcspOids.DIGESTS.getValue(DigestAlgorithm.Sha256)) }
                    octetString(filled(SHA256_BYTES))
                    octetString(filled(1))
                    integer(1L)
                },
            ),
            request(outer = { nullValue() }),
            ByteString(),
        )
        refused.forEach { encoded -> ocsp.decodeRequest(encoded).failureOrNull() shouldBe OcspFailure.Malformed }
        val valid = request()
        val truncated = valid.substring(startIndex = 0, endIndex = valid.size - 1)
        ocsp.decodeRequest(truncated).failureOrNull() shouldBe OcspFailure.Malformed
        val small = Ocsp(crypto, OcspLimits(maximumBytes = SMALL_BYTES))
        small.decodeRequest(valid).getOrNull() shouldBe null
        val single = Ocsp(crypto, OcspLimits(maximumEntries = 1))
        val pair = request(list = {
            sequence {
                sequence { writeCertId(ID) }
                sequence { writeCertId(ID) }
            }
        })
        single.decodeRequest(pair).failureOrNull() shouldBe OcspFailure.Malformed
        single.decodeRequest(valid).getOrNull()?.certIds shouldBe listOf(ID)
    }
})
