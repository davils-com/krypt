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

package com.davils.krypt.ocsp

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.ocsp.fixture.NOW
import com.davils.krypt.ocsp.fixture.SHA256_BYTES
import com.davils.krypt.ocsp.fixture.Scenario
import com.davils.krypt.ocsp.fixture.crypto
import com.davils.krypt.ocsp.fixture.der
import com.davils.krypt.ocsp.fixture.filled
import com.davils.krypt.ocsp.fixture.ocsp
import com.davils.krypt.ocsp.internal.CertIdCodec.writeCertId
import com.davils.krypt.ocsp.internal.OcspOids
import com.davils.krypt.x509.AlgorithmIdentifiers
import com.davils.krypt.x509.RevocationReason
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private const val KEY_HASH_BYTES: Int = 20
private const val UNUSED_REASON: Long = 7L
private const val TOO_LARGE_REASON: Long = 11L
private const val UNKNOWN_STATUS: Long = 4L
private const val TOO_LARGE_STATUS: Long = 7L
private const val OVERSIZED_NONCE: Int = 129
private const val SUPERSEDED: Long = 4L
private val OTHER: ObjectIdentifier = ObjectIdentifier.of("1.2.3.4")
private val ID: CertId = CertId(
    hashAlgorithm = DigestAlgorithm.Sha256,
    issuerNameHash = filled(SHA256_BYTES),
    issuerKeyHash = filled(SHA256_BYTES),
    serialNumber = DerInteger.of(1L),
)
private val NAME: DerWriter.() -> Unit = { explicit(1) { sequence { } } }
private val GOOD: DerWriter.() -> Unit = { element(Tag.context(number = 0, isConstructed = false), ByteString()) }

private fun single(
    status: DerWriter.() -> Unit = GOOD,
    thisUpdate: Instant = NOW,
    tail: DerWriter.() -> Unit = {},
): DerWriter.() -> Unit = {
    sequence {
        writeCertId(ID)
        status()
        generalizedTime(thisUpdate)
        tail()
    }
}

private fun data(
    responder: DerWriter.() -> Unit = NAME,
    responses: DerWriter.() -> Unit = { sequence(single()) },
    tail: DerWriter.() -> Unit = {},
): DerWriter.() -> Unit = {
    responder()
    generalizedTime(NOW)
    responses()
    tail()
}

private fun basic(
    data: DerWriter.() -> Unit = data(),
    algorithm: ByteString = AlgorithmIdentifiers.encode(SignatureAlgorithm.EcdsaSha256),
    unusedBits: Int = 0,
    tail: DerWriter.() -> Unit = {},
): ByteString = der {
    sequence {
        sequence(data)
        raw(algorithm)
        bitString(BitString(ByteString(2), unusedBits))
        tail()
    }
}

private fun response(
    basic: ByteString? = basic(),
    status: Long = 0L,
    type: ObjectIdentifier = OcspOids.BASIC,
): ByteString = der {
    sequence {
        integer(status, Tag.Enumerated)
        basic?.let { bytes ->
            explicit(0) {
                sequence {
                    objectIdentifier(type)
                    octetString(bytes)
                }
            }
        }
    }
}

private fun extensions(number: Int, vararg entries: DerWriter.() -> Unit): DerWriter.() -> Unit = {
    explicit(number) { sequence { entries.forEach { entry -> sequence(entry) } } }
}

private fun nonce(value: ByteString): DerWriter.() -> Unit = {
    objectIdentifier(OcspOids.NONCE)
    octetString(der { octetString(value) })
}

private val CRITICAL: DerWriter.() -> Unit = {
    objectIdentifier(OTHER)
    boolean(true)
    octetString(ByteString())
}

private fun revoked(reason: Long?): DerWriter.() -> Unit = {
    constructed(Tag.context(number = 1, isConstructed = true)) {
        generalizedTime(NOW)
        reason?.let { code -> explicit(0) { integer(code, Tag.Enumerated) } }
    }
}

private fun answering(entry: DerWriter.() -> Unit): ByteString = response(basic(data(responses = { sequence(entry) })))

private fun empty(number: Int): DerWriter.() -> Unit = {
    element(Tag.context(number = number, isConstructed = false), ByteString())
}

private fun read(encoded: ByteString, limits: OcspLimits = OcspLimits.Default): OcspResponse? {
    val outcome = Ocsp(crypto, limits).decodeResponse(encoded)
    return outcome.getOrNull()
}

private fun failureOf(encoded: ByteString, limits: OcspLimits = OcspLimits.Default): OcspFailure? {
    val outcome = Ocsp(crypto, limits).decodeResponse(encoded)
    return outcome.failureOrNull()
}

private fun answerOf(encoded: ByteString): SingleResponse? = read(encoded)?.basic?.run { responses.single() }

class HostileResponseTest : FunSpec({
    test("crafted but well formed responses are read") {
        val byKey = checkNotNull(
            read(response(basic(data(responder = { explicit(2) { octetString(filled(KEY_HASH_BYTES)) } })))),
        )
        byKey.basic?.responderId shouldBe ResponderId.ByKey(filled(KEY_HASH_BYTES))
        byKey.basic?.signatureAlgorithm shouldBe SignatureAlgorithm.EcdsaSha256
        answerOf(answering(single(status = revoked(null))))?.status shouldBe CertificateStatus.Revoked(NOW)
        val superseded = CertificateStatus.Revoked(NOW, RevocationReason.Superseded)
        answerOf(answering(single(status = revoked(SUPERSEDED))))?.status shouldBe superseded
        answerOf(answering(single(status = empty(2))))?.status shouldBe CertificateStatus.Unknown
        val harmless: DerWriter.() -> Unit = {
            objectIdentifier(OTHER)
            octetString(ByteString())
        }
        val noted = single(tail = extensions(1, harmless))
        answerOf(answering(noted))?.run { extensions.size } shouldBe 1
        val unknownAlgorithm = der { sequence { objectIdentifier(OTHER) } }
        val strange = checkNotNull(read(response(basic(algorithm = unknownAlgorithm))))
        strange.basic?.signatureAlgorithm shouldBe null
        val scenario = Scenario.create()
        val outcome = ocsp.verify(strange, scenario.leaf, scenario.issuer)
        outcome.failureOrNull() shouldBe OcspFailure.AlgorithmNotPermitted
    }

    test("responses that break their structure are refused") {
        val refused = listOf(
            response(status = UNKNOWN_STATUS, basic = null),
            response(status = TOO_LARGE_STATUS, basic = null),
            response(basic = null),
            response(status = 1L),
            response(type = OTHER),
            response(basic = ByteString(1, 2)),
            response(basic(unusedBits = 1)),
            response(basic(tail = { explicit(0) { sequence { sequence { } } } })),
            response(
                basic(data = {
                    explicit(0) { integer(0L) }
                    data()()
                }),
            ),
            response(basic(data(responder = { explicit(2) { octetString(filled(KEY_HASH_BYTES - 1)) } }))),
            response(basic(data(responder = { explicit(3) { sequence { } } }))),
            response(basic(data(responses = { sequence { } }))),
            response(basic(data(tail = { nullValue() }))),
            answering(single(status = empty(3))),
            answering(single(status = { element(Tag.context(number = 0, isConstructed = false), ByteString(0)) })),
            answering(single(status = revoked(UNUSED_REASON))),
            answering(single(status = revoked(TOO_LARGE_REASON))),
            answering(single(tail = { explicit(0) { generalizedTime(NOW - 1.days) } })),
            answering(single(tail = extensions(1, CRITICAL))),
            response(basic(data(tail = extensions(1, CRITICAL)))),
            response(basic(data(tail = extensions(1, nonce(ByteString()))))),
            response(basic(data(tail = extensions(1, nonce(filled(OVERSIZED_NONCE)))))),
            response(basic(data(tail = extensions(1)))),
        )
        refused.forEachIndexed { index, encoded ->
            Pair(
                index,
                failureOf(encoded),
            ) shouldBe Pair(index, OcspFailure.Malformed)
        }
    }

    test("certificates and entries in responses obey the limits") {
        val scenario = Scenario.create()
        val two = scenario.authority.issue("two").certificate
        val both = ocsp.request(listOf(scenario.certId(), ocsp.certId(two, scenario.issuer)))
        val encoded = scenario.authority.responder().respond(both)
        failureOf(encoded, OcspLimits(maximumEntries = 1)) shouldBe OcspFailure.Malformed
        val delegate = scenario.authority.delegate()
        val delegated = scenario.authority.responder(signer = delegate.signer, certificate = delegate.certificate)
        val withCertificate = delegated.respond(scenario.request())
        failureOf(withCertificate, OcspLimits(maximumBytes = withCertificate.size - 1)) shouldBe OcspFailure.Malformed
        val truncated = withCertificate.substring(startIndex = 0, endIndex = withCertificate.size - 1)
        failureOf(truncated) shouldBe OcspFailure.Malformed
        val badCertificate = response(basic(tail = { explicit(0) { sequence { sequence { integer(1L) } } } }))
        failureOf(badCertificate) shouldBe OcspFailure.Malformed
        val certificate = delegate.certificate.encoded
        val twoCertificates = response(
            basic(tail = {
                explicit(0) {
                    sequence {
                        raw(certificate)
                        raw(certificate)
                    }
                }
            }),
        )
        failureOf(twoCertificates, OcspLimits(maximumCertificates = 1)) shouldBe OcspFailure.Malformed
        read(twoCertificates)?.basic?.run { certificates.size } shouldBe 2
    }
})
