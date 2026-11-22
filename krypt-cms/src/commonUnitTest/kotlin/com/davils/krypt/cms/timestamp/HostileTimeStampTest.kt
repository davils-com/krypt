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
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.Identity
import com.davils.krypt.cms.fixture.NOW
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.truncated
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.internal.CmsOids
import com.davils.krypt.cms.signed.SignatureParameters
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private val POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.20")
private val UNKNOWN: ObjectIdentifier = ObjectIdentifier.of("1.2.3.4")
private const val MILLIS: Int = 0
private const val MICROS: Int = 1
private const val PART_LIMIT: Long = 1_000
private const val UNKNOWN_STATUS: Long = 6
private const val HASH_BYTES: Int = 32
private const val EXTENDED_MILLIS: Int = 2
private const val EXTENDED_MICROS: Int = 3
private const val EXTENDED_NONCE: Long = 7
private const val DIRECTORY_NAME: Int = 4

private val timeStamps: TimeStamps = TimeStamps(crypto)

private fun DerWriter.imprint(
    digest: ObjectIdentifier = CmsOids.SHA256,
    hash: ByteString = ByteString(
        ByteArray(HASH_BYTES),
    ),
) {
    sequence {
        sequence { objectIdentifier(digest) }
        octetString(hash)
    }
}

private fun tstInfo(
    version: Long = 1,
    digest: ObjectIdentifier = CmsOids.SHA256,
    hash: ByteString = ByteString(ByteArray(HASH_BYTES)),
    tail: DerWriter.() -> Unit = {},
): ByteString = der {
    sequence {
        integer(version)
        objectIdentifier(POLICY)
        imprint(digest, hash)
        integer(1)
        generalizedTime(NOW)
        tail()
    }
}

private suspend fun token(identity: Identity, info: ByteString, isDetached: Boolean = false): ByteString {
    val signed = cms.sign(info) {
        contentType = ContentTypes.TstInfo
        this.isDetached = isDetached
        signer(identity.signer, identity.certificate)
    }
    return signed.encoded
}

private fun response(status: Long, token: ByteString? = null, tail: DerWriter.() -> Unit = {}): ByteString = der {
    sequence {
        sequence {
            integer(status)
            tail()
        }
        token?.let { found -> raw(found) }
    }
}

class HostileTimeStampTest : FunSpec({
    test("requests are strict") {
        val valid = der {
            sequence {
                integer(1)
                imprint()
            }
        }
        timeStamps.decodeRequest(valid).value().isCertificateRequested shouldBe false
        val falseRequest = der {
            sequence {
                integer(1)
                imprint()
                boolean(false)
            }
        }
        val wrongVersion = der {
            sequence {
                integer(2)
                imprint()
            }
        }
        val shortHash = der {
            sequence {
                integer(1)
                imprint(hash = ByteString(1))
            }
        }
        listOf(falseRequest, wrongVersion, shortHash, truncated(valid), ByteString()).forEach { encoded ->
            timeStamps.decodeRequest(encoded).failureOrNull() shouldBe CmsFailure.Malformed
        }
        val strange = der {
            sequence {
                integer(1)
                imprint(digest = UNKNOWN, hash = ByteString(1))
            }
        }
        val decoded = timeStamps.decodeRequest(strange).value()
        decoded.toString() shouldContain "TimeStampRequest(,"
        shouldThrow<IllegalArgumentException> { timeStamps.request(CONTENT, digest = DigestAlgorithm.Sha3256) }
    }

    test("responses are strict") {
        val pki = Pki.create()
        val tsa = pki.authority()
        val good = token(tsa, tstInfo(hash = crypto.digests.digest(CONTENT)))
        val goodResponse = timeStamps.decodeResponse(response(0, good)).value()
        checkNotNull(goodResponse.token).info.policy shouldBe POLICY
        timeStamps.decodeResponse(response(UNKNOWN_STATUS)).failureOrNull() shouldBe CmsFailure.Malformed
        timeStamps.decodeResponse(response(0, der { sequence { } })).failureOrNull() shouldBe CmsFailure.Malformed
        val withText = response(2) {
            sequence { utf8String("no") }
            bitString(BitString.ofNamedBits(setOf(2)))
        }
        timeStamps.decodeResponse(withText).value().failures shouldBe setOf(2)
        val granted = timeStamps.decodeResponse(response(0)).value()
        val request = timeStamps.request(CONTENT)
        timeStamps.verify(granted, request).failureOrNull() shouldBe CmsFailure.TimeStampRejected
        val waiting = timeStamps.decodeResponse(response(3, good)).value()
        waiting.token shouldBe timeStamps.decodeToken(good).value()
        timeStamps.verify(waiting, request).failureOrNull() shouldBe CmsFailure.TimeStampRejected
    }

    test("tokens are strict") {
        val pki = Pki.create()
        val tsa = pki.authority()
        val other = pki.issue(KeyType.P256, "other")
        val twoSigners = cms.sign(tstInfo()) {
            contentType = ContentTypes.TstInfo
            signer(tsa.signer, tsa.certificate)
            signer(other.signer, other.certificate)
        }
        val two = twoSigners.encoded
        val typedData = cms.sign(tstInfo()) { signer(tsa.signer, tsa.certificate) }
        val typed = typedData.encoded
        val malformed = listOf(
            two,
            typed,
            token(tsa, tstInfo(), isDetached = true),
            token(tsa, tstInfo(version = 2)),
            token(tsa, tstInfo(hash = ByteString(1))),
            token(tsa, tstInfo { boolean(false) }),
            token(tsa, tstInfo { sequence { } }),
            token(
                tsa,
                tstInfo { sequence { integer(PART_LIMIT, Tag.context(number = MILLIS, isConstructed = false)) } },
            ),
            token(tsa, tstInfo { sequence { integer(0, Tag.context(number = MICROS, isConstructed = false)) } }),
            token(
                tsa,
                tstInfo { sequence { element(Tag.context(number = MILLIS, isConstructed = false), ByteString(0, 5)) } },
            ),
            token(
                tsa,
                tstInfo {
                    sequence {
                        element(
                            Tag.context(number = MILLIS, isConstructed = false),
                            ByteString(ByteArray(9) { 1 }),
                        )
                    }
                },
            ),
            der { nullValue() },
        )
        malformed.forEach { encoded -> timeStamps.decodeToken(encoded).failureOrNull() shouldBe CmsFailure.Malformed }
        val extendedInfo = tstInfo {
            sequence {
                integer(EXTENDED_MILLIS.toLong(), Tag.context(number = MILLIS, isConstructed = false))
                integer(EXTENDED_MICROS.toLong(), Tag.context(number = MICROS, isConstructed = false))
            }
            integer(EXTENDED_NONCE)
            explicit(0) { constructed(Tag.context(number = DIRECTORY_NAME, isConstructed = true)) { sequence { } } }
            constructed(Tag.context(number = 1, isConstructed = true)) { sequence { objectIdentifier(UNKNOWN) } }
        }
        val extended = timeStamps.decodeToken(token(tsa, extendedInfo)).value()
        extended.info.accuracy shouldBe Accuracy(millis = EXTENDED_MILLIS, micros = EXTENDED_MICROS)
        extended.info.nonce?.toLongOrNull() shouldBe EXTENDED_NONCE
        val unknown = timeStamps.decodeToken(token(tsa, tstInfo(digest = UNKNOWN, hash = ByteString(1)))).value()
        unknown.info.digest shouldBe null
        timeStamps.verifyToken(unknown, CONTENT).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val otherDigest = timeStamps.decodeToken(token(tsa, tstInfo(hash = crypto.digests.digest(CONTENT)))).value()
        val request = timeStamps.request(
            data = CONTENT,
            digest = DigestAlgorithm.Sha512,
            nonceBytes = null,
            isCertificateRequested = false,
        )
        val response = timeStamps.decodeResponse(response(0, otherDigest.encoded)).value()
        val mismatch = timeStamps.verify(response, request, SignatureParameters())
        mismatch.failureOrNull() shouldBe CmsFailure.TimeStampMismatch
        val unsigned = cms.sign(tstInfo(hash = crypto.digests.digest(CONTENT))) {
            contentType = ContentTypes.TstInfo
            signer(tsa.signer, tsa.certificate) { isSignedAttributesUsed = false }
        }
        val unsignedToken = timeStamps.decodeToken(unsigned.encoded).value()
        timeStamps.verifyToken(unsignedToken, CONTENT).failureOrNull() shouldBe CmsFailure.AttributeMismatch
    }

    test("an authority writes sub-second accuracies") {
        val pki = Pki.create()
        val tsa = pki.authority()
        val authority = TimeStampAuthority(
            crypto = crypto,
            signer = tsa.signer,
            certificate = tsa.certificate,
            policy = POLICY,
            accuracy = Accuracy(millis = 5, micros = 7),
        )
        val request = timeStamps.request(CONTENT)
        val token = checkNotNull(timeStamps.decodeResponse(authority.respond(request)).value().token)
        token.info.accuracy shouldBe Accuracy(millis = 5, micros = 7)
    }
})
