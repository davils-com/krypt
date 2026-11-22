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

package com.davils.krypt.cose

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborSimple
import com.davils.krypt.cose.cbor.CborTag
import com.davils.krypt.cose.cbor.CborText
import com.davils.krypt.cose.fixture.CONTENT
import com.davils.krypt.cose.fixture.NOW
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days

private const val PRIVATE_LABEL: Long = -65_537
private val SIGNATURES: Set<CoseAlgorithm> = setOf(CoseAlgorithm.Esp256)

private fun label(value: Long): CborItem = CborInteger.of(value)

private suspend fun certificate(): Certificate {
    val pair = crypto.keys.generate(KeyType.P256)
    return Certificates(crypto).issue(crypto.signatures.signer(pair.privateKey)) {
        subject { commonName("cose") }
        publicKey = pair.publicKey
        notBefore = NOW - 1.days
        notAfter = NOW + 1.days
    }
}

private suspend fun signed(
    protectedHeaders: CoseHeaders,
    unprotectedHeaders: CoseHeaders = CoseHeaders.Empty,
): Pair<CoseSign1, CoseKey> {
    val pair = crypto.keys.generate(KeyType.P256)
    val signer = CoseSigner(
        key = CoseKey.of(pair.privateKey),
        algorithm = CoseAlgorithm.Esp256,
        protectedHeaders = protectedHeaders,
        unprotectedHeaders = unprotectedHeaders,
    )
    return cose.sign1(payload = utf8(CONTENT), signer = signer) to CoseKey.of(pair.publicKey)
}

private fun sign1(protectedHeaders: CborMap, unprotectedHeaders: CborMap): ByteString {
    val encoded = Cbor.encode(protectedHeaders).takeUnless { protectedHeaders.size == 0 } ?: ByteString()
    val array = CborArray.of(CborBytes(encoded), unprotectedHeaders, CborBytes(utf8(CONTENT)), CborBytes(ByteString()))
    return Cbor.encode(CborTag(number = CoseMessageType.Sign1.tag, content = array))
}

class HeadersTest : FunSpec({
    test("the common parameters are typed and checked") {
        val hash = CoseCertificateHash(algorithm = label(value = -16), value = utf8("hash"))
        val headers = CoseHeaders.of(
            keyId = utf8("kid"),
            contentType = CborText("text/plain"),
            certificateHash = hash,
            critical = listOf(label(PRIVATE_LABEL)),
            parameters = CborMap.of(
                label(PRIVATE_LABEL) to CborSimple.True,
                label(value = 5) to CborBytes(utf8("iv")),
                label(value = 1) to label(value = -9),
            ),
        )
        headers.keyId shouldBe utf8("kid")
        headers.contentType shouldBe CborText("text/plain")
        headers.certificateHash shouldBe hash
        headers.critical shouldBe listOf(label(PRIVATE_LABEL))
        headers.iv shouldBe utf8("iv")
        headers.partialIv shouldBe null
        headers.algorithm shouldBe CoseAlgorithm.Esp256
        headers[PRIVATE_LABEL] shouldBe CborSimple.True
        headers[label(PRIVATE_LABEL)] shouldBe CborSimple.True
        headers.isEmpty shouldBe false
        headers.certificateChain shouldBe emptyList()
        CoseHeaders.Empty.isEmpty shouldBe true
        CoseHeaders.Empty.algorithm shouldBe null
        CoseHeaders.Empty.certificateHash shouldBe null
        headers shouldBe CoseHeaders.of(headers.parameters)
        headers shouldNotBe CoseHeaders.Empty
        headers.hashCode() shouldBe headers.parameters.hashCode()
        headers.equals(CONTENT) shouldBe false
        headers.toString() shouldContain "CoseHeaders"
        CoseHeaders.of(parameters = CborMap.of(label(value = 1) to CborText("x"))).algorithm shouldBe null
        CoseHeaders.of(parameters = CborMap.of(label(value = 1) to label(value = 9_999))).algorithm shouldBe null
        val wrong = listOf(
            CborMap.of(CborSimple.True to label(value = 1)),
            CborMap.of(label(value = 1) to CborSimple.True),
            CborMap.of(label(value = 2) to CborArray.of()),
            CborMap.of(label(value = 2) to CborArray.of(CborSimple.True)),
            CborMap.of(label(value = 2) to CborSimple.True),
            CborMap.of(label(value = 3) to label(value = -1)),
            CborMap.of(label(value = 3) to CborSimple.True),
            CborMap.of(label(value = 4) to CborText("kid")),
            CborMap.of(label(value = 5) to CborBytes(utf8("iv")), label(value = 6) to CborBytes(utf8("p"))),
            CborMap.of(label(value = 33) to CborArray.of()),
            CborMap.of(label(value = 33) to CborArray.of(CborSimple.True)),
            CborMap.of(label(value = 33) to CborSimple.True),
            CborMap.of(label(value = 34) to CborArray.of(label(value = -16))),
            CborMap.of(label(value = 34) to CborArray.of(CborSimple.True, CborBytes(utf8("hash")))),
            CborMap.of(label(value = 34) to CborArray.of(label(value = -16), CborSimple.True)),
            CborMap.of(label(value = 34) to CborSimple.True),
            CborMap.of(label(value = -1) to CborSimple.True),
            CborMap.of(label(value = -20) to CborSimple.True),
            CborMap.of(label(value = -21) to CborSimple.True),
            CborMap.of(label(value = -22) to CborSimple.True),
            CborMap.of(CborInteger.unsigned(ULong.MAX_VALUE) to CborSimple.True),
        )
        wrong.forEach { parameters -> shouldThrow<IllegalArgumentException> { CoseHeaders.of(parameters) } }
        val right = CborMap.of(
            label(value = -21) to CborSimple.Null,
            label(value = -22) to label(value = 7),
            label(value = -23) to CborBytes(utf8("other")),
            label(value = 3) to label(value = 0),
            CborText("private") to CborSimple.True,
        )
        CoseHeaders.of(right).parameters shouldBe right
    }

    test("certificates travel in x5chain and are named by x5t") {
        val first = certificate()
        val second = certificate()
        val single = CoseHeaders.of(certificateChain = listOf(first))
        single.certificateChain shouldBe listOf(first.encoded)
        cose.certificateChain(single).value() shouldBe listOf(first)
        val chain = CoseHeaders.of(certificateChain = listOf(first, second))
        cose.certificateChain(chain).value() shouldBe listOf(first, second)
        val broken = CoseHeaders.of(parameters = CborMap.of(label(value = 33) to CborBytes(utf8("broken"))))
        cose.certificateChain(broken).failure() shouldBe CoseFailure.Malformed
        val hash = cose.certificateHash(first)
        hash.digest shouldBe DigestAlgorithm.Sha256
        cose.matches(hash, first) shouldBe true
        cose.matches(hash, second) shouldBe false
        cose.matches(cose.certificateHash(first, DigestAlgorithm.Sha384), first) shouldBe true
        cose.matches(cose.certificateHash(first, DigestAlgorithm.Sha512), first) shouldBe true
        val unknown = CoseCertificateHash(algorithm = label(value = -15), value = hash.value)
        unknown.digest shouldBe null
        cose.matches(unknown, first) shouldBe false
        CoseCertificateHash(algorithm = CborText("sha"), value = hash.value).digest shouldBe null
        shouldThrow<IllegalArgumentException> { CoseCertificateHash.idOf(DigestAlgorithm.Sha3256) }
        hash shouldNotBe unknown
        hash shouldNotBe CoseCertificateHash(algorithm = hash.algorithm, value = utf8("other"))
        hash.equals(CONTENT) shouldBe false
        hash.hashCode() shouldBe CoseCertificateHash(hash.algorithm, hash.value).hashCode()
        hash.toString() shouldContain "CoseCertificateHash(-16, "
        val (message, key) = signed(protectedHeaders = chain)
        val decoded = cose.decodeSign1(message.encode()).value()
        cose.certificateChain(decoded.protectedHeaders).value() shouldBe listOf(first, second)
        cose.verify(message = decoded, keys = listOf(key), algorithms = SIGNATURES).value() shouldBe utf8(CONTENT)
        val bounded = Cose(crypto = crypto, limits = CoseLimits(maximumCertificates = 1))
        bounded.decodeSign1(message.encode()).failure() shouldBe CoseFailure.Malformed
    }

    test("crit names labels that are protected and understood") {
        val known = CoseHeaders.of(critical = listOf(label(value = 4)), keyId = utf8("kid"))
        val (message, key) = signed(protectedHeaders = known)
        cose.verify(message = message, keys = listOf(key), algorithms = SIGNATURES).value() shouldBe utf8(CONTENT)
        val private = CoseHeaders.of(
            critical = listOf(label(PRIVATE_LABEL)),
            parameters = CborMap.of(label(PRIVATE_LABEL) to CborSimple.True),
        )
        val (privateMessage, privateKey) = signed(protectedHeaders = private)
        val outcome1 = cose.verify(
            message = privateMessage,
            keys = listOf(privateKey),
            algorithms = SIGNATURES,
        )
        outcome1.failure() shouldBe CoseFailure.UnknownCritical
        val understanding = Cose(crypto = crypto, criticalLabels = setOf(label(PRIVATE_LABEL)))
        val outcome2 = understanding.verify(
            message = privateMessage,
            keys = listOf(privateKey),
            algorithms = SIGNATURES,
        )
        outcome2.value() shouldBe utf8(CONTENT)
        understanding.toString() shouldContain "criticalLabels"
        val absent = CoseHeaders.of(critical = listOf(label(PRIVATE_LABEL)))
        val (absentMessage, absentKey) = signed(protectedHeaders = absent)
        val outcome3 = cose.verify(
            message = absentMessage,
            keys = listOf(absentKey),
            algorithms = SIGNATURES,
        )
        outcome3.failure() shouldBe CoseFailure.Malformed
        shouldThrow<IllegalArgumentException> {
            signed(
                protectedHeaders = CoseHeaders.Empty,
                unprotectedHeaders = known,
            )
        }
        shouldThrow<IllegalArgumentException> {
            signed(
                protectedHeaders = CoseHeaders.of(keyId = utf8("a")),
                unprotectedHeaders = CoseHeaders.of(keyId = utf8("b")),
            )
        }
        shouldThrow<IllegalArgumentException> {
            signed(protectedHeaders = CoseHeaders.of(parameters = CborMap.of(label(value = 1) to label(value = -7))))
        }
    }

    test("decoded headers must not repeat a label or leave crit unprotected") {
        val algorithm = CborMap.of(label(value = 1) to label(value = -9))
        val outcome4 = cose.decodeSign1(
            sign1(protectedHeaders = algorithm, unprotectedHeaders = algorithm),
        )
        outcome4.failure() shouldBe CoseFailure.Malformed
        val crit = CborMap.of(label(value = 2) to CborArray.of(label(value = 1)))
        val outcome5 = cose.decodeSign1(
            sign1(protectedHeaders = algorithm, unprotectedHeaders = crit),
        )
        outcome5.failure() shouldBe CoseFailure.Malformed
        val badType = CborMap.of(label(value = 4) to CborText("kid"))
        val outcome6 = cose.decodeSign1(
            sign1(protectedHeaders = algorithm, unprotectedHeaders = badType),
        )
        outcome6.failure() shouldBe CoseFailure.Malformed
        val outcome7 = cose.decodeSign1(
            sign1(protectedHeaders = badType, unprotectedHeaders = CborMap.Empty),
        )
        outcome7.failure() shouldBe CoseFailure.Malformed
        val outcome8 = cose.decodeSign1(
            sign1(protectedHeaders = CborMap.Empty, unprotectedHeaders = CborMap.Empty),
        )
        val missing = outcome8.value()
        val outcome9 = cose.verify(
            message = missing,
            keys = emptyList(),
            algorithms = SIGNATURES,
        )
        outcome9.failure() shouldBe CoseFailure.AlgorithmNotPermitted
    }
})
