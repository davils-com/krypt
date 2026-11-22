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

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborText
import com.davils.krypt.cose.fixture.CONTENT
import com.davils.krypt.cose.fixture.ECDSA_SIG_01
import com.davils.krypt.cose.fixture.ECDSA_SIG_01_KEY_0
import com.davils.krypt.cose.fixture.ECDSA_SIG_02
import com.davils.krypt.cose.fixture.ECDSA_SIG_02_KEY_0
import com.davils.krypt.cose.fixture.ECDSA_SIG_03
import com.davils.krypt.cose.fixture.ECDSA_SIG_03_KEY_0
import com.davils.krypt.cose.fixture.EDDSA_01
import com.davils.krypt.cose.fixture.EDDSA_01_KEY_0
import com.davils.krypt.cose.fixture.EDDSA_SIG_01
import com.davils.krypt.cose.fixture.EDDSA_SIG_01_KEY_0
import com.davils.krypt.cose.fixture.EDDSA_SIG_02
import com.davils.krypt.cose.fixture.EDDSA_SIG_02_KEY_0
import com.davils.krypt.cose.fixture.RFC_C_1_1
import com.davils.krypt.cose.fixture.RFC_C_1_1_KEY_0
import com.davils.krypt.cose.fixture.RFC_C_1_2
import com.davils.krypt.cose.fixture.RFC_C_1_2_KEY_0
import com.davils.krypt.cose.fixture.RFC_C_1_2_KEY_1
import com.davils.krypt.cose.fixture.RFC_C_2_1
import com.davils.krypt.cose.fixture.RSA_PSS_01
import com.davils.krypt.cose.fixture.RSA_PSS_01_KEY_0
import com.davils.krypt.cose.fixture.SIGN1_FAIL_01
import com.davils.krypt.cose.fixture.SIGN1_FAIL_02
import com.davils.krypt.cose.fixture.SIGN1_FAIL_03
import com.davils.krypt.cose.fixture.SIGN1_FAIL_04
import com.davils.krypt.cose.fixture.SIGN1_FAIL_06
import com.davils.krypt.cose.fixture.SIGN1_FAIL_07
import com.davils.krypt.cose.fixture.SIGN1_PASS_01_KEY_0
import com.davils.krypt.cose.fixture.SIGN1_PASS_02
import com.davils.krypt.cose.fixture.SIGN1_PASS_02_AAD
import com.davils.krypt.cose.fixture.SIGN1_PASS_03
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.hexOf
import com.davils.krypt.cose.fixture.key
import com.davils.krypt.cose.fixture.relaxed
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private val ALL_SIGNATURES: Set<CoseAlgorithm> =
    CoseAlgorithm.entries.filter { algorithm -> algorithm.kind == CoseAlgorithmKind.Signature }.toSet()

private suspend fun verifiesSign1(encoded: String, keyHex: String, externalAad: ByteString = ByteString()) {
    val message = relaxed.decodeSign1(hex(encoded)).value()
    val payload = relaxed.verify(
        message = message,
        keys = listOf(key(keyHex)),
        algorithms = ALL_SIGNATURES,
        externalAad = externalAad,
    )
    payload.value() shouldBe utf8(CONTENT)
}

private suspend fun verifiesSign(encoded: String, keys: List<String>) {
    val message = relaxed.decodeSign(hex(encoded)).value()
    val outcome = relaxed.verify(
        message = message,
        keys = keys.map { found -> key(found) },
        algorithms = ALL_SIGNATURES,
    )
    message.signatures shouldContainOutcome outcome.value()
}

private infix fun List<CoseSignature>.shouldContainOutcome(signature: CoseSignature) {
    (signature in this) shouldBe true
}

private suspend fun failsSign1(encoded: String, failure: CoseFailure) {
    val message = relaxed.decodeSign1(hex(encoded)).value()
    val outcome1 = relaxed.verify(
        message = message,
        keys = listOf(key(SIGN1_PASS_01_KEY_0)),
        algorithms = ALL_SIGNATURES,
    )
    outcome1.failure() shouldBe failure
}

class SignTest : FunSpec({
    test("the Sign1 examples of the COSE working group verify") {
        verifiesSign1(encoded = SIGN1_PASS_02, keyHex = SIGN1_PASS_01_KEY_0, externalAad = hex(SIGN1_PASS_02_AAD))
        verifiesSign1(encoded = SIGN1_PASS_03, keyHex = SIGN1_PASS_01_KEY_0)
        verifiesSign1(encoded = ECDSA_SIG_01, keyHex = ECDSA_SIG_01_KEY_0)
        verifiesSign1(encoded = ECDSA_SIG_02, keyHex = ECDSA_SIG_02_KEY_0)
        verifiesSign1(encoded = ECDSA_SIG_03, keyHex = ECDSA_SIG_03_KEY_0)
        verifiesSign1(encoded = EDDSA_SIG_01, keyHex = EDDSA_SIG_01_KEY_0)
        verifiesSign1(encoded = RFC_C_2_1, keyHex = SIGN1_PASS_01_KEY_0)
    }

    test("Ed448 verifies where the platform has it") {
        val isSupported = crypto.capabilities.supports(KeyType.Ed448)
        if (isSupported) verifiesSign1(encoded = EDDSA_SIG_02, keyHex = EDDSA_SIG_02_KEY_0)
    }

    test("the Sign examples of RFC 9052 and the working group verify") {
        verifiesSign(encoded = RFC_C_1_1, keys = listOf(RFC_C_1_1_KEY_0))
        verifiesSign(encoded = RFC_C_1_2, keys = listOf(RFC_C_1_2_KEY_0, RFC_C_1_2_KEY_1))
        verifiesSign(encoded = RFC_C_1_2, keys = listOf(RFC_C_1_2_KEY_1))
        verifiesSign(encoded = RSA_PSS_01, keys = listOf(RSA_PSS_01_KEY_0))
        verifiesSign(encoded = EDDSA_01, keys = listOf(EDDSA_01_KEY_0))
    }

    test("EdDSA signs exactly as the known answer") {
        val signer = CoseSigner(
            key = key(EDDSA_SIG_01_KEY_0),
            algorithm = CoseAlgorithm.EdDsa,
            protectedHeaders = CoseHeaders.of(
                contentType = CborInteger
                    .of(0L),
            ),
        )
        val message = cose.sign1(payload = utf8(CONTENT), signer = signer)
        hexOf(message.encode()) shouldBe EDDSA_SIG_01
    }

    test("the failure examples of the working group are refused") {
        relaxed.decodeSign1(hex(SIGN1_FAIL_01)).failure() shouldBe CoseFailure.Malformed
        failsSign1(encoded = SIGN1_FAIL_02, failure = CoseFailure.InvalidSignature)
        failsSign1(encoded = SIGN1_FAIL_03, failure = CoseFailure.AlgorithmNotPermitted)
        failsSign1(encoded = SIGN1_FAIL_04, failure = CoseFailure.AlgorithmNotPermitted)
        failsSign1(encoded = SIGN1_FAIL_06, failure = CoseFailure.InvalidSignature)
        failsSign1(encoded = SIGN1_FAIL_07, failure = CoseFailure.InvalidSignature)
    }

    test("every signature algorithm signs and verifies tagged, untagged and detached") {
        val pairs = listOf(
            CoseAlgorithm.Es256 to KeyType.P256,
            CoseAlgorithm.Es384 to KeyType.P384,
            CoseAlgorithm.Es512 to KeyType.P521,
            CoseAlgorithm.Esp256 to KeyType.P256,
            CoseAlgorithm.Esp384 to KeyType.P384,
            CoseAlgorithm.Esp512 to KeyType.P521,
            CoseAlgorithm.EdDsa to KeyType.Ed25519,
            CoseAlgorithm.Ed25519 to KeyType.Ed25519,
            CoseAlgorithm.Ps256 to KeyType.Rsa3072,
            CoseAlgorithm.Ps384 to KeyType.Rsa3072,
            CoseAlgorithm.Ps512 to KeyType.Rsa3072,
        )
        pairs.forEach { (algorithm, type) -> roundTrip(algorithm = algorithm, type = type) }
        if (crypto.capabilities.supports(
                KeyType.Ed448,
            )
        ) {
            roundTrip(algorithm = CoseAlgorithm.Ed448, type = KeyType.Ed448)
        }
    }

    test("a COSE_Sign carries several signers and verifies with any of them") {
        val first = crypto.keys.generate(KeyType.P256)
        val second = crypto.keys.generate(KeyType.Ed25519)
        val signers = listOf(
            CoseSigner(key = CoseKey.of(first.privateKey, keyId = utf8("one")), algorithm = CoseAlgorithm.Esp256),
            CoseSigner(key = CoseKey.of(second.privateKey, keyId = utf8("two")), algorithm = CoseAlgorithm.Ed25519),
        )
        val message = cose.sign(
            payload = utf8(CONTENT),
            signers = signers,
            protectedHeaders = CoseHeaders.of(
                contentType = CborText("text/plain"),
            ),
            externalAad = utf8("aad"),
            isDetached = true,
        )
        val decoded = cose.decodeSign(message.encode(isTagged = false)).value()
        decoded shouldBe message
        val publicSecond = CoseKey.of(second.publicKey, keyId = utf8("two"))
        val verified = cose.verify(
            message = decoded,
            keys = listOf(publicSecond),
            algorithms = setOf(CoseAlgorithm.Ed25519),
            externalAad = utf8("aad"),
            detachedPayload = utf8(CONTENT),
        )
        verified.value() shouldBe decoded.signatures[1]
        val outcome2 = cose.verify(
            message = decoded,
            keys = listOf(publicSecond),
            algorithms = setOf(CoseAlgorithm.Esp256),
            detachedPayload = utf8(CONTENT),
        )
        outcome2.failure() shouldBe CoseFailure.KeyNotFound
        val outcome3 = cose.verify(
            message = decoded,
            keys = listOf(publicSecond),
            algorithms = setOf(CoseAlgorithm.Es256),
            detachedPayload = utf8(CONTENT),
        )
        outcome3.failure() shouldBe CoseFailure.AlgorithmNotPermitted
        val outcome4 = cose.verify(
            message = decoded,
            keys = listOf(publicSecond),
            algorithms = ALL_SIGNATURES,
            detachedPayload = utf8(CONTENT),
        )
        outcome4.failure() shouldBe CoseFailure.InvalidSignature
        val outcome5 = cose.verify(
            message = decoded,
            keys = emptyList(),
            algorithms = ALL_SIGNATURES,
            detachedPayload = utf8(CONTENT),
        )
        outcome5.failure() shouldBe CoseFailure.KeyNotFound
        cose.verify(message = decoded, keys = listOf(publicSecond), algorithms = ALL_SIGNATURES).failure() shouldBe
            CoseFailure.Malformed
        shouldThrow<IllegalArgumentException> { cose.sign(payload = utf8(CONTENT), signers = emptyList()) }
    }
})

private suspend fun roundTrip(algorithm: CoseAlgorithm, type: KeyType) {
    val pair = crypto.keys.generate(type)
    val signer = CoseSigner(key = CoseKey.of(pair.privateKey, keyId = utf8("kid")), algorithm = algorithm)
    val verifier = CoseKey.of(pair.publicKey, keyId = utf8("kid"), algorithm = algorithm)
    val message = cose.sign1(payload = utf8(CONTENT), signer = signer, externalAad = utf8("aad"))
    val tagged = cose.decodeSign1(message.encode()).value()
    val untagged = cose.decodeSign1(message.encode(isTagged = false)).value()
    tagged shouldBe untagged
    val outcome6 = cose.verify(
        message = tagged,
        keys = listOf(verifier),
        algorithms = setOf(algorithm),
        externalAad = utf8("aad"),
    )
    outcome6.value() shouldBe utf8(CONTENT)
    cose.verify(message = tagged, keys = listOf(verifier), algorithms = setOf(algorithm)).failure() shouldBe
        CoseFailure.InvalidSignature
    val detached = cose.sign1(payload = utf8(CONTENT), signer = signer, isDetached = true)
    val outcome7 = cose.verify(
        message = detached,
        keys = listOf(verifier),
        algorithms = setOf(algorithm),
        detachedPayload = utf8(CONTENT),
    )
    outcome7.value() shouldBe utf8(CONTENT)
}
