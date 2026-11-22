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

package com.davils.krypt.primitive

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoProfile
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.fixture.utf8
import com.davils.krypt.primitive.internal.Dhkem
import com.davils.krypt.primitive.key.KeyPair
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private const val MESSAGE: String = "matrix"
private const val DERIVED: Int = 48

private val everything: Crypto = Crypto(
    environment {
        policy = cryptoPolicy(CryptoProfile.Compatible) {
            minimumRsaBits = KeyType.Rsa2048.bits
            minimumIterations = DERIVED * DERIVED
            minimumVerifiedIterations = DERIVED * DERIVED
        }
    },
)

private val algorithms: List<Algorithm> = DigestAlgorithm.entries +
    MacAlgorithm.entries +
    AeadAlgorithm.entries +
    KeyWrapAlgorithm.entries +
    KdfAlgorithm.entries +
    SignatureAlgorithm.entries +
    KeyAgreementAlgorithm.entries +
    AsymmetricEncryptionAlgorithm.entries +
    KemAlgorithm.entries

private val baseline: Set<Algorithm> = setOf(
    DigestAlgorithm.Sha256,
    MacAlgorithm.HmacSha384,
    AeadAlgorithm.Aes128Gcm,
    KeyWrapAlgorithm.Aes128Kw,
    KdfAlgorithm.Pbkdf2Sha512,
    SignatureAlgorithm.EcdsaSha384,
    KeyAgreementAlgorithm.EcdhP521,
    AsymmetricEncryptionAlgorithm.RsaOaepSha512,
    KemAlgorithm.DhkemP256,
)

private suspend fun exercise(pair: KeyPair) {
    val keys = everything.keys
    keys.pair(pair.privateKey, pair.publicKey) shouldNotBe null
    val decoded = checkNotNull(keys.decodePrivate(keys.encodePrivate(pair.privateKey)).getOrNull())
    keys.pair(decoded, pair.publicKey) shouldNotBe null
    keys.decodePublic(pair.publicKey.encoded).getOrNull() shouldBe pair.publicKey
}

private suspend fun digestOrNull(digest: DigestAlgorithm): Int? {
    val isSupported = everything.capabilities.supports(digest)
    val result = digest.takeIf { isSupported }?.let { found -> everything.digests.digest(utf8(MESSAGE), found) }
    return result?.size
}

private suspend fun signsWithEvery(type: KeyType) {
    val pair = everything.keys.generate(type)
    val schemes = SignatureAlgorithm.entries.filter { algorithm ->
        algorithm.family == type.family &&
            !algorithm.isLegacy
    }
    schemes.forEach { algorithm ->
        val signature = everything.signatures.sign(key = pair.privateKey, data = utf8(MESSAGE), algorithm = algorithm)
        val verification = everything.signatures.verify(
            key = pair.publicKey,
            data = utf8(MESSAGE),
            signature = signature,
            algorithm = algorithm,
        )
        verification shouldBe Verification.Valid
    }
}

private suspend fun encapsulatesWith(kem: KemAlgorithm) {
    val recipient = everything.keys.generate(Dhkem.keyTypeOf(kem))
    val encapsulation = everything.kems.encapsulate(recipient.publicKey, kem)
    val opened = everything.kems.decapsulate(recipient.privateKey, encapsulation.encapsulated, kem)
    opened shouldBe encapsulation.sharedSecret
    everything.kems.decapsulate(recipient.privateKey, utf8(MESSAGE), kem) shouldBe null
}

class MatrixTest : FunSpec({
    context("every algorithm answers whether it is available") {
        withData(nameFn = { algorithm -> algorithm.algorithmName }, algorithms) { algorithm ->
            val isSupported = everything.capabilities.supports(algorithm)
            if (algorithm in baseline) isSupported shouldBe true
        }
    }

    context("every key type that is available round-trips and pairs") {
        withData(nameFn = { type -> type.name }, KeyType.entries) { type ->
            val isSupported = everything.capabilities.supports(type)
            val pair = type.takeIf { isSupported }?.let { found -> everything.keys.generate(found) }
            pair?.let { found -> exercise(found) }
        }
    }

    context("every digest that is available hashes") {
        withData(
            nameFn = { digest -> digest.algorithmName },
            DigestAlgorithm.entries.filterNot { digest -> digest.isLegacy },
        ) { digest ->
            digestOrNull(digest)?.let { size -> size shouldBe digest.outputBytes }
        }
    }

    context("every MAC and HKDF works") {
        withData(nameFn = { mac -> mac.algorithmName }, MacAlgorithm.entries) { mac ->
            val key = everything.keys.generateSecret()
            val tag = everything.macs.mac(key = key, data = utf8(MESSAGE), algorithm = mac)
            everything.macs.verify(
                key = key,
                data = utf8(MESSAGE),
                tag = tag,
                algorithm = mac,
            ) shouldBe Verification.Valid
        }
        withData(
            nameFn = { kdf -> kdf.algorithmName },
            KdfAlgorithm.entries.filterNot { kdf -> kdf.isPasswordBased },
        ) { kdf ->
            val key = everything.keys.generateSecret().export()
            val derived = everything.derivations.hkdf(
                inputKey = key,
                salt = utf8(MESSAGE),
                info = utf8(MESSAGE),
                length = DERIVED,
                algorithm = kdf,
            )
            derived.size shouldBe DERIVED
        }
    }

    test("signing keys sign with every scheme of their family") {
        signsWithEvery(KeyType.P256)
        signsWithEvery(KeyType.Rsa2048)
    }

    test("every DHKEM encapsulates to its curve") {
        val kems = KemAlgorithm.entries.filter { kem -> kem.family != KeyFamily.MlKem }
        kems.filter { kem -> everything.capabilities.supports(kem) }.forEach { kem -> encapsulatesWith(kem) }
    }
})
