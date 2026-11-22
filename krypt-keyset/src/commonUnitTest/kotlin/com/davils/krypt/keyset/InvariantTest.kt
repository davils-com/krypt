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

package com.davils.krypt.keyset

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.keyset.fixture.crypto
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val SHORT_SECRET: Int = 16

private fun KeysetKey.with(
    status: KeyStatus = this.status,
    secret: SecretKey? = this.secret,
    privateKey: PrivateKey? = this.privateKey,
    publicKey: PublicKey? = this.publicKey,
): KeysetKey = KeysetKey(
    id = id,
    status = status,
    createdAt = createdAt,
    secret = secret,
    privateKey = privateKey,
    publicKey = publicKey,
)

class InvariantTest : FunSpec({
    test("a key holds a secret, or a public key with or without its private key, until it is destroyed") {
        val symmetric = keysets.generate(KeyPurpose.Aead()).primary
        val asymmetric = keysets.generate(KeyPurpose.Signing()).primary
        shouldThrow<IllegalArgumentException> { symmetric.with(status = KeyStatus.Destroyed) }
        shouldThrow<IllegalArgumentException> { symmetric.with(secret = null) }
        shouldThrow<IllegalArgumentException> { symmetric.with(publicKey = asymmetric.publicKey) }
        shouldThrow<IllegalArgumentException> { symmetric.with(privateKey = asymmetric.privateKey) }
        shouldThrow<IllegalArgumentException> { asymmetric.with(publicKey = null) }
        asymmetric.with(privateKey = null).privateKey shouldBe null
        symmetric.destroyed().status shouldBe KeyStatus.Destroyed
    }

    test("a key set holds every id once, an enabled primary key and the material of its purpose") {
        val aead = keysets.rotate(keysets.generate(KeyPurpose.Aead()))
        val first = aead.keys.first()
        val purpose = aead.purpose
        shouldThrow<IllegalArgumentException> {
            Keyset(purpose = purpose, keys = aead.keys + first, primaryId = aead.primaryId)
        }
        shouldThrow<IllegalArgumentException> {
            Keyset(purpose = purpose, keys = listOf(first), primaryId = aead.primaryId)
        }
        shouldThrow<IllegalArgumentException> {
            Keyset(purpose = purpose, keys = listOf(first.withStatus(KeyStatus.Disabled)), primaryId = first.id)
        }
        val short = first.with(secret = crypto.keys.generateSecret(SHORT_SECRET))
        shouldThrow<IllegalArgumentException> { Keyset(purpose = purpose, keys = listOf(short), primaryId = first.id) }
        shouldThrow<IllegalArgumentException> {
            Keyset(purpose = KeyPurpose.Signing(), keys = listOf(first), primaryId = first.id)
        }
        val signing = keysets.generate(KeyPurpose.Signing())
        val signingKey = signing.primary
        shouldThrow<IllegalArgumentException> {
            Keyset(purpose = KeyPurpose.Signing(KeyType.Ed448), keys = signing.keys, primaryId = signing.primaryId)
        }
        shouldThrow<IllegalArgumentException> {
            Keyset(purpose = purpose, keys = signing.keys, primaryId = signing.primaryId)
        }
        val destroyed = Keyset(
            purpose = KeyPurpose.Signing(),
            keys = listOf(signingKey, first.destroyed()),
            primaryId = signingKey.id,
        )
        destroyed.keys.size shouldBe 2
    }

    test("a primitive of a key set matches the purpose of the key set") {
        val aead = keysets.generate(KeyPurpose.Aead())
        val mac = keysets.generate(KeyPurpose.Mac())
        val signing = keysets.generate(KeyPurpose.Signing())
        val hybrid = keysets.generate(KeyPurpose.Hybrid())
        val otherSuite = HpkeSuite.P384Aes256Gcm
        val suite = (hybrid.purpose as KeyPurpose.Hybrid).suite
        shouldThrow<IllegalArgumentException> {
            KeysetAead(crypto = crypto, keyset = aead, algorithm = AeadAlgorithm.ChaCha20Poly1305)
        }
        shouldThrow<IllegalArgumentException> {
            KeysetAead(crypto = crypto, keyset = mac, algorithm = AeadAlgorithm.Aes256Gcm)
        }
        shouldThrow<IllegalArgumentException> {
            KeysetMac(crypto = crypto, keyset = mac, algorithm = MacAlgorithm.HmacSha512)
        }
        shouldThrow<IllegalArgumentException> {
            KeysetMac(crypto = crypto, keyset = aead, algorithm = MacAlgorithm.HmacSha256)
        }
        shouldThrow<IllegalArgumentException> { KeysetSigner(crypto = crypto, keyset = hybrid) }
        shouldThrow<IllegalArgumentException> { KeysetVerifier(crypto = crypto, keyset = hybrid) }
        shouldThrow<IllegalArgumentException> { HybridEncrypter(crypto = crypto, keyset = hybrid, suite = otherSuite) }
        shouldThrow<IllegalArgumentException> { HybridEncrypter(crypto = crypto, keyset = signing, suite = suite) }
        shouldThrow<IllegalArgumentException> { HybridDecrypter(crypto = crypto, keyset = hybrid, suite = otherSuite) }
        shouldThrow<IllegalArgumentException> { HybridDecrypter(crypto = crypto, keyset = signing, suite = suite) }
        shouldThrow<IllegalArgumentException> {
            HybridDecrypter(crypto = crypto, keyset = keysets.publicKeyset(hybrid), suite = suite)
        }
    }
})
