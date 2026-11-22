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
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.primitive.exchange.HpkeSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private const val LIMIT_HASH: Int = 31 * KeysetLimits.DEFAULT_MAXIMUM_KEYS + KeysetLimits.DEFAULT_MAXIMUM_ENCODED_BYTES

class KeyPurposeTest : FunSpec({
    test("purposes compare by their algorithms and show them") {
        val purposes = listOf(
            KeyPurpose.Aead(),
            KeyPurpose.Mac(),
            KeyPurpose.Signing(),
            KeyPurpose.Hybrid(),
        )
        purposes.map { purpose -> purpose.toString() } shouldBe listOf(
            "Aead(AES-256-GCM)",
            "Mac(HMAC-SHA-256)",
            "Signing(Ed25519)",
            "Hybrid(${HpkeSuite.X25519Aes256Gcm})",
        )
        purposes.map { purpose -> purpose.keyType } shouldBe listOf(null, null, KeyType.Ed25519, KeyType.X25519)
        purposes shouldBe listOf(KeyPurpose.Aead(), KeyPurpose.Mac(), KeyPurpose.Signing(), KeyPurpose.Hybrid())
        purposes.map { purpose -> purpose.hashCode() } shouldBe listOf(
            AeadAlgorithm.Aes256Gcm.hashCode(),
            MacAlgorithm.HmacSha256.hashCode(),
            KeyType.Ed25519.hashCode(),
            HpkeSuite.X25519Aes256Gcm.hashCode(),
        )
        KeyPurpose.Aead() shouldNotBe KeyPurpose.Aead(AeadAlgorithm.ChaCha20Poly1305)
        KeyPurpose.Mac() shouldNotBe KeyPurpose.Mac(MacAlgorithm.HmacSha512)
        KeyPurpose.Signing() shouldNotBe KeyPurpose.Signing(KeyType.P256)
        KeyPurpose.Hybrid() shouldNotBe KeyPurpose.Hybrid(HpkeSuite.P384Aes256Gcm)
    }

    test("a purpose refuses keys and suites that cannot serve it") {
        shouldThrow<IllegalArgumentException> { KeyPurpose.Signing(KeyType.X25519) }
        val exportOnly = HpkeSuite(kem = KemAlgorithm.DhkemX25519, kdf = KdfAlgorithm.HkdfSha256, aead = null)
        shouldThrow<IllegalArgumentException> { KeyPurpose.Hybrid(exportOnly) }
    }

    test("limits are checked against their ceilings") {
        val limits = KeysetLimits()
        limits shouldBe KeysetLimits.Default
        limits.hashCode() shouldBe LIMIT_HASH
        limits.toString() shouldBe "KeysetLimits(maximumKeys=256, maximumEncodedBytes=1048576)"
        limits shouldNotBe KeysetLimits(maximumKeys = 1)
        limits shouldNotBe KeysetLimits(maximumEncodedBytes = 1)
        shouldThrow<IllegalArgumentException> { KeysetLimits(maximumKeys = 0) }
        shouldThrow<IllegalArgumentException> { KeysetLimits(maximumKeys = KeysetLimits.HARD_MAXIMUM_KEYS + 1) }
        shouldThrow<IllegalArgumentException> { KeysetLimits(maximumEncodedBytes = 0) }
        shouldThrow<IllegalArgumentException> {
            KeysetLimits(maximumEncodedBytes = KeysetLimits.HARD_MAXIMUM_ENCODED_BYTES + 1)
        }
    }
})
