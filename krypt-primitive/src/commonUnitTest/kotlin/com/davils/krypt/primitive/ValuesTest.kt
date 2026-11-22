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

import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.cipher.SealedBox
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.utf8
import com.davils.krypt.primitive.key.KeyPair
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val MESSAGE: String = "value"
private const val TOO_LONG: Int = 1_025
private const val SALT: Int = 16

class ValuesTest : FunSpec({
    test("sealed boxes compare nonce and ciphertext") {
        val box = SealedBox(nonce = utf8("n"), ciphertext = utf8("c"))
        box shouldNotBe SealedBox(nonce = utf8("m"), ciphertext = utf8("c"))
        box shouldNotBe SealedBox(nonce = utf8("n"), ciphertext = utf8("d"))
        box.equals(MESSAGE) shouldBe false
    }

    test("keys and pairs compare and show themselves") {
        val ed = crypto.keys.generate(KeyType.Ed25519)
        val other = crypto.keys.generate(KeyType.Ed25519)
        ed.publicKey.equals(MESSAGE) shouldBe false
        ed.publicKey.toString() shouldBe "PublicKey(Ed25519, curve=, bits=256)"
        ed.privateKey.toString() shouldContain "curve=,"
        ed shouldNotBe KeyPair(publicKey = other.publicKey, privateKey = ed.privateKey)
        ed shouldNotBe KeyPair(publicKey = ed.publicKey, privateKey = other.privateKey)
        ed.equals(MESSAGE) shouldBe false
        crypto.keys.generateSecret().equals(MESSAGE) shouldBe false
    }

    test("HPKE suites compare every algorithm") {
        val suite = HpkeSuite.X25519Aes256Gcm
        suite shouldNotBe HpkeSuite(KemAlgorithm.DhkemP256, KdfAlgorithm.HkdfSha256, AeadAlgorithm.Aes256Gcm)
        suite shouldNotBe HpkeSuite(KemAlgorithm.DhkemX25519, KdfAlgorithm.HkdfSha256, AeadAlgorithm.Aes128Gcm)
        suite.toString() shouldBe "HpkeSuite(DHKEM(X25519, HKDF-SHA256), HKDF-SHA-256, AES-256-GCM)"
        shouldThrow<IllegalArgumentException> {
            HpkeSuite(KemAlgorithm.DhkemX25519, KdfAlgorithm.HkdfSha256, AeadAlgorithm.Aes192Gcm)
        }
    }

    test("agreements, derivations and digests refuse what does not fit") {
        val p256 = crypto.keys.generate(KeyType.P256)
        val x25519 = crypto.keys.generate(KeyType.X25519)
        shouldThrow<IllegalArgumentException> { crypto.agreements.agree(p256.privateKey, x25519.publicKey) }
        shouldThrow<IllegalArgumentException> {
            fastCrypto.derivations.pbkdf2(
                password = SecretText.of(MESSAGE),
                salt = ByteString(ByteArray(SALT)),
                iterations = SALT * SALT * SALT,
                length = TOO_LONG,
            )
        }
    }
})
