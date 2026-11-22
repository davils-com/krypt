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

package com.davils.krypt.primitive

import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.RandomSource
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.fixture.HiddenEcKey
import com.davils.krypt.primitive.fixture.on
import com.davils.krypt.primitive.key.fromJca
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

private const val SECRET_BYTES: Int = 32
private const val SUN: String = "SUN"
private const val SUN_JCE: String = "SunJCE"
private val MESSAGE: ByteString = "jca".encodeToByteString()

class JcaTest : FunSpec({
    test("digests and symmetric engines run on the provider the environment names") {
        on(SUN).digests.digest(MESSAGE).size shouldBe DigestAlgorithm.Sha256.outputBytes
        val digester = checkNotNull(on(SUN).digests.digester())
        digester.finish().size shouldBe DigestAlgorithm.Sha256.outputBytes
        val sunJce = on(SUN_JCE)
        val key = sunJce.keys.generateSecret()
        sunJce.macs.mac(key = key, data = MESSAGE, algorithm = MacAlgorithm.HmacSha256).size shouldBe SECRET_BYTES
        val box = sunJce.aead.seal(key = key, plaintext = MESSAGE)
        sunJce.aead.open(key = key, box = box) shouldBe MESSAGE
        val wrapped = sunJce.keyWraps.wrap(kek = key, key = key.export())
        sunJce.keyWraps.unwrap(kek = key, wrapped = wrapped) shouldNotBe null
        sunJce.capabilities.supports(KdfAlgorithm.Pbkdf2Sha256) shouldBe true
        on(SUN).capabilities.supports(AeadAlgorithm.Aes256Gcm) shouldBe false
        shouldThrow<UnsupportedAlgorithmException> { on(SUN).aead.seal(key = key, plaintext = MESSAGE) }
    }

    test("asymmetric engines run on the provider the environment names") {
        val sunEc = on("SunEC")
        val pair = sunEc.keys.generate(KeyType.P256)
        val signature = sunEc.signatures.sign(key = pair.privateKey, data = MESSAGE)
        sunEc.signatures.verify(key = pair.publicKey, data = MESSAGE, signature = signature) shouldBe Verification.Valid
        val other = sunEc.keys.generate(KeyType.P256)
        sunEc.agreements.agree(pair.privateKey, other.publicKey).size shouldBe SECRET_BYTES
        val rsa = on("SunRsaSign").keys.generate(KeyType.Rsa3072)
        val encrypted = on(SUN_JCE).encryptions.encrypt(publicKey = rsa.publicKey, plaintext = MESSAGE)
        encrypted.size shouldBe KeyType.Rsa3072.bits / Byte.SIZE_BITS
    }

    test("an ML-KEM provider decapsulates and refuses encapsulations of the wrong size") {
        val crypto = Crypto()
        val recipient = crypto.keys.generate(KeyType.MlKem768)
        crypto.kems.decapsulate(recipient.privateKey, ByteString(ByteArray(1)), KemAlgorithm.MlKem768) shouldBe null
        on(SUN_JCE).capabilities.supports(KemAlgorithm.MlKem1024) shouldBe true
    }

    test("a deterministic randomness feeds the JCA engines") {
        val counter = intArrayOf(0)
        val crypto = Crypto(environment { random = RandomSource { target -> target.fill(counter[0]++.toByte()) } })
        crypto.keys.generate(KeyType.Ed25519)
        (counter[0] > 0) shouldBe true
    }

    test("legacy RSA PKCS #1 v1.5 decrypts under an accepting policy and odd JCA keys are refused") {
        val legacy = Crypto(
            environment { policy = cryptoPolicy { acceptLegacy(AsymmetricEncryptionAlgorithm.RsaPkcs1) } },
        )
        val pair = legacy.keys.generate(KeyType.Rsa3072)
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(pair.publicKey.encoded.toByteArray())),
        )
        val encrypted = ByteString(cipher.doFinal(MESSAGE.toByteArray()))
        val decrypted = legacy.encryptions.decrypt(
            privateKey = pair.privateKey,
            ciphertext = encrypted,
            algorithm = AsymmetricEncryptionAlgorithm.RsaPkcs1,
        )
        decrypted?.reveal { bytes -> ByteString(bytes) } shouldBe MESSAGE
        val dh = KeyPairGenerator.getInstance("DiffieHellman").genKeyPair()
        shouldThrow<IllegalArgumentException> { Crypto().keys.fromJca(publicKey = dh.public, privateKey = dh.private) }
    }

    test("a key the provider does not encode stays inside it and still signs") {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val generated = generator.generateKeyPair()
        val crypto = Crypto()
        val hidden = HiddenEcKey(generated.private as ECPrivateKey)
        val pair = crypto.keys.fromJca(publicKey = generated.public, privateKey = hidden)
        pair.privateKey.isExtractable shouldBe false
        val signature = crypto.signatures.sign(key = pair.privateKey, data = MESSAGE)
        crypto.signatures.verify(
            key = pair.publicKey,
            data = MESSAGE,
            signature = signature,
        ) shouldBe Verification.Valid
        shouldThrow<IllegalStateException> { crypto.keys.encodePrivate(pair.privateKey) }
        pair.privateKey.destroy()
        pair.privateKey.isDestroyed shouldBe true
    }
})
